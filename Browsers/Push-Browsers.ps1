#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Consolidated remote push-install/update for Chrome, Edge, and Firefox via
    PsExec - replaces ChromeInstall23.ps1, Chrome Powershell.ps1,
    EdgeInstall23.ps1, and Edge Update.ps1 (archived under
    ..\Browser Install Archive\) with one implementation.

.DESCRIPTION
    Pushes an install/update of one or more browsers to a list of REMOTE
    machines via PsExec + robocopy - the same transport as the four scripts
    this replaces, kept deliberately rather than switched to WinRM/PSSession
    remoting: WinRM is available on this fleet's older, AD-joined machines,
    but this repo is actively moving toward Intune-managed, non-domain-joined
    devices, where PsExec's local-admin-credential-over-SMB model keeps
    working without the Kerberos/domain-trust assumptions WinRM remoting
    needs. Not the same tool as
    ..\Intune PreDeployment Scripts\Browsers\Install-Browsers.ps1, which installs
    only on the local machine it's run on.

    Two staging modes, unifying what used to be two separate script pairs:
      - -SourcePath supplied: use an already-staged installer folder (e.g. a
        network share someone keeps current) - matches ChromeInstall23.ps1/
        EdgeInstall23.ps1's old behavior. No internet access needed from the
        machine running this script.
      - -SourcePath omitted: download the latest installer fresh from the
        vendor once, into WorkingRoot, then push that - matches Chrome
        Powershell.ps1/Edge Update.ps1's old behavior.
    Either way, the resulting local staging folder is what actually gets
    robocopied out to each target and run via PsExec + msiexec.

    The staged/downloaded MSI's Authenticode signature is verified against the
    expected publisher ONCE, before it is copied to any machine - a compromised
    share, a tampered file someone dropped there, or a compromised CDN response
    would otherwise get pushed to the whole list via PsExec as SYSTEM with no
    check at all.

.PARAMETER Browser
    One or more of Chrome, Edge, Firefox. If omitted and the session is
    interactive, shows a menu to pick from. If omitted and the session is NOT
    interactive, throws rather than hanging on a prompt nothing will answer.

.PARAMETER ComputerName
    Single target computer name.

.PARAMETER CsvPath
    CSV file with a "ComputerName" column listing target machines.

.PARAMETER SourcePath
    Folder already containing the installer MSI for the selected browser(s).
    When omitted, the latest installer is downloaded fresh into WorkingRoot
    instead.

.PARAMETER PsExecPath
    Path to PsExec.exe. Defaults to C:\PSTools\psexec.exe.

.PARAMETER WorkingRoot
    Local staging root used when downloading fresh (SourcePath omitted), and
    for the FailedCsv default. Defaults to C:\Patches.

.PARAMETER FailedCsv
    Output CSV for machines that failed, per browser. Defaults to
    Failed-<Browser>-<timestamp>.csv under WorkingRoot.

.PARAMETER MaxTargets
    Safety valve: if the resolved target list (-ComputerName/-CsvPath)
    exceeds this count, an explicit typed confirmation is required (or the
    run aborts outright in a non-interactive session) before any machine is
    touched. Defaults to 50.

.PARAMETER PsExecTimeoutSeconds
    Per-machine timeout for the PsExec install call, in seconds. If a remote
    msiexec hangs past this, PsExec is killed and that machine is recorded
    as failed rather than stalling the whole run. Defaults to 300.

.EXAMPLE
    .\Push-Browsers.ps1 -Browser Chrome -CsvPath .\computers.csv
    Downloads the latest Chrome fresh, pushes it to every machine in the CSV.

.EXAMPLE
    .\Push-Browsers.ps1 -Browser Edge -ComputerName PC001 -SourcePath \\fileserver\patches\Edge -WhatIf
    Pushes from an already-staged share, previewing what would happen.

.NOTES
    Exit code: 0 if every (browser, machine) pair succeeded, 1 if any failed.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Chrome', 'Edge', 'Firefox')]
    [string[]] $Browser,
    [string]   $ComputerName,
    [string]   $CsvPath,
    [string]   $SourcePath,
    [string]   $PsExecPath  = 'C:\PSTools\psexec.exe',
    [string]   $WorkingRoot = 'C:\Patches',
    [string]   $Proxy,
    [int]      $CacheHours  = 4,
    [string]   $FailedCsv,
    [switch]   $NoHashCheck,
    [switch]   $NoResume,

    # Safety valve: a -CsvPath that unexpectedly expands to a huge machine
    # list must not silently push-install to every match. Above this count,
    # an explicit typed confirmation is required before the push loop
    # starts. Mirrors ..\Windows 10 patching\Windows 10 patching.ps1's
    # -MaxTargets.
    [int]      $MaxTargets = 50,

    # PsExec itself blocks until the remote process exits, so without a
    # timeout a single hung remote msiexec stalls this entire multi-machine
    # loop indefinitely. 300s (5 min) default - a browser MSI install is
    # usually a couple of minutes; override for slower/loaded machines.
    [int]      $PsExecTimeoutSeconds = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\Intune PreDeployment Scripts\Common\BrowserDeploy.Common.psm1') -Force

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

################################################################################
# Browser selection: explicit -Browser, or an interactive menu               #
################################################################################

function Show-BrowserMenu {
    if (-not [Environment]::UserInteractive) {
        throw 'No -Browser specified and this session is not interactive - pass -Browser explicitly instead of relying on the menu.'
    }
    Write-Host ''
    Write-Host 'Select browser(s) to push:' -ForegroundColor Cyan
    Write-Host '  [1] Chrome'
    Write-Host '  [2] Edge'
    Write-Host '  [3] Firefox'
    Write-Host '  [A] All'
    Write-Host '  [Q] Cancel'
    $choice = Read-Host 'Enter choice(s), comma-separated (e.g. 1,3)'
    if ([string]::IsNullOrWhiteSpace($choice) -or $choice -match '^\s*[Qq]\s*$') { return @() }
    if ($choice -match '^\s*[Aa]\s*$') { return @('Chrome', 'Edge', 'Firefox') }
    $map = @{ '1' = 'Chrome'; '2' = 'Edge'; '3' = 'Firefox' }
    $selected = ($choice -split ',') | ForEach-Object { $map[$_.Trim()] } | Where-Object { $_ }
    return @($selected | Select-Object -Unique)
}

if (-not $Browser -or $Browser.Count -eq 0) {
    $Browser = Show-BrowserMenu
    if (-not $Browser -or $Browser.Count -eq 0) {
        Write-Host 'No browser selected - nothing to do.' -ForegroundColor Yellow
        exit 0
    }
}
$Browser = @($Browser | Select-Object -Unique)

################################################################################
# Target list                                                                 #
################################################################################

$computers = [System.Collections.Generic.List[string]]::new()
if ($ComputerName) { $computers.Add($ComputerName) }
if ($CsvPath)      { (Import-Csv -Path $CsvPath).ComputerName | ForEach-Object { $computers.Add($_) } }
if ($computers.Count -eq 0) { throw 'Provide -ComputerName or -CsvPath.' }

# Refuse to push-install to the machine running this script - a self-
# targeting entry (typo, stale CSV row, etc.) would run the install via
# PsExec against localhost instead of a remote target.
$selfTargetNames  = @('localhost', '127.0.0.1', '.')
$remoteComputers  = [System.Collections.Generic.List[string]]::new()
foreach ($c in $computers) {
    if ($c -in $selfTargetNames -or $c -eq $env:COMPUTERNAME) {
        Write-Warning "Skipping '$c' - self-targeting entries are not allowed."
        continue
    }
    $remoteComputers.Add($c)
}
$computers = $remoteComputers
if ($computers.Count -eq 0) { throw 'No remote targets remain after excluding self-targeting entries.' }

# Safety valve: a -CsvPath that resolves to far more machines than intended
# must not silently push-install to the whole list. Above -MaxTargets,
# require a typed confirmation before anything below touches a single
# machine. $PSCmdlet.ShouldContinue() was considered, but it throws outright
# (rather than degrading safely) when the host can't prompt (e.g.
# unattended/SYSTEM context) - a plain Read-Host with an explicit
# non-interactive check fails closed instead, matching the pattern in
# ..\Windows 10 patching\Windows 10 patching.ps1.
if ($computers.Count -gt $MaxTargets) {
    Write-Warning "Resolved target list contains $($computers.Count) computer(s), which exceeds the safety threshold of $MaxTargets (see -MaxTargets to raise it). This run will push-install to every matched machine."
    if (-not [Environment]::UserInteractive) {
        throw "Aborting: $($computers.Count) resolved target(s) exceeds -MaxTargets ($MaxTargets) and this session is non-interactive, so explicit confirmation cannot be collected. Re-run interactively to confirm, or pass a higher -MaxTargets if this scale is intentional."
    }
    $confirmation = Read-Host "Type YES to confirm pushing to $($computers.Count) machine(s)"
    if ($confirmation -ne 'YES') {
        Write-Warning "Aborted: confirmation not received for a $($computers.Count)-machine run."
        exit 0
    }
}

if (-not (Test-Path $PsExecPath)) { throw "PsExec not found: $PsExecPath" }
if ($SourcePath -and -not (Test-Path $SourcePath)) { throw "Source path not found: $SourcePath" }

################################################################################
# Per-browser definitions                                                     #
################################################################################

$BrowserDefs = @{
    Chrome  = @{
        DisplayNamePattern = 'Google Chrome'
        SignerPattern      = 'O=Google LLC'
        StagedMsiPattern   = 'GoogleChrome*.msi'
        GetLatestInfo      = { Get-ChromeLatestInfo -Proxy $Proxy -CacheHours $CacheHours }
    }
    Edge    = @{
        # Exact match, not a wildcard - "Microsoft Edge*" would also match
        # "Microsoft Edge WebView2 Runtime" and "Microsoft Edge Update", both
        # commonly present alongside real Edge.
        DisplayNamePattern = 'Microsoft Edge'
        SignerPattern      = 'O=Microsoft Corporation'
        StagedMsiPattern   = 'MicrosoftEdge*.msi'
        GetLatestInfo      = { Get-EdgeLatestInfo -Proxy $Proxy -CacheHours $CacheHours }
    }
    Firefox = @{
        DisplayNamePattern = 'Mozilla Firefox*'
        SignerPattern      = 'O=Mozilla Corporation'
        StagedMsiPattern   = 'Firefox Setup*.msi'
        GetLatestInfo      = { Get-FirefoxLatestInfo -Proxy $Proxy -CacheHours $CacheHours }
    }
}

################################################################################
# Helpers                                                                     #
################################################################################

function Get-RemoteBrowserVersion {
    <#
    .SYNOPSIS
        Reads DisplayVersion for a browser off a remote machine's uninstall
        registry keys (32-bit and WOW6432Node), via the Remote Registry
        service. Returns $null (not an error) if the service is unavailable -
        that's the common case on a workstation with Remote Registry disabled
        by default, not a sign the install failed.
    #>
    param([string]$ComputerName, [string]$DisplayNamePattern)
    $remoteReg = $null
    try {
        $remoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $ComputerName)
        foreach ($subPath in 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
            $uninstKey = $remoteReg.OpenSubKey($subPath)
            if (-not $uninstKey) { continue }
            try {
                foreach ($subName in $uninstKey.GetSubKeyNames()) {
                    $entry = $uninstKey.OpenSubKey($subName)
                    try {
                        if ($entry.GetValue('DisplayName') -like $DisplayNamePattern) {
                            return $entry.GetValue('DisplayVersion')
                        }
                    } finally { $entry.Close() }
                }
            } finally { $uninstKey.Close() }
        }
        return $null
    } catch {
        return $null
    } finally {
        if ($remoteReg) { $remoteReg.Close() }
    }
}

function Get-StagedInstaller {
    <#
    .SYNOPSIS
        Resolves the local (staging-machine) path to a verified installer MSI
        for one browser - either found under -SourcePath, or downloaded fresh
        into WorkingRoot when -SourcePath wasn't supplied. Verifies the
        Authenticode signature once here, before anything gets pushed out to
        any target machine.
    #>
    param([Parameter(Mandatory)][string]$Name)
    $def = $BrowserDefs[$Name]

    if ($SourcePath) {
        $msi = Get-ChildItem -Path $SourcePath -Filter $def.StagedMsiPattern -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $msi) { throw "No file matching '$($def.StagedMsiPattern)' found under $SourcePath." }
        $msiPath = $msi.FullName
    } else {
        $latest = & $def.GetLatestInfo
        $dlDir  = Join-Path $WorkingRoot $Name
        New-Item -Path $dlDir -ItemType Directory -Force | Out-Null
        $msiPath = Join-Path $dlDir $latest.FileName
        Invoke-VerifiedDownload -Url $latest.Url -Destination $msiPath -Sha256 $latest.Sha256 `
            -Proxy $Proxy -NoHashCheck:$NoHashCheck -NoResume:$NoResume `
            -LogAction { param($Message, $Level) if ($Level -eq 'Warning') { Write-Warning $Message } else { Write-Verbose $Message } }
    }

    $msiName = Split-Path $msiPath -Leaf
    # $msiName is embedded verbatim into a `cmd /c` string run via PsExec as
    # SYSTEM on every target machine below (see Push-OneBrowser). It comes
    # from either an arbitrary -SourcePath folder or a vendor feed's
    # FileName field, so it must be validated here - once, before any
    # machine is touched - rather than trusted as-is: a name containing "
    # would break the quoting, and one containing &/|/^ could inject
    # additional shell commands. Known-good names are plain ASCII with
    # spaces (e.g. Firefox's "Firefox Setup 129.0.msi" from
    # Get-FirefoxLatestInfo), so the allowed set is deliberately narrow.
    # Windows treats the portion of a filename before its first '.' as the
    # device name, regardless of what follows - "CON.msi" still resolves to
    # the CON device, not a real file - so that leading segment is checked
    # against the reserved list separately from the character-set check.
    $reservedDeviceNames = @(
        'CON', 'PRN', 'AUX', 'NUL',
        'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    )
    $nameStem = ($msiName -split '\.')[0]
    if ($msiName -notmatch '^[A-Za-z0-9 ._\-]+\.msi$' -or $nameStem -in $reservedDeviceNames) {
        throw "Refusing to deploy $Name installer: filename '$msiName' contains characters outside the safe set (letters, digits, space, dot, underscore, hyphen, ending in .msi) or is a reserved Windows device name - refusing to embed it in a remote command line."
    }

    # Unconditional - independent of any hash check above (which silently
    # no-ops for a feed that doesn't publish one, e.g. Firefox's, and isn't
    # run at all in -SourcePath mode). This is the real integrity gate before
    # anything gets pushed to a single machine, let alone the whole list.
    $sig = Get-AuthenticodeSignature -FilePath $msiPath
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch [regex]::Escape($def.SignerPattern)) {
        throw "MSI at $msiPath failed Authenticode validation (status: $($sig.Status)) - refusing to deploy it to any machine."
    }
    Write-Host "$Name installer Authenticode signature verified ($($def.SignerPattern)): $msiPath" -ForegroundColor Green
    return $msiPath
}

function Push-OneBrowser {
    # SupportsShouldProcess is required here, not just on the top-level script -
    # $PSCmdlet is unpopulated inside a plain function, so .ShouldProcess() below
    # would throw a null-reference at runtime without this.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$MsiPath,
        [int]$PsExecTimeoutSeconds = 300
    )

    $def       = $BrowserDefs[$Name]
    $msiName   = Split-Path $MsiPath -Leaf
    $succeeded = [System.Collections.Generic.List[string]]::new()
    $failed    = [System.Collections.Generic.List[string]]::new()

    foreach ($computer in $computers) {
        $tempDirName = "Temp$Name"
        $uncTemp     = "\\$computer\c$\$tempDirName"
        $remoteMsi   = "C:\$tempDirName\$msiName"

        Write-Host "[$computer] Starting $Name push..."

        if (-not (Test-Connection -ComputerName $computer -Count 1 -Quiet)) {
            Write-Warning "[$computer] Not reachable - skipping."
            $failed.Add($computer)
            continue
        }

        $beforeVer = Get-RemoteBrowserVersion -ComputerName $computer -DisplayNamePattern $def.DisplayNamePattern

        try {
            if ($PSCmdlet.ShouldProcess($computer, "Copy $Name installer and install via msiexec")) {
                New-Item -Path $uncTemp -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

                robocopy (Split-Path $MsiPath -Parent) $uncTemp $msiName /R:2 /W:2 | Out-Null
                if ($LASTEXITCODE -ge 8) {
                    Write-Warning "[$computer] Robocopy failed (exit $LASTEXITCODE) - skipping."
                    $failed.Add($computer)
                    continue
                }

                # PsExec itself blocks until the remote process exits, so the
                # call operator ($proc = & $PsExecPath ...) gives no Process
                # handle to wait on with a timeout - a hung remote msiexec
                # would stall this entire multi-machine loop indefinitely.
                # Start-Process -PassThru does give a handle, at the cost of
                # losing the simple `2>&1` capture the old `&` form had, so
                # stdout/stderr are redirected to temp files and read back
                # below for the same warning-message behavior on failure.
                $psexecArgs   = @("\\$computer", '-s', '-accepteula', 'cmd', '/c', "msiexec.exe /I `"$remoteMsi`" /qn /norestart")
                $stdOutFile   = [System.IO.Path]::GetTempFileName()
                $stdErrFile   = [System.IO.Path]::GetTempFileName()
                $psexecOutput = $null
                $rc           = $null
                try {
                    $psexecProc = Start-Process -FilePath $PsExecPath -ArgumentList $psexecArgs -PassThru -NoNewWindow `
                                  -RedirectStandardOutput $stdOutFile -RedirectStandardError $stdErrFile -ErrorAction Stop
                    $psexecExited = $psexecProc.WaitForExit($PsExecTimeoutSeconds * 1000)
                    if (-not $psexecExited) {
                        $psexecProc.Kill()
                        Write-Warning "[$computer] PsExec did not complete within ${PsExecTimeoutSeconds}s and was terminated (see -PsExecTimeoutSeconds) - treating $computer as failed."
                        $failed.Add($computer)
                        continue
                    }
                    $rc           = $psexecProc.ExitCode
                    $psexecOutput = @(Get-Content -Path $stdOutFile -ErrorAction SilentlyContinue) + @(Get-Content -Path $stdErrFile -ErrorAction SilentlyContinue)
                } finally {
                    Remove-Item -Path $stdOutFile, $stdErrFile -Force -ErrorAction SilentlyContinue
                }

                if ($rc -in @(0, 3010, 1641)) {
                    $afterVer = Get-RemoteBrowserVersion -ComputerName $computer -DisplayNamePattern $def.DisplayNamePattern
                    $verNote  = if ($afterVer) { "now $afterVer" } else { '(version not confirmed - Remote Registry may be disabled on this machine)' }
                    Write-Host "[$computer] $Name installed successfully (exit $rc). Before: $(if ($beforeVer) { $beforeVer } else { 'not installed' }); $verNote." -ForegroundColor Green
                    if ($rc -ne 0) { Write-Host "[$computer] NOTE: Reboot pending to complete install." -ForegroundColor Yellow }
                    $succeeded.Add($computer)
                } else {
                    Write-Warning "[$computer] msiexec returned exit code $rc."
                    if ($psexecOutput) { Write-Warning "[$computer] PsExec output: $($psexecOutput -join ' | ')" }
                    $failed.Add($computer)
                }
            }
        } catch {
            Write-Warning "[$computer] Unexpected error: $_"
            $failed.Add($computer)
        } finally {
            Remove-Item -Path $uncTemp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    return [pscustomobject]@{ Browser = $Name; Succeeded = $succeeded; Failed = $failed }
}

################################################################################
# Main                                                                        #
################################################################################

$allResults = foreach ($b in $Browser) {
    Write-Host ''
    Write-Host "=== $b ===" -ForegroundColor Cyan
    try {
        $msiPath = Get-StagedInstaller -Name $b
        Push-OneBrowser -Name $b -MsiPath $msiPath -PsExecTimeoutSeconds $PsExecTimeoutSeconds
    } catch {
        Write-Warning "$b - aborted before any machine was touched: $_"
        [pscustomobject]@{ Browser = $b; Succeeded = @(); Failed = @($computers) }
    }
}

Write-Host ''
$anyFailed = $false
foreach ($r in $allResults) {
    Write-Host "$($r.Browser): $($r.Succeeded.Count) succeeded, $($r.Failed.Count) failed."
    if ($r.Failed.Count -gt 0) {
        $anyFailed = $true
        Write-Warning "$($r.Browser) failed machines: $($r.Failed -join ', ')"
        $csvPath = if ($FailedCsv) { $FailedCsv } else { Join-Path $WorkingRoot "Failed-$($r.Browser)-$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
        $r.Failed | ForEach-Object { [pscustomobject]@{ ComputerName = $_ } } | Export-Csv -Path $csvPath -NoTypeInformation -Force
        Write-Host "  Failed list saved to $csvPath" -ForegroundColor Yellow
    }
}

exit ($(if ($anyFailed) { 1 } else { 0 }))
