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
    machines via PsExec + robocopy (WinRM/PSRemoting is not available in this
    environment, same as the four scripts this replaces). Not the same tool as
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
    [switch]   $NoResume
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\Intune PreDeployment Scripts\Common\BrowserDeploy.Common.psm1') -Force

if ((([Net.ServicePointManager]::SecurityProtocol) -band 3072) -eq 0) { [Net.ServicePointManager]::SecurityProtocol += 3072 }

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
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$MsiPath)

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

                $psexecOutput = & $PsExecPath "\\$computer" -s -accepteula cmd /c "msiexec.exe /I `"$remoteMsi`" /qn /norestart" 2>&1
                $rc = $LASTEXITCODE

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
        Push-OneBrowser -Name $b -MsiPath $msiPath
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
