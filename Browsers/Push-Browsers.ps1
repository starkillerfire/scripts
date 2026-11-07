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
# BEGIN SCRIPT LIBRARY REMOTE UPDATE
# Generated by maintenance/Install-RemoteUpdate.ps1. Edit the template, then regenerate.
# Verify the installed file before any original operational code is reached.
if (-not (&{
    param([string]$Path)
    if (-not $Path) { return $false }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    return ($signature.Status -eq 'Valid' -and $signature.SignerCertificate.Thumbprint -eq 'CEFA4DF2F31F5218A3F3B28144AFD9A96770A315')
} $PSCommandPath)) { throw 'This library file must have a valid signature from the approved DOI signing certificate.' }
& {
    function Update-LibraryScript {
        [CmdletBinding(SupportsShouldProcess)]
        param([string]$LocalPath, [string]$RepositoryPath, [datetimeoffset]$Baseline, [string]$ExpectedSha256)

        # A preview must not download, replace files, or advance update state.
        $customPreview = Get-Variable -Name WhatIf -Scope Script -ErrorAction SilentlyContinue
        if ($WhatIfPreference -or ($customPreview -and [bool]$customPreview.Value) -or $env:SCRIPT_LIBRARY_SKIP_UPDATE -eq '1' -or -not $LocalPath) { return }
        $temporary = $null
        $stateTemporary = $null
        $statePrevious = $null
        $pendingPrevious = $null
        try {
            $statePath = $LocalPath + '.update.json'
            if (Test-Path -LiteralPath $statePath) {
                $state = Get-Content -LiteralPath $statePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                $savedDate = [datetimeoffset]$state.CommittedAt
                if ($savedDate -gt $Baseline) { $Baseline = $savedDate }
            }
            $encodedPath = [uri]::EscapeDataString($RepositoryPath)
            $githubHeaders = @{ 'User-Agent' = 'ScriptLibrary-Updater'; Accept = 'application/vnd.github+json' }
            $gitlabHeaders = @{ 'User-Agent' = 'ScriptLibrary-Updater' }
            if ($env:SCRIPT_LIBRARY_GITHUB_TOKEN) { $githubHeaders.Authorization = 'Bearer ' + $env:SCRIPT_LIBRARY_GITHUB_TOKEN }
            if ($env:SCRIPT_LIBRARY_GITLAB_TOKEN) { $gitlabHeaders['PRIVATE-TOKEN'] = $env:SCRIPT_LIBRARY_GITLAB_TOKEN }
            $githubRef = $env:SCRIPT_LIBRARY_GITHUB_REF
            $gitlabRef = $env:SCRIPT_LIBRARY_GITLAB_REF
            # An empty ref asks each server for its default branch.
            $githubQuery = if ($githubRef) { '&sha=' + [uri]::EscapeDataString($githubRef) } else { '' }
            $gitlabQuery = if ($gitlabRef) { '&ref_name=' + [uri]::EscapeDataString($gitlabRef) } else { '' }
            $gitlabApi = 'https://gitlab.bor.doi.net/api/v4/projects/powershell-group%2FGitLab-Script-Library'
            $sources = @(
                @{ Name = 'GitLab'; Headers = $gitlabHeaders; Uri = "$gitlabApi/repository/commits?path=$encodedPath&per_page=1$gitlabQuery" },
                @{ Name = 'GitHub'; Headers = $githubHeaders; Uri = "https://api.github.com/repos/starkillerfire/scripts/commits?path=$encodedPath&per_page=1$githubQuery" }
            )
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            $candidates = @(
                foreach ($source in $sources) {
                    try {
                        $response = Invoke-RestMethod -Uri $source.Uri -Headers $source.Headers -TimeoutSec 5 -MaximumRedirection 0 -ErrorAction Stop
                    } catch {
                        Write-Verbose "Update check unavailable for $($source.Name): $RepositoryPath"
                        continue
                    }
                        # A reachable primary is authoritative, even if stale or empty.
                        # Malformed metadata, rejected signatures, and failed downloads
                        # never authorize installing different secondary content.
                        $commits = @($response)
                        if ($commits.Count -eq 0 -or $null -eq $commits[0]) { break }
                        $commit = $commits[0]
                        if ($source.Name -eq 'GitHub') {
                            $sha = [string]$commit.sha
                            $date = [datetimeoffset]$commit.commit.committer.date
                            $download = "https://api.github.com/repos/starkillerfire/scripts/contents/${encodedPath}?ref=$sha"
                        } else {
                            $sha = [string]$commit.id
                            $date = [datetimeoffset]$commit.committed_date
                            $download = "$gitlabApi/repository/files/$encodedPath/raw?ref=$sha"
                        }
                        if ($sha -notmatch '^[a-fA-F0-9]{40,64}$') { throw 'Invalid commit identifier.' }
                        if ($date -gt $Baseline) {
                            [pscustomobject]@{ Name = $source.Name; Sha = $sha; Date = $date; Uri = $download; Headers = $source.Headers }
                        }
                        break
                }
            )
            foreach ($candidate in ($candidates | Sort-Object Date -Descending)) {
                try {
                    $extension = [IO.Path]::GetExtension($LocalPath)
                    $temporary = $LocalPath + '.' + [guid]::NewGuid().ToString('N') + '.download' + $extension
                    $headers = @{}
                    foreach ($key in $candidate.Headers.Keys) { $headers[$key] = $candidate.Headers[$key] }
                    if ($candidate.Name -eq 'GitHub') { $headers.Accept = 'application/vnd.github.raw+json' }
                    Invoke-WebRequest -Uri $candidate.Uri -Headers $headers -UseBasicParsing -OutFile $temporary -TimeoutSec 15 -MaximumRedirection 0 -ErrorAction Stop | Out-Null
                    $content = [IO.File]::ReadAllText($temporary)
                    if ([string]::IsNullOrWhiteSpace($content) -or $content -match '(?is)^\s*<(?:!doctype|html)') { throw 'Empty or HTML download rejected.' }
                    if ($extension -in @('.ps1', '.psm1')) {
                        $parseTokens = $null
                        $parseErrors = $null
                        $null = [Management.Automation.Language.Parser]::ParseInput($content, [ref]$parseTokens, [ref]$parseErrors)
                        if ($parseErrors.Count -gt 0) { throw 'Downloaded PowerShell did not pass syntax validation.' }
                        if (-not $content.Contains('# BEGIN SCRIPT LIBRARY REMOTE UPDATE')) { throw 'Download lacks remote-update support; refusing to install a legacy copy.' }
                        $existingSignature = Get-AuthenticodeSignature -LiteralPath $LocalPath -ErrorAction Stop
                        # Approved by the library owner; public certificate thumbprint only.
                        $approvedSigners = @('CEFA4DF2F31F5218A3F3B28144AFD9A96770A315')
                        if ($existingSignature.Status -eq 'Valid') {
                            if ($existingSignature.SignerCertificate.Thumbprint -notin $approvedSigners) { throw 'Installed script signer is not approved.' }
                        } elseif ($existingSignature.Status -ne 'NotSigned') {
                            throw 'Installed script has an invalid signature; investigate before updating.'
                        }
                        if ($approvedSigners.Count -gt 0) {
                            $newSignature = Get-AuthenticodeSignature -LiteralPath $temporary -ErrorAction Stop
                            if ($newSignature.Status -ne 'Valid' -or $newSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -notin $approvedSigners) {
                                throw 'Update is not validly signed by an approved certificate.'
                            }
                        }
                    } elseif ($extension -eq '.bat' -and $content -notmatch '(?im)^@?echo\s+off\s*$') {
                        throw 'Download is not a recognized batch launcher.'
                    }
                    if ($extension -eq '.bat') {
                        # BAT has no Authenticode support. Its approved hash is
                        # carried by the signed PowerShell script that launches it.
                        if (-not $ExpectedSha256 -or (Get-FileHash -LiteralPath $temporary -Algorithm SHA256 -ErrorAction Stop).Hash -ne $ExpectedSha256) {
                            throw 'Batch update does not match the hash approved by its PowerShell companion.'
                        }
                    }
                    $changed = (Get-FileHash -LiteralPath $temporary -Algorithm SHA256 -ErrorAction Stop).Hash -ne (Get-FileHash -LiteralPath $LocalPath -Algorithm SHA256 -ErrorAction Stop).Hash
                    if (-not $PSCmdlet.ShouldProcess($LocalPath, 'Install approved remote update and record version')) { break }
                    if ($changed) {
                        if ($extension -eq '.bat' -and $env:SCRIPT_LIBRARY_ACTIVE_LAUNCHER -eq $LocalPath) {
                            # CMD may still be reading this launcher. Its preamble applies this on next launch.
                            if (-not $content.Contains('SCRIPT_LIBRARY_ACTIVE_LAUNCHER')) { throw 'Batch update lacks the safe-update preamble.' }
                            $pending = $LocalPath + '.update.pending'
                            if (Test-Path -LiteralPath $pending) {
                                $pendingPrevious=$pending+'.'+[guid]::NewGuid().ToString('N')+'.previous'
                                [IO.File]::Replace($temporary, $pending, $pendingPrevious)
                            }
                            else { [IO.File]::Move($temporary, $pending) }
                        } else {
                            # Same-volume replacement is atomic. Keep the previous working copy.
                            [IO.File]::Replace($temporary, $LocalPath, ($LocalPath + '.bak'))
                        }
                        $temporary = $null
                        Write-Host "Updated $RepositoryPath from $($candidate.Name). The new version takes effect on the next run."
                    }
                    $stateTemporary = $statePath + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
                    @{ CommittedAt = $candidate.Date.ToString('o'); Commit = $candidate.Sha; Source = $candidate.Name } |
                        ConvertTo-Json | Set-Content -LiteralPath $stateTemporary -Encoding UTF8 -ErrorAction Stop
                    if (Test-Path -LiteralPath $statePath) {
                        $statePrevious=$statePath+'.'+[guid]::NewGuid().ToString('N')+'.previous'
                        [IO.File]::Replace($stateTemporary, $statePath, $statePrevious)
                    }
                    else { [IO.File]::Move($stateTemporary, $statePath) }
                    $stateTemporary = $null
                    break
                } catch {
                    # Do not fall back after replacement if only recording state failed.
                    Write-Warning "Update could not complete for ${RepositoryPath}: $($_.Exception.Message)"
                    if (-not $temporary) { break }
                } finally {
                    if ($temporary -and (Test-Path -LiteralPath $temporary)) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
                    $temporary = $null
                }
            }
        } catch {
            Write-Warning "Update skipped for ${RepositoryPath}: $($_.Exception.Message)"
        } finally {
            if ($stateTemporary -and (Test-Path -LiteralPath $stateTemporary)) { Remove-Item -LiteralPath $stateTemporary -Force -ErrorAction SilentlyContinue }
            foreach ($previous in @($statePrevious,$pendingPrevious)) {
                if ($previous -and (Test-Path -LiteralPath $previous)) { Remove-Item -LiteralPath $previous -Force -ErrorAction SilentlyContinue }
            }
        }
    }
    Update-LibraryScript -LocalPath $PSCommandPath -RepositoryPath 'Browsers/Push-Browsers.ps1' -Baseline '2026-11-06T00:00:00Z'
}
# END SCRIPT LIBRARY REMOTE UPDATE



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

# SIG # Begin signature block
# MIIsWQYJKoZIhvcNAQcCoIIsSjCCLEYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBjuLzM7wHyRaKw
# HnaB86VqHVC80a7ASJPWAj1BWi2JX6CCJX4wggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYg
# MjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphB
# cr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6p
# vF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHe
# HYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEd
# gkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjU
# jsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bR
# VFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeS
# LsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIV
# NSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL
# 6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2Zd
# SoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFU
# eEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEw
# DQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/
# T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQ
# E7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9r
# EVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y
# 1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gx
# dEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3t
# y9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcy
# tL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEB
# YTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud
# /v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiS
# uEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZP
# ubdcMIIG7TCCBNWgAwIBAgIQCE/cM09+RU7bww+P+ZIYNTANBgkqhkiG9w0BAQsF
# ADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hB
# MjU2IDIwMjUgQ0ExMB4XDTI2MDgwNTAwMDAwMFoXDTM3MTEwNDIzNTk1OVowYzEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJE
# aWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjYg
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALZ7pvLJ/s1K+NSbTGWz
# /TjGMPh8CQ6RucZCLv5anHzWJjF/NWJrFIhy24fcpKXlgRiky4WAawDfU3YP0BMx
# t9l3Dm5oCG5Z69AqEN1kgHg2epx+l+lZBcmJCcN0ASURML5uFIS80sZsDwO3BSkU
# xDjLJhBI+qiZP3aixAC/qEGLjsBNlLol9VZ7pfGEXiMlneJIC5/YKuizVzNFKZZE
# eoy/0B8Zm+nzKBgSWG52lCO1w+nCg6XpCtklTJXeIg283hw7TmmsZXR+SMbjbrEO
# vZ3fP2VxIgeR28Y90ZStd3F9VuA5RVynb/whITPAo9b75Zr4Ta6Mj3URm26QZYMn
# /FnbuTegcoRcFEZ9FOqM5T6MTdtr/n74lIT/ug0eeOzmZ6QTFg33otX+bFRsIolv
# ykE1jive4PuESaT8zzVeFWDAMDtozNgLctkGD1ZjkEyZtJrLl5ya0m5doH/ScpaZ
# CZVl6pNUOCybMc/kxC6EAmSJY24L0yYKD1Nkddsnb/ItVKi/2nXpQNMu1PT5prW8
# 3vV8d67WowuUs0HdY4H8AMLGvdL/WHEj3ZnqMqAQQP9u3Ai9t+5eQ02GDwy0ODjd
# zi0xlp70W+ow63/0++YDEX1M0iwgUHwbrJvfpklkZQvw3+kv3vUPItdwroczk9ic
# flf55W1zOEKAcJVAIXpcMCU9AgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0G
# A1UdDgQWBBQUyWOKMC7USvtulPPm40B+9ezN4jAfBgNVHSMEGDAWgBTvb1NK6eQG
# fHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEy
# NTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hB
# MjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQCNxTphHp1SCt+ZrAmAfn0oQLFr0mLywSLaDXQI
# ENoyKqxrFbJblzCVP/pkXmwXOdrOpWygLzlT12os5ipDCy35RBCg2UMeApEtrfGh
# z45F4Wt4WGdNdIbRWt3YTYJmpR+b7lr4d7Uwn+H600u4D7RnOGf8Wj4UNgAdZkfH
# hHv1mx9EVh71SJelcEN/oORSjXzdjfw1iZH9d8Nh/thn6hH23d+VsPAr6GAYyzSA
# 02nXD1nYLI7Ijmiv+xLCiYC41DSFYL3GhTiy0PxpawPtGRyaBVGzq+UiTfM8pD7K
# VyF5aQyWP4KhVGUUTnmm/RlYJoW3TiXA/+t0YcT2oRVBm3JETjajHug2AL+v5jht
# KVnd3D0rbHXEu27o+Q8p4sEWPMqKDB+qbceb6T/6WcwTwXmQ9lOCLLYcsQeSWmvK
# qzpAec9etE14jOQAzLKWdE3w/TCaKtLRaRT7LCkRYVnhA2D73FLje1O5b3HR5eHs
# 0NzU/+xX7NbEdcofy0W3Wdwd1XOqtlpg/JgwtKfZM5dqO94lbUveOiJBI+xZEbGR
# sMNbXmMREUTgu+Oca7Y73MPWcslIx2VhkSKSXjDbD6rgg39H5Mh7QfieAIjWagkJ
# Nt68Yfim6cjEzVSiLSeZfdkr5dtFPTW6jATlWJdYeeDRGCyatf8R1hSjzSvdN8yW
# QPT9gzCCB4kwggZxoAMCAQICExIAI8GhPULglG3PUeAAAAAjwaEwDQYJKoZIhvcN
# AQELBQAwPjETMBEGCgmSJomT8ixkARkWA25ldDETMBEGCgmSJomT8ixkARkWA2Rv
# aTESMBAGA1UEAxMJRE9JSU1DQTMxMB4XDTI2MTEwNjIwMTA1OVoXDTI3MTEwNjIw
# MTA1OVowgYsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEPMA0GA1UEBxMGWWFr
# aW1hMR8wHQYDVQQKExZEZXBhcnRtZW50IG9mIEludGVyaW9yMRMwEQYDVQQDEwpT
# YW0gQ2FybWFuMSgwJgYJKoZIhvcNAQkBFhlzYW11YWxfY2FybWFuQGlvcy5kb2ku
# Z292MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAswHrlCEAF//oRE2y
# E+hgqXP9MB7F4Tzc9r1pMupaEsER6vJxyCmXsoBjHE1g/Tp7dKtls9fTagTGMd1w
# wVhCiFend30dYqF9FywoQCUvxaaAjdMb0WktLUfF/5ulJdchrcVLXfdRUDqapfQe
# 0KdficqSfyBWsND8CvUbRkyDamwelMXF8ScZV/PUJONcEIpQTS6re1l5FkmQ9uqK
# EZcJ2TbqXsEicUokcTGkcODYz0Em7fz/ZBe8BD+t23j2oBBG9ZiNtuU6OLSCvSIw
# 6k9Vj71gq4OM61ZDG6KfP3iypameMAYVW99sa9FXSjgg1bjlEqhcizFLP1g0nl7k
# d0wDqj2xejmC1EnX1FvrH0y2YEESvwUUpcRcUP7JjxvLle3nqzOJ+o83D0Bxuu6H
# HDWsPDUKW+1AaDspLTV6oj0iy3p7daES7c3TM6/4iQrYKoYKm1ujZcQK49bm3WzY
# 71WN0AiYSAB4MzBD3qDzRhepZILkN4UGiKkK1H1I5AZ+OiRWVGzVvxmyEDtKOBjB
# 27oGYTQk5dnGvCJLact0dxDADF8E5YtRR57y+jAgOuk88cadCQ0Eup9lXwT28A2j
# fHWb7LhBVGSK7ZhyLTblpCfQKc/XL0Jb6LtLuvjdnCsfPbuzZTve3jaFeNYgXki+
# 1ND0QvUdqXrxdXQqqDBK5kO/8y0CAwEAAaOCAzAwggMsMAsGA1UdDwQEAwIHgDA9
# BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiF3tVJooJoh6mHI4fdh0yDtdcogSCH
# mKZNh7yeHgIBZAIBITAdBgNVHQ4EFgQU4al/vMfOhBmsEOeH/LjW9Wy4kOswHwYD
# VR0jBBgwFoAUnXdWAF7QaXl7W8AVZ23zWfFAYFQwggEwBgNVHR8EggEnMIIBIzCC
# AR+gggEboIIBF4aBsWxkYXA6Ly8vQ049RE9JSU1DQTMxLENOPUlJTkRFTklNQ0Ez
# MSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMs
# Q049Q29uZmlndXJhdGlvbixEQz1kb2ksREM9bmV0P2NlcnRpZmljYXRlUmV2b2Nh
# dGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludIY0
# aHR0cDovL0lJTkRFTklNQ0EzMS5kb2kubmV0L0NlcnRFbnJvbGwvRE9JSU1DQTMx
# LmNybIYraHR0cDovL3BraS5kb2kubmV0L0NlcnRFbnJvbGwvRE9JSU1DQTMxLmNy
# bDCCATYGCCsGAQUFBwEBBIIBKDCCASQwgaQGCCsGAQUFBzAChoGXbGRhcDovLy9D
# Tj1ET0lJTUNBMzEsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENO
# PVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9ZG9pLERDPW5ldD9jQUNlcnRp
# ZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTBV
# BggrBgEFBQcwAoZJaHR0cDovL0lJTkRFTklNQ0EzMS5kb2kubmV0L0NlcnRFbnJv
# bGwvSUlOREVOSU1DQTMxLmRvaS5uZXRfRE9JSU1DQTMxLmNydDAkBggrBgEFBQcw
# AYYYaHR0cDovL29jc3AuZG9pLmdvdi9vY3NwMBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYBBQUHAwMwDQYJKoZIhvcNAQELBQADggEB
# AAnLSgi8PVhQIdpgzOqaSYB/d8aAqXktevievNVRDw3Ko5U6h9LnIkV5UfVLcxh1
# B13Lq3apasyt2kS4On3VWZFM4kbI1kHKPbbdUqgG2WZU+0TaWkqaKg6+9Fyh1NNt
# YWy3FYFVccC1T3MInrAhCieOnLP2oJy1o3/Szu6twPZhSTsy9zAoQlDEZUPLG3yr
# Gmm0VCVml0hsCpVpzqW+ghT3cZI6vn92QhZogL1M2xNbYzHG6Fonz6Uuyp4Cq35M
# fXT8J5kd8x14GAFLtAlEUfQ3HsfVVwvWmU4oCcrPsJFz5M0Oo6a96yYsbi3Sx9SY
# xzKVYsFh7JTvZqyqabVR8NkwggqzMIIIm6ADAgECAhNMAAAAQk/heR1/eELxAAAA
# AABCMA0GCSqGSIb3DQEBCwUAMBUxEzARBgNVBAMTCkRPSVJvb3RDQTIwHhcNMjMw
# NjI2MTkyMTIyWhcNMjgwNjI2MTkzMTIyWjA+MRMwEQYKCZImiZPyLGQBGRYDbmV0
# MRMwEQYKCZImiZPyLGQBGRYDZG9pMRIwEAYDVQQDEwlET0lJTUNBMzEwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtHqFuPS36YqB1wlzOXNTo5Zx8yylH
# WLMzZjmea2NypX7LOfM7ce8JJ88PJk32x6q746aO/9rFBIkMcpv3KfK3l/1Rp8L0
# +gMrEa5yYhCp9gwz8JG1LcXi5TdLnABc1O9E59umJ4ZZEr8CBoQh4huAcGBb001L
# 6StASEbZNNwF2fc3M1VESMp7NjCL+hDflIN4+7VPyu3ItsGroksjmAYJ/JxftmBB
# xcrMFAml/Si+WBhJJ1a+WJFFMiI28l7HGMQcIuEfeokwqBiQkCWpD1Cr0k8W6t3B
# C/cT+4j7ppk/lL/0fJP5nI32Wl2U9AxkHInsfq5ZKwi+1e2dlUxB7d7/AgMBAAGj
# ggbRMIIGzTAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQUnXdWAF7QaXl7W8AV
# Z23zWfFAYFQwggTrBgNVHSAEggTiMIIE3jCCAg4GCWCGSAFlAwIBEzCCAf8wLwYI
# KwYBBQUHAgEWI2h0dHA6Ly9wa2kyLmRvaS5uZXQvbGVnYWxwb2xpY3kuYXNwMIIB
# ygYIKwYBBQUHAgIwggG8HoIBuABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABpAHMA
# cwB1AGUAZAAgAGIAeQAgAHQAaABlACAARABlAHAAYQByAHQAbQBlAG4AdAAgAG8A
# ZgAgAHQAaABlACAASQBuAHQAZQByAGkAbwByACAAYQByAGUAIABvAG4AbAB5ACAA
# ZgBvAHIAIABpAG4AdABlAHIAbgBhAGwAIAB1AG4AYwBsAGEAcwBzAGkAZgBpAGUA
# ZAAgAFUAUwAgAEcAbwB2AGUAcgBuAG0AZQBuAHQAIAB1AHMAZQAgAGEAbABsACAA
# bwB0AGgAZQByACAAdQBzAGUAIABpAHMAIABwAHIAbwBoAGkAYgBpAHQAZQBkAC4A
# IABVAG4AYQB1AHQAaABvAHIAaQB6AGUAZAAgAHUAcwBlACAAbQBhAHkAIABzAHUA
# YgBqAGUAYwB0ACAAdgBpAG8AbABhAHQAbwByAHMAIAB0AG8AIABjAHIAaQBtAGkA
# bgBhAGwALAAgAGMAaQB2AGkAbAAgAGEAbgBkAC8AbwByACAAZABpAHMAYwBpAHAA
# bABpAG4AYQByAHkAIABhAGMAdABpAG8AbgAuMIICyAYKYIZIAWUDAgETATCCArgw
# NAYIKwYBBQUHAgEWKGh0dHA6Ly9wa2kyLmRvaS5uZXQvbGltaXRlZHVzZXBvbGlj
# eS5hc3AwggJ+BggrBgEFBQcCAjCCAnAeggJsAFUAcwBlACAAbwBmACAAdABoAGkA
# cwAgAEMAZQByAHQAaQBmAGkAYwBhAHQAZQAgAGkAcwAgAGwAaQBtAGkAdABlAGQA
# IAB0AG8AIABJAG4AdABlAHIAbgBhAGwAIABHAG8AdgBlAHIAbgBtAGUAbgB0ACAA
# dQBzAGUAIABiAHkAIAAvACAAZgBvAHIAIAB0AGgAZQAgAEQAZQBwAGEAcgB0AG0A
# ZQBuAHQAIABvAGYAIAB0AGgAZQAgAEkAbgB0AGUAcgBpAG8AcgAgAG8AbgBsAHkA
# IQAgAEUAeAB0AGUAcgBuAGEAbAAgAHUAcwBlACAAbwByACAAcgBlAGMAZQBpAHAA
# dAAgAG8AZgAgAHQAaABpAHMAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABzAGgA
# bwB1AGwAZAAgAG4AbwB0ACAAYgBlACAAdAByAHUAcwB0AGUAZAAuACAAQQBsAGwA
# IABzAHUAcwBwAGUAYwB0AGUAZAAgAG0AaQBzAHUAcwBlACAAbwByACAAYwBvAG0A
# cAByAG8AbQBpAHMAZQAgAG8AZgAgAHQAaABpAHMAIABjAGUAcgB0AGkAZgBpAGMA
# YQB0AGUAIABzAGgAbwB1AGwAZAAgAGIAZQAgAHIAZQBwAG8AcgB0AGUAZAAgAGkA
# bQBtAGUAZABpAGEAdABlAGwAeQAgAHQAbwAgAGEAIABEAGUAcABhAHIAdABtAGUA
# bgB0ACAAbwBmACAAdABoAGUAIABJAG4AdABlAHIAaQBvAHIAIABTAGUAYwB1AHIA
# aQB0AHkAIABPAGYAZgBpAGMAZQByAC4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBD
# AEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUv4Yr
# yvNsbT5fHDtOTtiN52rHak8wgfgGA1UdHwSB8DCB7TCB6qCB56CB5IaBsmxkYXA6
# Ly8vQ049RE9JUm9vdENBMixDTj1JSU5ERU5PUkNBMDEsQ049Q0RQLENOPVB1Ymxp
# YyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24s
# REM9ZG9pLERDPW5ldD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2Jq
# ZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnSGLWh0dHA6Ly9wa2kyLmRvaS5u
# ZXQvQ2VydEVucm9sbC9ET0lSb290Q0EyLmNybDBWBggrBgEFBQcBAQRKMEgwRgYI
# KwYBBQUHMAKGOmh0dHA6Ly9wa2kyLmRvaS5uZXQvQ2VydEVucm9sbC9JSU5ERU5P
# UkNBMDFfRE9JUm9vdENBMi5jcnQwDQYJKoZIhvcNAQELBQADggIBAMbtHUPT3Ocf
# H5/9kVgDdyf1HFB027B+OSxmoscIkz7DnLzO81etLLuw0V96cr860q8LzxInZOhI
# vCBng5cK9ha4qq9kawGxjT9qwUsFja6K3Ch84cchR87ftm0bedzi8OW4eCE1hp89
# 0+7Uh61tYLplfShqxVXbc6IB4bS1jO3axUw1TmypGgtnEu2poBX8pvqxyckf5H/D
# ERTFKCdmTGVX/gr4+dhaZ4CAzX88pc1GTczqBlhn0SQG3jQW1Hwz300X/liKe/Jo
# SENa6KUbxyPFiZjrPyrWuu/5M0vaul9SLrltHboX/SMety1OmnVqcBIAfO1pK3l1
# QwPDeyTy2JilsZu+7rzn0HoGA/RxspvdPvlI628mNydllpqk8PEw+/6K0fvOvOtw
# fUJftOKXFQIAUp3oaLMitII77VF+XnNyssu/FvijE7PTvrdf/p7wJdhkz3a9fNmW
# JxLCT3SppcDofYElY1fF5zxjMXDns4ZMkEzuXNQVqA+RxJSFdkN6x1CKT3h0W/GA
# zPw1UHQS4krX7xfBCN+hB8AS0VbSedkdSBnKflOSoUW9VsgFFDpTV9RLeDlbNh9h
# +eZgobVUKTZf7jcply4LsBb8nHACJz6ErFIh7ltNHZ/GlCBRP8mvYZRMAg3XgUtc
# 50DYYTKR0le9oluxLNSKnSXN6A8p7Ne4MYIGMTCCBi0CAQEwVTA+MRMwEQYKCZIm
# iZPyLGQBGRYDbmV0MRMwEQYKCZImiZPyLGQBGRYDZG9pMRIwEAYDVQQDEwlET0lJ
# TUNBMzECExIAI8GhPULglG3PUeAAAAAjwaEwDQYJYIZIAWUDBAIBBQCggYQwGAYK
# KwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIB
# BDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg
# vj8NgVi4ogKL1zkTpPFjpfSoqRUBq6gowlCjHOFZYIUwDQYJKoZIhvcNAQEBBQAE
# ggIAKJRVvZKXZn7K1ZW2upGqxXtfvgLkwlzp0VIxdCRl+0+ujgEZexiCWI7CoBlY
# NUtQ2c/z3YInGYctc9YnulopRbmYqEiaL/LuaTEEYo89k/wM9zRkestMRVH7JbqX
# x3N89vps3RDjd3/5vauDB3KbM139xdiUcDv230UtEeyxK98veRjK9FuKHPdVAJaW
# tU+WviHmDODzpKIWE1jeXnxlm9HJg4yak4YZ20zOf1JXsk8Bkv12rDjR8hK3RHq0
# eP9eWTknvBUmMGEjNGmIMwxvQigVxZT2OmCM/d+VDFbu2pu92gTAZ5KlGXvedkML
# xFoxCxeDWzBfCum+yv+hzf1yIHFfcXwVt8dXBd8BLbwT5MX0TZuna/07H6brSChd
# aDkBy7GcPclRny6hKRVcwU+Sdusb8sGFWSHHiZJj0Gw5AgcnOHmFfZMmi73mKdy5
# LkIdW2UtM3UHcDE3phvFyStQhMVHf8v/CeUzoLwdEazNCe4j/51JQvEnaoLhny3u
# IvJyBcibF8O8RQrG9tzYKLfBDSD/aTAXy+whYaSP2gZM8jeEIi2WMK9VR3rF7QAx
# Vp0UYd57r8HyQIodVW0BVmrSwx8QZG6SFEyexp59QUn8IrZhhwzWztgBs21nNGaY
# /xwCV7y9OuIFLbeMp3NRCVaOAufQ4H5eRUaro9HdUGQ1zOChggMmMIIDIgYJKoZI
# hvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0
# YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAIT9wzT35FTtvDD4/5khg1
# MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkq
# hkiG9w0BCQUxDxcNMjYxMTA2MjM1ODQ2WjAvBgkqhkiG9w0BCQQxIgQg8PjUPDKw
# CikKTZwCF2AijsMoeSRJLtdxYBpePkk7bO4wDQYJKoZIhvcNAQEBBQAEggIApNVJ
# SYupBtUgepOX4EuHD/ZEV238xu48RvyBC2HUutX5z/giQOdSgUAWYWf6Y1y2PhpV
# h4k3ahW8v3ZnW9jJwUfkYDb2uQTkSnqWzrfGlBgbtbfmLiPAgS7nMVNAbs/EKV/k
# OlZcCT1KE1UK8MeQ1dbLZGg2EGOo8SFN+oDJ9n2Gh7vIhgKoE8LCEZSFkDv9A2+r
# ZoPN6LY7/TqG/4OzhNDYNsvQpsethjsMDioOF1uaC2mPsJCAcR8g6rtqRjmUYfRh
# VCT9dVah7PTXQ/APs1ss+PKAaIzwceu8DtH93vZScvUKgjrE/dcuxCkCW1Hm8UD7
# jXOYyvt7vCVj8y6URPoW6YKUlXvNshpFBKI8G74rPM9BfghZ/huvhb1eqpv+QYr/
# E2UKXXei9rNduQlClKxQ1J5CTUjOMdwDAULC7uDoF27vfBJuTPVkDli8VPBXPBMP
# i/GtWQrd6AfMLCUCxIFAFSJBSOywts8rEDdddb+ssdLsph/eUnCDVaGUmnLD1nd/
# 6fLLVugt0yq1ksEIl1M8BEvlgTXHLZ0iIfV512jt+AYm3yqin0ax6OBX4qE0JVCi
# wUGtfdB5ET4w2ngeTVKA827znQkAKWtLLzafurRq5zLClAx/tyfQLH7zBOf83jcC
# IVw9yKHfYx6Dq/FUKMU7Ae+ycz77OFxPneXcVuw=
# SIG # End signature block
