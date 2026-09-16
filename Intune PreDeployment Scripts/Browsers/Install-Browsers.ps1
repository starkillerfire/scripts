#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Consolidated local install/update for Chrome, Edge, and Firefox - replaces
    installChrome.ps1, Edge.ps1, and NewImageInstalls.ps1's inline Install-Chrome/
    Install-Edge duplicates with one implementation.

.DESCRIPTION
    Installs/updates one or more browsers on THIS machine (not a remote fleet-push
    tool - see Chrome\ and Edge\ at the repo root for the PsExec-based remote
    pushers, which this does not replace).

    For each selected browser: skips if already at the latest version, otherwise
    tries winget first, then falls back to downloading the vendor's official MSI
    directly and installing via msiexec. The downloaded MSI's Authenticode
    signature is verified against the expected publisher unconditionally before
    it's ever run - this is the real integrity gate (SHA-256 verification only
    happens when the vendor's feed publishes a hash, which Chrome and Edge do and
    Firefox currently doesn't).

    Shares BrowserDeploy.Common.psm1 (single-instance locking, adaptive BITS
    download with hash verification, event-log-backed logging) with the rest of
    the Intune PreDeployment pipeline, instead of reimplementing it a third time.

.PARAMETER Browser
    One or more of Chrome, Edge, Firefox. If omitted and the session is
    interactive, shows a menu to pick from. If omitted and the session is NOT
    interactive (e.g. invoked unattended by MasterInstaller.ps1/NewImageInstalls.ps1),
    throws rather than hanging on a prompt nothing will ever answer.

.PARAMETER WorkingRoot
    Root folder for downloaded installers. Defaults to C:\Patches.

.PARAMETER Proxy
    Explicit proxy to use for downloads. Auto-detected from WinHTTP settings when
    not supplied.

.PARAMETER Cleanup
    Delete the downloaded MSI after a successful install instead of leaving it in
    WorkingRoot.

.PARAMETER NoWinget
    Skip the winget path entirely and go straight to the direct-MSI-download
    fallback for every selected browser.

.EXAMPLE
    .\Install-Browsers.ps1
    Interactive - shows the menu.

.EXAMPLE
    .\Install-Browsers.ps1 -Browser Chrome
    Non-interactive - installs/updates Chrome only, no menu.

.EXAMPLE
    .\Install-Browsers.ps1 -Browser Chrome,Edge,Firefox
    Non-interactive - installs/updates all three.

.NOTES
    Exit codes match the rest of the Intune PreDeployment pipeline: 0 success,
    3010/1641 success-reboot-required, 1 one or more browsers failed.
#>
[CmdletBinding()]
param(
    [ValidateSet('Chrome', 'Edge', 'Firefox')]
    [string[]] $Browser,
    [string]   $WorkingRoot = 'C:\Patches',
    [string]   $Proxy,
    [int]      $CacheHours  = 4,
    [switch]   $NoHashCheck,
    [switch]   $NoResume,
    [switch]   $Cleanup,
    [switch]   $NoWinget
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\Common\BrowserDeploy.Common.psm1') -Force

################################################################################
# Setup: TLS, proxy auto-detect, disk-space guard                             #
################################################################################

if ((([Net.ServicePointManager]::SecurityProtocol) -band 3072) -eq 0) { [Net.ServicePointManager]::SecurityProtocol += 3072 }

if (-not $Proxy) {
    try {
        $proxyOut = (netsh winhttp show proxy) 2>&1
        if ($proxyOut -match 'Proxy Server\W*:\W*(\S+)') { $Proxy = $Matches[1] }
    } catch { Write-Warning "Proxy auto-detection failed: $($_.Exception.Message)" }
}

New-Item -Path $WorkingRoot -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
try {
    $driveLetter = (Split-Path -Qualifier $WorkingRoot).TrimEnd(':')
    $freeGB      = [math]::Round((Get-PSDrive -Name $driveLetter -ErrorAction Stop).Free / 1GB, 2)
    if ($freeGB -lt 1) {
        Write-Error "Only $freeGB GB free on ${driveLetter}: - need at least 1 GB. Aborting."
        exit 1
    }
} catch { Write-Warning "Could not determine free space on $WorkingRoot - continuing." }

################################################################################
# Browser selection: explicit -Browser, or an interactive menu               #
################################################################################

function Show-BrowserMenu {
    if (-not [Environment]::UserInteractive) {
        throw 'No -Browser specified and this session is not interactive (e.g. running unattended under Intune/SYSTEM) - pass -Browser explicitly instead of relying on the menu.'
    }
    Write-Host ''
    Write-Host 'Select browser(s) to install/update:' -ForegroundColor Cyan
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
# Per-browser definitions and shared install engine                           #
################################################################################
# The version-feed lookups (Get-ChromeLatestInfo/Get-EdgeLatestInfo/
# Get-FirefoxLatestInfo) live in BrowserDeploy.Common.psm1, shared with
# Browsers\Push-Browsers.ps1 (repo root) - the remote PsExec-push counterpart
# to this local installer - rather than duplicated in both.

$BrowserDefs = @{
    Chrome  = @{
        WingetId      = 'Google.Chrome'
        SignerPattern = 'O=Google LLC'
        ProcessName   = 'chrome'
        ExePaths      = @(
            "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
            "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
        )
        GetLatestInfo = { Get-ChromeLatestInfo -Proxy $Proxy -CacheHours $CacheHours }
        MsiExtraArgs  = 'ALLUSERS=1'
    }
    Edge    = @{
        WingetId      = 'Microsoft.Edge'
        SignerPattern = 'O=Microsoft Corporation'
        ProcessName   = 'msedge'
        ExePaths      = @(
            "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
            "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
        )
        GetLatestInfo = { Get-EdgeLatestInfo -Proxy $Proxy -CacheHours $CacheHours }
        MsiExtraArgs  = ''
    }
    Firefox = @{
        WingetId      = 'Mozilla.Firefox'
        SignerPattern = 'O=Mozilla Corporation'
        ProcessName   = 'firefox'
        ExePaths      = @(
            "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
            "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
        )
        GetLatestInfo = { Get-FirefoxLatestInfo -Proxy $Proxy -CacheHours $CacheHours }
        MsiExtraArgs  = ''
    }
}

function Install-OneBrowser {
    param([Parameter(Mandatory)][ValidateSet('Chrome', 'Edge', 'Firefox')][string]$Name)

    $def      = $BrowserDefs[$Name]
    $EventSrc = "Install-Browsers-$Name"
    $LockPath = Join-Path $env:TEMP "installbrowsers-$($Name.ToLower()).lock"

    $LockStream = New-SingleInstanceLock -Path $LockPath
    if (-not $LockStream) {
        Write-DeployLog -Message "Another $Name install/update is already running - skipping." -EventSource $EventSrc -Level Warning
        return [pscustomobject]@{ Browser = $Name; Result = 'AlreadyRunning'; ExitCode = 0 }
    }

    try {
        Write-DeployLog -Message "=== $Name install/update started ===" -EventSource $EventSrc

        $exePath = $def.ExePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
        $curVer  = if ($exePath) {
            try { [version](Get-Item $exePath).VersionInfo.ProductVersion } catch { [version]'0.0.0.0' }
        } else { [version]'0.0.0.0' }
        Write-DeployLog -Message "Installed ${Name}: $curVer" -EventSource $EventSrc

        try {
            $latest = & $def.GetLatestInfo
        } catch {
            Write-DeployLog -Message "Version lookup failed: $_" -EventSource $EventSrc -Level Error
            return [pscustomobject]@{ Browser = $Name; Result = 'ManifestFail'; ExitCode = 1 }
        }

        if ($curVer -ge $latest.Version -and $latest.Version -ne [version]'0.0.0.0') {
            Write-DeployLog -Message "$Name already current ($curVer)." -EventSource $EventSrc
            return [pscustomobject]@{ Browser = $Name; Result = 'AlreadyCurrent'; ExitCode = 0 }
        }

        if (Get-Process -Name $def.ProcessName -ErrorAction SilentlyContinue) {
            Write-DeployLog -Message "Closing running $Name..." -EventSource $EventSrc
            Get-Process -Name $def.ProcessName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }

        if (-not $NoWinget) {
            $winget = Get-Command winget -ErrorAction SilentlyContinue
            if ($winget) {
                Write-DeployLog -Message "Attempting winget install: $($def.WingetId)" -EventSource $EventSrc
                $wingetArgs = @('install', '--id', $def.WingetId, '--exact', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--scope', 'machine')
                if ($Proxy) { $wingetArgs += '--proxy', $Proxy }
                $proc = Start-Process -FilePath $winget.Source -ArgumentList $wingetArgs -Wait -PassThru -NoNewWindow
                # 0 = success; -1978335215 (0x8A150011) = already at latest version
                if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq -1978335215) {
                    Write-DeployLog -Message "winget succeeded (exit $($proc.ExitCode))." -EventSource $EventSrc
                    return [pscustomobject]@{ Browser = $Name; Result = 'WingetSuccess'; ExitCode = 0 }
                }
                Write-DeployLog -Message "winget failed (exit $($proc.ExitCode)) - falling back to direct MSI install." -EventSource $EventSrc -Level Warning
            } else {
                Write-DeployLog -Message 'winget not found - using direct MSI install.' -EventSource $EventSrc
            }
        }

        $dlDir   = Join-Path $WorkingRoot $Name
        New-Item -Path $dlDir -ItemType Directory -Force | Out-Null
        $msiPath = Join-Path $dlDir $latest.FileName

        try {
            Invoke-VerifiedDownload -Url $latest.Url -Destination $msiPath -Sha256 $latest.Sha256 `
                -Proxy $Proxy -NoHashCheck:$NoHashCheck -NoResume:$NoResume `
                -LogAction { param($Message, $Level) Write-DeployLog -Message $Message -EventSource $EventSrc -Level $Level }
        } catch {
            Write-DeployLog -Message "Download failed: $_" -EventSource $EventSrc -Level Error
            return [pscustomobject]@{ Browser = $Name; Result = 'DownloadFail'; ExitCode = 1 }
        }

        # Unconditional - independent of the hash check above, which silently
        # no-ops when a feed doesn't publish one (e.g. Firefox's). Without
        # this, an artifact with no published hash would run as SYSTEM with
        # zero integrity verification at all.
        $sig = Get-AuthenticodeSignature -FilePath $msiPath
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch [regex]::Escape($def.SignerPattern)) {
            Remove-Item -Path $msiPath -Force -ErrorAction SilentlyContinue
            Write-DeployLog -Message "Installer failed Authenticode validation (status: $($sig.Status)) - refusing to run it." -EventSource $EventSrc -Level Error
            return [pscustomobject]@{ Browser = $Name; Result = 'BadSignature'; ExitCode = 1 }
        }
        Write-DeployLog -Message "Installer Authenticode signature verified ($($def.SignerPattern)): $msiPath" -EventSource $EventSrc

        $msiArgs = "/i `"$msiPath`" /qn /norestart"
        if ($def.MsiExtraArgs) { $msiArgs += " $($def.MsiExtraArgs)" }
        $proc = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru

        $result = switch ($proc.ExitCode) {
            0       { 'Success' }
            3010    { 'RebootRequired' }
            1641    { 'InstallerReboot' }
            default { "Error_$($proc.ExitCode)" }
        }
        $level = if ($result -like 'Error_*') { 'Error' } else { 'Information' }
        Write-DeployLog -Message "Install result: $result (exit $($proc.ExitCode))" -EventSource $EventSrc -Level $level

        if ($Cleanup) { Remove-Item -Path $msiPath -Force -ErrorAction SilentlyContinue }

        $exitCode = if ($proc.ExitCode -in 0, 3010, 1641) { $proc.ExitCode } else { 1 }
        return [pscustomobject]@{ Browser = $Name; Result = $result; ExitCode = $exitCode }
    } catch {
        Write-DeployLog -Message "Unexpected error: $_" -EventSource $EventSrc -Level Error
        return [pscustomobject]@{ Browser = $Name; Result = 'UnexpectedError'; ExitCode = 1 }
    } finally {
        Close-SingleInstanceLock -LockStream $LockStream -Path $LockPath
    }
}

################################################################################
# Main                                                                        #
################################################################################

$results = foreach ($b in $Browser) { Install-OneBrowser -Name $b }

Write-Host ''
foreach ($r in $results) {
    $color = if ($r.ExitCode -eq 0) { 'Green' } elseif ($r.ExitCode -in 3010, 1641) { 'Yellow' } else { 'Red' }
    Write-Host "$($r.Browser): $($r.Result)" -ForegroundColor $color
}

$anyFailed = @($results | Where-Object { $_.ExitCode -eq 1 }).Count -gt 0
$anyReboot = @($results | Where-Object { $_.ExitCode -in 3010, 1641 }).Count -gt 0

if ($anyFailed) { exit 1 }
elseif ($anyReboot) { exit 3010 }
else { exit 0 }
