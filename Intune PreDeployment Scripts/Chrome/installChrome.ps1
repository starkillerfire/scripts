<#---------------------------------------------------------------------------
.SYNOPSIS
    Enterprise-grade Google Chrome installer / updater (v5.0.0, 2026-05-05)
---------------------------------------------------------------------------#>

#requires -RunAsAdministrator
[CmdletBinding()]
param (
    [Alias('Root')]
    [string]  $WorkingRoot          = 'C:\Patches',

    [ValidateSet('stable','beta','dev','canary')]
    [string]  $Channel              = 'stable',

    [string]  $Proxy,
    [int]     $LogRetentionDays     = 30,
    [int]     $ArchiveRetentionDays = 7,
    [int]     $CacheHours           = 4,
    [int]     $MinOsBuild           = 17763,
    [int]     $MinFreeGB            = 1,

    [switch]  $Cleanup,
    [switch]  $NoForceClose,
    [switch]  $VerboseLog,
    [switch]  $NoHashCheck,
    [switch]  $NoResume,
    [switch]  $AuditOnly,
    [switch]  $NoWinget
)

################################################################################
# 0.  Setup (guards, TLS, free-space, lock)                                   #
################################################################################
$ScriptStart = Get-Date
$ForceClose  = -not $NoForceClose
$exit        = 0

if ($VerboseLog) { $PSDefaultParameterValues['*:Verbose'] = $true }

if ([Environment]::OSVersion.Version.Build -lt $MinOsBuild) {
    Write-Error "OS build too old (< $MinOsBuild). Aborting."
    exit 30
}

Import-Module (Join-Path $PSScriptRoot '..\Common\BrowserDeploy.Common.psm1') -Force

# Disk-space guard - use drive letter directly so check works before WorkingRoot is created
try {
    $driveLetter = (Split-Path -Qualifier $WorkingRoot).TrimEnd(':')
    $freeGB      = [math]::Round((Get-PSDrive -Name $driveLetter -EA Stop).Free / 1GB, 2)
    if ($freeGB -lt $MinFreeGB) {
        Write-Error "Only $freeGB GB free on ${driveLetter}:, need >= $MinFreeGB GB."
        exit 30
    }
} catch {
    Write-Warning "Could not determine free space - continuing."
}

# TLS
if ([enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.SecurityProtocolType]::Tls13 -bor [Net.SecurityProtocolType]::Tls12
} else {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

# Proxy auto-detect
if (-not $Proxy) {
    try {
        $proxyOut = (netsh winhttp show proxy) 2>&1
        if ($proxyOut -match 'Proxy Server\W*:\W*(\S+)') { $Proxy = $Matches[1] }
    } catch { Write-Warning "Proxy auto-detection failed: $($_.Exception.Message)" }
}

# Concurrency lock
$LockPath   = Join-Path $env:TEMP 'chrome-update.lock'
$LockStream = New-SingleInstanceLock -Path $LockPath
if (-not $LockStream) {
    Write-Output 'Another Chrome-update instance is already running - exiting.'
    exit 0
}
function Close-Lock { Close-SingleInstanceLock -LockStream $LockStream -Path $LockPath }

################################################################################
# 1.  Logging and state                                                       #
################################################################################
$Software   = 'Chrome'
$DateStamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$LogDir     = Join-Path $WorkingRoot 'Logs'
$DlDir      = Join-Path $WorkingRoot $Software
$ArcDir     = Join-Path $WorkingRoot 'Archive'
$LogPath    = Join-Path $LogDir "$Software-$DateStamp.log"
$StatusJ    = Join-Path $WorkingRoot 'status.json'
$SummaryJ   = Join-Path $WorkingRoot "summary-$DateStamp.json"
$EventSrc   = 'Install-Chrome-Enterprise'

New-Item $LogDir, $DlDir, $ArcDir -ItemType Directory -Force | Out-Null
Start-Transcript -Path $LogPath -Append | Out-Null

function Write-Log {
    param (
        [string]$Message,
        [ValidateSet('Information','Warning','Error')]
        [string]$Level = 'Information'
    )
    Write-DeployLog -Message $Message -EventSource $EventSrc -EventId 2201 -Level $Level
}

# Trim old logs
Get-ChildItem $LogDir -File |
  Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-$LogRetentionDays) } |
  Remove-Item -Force -EA SilentlyContinue

# Health state
$State = if (Test-Path $StatusJ) {
    Get-Content $StatusJ -Raw | ConvertFrom-Json
} else {
    [ordered]@{ Software='Chrome'; Version=''; Result=''; Phase=''; NextRetry='' }
}
function Save-State { param($Phase) $State.Phase = $Phase; $State | ConvertTo-Json | Set-Content $StatusJ }

if ($State.NextRetry -and (Get-Date) -lt [datetime]$State.NextRetry) {
    Write-Log 'Retry window not reached - exiting.' 'Warning'
    Close-Lock; Stop-Transcript; exit 20
}

################################################################################
# 2.  Helper functions                                                        #
################################################################################

# Cache architecture detection once - avoids repeated CIM queries throughout the script
$script:IsArm = (Get-CimInstance Win32_Processor).Architecture -eq 12

function Invoke-Download {
    param ($Url, $Dest, $Sha256)
    Invoke-VerifiedDownload -Url $Url -Destination $Dest -Sha256 $Sha256 `
        -Proxy $Proxy -NoHashCheck:$NoHashCheck -NoResume:$NoResume `
        -LogAction { param($Message, $Level) Write-Log $Message $Level }
}

function Get-ChromeLatestInfo {
    param ([string]$Channel)
    $archKey = if ($script:IsArm) { 'win64-arm64' } else { 'win64' }

    $cache = Join-Path $env:TEMP "chrome-$archKey-$Channel.json"
    if ((Test-Path $cache) -and (Get-Item $cache).LastWriteTime -gt (Get-Date).AddHours(-$CacheHours)) {
        return Get-Content $cache -Raw | ConvertFrom-Json
    }

    $api = "https://versionhistory.googleapis.com/v1/chrome/" +
           "platforms/$archKey/channels/$Channel/versions?filter=endtime%3Dnone&num_versions=1"
    # Only pass -Proxy when a proxy is actually configured; an empty string causes UriFormatException
    $iwArgs = @{ Uri = $api; ErrorAction = 'Stop' }
    if ($Proxy) { $iwArgs.Proxy = $Proxy }
    $json = Invoke-RestMethod @iwArgs
    $ver  = $json.versions | Select-Object -First 1
    $file = $ver.files     | Where-Object { $_.name -like '*.msi' } | Select-Object -First 1

    $parsedVersion = try { [version]$ver.version } catch { [version]'0.0.0.0' }
    $info = [pscustomobject]@{
        Version  = $parsedVersion
        Sha256   = $file.sha256
        FileName = $file.name
    }
    $info | ConvertTo-Json | Set-Content $cache
    return $info
}

function Invoke-WingetInstall {
    param ([string]$Channel)
    $pkgMap = @{
        stable = 'Google.Chrome'
        beta   = 'Google.Chrome.Beta'
        dev    = 'Google.Chrome.Dev'
        canary = 'Google.Chrome.Canary'
    }
    $pkgId = $pkgMap[$Channel]

    $winget = Get-Command winget -EA SilentlyContinue
    if (-not $winget) {
        Write-Log 'winget not found - skipping winget path.' 'Warning'
        return $false
    }

    Write-Log "Attempting winget install: $pkgId"
    $wingetArgs = @(
        'install', '--id', $pkgId,
        '--exact', '--silent',
        '--accept-package-agreements', '--accept-source-agreements',
        '--scope', 'machine'
    )
    if ($Proxy) { $wingetArgs += '--proxy', $Proxy }

    $proc = Start-Process -FilePath $winget.Source -ArgumentList $wingetArgs -Wait -PassThru -NoNewWindow
    # 0 = success; -1978335215 (0x8A150011) = already at latest version
    if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq -1978335215) {
        Write-Log "winget succeeded (exit $($proc.ExitCode))."
        return $true
    }
    Write-Log "winget failed (exit $($proc.ExitCode)) - falling back to MSI." 'Warning'
    return $false
}

################################################################################
# 3.  Manifest lookup                                                         #
################################################################################
Save-State 'Manifest'
try { $Latest = Get-ChromeLatestInfo -Channel $Channel }
catch { Write-Log "Manifest fetch failed: $_" 'Error'; Close-Lock; Stop-Transcript; exit 20 }

# Check the property values (not the object) - $Latest is always a PSCustomObject after the try/catch
$dlName = if ($Latest.FileName) {
    $Latest.FileName
} elseif ($script:IsArm) {
    'GoogleChromeStandaloneEnterpriseArm64.msi'
} else {
    'GoogleChromeStandaloneEnterprise64.msi'
}
$dlUrl  = "https://dl.google.com/dl/chrome/install/$dlName"
$reqVer = $Latest.Version
$sha256 = if ($Latest.Sha256) { $Latest.Sha256 } else { '' }

################################################################################
# 4.  Detect installed & audit-only                                           #
################################################################################
$ChromeExe = @(
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

$curVer = if ($ChromeExe) {
    try { [version](Get-Item $ChromeExe).VersionInfo.ProductVersion }
    catch { [version]'0.0.0.0' }
} else { [version]'0.0.0.0' }

Write-Log "Installed Chrome: $curVer"

if ($AuditOnly) {
    [pscustomobject]@{ Version=$curVer; Channel=$Channel } | ConvertTo-Json | Out-Host
    Close-Lock; Stop-Transcript; exit 0
}

################################################################################
# Main deployment - do/while ($false) lets 'break' serve as goto Finish      #
################################################################################
do {

    if ($curVer -ge $reqVer -and $reqVer -ne [version]'0.0.0.0') {
        Write-Log 'Latest version already installed.'
        $State.Version = "$curVer"
        $State.Result  = 'AlreadyCurrent'
        Save-State 'Done'
        break
    }

    ##########################################################################
    # 5.  32-bit -> 64-bit migration                                         #
    ##########################################################################
    if (-not $script:IsArm -and (Test-Path "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe")) {
        Write-Log 'Uninstalling 32-bit Chrome...'
        $unKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        $chromeKey = Get-ChildItem $unKey | Where-Object {
            (Get-ItemProperty $_.PSPath).DisplayName -like 'Google Chrome*'
        } | Select-Object -First 1
        if ($chromeKey) {
            $uninstallStr = (Get-ItemProperty $chromeKey.PSPath).UninstallString
            # Parse exe and args safely - passing the raw string to cmd /c breaks on spaces/quotes
            if ($uninstallStr -match '^"?([^"]+\.exe)"?\s*(.*)$') {
                $unExe  = $Matches[1].Trim()
                $unArgs = $Matches[2].Trim()
                if ($unArgs -notmatch '/qn') { $unArgs += ' /qn' }
                Start-Process -FilePath $unExe -ArgumentList $unArgs -Wait -EA SilentlyContinue
                Start-Sleep 2
            }
        }
    }

    ##########################################################################
    # 6.  Force-close Chrome                                                 #
    ##########################################################################
    if ($ForceClose -and (Get-Process chrome -EA SilentlyContinue)) {
        Write-Log 'Closing running Chrome...'
        Get-Process chrome -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
        Start-Sleep 2
    }

    ##########################################################################
    # 7.  winget (primary install path)                                      #
    ##########################################################################
    if (-not $NoWinget) {
        Save-State 'Winget'
        if (Invoke-WingetInstall -Channel $Channel) {
            $newExe = @(
                "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
                "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
            ) | Where-Object { Test-Path $_ } | Select-Object -First 1
            $newVer = if ($newExe) {
                try { [version](Get-Item $newExe).VersionInfo.ProductVersion }
                catch { $reqVer }
            } else { $reqVer }
            $State.Version = "$newVer"
            $State.Result  = 'WingetSuccess'
            Save-State 'Done'
            break
        }
        # winget failed - fall through to MSI
    }

    ##########################################################################
    # 8.  Download (MSI fallback)                                            #
    ##########################################################################
    Save-State 'Download'
    $MsiPath = Join-Path $DlDir $dlName
    try {
        Invoke-Download -Url $dlUrl -Dest $MsiPath -Sha256 $sha256
    } catch {
        Write-Log "Download failed: $_" 'Error'
        $State.Result    = 'DownloadFail'
        $State.NextRetry = (Get-Date).AddMinutes(60)
        Save-State 'Error'
        break
    }

    ##########################################################################
    # 9.  Validate & install                                                 #
    ##########################################################################
    if ((Get-AuthenticodeSignature $MsiPath).Status -ne 'Valid') {
        Write-Log 'MSI signature invalid.' 'Error'
        $State.Result = 'BadSignature'
        Save-State 'Error'
        break
    }

    Save-State 'Install'
    $proc = Start-Process msiexec.exe `
                -ArgumentList "/i `"$MsiPath`" /qn /norestart ALLUSERS=1" `
                -Wait -PassThru
    switch ($proc.ExitCode) {
        0       { $State.Result = 'Success';         $exit = 0    }
        3010    { $State.Result = 'RebootRequired';  $exit = 3010 }
        1641    { $State.Result = 'InstallerReboot'; $exit = 1641 }
        default { $State.Result = "Error_$($proc.ExitCode)"; $exit = 30 }
    }
    Write-Log "Install result: $($State.Result)"
    $State.Version = "$reqVer"

    # Archive or remove the MSI - these are mutually exclusive; the original moved first
    # then tried to Remove-Item the already-moved file, making -Cleanup a no-op
    Save-State 'Archive'
    $dayDir = Join-Path $ArcDir (Get-Date -Format 'yyyyMMdd')
    New-Item $dayDir -ItemType Directory -Force | Out-Null
    if ($Cleanup) {
        Remove-Item $MsiPath -Force -EA SilentlyContinue
    } else {
        Move-Item $MsiPath -Destination $dayDir -Force -EA SilentlyContinue
    }
    Get-ChildItem $ArcDir -Directory |
      Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-$ArchiveRetentionDays) } |
      Remove-Item -Recurse -Force -EA SilentlyContinue

} while ($false)

################################################################################
# 10.  Finish & telemetry                                                     #
################################################################################
Save-State 'Done'

[pscustomobject]@{
    Machine   = $env:COMPUTERNAME
    Result    = $State.Result
    Version   = "$($State.Version)"
    Channel   = $Channel
    ElapsedMs = [int]((Get-Date) - $ScriptStart).TotalMilliseconds
} | ConvertTo-Json | Set-Content $SummaryJ

Write-Log 'Chrome deployment complete.'
Stop-Transcript | Out-Null
Close-Lock
exit $exit
