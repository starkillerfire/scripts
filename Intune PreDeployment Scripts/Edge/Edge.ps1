<#
.SYNOPSIS
    Enterprise-grade Microsoft Edge (Chromium) installer / updater - Windows 11 (PowerShell 5.x)
    Version 3.3  (2025-06-12)

    KEY FEATURES
      • Mutex lock-file (CreateNew) with guaranteed release (try/finally)
      • TLS 1.2 enforced (TLS 1.3 appended when available) + WinHTTP proxy auto-detect
      • Disk-space guard (≥ 1 GB free on WorkingRoot drive)
      • Adaptive BITS priority (VPN-aware, foreground/high/low)
      • SHA-256 integrity check (optional CA thumbprint pin with -PinnedThumbprint)
      • Feed-based version lookup (Stable / Beta / Dev / Canary) with retry logic
      • Health status.json with exponential retry back-off
      • Switches: -AuditOnly -NoHashCheck -NoResume -Cleanup -VerboseLog
      • Automatically force-closes Edge if running
      • Custom exit codes: 0 Success  10 Reboot  20 DownloadFail  30 OtherError
      • Event IDs: 2301 Start  2302 DownloadFail  2303 HashFail  2304 Success  2305 NoUpdate
      • Log rotation with ZIP compression; transcript compressed after run
      • JSON result includes installer SHA-256
.NOTES
    Author  : Samual Carman
    Tested  : PowerShell 5.1 • Windows 11 22H2 / 23H2
#>

#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Alias('Cfg')]  [string]$ConfigPath,
    [Alias('Root')][ValidateScript({ Test-Path (Split-Path $_ -Qualifier) })] [string]$WorkingRoot = 'C:\Patches',
    [ValidateSet('Stable','Beta','Dev','Canary')] [string]$Channel = 'Stable',
    [string]$Proxy,
    [ValidateRange(1,365)] [int]$LogRetentionDays     = 30,
    [ValidateRange(1,365)] [int]$ArchiveRetentionDays = 7,
    [ValidateRange(1,168)] [int]$CacheHours           = 4,
    [int]$MinOsBuild = 22000,   # Windows 11 GA build

    [switch]$Cleanup,
    [switch]$VerboseLog,
    [switch]$NoHashCheck,
    [switch]$NoResume,
    [switch]$AuditOnly,
    [string]$PinnedThumbprint = ''
)

# Script-wide defaults
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#############################  ENUM / CONSTANTS  #############################

enum DeployExit { Success = 0; Reboot = 10; DownloadFail = 20; OtherError = 30 }

$EventSource = 'Install-Edge-Enterprise'
$EvtStart    = 2301
$EvtDLFail   = 2302
$EvtHashFail = 2303
$EvtSuccess  = 2304
$EvtNoUpdate = 2305

########################## 0. PARAMETER VALIDATION ###########################

if ($AuditOnly -and $Cleanup) { throw '-AuditOnly cannot be combined with install-time actions' }

########################## 1. JSON CONFIG MERGE ##############################

if ($ConfigPath -and (Test-Path $ConfigPath)) {
    (Get-Content $ConfigPath -Raw | ConvertFrom-Json).PSObject.Properties |
        Where-Object { -not $PSBoundParameters.ContainsKey($_.Name) } |
        ForEach-Object { Set-Variable -Name $_.Name -Value $_.Value -Scope Script }
}

########################## 2. PREREQUISITES ##################################

if ($VerboseLog) { $PSDefaultParameterValues['*:Verbose'] = $true }
if ([Environment]::OSVersion.Version.Build -lt $MinOsBuild) {
    Write-Error "OS build too old (<$MinOsBuild). Aborting."; exit [DeployExit]::OtherError }

Import-Module (Join-Path $PSScriptRoot '..\Common\BrowserDeploy.Common.psm1') -Force

$sslProto = [System.Net.SecurityProtocolType]::Tls12
try { $sslProto = $sslProto -bor [System.Net.SecurityProtocolType]::Tls13 } catch {}
[System.Net.ServicePointManager]::SecurityProtocol = $sslProto

if (-not $Proxy) {
    try {
        $winhttp = (netsh winhttp show proxy) 2>&1
        if ($winhttp -match 'Proxy Server') { $Proxy = ($winhttp -split ': ')[1].Trim() }
    } catch {}
}

######################### 3. SINGLE-INSTANCE LOCK ############################

$LockFile   = Join-Path $env:TEMP 'edge-update.lock'
$LockStream = New-SingleInstanceLock -Path $LockFile
if (-not $LockStream) { Write-Output 'Another Edge update already running. Exiting.'; exit [DeployExit]::Success }
function Close-Lock { Close-SingleInstanceLock -LockStream $LockStream -Path $LockFile }

######################### 4. HELPER FUNCTIONS ###############################

function Write-Log {
    param([string]$Message,[int]$EventId,[ValidateSet('Information','Warning','Error')][string]$Level='Information')
    Write-DeployLog -Message $Message -EventSource $EventSource -EventId $EventId -Level $Level
}

function Invoke-EdgeDownload {
    param([string]$Url,[string]$Dest,[string]$Sha256)
    # -CheckVpnForBitsPriority preserves this script's original VPN-aware
    # priority selection (prefer Foreground on a VPN link).
    Invoke-VerifiedDownload -Url $Url -Destination $Dest -Sha256 $Sha256 `
        -Proxy $Proxy -NoHashCheck:$NoHashCheck -NoResume:$NoResume -CheckVpnForBitsPriority `
        -LogAction { param($Message, $Level) Write-Log $Message $EvtDLFail $Level }
}

############################# 5. MAIN #######################################
try {
    # 5.1 Disk guard
    # Split-Path -Qualifier returns "C:" (with the colon); Get-PSDrive -Name
    # wants just "C" and throws DriveNotFoundException otherwise - this
    # crashed on the very first line of every single run.
    $drive = Get-PSDrive -Name (Split-Path $WorkingRoot -Qualifier).TrimEnd(':')
    if ($drive.Free -lt 1GB) { Write-Log 'Insufficient disk space (<1 GB).' $EvtHashFail 'Error'; exit [DeployExit]::OtherError }

    # 5.2 Paths
    $Now      = Get-Date -Format 'yyyyMMdd-HHmmss'
    $Software = 'Edge'
    $LogDir   = Join-Path $WorkingRoot 'Logs'
    $DlDir    = Join-Path $WorkingRoot $Software
    $LogPath  = Join-Path $LogDir "$Software-$Now.log"
    $StatusJs = Join-Path $WorkingRoot 'status.json'

    New-Item $LogDir,$DlDir -ItemType Directory -Force | Out-Null
    try { Start-Transcript -Path $LogPath -Append | Out-Null } catch { Write-Warning "Transcript failed: $_" }

    # 5.3 Rotate logs
    Get-ChildItem $LogDir -Directory | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-$LogRetentionDays) } |
        ForEach-Object {
            Compress-Archive -Path (Join-Path $_.FullName '*') -DestinationPath "$($_.FullName).zip" -Force
            Remove-Item $_ -Recurse -Force
        }
    Get-ChildItem $LogDir -Filter '*.zip' | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-$ArchiveRetentionDays) } | Remove-Item -Force

    # 5.4 Status helpers
    $State = if (Test-Path $StatusJs) { Get-Content $StatusJs -Raw | ConvertFrom-Json } else { [ordered]@{Software=$Software;Version='';Result='';Phase='';Retry=0;NextRetry='';Hash=''} }
    function Save-State([string]$Phase) { $State.Phase = $Phase; $State | ConvertTo-Json | Set-Content $StatusJs }
    if ($State.NextRetry -and (Get-Date) -lt [datetime]$State.NextRetry) { Write-Log 'Retry delay active - exiting.' $EvtDLFail 'Warning'; exit [DeployExit]::DownloadFail }

    # 5.5 Manifest lookup
    Save-State 'Manifest'
    $Arch = if ($Env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }
    $FeedUrl = 'https://edgeupdates.microsoft.com/api/products?view=enterprise'
    $Feed    = $null
    for ($i = 1; $i -le 3; $i++) {
        try { $Feed = Invoke-RestMethod $FeedUrl -Proxy $Proxy -TimeoutSec 15; break }
        catch {
            if ($i -eq 3) {
                Write-Log "Feed fetch failed: $_" $EvtDLFail 'Error'
                $State.Retry++; $State.NextRetry = (Get-Date).AddMinutes([math]::Pow(2,$State.Retry)*30); Save-State 'Error'
                exit [DeployExit]::DownloadFail
            }
            Start-Sleep ([math]::Pow(2,$i))
        }
    }

    # The real edgeupdates.microsoft.com response is a flat array of
    # { Product, Releases: [ { Platform, Architecture, ProductVersion,
    # Artifacts: [ { ArtifactName, Location, Hash } ] } ] } - not the
    # {products:[{name,releases:[{channel,build,artifacts:[{platform,type,
    # location,hashSHA256}]}]}]} shape this used to assume, which meant
    # $Rel was always $null and the next line threw on every run.
    $channelObj = $Feed | Where-Object { $_.Product -eq $Channel }
    if (-not $channelObj) {
        Write-Log "Channel '$Channel' not found in Edge Updates API response." $EvtDLFail 'Error'
        $State.Retry++; $State.NextRetry = (Get-Date).AddMinutes([math]::Pow(2,$State.Retry)*30); Save-State 'Error'
        exit [DeployExit]::DownloadFail
    }
    $Rel = $channelObj.Releases | Where-Object { $_.Platform -eq 'Windows' -and $_.Architecture -eq $Arch } |
           Sort-Object { [version]$_.ProductVersion } -Descending | Select-Object -First 1
    if (-not $Rel) {
        Write-Log "No Edge release found for Platform=Windows/Architecture=$Arch." $EvtDLFail 'Error'
        $State.Retry++; $State.NextRetry = (Get-Date).AddMinutes([math]::Pow(2,$State.Retry)*30); Save-State 'Error'
        exit [DeployExit]::DownloadFail
    }
    $Pkg = $Rel.Artifacts | Where-Object { $_.Location -match '\.msi$' } | Select-Object -First 1
    if (-not $Pkg) {
        Write-Log 'No MSI artifact found for the latest Edge release.' $EvtDLFail 'Error'
        $State.Retry++; $State.NextRetry = (Get-Date).AddMinutes([math]::Pow(2,$State.Retry)*30); Save-State 'Error'
        exit [DeployExit]::DownloadFail
    }
    $Latest    = [version]$Rel.ProductVersion
    $Url       = $Pkg.Location
    $Sha       = $Pkg.Hash
    $Installer = Join-Path $DlDir ([IO.Path]::GetFileName($Url))

    # 5.6 Current install
    Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' -Name UpdateDefault -ErrorAction SilentlyContinue
    $Exe     = "${Env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    $Current = if (Test-Path $Exe) { [version](Get-Item $Exe).VersionInfo.ProductVersion } else { [version]'0.0.0.0' }
    Write-Log "Installed Edge: $Current" $EvtStart

    if ($AuditOnly) {
        [pscustomobject]@{Installed=$Current;Latest=$Latest;Channel=$Channel;InstallerSHA=$Sha} | ConvertTo-Json | Out-Host
        exit [DeployExit]::Success
    }
    if ($Current -ge $Latest) {
        Write-Log 'Edge already current.' $EvtNoUpdate
        $State.Version="$Current";$State.Result='AlreadyCurrent';$State.Hash=$Sha;Save-State 'Done'
        Write-Output ($State | ConvertTo-Json -Compress)
        exit [DeployExit]::Success
    }

    # 5.7 Force-close any running Edge
    Get-Process msedge -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Log 'Closing running Edge instances…' $EvtStart
        $_ | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    # 5.8 Download installer
    Save-State 'Download'
    try { Invoke-EdgeDownload -Url $Url -Dest $Installer -Sha256 $Sha }
    catch {
        Write-Log 'Permanent download failure.' $EvtDLFail 'Error'
        $State.Retry++;$State.NextRetry=(Get-Date).AddMinutes([math]::Pow(2,$State.Retry)*30);Save-State 'Error'
        exit [DeployExit]::DownloadFail
    }

    # 5.9 Authenticode verification
    # Unconditional - independent of -PinnedThumbprint (which is opt-in and
    # empty by default) and of the hash check in Invoke-VerifiedDownload
    # (which silently skips if the feed's Hash field is empty). Without
    # this, an artifact with no Hash and no pinned thumbprint would run as
    # SYSTEM with zero integrity verification at all.
    $Sig = Get-AuthenticodeSignature $Installer
    if ($Sig.Status -ne 'Valid' -or $Sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        Write-Log "Installer failed Authenticode validation (status: $($Sig.Status))." $EvtHashFail 'Error'
        exit [DeployExit]::OtherError
    }
    if ($PinnedThumbprint -and $Sig.SignerCertificate.IssuerThumbprint -ne $PinnedThumbprint) {
        Write-Log 'Certificate pin check failed.' $EvtHashFail 'Error'; exit [DeployExit]::OtherError
    }
    Unblock-File $Installer

    # 5.10 Install
    Save-State 'Install'
    Write-Log 'Launching Edge installer…' $EvtStart
    $p = Start-Process msiexec.exe -ArgumentList '/i', $Installer, '/qn', '/norestart' -Wait -PassThru
    switch ($p.ExitCode) {
        0 { $Res='Success';$Exit=[DeployExit]::Success }
        3010 { $Res='RebootRequired';$Exit=[DeployExit]::Reboot }
        1641 { $Res='InstallerReboot';$Exit=[DeployExit]::Reboot }
        default { $Res="Error_$($p.ExitCode)";$Exit=[DeployExit]::OtherError }
    }
    $State.Version="$Latest";$State.Result=$Res;$State.Hash=$Sha;Save-State 'Done'
    Write-Log "Installer exited with code $($p.ExitCode) ($Res)" $EvtSuccess

    # 5.11 Cleanup
    if ($Cleanup -and (Test-Path $Installer)) { Remove-Item $Installer -Force -EA SilentlyContinue }

    # Compress transcript
    try { Stop-Transcript | Out-Null; Compress-Archive -Path $LogPath -DestinationPath "$LogPath.zip" -Force; Remove-Item $LogPath -Force }
    catch { Write-Warning "Transcript compression failed: $_" }

    Close-Lock
    Write-Output ($State | ConvertTo-Json -Compress)
    exit $Exit
}
finally { Close-Lock }
