#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Download PSTools, extract to C:\PSTools, and pre-accept the PsExec EULA.

.PARAMETER DownloadUrl
    URL of the PSTools zip. Defaults to the official Sysinternals download.

.PARAMETER InstallPath
    Destination folder. Defaults to C:\PSTools.

.PARAMETER ExpectedHash
    Optional SHA-256 hash of the zip. When supplied, the download is verified before
    extraction. Sysinternals does not publish hashes officially, but you can capture
    the hash of a known-good copy and pass it here for integrity checking.

.EXAMPLE
    .\PS Exec Install.ps1
    .\PS Exec Install.ps1 -InstallPath D:\Tools\PSTools
    .\PS Exec Install.ps1 -ExpectedHash 'ABC123...'
#>
[CmdletBinding()]
param(
    [string] $DownloadUrl  = 'https://download.sysinternals.com/files/PSTools.zip',
    [string] $InstallPath  = 'C:\PSTools',
    [string] $ExpectedHash = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Enforce TLS 1.2 for the download
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$zipPath = Join-Path $env:TEMP 'PSTools.zip'

# --- Step 1: Download ---
Write-Host "Downloading PSTools from Sysinternals..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
    Write-Host "Download complete: $zipPath" -ForegroundColor Green
} catch {
    Write-Error "Download failed: $($_.Exception.Message)"
    exit 1
}

# --- Step 2: Hash verification (optional) ---
if ($ExpectedHash) {
    Write-Host "Verifying SHA-256 hash..." -ForegroundColor Cyan
    $actual = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash
    if ($actual -ne $ExpectedHash.ToUpperInvariant()) {
        Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
        Write-Error "Hash mismatch! Expected: $ExpectedHash`n  Actual: $actual`nDownload aborted."
        exit 1
    }
    Write-Host "Hash verified." -ForegroundColor Green
} else {
    Write-Warning "No -ExpectedHash supplied. Skipping integrity check."
}

# --- Step 3: Extract ---
Write-Host "Extracting to $InstallPath..." -ForegroundColor Cyan
try {
    if (-not (Test-Path $InstallPath)) { New-Item -ItemType Directory -Path $InstallPath | Out-Null }
    Expand-Archive -Path $zipPath -DestinationPath $InstallPath -Force
    Write-Host "Extraction complete." -ForegroundColor Green
} catch {
    Write-Error "Extraction failed: $($_.Exception.Message)"
    exit 1
} finally {
    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
}

# --- Step 4: Accept EULA (HKCU for interactive sessions, HKLM for SYSTEM/Intune) ---
Write-Host "Accepting PsExec EULA..." -ForegroundColor Cyan
foreach ($hive in @('HKCU:\Software\Sysinternals\PsExec', 'HKLM:\SOFTWARE\Sysinternals\PsExec')) {
    try {
        if (-not (Test-Path $hive)) { New-Item -Path $hive -Force | Out-Null }
        Set-ItemProperty -Path $hive -Name EulaAccepted -Value 1 -Type DWord -Force
    } catch {
        Write-Warning "Could not set EULA in ${hive}: $($_.Exception.Message)"
    }
}
Write-Host "EULA accepted." -ForegroundColor Green

# --- Step 5: Confirm ---
$exe = Join-Path $InstallPath 'PsExec.exe'
if (Test-Path $exe) {
    Write-Host "PsExec installed successfully at: $exe" -ForegroundColor Green
} else {
    Write-Error "PsExec.exe not found after extraction. Check $InstallPath."
    exit 1
}
