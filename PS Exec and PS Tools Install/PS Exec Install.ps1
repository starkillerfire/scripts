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

    This is on top of, not instead of, the Authenticode check this script always
    runs on the extracted executables (see Step 4) - that one doesn't depend on
    Sysinternals publishing anything, since Microsoft signs these binaries
    regardless of release version.

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

# --- Step 4: Verify the extracted binaries are actually signed by Microsoft ---
# This is the check that's actually always-on: PsExec grants remote code
# execution, and unlike the zip-level -ExpectedHash (which nobody can pin
# to a fixed value since Sysinternals doesn't publish official hashes and
# ships updates regularly), Microsoft signs every one of these executables
# regardless of version. There's no good reason to skip this one.
Write-Host "Verifying PsExec.exe Authenticode signature..." -ForegroundColor Cyan
$psExecPath = Join-Path $InstallPath 'PsExec.exe'
if (-not (Test-Path $psExecPath)) {
    Write-Error "PsExec.exe not found after extraction. Check $InstallPath."
    exit 1
}
$sig = Get-AuthenticodeSignature -FilePath $psExecPath
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
    Remove-Item -Path $InstallPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Error "PsExec.exe failed Authenticode validation (status: $($sig.Status); signer: $($sig.SignerCertificate.Subject)) - removing $InstallPath and aborting."
    exit 1
}
Write-Host "PsExec.exe Authenticode signature verified (Microsoft Corporation)." -ForegroundColor Green

# --- Step 5: Accept EULA (HKCU for interactive sessions, HKLM for SYSTEM/Intune) ---
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
Write-Host "PsExec installed successfully at: $psExecPath" -ForegroundColor Green
