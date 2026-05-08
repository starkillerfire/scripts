<#
.SYNOPSIS
    Fully silent ScanSnap Home v2.22.2 installer—no GUI at any stage.
.DESCRIPTION
    1. Downloads the offline installer.
    2. Uses /extract_all to unpack it (silent).
    3. Installs VC++ 2013 & 2017 redists.
    4. Runs every ScanSnap component with its .ISS file:
         /s        – silent
         /SMS       wait + suppress pop‑ups
         /f1 <iss>  feed response file (auto‑accept EULA, default paths)
         /f2 <log>  per‑component log
    5. Cleans up (unless –KeepFiles is passed).
    Logs aggregate installer output to %TEMP%.
#>

[CmdletBinding()]
param(
    [string]$SourceUrl  = 'https://origin.pfultd.com/downloads/ss/sshinst/w-2222/WinSSHOfflineInstaller_2_22_2.exe',
    [string]$WorkFolder = "$env:TEMP\ScanSnapHome_$([guid]::NewGuid().ToString('N'))",
    [switch]$KeepFiles
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# --- Paths -------------------------------------------------------------
$exePath = Join-Path $WorkFolder 'ScanSnapOffline.exe'
$logRoot = Join-Path $env:TEMP  ("ScanSnapHome-Install-{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

# --- Self‑elevate ------------------------------------------------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Prefer pwsh (PS7) when available, fall back to Windows PowerShell
    $elevatedExe = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell.exe' }
    Start-Process $elevatedExe "-NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    return
}

try {
    # 1. Download the offline bundle
    New-Item $WorkFolder -ItemType Directory -Force | Out-Null
    Invoke-WebRequest $SourceUrl -OutFile $exePath -UseBasicParsing

    # 2. Silent extraction (no GUI, no install)
    Start-Process -FilePath $exePath `
        -ArgumentList "/extract_all=`"$WorkFolder`"","/hide_progress" `
        -WindowStyle Hidden -Wait

    $root = Join-Path $WorkFolder 'SSHomeDownloadInstaller'
    if (-not (Test-Path $root)) { throw 'Extraction failed—SSHomeDownloadInstaller not found.' }

    # 3. VC++ prerequisites
    foreach ($vc in 'ms_vcredist_x86_2013','ms_vcredist_x86_2017') {
        $vcExe = Get-ChildItem (Join-Path $root "Prerequisite\$vc") -Filter *.exe
        Start-Process $vcExe.FullName -ArgumentList '/install','/quiet','/norestart' -Wait
    }

    # 4. Main ScanSnap components (silent with .ISS)
    $download   = Join-Path $root 'download'
    $payloads   = Get-ChildItem $download -Filter *.exe

    foreach ($pkg in $payloads) {
        $issPath = Join-Path $pkg.DirectoryName ($pkg.BaseName + '.iss')
        if (-not (Test-Path $issPath)) {
            Write-Warning "No ISS file for $($pkg.Name) – skipping"
            continue
        }
        $silentArgs = @('/s','/SMS',"/f1`"$issPath`"","/f2`"$logRoot`"")
        $proc = Start-Process $pkg.FullName -ArgumentList $silentArgs -WindowStyle Hidden -Wait -PassThru
        if ($proc.ExitCode -ne 0) { throw "$($pkg.Name) exited with $($proc.ExitCode)" }
    }

    Write-Host "`n✅ ScanSnap Home installed silently (EULA accepted, defaults kept)."
}
catch {
    Write-Error "❌ $($_.Exception.Message)"
}
finally {
    if (-not $KeepFiles) { Remove-Item $WorkFolder -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "Install logs: $logRoot"
}
