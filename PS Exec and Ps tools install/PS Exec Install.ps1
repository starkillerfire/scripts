#Requires -RunAsAdministrator
# Script to Download, Install PsExec to C:\PSTools, and Accept EULA

# Define variables
$DownloadUrl = "https://download.sysinternals.com/files/PSTools.zip"
$OutputPath = "$env:TEMP\PSTools.zip"
$InstallPath = "C:\PSTools"

# Step 1: Download the PSTools Suite
Write-Host "Downloading PsExec from Sysinternals..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $OutputPath
    Write-Host "Download complete! File saved to: $OutputPath" -ForegroundColor Green
}
catch {
    Write-Error "Failed to download PsExec. Please check your internet connection or permissions."
    exit
}

# Step 2: Extract the PSTools to C:\PSTools
Write-Host "Extracting PSTools.zip to $InstallPath..." -ForegroundColor Cyan
try {
    if (-Not (Test-Path -Path $InstallPath)) {
        New-Item -ItemType Directory -Path $InstallPath | Out-Null
    }
    Expand-Archive -Path $OutputPath -DestinationPath $InstallPath -Force
    Write-Host "Extraction complete! Files installed to: $InstallPath" -ForegroundColor Green
}
catch {
    Write-Error "Failed to extract the archive. Check if the zip file is valid."
    exit
}

# Step 3: Automatically Accept the EULA for PsExec
# Set in both HKCU (interactive sessions) and HKLM (SYSTEM / Intune context)
Write-Host "Accepting PsExec EULA..." -ForegroundColor Cyan
try {
    foreach ($hive in @("HKCU:\Software\Sysinternals\PsExec", "HKLM:\SOFTWARE\Sysinternals\PsExec")) {
        if (-Not (Test-Path -Path $hive)) {
            New-Item -Path $hive -Force | Out-Null
        }
        Set-ItemProperty -Path $hive -Name "EulaAccepted" -Value 1
    }
    Write-Host "EULA accepted successfully!" -ForegroundColor Green
}
catch {
    Write-Error "Failed to accept the PsExec EULA. Check permissions."
    exit
}

# Step 4: Clean up the downloaded zip
Remove-Item -Path $OutputPath -Force -ErrorAction SilentlyContinue

# Step 5: Confirm Installation
if (Test-Path "$InstallPath\PsExec.exe") {
    Write-Host "PsExec is installed successfully!" -ForegroundColor Green
    Write-Host "Path: $InstallPath\PsExec.exe" -ForegroundColor Cyan
} else {
    Write-Error "PsExec.exe was not found. Installation failed."
}
