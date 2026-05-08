# Ensure the script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    exit
}

Write-Host "Scanning for RSAT features..." -ForegroundColor Cyan

# Get all RSAT features that are not installed
$rsatFeatures = Get-WindowsCapability -Online | Where-Object {
    $_.Name -like "Rsat.*" -and $_.State -ne "Installed"
}

if (@($rsatFeatures).Count -eq 0) {
    Write-Host "All RSAT features are already installed." -ForegroundColor Green
    exit
}

# Install each RSAT feature
foreach ($feature in $rsatFeatures) {
    Write-Host "Installing $($feature.Name)..." -ForegroundColor Yellow
    try {
        Add-WindowsCapability -Online -Name $feature.Name -ErrorAction Stop
        Write-Host "$($feature.Name) installed successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to install $($feature.Name): $_" -ForegroundColor Red
    }
}

Write-Host "RSAT installation complete." -ForegroundColor Cyan
