# Ensure the script runs as Administrator
$CurrentUser = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$AdminRole = [Security.Principal.WindowsBuiltInRole]::Administrator

if (-not $CurrentUser.IsInRole($AdminRole)) {
    Write-Host "Restarting script as Administrator..."
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Define the registry path
$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"

# Check if the registry key exists
if (Test-Path $RegistryPath) {
    Write-Host "Registry key found: $RegistryPath"

    # Modify the 'Enabled' value if it exists
    if (Get-ItemProperty -Path $RegistryPath -Name "Enabled" -ErrorAction SilentlyContinue) {
        Set-ItemProperty -Path $RegistryPath -Name "Enabled" -Value 0
        Write-Host "Set 'Enabled' to 0"
    }

    # Modify the 'WasEnabledBy' value if it exists
    if (Get-ItemProperty -Path $RegistryPath -Name "WasEnabledBy" -ErrorAction SilentlyContinue) {
        Set-ItemProperty -Path $RegistryPath -Name "WasEnabledBy" -Value 0
        Write-Host "Set 'WasEnabledBy' to 0"
    }

    # Prompt for system restart
    $Restart = Read-Host "Changes have been made. Do you want to restart now? (Y/N)"
    if ($Restart -eq "Y" -or $Restart -eq "y") {
        Restart-Computer -Force
    } else {
        Write-Host "Please restart your computer for the changes to take effect."
    }
} else {
    Write-Host "Registry key not found: $RegistryPath. No changes made."
}
