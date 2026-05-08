#Requires -RunAsAdministrator
# Disable Memory Integrity (HVCI) for Red Lion compatibility.

$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"

if (-not (Test-Path $RegistryPath)) {
    Write-Host "Registry key not found: $RegistryPath" -ForegroundColor Yellow
    Write-Host "Memory Integrity may not be configured on this machine — nothing to disable."
    exit 0
}

try {
    Set-ItemProperty -Path $RegistryPath -Name "Enabled"     -Value 0 -ErrorAction Stop
    Set-ItemProperty -Path $RegistryPath -Name "WasEnabledBy" -Value 0 -ErrorAction Stop
    Write-Host "Memory Integrity disabled successfully." -ForegroundColor Green
    Write-Host "Restart your computer for the changes to take effect." -ForegroundColor Yellow
} catch {
    Write-Error "Failed to update registry: $($_.Exception.Message)"
    exit 1
}
