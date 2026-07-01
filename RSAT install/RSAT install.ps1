#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Install all missing RSAT features on the local machine.

.PARAMETER Feature
    Optional filter. Only install features whose name contains this string.
    Example: -Feature DNS   installs only RSAT DNS tools.
    Omit to install all missing RSAT features.

.EXAMPLE
    .\RSAT install.ps1
    .\RSAT install.ps1 -Feature ActiveDirectory
#>
[CmdletBinding()]
param(
    [string] $Feature = ''
)

Set-StrictMode -Version Latest

Write-Host "Scanning for RSAT features..." -ForegroundColor Cyan

try {
    $capabilities = Get-WindowsCapability -Online -ErrorAction Stop
} catch {
    Write-Error "Could not query Windows capabilities (DISM/WMI may be unavailable): $($_.Exception.Message)"
    exit 1
}

$missing = $capabilities |
    Where-Object {
        $_.Name -like 'Rsat.*' -and
        $_.State -notin @('Installed', 'InstallPending') -and
        ($Feature -eq '' -or $_.Name -like "*$Feature*")
    }

if ($missing.Count -eq 0) {
    Write-Host "All matching RSAT features are already installed." -ForegroundColor Green
    exit 0
}

Write-Host "Found $($missing.Count) feature(s) to install." -ForegroundColor Cyan

$succeeded = 0
$failed    = 0

foreach ($cap in $missing) {
    Write-Host "Installing $($cap.Name)..." -ForegroundColor Yellow
    try {
        Add-WindowsCapability -Online -Name $cap.Name -ErrorAction Stop | Out-Null
        Write-Host "  OK: $($cap.Name)" -ForegroundColor Green
        $succeeded++
    } catch {
        Write-Warning "  FAILED: $($cap.Name) - $($_.Exception.Message)"
        $failed++
    }
}

Write-Host ""
Write-Host "RSAT install complete - $succeeded succeeded, $failed failed." -ForegroundColor Cyan
exit $(if ($failed -gt 0) { 1 } else { 0 })
