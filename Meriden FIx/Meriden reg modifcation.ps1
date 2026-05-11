#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Set WorkspaceDB=8 for the AutoManager Meridian client in both 64-bit and WOW6432Node
    registry paths, then schedule a reboot.

.PARAMETER RebootDelaySecs
    Seconds before the forced reboot. Default: 300 (5 minutes). Use 0 to skip reboot.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [int] $RebootDelaySecs = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$paths = @(
    'HKLM:\SOFTWARE\Cyco\AutoManager Meridian\CurrentVersion\Client',
    'HKLM:\SOFTWARE\WOW6432Node\Cyco\AutoManager Meridian\CurrentVersion\Client'
)

foreach ($path in $paths) {
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    Set-ItemProperty -Path $path -Name WorkspaceDB -Value 8 -Type DWord -Force
    Write-Host "Set $path -> WorkspaceDB = 8" -ForegroundColor Green
}

Write-Host "Registry updated successfully." -ForegroundColor Green

if ($RebootDelaySecs -gt 0) {
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Reboot in $RebootDelaySecs seconds")) {
        Write-Warning "System will reboot in $RebootDelaySecs seconds..."
        shutdown.exe /r /t $RebootDelaySecs /c "Meridian client registry update applied. Rebooting."
    }
} else {
    Write-Host "Reboot skipped (-RebootDelaySecs 0). Restart manually to apply changes." -ForegroundColor Yellow
}
