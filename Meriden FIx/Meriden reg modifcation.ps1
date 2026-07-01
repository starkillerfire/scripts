#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Set WorkspaceDB=8 for the AutoManager Meridian client in both 64-bit and WOW6432Node
    registry paths, then schedule a reboot.

.PARAMETER RebootDelaySecs
    Seconds before the forced reboot. Default: 300 (5 minutes). Use 0 to skip reboot.

.PARAMETER LogPath
    Path to a plaintext log of what this script did. Defaults to
    C:\ProgramData\Logs\Meriden-RegFix.log.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [int]    $RebootDelaySecs = 300,
    [string] $LogPath         = 'C:\ProgramData\Logs\Meriden-RegFix.log'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line -ForegroundColor $(if ($Level -eq 'ERROR') { 'Red' } elseif ($Level -eq 'WARN') { 'Yellow' } else { 'Green' })
    $logDir = Split-Path $LogPath
    if ($logDir -and -not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
}

$paths = @(
    'HKLM:\SOFTWARE\Cyco\AutoManager Meridian\CurrentVersion\Client',
    'HKLM:\SOFTWARE\WOW6432Node\Cyco\AutoManager Meridian\CurrentVersion\Client'
)

# Registry writes are wrapped so a failure here (permissions, a locked
# hive, etc.) is logged clearly and stops the script before it reboots the
# machine over a change that didn't actually take effect.
$anyChanged = $false
try {
    foreach ($path in $paths) {
        $before = if (Test-Path $path) { (Get-ItemProperty -Path $path -Name WorkspaceDB -ErrorAction SilentlyContinue).WorkspaceDB } else { $null }
        if ($before -eq 8) {
            Write-Log "$path already has WorkspaceDB = 8 - nothing to change."
            continue
        }

        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        Set-ItemProperty -Path $path -Name WorkspaceDB -Value 8 -Type DWord -Force
        Write-Log "Set $path -> WorkspaceDB = 8 (was: $(if ($null -eq $before) { 'not set' } else { $before }))"
        $anyChanged = $true
    }
} catch {
    Write-Log "Failed to update Meridian registry settings: $($_.Exception.Message)" 'ERROR'
    Write-Log "Aborting without rebooting, since the change may not have applied." 'ERROR'
    exit 1
}

Write-Log "Registry check complete."

if (-not $anyChanged) {
    Write-Log "No changes were needed - skipping reboot."
    exit 0
}

if ($RebootDelaySecs -gt 0) {
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Reboot in $RebootDelaySecs seconds")) {
        Write-Log "System will reboot in $RebootDelaySecs seconds..." 'WARN'
        shutdown.exe /r /t $RebootDelaySecs /c "Meridian client registry update applied. Rebooting."
    }
} else {
    Write-Log "Reboot skipped (-RebootDelaySecs 0). Restart manually to apply changes." 'WARN'
}
