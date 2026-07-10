#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Disable Memory Integrity (HVCI) for Red Lion compatibility.

.DESCRIPTION
    HVCI is a kernel-mode code-integrity boundary - turning it off weakens
    protection against kernel exploits and rootkits for the whole machine,
    and it stays off indefinitely since there's nothing here that
    re-enables it automatically.

    Because of that, every run writes an audit trail (local log file under
    C:\ProgramData\Logs plus a Windows Application event) recording who ran
    it, on what machine, and why, so this exception is actually traceable
    later instead of being a silent registry change nobody remembers.

.PARAMETER Reason
    Free-text justification stored in the audit log. Defaults to the
    standard Red Lion compatibility reason; override if disabling for a
    different cause.

.PARAMETER TicketReference
    Ticket/case number for this exception. Not required, but without one
    there's no way to trace the change back to an approved request later.
#>
param(
    [string]$Reason = "Red Lion software compatibility (HVCI conflicts with Red Lion drivers)",
    [string]$TicketReference = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
$LogPath      = "C:\ProgramData\Logs\RedLion-HVCI-Disable.log"
$EventSource  = "RedLion-HVCI"

function Write-AuditEntry {
    param([string]$Message)
    $line = "{0} | User: {1} | Machine: {2} | Reason: {3} | Ticket: {4} | {5}" -f `
        (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $env:USERNAME, $env:COMPUTERNAME, $Reason, $TicketReference, $Message
    $logDir = Split-Path $LogPath
    if ($logDir -and -not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
            New-EventLog -LogName Application -Source $EventSource
        }
        Write-EventLog -LogName Application -Source $EventSource -EventId 7000 -EntryType Warning -Message $line
    } catch {}
}

if (-not $TicketReference) {
    # Not a hard requirement, but disabling a security control with nothing
    # tying it to an approved request makes it very hard for anyone to find
    # and re-evaluate this machine later.
    Write-Host "NOTE: No -TicketReference supplied. Disabling a security control without a" -ForegroundColor Yellow
    Write-Host "tracked ticket makes it harder to find/revisit this exception later." -ForegroundColor Yellow
}

if (-not (Test-Path $RegistryPath)) {
    Write-Host "Registry key not found: $RegistryPath" -ForegroundColor Yellow
    Write-Host "Memory Integrity may not be configured on this machine - nothing to disable."
    Write-AuditEntry "No-op: HVCI registry key not present."
    exit 0
}

try {
    Set-ItemProperty -Path $RegistryPath -Name "Enabled"     -Value 0 -ErrorAction Stop
    Set-ItemProperty -Path $RegistryPath -Name "WasEnabledBy" -Value 0 -ErrorAction Stop
    Write-Host "Memory Integrity disabled successfully." -ForegroundColor Green
    Write-Host "Restart your computer for the changes to take effect." -ForegroundColor Yellow
    Write-AuditEntry "HVCI disabled successfully."
} catch {
    Write-Error "Failed to update registry: $($_.Exception.Message)"
    Write-AuditEntry "FAILED to disable HVCI: $($_.Exception.Message)"
    exit 1
}
