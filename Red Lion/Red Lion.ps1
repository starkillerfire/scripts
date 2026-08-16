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

.PARAMETER Force
    Skip the automated Red Lion software/driver detection check and disable
    HVCI anyway. Only use this after independently confirming Red Lion
    software is actually installed on this machine (e.g. under a product
    name the detection check doesn't recognize) - this script disables a
    kernel security control and should not run on machines that don't need
    the exception.
#>
param(
    [string]$Reason = "Red Lion software compatibility (HVCI conflicts with Red Lion drivers)",
    [string]$TicketReference = "",
    [switch]$Force
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
    } catch { Write-Verbose "Failed to write Windows Application event log entry: $($_.Exception.Message)" }
}

function Test-RedLionSoftwarePresent {
    # No existing Red Lion detection logic exists elsewhere in this script,
    # so this checks the two places Red Lion's Crimson/driver-based software
    # would normally show up: the standard installed-program uninstall keys
    # (32-bit and 64-bit) by display name, and loaded system drivers by
    # name, in case it was installed without a matching uninstall entry.
    $uninstallKeyPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($path in $uninstallKeyPaths) {
        $match = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match 'Red\s*Lion' }
        if ($match) { return $true }
    }

    $driverMatch = Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'RedLion' -or $_.DisplayName -match 'Red\s*Lion' }
    if ($driverMatch) { return $true }

    return $false
}

if (-not $TicketReference) {
    # Not a hard requirement, but disabling a security control with nothing
    # tying it to an approved request makes it very hard for anyone to find
    # and re-evaluate this machine later.
    Write-Host "NOTE: No -TicketReference supplied. Disabling a security control without a" -ForegroundColor Yellow
    Write-Host "tracked ticket makes it harder to find/revisit this exception later." -ForegroundColor Yellow
}

$redLionDetected = Test-RedLionSoftwarePresent
if (-not $redLionDetected) {
    if (-not $Force) {
        Write-Host "No Red Lion software or driver was detected on this machine (checked installed-program uninstall keys and system drivers for a 'Red Lion' name match)." -ForegroundColor Yellow
        Write-AuditEntry "ABORTED: No Red Lion software detected and -Force was not supplied; HVCI left unchanged."
        throw "No Red Lion software was detected on this machine. This script disables a kernel security control (HVCI) and should only be run where the Red Lion compatibility exception is actually needed. Re-run with -Force if you have independently verified Red Lion software is installed under a name this check doesn't recognize."
    }
    Write-Host "WARNING: No Red Lion software was detected, but -Force was supplied - proceeding anyway." -ForegroundColor Yellow
    Write-AuditEntry "WARNING: Proceeding without detected Red Lion software because -Force was supplied."
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
