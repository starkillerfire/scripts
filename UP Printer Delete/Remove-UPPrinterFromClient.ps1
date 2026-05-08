#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Discovers and removes broken Universal Print / cloud printers from the local Windows client.

.DESCRIPTION
    Scans all registry locations and the print spooler, then opens a selection window
    where you can check one or more printers to remove. Designed for Tier 1 use —
    no parameters needed, just run it and pick from the list.

    Use this when a Universal Print printer GUID has changed (failed add, print server
    reconfiguration, connector update) and the locally-installed printer is stale or broken.

    Locations scanned:
      - Windows Print Spooler
      - HKLM Cloud Print Provider  (GUID-keyed Universal Print entries)
      - HKLM SYSTEM Spooler Printers
      - HKLM Print Connections
      - HKCU Devices / PrinterPorts / Printers\Connections

.PARAMETER Force
    Skip the confirmation message box before removing (use for scripted/unattended runs).

.EXAMPLE
    .\Remove-UPPrinterFromClient.ps1
    Opens the selection window — check the printer(s) to remove, click OK.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Force
)

# ── Colour helpers ───────────────────────────────────────────────────────────────
function Write-Info    ([string]$m) { Write-Host "[INFO]  $m" -ForegroundColor Cyan }
function Write-OK      ([string]$m) { Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn    ([string]$m) { Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Fail    ([string]$m) { Write-Host "[ERROR] $m" -ForegroundColor Red }
function Write-Section ([string]$m) { Write-Host "`n=== $m ===" -ForegroundColor White }

# Popup message box helper (no external dependencies)
function Show-MsgBox {
    param([string]$Message, [string]$Title = "UP Printer Cleanup", [string]$Buttons = "OKCancel")
    Add-Type -AssemblyName PresentationFramework
    return [System.Windows.MessageBox]::Show($Message, $Title, $Buttons, 'Question')
}

# ── Admin guard ──────────────────────────────────────────────────────────────────
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show(
        "Please re-run this script as Administrator.`n(Right-click > Run as Administrator)",
        "UP Printer Cleanup", "OK", "Error") | Out-Null
    exit 1
}

Write-Host "`nUniversal Print — Client Printer Cleanup" -ForegroundColor White
Write-Info "Computer : $env:COMPUTERNAME"
Write-Info "User     : $env:USERNAME"

# ────────────────────────────────────────────────────────────────────────────────
# STEP 1 — Discovery: scan every location and build a full inventory
# ────────────────────────────────────────────────────────────────────────────────
Write-Section "Step 1: Discovering all installed printers — please wait..."

$inventory = [System.Collections.Generic.List[pscustomobject]]::new()

function Add-Entry {
    param([string]$PrinterName, [string]$GUID, [string]$Source,
          [string]$RegPath, [string]$EntryType)
    $inventory.Add([pscustomobject]@{
        PrinterName = $PrinterName
        GUID        = $GUID
        Source      = $Source
        RegPath     = $RegPath
        EntryType   = $EntryType
    }) | Out-Null
}

# Spooler
try {
    Get-Printer -ErrorAction Stop | ForEach-Object {
        Add-Entry -PrinterName $_.Name -GUID '(spooler)' -Source 'Print Spooler' `
                  -RegPath '' -EntryType 'Spooler'
    }
} catch { Write-Warn "Could not query print spooler: $_" }

# HKLM Cloud Print Provider (GUID-keyed Universal Print entries)
$cloudRoot = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Providers\Cloud Print Provider\Printers"
if (Test-Path $cloudRoot) {
    Get-ChildItem -Path $cloudRoot -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
        $name  = if ($props.PrinterName) { $props.PrinterName }
                 elseif ($props.Name)    { $props.Name }
                 else                   { '(unknown)' }
        Add-Entry -PrinterName $name -GUID $_.PSChildName `
                  -Source 'HKLM Cloud Print Provider' -RegPath $_.PSPath -EntryType 'Key'
    }
} else { Write-Warn "HKLM Cloud Print Provider path not found." }

# HKLM SYSTEM Spooler Printers
$sysSpooler = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers"
if (Test-Path $sysSpooler) {
    Get-ChildItem -Path $sysSpooler -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Entry -PrinterName $_.PSChildName -GUID '(none)' `
                  -Source 'HKLM SYSTEM\Print\Printers' -RegPath $_.PSPath -EntryType 'Key'
    }
}

# HKLM Print Connections (machine-wide)
$machConn = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Connections"
if (Test-Path $machConn) {
    Get-ChildItem -Path $machConn -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
        $name  = if ($props.Printer) { $props.Printer } else { $_.PSChildName }
        $guid  = if ($_.PSChildName -match '^\{') { $_.PSChildName } else { '(none)' }
        Add-Entry -PrinterName $name -GUID $guid `
                  -Source 'HKLM Print\Connections' -RegPath $_.PSPath -EntryType 'Key'
    }
}

# HKCU Devices (per-user)
$hkcuDevices = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Devices"
if (Test-Path $hkcuDevices) {
    foreach ($v in (Get-Item -Path $hkcuDevices -ErrorAction SilentlyContinue).GetValueNames()) {
        Add-Entry -PrinterName $v -GUID '(value)' -Source 'HKCU Devices' `
                  -RegPath "$hkcuDevices|$v" -EntryType 'Value'
    }
}

# HKCU PrinterPorts (per-user)
$hkcuPorts = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PrinterPorts"
if (Test-Path $hkcuPorts) {
    foreach ($v in (Get-Item -Path $hkcuPorts -ErrorAction SilentlyContinue).GetValueNames()) {
        Add-Entry -PrinterName $v -GUID '(value)' -Source 'HKCU PrinterPorts' `
                  -RegPath "$hkcuPorts|$v" -EntryType 'Value'
    }
}

# HKCU Printers\Connections (per-user cloud/network connections)
$hkcuConn = "HKCU:\Printers\Connections"
if (Test-Path $hkcuConn) {
    Get-ChildItem -Path $hkcuConn -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
        $name  = if ($props.Printer) { $props.Printer } else { $_.PSChildName }
        $guid  = if ($_.PSChildName -match '^\{') { $_.PSChildName } else { '(none)' }
        Add-Entry -PrinterName $name -GUID $guid `
                  -Source 'HKCU Printers\Connections' -RegPath $_.PSPath -EntryType 'Key'
    }
}

if ($inventory.Count -eq 0) {
    Write-Warn "No printers found anywhere on this machine."
    [System.Windows.MessageBox]::Show("No printers were found on this machine.", "UP Printer Cleanup", "OK", "Information") | Out-Null
    exit 0
}

Write-OK "Found $($inventory.Count) printer entries across all locations."

# ────────────────────────────────────────────────────────────────────────────────
# STEP 2 — Selection: Out-GridView checkbox window
# ────────────────────────────────────────────────────────────────────────────────
Write-Section "Step 2: Select printers to remove"
Write-Info "A selection window will open — check the printer(s) to remove, then click OK."
Write-Info "You can type in the filter box at the top to search by name or GUID."

# Build display rows (hide internal fields from the grid)
$displayRows = $inventory | ForEach-Object {
    [pscustomobject]@{
        'Printer Name' = $_.PrinterName
        'GUID'         = $_.GUID
        'Source'       = $_.Source
    }
}

$selected = $displayRows | Out-GridView `
    -Title "UP Printer Cleanup — Check printers to REMOVE, then click OK" `
    -PassThru

if (-not $selected -or @($selected).Count -eq 0) {
    Write-Warn "No printers selected. Nothing was removed."
    exit 0
}

# Map selected display rows back to full inventory entries for removal
$toRemove = foreach ($sel in @($selected)) {
    $inventory | Where-Object {
        $_.PrinterName -eq $sel.'Printer Name' -and
        $_.GUID        -eq $sel.'GUID'         -and
        $_.Source      -eq $sel.'Source'
    }
}

# ── Confirm before removing ──────────────────────────────────────────────────────
$nameList   = (@($toRemove) | Select-Object -ExpandProperty PrinterName -Unique) -join "`n  - "
$confirmMsg = "You are about to remove $(@($toRemove).Count) printer entry/entries:`n`n  - $nameList`n`nContinue?"

if (-not $Force) {
    $answer = Show-MsgBox -Message $confirmMsg -Title "Confirm Removal" -Buttons "OKCancel"
    if ($answer -ne 'OK') {
        Write-Warn "Removal cancelled by user."
        exit 0
    }
}

# ────────────────────────────────────────────────────────────────────────────────
# STEP 3 — Remove selected entries
# ────────────────────────────────────────────────────────────────────────────────
Write-Section "Step 3: Removing selected entries"

$removedItems = [System.Collections.Generic.List[string]]::new()
$failedItems  = [System.Collections.Generic.List[string]]::new()

function Remove-RegKey ([string]$path, [string]$label) {
    if (Test-Path $path) {
        try {
            Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
            Write-OK "Removed key  : $label"
            $removedItems.Add("RegKey: $label") | Out-Null
        } catch {
            Write-Fail "Failed key   : $label — $_"
            $failedItems.Add("RegKey: $label") | Out-Null
        }
    }
}

function Remove-RegValue ([string]$path, [string]$valueName) {
    try {
        Remove-ItemProperty -Path $path -Name $valueName -Force -ErrorAction Stop
        Write-OK "Removed value: $path -> $valueName"
        $removedItems.Add("RegValue: $path\$valueName") | Out-Null
    } catch {
        Write-Fail "Failed value : $path -> $valueName — $_"
        $failedItems.Add("RegValue: $path\$valueName") | Out-Null
    }
}

foreach ($entry in @($toRemove)) {
    Write-Info "Removing: '$($entry.PrinterName)' | GUID: $($entry.GUID) | $($entry.Source)"
    switch ($entry.EntryType) {
        'Spooler' {
            try {
                Remove-Printer -Name $entry.PrinterName -Confirm:$false -ErrorAction Stop
                Write-OK "Removed from spooler: $($entry.PrinterName)"
                $removedItems.Add("Spooler: $($entry.PrinterName)") | Out-Null
            } catch {
                Write-Fail "Could not remove '$($entry.PrinterName)' from spooler: $_"
                $failedItems.Add("Spooler: $($entry.PrinterName)") | Out-Null
            }
        }
        'Key' {
            if ($entry.RegPath) {
                Remove-RegKey -path $entry.RegPath `
                              -label "$($entry.Source) — $($entry.GUID) ($($entry.PrinterName))"
            }
        }
        'Value' {
            $parts = $entry.RegPath -split '\|', 2
            if ($parts.Count -eq 2) { Remove-RegValue -path $parts[0] -valueName $parts[1] }
        }
    }
}

# ────────────────────────────────────────────────────────────────────────────────
# STEP 4 — Restart Print Spooler
# Clears in-memory printer state and releases driver file locks before reboot.
# ────────────────────────────────────────────────────────────────────────────────
Write-Section "Step 4: Restarting Print Spooler"

try {
    Write-Info "Stopping Spooler..."
    Stop-Service -Name Spooler -Force -ErrorAction Stop
    Write-Info "Starting Spooler..."
    Start-Service -Name Spooler -ErrorAction Stop
    Write-OK "Print Spooler restarted."
} catch {
    Write-Fail "Could not restart Spooler: $_"
}

# ────────────────────────────────────────────────────────────────────────────────
# Summary popup + console output
# ────────────────────────────────────────────────────────────────────────────────
Write-Section "Summary"

$summaryLines = @("Removed : $($removedItems.Count)", "Failed  : $($failedItems.Count)")
if ($failedItems.Count -gt 0) {
    $summaryLines += "`nFailed entries:"
    $failedItems | ForEach-Object { $summaryLines += "  - $_" }
}

$summaryIcon = if ($failedItems.Count -gt 0) { 'Warning' } else { 'Information' }
[System.Windows.MessageBox]::Show(
    ($summaryLines -join "`n"),
    "UP Printer Cleanup — Done",
    "OK",
    $summaryIcon
) | Out-Null

Write-Host "`n  Removed : $($removedItems.Count)" -ForegroundColor Green
Write-Host "  Failed  : $($failedItems.Count)" -ForegroundColor $(if ($failedItems.Count) { 'Red' } else { 'Green' })
if ($removedItems.Count -gt 0) {
    Write-Host "`n  Removed entries:" -ForegroundColor Green
    $removedItems | ForEach-Object { Write-Host "    - $_" -ForegroundColor Green }
}
if ($failedItems.Count -gt 0) {
    Write-Host "`n  Failed entries:" -ForegroundColor Red
    $failedItems | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
}

# ────────────────────────────────────────────────────────────────────────────────
# STEP 5 — Reboot
# Auto-schedules a reboot in 5 minutes. Prompt lets tech reboot now or cancel it.
# ────────────────────────────────────────────────────────────────────────────────
Write-Section "Step 4: Reboot"

if ($Force) {
    Write-Info "Force mode — rebooting now."
    shutdown /r /t 0 /c "UP Printer Cleanup: forced reboot"
} else {
    # Schedule the reboot first so the countdown is already running while they read the prompt
    shutdown /r /t 300 /c "UP Printer Cleanup: automatic reboot in 5 minutes to finish printer removal"
    Write-Info "Reboot scheduled in 5 minutes."

    $rebootMsg = "Printer cleanup complete.`n`n" +
                 "This computer will REBOOT automatically in 5 minutes.`n`n" +
                 "  Yes    = Reboot RIGHT NOW`n" +
                 "  No     = Keep the 5-minute countdown`n" +
                 "  Cancel = Abort the reboot (you will need to reboot manually later)`n`n" +
                 "After rebooting, re-add the printer from:`n" +
                 "Settings > Bluetooth & devices > Printers & scanners"

    $rebootAnswer = [System.Windows.MessageBox]::Show(
        $rebootMsg,
        "Reboot Required — UP Printer Cleanup",
        "YesNoCancel",
        "Warning"
    )

    switch ($rebootAnswer) {
        'Yes' {
            Write-Info "Rebooting now..."
            shutdown /r /t 0 /c "UP Printer Cleanup: user requested immediate reboot"
        }
        'No' {
            Write-OK "5-minute reboot countdown is running. The computer will reboot automatically."
        }
        'Cancel' {
            shutdown /a 2>$null
            Write-Warn "Reboot cancelled. Remember to reboot manually before re-adding the printer."
            [System.Windows.MessageBox]::Show(
                "Reboot was cancelled.`n`nPlease reboot this computer manually before attempting to re-add the printer.",
                "Reboot Cancelled",
                "OK",
                "Warning"
            ) | Out-Null
        }
    }
}
