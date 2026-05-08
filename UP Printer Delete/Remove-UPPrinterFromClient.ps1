#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Discovers and removes broken Universal Print / cloud printers from the local Windows client.

.DESCRIPTION
    Scans all registry locations and the print spooler, then opens a selection window
    grouped by printer name. Selecting a printer removes it from every registry location
    automatically — no need to pick the same printer multiple times.

    Additional safety and audit features:
      - Registry keys are backed up to a .reg file before deletion (restorable by double-click)
      - Full transcript log saved to %TEMP% for audit trail
      - Orphaned printer driver detection and optional cleanup after removal

    Use this when a Universal Print printer GUID has changed (failed add, print server
    reconfiguration, connector update) and the locally-installed printer is stale or broken.

    Locations scanned:
      - Windows Print Spooler
      - HKLM Cloud Print Provider  (GUID-keyed Universal Print entries)
      - HKLM SYSTEM Spooler Printers
      - HKLM Print Connections
      - HKCU Devices / PrinterPorts / Printers\Connections

.PARAMETER Force
    Skip confirmation prompts and reboot immediately. For scripted/unattended runs.

.EXAMPLE
    .\Remove-UPPrinterFromClient.ps1
    Opens the selection window — pick the printer(s) to remove, click OK.
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

function Show-MsgBox {
    param([string]$Message, [string]$Title = "UP Printer Cleanup", [string]$Buttons = "OKCancel",
          [string]$Icon = "Question")
    return [System.Windows.MessageBox]::Show($Message, $Title, $Buttons, $Icon)
}

# ── Admin guard ──────────────────────────────────────────────────────────────────
Add-Type -AssemblyName PresentationFramework
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    [System.Windows.MessageBox]::Show(
        "Please re-run this script as Administrator.`n(Right-click > Run as Administrator)",
        "UP Printer Cleanup", "OK", "Error") | Out-Null
    exit 1
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

Write-Host "`nUniversal Print — Client Printer Cleanup" -ForegroundColor White
Write-Info "Computer : $env:COMPUTERNAME"
Write-Info "User     : $env:USERNAME"

# ── Transcript ───────────────────────────────────────────────────────────────────
$transcriptPath = "$env:TEMP\UPPrinterCleanup_${stamp}_$env:COMPUTERNAME.txt"
Start-Transcript -Path $transcriptPath -ErrorAction SilentlyContinue | Out-Null
Write-Info "Transcript : $transcriptPath"

# ── Registry backup directory ────────────────────────────────────────────────────
$backupDir = "$env:TEMP\UPPrinterBackup_$stamp"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
Write-Info "Reg backup : $backupDir"

# Converts PS drive paths and PSPath format to reg.exe-compatible paths
function Get-RegExportPath ([string]$path) {
    $path `
        -replace 'Microsoft\.PowerShell\.Core\\Registry::', '' `
        -replace 'HKEY_LOCAL_MACHINE\\', 'HKLM\' `
        -replace 'HKEY_CURRENT_USER\\',  'HKCU\' `
        -replace '^HKLM:\\', 'HKLM\' `
        -replace '^HKCU:\\', 'HKCU\'
}

function Backup-RegKey ([string]$path) {
    try {
        $regPath    = Get-RegExportPath $path
        $safeName   = ($regPath -replace '[\\:\{\}\s\(\)]', '_') -replace '_+', '_'
        $backupFile = Join-Path $backupDir "$safeName.reg"
        $null = & reg.exe export $regPath $backupFile /y 2>&1
    } catch { }  # Backup failure must never block the removal
}

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
    [System.Windows.MessageBox]::Show("No printers were found on this machine.",
        "UP Printer Cleanup", "OK", "Information") | Out-Null
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    exit 0
}

Write-OK "Found $($inventory.Count) entries across all locations."

# ────────────────────────────────────────────────────────────────────────────────
# STEP 2 — Selection: grouped by printer name (one row per printer)
# ────────────────────────────────────────────────────────────────────────────────
Write-Section "Step 2: Select printers to remove"
Write-Info "Each row = one printer. Selecting it removes ALL registry locations for that printer."
Write-Info "Use the filter box to search. Hold Ctrl to select multiple printers."

$groupedRows = $inventory | Group-Object PrinterName | ForEach-Object {
    $sources   = ($_.Group | Select-Object -ExpandProperty Source -Unique) -join ', '
    $realGuids = $_.Group | Where-Object { $_.GUID -notmatch '^\(' } |
                 Select-Object -ExpandProperty GUID -Unique
    $guidStr   = if ($realGuids) { $realGuids -join ', ' } else { '(none)' }
    [pscustomobject]@{
        'Printer Name'       = $_.Name
        'Registry Locations' = $sources
        'GUIDs'              = $guidStr
        'Total Entries'      = $_.Count
    }
} | Sort-Object 'Printer Name'

$selected = $groupedRows | Out-GridView `
    -Title "UP Printer Cleanup — Select printer(s) to REMOVE then click OK  |  All registry locations removed automatically" `
    -PassThru

if (-not $selected -or @($selected).Count -eq 0) {
    Write-Warn "No printers selected. Nothing was removed."
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    exit 0
}

# Expand grouped selection back to every matching inventory entry
$toRemove = foreach ($sel in @($selected)) {
    $inventory | Where-Object { $_.PrinterName -eq $sel.'Printer Name' }
}

# ── Confirm ──────────────────────────────────────────────────────────────────────
$selectedNames = (@($selected) | Select-Object -ExpandProperty 'Printer Name') -join "`n  - "
$confirmMsg    = "Remove $(@($selected).Count) printer(s) from ALL registry locations?`n`n  - $selectedNames`n`n" +
                 "Registry keys will be backed up to:`n$backupDir"

if (-not $Force) {
    $answer = Show-MsgBox -Message $confirmMsg -Title "Confirm Removal" -Buttons "OKCancel"
    if ($answer -ne 'OK') {
        Write-Warn "Removal cancelled by user."
        Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
        exit 0
    }
}

# ── Capture driver names before spooler entries are removed ──────────────────────
$driversUsedByRemoved = [System.Collections.Generic.List[string]]::new()
foreach ($entry in @($toRemove)) {
    if ($entry.EntryType -eq 'Spooler') {
        $p = Get-Printer -Name $entry.PrinterName -ErrorAction SilentlyContinue
        if ($p -and $p.DriverName) { $driversUsedByRemoved.Add($p.DriverName) | Out-Null }
    }
}

# ────────────────────────────────────────────────────────────────────────────────
# STEP 3 — Remove selected entries (with registry backup before each delete)
# ────────────────────────────────────────────────────────────────────────────────
Write-Section "Step 3: Removing selected entries"

$removedItems = [System.Collections.Generic.List[string]]::new()
$failedItems  = [System.Collections.Generic.List[string]]::new()

function Remove-RegKey ([string]$path, [string]$label) {
    if (Test-Path $path) {
        Backup-RegKey $path
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

function Remove-RegValue ([string]$keyPath, [string]$valueName) {
    Backup-RegKey $keyPath  # Back up parent key before removing value
    try {
        Remove-ItemProperty -Path $keyPath -Name $valueName -Force -ErrorAction Stop
        Write-OK "Removed value: $keyPath -> $valueName"
        $removedItems.Add("RegValue: $keyPath\$valueName") | Out-Null
    } catch {
        Write-Fail "Failed value : $keyPath -> $valueName — $_"
        $failedItems.Add("RegValue: $keyPath\$valueName") | Out-Null
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
            if ($parts.Count -eq 2) { Remove-RegValue -keyPath $parts[0] -valueName $parts[1] }
        }
    }
}

# ────────────────────────────────────────────────────────────────────────────────
# STEP 4 — Orphaned printer driver cleanup
# ────────────────────────────────────────────────────────────────────────────────
Write-Section "Step 4: Checking for orphaned printer drivers"

$uniqueDrivers = @($driversUsedByRemoved | Select-Object -Unique)
if ($uniqueDrivers.Count -gt 0) {
    $remainingPrinters = @(Get-Printer -ErrorAction SilentlyContinue)
    $orphanedDrivers   = $uniqueDrivers | Where-Object {
        $d = $_; -not ($remainingPrinters | Where-Object { $_.DriverName -eq $d })
    }

    if (@($orphanedDrivers).Count -gt 0) {
        Write-Info "Found $(@($orphanedDrivers).Count) orphaned driver(s) — opening selection window."
        $driverRows = @($orphanedDrivers) | ForEach-Object {
            [pscustomobject]@{ 'Driver Name' = $_ }
        }
        $selectedDrivers = $driverRows | Out-GridView `
            -Title "Orphaned Printer Drivers — Select to remove (optional), or click Cancel to skip" `
            -PassThru

        foreach ($d in @($selectedDrivers)) {
            try {
                Remove-PrinterDriver -Name $d.'Driver Name' -ErrorAction Stop
                Write-OK "Removed driver: $($d.'Driver Name')"
                $removedItems.Add("Driver: $($d.'Driver Name')") | Out-Null
            } catch {
                Write-Fail "Could not remove driver '$($d.'Driver Name')': $_"
                $failedItems.Add("Driver: $($d.'Driver Name')") | Out-Null
            }
        }
    } else {
        Write-OK "No orphaned drivers found."
    }
} else {
    Write-Info "No spooler entries removed — skipping driver check."
}

# ────────────────────────────────────────────────────────────────────────────────
# STEP 5 — Restart Print Spooler
# Clears in-memory printer state and releases driver file locks before reboot.
# ────────────────────────────────────────────────────────────────────────────────
Write-Section "Step 5: Restarting Print Spooler"

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
# Summary
# ────────────────────────────────────────────────────────────────────────────────
Write-Section "Summary"

$summaryLines = @(
    "Removed : $($removedItems.Count)",
    "Failed  : $($failedItems.Count)",
    "",
    "Log      : $transcriptPath",
    "Reg backup: $backupDir"
)
if ($failedItems.Count -gt 0) {
    $summaryLines += ""
    $summaryLines += "Failed entries:"
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
Write-Host "  Failed  : $($failedItems.Count)"  -ForegroundColor $(if ($failedItems.Count) { 'Red' } else { 'Green' })
Write-Info "Log      : $transcriptPath"
Write-Info "Reg backup: $backupDir"
if ($removedItems.Count -gt 0) {
    Write-Host "`n  Removed entries:" -ForegroundColor Green
    $removedItems | ForEach-Object { Write-Host "    - $_" -ForegroundColor Green }
}
if ($failedItems.Count -gt 0) {
    Write-Host "`n  Failed entries:" -ForegroundColor Red
    $failedItems | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
}

# ────────────────────────────────────────────────────────────────────────────────
# STEP 6 — Reboot
# Auto-schedules a reboot in 5 minutes. Prompt lets tech reboot now or cancel.
# ────────────────────────────────────────────────────────────────────────────────
Write-Section "Step 6: Reboot"

Stop-Transcript -ErrorAction SilentlyContinue | Out-Null

if ($Force) {
    Write-Info "Force mode — rebooting now."
    shutdown /r /t 0 /c "UP Printer Cleanup: forced reboot"
} else {
    shutdown /r /t 300 /c "UP Printer Cleanup: automatic reboot in 5 minutes to finish printer removal"
    Write-Info "Reboot scheduled in 5 minutes."

    $rebootMsg = "Printer cleanup complete.`n`n" +
                 "This computer will REBOOT automatically in 5 minutes.`n`n" +
                 "  Yes    = Reboot RIGHT NOW`n" +
                 "  No     = Keep the 5-minute countdown`n" +
                 "  Cancel = Abort the reboot (reboot manually before re-adding the printer)`n`n" +
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
            Write-OK "5-minute countdown running. Computer will reboot automatically."
        }
        'Cancel' {
            shutdown /a 2>$null
            Write-Warn "Reboot cancelled. Remember to reboot manually before re-adding the printer."
            [System.Windows.MessageBox]::Show(
                "Reboot was cancelled.`n`nPlease reboot this computer manually before attempting to re-add the printer.",
                "Reboot Cancelled", "OK", "Warning"
            ) | Out-Null
        }
    }
}
