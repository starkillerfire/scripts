<#
.SYNOPSIS
    Discovers and removes broken Universal Print / cloud printers from the local Windows client.

.DESCRIPTION
    Scans all registry locations (including other user profiles) and the print spooler,
    then opens a selection window grouped by printer name. Selecting a printer removes it
    from every registry location automatically.

    Features:
      - Auto-elevates to Administrator if not already running elevated
      - Scans all loaded user profile hives (HKU), not just the current user
      - Registry keys backed up to a .reg file before deletion (double-click to restore)
      - Orphaned printer driver and port detection with optional cleanup
      - Full transcript log saved to %TEMP% for audit trail

    Use this when a Universal Print printer GUID has changed (failed add, print server
    reconfiguration, connector update) and the locally-installed printer is stale or broken.

.PARAMETER Force
    Skip confirmation prompts and reboot immediately. For scripted/unattended runs.

.EXAMPLE
    .\Remove-UPPrinterFromClient.ps1
    Opens the selection window - pick the printer(s) to remove, click OK.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Auto-elevation: relaunch as admin if needed ──────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
               [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $scriptPath = $MyInvocation.MyCommand.Path
    if ([string]::IsNullOrEmpty($scriptPath)) {
        Write-Host "Cannot auto-elevate: script path unavailable." -ForegroundColor Red
        Write-Host "Save the file to disk, then right-click > Run with PowerShell (as Administrator)." -ForegroundColor Yellow
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-Host "Not running as Administrator - relaunching elevated..." -ForegroundColor Yellow
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    if ($Force) { $argList += " -Force" }
    # -WhatIf/-Confirm are automatic parameters from SupportsShouldProcess, not
    # in $Force above - previously they were silently dropped on relaunch, so
    # running this non-elevated with -WhatIf (the normal way a technician would
    # preview it) still performed real deletions once UAC elevated it.
    if ($WhatIfPreference) { $argList += " -WhatIf" }
    if ($PSBoundParameters.ContainsKey('Confirm')) { $argList += " -Confirm:`$$($PSBoundParameters['Confirm'])" }
    Start-Process powershell.exe -ArgumentList $argList -Verb RunAs
    exit
}

# ── Colour helpers ───────────────────────────────────────────────────────────────
Add-Type -AssemblyName PresentationFramework

function Write-Info    ([string]$m) { Write-Host "[INFO]  $m" -ForegroundColor Cyan }
function Write-OK      ([string]$m) { Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn    ([string]$m) { Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Fail    ([string]$m) { Write-Host "[ERROR] $m" -ForegroundColor Red }
function Write-Section ([string]$m) { Write-Host "`n=== $m ===" -ForegroundColor White }

function Show-MsgBox {
    param([string]$Message, [string]$Title = "UP Printer Cleanup",
          [string]$Buttons = "OKCancel", [string]$Icon = "Question")
    return [System.Windows.MessageBox]::Show($Message, $Title, $Buttons, $Icon)
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

Write-Host "`nUniversal Print - Client Printer Cleanup" -ForegroundColor White
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

# Converts PS/PSPath formats to a path reg.exe understands
function Get-RegExportPath ([string]$path) {
    $path `
        -replace 'Microsoft\.PowerShell\.Core\\Registry::', '' `
        -replace 'HKEY_LOCAL_MACHINE\\', 'HKLM\' `
        -replace 'HKEY_CURRENT_USER\\',  'HKCU\' `
        -replace 'HKEY_USERS\\',         'HKU\'  `
        -replace '^HKLM:\\', 'HKLM\' `
        -replace '^HKCU:\\', 'HKCU\' `
        -replace '^HKU:\\',  'HKU\'
}

function Backup-RegKey ([string]$path) {
    try {
        $regPath    = Get-RegExportPath $path
        $safeName   = ($regPath -replace '[\\:\{\}\s\(\)]', '_') -replace '_+', '_'
        $backupFile = Join-Path $backupDir "$safeName.reg"
        $null = & reg.exe export $regPath $backupFile /y 2>&1
    } catch { Write-Warn "Registry backup of '$path' failed: $($_.Exception.Message)" }  # Backup failure must never block removal
}

# ────────────────────────────────────────────────────────────────────────────────
# STEP 1 - Discovery: scan every location and build a full inventory
# ────────────────────────────────────────────────────────────────────────────────
Write-Section "Step 1: Discovering all installed printers - please wait..."

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

# Helper: scan the three per-user printer registry paths under any hive root
function Read-UserHive {
    param([string]$HiveRoot, [string]$SourceLabel)

    $devPath  = "$HiveRoot\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Devices"
    $portPath = "$HiveRoot\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PrinterPorts"
    $connPath = "$HiveRoot\Printers\Connections"

    if (Test-Path $devPath) {
        foreach ($v in (Get-Item -Path $devPath -ErrorAction SilentlyContinue).GetValueNames()) {
            Add-Entry -PrinterName $v -GUID '(value)' -Source "$SourceLabel Devices" `
                      -RegPath "$devPath|$v" -EntryType 'Value'
        }
    }
    if (Test-Path $portPath) {
        foreach ($v in (Get-Item -Path $portPath -ErrorAction SilentlyContinue).GetValueNames()) {
            Add-Entry -PrinterName $v -GUID '(value)' -Source "$SourceLabel PrinterPorts" `
                      -RegPath "$portPath|$v" -EntryType 'Value'
        }
    }
    if (Test-Path $connPath) {
        Get-ChildItem -Path $connPath -ErrorAction SilentlyContinue | ForEach-Object {
            $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            $name  = if ($props.Printer) { $props.Printer } else { $_.PSChildName }
            $guid  = if ($_.PSChildName -match '^\{') { $_.PSChildName } else { '(none)' }
            Add-Entry -PrinterName $name -GUID $guid -Source "$SourceLabel Connections" `
                      -RegPath $_.PSPath -EntryType 'Key'
        }
    }
}

# ── Print Spooler ────────────────────────────────────────────────────────────────
try {
    Get-Printer -ErrorAction Stop | ForEach-Object {
        Add-Entry -PrinterName $_.Name -GUID '(spooler)' -Source 'Print Spooler' `
                  -RegPath '' -EntryType 'Spooler'
    }
} catch { Write-Warn "Could not query print spooler: $_" }

# ── HKLM Cloud Print Provider (GUID-keyed Universal Print entries) ───────────────
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

# ── HKLM SYSTEM Spooler Printers ────────────────────────────────────────────────
$sysSpooler = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers"
if (Test-Path $sysSpooler) {
    Get-ChildItem -Path $sysSpooler -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Entry -PrinterName $_.PSChildName -GUID '(none)' `
                  -Source 'HKLM SYSTEM\Print\Printers' -RegPath $_.PSPath -EntryType 'Key'
    }
}

# ── HKLM Print Connections (machine-wide) ───────────────────────────────────────
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

# ── HKCU - current user ──────────────────────────────────────────────────────────
Read-UserHive -HiveRoot 'HKCU:' -SourceLabel 'HKCU'

# ── HKU - all other loaded user profile hives ────────────────────────────────────
Write-Info "Scanning other loaded user profile hives (HKU)..."
if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
}

$skipSids = @('S-1-5-18', 'S-1-5-19', 'S-1-5-20', '.DEFAULT')

Get-ChildItem -Path 'HKU:\' -ErrorAction SilentlyContinue | Where-Object {
    $sid = $_.PSChildName
    $sid -notin $skipSids -and $sid -notmatch '_Classes$'
} | ForEach-Object {
    $sid      = $_.PSChildName
    $hkuRoot  = "HKU:\$sid"
    $label    = "HKU\$sid"

    # Resolve SID to a friendly username if possible
    try {
        $ntAccount = ([System.Security.Principal.SecurityIdentifier]$sid).Translate(
                         [System.Security.Principal.NTAccount])
        $label = "HKU\$($ntAccount.Value.Split('\')[-1])"
    } catch { Write-Warn "Could not resolve SID '$sid' to a username: $($_.Exception.Message)" }

    # Skip the current user - already covered by HKCU scan above
    $currentSid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    if ($sid -eq $currentSid) { return }

    Read-UserHive -HiveRoot $hkuRoot -SourceLabel $label
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
# STEP 2 - Selection: grouped by printer name (one row per printer)
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
    -Title "UP Printer Cleanup - Select printer(s) to REMOVE then click OK  |  All locations cleaned automatically" `
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

# ── Capture driver + port names before spooler entries are removed ───────────────
$driversUsedByRemoved = [System.Collections.Generic.List[string]]::new()
$portsUsedByRemoved   = [System.Collections.Generic.List[string]]::new()

foreach ($entry in @($toRemove)) {
    if ($entry.EntryType -eq 'Spooler') {
        $p = Get-Printer -Name $entry.PrinterName -ErrorAction SilentlyContinue
        if ($p) {
            if ($p.DriverName) { $driversUsedByRemoved.Add($p.DriverName) | Out-Null }
            if ($p.PortName)   { $portsUsedByRemoved.Add($p.PortName)     | Out-Null }
        }
    }
}

# ────────────────────────────────────────────────────────────────────────────────
# STEP 3 - Remove selected entries (registry backed up before each delete)
# ────────────────────────────────────────────────────────────────────────────────
Write-Section "Step 3: Removing selected entries"

$removedItems = [System.Collections.Generic.List[string]]::new()
$failedItems  = [System.Collections.Generic.List[string]]::new()

function Remove-RegKey {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$path, [string]$label)
    if (Test-Path $path) {
        if (-not $PSCmdlet.ShouldProcess($label, "Remove registry key")) { return }
        Backup-RegKey $path
        try {
            Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
            Write-OK "Removed key  : $label"
            $removedItems.Add("RegKey: $label") | Out-Null
        } catch {
            Write-Fail "Failed key   : $label - $_"
            $failedItems.Add("RegKey: $label") | Out-Null
        }
    }
}

function Remove-RegValue {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$keyPath, [string]$valueName)
    if (-not $PSCmdlet.ShouldProcess("$keyPath -> $valueName", "Remove registry value")) { return }
    Backup-RegKey $keyPath
    try {
        Remove-ItemProperty -Path $keyPath -Name $valueName -Force -ErrorAction Stop
        Write-OK "Removed value: $keyPath -> $valueName"
        $removedItems.Add("RegValue: $keyPath\$valueName") | Out-Null
    } catch {
        Write-Fail "Failed value : $keyPath -> $valueName - $_"
        $failedItems.Add("RegValue: $keyPath\$valueName") | Out-Null
    }
}

foreach ($entry in @($toRemove)) {
    Write-Info "Removing: '$($entry.PrinterName)' | GUID: $($entry.GUID) | $($entry.Source)"
    switch ($entry.EntryType) {
        'Spooler' {
            if ($PSCmdlet.ShouldProcess($entry.PrinterName, "Remove from spooler")) {
                try {
                    Remove-Printer -Name $entry.PrinterName -Confirm:$false -ErrorAction Stop
                    Write-OK "Removed from spooler: $($entry.PrinterName)"
                    $removedItems.Add("Spooler: $($entry.PrinterName)") | Out-Null
                } catch {
                    Write-Fail "Could not remove '$($entry.PrinterName)' from spooler: $_"
                    $failedItems.Add("Spooler: $($entry.PrinterName)") | Out-Null
                }
            }
        }
        'Key' {
            if ($entry.RegPath) {
                Remove-RegKey -path $entry.RegPath `
                              -label "$($entry.Source) - $($entry.GUID) ($($entry.PrinterName))"
            }
        }
        'Value' {
            $parts = $entry.RegPath -split '\|', 2
            if ($parts.Count -eq 2) { Remove-RegValue -keyPath $parts[0] -valueName $parts[1] }
        }
    }
}

# ────────────────────────────────────────────────────────────────────────────────
# STEP 4 - Orphaned printer driver cleanup
# ────────────────────────────────────────────────────────────────────────────────
Write-Section "Step 4: Checking for orphaned printer drivers"

$uniqueDrivers = @($driversUsedByRemoved | Select-Object -Unique)
if ($uniqueDrivers.Count -gt 0) {
    $remainingPrinters = @(Get-Printer -ErrorAction SilentlyContinue)
    $orphanedDrivers   = $uniqueDrivers | Where-Object {
        $d = $_; -not ($remainingPrinters | Where-Object { $_.DriverName -eq $d })
    }

    if (@($orphanedDrivers).Count -gt 0) {
        Write-Info "Found $(@($orphanedDrivers).Count) orphaned driver(s) - opening selection window."
        $selectedDrivers = @($orphanedDrivers) |
            ForEach-Object { [pscustomobject]@{ 'Driver Name' = $_ } } |
            Out-GridView -Title "Orphaned Printer Drivers - Select to remove (optional), or Cancel to skip" -PassThru

        foreach ($d in @($selectedDrivers)) {
            if ($PSCmdlet.ShouldProcess($d.'Driver Name', "Remove printer driver")) {
                try {
                    Remove-PrinterDriver -Name $d.'Driver Name' -ErrorAction Stop
                    Write-OK "Removed driver: $($d.'Driver Name')"
                    $removedItems.Add("Driver: $($d.'Driver Name')") | Out-Null
                } catch {
                    Write-Fail "Could not remove driver '$($d.'Driver Name')': $_"
                    $failedItems.Add("Driver: $($d.'Driver Name')") | Out-Null
                }
            }
        }
    } else {
        Write-OK "No orphaned drivers found."
    }
} else {
    Write-Info "No spooler entries removed - skipping driver check."
}

# ────────────────────────────────────────────────────────────────────────────────
# STEP 5 - Orphaned printer port cleanup
# ────────────────────────────────────────────────────────────────────────────────
Write-Section "Step 5: Checking for orphaned printer ports"

$uniquePorts = @($portsUsedByRemoved | Select-Object -Unique)
if ($uniquePorts.Count -gt 0) {
    $remainingPrinters = @(Get-Printer -ErrorAction SilentlyContinue)

    # Skip built-in system ports that should never be removed
    $systemPortPattern = '^(LPT\d*|COM\d*|USB\d*|FILE:|NUL:|PORTPROMPT:|XPS.*|OneNote.*|Microsoft.*)$'

    $orphanedPorts = $uniquePorts | Where-Object {
        $portName = $_
        $portName -notmatch $systemPortPattern -and
        -not ($remainingPrinters | Where-Object { $_.PortName -eq $portName })
    }

    if (@($orphanedPorts).Count -gt 0) {
        Write-Info "Found $(@($orphanedPorts).Count) orphaned port(s) - opening selection window."
        $selectedPorts = @($orphanedPorts) |
            ForEach-Object { [pscustomobject]@{ 'Port Name' = $_ } } |
            Out-GridView -Title "Orphaned Printer Ports - Select to remove (optional), or Cancel to skip" -PassThru

        foreach ($port in @($selectedPorts)) {
            if ($PSCmdlet.ShouldProcess($port.'Port Name', "Remove printer port")) {
                try {
                    Remove-PrinterPort -Name $port.'Port Name' -ErrorAction Stop
                    Write-OK "Removed port: $($port.'Port Name')"
                    $removedItems.Add("Port: $($port.'Port Name')") | Out-Null
                } catch {
                    Write-Fail "Could not remove port '$($port.'Port Name')': $_"
                    $failedItems.Add("Port: $($port.'Port Name')") | Out-Null
                }
            }
        }
    } else {
        Write-OK "No orphaned ports found."
    }
} else {
    Write-Info "No spooler entries removed - skipping port check."
}

# ────────────────────────────────────────────────────────────────────────────────
# STEP 6 - Restart Print Spooler
# ────────────────────────────────────────────────────────────────────────────────
Write-Section "Step 6: Restarting Print Spooler"

# Was unconditional - a real service disruption (stop+start) even under
# -WhatIf with items "selected" but not actually changed, despite no
# registry/printer/driver/port change having occurred.
if ($PSCmdlet.ShouldProcess("Print Spooler service", "Restart")) {
    try {
        Write-Info "Stopping Spooler..."
        Stop-Service -Name Spooler -Force -ErrorAction Stop
        Write-Info "Starting Spooler..."
        Start-Service -Name Spooler -ErrorAction Stop
        Write-OK "Print Spooler restarted."
    } catch {
        Write-Fail "Could not restart Spooler: $_"
        # One retry after a short delay before giving up - a handle transiently
        # held by another process during Stop-Service is common enough that a
        # short-delayed Start-Service retry often succeeds. If it still fails,
        # this needs to be visible in the final summary (not just scrolled past
        # in the console) - a stopped Print Spooler means printing is completely
        # broken on this machine with no other automatic recovery.
        Start-Sleep -Seconds 5
        try {
            Start-Service -Name Spooler -ErrorAction Stop
            Write-OK "Print Spooler started on retry."
        } catch {
            Write-Fail "Print Spooler could not be restarted after retry: $_"
            $failedItems.Add('Spooler service is NOT RUNNING - printing is broken on this machine. Manual intervention required.') | Out-Null
        }
    }
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
    "UP Printer Cleanup - Done",
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
# STEP 7 - Reboot
# Auto-schedules a reboot in 5 minutes. Prompt lets tech reboot now or cancel.
# ────────────────────────────────────────────────────────────────────────────────
Write-Section "Step 7: Reboot"

Stop-Transcript -ErrorAction SilentlyContinue | Out-Null

if ($removedItems.Count -eq 0) {
    Write-Info "Nothing was removed - reboot not needed."
} elseif ($Force) {
    Write-Info "Force mode - rebooting now."
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
        "Reboot Required - UP Printer Cleanup",
        "YesNoCancel",
        "Warning"
    )

    switch ($rebootAnswer) {
        'Yes' {
            Write-Info "Rebooting now..."
            # FIX 4: a shutdown /r /t 300 is already pending from above.
            # Without cancelling it first, this second scheduled shutdown is
            # rejected by shutdown.exe (error 1190 - a shutdown is already in
            # progress) and silently no-ops, leaving the machine on the
            # original 5-minute timer instead of rebooting now. 2>$null
            # suppresses the harmless "no shutdown to abort" case if the
            # first schedule didn't stick for some reason.
            shutdown /a 2>$null
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

# Previously the script just fell off the end here, so its exit code was
# whatever native command last set $LASTEXITCODE (e.g. shutdown.exe) rather
# than a true success/failure signal - the launcher .bat's %errorlevel% check
# was checking noise, not this script's actual outcome.
exit $(if ($failedItems.Count -gt 0) { 1 } else { 0 })
