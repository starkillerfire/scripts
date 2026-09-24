#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
    .NOTES
    ===========================================================================
     Created on:    4/21/2017
     Created by:    OCIO SCCM Team
     Updated:       2026-06-23 - Full rewrite for PS 5.1/7 compatibility.
                                  See revision history in source control.
     Filename:      Uninstall-ezPivCard.ps1
    ===========================================================================
    .DESCRIPTION
        Uninstalls ezPivCard by locating its MSI entry in the registry and
        invoking msiexec.

        Features:
          - Colored console output for easy local/interactive reading
          - Pre-flight checks: pending reboot, active MSI operation
          - Timestamped transcript log with automatic rotation
          - MSI verbose log with automatic rotation
          - Windows Application Event Log entries (source auto-registered)
          - msiexec timeout: process killed if it exceeds the configured limit
          - Post-uninstall registry verification to confirm removal
          - Reboot prompt when exit 3010 is returned (interactive mode only)
          - End-of-run summary table with color-coded status
          - Dry run mode: reports what would be uninstalled without taking action
          - Per-product confirmation prompt to prevent accidental removal
          - Additional product info: publisher, install date, install location
          - Opens transcript log in Notepad on completion (interactive mode)
          - Exit code propagation for deployment tool compatibility

        Requires: PowerShell 5.1 or later, Administrator rights.
        Compatible with: PowerShell 5.1 and PowerShell 7+.

        Parameters override the matching Configuration values below.
        Examples:
            .\Uninstall-ezPivCard.ps1 -DryRun
            .\Uninstall-ezPivCard.ps1 -Silent
            .\Uninstall-ezPivCard.ps1 -NoConfirm -TimeoutSeconds 600
            .\Uninstall-ezPivCard.ps1 -LogDir D:\Logs
#>
param(
    # Scan the registry and report what would be removed without running msiexec.
    [switch]$DryRun,

    # Suppress UI, colors, prompts, and msiexec progress bar. Use for deployment tools.
    [switch]$Silent,

    # Skip the per-product Y/N confirmation prompt even when $showUI is $true.
    [switch]$NoConfirm,

    # Do not open the transcript in Notepad after the script finishes.
    [switch]$NoOpenLog,

    # Override the log directory (default: C:\SoftwareLogs).
    [string]$LogDir,

    # Override the msiexec timeout in seconds (default: 300).
    [int]$TimeoutSeconds
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region --- Configuration ---

# Root directory for all logs written by this script.
$logDir = 'C:\SoftwareLogs'

# Number of transcript (.log) files to retain. Oldest removed before each run.
# Minimum value: 1
$transcriptKeepCount = 5

# Number of MSI verbose log files to retain per product. Oldest removed after each uninstall.
# Minimum value: 1
$msiLogKeepCount = 5

# Seconds to wait for msiexec before killing it and treating the uninstall as failed.
# Increase for large or slow packages.
$uninstallTimeoutSeconds = 300

# Windows Event Log source name. Registered in the Application log on first run.
$eventLogSource = 'ezPivCard Uninstaller'

# $true  = reduced UI (progress bar) + colored output + reboot prompt — for local/interactive runs.
# $false = fully silent (/qn) + plain output                          — for SCCM/Intune deployment.
$showUI = $true

# When $showUI is $true and an uninstall requires a reboot (exit 3010),
# prompt the user to restart the computer immediately.
$rebootPromptEnabled = $true

# $true  = scan the registry and report what WOULD be uninstalled, but do not run msiexec.
# $false = normal operation (default).
# Useful for verifying the script targets the correct entries before committing.
$dryRun = $false

# When $showUI is $true, prompt for confirmation before each uninstall.
# Prevents accidental removal when the script is run interactively.
$confirmEachUninstall = $true

# When $showUI is $true, open the transcript log in Notepad after the script finishes.
$openLogWhenDone = $true

#endregion

#region --- Apply Parameter Overrides ---

# Parameters take precedence over the Configuration defaults above.
if ($DryRun)          { $dryRun                 = $true  }
if ($Silent)          { $showUI                 = $false }
if ($NoConfirm)       { $confirmEachUninstall   = $false }
if ($NoOpenLog)       { $openLogWhenDone        = $false }
if ($LogDir)          { $logDir                 = $LogDir }
if ($TimeoutSeconds)  { $uninstallTimeoutSeconds = $TimeoutSeconds }

#endregion

#region --- Helper Functions ---

function Register-AppEventSource {
    <#
    .SYNOPSIS
        Ensures the Windows Event Log source exists. Creates it if not.
        Uses the .NET API directly for PS 5.1 and PS 7+ compatibility.
    #>
    param([string]$Source)
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
            [System.Diagnostics.EventLog]::CreateEventSource($Source, 'Application')
            Write-Host "Registered Windows Event Log source: '$Source'" -ForegroundColor DarkGray
        }
    } catch {
        Write-Warning "Could not register Event Log source '$Source': $_"
    }
}

function Write-AppEvent {
    <#
    .SYNOPSIS
        Writes an entry to the Windows Application Event Log.
        Silently warns on failure so a logging problem never aborts the uninstall.

    Event IDs used by this script:
        1000 - Script started
        1001 - Product not found (nothing to uninstall)
        1002 - Uninstall succeeded
        1003 - Uninstall succeeded, reboot required
        1004 - Uninstall failed
        1005 - msiexec timed out
        1006 - msiexec could not be launched
        1007 - Script completed successfully
        1008 - Script completed with one or more failures
    #>
    param(
        [string]$Message,
        [System.Diagnostics.EventLogEntryType]$EntryType = 'Information',
        [int]$EventId = 1000
    )
    try {
        $log        = [System.Diagnostics.EventLog]::new('Application')
        $log.Source = $script:eventLogSource
        $log.WriteEntry($Message, $EntryType, $EventId)
        $log.Dispose()
    } catch {
        Write-Warning "Could not write to Windows Event Log (ID $EventId): $_"
    }
}

function Invoke-LogRotation {
    <#
    .SYNOPSIS
        Deletes the oldest log files matching Filter when count exceeds KeepCount.
        Files are sorted by LastWriteTime; the newest KeepCount are retained.
    #>
    param(
        [string]$Path,
        [string]$Filter,
        [int]$KeepCount
    )
    if ($KeepCount -lt 0) { $KeepCount = 0 }

    # @() wrap is required under StrictMode: a single matching file collapses
    # the pipeline result to a scalar FileInfo, and .Count on a scalar throws.
    $logs = @(Get-ChildItem -Path $Path -Filter $Filter -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending)

    if ($logs.Count -gt $KeepCount) {
        foreach ($file in ($logs | Select-Object -Skip $KeepCount)) {
            try {
                Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                Write-Host "  Log rotation: removed $($file.Name)" -ForegroundColor DarkGray
            } catch {
                Write-Warning "Log rotation: could not remove '$($file.Name)': $_"
            }
        }
    }
}

function Test-PendingReboot {
    <#
    .SYNOPSIS
        Returns $true if the system has a pending reboot from any common source.
        A pending reboot can cause MSI operations to fail or behave unexpectedly.
    #>
    # Component Based Servicing (Windows Updates / features)
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        return $true
    }
    # Windows Update
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        return $true
    }
    # Pending File Rename Operations (file-in-use replacements queued for reboot)
    $pfro = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
                             -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
    if ($pfro -and $pfro.PendingFileRenameOperations) { return $true }

    return $false
}

function Test-MSIBusy {
    <#
    .SYNOPSIS
        Returns 'Busy', 'NotBusy', or 'Unknown' for whether another MSI
        install/uninstall is currently in progress. Uses the
        Global\_MSIExecute mutex, which the Windows Installer holds
        exclusively during any active install or uninstall operation.

    .DESCRIPTION
        WaitHandleCannotBeOpenedException specifically means the mutex
        doesn't exist right now - a real "not busy". Any other exception
        (e.g. access denied opening it under a restrictive policy) means
        the busy/not-busy state genuinely couldn't be determined, which is
        a different thing from confirming it's not busy and shouldn't be
        reported to the operator as if it were.
    #>
    try {
        $mutex = [System.Threading.Mutex]::OpenExisting('Global\_MSIExecute')
        $mutex.Dispose()
        return 'Busy'
    } catch [System.Threading.WaitHandleCannotBeOpenedException] {
        return 'NotBusy'
    } catch {
        return 'Unknown'
    }
}

#endregion

#region --- Setup ---

$startTime = Get-Date

if (-not (Test-Path -Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force -ErrorAction Stop | Out-Null
}

# Register the Event Log source before starting the transcript so any
# registration output is captured in the log.
Register-AppEventSource -Source $eventLogSource

# Rotate transcript logs down to (KeepCount - 1) BEFORE starting the new transcript
# so that after it opens the total count equals KeepCount.
Invoke-LogRotation -Path $logDir -Filter 'Uninstall-ezPivCard_*.log' -KeepCount ($transcriptKeepCount - 1)

$transcript = "$logDir\Uninstall-ezPivCard_$($startTime.ToString('yyyy-MM-dd_HHmmss')).log"
# -ErrorAction SilentlyContinue: transcript logging is best-effort and runs
# before the try/finally below, so under $ErrorActionPreference = 'Stop' an
# unhandled failure here would abort the whole uninstall before it starts.
Start-Transcript -Path $transcript -Append -ErrorAction SilentlyContinue | Out-Null

#endregion

# Wrap all logic in try/finally so Stop-Transcript always runs,
# even if an unhandled exception aborts execution mid-script.
try {

    #region --- Header ---

    $osCaption = try {
        (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
    } catch {
        "Unknown (CIM unavailable: $_)"
    }

    $divider = '=' * 60

    Write-Host "`n$divider" -ForegroundColor Cyan
    Write-Host '  ezPivCard Uninstall Script' -ForegroundColor Cyan
    Write-Host $divider -ForegroundColor Cyan
    Write-Host "  Started    : $startTime" -ForegroundColor White
    Write-Host "  Computer   : $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "  Running as : $([Security.Principal.WindowsIdentity]::GetCurrent().Name)" -ForegroundColor White
    Write-Host "  PS version : $($PSVersionTable.PSVersion)" -ForegroundColor White
    Write-Host "  OS         : $osCaption" -ForegroundColor White
    Write-Host "  Timeout    : $uninstallTimeoutSeconds seconds per product" -ForegroundColor White
    Write-Host "  Show UI    : $showUI" -ForegroundColor White
    Write-Host "  Dry run    : $dryRun" -ForegroundColor White
    Write-Host "  Log        : $transcript" -ForegroundColor White
    Write-Host $divider -ForegroundColor Cyan

    if ($dryRun) {
        Write-Host '  *** DRY RUN MODE — registry will be scanned but msiexec will NOT run ***' -ForegroundColor Magenta
        Write-Host $divider -ForegroundColor Cyan
    }

    $dryRunNote = if ($dryRun) { ' [DRY RUN — no changes]' } else { '' }
    Write-AppEvent -EventId 1000 -EntryType Information `
        -Message "ezPivCard uninstall started$dryRunNote on $env:COMPUTERNAME by $([Security.Principal.WindowsIdentity]::GetCurrent().Name). PS $($PSVersionTable.PSVersion)."

    #endregion

    #region --- Pre-flight Checks ---

    Write-Host "`n[Pre-flight checks]" -ForegroundColor Cyan

    if (Test-PendingReboot) {
        Write-Host '  WARNING: This system has a pending reboot.' -ForegroundColor Yellow
        Write-Host '           MSI operations may fail or behave unexpectedly until restarted.' -ForegroundColor Yellow
    } else {
        Write-Host '  Pending reboot : None' -ForegroundColor Green
    }

    switch (Test-MSIBusy) {
        'Busy' {
            Write-Host '  WARNING: Another install/uninstall is currently in progress (MSI mutex held).' -ForegroundColor Yellow
            Write-Host '           This uninstall may fail with exit code 1618. Consider retrying later.' -ForegroundColor Yellow
        }
        'Unknown' {
            Write-Host '  WARNING: Could not determine whether another MSI operation is running' -ForegroundColor Yellow
            Write-Host '           (mutex check failed, possibly a permissions restriction). If this' -ForegroundColor Yellow
            Write-Host '           uninstall fails with exit code 1618, another MSI operation may be active.' -ForegroundColor Yellow
        }
        default {
            Write-Host '  MSI busy       : No other MSI operation running' -ForegroundColor Green
        }
    }

    #endregion

    #region --- Locate ezPivCard Registry Entries ---

    Write-Host "`n[Searching registry for ezPivCard...]" -ForegroundColor Cyan

    $registryPaths = @(
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    # Select-Object normalizes every entry to a fixed property set before
    # filtering. Under StrictMode, accessing $_.DisplayName on a raw
    # Get-ItemProperty result throws for any Uninstall subkey that has no
    # DisplayName value at all (common - many subkeys are hotfix/component
    # entries with only a handful of values) rather than returning $null.
    # Selecting these properties up front guarantees they exist (as $null
    # when absent from the registry) on every object the rest of the script
    # reads from $found/$entry below.
    $found = Get-ChildItem -Path $registryPaths -ErrorAction SilentlyContinue |
             Get-ItemProperty -ErrorAction SilentlyContinue |
             Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, UninstallString |
             Where-Object { $_.DisplayName -like 'ezPivCard*' }

    if (-not $found) {
        $msg = "ezPivCard not found in registry on $env:COMPUTERNAME. Nothing to uninstall."
        Write-Host '  ezPivCard not found in registry. Nothing to uninstall.' -ForegroundColor Yellow
        Write-AppEvent -EventId 1001 -EntryType Information -Message $msg
        exit 0
    }

    # Deduplicate: same product can appear in both native and Wow6432Node hives.
    $found = $found | Sort-Object UninstallString -Unique
    Write-Host "  Found $(@($found).Count) unique entry/entries to process." -ForegroundColor White

    #endregion

    #region --- Uninstall Each Entry ---

    # Fully-qualified path avoids any PATH-based resolution issue.
    $msiexec      = "$env:SystemRoot\System32\msiexec.exe"
    $illegalChars = '[\\/:*?"<>|\s]'
    $quietFlag    = if ($showUI) { '/q' } else { '/qn' }
    $exitCode     = 0
    $needsReboot  = $false

    # Collects one row per product for the summary table shown at the end.
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($entry in $found) {

        $displayName     = $entry.DisplayName
        $displayVersion  = $entry.DisplayVersion
        $publisher       = $entry.Publisher
        $installDate     = $entry.InstallDate
        $installLocation = $entry.InstallLocation

        Write-Host "`n$('-' * 60)" -ForegroundColor DarkGray
        Write-Host "  Product    : $displayName $displayVersion" -ForegroundColor White
        if ($publisher)       { Write-Host "  Publisher  : $publisher"       -ForegroundColor DarkGray }
        if ($installDate)     { Write-Host "  Installed  : $installDate"     -ForegroundColor DarkGray }
        if ($installLocation) { Write-Host "  Location   : $installLocation" -ForegroundColor DarkGray }

        # --- Validate registry entry ---
        if (-not $entry.UninstallString) {
            Write-Host '  SKIP: No UninstallString found.' -ForegroundColor Yellow
            $results.Add([PSCustomObject]@{ Product = $displayName; Version = $displayVersion; Status = 'SKIPPED'; Code = '-'; Elapsed = '-' })
            continue
        }

        if ($entry.UninstallString -notlike '*msiexec*') {
            Write-Host '  SKIP: Non-MSI uninstaller — manual removal may be required.' -ForegroundColor Yellow
            Write-Host "        UninstallString: $($entry.UninstallString)" -ForegroundColor DarkGray
            $results.Add([PSCustomObject]@{ Product = $displayName; Version = $displayVersion; Status = 'SKIPPED'; Code = '-'; Elapsed = '-' })
            continue
        }

        if ($entry.UninstallString -match '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}') {
            $guid = $Matches[0]
        } else {
            Write-Host '  SKIP: Could not parse a valid GUID from UninstallString.' -ForegroundColor Yellow
            Write-Host "        UninstallString: $($entry.UninstallString)" -ForegroundColor DarkGray
            $results.Add([PSCustomObject]@{ Product = $displayName; Version = $displayVersion; Status = 'SKIPPED'; Code = '-'; Elapsed = '-' })
            continue
        }

        # --- Dry run: report without executing ---
        if ($dryRun) {
            Write-Host "  [DRY RUN] Would uninstall: $displayName $displayVersion" -ForegroundColor Magenta
            Write-Host "            GUID: $guid" -ForegroundColor Magenta
            $results.Add([PSCustomObject]@{ Product = $displayName; Version = $displayVersion; Status = 'DRY RUN'; Code = '-'; Elapsed = '-' })
            continue
        }

        # --- Confirmation prompt ---
        if ($showUI -and $confirmEachUninstall) {
            Write-Host "`n  About to uninstall: $displayName $displayVersion" -ForegroundColor Yellow
            Write-Host '  Proceed? (Y/N): ' -ForegroundColor Yellow -NoNewline
            $confirm = Read-Host
            if ($confirm -notmatch '^[Yy]') {
                Write-Host '  SKIPPED by user.' -ForegroundColor Yellow
                $results.Add([PSCustomObject]@{ Product = $displayName; Version = $displayVersion; Status = 'SKIPPED'; Code = '-'; Elapsed = '-' })
                continue
            }
        }

        # --- Build paths and arguments ---
        $dName  = $displayName -replace $illegalChars, '_'
        $dVer   = if ($displayVersion) {
                      $displayVersion -replace $illegalChars, '-' -replace '\.', '-'
                  } else {
                      'unknown'
                  }
        $msiLog = "$logDir\${dName}_${dVer}_uninstall.log"

        # /X  = uninstall by GUID
        # /q or /qn = UI mode controlled by $showUI
        # /norestart = suppress automatic reboot
        # /l*v = verbose MSI log
        $uArgs = "/X$guid $quietFlag /norestart /l*v `"$msiLog`""

        Write-Host "  GUID    : $guid" -ForegroundColor DarkGray
        Write-Host "  MSI log : $msiLog" -ForegroundColor DarkGray
        Write-Host "  Timeout : $uninstallTimeoutSeconds seconds" -ForegroundColor DarkGray
        Write-Host '  Running msiexec...' -ForegroundColor White

        # --- Launch msiexec with timeout ---
        $entryStart = Get-Date

        try {
            # Do NOT use -Wait. WaitForExit(ms) returns a bool so we can implement a timeout.
            $proc   = Start-Process -FilePath $msiexec -ArgumentList $uArgs `
                                    -NoNewWindow -PassThru -ErrorAction Stop

            # $true = exited within timeout; $false = timed out
            $exited = $proc.WaitForExit($uninstallTimeoutSeconds * 1000)

            if (-not $exited) {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                $elapsed     = [Math]::Round(((Get-Date) - $entryStart).TotalSeconds, 1)
                $timeoutMsg  = "msiexec timed out after $uninstallTimeoutSeconds seconds for '$displayName $displayVersion' on $env:COMPUTERNAME. Process killed."
                Write-Host "  TIMEOUT: msiexec killed after ${uninstallTimeoutSeconds}s. See MSI log: $msiLog" -ForegroundColor Red
                Write-AppEvent -EventId 1005 -EntryType Error -Message $timeoutMsg
                $results.Add([PSCustomObject]@{ Product = $displayName; Version = $displayVersion; Status = 'TIMED OUT'; Code = '-2'; Elapsed = "${elapsed}s" })
                $exitCode = -2
                $proc.Dispose()
                continue
            }

            # No-arg WaitForExit after the timed wait ensures ExitCode is fully flushed.
            $proc.WaitForExit()
            $result = if ($null -ne $proc.ExitCode) { $proc.ExitCode } else { -1 }
            $proc.Dispose()

        } catch {
            $elapsed    = [Math]::Round(((Get-Date) - $entryStart).TotalSeconds, 1)
            $launchMsg  = "Failed to launch msiexec.exe for '$displayName $displayVersion' on $env:COMPUTERNAME`: $_"
            Write-Host "  FAILED: Could not launch msiexec.exe: $_" -ForegroundColor Red
            Write-AppEvent -EventId 1006 -EntryType Error -Message $launchMsg
            $results.Add([PSCustomObject]@{ Product = $displayName; Version = $displayVersion; Status = 'LAUNCH FAILED'; Code = '1'; Elapsed = "${elapsed}s" })
            $exitCode = 1
            continue
        }

        $elapsed = [Math]::Round(((Get-Date) - $entryStart).TotalSeconds, 1)

        # --- Interpret exit code ---
        switch ($result) {
            0 {
                Write-Host "  SUCCESS (exit 0) — elapsed: ${elapsed}s" -ForegroundColor Green
                Write-AppEvent -EventId 1002 -EntryType Information `
                    -Message "Successfully uninstalled $displayName $displayVersion on $env:COMPUTERNAME in ${elapsed}s."
                $results.Add([PSCustomObject]@{ Product = $displayName; Version = $displayVersion; Status = 'SUCCESS'; Code = '0'; Elapsed = "${elapsed}s" })
            }
            3010 {
                Write-Host "  SUCCESS — reboot required (exit 3010) — elapsed: ${elapsed}s" -ForegroundColor Yellow
                Write-AppEvent -EventId 1003 -EntryType Warning `
                    -Message "Successfully uninstalled $displayName $displayVersion on $env:COMPUTERNAME in ${elapsed}s. Reboot required."
                $results.Add([PSCustomObject]@{ Product = $displayName; Version = $displayVersion; Status = 'SUCCESS/REBOOT'; Code = '3010'; Elapsed = "${elapsed}s" })
                $needsReboot = $true
            }
            1605 {
                Write-Host "  NOT INSTALLED (exit 1605) — may have already been removed." -ForegroundColor Yellow
                $results.Add([PSCustomObject]@{ Product = $displayName; Version = $displayVersion; Status = 'NOT FOUND'; Code = '1605'; Elapsed = "${elapsed}s" })
            }
            1603 {
                Write-Host "  FAILED — fatal error (exit 1603) after ${elapsed}s. See MSI log: $msiLog" -ForegroundColor Red
                Write-AppEvent -EventId 1004 -EntryType Error `
                    -Message "Fatal error uninstalling $displayName $displayVersion on $env:COMPUTERNAME (exit 1603). See: $msiLog"
                $results.Add([PSCustomObject]@{ Product = $displayName; Version = $displayVersion; Status = 'FAILED'; Code = '1603'; Elapsed = "${elapsed}s" })
                $exitCode = $result
            }
            1618 {
                Write-Host "  FAILED — another install/uninstall in progress (exit 1618). Retry after other operation completes." -ForegroundColor Red
                Write-AppEvent -EventId 1004 -EntryType Error `
                    -Message "Uninstall of $displayName $displayVersion failed on $env:COMPUTERNAME — MSI busy (exit 1618)."
                $results.Add([PSCustomObject]@{ Product = $displayName; Version = $displayVersion; Status = 'FAILED'; Code = '1618'; Elapsed = "${elapsed}s" })
                $exitCode = $result
            }
            1619 {
                Write-Host "  FAILED — MSI package could not be opened (exit 1619). Package may be missing or corrupt." -ForegroundColor Red
                Write-AppEvent -EventId 1004 -EntryType Error `
                    -Message "Uninstall of $displayName $displayVersion failed on $env:COMPUTERNAME — package not found (exit 1619)."
                $results.Add([PSCustomObject]@{ Product = $displayName; Version = $displayVersion; Status = 'FAILED'; Code = '1619'; Elapsed = "${elapsed}s" })
                $exitCode = $result
            }
            -1 {
                Write-Host '  FAILED — msiexec exit code was null (process handle lost).' -ForegroundColor Red
                Write-AppEvent -EventId 1004 -EntryType Error `
                    -Message "Uninstall of $displayName $displayVersion failed on $env:COMPUTERNAME — null exit code."
                $results.Add([PSCustomObject]@{ Product = $displayName; Version = $displayVersion; Status = 'FAILED'; Code = '-1'; Elapsed = "${elapsed}s" })
                $exitCode = -1
            }
            default {
                Write-Host "  FAILED — exit code $result after ${elapsed}s. See MSI log: $msiLog" -ForegroundColor Red
                Write-AppEvent -EventId 1004 -EntryType Error `
                    -Message "Uninstall of $displayName $displayVersion failed on $env:COMPUTERNAME with exit code $result. See: $msiLog"
                $results.Add([PSCustomObject]@{ Product = $displayName; Version = $displayVersion; Status = 'FAILED'; Code = "$result"; Elapsed = "${elapsed}s" })
                $exitCode = $result
            }
        }

        # --- Post-uninstall registry verification ---
        # Confirm the registry entry is actually gone after a reported success.
        if ($result -eq 0 -or $result -eq 3010) {
            $verifyPaths  = $registryPaths | ForEach-Object { "$_\$guid" }
            $stillPresent = $verifyPaths | Where-Object { Test-Path -Path $_ }
            if ($stillPresent) {
                Write-Host '  WARNING: msiexec reported success but the registry entry is still present.' -ForegroundColor Yellow
                Write-Host '           The removal may be incomplete. Check the MSI log for details.' -ForegroundColor Yellow
            } else {
                Write-Host '  Verified: registry entry removed.' -ForegroundColor DarkGray
            }
        }

        # --- Rotate MSI logs after the uninstall ---
        # The log just created is the newest; rotation keeps $msiLogKeepCount including it.
        Invoke-LogRotation -Path $logDir -Filter "${dName}_*_uninstall.log" -KeepCount $msiLogKeepCount
    }

    #endregion

    #region --- Summary ---

    $totalElapsed = [Math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)

    Write-Host "`n$divider" -ForegroundColor Cyan
    Write-Host '  UNINSTALL SUMMARY' -ForegroundColor Cyan
    Write-Host $divider -ForegroundColor Cyan

    foreach ($r in $results) {
        $color = switch ($r.Status) {
            'SUCCESS'        { 'Green'   }
            'SUCCESS/REBOOT' { 'Yellow'  }
            'DRY RUN'        { 'Magenta' }
            default          { if ($r.Status -like 'SKIP*' -or $r.Status -eq 'NOT FOUND') { 'Yellow' } else { 'Red' } }
        }
        $label = "[$($r.Status)]".PadRight(18)
        Write-Host "  $label $($r.Product) $($r.Version)  [$($r.Elapsed)]" -ForegroundColor $color
    }

    Write-Host $divider -ForegroundColor Cyan
    Write-Host "  Computer  : $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "  Started   : $startTime" -ForegroundColor White
    Write-Host "  Finished  : $(Get-Date)" -ForegroundColor White
    Write-Host "  Duration  : ${totalElapsed}s" -ForegroundColor White

    $codeColor = if ($exitCode -eq 0) { 'Green' } else { 'Red' }
    Write-Host "  Exit code : $exitCode" -ForegroundColor $codeColor
    Write-Host $divider -ForegroundColor Cyan

    if ($exitCode -eq 0) {
        Write-AppEvent -EventId 1007 -EntryType Information `
            -Message "ezPivCard uninstall completed successfully on $env:COMPUTERNAME. Duration: ${totalElapsed}s."
    } else {
        Write-AppEvent -EventId 1008 -EntryType Error `
            -Message "ezPivCard uninstall completed with errors on $env:COMPUTERNAME. Exit code: $exitCode. Duration: ${totalElapsed}s."
    }

    #endregion

    #region --- Reboot Prompt ---

    if ($needsReboot -and $showUI -and $rebootPromptEnabled) {
        Write-Host "`nA system restart is required to complete the uninstall." -ForegroundColor Yellow
        Write-Host 'Restart now? (Y/N): ' -ForegroundColor Yellow -NoNewline
        $answer = Read-Host
        if ($answer -match '^[Yy]') {
            Write-Host 'Restarting...' -ForegroundColor Cyan
            # Stop transcript before restart so the log is properly closed.
            Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
            # -ErrorAction SilentlyContinue: this is the last meaningful step;
            # a failure here shouldn't prevent the script from reaching its
            # already-computed exit code below.
            Restart-Computer -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host 'Restart deferred. Please restart as soon as possible.' -ForegroundColor Yellow
        }
    }

    #endregion

    # Open the transcript log in Notepad so the user can review it without hunting for the file.
    if ($showUI -and $openLogWhenDone) {
        Write-Host "`nLog file: $transcript" -ForegroundColor DarkGray
        # -ErrorAction SilentlyContinue: opening the log for convenience
        # should never prevent the script from reaching `exit $exitCode`.
        Start-Process 'notepad.exe' -ArgumentList $transcript -ErrorAction SilentlyContinue
    }

    exit $exitCode

} finally {
    # -ErrorAction SilentlyContinue suppresses the error thrown when no
    # transcript is running (e.g., already stopped before a Restart-Computer).
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
}
