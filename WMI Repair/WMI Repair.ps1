#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enterprise-grade script to repair and reset the WMI repository, re-register WMI components,
    perform DISM and SFC health checks, log results locally and optionally to a remote share,
    and reboot the system after a delay.

.PARAMETER Silent
    Suppress most on-screen output.

.PARAMETER NoReboot
    Do not schedule reboot after repair is complete.

.PARAMETER UploadLog
    Upload the log file to a central UNC path.

.NOTES
    Author: Iron Wolf Technology
    Version: 1.1
    Date: 2025-06-20
#>

[CmdletBinding()]
param (
    [switch] $Silent,
    [switch] $NoReboot,
    [switch] $UploadLog,
    [string] $LogFile        = 'C:\ProgramData\Logs\WMI_Repair_Log.txt',
    [string] $CentralLogPath = '\\fileserver\logs$\WMIRepair'
)

Set-StrictMode -Version Latest

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp][$Level] $Message"
    if (-not $Silent) { Write-Host $entry }
    Add-Content -Path $LogFile -Value $entry
}

# Start fresh log
$logDir = Split-Path $LogFile
if ($logDir -and -not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
Remove-Item $LogFile -ErrorAction SilentlyContinue
$transcriptPath = Join-Path (Split-Path $LogFile) 'WMI_Repair_Transcript.txt'
# Was -Append with nothing ever clearing it, so it grew unbounded across
# repeated runs on the same machine - $LogFile just above is already started
# fresh each run (Remove-Item before Add-Content), so match that here too.
Remove-Item $transcriptPath -ErrorAction SilentlyContinue
Start-Transcript -Path $transcriptPath

# Exit on domain controllers
try {
    $role = (Get-CimInstance Win32_ComputerSystem).DomainRole
    if ($role -in 4, 5) {
        Write-Log "Domain controller detected. Exiting for safety." "WARN"
        Stop-Transcript
        # Explicit 0: a bare `exit` here would return whatever $LASTEXITCODE
        # happened to hold from before this script started (native exit
        # codes persist across invocations in the same console), which
        # could show a stale nonzero/zero code unrelated to this
        # intentional, successful skip.
        exit 0
    }
} catch {
    Write-Log "Unable to determine domain role." "WARN"
}

$script:hadFailure = $false

Write-Log "=== Starting WMI Repair and Windows Health Check ==="

# Check if WMI is broken
if (-not (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue)) {
    Write-Log "WMI is not responding. Repair will proceed." "WARN"
} else {
    Write-Log "WMI appears to be functional."
}

# Stop services (exclude EventLog and RpcSs to avoid system impact)
$servicesToStop = @("Winmgmt", "wscsvc", "iphlpsvc", "msiserver", "BITS")
foreach ($svc in $servicesToStop) {
    # -Force -ErrorAction SilentlyContinue makes this non-terminating, so a
    # try/catch here never actually fires - check the real resulting status
    # instead. Best-effort: a failure to stop one of these auxiliary
    # services should not abort the repair.
    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    $svcAfterStop = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($svcAfterStop -and $svcAfterStop.Status -ne 'Stopped') {
        Write-Log "Could not stop: $svc (status: $($svcAfterStop.Status))" "WARN"
    } else {
        Write-Log "Stopped: $svc"
    }
}
Start-Sleep -Seconds 5

# Confirm Winmgmt actually stopped before backing up its repository - a
# partially-locked copy taken while the service is still running/shutting
# down can silently produce an incomplete backup right before the
# destructive salvage/reset steps below run.
$winmgmtSvc = Get-Service -Name Winmgmt -ErrorAction SilentlyContinue
if ($winmgmtSvc -and $winmgmtSvc.Status -ne 'Stopped') {
    Write-Log "Winmgmt did not fully stop (status: $($winmgmtSvc.Status)) - the repository backup below may be incomplete." "WARN"
}

# Backup repository
$backupPath = "$env:WINDIR\System32\wbem\Repository_Backup_$(Get-Date -Format 'yyyyMMddHHmmss')"
New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
try {
    Copy-Item -Path "$env:WINDIR\System32\wbem\Repository\*" -Destination $backupPath -Recurse -Force -ErrorAction Stop
    Write-Log "WMI repository backed up to: $backupPath"
} catch {
    Write-Log "WMI repository backup FAILED: $_ - proceeding with repair anyway, but there is no safety net if the salvage/reset below goes wrong." "ERROR"
    $script:hadFailure = $true
}

# Restrict the backup to admins - it's a full copy of the WMI repository
# under System32 and shouldn't be left world-readable.
cmd /c "icacls `"$backupPath`" /inheritance:r /grant:r `"Administrators:(OI)(CI)F`" `"SYSTEM:(OI)(CI)F`"" | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Log "Failed to set restrictive ACL on backup directory (icacls exit $LASTEXITCODE)." "WARN" }

# Repository_Backup_* directories accumulate on every run otherwise - prune
# anything older than 30 days.
Get-ChildItem "$env:WINDIR\System32\wbem" -Directory -Filter 'Repository_Backup_*' -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

# Attempt to salvage the repository first; only hard-reset if WMI still fails
cmd /c "winmgmt /salvagerepository" | Out-Null
Write-Log "WMI salvage attempted (exit $LASTEXITCODE)."

Start-Service winmgmt -ErrorAction SilentlyContinue
Start-Sleep -Seconds 5

if (-not (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue)) {
    Write-Log "WMI still unresponsive after salvage - performing hard reset." "WARN"
    Stop-Service winmgmt -Force -ErrorAction SilentlyContinue
    cmd /c "winmgmt /resetrepository" | Out-Null
    Write-Log "WMI hard reset completed (exit $LASTEXITCODE)."
    # Must restart winmgmt here, before DLL registration/MOF recompilation below -
    # mofcomp needs a running WMI service to connect to, and previously this
    # didn't restart until after that step, so recompilation silently failed
    # in exactly this hard-reset scenario.
    Start-Service winmgmt -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
} else {
    Write-Log "WMI responsive after salvage - skipping hard reset."
}

# Register DLLs
$wmiDlls = @("wbemdisp.dll", "wbemprox.dll", "wbemcomn.dll", "fastprox.dll", "scrcons.exe")
$system32 = "$env:WINDIR\System32"
foreach ($dll in $wmiDlls) {
    $dllPath = Join-Path $system32 "wbem\$dll"
    if (Test-Path $dllPath) {
        # cmd /c never throws .NET exceptions - check $LASTEXITCODE instead
        cmd /c "regsvr32 /s `"$dllPath`"" | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Registered: $dll"
        } else {
            Write-Log "Failed to register: $dll (regsvr32 exit $LASTEXITCODE)" "WARN"
        }
    }
}

# Recompile MOFs
Push-Location "$env:WINDIR\System32\wbem"
Get-ChildItem *.mof, *.mfl -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    # cmd /c never throws .NET exceptions - check $LASTEXITCODE instead
    cmd /c "mofcomp `"$($_.FullName)`"" | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Log "Compiled: $($_.Name)"
    } else {
        Write-Log "Failed to compile: $($_.Name) (mofcomp exit $LASTEXITCODE)" "WARN"
    }
}
Pop-Location

# Start WMI
try {
    Start-Service winmgmt -ErrorAction Stop
    Write-Log "Started: winmgmt"
} catch {
    Write-Log "Failed to start winmgmt: $_" "ERROR"
    $script:hadFailure = $true
}

# Retries a command that returns a process exit code (DISM/SFC, both of
# which can fail transiently - e.g. a momentarily locked file - and succeed
# on a second try) up to $Max times, waiting $Delay seconds between
# attempts. Returns whatever exit code the last attempt produced, whether
# that's the success on a retry or the final failure once attempts run out.
function Invoke-RetryCommand {
    param([scriptblock]$Cmd, [int]$Max = 3, [int]$Delay = 5)
    # Guards against a StrictMode crash on the final `return $result` if
    # -Max is ever 0 or negative (no current caller does this, but nothing
    # stops a future one) - the loop body would never run, leaving $result
    # undefined instead of $null.
    $result = $null
    for ($i = 1; $i -le $Max; $i++) {
        $result = & $Cmd
        if ($result -eq 0) { return $result }
        if ($i -lt $Max) { Start-Sleep -Seconds $Delay }
    }
    return $result
}

# DISM
Write-Log "Running DISM..."
$exitCode = Invoke-RetryCommand -Cmd { (Start-Process DISM -ArgumentList "/Online","/Cleanup-Image","/RestoreHealth" -Wait -PassThru).ExitCode }
Write-Log "DISM exit code: $exitCode"
if ($exitCode -ne 0) { Write-Log "DISM failed." "ERROR"; $script:hadFailure = $true }

# SFC
Write-Log "Running SFC..."
$exitCode = Invoke-RetryCommand -Cmd { (Start-Process sfc -ArgumentList "/scannow" -Wait -PassThru).ExitCode }
Write-Log "SFC exit code: $exitCode"
if ($exitCode -ne 0) { Write-Log "SFC encountered issues." "WARN"; $script:hadFailure = $true }

# Restart services
foreach ($svc in $servicesToStop) {
    # -ErrorAction SilentlyContinue makes this non-terminating, so a
    # try/catch here never actually fires - check the real resulting status
    # instead. Best-effort: a failure to start one of these auxiliary
    # services should not abort the repair.
    Start-Service -Name $svc -ErrorAction SilentlyContinue
    $svcAfterStart = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($svcAfterStart -and $svcAfterStart.Status -eq 'Running') {
        Write-Log "Started: $svc"
    } else {
        Write-Log "Could not start: $svc$(if ($svcAfterStart) { " (status: $($svcAfterStart.Status))" })" "WARN"
    }
}

# Final verification - the exit code and "completed" message below only
# reflect DISM/SFC results. This confirms whether the actual WMI repair
# (the reason this script exists) succeeded, since the script could
# otherwise report success even when the core repair failed.
if (-not (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue)) {
    Write-Log "WMI is still unresponsive after all repair steps - the underlying repair did not succeed." "ERROR"
    $script:hadFailure = $true
} else {
    Write-Log "WMI verified responsive after repair."
}

# Event log
if (-not $Silent) {
    try {
        New-EventLog -LogName Application -Source "WMIRepairScript" -ErrorAction SilentlyContinue
    } catch {}
    Write-EventLog -LogName Application -Source "WMIRepairScript" -EntryType Information -EventId 1001 -Message "WMI Repair completed on $env:COMPUTERNAME"
}

# Upload log. -CentralLogPath defaults to a placeholder UNC path
# ('\\fileserver\logs$\WMIRepair') that won't exist in most environments -
# confirm/update it for this site. Previously, if -UploadLog was requested
# but that share wasn't reachable, this step just silently did nothing;
# now it logs a clear warning instead so a misconfigured/unreachable share
# doesn't look like a successful, silent no-op.
if ($UploadLog) {
    if (Test-Path $CentralLogPath) {
        $name = "$env:COMPUTERNAME-$(Get-Date -Format yyyyMMdd_HHmmss).txt"
        Copy-Item -Path $LogFile -Destination (Join-Path $CentralLogPath $name)
        Write-Log "Uploaded log to $CentralLogPath"
    } else {
        Write-Log "UploadLog was requested but CentralLogPath is not reachable: $CentralLogPath (check the path is correct for this site and that this machine has access)" "WARN"
    }
}

# Final message and reboot
Write-Log "=== WMI and Windows repair completed. ==="
if (-not $NoReboot) {
    Write-Log "System will reboot in 5 minutes. Save all work!" "INFO"
    shutdown.exe /r /t 300 /c "System will reboot in 5 minutes to complete WMI and Windows repair. Please save your work."
}

Stop-Transcript
exit ($(if ($script:hadFailure) { 1 } else { 0 }))
