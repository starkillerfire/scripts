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
Start-Transcript -Path $transcriptPath -Append

# Exit on domain controllers
try {
    $role = (Get-CimInstance Win32_ComputerSystem).DomainRole
    if ($role -in 4, 5) {
        Write-Log "Domain controller detected. Exiting for safety." "WARN"
        Stop-Transcript
        exit
    }
} catch {
    Write-Log "Unable to determine domain role." "WARN"
}

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
    try { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue; Write-Log "Stopped: $svc" }
    catch { Write-Log "Could not stop: $svc" "WARN" }
}
Start-Sleep -Seconds 5

# Backup repository
$backupPath = "$env:WINDIR\System32\wbem\Repository_Backup_$(Get-Date -Format 'yyyyMMddHHmmss')"
New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
Copy-Item -Path "$env:WINDIR\System32\wbem\Repository\*" -Destination $backupPath -Recurse -Force
Write-Log "WMI repository backed up to: $backupPath"

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
Start-Service winmgmt
Write-Log "Started: winmgmt"

# Retries a command that returns a process exit code (DISM/SFC, both of
# which can fail transiently - e.g. a momentarily locked file - and succeed
# on a second try) up to $Max times, waiting $Delay seconds between
# attempts. Returns whatever exit code the last attempt produced, whether
# that's the success on a retry or the final failure once attempts run out.
function Invoke-RetryCommand {
    param([scriptblock]$Cmd, [int]$Max = 3, [int]$Delay = 5)
    for ($i = 1; $i -le $Max; $i++) {
        $result = & $Cmd
        if ($result -eq 0) { return $result }
        if ($i -lt $Max) { Start-Sleep -Seconds $Delay }
    }
    return $result
}

$script:hadFailure = $false

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
    try { Start-Service -Name $svc -ErrorAction SilentlyContinue; Write-Log "Started: $svc" }
    catch { Write-Log "Could not start: $svc" "WARN" }
}

# Event log
if (-not $Silent) {
    try {
        New-EventLog -LogName Application -Source "WMIRepairScript" -ErrorAction SilentlyContinue
    } catch {}
    Write-EventLog -LogName Application -Source "WMIRepairScript" -EntryType Information -EventId 1001 -Message "WMI Repair completed on $env:COMPUTERNAME"
}

# Upload log
if ($UploadLog -and (Test-Path $CentralLogPath)) {
    $name = "$env:COMPUTERNAME-$(Get-Date -Format yyyyMMdd_HHmmss).txt"
    Copy-Item -Path $LogFile -Destination (Join-Path $CentralLogPath $name)
    Write-Log "Uploaded log to $CentralLogPath"
}

# Final message and reboot
Write-Log "=== WMI and Windows repair completed. ==="
if (-not $NoReboot) {
    Write-Log "System will reboot in 5 minutes. Save all work!" "INFO"
    shutdown.exe /r /t 300 /c "System will reboot in 5 minutes to complete WMI and Windows repair. Please save your work."
}

Stop-Transcript
exit ($(if ($script:hadFailure) { 1 } else { 0 }))
