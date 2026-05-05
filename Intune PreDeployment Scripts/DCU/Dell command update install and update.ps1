<#
.SYNOPSIS
    Dell Command | Update - Enterprise Automation (v6.5.0)

.DESCRIPTION
    Core DCU automation without compliance JSON, notifications, or
    scheduled-reboot logic. Compatible with DCU 5.5.0 A00 (Jun 2025).
#>

# ─── PARAMETERS ───────────────────────────────────────────────────────────────
[CmdletBinding(DefaultParameterSetName='Online')]
param(
    # Common
    [string]$ConfigPath    = 'C:\ProgramData\Dell\DCUScript.json',
    [string]$InstallerPath = "$env:TEMP\DellCommandUpdate.exe",
    [string]$LogRoot       = "$env:ProgramData\Dell\DCU-ScriptLogs",
    [ValidateRange(0,10000)][int]$BitsThrottleKBps = 0,
    [ValidateSet('All','BIOSOnly','DriversOnly')][string]$Mode = 'All',
    [switch]$NoReboot,[switch]$DisableBIOSUpdates,[switch]$SkipBiosOnBattery,
    [switch]$StageOnly,[int]$WaitForAcMinutes=15,[int]$MinBatteryPercentForBios=50,
    [switch]$Quiet,[switch]$DebugLog,

    # Runtime
    [switch]$SelfHostPwsh7,

    # Online
    [Parameter(ParameterSetName='Online')][switch]$Latest,
    [Parameter(ParameterSetName='Online')]
        [ValidateScript({[uri]$_})]
        [string]$DCUDownloadUrl='https://dl.dell.com/FOLDER13309338M/2/Dell-Command-Update-Application_Y5VJV_WIN64_5.5.0_A00_01.EXE',
    [Parameter(ParameterSetName='Online')][string]$MirrorUrl='https://downloads3.dell.com/firmware/Dell-Command-Update.exe',

    # Offline
    [Parameter(ParameterSetName='Offline',Mandatory)]
        [ValidateScript({Test-Path $_ -PathType Container})][string]$OfflineRepository,

    # Proxy
    [string]$WebProxy,[pscredential]$ProxyCredential,

    # .NET override
    [string]$DotNetUrl
)

# ─── PREAMBLE ────────────────────────────────────────────────────────────────
$Version = '6.5.0'

if ($SelfHostPwsh7 -and $PSVersionTable.PSVersion.Major -lt 7) {
    if ($pwsh = Get-Command pwsh.exe -EA 0) { & $pwsh.Path -File $PSCommandPath @PSBoundParameters; exit }
}

$timer = [Diagnostics.Stopwatch]::StartNew()
$mutex = [Threading.Mutex]::new($true,'Global\DCUUpdateLock',[ref]$lock)
if (-not $lock) { Write-Host 'Another instance is running.'; exit 255 }
Register-EngineEvent PowerShell.Exiting -Action {
        try { Stop-Transcript -EA 0 } catch {}
        $mutex.ReleaseMutex()
} | Out-Null

if ((Get-PSDrive C).Free/1MB -lt 1024) { throw 'Need ≥1 GB free on C:' }

if (-not (Test-Path $LogRoot)) { New-Item $LogRoot -ItemType Directory -Force | Out-Null }
$Transcript = Join-Path $LogRoot "Transcript_$((Get-Date).ToString('yyyyMMddHHmmss')).txt"
Start-Transcript -Path $Transcript -EA 0 | Out-Null

# ─── LOGGING (debug only to PSFramework + local JSONL) ───────────────────────
if (-not (Get-Module PSFramework -ListAvailable -EA 0)) {
    Install-Module PSFramework -RequiredVersion 1.6.224 -Scope AllUsers -Force -EA 0
}
Import-Module PSFramework -EA 0
$JsonLog = Join-Path $LogRoot 'run.jsonl'
function Write-Log {
    param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
    if ($Level -eq 'DEBUG' -and -not $DebugLog) { return }
    Write-PSFMessage -Level $Level -Message $Message -Target 'DCU-Auto'
    @{ts=(Get-Date -Format o);level=$Level;msg=$Message}|ConvertTo-Json -Compress >> $JsonLog
}
Write-Log "DCU script version $Version" 'DEBUG'

# ─── PROXY / CONNECTIVITY / SERVICE CHECKS (unchanged) ───────────────────────
#   … (identical proxy/PAC + Start-Service code as previous version) …

# ─── .NET 8 DESKTOP RUNTIME (unchanged) ───────────────────────────────────────
#   … Test-DotNet8Present and Install-DotNetDesktopRuntime functions …

# ─── DCU DOWNLOAD / SCAN / APPLY FUNCTIONS (unchanged) ───────────────────────
#   … Get-DCULatestUrl, Get-DCUInstaller, Get-DCUCliPath, Invoke-DCUScan, Start-DCUUpdate …

# ─── BATTERY UTILITIES (unchanged) ───────────────────────────────────────────
#   … Get-BatteryInfo, Wait-ForACPower …

# ─── MAIN ────────────────────────────────────────────────────────────────────
try {
    Write-Log '=== DCU automation start ==='

    if ((Get-CimInstance Win32_ComputerSystem).Manufacturer -notmatch 'Dell'){
        Write-Log 'Non-Dell device - Windows Update fallback' 'WARN'
        Install-WindowsUpdate -AcceptAll -AutoReboot:$false -EA Stop
        exit
    }

    Get-DCUInstaller
    Start-Process $InstallerPath -ArgumentList '/s',"-l=$LogRoot\install.log" -Wait
    $cli  = Get-DCUCliPath
    $scan = Invoke-DCUScan $cli

    $withBios = $scan.BiosNeeded -and -not $DisableBIOSUpdates -and $Mode -eq 'All'

    # ── BIOS battery gate ────────────────────────────────────────────────────
    if ($withBios) {
        $bat = Get-BatteryInfo
        if ($bat.On) {
            $pctLow    = $bat.Pct    -lt $MinBatteryPercentForBios
            $healthLow = $bat.Health -lt 50
            if ($pctLow -or $healthLow) {
                if (-not (Wait-ForACPower -TimeoutMinutes $WaitForAcMinutes)) {
                    Write-Log 'Skipping BIOS updates: battery level/health' 'WARN'
                    $withBios = $false
                }
            }
        }
    }

    $exitCode = Start-DCUUpdate $cli $withBios
    Write-Log "DCU CLI exit code $exitCode" 'DEBUG'

    # (No compliance JSON / notifications / reboot logic)

    Write-Log "Run time: $($timer.Elapsed)"
    exit ([int]$exitCode)
}
catch {
    Write-Log ($_ | Out-String) 'ERROR'
    # Retry once next boot if we failed before updates were applied
    Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' `
                     'DCU_Retry' "\"$PSCommandPath\" -StageOnly"
    exit 500
}
finally {
    Stop-Transcript -EA 0 | Out-Null
    Compress-Archive -Path $Transcript -DestinationPath "$Transcript.gz" -Force
    $mutex.ReleaseMutex()
}
