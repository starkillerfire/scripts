#Requires -RunAsAdministrator
#Requires -Version 5.1
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
    [switch]$StageOnly, # currently unused/reserved - nothing in this script branches on it yet
    [int]$WaitForAcMinutes=15,[int]$MinBatteryPercentForBios=50,
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
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Version = '6.5.0'

# Don't rely on the OS/.NET default protocol for the dl.dell.com /
# downloads3.dell.com downloads below - freshly-imaged machines may not yet
# default to TLS 1.2.
if ((([Net.ServicePointManager]::SecurityProtocol) -band 3072) -eq 0) { [Net.ServicePointManager]::SecurityProtocol += 3072 }

if ($SelfHostPwsh7 -and $PSVersionTable.PSVersion.Major -lt 7) {
    if ($pwsh = Get-Command pwsh.exe -EA 0) { & $pwsh.Path -File $PSCommandPath @PSBoundParameters; exit }
}

$timer = [Diagnostics.Stopwatch]::StartNew()
$mutex = [Threading.Mutex]::new($true,'Global\DCUUpdateLock',[ref]$lock)
if (-not $lock) { Write-Host 'Another instance is running.'; exit 255 }
Register-EngineEvent PowerShell.Exiting -Action {
        # Write-Host/-Warning (not Write-Log) deliberately here: this handler
        # can fire on an unhandled terminating error raised before Write-Log
        # is defined below (e.g. the disk-space check just after this
        # registration), so it can't depend on that function existing yet.
        try { Stop-Transcript -EA 0 } catch { Write-Warning "Stop-Transcript failed during exit cleanup: $($_.Exception.Message)" }
        # This is a safety-net release for exits that skip past the normal
        # end-of-script $mutex.ReleaseMutex() call below (Ctrl+C, an
        # unexpected terminating error, etc.). On a normal run, that call
        # already released the mutex by the time this fires, and a second
        # ReleaseMutex() on an already-released mutex throws - harmless to
        # the exit code by this point, but a confusing stray error during
        # shutdown otherwise.
        try { $mutex.ReleaseMutex() } catch { Write-Warning "ReleaseMutex failed during exit cleanup (expected if already released): $($_.Exception.Message)" }
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
# Install/Import above are both -EA 0 (offline machines with no PSGallery
# access shouldn't hard-fail this script just for its own debug logging) -
# but Write-Log used to call Write-PSFMessage unconditionally, so on exactly
# that offline case it called an undefined function and every run failed
# before doing any real work, scheduling a RunOnce retry that would fail the
# same way. Now it only calls into PSFramework if the module actually loaded;
# otherwise it silently falls back to the local JSONL log.
$script:PSFrameworkAvailable = [bool](Get-Module PSFramework -EA 0)
$JsonLog = Join-Path $LogRoot 'run.jsonl'
function Write-Log {
    param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
    if ($Level -eq 'DEBUG' -and -not $DebugLog) { return }
    if ($script:PSFrameworkAvailable) { Write-PSFMessage -Level $Level -Message $Message -Target 'DCU-Auto' }
    @{ts=(Get-Date -Format o);level=$Level;msg=$Message}|ConvertTo-Json -Compress >> $JsonLog
}
Write-Log "DCU script version $Version" 'DEBUG'

# ─── PROXY / CONNECTIVITY / SERVICE CHECKS ────────────────────────────────────
function Get-ProxyArgs {
    # Returns a hashtable to splat onto Invoke-WebRequest/Start-BitsTransfer
    # calls so every download in this script honors -WebProxy/-ProxyCredential
    # consistently, instead of each call site reimplementing the same checks.
    $proxyArgs = @{}
    if ($WebProxy) {
        $proxyArgs['Proxy'] = $WebProxy
        if ($ProxyCredential) { $proxyArgs['ProxyCredential'] = $ProxyCredential }
    }
    return $proxyArgs
}

function Test-DCUConnectivity {
    # BITS is what actually does the throttled background download below
    # (via $BitsThrottleKBps) - DCU itself doesn't depend on a running
    # service, but a stopped BITS service makes Start-BitsTransfer fail
    # outright rather than just transferring slowly, so make sure it's up
    # before relying on it.
    $bits = Get-Service -Name BITS -ErrorAction SilentlyContinue
    if ($bits -and $bits.Status -ne 'Running') {
        Write-Log 'BITS service is not running - starting it' 'DEBUG'
        try { Start-Service -Name BITS -ErrorAction Stop }
        catch { Write-Log "Could not start BITS service: $($_.Exception.Message)" 'WARN' }
    }
}

# ─── .NET 8 DESKTOP RUNTIME ────────────────────────────────────────────────────
function Test-DotNet8Present {
    # DCU 5.x+ requires the .NET Desktop Runtime to run; this checks the
    # same registry location .NET's own installer records itself under,
    # rather than shelling out to `dotnet --list-runtimes` (which requires
    # the dotnet.exe muxer to be on PATH, not guaranteed on a fresh image).
    $key = 'HKLM:\SOFTWARE\WOW6432Node\dotnet\Setup\InstalledVersions\x64\sharedfx\Microsoft.WindowsDesktop.App'
    if (-not (Test-Path $key)) { return $false }
    $installed = (Get-Item $key).GetValueNames() | Where-Object { $_ -match '^8\.' }
    return [bool]$installed
}

function Install-DotNetDesktopRuntime {
    if (Test-DotNet8Present) {
        Write-Log '.NET 8 Desktop Runtime already present' 'DEBUG'
        return
    }

    Write-Log 'Installing .NET 8 Desktop Runtime' 'INFO'
    try {
        winget install Microsoft.DotNet.DesktopRuntime.8 -e --accept-package-agreements --accept-source-agreements --silent
        if ($LASTEXITCODE -ne 0) { throw "winget exited $LASTEXITCODE" }
        Write-Log '.NET 8 Desktop Runtime installed via winget' 'DEBUG'
        return
    } catch {
        Write-Log "winget install of .NET 8 failed, falling back to direct download: $($_.Exception.Message)" 'WARN'
    }

    # Fallback for images where winget isn't available/working. $DotNetUrl
    # lets a caller pin a specific build; otherwise this defaults to the
    # known-good 8.0.18 release used elsewhere in this repo's deployment
    # scripts, so all of them stay on the same runtime version.
    $uri  = if ($DotNetUrl) { $DotNetUrl } else { 'https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/8.0.18/windowsdesktop-runtime-8.0.18-win-x64.exe' }
    $path = Join-Path $env:TEMP 'windowsdesktop-runtime-8.0.18-win-x64.exe'
    $proxyArgs = Get-ProxyArgs
    Invoke-WebRequest -Uri $uri -OutFile $path -UseBasicParsing @proxyArgs -ErrorAction Stop

    # Verify the fallback download is actually signed by Microsoft before
    # running it - winget already validates its own packages, but a direct
    # download has no such guarantee on its own.
    $sig = Get-AuthenticodeSignature -FilePath $path
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        Remove-Item $path -Force -ErrorAction SilentlyContinue
        throw ".NET runtime installer failed Authenticode validation (status: $($sig.Status)) - refusing to run it"
    }

    $proc = Start-Process -Wait -FilePath $path -ArgumentList '/install','/quiet','/norestart' -PassThru
    if ($proc.ExitCode -notin @(0, 3010)) { throw ".NET runtime installer exited $($proc.ExitCode)" }
    Remove-Item $path -Force -ErrorAction SilentlyContinue
    Write-Log '.NET 8 Desktop Runtime installed via direct download' 'DEBUG'
}

# ─── DCU DOWNLOAD / SCAN / APPLY FUNCTIONS ────────────────────────────────────
function Get-DCULatestUrl {
    # There's no Dell API queried here for "the latest" version - -Latest
    # just documents intent. What this actually does is try the primary
    # Dell CDN URL first and fall back to the mirror only if the primary
    # doesn't respond, so a single dead link doesn't fail the whole run.
    $proxyArgs = Get-ProxyArgs
    foreach ($candidate in @($DCUDownloadUrl, $MirrorUrl)) {
        if (-not $candidate) { continue }
        try {
            Invoke-WebRequest -Uri $candidate -Method Head -UseBasicParsing -TimeoutSec 15 @proxyArgs -ErrorAction Stop | Out-Null
            return $candidate
        } catch {
            Write-Log "DCU source unreachable, trying next: $candidate ($($_.Exception.Message))" 'WARN'
        }
    }
    throw 'No reachable DCU download source (primary or mirror).'
}

function Get-DCUInstaller {
    # Populates $InstallerPath with a verified DCU installer, either by
    # copying the newest one out of $OfflineRepository (Offline parameter
    # set) or by downloading it (Online parameter set, the default).
    if ($OfflineRepository) {
        $exe = Get-ChildItem -Path $OfflineRepository -Filter 'Dell-Command-Update*.exe' -Recurse -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $exe) { throw "No Dell Command Update installer found under $OfflineRepository" }
        Copy-Item -Path $exe.FullName -Destination $InstallerPath -Force
    } elseif (Test-Path $InstallerPath) {
        Write-Log "Using already-downloaded installer at $InstallerPath" 'DEBUG'
    } else {
        $url = Get-DCULatestUrl
        $proxyArgs = Get-ProxyArgs
        Write-Log "Downloading DCU installer from $url" 'INFO'
        if ($BitsThrottleKBps -gt 0) {
            Start-BitsTransfer -Source $url -Destination $InstallerPath -Priority Foreground @proxyArgs -ErrorAction Stop
        } else {
            Invoke-WebRequest -Uri $url -OutFile $InstallerPath -UseBasicParsing @proxyArgs -ErrorAction Stop
        }
    }

    # Dell signs every DCU release. Whether the installer came from the
    # network or an offline repository share, refuse to run it unless it's
    # validly signed by Dell - this is the one thing standing between a
    # compromised/typo-squatted download (or a tampered offline share) and
    # silently running arbitrary code as part of this automation.
    $sig = Get-AuthenticodeSignature -FilePath $InstallerPath
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Dell') {
        Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue
        throw "DCU installer at $InstallerPath failed Authenticode validation (status: $($sig.Status)) - refusing to run it"
    }
    Write-Log 'DCU installer Authenticode signature verified (Dell).' 'DEBUG'
}

function Get-DCUCliPath {
    $candidates = @(
        'C:\Program Files\Dell\CommandUpdate\dcu-cli.exe',
        'C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe'
    )
    $cli = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $cli) { throw 'dcu-cli.exe not found after install - the DCU install may have failed.' }
    return $cli
}

function Invoke-DCUScan {
    param([Parameter(Mandatory)][string]$CliPath)

    $reportPath = Join-Path $LogRoot 'scan-report.xml'
    Remove-Item $reportPath -Force -ErrorAction SilentlyContinue

    $proc = Start-Process -FilePath $CliPath -ArgumentList '/scan',"-report=`"$reportPath`"" -Wait -PassThru -WindowStyle Hidden
    Write-Log "DCU scan exit code $($proc.ExitCode)" 'DEBUG'
    # Per Dell's dcu-cli reference, /scan returns 0 (no updates found) or 1
    # (updates found) as normal outcomes, not failures - anything else is a
    # real scan failure.
    if ($proc.ExitCode -notin 0,1) { throw "dcu-cli /scan failed with exit code $($proc.ExitCode)" }

    $biosNeeded = $false
    if (Test-Path $reportPath) {
        try {
            [xml]$report = Get-Content -Path $reportPath -Raw
            # NOTE: this assumes each <Update> node exposes its category via
            # a "type" or "category" attribute equal to "BIOS", matching
            # Dell's documented scan-report schema. Confirm against a real
            # report from this fleet's DCU version before relying on this in
            # production - Dell has changed this schema across CLI versions
            # before.
            $updates = $report.SelectNodes('//Update')
            $biosNeeded = [bool]($updates | Where-Object { $_.type -eq 'BIOS' -or $_.category -eq 'BIOS' })
        } catch {
            Write-Log "Could not parse DCU scan report at ${reportPath}: $($_.Exception.Message)" 'WARN'
        }
    }

    [pscustomobject]@{
        ExitCode   = $proc.ExitCode
        ReportPath = $reportPath
        BiosNeeded = $biosNeeded
    }
}

function Start-DCUUpdate {
    param(
        [Parameter(Mandatory)][string]$CliPath,
        [Parameter(Mandatory)][bool]$IncludeBios
    )

    $updateArgs = @('/applyUpdates', '-silent')
    $updateArgs += if ($NoReboot) { '-reboot=disable' } else { '-reboot=enable' }

    switch ($Mode) {
        'BIOSOnly'    { $updateArgs += '-updateType=bios' }
        'DriversOnly' { $updateArgs += '-updateType=driver' }
        default {
            # 'All', but BIOS got excluded above by the battery gate -
            # apply everything except BIOS this run.
            if (-not $IncludeBios) { $updateArgs += '-updateType=driver,firmware,application,others' }
        }
    }

    Write-Log "Running: $CliPath $($updateArgs -join ' ')" 'DEBUG'
    $proc = Start-Process -FilePath $CliPath -ArgumentList $updateArgs -Wait -PassThru -WindowStyle Hidden
    return $proc.ExitCode
}

# ─── BATTERY UTILITIES ─────────────────────────────────────────────────────────
function Get-BatteryInfo {
    $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $battery) {
        # Desktop, or a laptop reporting no battery at all - never gate
        # BIOS updates on battery state in that case.
        return [pscustomobject]@{ On = $false; Pct = 100; Health = 100 }
    }

    # Win32_Battery.BatteryStatus: 1 = discharging (on battery), 2 = on AC/charging.
    $onBattery = $battery.BatteryStatus -eq 1

    $health = 100
    try {
        $designCap = (Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData -ErrorAction Stop | Select-Object -First 1).DesignedCapacity
        $fullCap   = (Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop | Select-Object -First 1).FullChargedCapacity
        if ($designCap -gt 0) { $health = [Math]::Round(($fullCap / $designCap) * 100) }
    } catch {
        Write-Log "Could not read battery health data, assuming healthy: $($_.Exception.Message)" 'DEBUG'
    }

    [pscustomobject]@{
        On     = $onBattery
        Pct    = $battery.EstimatedChargeRemaining
        Health = $health
    }
}

function Wait-ForACPower {
    param([int]$TimeoutMinutes = 15)
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    while ((Get-Date) -lt $deadline) {
        if (-not (Get-BatteryInfo).On) { return $true }
        Start-Sleep -Seconds 30
    }
    return -not (Get-BatteryInfo).On
}

# ─── MAIN ────────────────────────────────────────────────────────────────────
try {
    Write-Log '=== DCU automation start ==='

    if ((Get-CimInstance Win32_ComputerSystem).Manufacturer -notmatch 'Dell'){
        Write-Log 'Non-Dell device - Windows Update fallback' 'WARN'
        if (-not (Get-Module PSWindowsUpdate -ListAvailable -EA 0)) {
            Install-Module PSWindowsUpdate -Scope AllUsers -Force -EA Stop
        }
        Import-Module PSWindowsUpdate -EA Stop
        Install-WindowsUpdate -AcceptAll -AutoReboot:$false -EA Stop
        # Was a bare `exit`, relying on whatever $LASTEXITCODE happened to be
        # rather than an intentional code. Reaching this line means the
        # Windows Update fallback above completed without throwing (-EA Stop
        # would have hit the outer catch otherwise), so 0 is the correct,
        # deliberate exit code.
        exit 0
    }

    Test-DCUConnectivity
    Install-DotNetDesktopRuntime
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
    # Retry once next boot if we failed before updates were applied.
    # -StageOnly isn't passed here: it's declared as a parameter but never
    # actually referenced anywhere in this script, so passing it would just
    # imply a "staged" retry that doesn't exist - this retry re-runs the
    # full script identically to a normal invocation.
    Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' `
                     'DCU_Retry' "\"$PSCommandPath\""
    exit 500
}
finally {
    Stop-Transcript -EA 0 | Out-Null
    # Compress-Archive produces a real ZIP file, not gzip - name it accordingly.
    Compress-Archive -Path $Transcript -DestinationPath "$Transcript.zip" -Force
    $mutex.ReleaseMutex()
}
