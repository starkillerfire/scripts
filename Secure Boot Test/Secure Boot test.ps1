#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Checks and, on Dell hardware, remediates Secure Boot / UEFI CA 2023 servicing state
    (CVE-2023-24932 / BlackLotus readiness).

.DESCRIPTION
    Snapshots the current Secure Boot / UEFI CA 2023 servicing state (registry markers, the
    UEFI db variable, and recent TPM-WMI events), logs it, and then drives the built-in
    \Microsoft\Windows\PI\Secure-Boot-Update scheduled task through its phases based on that
    state. If Secure Boot itself is disabled on a Dell system, attempts to clear the Legacy
    Option ROM blocker and enable Secure Boot in firmware first (via the Dell BIOS PowerShell
    provider or cctk.exe). A reboot is required between several of these phases; this script
    exits 3010 to signal that rather than rebooting on its own unless -ForceRestart is passed.

.PARAMETER ForceRestart
    Restart the computer automatically when a step in this script determines a reboot is
    required. Uses a warned shutdown (5-minute window, on-screen message) rather than an
    immediate forced restart. Without this switch, the script exits 3010 and leaves the
    reboot to be scheduled separately.

.PARAMETER SkipDellBiosChange
    Do not attempt any Dell BIOS changes (Legacy Option ROM / Secure Boot enable) even if
    Secure Boot is currently disabled on a Dell system. The script exits with an error in
    that case instead, for environments that manage BIOS settings through another channel.
#>
[CmdletBinding()]
param(
    [switch]$ForceRestart,
    [switch]$SkipDellBiosChange
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$ScriptVersion = '2.0'
$LogPath = Join-Path $env:ProgramData ("SecureBoot-UEFICA2023-v{0}-{1}.log" -f $ScriptVersion, (Get-Date -Format 'yyyyMMdd-HHmmss'))

# ----------------------------
# Logging / utility
# ----------------------------
function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    Add-Content -Path $LogPath -Value $line
}

function Start-WarnedRestart {
    # Restart-Computer -Force gives anyone logged on zero warning. Use the
    # same shutdown.exe warning pattern as the rest of this script library
    # (see Invoke-FleetPatchSweep.ps1) instead - a 5-minute window with an
    # on-screen message - and log if the restart couldn't even be scheduled.
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param()

    if ($PSCmdlet.ShouldProcess('local computer', 'Schedule restart in 5 minutes via shutdown.exe')) {
        shutdown /r /t 300 /c "Secure Boot remediation requires a restart. This computer will restart in 5 minutes. Save your work now."
        if ($LASTEXITCODE -ne 0) {
            Write-Log ("shutdown.exe failed to schedule the restart (exit {0})." -f $LASTEXITCODE) 'WARN'
        }
    }
}

function Test-IsAdmin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-FirmwareType {
    try {
        $peFirmwareType = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name PEFirmwareType -ErrorAction Stop).PEFirmwareType
        switch ($peFirmwareType) {
            1 { return 'BIOS' }
            2 { return 'UEFI' }
            default { return "Unknown ($peFirmwareType)" }
        }
    }
    catch {
        return 'Unknown'
    }
}

function Get-HResultText {
    param([Nullable[Int32]]$Code)

    if ($null -eq $Code) { return $null }

    # A REG_DWORD with the high bit set (as every HRESULT failure code has,
    # by definition) is read back by Get-ItemProperty as a NEGATIVE Int32,
    # not the positive literal below - so the switch never matched a real
    # registry-read value. Worse, [UInt32]$Code on that negative value
    # actually throws (PowerShell's cast is checked, unlike C#'s unchecked
    # cast), so this crashed outright for virtually any real error code.
    # Masking through Int64 first reinterprets the same 32 bits as unsigned
    # without the overflow check.
    $unsignedCode = [uint32]([int64]$Code -band 0xFFFFFFFFL)
    switch ($unsignedCode) {
        2147946825 { return 'ERROR_SECUREBOOT_NOT_ENABLED (0x80071149)' }
        default    { return ('0x{0:X8}' -f $unsignedCode) }
    }
}

function Get-RegValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    try {
        return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    }
    catch {
        return $null
    }
}

function Get-HexString {
    param([Nullable[Int32]]$Value)

    if ($null -eq $Value) { return $null }
    # See Get-HResultText - [UInt32]$Value throws outright on a negative
    # Int32 (e.g. any HRESULT failure code, which always has the high bit
    # set). Masking through Int64 first reinterprets the same bits as
    # unsigned without the overflow check.
    return ('0x{0:X4}' -f ([uint32]([int64]$Value -band 0xFFFFFFFFL)))
}

# ----------------------------
# Secure Boot status / events
# ----------------------------
function Get-SecureBootSnapshot {
    $firmwareType = Get-FirmwareType
    $secureBootEnabled = $false
    $secureBootCheckRan = $false
    $dbHas2023 = $false

    try {
        $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
        $secureBootCheckRan = $true
    }
    catch {
        $secureBootCheckRan = $false
    }

    $availableUpdates      = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name 'AvailableUpdates'
    $svcStatus             = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -Name 'UEFICA2023Status'
    $svcError              = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -Name 'UEFICA2023Error'
    $svcErrorEvent         = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -Name 'UEFICA2023ErrorEvent'
    $svcCapable            = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -Name 'WindowsUEFICA2023Capable'
    $bucketHash            = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -Name 'BucketHash'
    $confidenceLevel       = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -Name 'ConfidenceLevel'

    try {
        $db = Get-SecureBootUEFI -Name db -ErrorAction Stop
        if ($db -and $db.Bytes) {
            $dbString = [System.Text.Encoding]::ASCII.GetString($db.Bytes)
            $dbHas2023 = ($dbString -match 'Windows UEFI CA 2023')
        }
    }
    catch {
        Write-Log ("Could not read Secure Boot UEFI db variable: {0}" -f $_.Exception.Message) 'WARN'
    }

    [pscustomobject]@{
        FirmwareType              = $firmwareType
        SecureBootEnabled         = $secureBootEnabled
        SecureBootCheckRan        = $secureBootCheckRan
        AvailableUpdates          = $availableUpdates
        AvailableUpdatesHex       = (Get-HexString -Value $availableUpdates)
        UEFICA2023Status          = $svcStatus
        UEFICA2023Error           = $svcError
        UEFICA2023ErrorHex        = (Get-HexString -Value $svcError)
        UEFICA2023ErrorText       = (Get-HResultText -Code $svcError)
        UEFICA2023ErrorEvent      = $svcErrorEvent
        WindowsUEFICA2023Capable  = $svcCapable
        BucketHash                = $bucketHash
        ConfidenceLevel           = $confidenceLevel
        DbHas2023                 = $dbHas2023
    }
}

function Get-SecureBootEvent {
    try {
        $ids = 1032,1033,1034,1036,1037,1043,1044,1045,1795,1796,1797,1800,1801,1802,1803,1808
        $events = Get-WinEvent -FilterHashtable @{
            LogName      = 'System'
            ProviderName = 'TPM-WMI'
            Id           = $ids
            StartTime    = (Get-Date).AddDays(-14)
        } -ErrorAction Stop | Sort-Object TimeCreated -Descending | Select-Object -First 20

        return $events
    }
    catch {
        Write-Log ("Could not read Secure Boot events: {0}" -f $_.Exception.Message) 'WARN'
        return @()
    }
}

function Write-SecureBootEventsToLog {
    $events = Get-SecureBootEvent
    if (-not $events -or $events.Count -eq 0) {
        Write-Log 'No recent TPM-WMI Secure Boot events found.'
        return
    }

    Write-Log 'Recent TPM-WMI Secure Boot events:'
    foreach ($evt in $events) {
        $msg = ($evt.Message -replace '\s+', ' ').Trim()
        Write-Log ("EventID={0} Time={1} Level={2} Message={3}" -f $evt.Id, $evt.TimeCreated, $evt.LevelDisplayName, $msg)
    }
}

function Get-LatestSecureBootEventId {
    $events = Get-SecureBootEvent
    if ($events -and $events.Count -gt 0) {
        return $events[0].Id
    }
    return $null
}

# ----------------------------
# Dell helpers
# ----------------------------
function Get-DellProviderModuleName {
    $mods = Get-Module -ListAvailable -Name 'DellBIOSProvider','Dell.CommandPowerShellProvider' |
            Sort-Object Name
    if ($mods) {
        return ($mods | Select-Object -First 1).Name
    }
    return $null
}

function Import-DellProvider {
    $name = Get-DellProviderModuleName
    if (-not $name) {
        Write-Log 'Dell BIOS PowerShell provider not installed.' 'WARN'
        return $false
    }

    try {
        Import-Module $name -ErrorAction Stop
        Write-Log ("Imported Dell BIOS provider module: {0}" -f $name)
        return $true
    }
    catch {
        Write-Log ("Failed to import Dell BIOS provider: {0}" -f $_.Exception.Message) 'WARN'
        return $false
    }
}

function Test-DellAdminPasswordSet {
    try {
        if (-not (Import-DellProvider)) { return $null }

        $item = Get-Item -Path 'DellSmbios:\Security\IsAdminPasswordSet' -ErrorAction Stop
        if ($null -ne $item.CurrentValue) {
            return [System.Convert]::ToBoolean($item.CurrentValue)
        }
        if ($null -ne $item.Value) {
            return [System.Convert]::ToBoolean($item.Value)
        }
        return $null
    }
    catch {
        Write-Log ("Unable to determine Dell BIOS admin password state: {0}" -f $_.Exception.Message) 'WARN'
        return $null
    }
}

function Get-CctkPath {
    $candidates = @(
        "${env:ProgramFiles(x86)}\Dell\Command Configure\X86_64\cctk.exe",
        "$env:ProgramFiles\Dell\Command Configure\X86_64\cctk.exe",
        "${env:ProgramFiles(x86)}\Dell\Command Configure\cctk.exe",
        "$env:ProgramFiles\Dell\Command Configure\cctk.exe",
        "${env:ProgramFiles(x86)}\Dell\Command Configure\X86\cctk.exe",
        "$env:ProgramFiles\Dell\Command Configure\X86\cctk.exe"
    )

    return ($candidates | Where-Object { Test-Path $_ } | Select-Object -First 1)
}

function Invoke-Cctk {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $cctk = Get-CctkPath
    if (-not $cctk) {
        return [pscustomobject]@{
            Found    = $false
            ExitCode = $null
            Output   = $null
            Path     = $null
        }
    }

    Write-Log ("Running CCTK: {0} {1}" -f $cctk, ($Arguments -join ' '))
    $output = & $cctk @Arguments 2>&1 | Out-String
    $code = $LASTEXITCODE

    Write-Log ("CCTK exit code: {0}" -f $code)
    if ($output) {
        Write-Log ("CCTK output: {0}" -f (($output -replace '\s+', ' ').Trim()))
    }

    return [pscustomobject]@{
        Found    = $true
        ExitCode = $code
        Output   = $output
        Path     = $cctk
    }
}

function Get-CctkExitMeaning {
    param([Nullable[Int32]]$Code)

    if ($null -eq $Code) { return $null }

    switch ($Code) {
        0   { return 'Success' }
        243 { return 'Owner password is incorrect.' }
        244 { return 'Error setting value. Setup/system password might be set.' }
        248 { return 'Option not supported by system hardware or BIOS version.' }
        253 { return 'Option is not supported on this machine.' }
        254 { return 'Unable to set option because Legacy Option ROM must be enabled and Secure Boot disabled.' }
        255 { return 'Unable to set option because boot mode must be UEFI and Legacy Option ROM must be disabled.' }
        256 { return 'Unable to enable/disable option because Secure Boot / boot mode dependency is not satisfied.' }
        default { return $null }
    }
}

function Disable-DellLegacyOrom {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([bool])]
    param()

    $changed = $false

    # CCTK path is the most reliable/documented for this.
    if ($PSCmdlet.ShouldProcess('Dell BIOS: Legacy Option ROM', "Disable via cctk.exe --legacyorom=disable")) {
        $cctk = Invoke-Cctk -Arguments @('--legacyorom=disable')
        if ($cctk.Found) {
            if ($cctk.ExitCode -eq 0) {
                Write-Log 'Legacy Option ROM disable command issued successfully.'
                return $true
            }
            else {
                $meaning = Get-CctkExitMeaning -Code $cctk.ExitCode
                if ($meaning) {
                    Write-Log ("CCTK legacyorom result: {0}" -f $meaning) 'WARN'
                }
            }
        }
    }

    # Provider fallback / best effort only.
    try {
        if (Import-DellProvider) {
            $candidatePaths = @(
                'DellSmbios:\BootSequence\LegacyOptionROM',
                'DellSmbios:\POSTBehavior\LegacyOptionRom',
                'DellSmbios:\POSTBehavior\LegacyOptionROM',
                'DellSmbios:\AdvancedBootOptions\LegacyOptionRom',
                'DellSmbios:\AdvancedBootOptions\LegacyOptionROM'
            )

            foreach ($path in $candidatePaths) {
                if (Test-Path $path) {
                    if ($PSCmdlet.ShouldProcess($path, "Set Dell BIOS attribute to 'Disabled'")) {
                        Set-Item -Path $path -Value 'Disabled' -ErrorAction Stop
                        Write-Log ("Set Dell BIOS attribute: {0} = Disabled" -f $path)
                        $changed = $true
                    }
                    break
                }
            }
        }
    }
    catch {
        Write-Log ("Provider fallback for Legacy Option ROM failed: {0}" -f $_.Exception.Message) 'WARN'
    }

    return $changed
}

function Enable-DellSecureBoot {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([bool])]
    param()

    $changed = $false

    # Provider first for SecureBoot token
    try {
        if (Import-DellProvider) {
            if (Test-Path 'DellSmbios:\SecureBoot\SecureBoot') {
                if ($PSCmdlet.ShouldProcess('DellSmbios:\SecureBoot\SecureBoot', "Set Dell BIOS attribute to 'Enabled'")) {
                    Set-Item -Path 'DellSmbios:\SecureBoot\SecureBoot' -Value 'Enabled' -ErrorAction Stop
                    Write-Log 'Set Dell BIOS attribute: DellSmbios:\SecureBoot\SecureBoot = Enabled'
                    return $true
                }
            }
        }
    }
    catch {
        Write-Log ("Dell provider Secure Boot enable failed: {0}" -f $_.Exception.Message) 'WARN'
    }

    # CCTK fallback
    if ($PSCmdlet.ShouldProcess('Dell BIOS: Secure Boot', "Enable via cctk.exe --secureboot=enable")) {
        $cctk = Invoke-Cctk -Arguments @('--secureboot=enable')
        if ($cctk.Found) {
            if ($cctk.ExitCode -eq 0) {
                Write-Log 'CCTK Secure Boot enable command issued successfully.'
                return $true
            }
            else {
                $meaning = Get-CctkExitMeaning -Code $cctk.ExitCode
                if ($meaning) {
                    Write-Log ("CCTK secureboot result: {0}" -f $meaning) 'WARN'
                }
            }
        }
    }

    return $changed
}

# ----------------------------
# Microsoft Secure Boot update task
# ----------------------------
function Get-SecureBootTask {
    try {
        return Get-ScheduledTask -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update' -ErrorAction Stop
    }
    catch {
        return $null
    }
}

function Start-SecureBootTask {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param()

    $task = Get-SecureBootTask
    if (-not $task) {
        throw 'Scheduled task \Microsoft\Windows\PI\Secure-Boot-Update was not found.'
    }

    if ($PSCmdlet.ShouldProcess('\Microsoft\Windows\PI\Secure-Boot-Update', 'Start scheduled task')) {
        Start-ScheduledTask -InputObject $task
        Write-Log 'Started scheduled task: \Microsoft\Windows\PI\Secure-Boot-Update'
    }
}

function Set-AvailableUpdates5944 {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param()

    $rootPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'

    if ($PSCmdlet.ShouldProcess("$rootPath\AvailableUpdates", 'Set registry DWord value to 0x5944')) {
        if (-not (Test-Path $rootPath)) {
            New-Item -Path $rootPath -Force | Out-Null
        }

        New-ItemProperty -Path $rootPath -Name 'AvailableUpdates' -PropertyType DWord -Value 0x5944 -Force | Out-Null
        Write-Log 'Set HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\AvailableUpdates = 0x5944'
    }
}

# ----------------------------
# Main
# ----------------------------
if (-not (Test-IsAdmin)) {
    throw 'This script must be run elevated.'
}

New-Item -ItemType File -Path $LogPath -Force | Out-Null
Write-Log ("Script version {0}" -f $ScriptVersion)
Write-Log ("Log path: {0}" -f $LogPath)

$cs   = Get-CimInstance -ClassName Win32_ComputerSystem
$bios = Get-CimInstance -ClassName Win32_BIOS

Write-Log ("Manufacturer : {0}" -f $cs.Manufacturer)
Write-Log ("Model        : {0}" -f $cs.Model)
Write-Log ("BIOS Version : {0}" -f (($bios.SMBIOSBIOSVersion | Select-Object -First 1)))

$state = Get-SecureBootSnapshot

Write-Log ("FirmwareType              : {0}" -f $state.FirmwareType)
Write-Log ("SecureBootEnabled         : {0}" -f $state.SecureBootEnabled)
Write-Log ("AvailableUpdates          : {0}" -f $state.AvailableUpdatesHex)
Write-Log ("UEFICA2023Status          : {0}" -f $state.UEFICA2023Status)
Write-Log ("UEFICA2023Error           : {0}" -f $state.UEFICA2023ErrorHex)
Write-Log ("UEFICA2023ErrorText       : {0}" -f $state.UEFICA2023ErrorText)
Write-Log ("UEFICA2023ErrorEvent      : {0}" -f $state.UEFICA2023ErrorEvent)
Write-Log ("WindowsUEFICA2023Capable  : {0}" -f $state.WindowsUEFICA2023Capable)
Write-Log ("BucketHash                : {0}" -f $state.BucketHash)
Write-Log ("ConfidenceLevel           : {0}" -f $state.ConfidenceLevel)
Write-Log ("DB contains CA 2023       : {0}" -f $state.DbHas2023)

Write-SecureBootEventsToLog

# Success / compliant states
if ($state.DbHas2023 -or $state.UEFICA2023Status -eq 'Updated' -or $state.WindowsUEFICA2023Capable -ge 1) {
    Write-Log 'UEFI CA 2023 already present / updated. Nothing to do.'
    exit 0
}

# Hard prereq gates
if ($state.FirmwareType -ne 'UEFI') {
    Write-Log 'System is not booted in UEFI mode. Secure Boot remediation cannot continue.' 'ERROR'
    exit 1
}

$task = Get-SecureBootTask
if (-not $task) {
    Write-Log 'The Microsoft Secure-Boot-Update scheduled task is missing. Install the current supported Windows update level first.' 'ERROR'
    exit 1
}

# Dell / BIOS remediation stage
if (-not $state.SecureBootEnabled) {
    Write-Log 'Secure Boot is currently disabled.' 'WARN'

    if ($cs.Manufacturer -notmatch 'Dell') {
        Write-Log 'Non-Dell system detected. Enable Secure Boot in firmware manually, then rerun the script.' 'ERROR'
        exit 1
    }

    if ($SkipDellBiosChange) {
        Write-Log 'SkipDellBiosChange was specified, so no Dell BIOS changes were attempted.' 'ERROR'
        exit 1
    }

    $adminPwdState = Test-DellAdminPasswordSet
    if ($adminPwdState -eq $true) {
        Write-Log 'A Dell BIOS admin password appears to be set. This script does not use BIOS passwords and will not attempt changes.' 'ERROR'
        exit 2
    }

    $cctkPath = Get-CctkPath
    $providerName = Get-DellProviderModuleName
    if (-not $cctkPath -and -not $providerName) {
        Write-Log 'Neither Dell Command | Configure (cctk.exe) nor the Dell BIOS PowerShell provider is installed. Cannot remediate BIOS settings in-band.' 'ERROR'
        exit 1
    }

    # Clear blocker first
    $legacyChanged = Disable-DellLegacyOrom

    # Then enable Secure Boot
    $sbChanged = Enable-DellSecureBoot

    if ($legacyChanged -or $sbChanged) {
        Write-Log 'Dell BIOS change(s) were issued. A reboot is required before Windows can continue with the UEFI CA 2023 update.'
        if ($ForceRestart) {
            Write-Log 'ForceRestart specified. Restarting now.'
            Start-WarnedRestart
        }
        exit 3010
    }
    else {
        Write-Log 'Unable to enable Secure Boot in-band. Review the log for Dell tooling output and current BIOS dependencies.' 'ERROR'
        exit 1
    }
}

# Microsoft update stage
# If the first phase was never queued, queue it.
if ($null -eq $state.AvailableUpdates -or $state.AvailableUpdates -eq 0) {
    Set-AvailableUpdates5944
    Start-SecureBootTask
    Start-Sleep -Seconds 8

    $post = Get-SecureBootSnapshot
    Write-Log ("Post-run AvailableUpdates     : {0}" -f $post.AvailableUpdatesHex)
    Write-Log ("Post-run UEFICA2023Status     : {0}" -f $post.UEFICA2023Status)
    Write-Log ("Post-run UEFICA2023Error      : {0}" -f $post.UEFICA2023ErrorHex)
    Write-Log ("Post-run UEFICA2023ErrorEvent : {0}" -f $post.UEFICA2023ErrorEvent)

    if ($post.UEFICA2023Error -and $post.UEFICA2023Error -ne 0) {
        Write-Log 'The Secure Boot servicing keys report an error after the first task run. Review the logged TPM-WMI events.' 'ERROR'
        exit 1
    }

    # Microsoft testing flow expects 0x4100 quickly, then reboot.
    if ($post.AvailableUpdates -eq 0x4100 -or $post.UEFICA2023Status -eq 'InProgress') {
        Write-Log 'First update phase completed. Reboot is required before the second task run.'
        if ($ForceRestart) {
            Write-Log 'ForceRestart specified. Restarting now.'
            Start-WarnedRestart
        }
        exit 3010
    }

    # If already updated early, return success.
    if ($post.DbHas2023 -or $post.UEFICA2023Status -eq 'Updated' -or $post.WindowsUEFICA2023Capable -ge 1) {
        Write-Log 'UEFI CA 2023 update completed successfully.'
        exit 0
    }

    Write-Log 'Update was queued, but the expected post-run state was not observed. Review the log and TPM-WMI events.' 'ERROR'
    exit 1
}

# If the box was rebooted after phase 1 and is sitting at 0x4100, run task again.
if ($state.AvailableUpdates -eq 0x4100) {
    Write-Log 'Detected AvailableUpdates=0x4100. Running second Secure-Boot-Update task phase.'
    Start-SecureBootTask
    Start-Sleep -Seconds 8

    $post = Get-SecureBootSnapshot
    Write-Log ("Second-phase AvailableUpdates     : {0}" -f $post.AvailableUpdatesHex)
    Write-Log ("Second-phase UEFICA2023Status     : {0}" -f $post.UEFICA2023Status)
    Write-Log ("Second-phase UEFICA2023Error      : {0}" -f $post.UEFICA2023ErrorHex)
    Write-Log ("Second-phase UEFICA2023ErrorEvent : {0}" -f $post.UEFICA2023ErrorEvent)

    if ($post.UEFICA2023Error -and $post.UEFICA2023Error -ne 0) {
        Write-Log 'Secure Boot servicing reported an error during the second phase. Review the TPM-WMI events in the log.' 'ERROR'
        exit 1
    }

    if ($post.DbHas2023 -or $post.UEFICA2023Status -eq 'Updated' -or $post.WindowsUEFICA2023Capable -ge 1) {
        Write-Log 'UEFI CA 2023 update completed successfully.'
        exit 0
    }

    if ($post.AvailableUpdates -eq 0x4000 -or $post.UEFICA2023Status -eq 'InProgress') {
        Write-Log 'Second phase completed but the device still reports an in-progress state. Another reboot / normal boot cycle may be required.'
        if ($ForceRestart) {
            Write-Log 'ForceRestart specified. Restarting now.'
            Start-WarnedRestart
        }
        exit 3010
    }

    Write-Log 'Second phase ran, but the expected final state was not observed. Review the log and recent Secure Boot events.' 'ERROR'
    exit 1
}

# 0x5944 is the marker Set-AvailableUpdates5944 writes before the task
# itself runs (see the top of this state machine) - if the script was
# interrupted (crash/power loss/manual Ctrl-C) between setting that marker
# and the task actually running, a rerun would otherwise fall through to
# the generic "unexpected state" error below with no way to retry short of
# manually clearing the registry value. Re-issuing the task here is the
# same recovery the 0x4100 branch above already does.
if ($state.AvailableUpdates -eq 0x5944) {
    Write-Log 'Detected AvailableUpdates=0x5944 with the task apparently not yet run (or interrupted). Re-running the Secure-Boot-Update task.'
    Start-SecureBootTask
    Start-Sleep -Seconds 8

    $post = Get-SecureBootSnapshot
    Write-Log ("Re-run AvailableUpdates     : {0}" -f $post.AvailableUpdatesHex)
    Write-Log ("Re-run UEFICA2023Status     : {0}" -f $post.UEFICA2023Status)
    Write-Log ("Re-run UEFICA2023Error      : {0}" -f $post.UEFICA2023ErrorHex)
    Write-Log ("Re-run UEFICA2023ErrorEvent : {0}" -f $post.UEFICA2023ErrorEvent)

    if ($post.UEFICA2023Error -and $post.UEFICA2023Error -ne 0) {
        Write-Log 'Secure Boot servicing reported an error after re-running the task. Review the TPM-WMI events in the log.' 'ERROR'
        exit 1
    }

    if ($post.DbHas2023 -or $post.UEFICA2023Status -eq 'Updated' -or $post.WindowsUEFICA2023Capable -ge 1) {
        Write-Log 'UEFI CA 2023 update completed successfully.'
        exit 0
    }

    if ($post.AvailableUpdates -eq 0x4100 -or $post.UEFICA2023Status -eq 'InProgress') {
        Write-Log 'Update phase completed after re-run. Reboot is required before the next phase.'
        if ($ForceRestart) {
            Write-Log 'ForceRestart specified. Restarting now.'
            Start-WarnedRestart
        }
        exit 3010
    }

    Write-Log 'Task was re-run, but the expected post-run state was not observed. Review the log and recent Secure Boot events.' 'ERROR'
    exit 1
}

# If already in a pending/in-progress state, avoid resetting to 0x5944.
if ($state.AvailableUpdates -eq 0x4000 -or $state.UEFICA2023Status -eq 'InProgress') {
    Write-Log 'Secure Boot update is already in progress / pending finalization. Review recent events and allow another reboot / normal boot cycle.'
    if ($ForceRestart) {
        Write-Log 'ForceRestart specified. Restarting now.'
        Start-WarnedRestart
    }
    exit 3010
}

# Fall-through handling
Write-Log 'No direct action taken because the device is in an unexpected Secure Boot servicing state. Review the logged registry values and TPM-WMI events.' 'ERROR'
exit 1