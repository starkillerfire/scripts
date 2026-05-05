<#
.SYNOPSIS
    Apply the Windows 11 DISA STIG baseline with PowerSTIG DSC and then
    remediate the SCC 5.14 non-compliance findings from
    Microsoft_Windows_11_STIG stream version 002.007.016.

.DESCRIPTION
    Improvements in this revision:
    - Leaves the PowerSTIG section unchanged.
    - Enforces Windows LAPS as a mandatory requirement.
    - Uses deterministic built-in account handling based on RID 500/501.
    - Uses SecureString for BitLocker startup PIN.
    - Exports backups before changes (secedit, auditpol, bcdedit, registry, BitLocker status).
    - Adds post-remediation validation summary.
    - Handles wildcard Bluetooth user service instances.
    - Pauses transcript around sensitive operations.

.NOTES
    - Run as Administrator.
    - A reboot is required for several settings (BitLocker/VBS/Device Guard).
    - Some findings are environment-dependent and cannot be fully completed
      without org input or external assets:
        * BitLocker TPM+PIN requires a real PIN and compatible TPM/Secure Boot.
        * DoD time source for standalone systems requires an authorized server.
        * DoD/ECA certificate findings require the actual certificate files.
        * Windows LAPS must be present and policy processing must succeed.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OrgSettingsPath,

    [Parameter(Mandatory = $false)]
    [switch]$SkipPowerSTIG,

    [Parameter(Mandatory = $false)]
    [securestring]$StartupPin,

    [Parameter(Mandatory = $false)]
    [string]$NtpServer,

    [Parameter(Mandatory = $false)]
    [string]$CertSourcePath,

    [Parameter(Mandatory = $false)]
    [string]$PowerShellTranscriptOutput = 'C:\ProgramData\PowerShellTranscripts',

    [Parameter(Mandatory = $false)]
    [switch]$UseEveryoneForDenyRdp,

    [Parameter(Mandatory = $false)]
    [switch]$DisableBluetoothRadio,

    [Parameter(Mandatory = $false)]
    [string]$LegalNoticeCaption = 'DoD Notice and Consent Banner',

    [Parameter(Mandatory = $false)]
    [string]$BuiltInAdministratorNewName = 'Admin_Local',

    [Parameter(Mandatory = $false)]
    [string]$BuiltInGuestNewName = 'Guest_Local',

    [Parameter(Mandatory = $false)]
    [string]$BackupRoot = 'C:\ProgramData\PowerSTIG\Backups'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:RebootRequired = $false
$script:OutstandingItems = New-Object System.Collections.Generic.List[string]
$script:ValidationResults = New-Object System.Collections.Generic.List[object]
$script:TranscriptActive = $false
$script:TranscriptPath = $null
$script:BackupPath = $null

# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────
function Write-Section {
    param([string]$Message)
    Write-Host ""
    Write-Host ('=' * 80) -ForegroundColor DarkCyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host ('=' * 80) -ForegroundColor DarkCyan
}

function New-StigDirectory {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Start-StigTranscript {
    param([Parameter(Mandatory)][string]$Path)
    if (-not $script:TranscriptActive) {
        Start-Transcript -Path $Path -Append -Force | Out-Null
        $script:TranscriptActive = $true
        $script:TranscriptPath = $Path
    }
}

function Suspend-StigTranscript {
    if ($script:TranscriptActive) {
        Stop-Transcript | Out-Null
        $script:TranscriptActive = $false
    }
}

function Resume-StigTranscript {
    if (-not $script:TranscriptActive -and $script:TranscriptPath) {
        Start-Transcript -Path $script:TranscriptPath -Append -Force | Out-Null
        $script:TranscriptActive = $true
    }
}

function Set-StigRegistryValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]
        [ValidateSet('DWord', 'QWord', 'String', 'ExpandString', 'MultiString')]
        [string]$Type,
        [Parameter(Mandatory)][object]$Value
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    if ($Type -eq 'MultiString') {
        New-ItemProperty -Path $Path -Name $Name -PropertyType MultiString -Value ([string[]]$Value) -Force | Out-Null
    }
    else {
        New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
    }
}

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [switch]$IgnoreExitCode
    )

    $output = & $FilePath @ArgumentList 2>&1
    $exitCode = $LASTEXITCODE

    if ($output) {
        $output | ForEach-Object { Write-Verbose $_ }
    }

    if (-not $IgnoreExitCode -and $exitCode -ne 0) {
        throw "Command failed: $FilePath $($ArgumentList -join ' ') (ExitCode=$exitCode)"
    }

    return $output
}

function Disable-StigService {
    param([Parameter(Mandatory)][string]$Name)

    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { return }

    if ($svc.Status -ne 'Stopped') {
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    }

    Set-Service -Name $Name -StartupType Disabled
}

function Disable-StigServiceByPattern {
    param([Parameter(Mandatory)][string]$Pattern)

    Get-Service -Name $Pattern -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Status -ne 'Stopped') {
            Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
        }
        Set-Service -Name $_.Name -StartupType Disabled -ErrorAction SilentlyContinue
    }
}

function Start-StigServiceAuto {
    param([Parameter(Mandatory)][string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { return }
    Set-Service -Name $Name -StartupType Automatic -ErrorAction SilentlyContinue
    if ($svc.Status -ne 'Running') {
        Start-Service -Name $Name -ErrorAction SilentlyContinue
    }
}

function Disable-StigOptionalFeature {
    param([Parameter(Mandatory)][string[]]$FeatureName)

    foreach ($feature in $FeatureName) {
        $state = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
        if ($state -and $state.State -eq 'Enabled') {
            Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction Stop | Out-Null
            $script:RebootRequired = $true
        }
    }
}

function Set-AuditPolicy {
    param(
        [Parameter(Mandatory)][string]$Subcategory,
        [Parameter(Mandatory)][bool]$Success,
        [Parameter(Mandatory)][bool]$Failure
    )

    $successArg = if ($Success) { 'enable' } else { 'disable' }
    $failureArg = if ($Failure) { 'enable' } else { 'disable' }

    Invoke-NativeCommand -FilePath auditpol.exe -ArgumentList @(
        '/set',
        "/subcategory:$Subcategory",
        "/success:$successArg",
        "/failure:$failureArg"
    ) | Out-Null
}

function Get-DomainContext {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $partOfDomain = [bool]$cs.PartOfDomain
    $domainName   = if ($partOfDomain) { [string]$cs.Domain } else { $null }

    $domainSid = $null
    if ($partOfDomain) {
        try {
            $domainAccount = New-Object System.Security.Principal.NTAccount("$domainName\Domain Admins")
            $domainAdminsSid = [System.Security.Principal.SecurityIdentifier]$domainAccount.Translate([System.Security.Principal.SecurityIdentifier])
            $domainSid = ($domainAdminsSid.Value -replace '-512$', '')
        }
        catch {
            Write-Warning "Unable to derive domain SID from Domain Admins."
        }
    }

    [pscustomobject]@{
        PartOfDomain = $partOfDomain
        DomainName   = $domainName
        DomainSid    = $domainSid
    }
}

function Invoke-StigSecurityTemplate {
    param(
        [hashtable]$SystemAccess = @{},
        [hashtable]$PrivilegeRights = @{}
    )

    $tempRoot = Join-Path $env:TEMP ("STIGSecEdit_" + [guid]::NewGuid().Guid)
    New-StigDirectory -Path $tempRoot

    $infPath = Join-Path $tempRoot 'stig.inf'
    $dbPath  = Join-Path $tempRoot 'stig.sdb'

    $lines = @(
        '[Unicode]'
        'Unicode=yes'
        '[Version]'
        'signature="$CHICAGO$"'
        'Revision=1'
    )

    if ($SystemAccess.Count -gt 0) {
        $lines += '[System Access]'
        foreach ($key in $SystemAccess.Keys) {
            $lines += "$key = $($SystemAccess[$key])"
        }
    }

    if ($PrivilegeRights.Count -gt 0) {
        $lines += '[Privilege Rights]'
        foreach ($key in $PrivilegeRights.Keys) {
            $value = $PrivilegeRights[$key]
            if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                $joined = ($value | Where-Object { $_ } | ForEach-Object { "*$_" }) -join ','
                $lines += "$key = $joined"
            }
            else {
                $lines += "$key = *$value"
            }
        }
    }

    Set-Content -Path $infPath -Value $lines -Encoding Unicode

    $areas = @()
    if ($SystemAccess.Count -gt 0) { $areas += 'SECURITYPOLICY' }
    if ($PrivilegeRights.Count -gt 0) { $areas += 'USER_RIGHTS' }

    if ($areas.Count -gt 0) {
        Invoke-NativeCommand -FilePath secedit.exe -ArgumentList @(
            '/configure',
            '/db', $dbPath,
            '/cfg', $infPath,
            '/areas', ($areas -join ' ')
        ) | Out-Null
    }

    Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

function Set-PerUserRegistryValue {
    param(
        [Parameter(Mandatory)][string]$SubKey,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]
        [ValidateSet('DWord', 'String')]
        [string]$Type,
        [Parameter(Mandatory)][object]$Value
    )

    $profileListPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $profiles = Get-ChildItem -Path $profileListPath | Where-Object {
        $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$'
    }

    foreach ($profileKey in $profiles) {
        $sid = $profileKey.PSChildName
        $loadedPath = "Registry::HKEY_USERS\$sid"
        $targetPath = Join-Path $loadedPath $SubKey
        $profilePath = (Get-ItemProperty -Path $profileKey.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath

        if (Test-Path -LiteralPath $loadedPath) {
            Set-StigRegistryValue -Path $targetPath -Name $Name -Type $Type -Value $Value
            continue
        }

        $ntUser = if ($profilePath) { Join-Path $profilePath 'NTUSER.DAT' } else { $null }
        if (-not $ntUser -or -not (Test-Path -LiteralPath $ntUser)) {
            continue
        }

        $mountName = 'TEMP_' + ($sid -replace '-', '_')
        try {
            Invoke-NativeCommand -FilePath reg.exe -ArgumentList @('load', "HKU\$mountName", $ntUser) -IgnoreExitCode | Out-Null
            $mountedTarget = "Registry::HKEY_USERS\$mountName\$SubKey"
            Set-StigRegistryValue -Path $mountedTarget -Name $Name -Type $Type -Value $Value
        }
        finally {
            Invoke-NativeCommand -FilePath reg.exe -ArgumentList @('unload', "HKU\$mountName") -IgnoreExitCode | Out-Null
        }
    }

    $defaultNtUser = 'C:\Users\Default\NTUSER.DAT'
    if (Test-Path -LiteralPath $defaultNtUser) {
        $mountName = 'TEMP_DEFAULT_USER'
        try {
            Invoke-NativeCommand -FilePath reg.exe -ArgumentList @('load', "HKU\$mountName", $defaultNtUser) -IgnoreExitCode | Out-Null
            $target = "Registry::HKEY_USERS\$mountName\$SubKey"
            Set-StigRegistryValue -Path $target -Name $Name -Type $Type -Value $Value
        }
        finally {
            Invoke-NativeCommand -FilePath reg.exe -ArgumentList @('unload', "HKU\$mountName") -IgnoreExitCode | Out-Null
        }
    }
}

function Import-StigCertificateIfMissing {
    param(
        [Parameter(Mandatory)][string]$StorePath,
        [Parameter(Mandatory)][string]$Thumbprint,
        [Parameter(Mandatory)][string]$SubjectLike
    )

    $normalizedThumb = ($Thumbprint -replace '\s', '').ToUpperInvariant()

    $existing = Get-ChildItem -Path $StorePath -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $normalizedThumb }

    if ($existing) {
        return
    }

    if (-not $CertSourcePath -or -not (Test-Path -LiteralPath $CertSourcePath)) {
        $script:OutstandingItems.Add("Certificate missing ($SubjectLike / $normalizedThumb) in $StorePath. Supply -CertSourcePath to import it.")
        return
    }

    $candidateFile = Get-ChildItem -Path $CertSourcePath -Recurse -File -Include *.cer, *.crt -ErrorAction SilentlyContinue |
        Where-Object {
            try {
                (Get-PfxCertificate -FilePath $_.FullName).Thumbprint -eq $normalizedThumb
            }
            catch {
                $false
            }
        } |
        Select-Object -First 1

    if (-not $candidateFile) {
        $script:OutstandingItems.Add("Certificate file not found for $SubjectLike / $normalizedThumb in $CertSourcePath.")
        return
    }

    Import-Certificate -FilePath $candidateFile.FullName -CertStoreLocation $StorePath -ErrorAction Stop | Out-Null
}

function Get-BuiltInLocalUserByRid {
    param([Parameter(Mandatory)][int]$Rid)

    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue
    Get-LocalUser -ErrorAction SilentlyContinue |
        Where-Object { $_.SID.Value -match "-$Rid$" } |
        Select-Object -First 1
}

function Rename-BuiltInAccounts {
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue

    $admin = Get-BuiltInLocalUserByRid -Rid 500
    if ($admin) {
        if ($admin.Name -ne $BuiltInAdministratorNewName) {
            $collision = Get-LocalUser -Name $BuiltInAdministratorNewName -ErrorAction SilentlyContinue
            if ($collision) {
                $script:OutstandingItems.Add("Cannot rename built-in Administrator to '$BuiltInAdministratorNewName' because that account name already exists.")
            }
            else {
                Rename-LocalUser -Name $admin.Name -NewName $BuiltInAdministratorNewName
                Write-Host "Renamed built-in Administrator to $BuiltInAdministratorNewName" -ForegroundColor Green
            }
        }
        else {
            Write-Host "Built-in Administrator already renamed to $BuiltInAdministratorNewName" -ForegroundColor DarkGreen
        }
    }

    $guest = Get-BuiltInLocalUserByRid -Rid 501
    if ($guest) {
        if ($guest.Name -ne $BuiltInGuestNewName) {
            $collision = Get-LocalUser -Name $BuiltInGuestNewName -ErrorAction SilentlyContinue
            if ($collision) {
                $script:OutstandingItems.Add("Cannot rename built-in Guest to '$BuiltInGuestNewName' because that account name already exists.")
            }
            else {
                Rename-LocalUser -Name $guest.Name -NewName $BuiltInGuestNewName
                Write-Host "Renamed built-in Guest to $BuiltInGuestNewName" -ForegroundColor Green
            }
        }
        else {
            Write-Host "Built-in Guest already renamed to $BuiltInGuestNewName" -ForegroundColor DarkGreen
        }
    }
}

function Invoke-BitLockerRemediation {
    param([Parameter(Mandatory)][securestring]$Pin)

    Write-Section 'Applying BitLocker policy and remediation'

    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE' -Name 'UseAdvancedStartup' -Type DWord -Value 1
    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE' -Name 'UseTPMPIN' -Type DWord -Value 1
    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE' -Name 'UseTPMKeyPIN' -Type DWord -Value 1
    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE' -Name 'MinimumPIN' -Type DWord -Value 6

    $secureBootOk = $false
    try {
        $secureBootOk = [bool](Confirm-SecureBootUEFI)
    }
    catch {
        Write-Warning 'Unable to confirm Secure Boot state. BitLocker TPM+PIN may fail if UEFI/Secure Boot is not enabled.'
    }

    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    if (-not $tpm -or -not $tpm.TpmPresent -or -not $tpm.TpmReady) {
        $script:OutstandingItems.Add('BitLocker TPM+PIN was not completed because TPM is absent or not ready.')
        return
    }

    if (-not $secureBootOk) {
        $script:OutstandingItems.Add('BitLocker TPM+PIN was not completed because Secure Boot is not confirmed as enabled.')
        return
    }

    $volumes = Get-BitLockerVolume | Where-Object { $_.VolumeType -in @('OperatingSystem', 'FixedData') }

    foreach ($volume in $volumes) {
        $mount = $volume.MountPoint
        if (-not $mount) { continue }

        if ($volume.ProtectionStatus -eq 'On') {
            if ($volume.VolumeType -eq 'OperatingSystem') {
                $hasTpmPin = $false
                foreach ($kp in $volume.KeyProtector) {
                    if ($kp.KeyProtectorType -match 'TpmPin') {
                        $hasTpmPin = $true
                    }
                }

                if (-not $hasTpmPin) {
                    Add-BitLockerKeyProtector -MountPoint $mount -Pin $Pin -TpmAndPinProtector -ErrorAction Stop | Out-Null
                }
            }

            continue
        }

        if ($volume.VolumeType -eq 'OperatingSystem') {
            Enable-BitLocker -MountPoint $mount `
                             -EncryptionMethod XtsAes256 `
                             -TpmAndPinProtector `
                             -Pin $Pin `
                             -RecoveryPasswordProtector `
                             -SkipHardwareTest `
                             -ErrorAction Stop | Out-Null
        }
        else {
            Enable-BitLocker -MountPoint $mount `
                             -EncryptionMethod XtsAes256 `
                             -RecoveryPasswordProtector `
                             -ErrorAction Stop | Out-Null
            Enable-BitLockerAutoUnlock -MountPoint $mount -ErrorAction SilentlyContinue | Out-Null
        }
    }

    $script:RebootRequired = $true
}

function Set-StigWindowsTime {
    $domainContext = Get-DomainContext

    Start-StigServiceAuto -Name 'W32Time'

    if ($domainContext.PartOfDomain) {
        Invoke-NativeCommand -FilePath w32tm.exe -ArgumentList @('/config', '/syncfromflags:domhier', '/update') | Out-Null
        Restart-Service -Name W32Time -Force -ErrorAction SilentlyContinue
        Invoke-NativeCommand -FilePath w32tm.exe -ArgumentList @('/resync', '/force') -IgnoreExitCode | Out-Null
        return
    }

    if ([string]::IsNullOrWhiteSpace($NtpServer)) {
        $script:OutstandingItems.Add('Standalone system time source is still outstanding. Supply -NtpServer with an authorized DoD NTP source.')
        return
    }

    Invoke-NativeCommand -FilePath w32tm.exe -ArgumentList @(
        '/config',
        "/manualpeerlist:$NtpServer",
        '/syncfromflags:manual',
        '/reliable:no',
        '/update'
    ) | Out-Null

    Restart-Service -Name W32Time -Force -ErrorAction SilentlyContinue
    Invoke-NativeCommand -FilePath w32tm.exe -ArgumentList @('/resync', '/force') -IgnoreExitCode | Out-Null
}

function Invoke-StigLapsPolicyProcessing {
    Write-Section 'Applying mandatory Windows LAPS configuration'

    $lapsPolicyPath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'

    Set-StigRegistryValue -Path $lapsPolicyPath -Name 'PasswordAgeDays'    -Type DWord -Value 60
    Set-StigRegistryValue -Path $lapsPolicyPath -Name 'PasswordLength'     -Type DWord -Value 14
    Set-StigRegistryValue -Path $lapsPolicyPath -Name 'PasswordComplexity' -Type DWord -Value 4

    $cmd = Get-Command -Name Invoke-LapsPolicyProcessing -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw 'Windows LAPS is mandatory in this script, but Invoke-LapsPolicyProcessing is not available on this system.'
    }

    try {
        Invoke-LapsPolicyProcessing | Out-Null
        Write-Host 'Windows LAPS policy processing completed.' -ForegroundColor Green
    }
    catch {
        throw "Windows LAPS is mandatory in this script, but policy processing failed: $($_.Exception.Message)"
    }
}

function Export-StigBackup {
    param([Parameter(Mandatory)][string]$RootPath)

    Write-Section 'Exporting pre-change backups'

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $backupPath = Join-Path $RootPath "PreChange_$stamp"
    New-StigDirectory -Path $backupPath

    try {
        Invoke-NativeCommand -FilePath secedit.exe -ArgumentList @('/export', '/cfg', (Join-Path $backupPath 'secedit_export.inf')) -IgnoreExitCode | Out-Null
    }
    catch {
        Write-Warning "secedit export failed: $($_.Exception.Message)"
    }

    try {
        Invoke-NativeCommand -FilePath auditpol.exe -ArgumentList @('/backup', "/file:$((Join-Path $backupPath 'auditpol_backup.csv'))") -IgnoreExitCode | Out-Null
    }
    catch {
        Write-Warning "auditpol backup failed: $($_.Exception.Message)"
    }

    try {
        & bcdedit.exe /enum all > (Join-Path $backupPath 'bcdedit_enum.txt') 2>&1
    }
    catch {
        Write-Warning "bcdedit export failed: $($_.Exception.Message)"
    }

    try {
        & manage-bde.exe -status > (Join-Path $backupPath 'manage-bde_status.txt') 2>&1
    }
    catch {
        Write-Warning "manage-bde status export failed: $($_.Exception.Message)"
    }

    $registryKeys = @(
        'HKLM\SOFTWARE\Policies\Microsoft\FVE',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM',
        'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
        'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
        'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0',
        'HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch',
        'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
    )

    foreach ($regKey in $registryKeys) {
        try {
            $safeName = ($regKey -replace '[\\/:*?"<>|]', '_') + '.reg'
            Invoke-NativeCommand -FilePath reg.exe -ArgumentList @('export', $regKey, (Join-Path $backupPath $safeName), '/y') -IgnoreExitCode | Out-Null
        }
        catch {
            Write-Warning "Registry export failed for ${regKey}: $($_.Exception.Message)"
        }
    }

    return $backupPath
}

function Add-StigValidationResult {
    param(
        [Parameter(Mandatory)][string]$Item,
        [Parameter(Mandatory)][string]$Expected,
        [Parameter(Mandatory)][string]$Actual,
        [Parameter(Mandatory)][bool]$Passed
    )

    $script:ValidationResults.Add([pscustomobject]@{
        Item     = $Item
        Expected = $Expected
        Actual   = $Actual
        Passed   = $Passed
    }) | Out-Null
}

function Test-StigRegistryValue {
    param(
        [Parameter(Mandatory)][string]$Item,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object]$Expected
    )

    try {
        $actual = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        $passed = "$actual" -eq "$Expected"
        Add-StigValidationResult -Item $Item -Expected "$Expected" -Actual "$actual" -Passed $passed
    }
    catch {
        Add-StigValidationResult -Item $Item -Expected "$Expected" -Actual '<missing>' -Passed $false
    }
}

function Test-StigServiceDisabled {
    param([Parameter(Mandatory)][string]$ServiceName)

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        $serviceInfo = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
        $startMode = if ($serviceInfo) { $serviceInfo.StartMode } else { '<unknown>' }
        $actual = "Status=$($svc.Status); StartType=$startMode"
        $passed = ($svc.Status -eq 'Stopped' -or $svc.Status -eq 'StopPending') -and ($startMode -eq 'Disabled')
        Add-StigValidationResult -Item "Service $ServiceName" -Expected 'Stopped / Disabled' -Actual $actual -Passed $passed
    }
    else {
        Add-StigValidationResult -Item "Service $ServiceName" -Expected 'Present and Disabled' -Actual '<not found>' -Passed $false
    }
}

function Test-StigOptionalFeatureDisabled {
    param([Parameter(Mandatory)][string]$FeatureName)

    $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue
    if ($feature) {
        Add-StigValidationResult -Item "Feature $FeatureName" -Expected 'Disabled' -Actual $feature.State -Passed ($feature.State -eq 'Disabled')
    }
    else {
        Add-StigValidationResult -Item "Feature $FeatureName" -Expected 'Disabled' -Actual '<not found>' -Passed $false
    }
}

function Test-StigAuditSubcategory {
    param(
        [Parameter(Mandatory)][string]$Subcategory,
        [Parameter(Mandatory)][string]$ExpectedSuccess,
        [Parameter(Mandatory)][string]$ExpectedFailure
    )

    try {
        $line = (auditpol.exe /get /subcategory:"$Subcategory" /r | Select-Object -Skip 1 | Select-Object -First 1)
        if ($line) {
            $cols = $line -split ','
            $actualSuccess = if ($cols.Count -ge 4) { $cols[2] } else { '<unknown>' }
            $actualFailure = if ($cols.Count -ge 4) { $cols[3] } else { '<unknown>' }
            $passed = ($actualSuccess -eq $ExpectedSuccess) -and ($actualFailure -eq $ExpectedFailure)
            Add-StigValidationResult -Item "Audit $Subcategory" -Expected "Success=$ExpectedSuccess; Failure=$ExpectedFailure" -Actual "Success=$actualSuccess; Failure=$actualFailure" -Passed $passed
        }
        else {
            Add-StigValidationResult -Item "Audit $Subcategory" -Expected "Success=$ExpectedSuccess; Failure=$ExpectedFailure" -Actual '<missing>' -Passed $false
        }
    }
    catch {
        Add-StigValidationResult -Item "Audit $Subcategory" -Expected "Success=$ExpectedSuccess; Failure=$ExpectedFailure" -Actual '<error>' -Passed $false
    }
}

function Test-StigBuiltInAccountName {
    param(
        [Parameter(Mandatory)][int]$Rid,
        [Parameter(Mandatory)][string]$ExpectedName
    )

    $user = Get-BuiltInLocalUserByRid -Rid $Rid
    if ($user) {
        Add-StigValidationResult -Item "RID $Rid account name" -Expected $ExpectedName -Actual $user.Name -Passed ($user.Name -eq $ExpectedName)
    }
    else {
        Add-StigValidationResult -Item "RID $Rid account name" -Expected $ExpectedName -Actual '<not found>' -Passed $false
    }
}

function Invoke-StigValidation {
    Write-Section 'Post-remediation validation summary'

    Test-StigRegistryValue -Item 'FVE MinimumPIN' `
        -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE' `
        -Name 'MinimumPIN' -Expected 6

    Test-StigRegistryValue -Item 'LAPS PasswordAgeDays' `
        -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' `
        -Name 'PasswordAgeDays' -Expected 60

    Test-StigRegistryValue -Item 'LAPS PasswordLength' `
        -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' `
        -Name 'PasswordLength' -Expected 14

    Test-StigRegistryValue -Item 'LAPS PasswordComplexity' `
        -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' `
        -Name 'PasswordComplexity' -Expected 4

    Test-StigRegistryValue -Item 'WinRM Client AllowBasic' `
        -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' `
        -Name 'AllowBasic' -Expected 0

    Test-StigRegistryValue -Item 'WinRM Service AllowBasic' `
        -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' `
        -Name 'AllowBasic' -Expected 0

    Test-StigRegistryValue -Item 'EventLog Security MaxSize' `
        -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' `
        -Name 'MaxSize' -Expected 1024000

    Test-StigRegistryValue -Item 'AllowTelemetry' `
        -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
        -Name 'AllowTelemetry' -Expected 0

    Test-StigRegistryValue -Item 'DisableWindowsConsumerFeatures' `
        -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent' `
        -Name 'DisableWindowsConsumerFeatures' -Expected 1

    Test-StigRegistryValue -Item 'ProcessCreationIncludeCmdLine_Enabled' `
        -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
        -Name 'ProcessCreationIncludeCmdLine_Enabled' -Expected 1

    Test-StigRegistryValue -Item 'Passport MinimumPINLength' `
        -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity' `
        -Name 'MinimumPINLength' -Expected 6

    Test-StigRegistryValue -Item 'LegalNoticeCaption' `
        -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -Name 'LegalNoticeCaption' -Expected $LegalNoticeCaption

    Test-StigRegistryValue -Item 'RestrictAnonymous' `
        -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'RestrictAnonymous' -Expected 1

    Test-StigRegistryValue -Item 'LmCompatibilityLevel' `
        -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'LmCompatibilityLevel' -Expected 5

    Test-StigRegistryValue -Item 'WDigest UseLogonCredential' `
        -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest' `
        -Name 'UseLogonCredential' -Expected 0

    Test-StigServiceDisabled -ServiceName 'seclogon'
    Test-StigOptionalFeatureDisabled -FeatureName 'MicrosoftWindowsPowerShellV2'
    Test-StigOptionalFeatureDisabled -FeatureName 'MicrosoftWindowsPowerShellV2Root'
    Test-StigBuiltInAccountName -Rid 500 -ExpectedName $BuiltInAdministratorNewName
    Test-StigBuiltInAccountName -Rid 501 -ExpectedName $BuiltInGuestNewName

    Test-StigAuditSubcategory -Subcategory 'Process Creation' -ExpectedSuccess 'Success' -ExpectedFailure 'Failure'
    Test-StigAuditSubcategory -Subcategory 'Credential Validation' -ExpectedSuccess 'Success' -ExpectedFailure 'Failure'
    Test-StigAuditSubcategory -Subcategory 'Account Lockout' -ExpectedSuccess 'No Auditing' -ExpectedFailure 'Failure'
    Test-StigAuditSubcategory -Subcategory 'Authorization Policy Change' -ExpectedSuccess 'Success' -ExpectedFailure 'No Auditing'

    $passed = ($script:ValidationResults | Where-Object { $_.Passed }).Count
    $failed = ($script:ValidationResults | Where-Object { -not $_.Passed }).Count

    $script:ValidationResults |
        Sort-Object Passed, Item |
        Format-Table -AutoSize

    Write-Host ""
    Write-Host "Validation Passed: $passed" -ForegroundColor Green
    Write-Host "Validation Failed: $failed" -ForegroundColor Yellow
}

# ─────────────────────────────────────────────────────────────────────────────
# Admin check / transcript
# ─────────────────────────────────────────────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Please run this script as Administrator.'
}

$logRoot = Join-Path $env:ProgramData 'PowerSTIG'
New-StigDirectory -Path $logRoot
New-StigDirectory -Path $BackupRoot

$script:TranscriptPath = Join-Path $logRoot ("Win11_STIG_Remediation_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
Start-StigTranscript -Path $script:TranscriptPath

try {
    Write-Section 'Starting Windows 11 STIG remediation'

    $script:BackupPath = Export-StigBackup -RootPath $BackupRoot
    Write-Host "Backup path: $script:BackupPath" -ForegroundColor Green

    # ─────────────────────────────────────────────────────────────────────────
    # PowerSTIG DSC
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $SkipPowerSTIG) {
        Write-Section 'Ensuring PowerSTIG is available'

        $psStigModule = Get-Module -ListAvailable -Name PowerSTIG | Sort-Object Version -Descending | Select-Object -First 1

        if (-not $psStigModule) {
            try {
                Install-PackageProvider -Name NuGet -Force -ErrorAction SilentlyContinue | Out-Null
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
                Install-Module -Name PowerSTIG -Scope AllUsers -Force -ErrorAction Stop
            }
            catch {
                Write-Warning "Failed to install PowerSTIG. Continuing with manual remediations only. $($_.Exception.Message)"
            }

            $psStigModule = Get-Module -ListAvailable -Name PowerSTIG | Sort-Object Version -Descending | Select-Object -First 1
        }

        if ($psStigModule) {
            Import-Module PowerSTIG -ErrorAction Stop

            foreach ($required in $psStigModule.RequiredModules) {
                if (-not (Get-Module -ListAvailable -Name $required.Name)) {
                    try {
                        Install-Module -Name $required.Name -Scope AllUsers -Force -ErrorAction Stop
                    }
                    catch {
                        Write-Warning "Failed to install PowerSTIG dependency $($required.Name): $($_.Exception.Message)"
                    }
                }
            }

            if ($OrgSettingsPath) {
                if (-not (Test-Path -LiteralPath $OrgSettingsPath)) {
                    throw "Specified OrgSettingsPath '$OrgSettingsPath' was not found."
                }

                $orgDefault = (Resolve-Path -LiteralPath $OrgSettingsPath).Path
            }
            else {
                $stigDataRoot = Join-Path $psStigModule.ModuleBase 'StigData\Processed'
                $candidateFiles = Get-ChildItem -Path $stigDataRoot -Filter 'WindowsClient-11-*.org.default.xml' -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        $m = [regex]::Match($_.Name, 'WindowsClient-11-(?<ver>[0-9\.]+)\.org\.default\.xml', 'IgnoreCase')
                        [pscustomobject]@{
                            File    = $_
                            Version = if ($m.Success) { [version]$m.Groups['ver'].Value } else { [version]'0.0' }
                        }
                    } |
                    Sort-Object Version -Descending

                if (-not $candidateFiles) {
                    throw "No WindowsClient-11-*.org.default.xml files were found under '$stigDataRoot'."
                }

                $orgDefault = $candidateFiles[0].File.FullName
            }

            $stigVersion = '2.2'
            $m2 = [regex]::Match((Split-Path -Leaf $orgDefault), 'WindowsClient-11-(?<ver>[0-9\.]+)\.org\.default\.xml', 'IgnoreCase')
            if ($m2.Success) {
                $stigVersion = $m2.Groups['ver'].Value
            }

            [DSCLocalConfigurationManager()]
            Configuration LCM_PushConfig {
                Node 'localhost' {
                    Settings {
                        ConfigurationMode    = 'ApplyAndAutoCorrect'
                        AllowModuleOverwrite = $true
                        RefreshMode          = 'Push'
                        RebootNodeIfNeeded   = $true
                    }
                }
            }

            Configuration Win11_STIG_Baseline {
                param(
                    [Parameter(Mandatory)][string]$OrgSettings,
                    [Parameter(Mandatory)][string]$StigVersion
                )

                Import-DscResource -ModuleName PowerSTIG

                Node 'localhost' {
                    WindowsClient STIGBaseline {
                        OsVersion   = '11'
                        StigVersion = $StigVersion
                        OrgSettings = $OrgSettings
                    }
                }
            }

            $lcmPath = Join-Path $logRoot 'LCM'
            $mofPath = Join-Path $logRoot 'Mof'
            New-StigDirectory -Path $lcmPath
            New-StigDirectory -Path $mofPath

            LCM_PushConfig -OutputPath $lcmPath
            Set-DscLocalConfigurationManager -Path $lcmPath -Verbose -Force | Out-Null

            Write-Host "Using OrgSettings: $orgDefault" -ForegroundColor Green
            Write-Host "Detected Windows 11 STIG version: $stigVersion" -ForegroundColor Green

            Win11_STIG_Baseline -OrgSettings $orgDefault -StigVersion $stigVersion -OutputPath $mofPath
            Start-DscConfiguration -Path $mofPath -Wait -Verbose -Force
        }
        else {
            Write-Warning 'PowerSTIG is not available. Continuing with manual remediations.'
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # Local security policy / user rights
    # ─────────────────────────────────────────────────────────────────────────
    Write-Section 'Applying local security policy and user rights'

    $domainContext = Get-DomainContext

    $privilegeRights = [ordered]@{}
    $privilegeRights['SeNetworkLogonRight']        = @('S-1-5-32-544', 'S-1-5-32-555')
    $privilegeRights['SeInteractiveLogonRight']    = @('S-1-5-32-544', 'S-1-5-32-545')
    $privilegeRights['SeBackupPrivilege']          = @('S-1-5-32-544')
    $privilegeRights['SeRestorePrivilege']         = @('S-1-5-32-544')

    $denyNetwork = New-Object System.Collections.Generic.List[string]
    $denyNetwork.Add('S-1-5-32-546') | Out-Null
    if ($domainContext.PartOfDomain -and $domainContext.DomainSid) {
        $denyNetwork.Add("$($domainContext.DomainSid)-519") | Out-Null
        $denyNetwork.Add("$($domainContext.DomainSid)-512") | Out-Null
        $denyNetwork.Add('S-1-5-113') | Out-Null
    }
    $privilegeRights['SeDenyNetworkLogonRight'] = @($denyNetwork.ToArray())

    $denyLocal = New-Object System.Collections.Generic.List[string]
    $denyLocal.Add('S-1-5-32-546') | Out-Null
    if ($domainContext.PartOfDomain -and $domainContext.DomainSid) {
        $denyLocal.Add("$($domainContext.DomainSid)-519") | Out-Null
        $denyLocal.Add("$($domainContext.DomainSid)-512") | Out-Null
    }
    $privilegeRights['SeDenyInteractiveLogonRight'] = @($denyLocal.ToArray())

    if ($UseEveryoneForDenyRdp) {
        $privilegeRights['SeDenyRemoteInteractiveLogonRight'] = @('S-1-1-0')
    }
    else {
        $denyRdp = New-Object System.Collections.Generic.List[string]
        $denyRdp.Add('S-1-5-32-546') | Out-Null
        if ($domainContext.PartOfDomain -and $domainContext.DomainSid) {
            $denyRdp.Add("$($domainContext.DomainSid)-519") | Out-Null
            $denyRdp.Add("$($domainContext.DomainSid)-512") | Out-Null
            $denyRdp.Add('S-1-5-113') | Out-Null
        }
        $privilegeRights['SeDenyRemoteInteractiveLogonRight'] = @($denyRdp.ToArray())
    }

    $systemAccess = [ordered]@{
        MinimumPasswordAge    = 1
        MaximumPasswordAge    = 60
        MinimumPasswordLength = 14
        PasswordComplexity    = 1
        PasswordHistorySize   = 24
        LockoutBadCount       = 3
        ResetLockoutCount     = 15
        LockoutDuration       = 15
    }

    Invoke-StigSecurityTemplate -SystemAccess $systemAccess -PrivilegeRights $privilegeRights

    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue
    Get-LocalUser -ErrorAction SilentlyContinue |
        Where-Object { $_.Enabled -and $_.PasswordNeverExpires } |
        ForEach-Object {
            Set-LocalUser -Name $_.Name -PasswordNeverExpires:$false
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Optional features / services
    # ─────────────────────────────────────────────────────────────────────────
    Write-Section 'Disabling insecure optional features and services'

    Disable-StigOptionalFeature -FeatureName @('MicrosoftWindowsPowerShellV2', 'MicrosoftWindowsPowerShellV2Root')
    Disable-StigService -Name 'seclogon'

    if ($DisableBluetoothRadio) {
        Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -eq 'OK' } |
            ForEach-Object {
                Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
            }

        Disable-StigService -Name 'bthserv'
        Disable-StigServiceByPattern -Pattern 'BluetoothUserService*'
    }

    # ─────────────────────────────────────────────────────────────────────────
    # Registry-based remediations (machine)
    # ─────────────────────────────────────────────────────────────────────────
    Write-Section 'Applying machine registry remediations'

    $regDword = @(
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'; Name='DisableExceptionChainValidation'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fAllowToGetHelp'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='NoAutoplayfornonVolume'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoAutorun'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoDriveTypeAutoRun'; Value=255 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name='AlwaysInstallElevated'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name='AllowBasic'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name='AllowBasic'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictAnonymous'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'; Name='LmCompatibilityLevel'; Value=5 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE'; Name='MinimumPIN'; Value=6 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE'; Name='UseAdvancedStartup'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE'; Name='UseTPMPIN'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE'; Name='UseTPMKeyPIN'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Connectivity'; Name='AllowBluetooth'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'; Name='MaxSize'; Value=32768 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; Name='MaxSize'; Value=1024000 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'; Name='MaxSize'; Value=32768 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'; Name='NoLockScreenCamera'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'; Name='NoLockScreenSlideshow'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'; Name='DisableIpSourceRouting'; Value=2 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='DisableIPSourceRouting'; Value=2 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest'; Name='UseLogonCredential'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'; Name='AllowInsecureGuestAuth'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections'; Name='NC_ShowSharedAccessUI'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'; Name='fBlockNonDomain'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config'; Name='AutoConnectAllowedOEM'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name='ProcessCreationIncludeCmdLine_Enabled'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'; Name='AllowProtectedCreds'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='EnableVirtualizationBasedSecurity'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='RequirePlatformSecurityFeatures'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'; Name='DriverLoadPolicy'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'; Name='NoGPOListChanges'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name='DisableWebPnPDownload'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoWebServices'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name='DisableHTTPPrinting'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'; Name='DontDisplayNetworkSelectionUI'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'; Name='DCSettingIndex'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'; Name='ACSettingIndex'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'; Name='RestrictRemoteClients'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures'; Name='EnhancedAntiSpoofing'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'; Name='EnumerateAdministrators'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='LimitEnhancedDiagnosticDataWindowsAnalytics'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='AllowTelemetry'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'; Name='EnableSmartScreen'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR'; Name='AllowGameDVR'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity'; Name='MinimumPINLength'; Value=6 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='DisablePasswordSaving'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fDisableCdm'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fPromptForPassword'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fEncryptRPCTraffic'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='MinEncryptionLevel'; Value=3 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'; Name='DisableEnclosureDownload'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name='AllowIndexingEncryptedStoresOrItems'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name='EnableUserControl'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='DisableAutomaticRestartSignOn'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name='EnableScriptBlockLogging'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name='EnableTranscripting'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name='AllowUnencryptedTraffic'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name='AllowUnencryptedTraffic'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name='DisableRunAs'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name='AllowDigest'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'; Name='LetAppsActivateWithVoiceAboveLock'; Value=2 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'; Name='LetAppsActivateWithVoice'; Value=2 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'; Name='AllowDomainPINLogon'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'; Name='AllowWindowsInkWorkspace'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection'; Name='DeviceEnumerationPolicy'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'; Name='SCENoApplyLegacyAuditPolicy'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='InactivityTimeoutSecs'; Value=900 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name='RequireSecuritySignature'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name='RequireSecuritySignature'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0'; Name='allownullsessionfallback'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\pku2u'; Name='AllowOnlineID'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; Name='SupportedEncryptionTypes'; Value=2147483640 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name='NTLMMinClientSec'; Value=537395200 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name='NTLMMinServerSec'; Value=537395200 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy'; Name='Enabled'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='FilterAdministratorToken'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorAdmin'; Value=2 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorUser'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftAccount'; Name='DisableUserAuth'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='EnableICMPRedirect'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'; Name='NoNameReleaseOnDemand'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='MSAOptional'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat'; Name='DisableInventory'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name='DisableWindowsConsumerFeatures'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; Name='DODownloadMode'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config'; Name='DODownloadMode'; Value=0 }
    )

    foreach ($entry in $regDword) {
        Set-StigRegistryValue -Path $entry.Path -Name $entry.Name -Type DWord -Value $entry.Value
    }

    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' `
        -Name 'EccCurves' -Type MultiString -Value @('NistP384', 'NistP256')

    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System' `
        -Name 'ShellSmartScreenLevel' -Type String -Value 'Block'

    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
        -Name 'OutputDirectory' -Type String -Value $PowerShellTranscriptOutput

    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
        -Name 'SCRemoveOption' -Type String -Value '1'

    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'RestrictRemoteSAM' -Type String -Value 'O:BAG:BAD:(A;;RC;;;BA)'

    New-StigDirectory -Path $PowerShellTranscriptOutput

    $legalNoticeText = @'
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE, or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
'@

    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -Name 'LegalNoticeText' -Type String -Value $legalNoticeText

    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -Name 'LegalNoticeCaption' -Type String -Value $LegalNoticeCaption

    foreach ($runAsPath in @(
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\batfile\shell\runasuser',
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\cmdfile\shell\runasuser',
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\exefile\shell\runasuser',
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\mscfile\shell\runasuser'
    )) {
        Set-StigRegistryValue -Path $runAsPath -Name 'SuppressionPolicy' -Type DWord -Value 4096
    }

    try {
        Invoke-NativeCommand -FilePath bcdedit.exe -ArgumentList @('/set', '{current}', 'hypervisorlaunchtype', 'Auto') -IgnoreExitCode | Out-Null
        Invoke-NativeCommand -FilePath bcdedit.exe -ArgumentList @('/set', '{current}', 'vsmlaunchtype', 'Auto') -IgnoreExitCode | Out-Null
        $script:RebootRequired = $true
    }
    catch {
        Write-Warning "Unable to update BCDEdit for VBS startup: $($_.Exception.Message)"
    }

    # ─────────────────────────────────────────────────────────────────────────
    # Per-user registry remediations
    # ─────────────────────────────────────────────────────────────────────────
    Write-Section 'Applying per-user registry remediations'

    Set-PerUserRegistryValue -SubKey 'SOFTWARE\Policies\Microsoft\Windows\CloudContent' `
        -Name 'DisableThirdPartySuggestions' -Type DWord -Value 1

    Set-PerUserRegistryValue -SubKey 'SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' `
        -Name 'NoToastApplicationNotificationOnLockScreen' -Type DWord -Value 1

    Set-PerUserRegistryValue -SubKey 'Software\Microsoft\BluetoothAuthenticationAgent' `
        -Name 'AcceptIncomingRequests' -Type DWord -Value 1

    try {
        Set-StigRegistryValue -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent' `
            -Name 'DisableThirdPartySuggestions' -Type DWord -Value 1
        Set-StigRegistryValue -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' `
            -Name 'NoToastApplicationNotificationOnLockScreen' -Type DWord -Value 1
        Set-StigRegistryValue -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\BluetoothAuthenticationAgent' `
            -Name 'AcceptIncomingRequests' -Type DWord -Value 1
        Set-StigRegistryValue -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer' `
            -Name 'AlwaysInstallElevated' -Type DWord -Value 0
    }
    catch {
        Write-Verbose "Current HKCU hive not updated: $($_.Exception.Message)"
    }

    # ─────────────────────────────────────────────────────────────────────────
    # Audit policy
    # ─────────────────────────────────────────────────────────────────────────
    Write-Section 'Applying audit policy remediations'

    $auditMap = @(
        @{ Subcategory='Credential Validation';            Success=$true;  Failure=$true  }
        @{ Subcategory='User Account Management';         Success=$false; Failure=$true  }
        @{ Subcategory='Plug and Play Events';            Success=$true;  Failure=$false }
        @{ Subcategory='Process Creation';                Success=$true;  Failure=$true  }
        @{ Subcategory='Account Lockout';                 Success=$false; Failure=$true  }
        @{ Subcategory='Group Membership';                Success=$true;  Failure=$false }
        @{ Subcategory='File Share';                      Success=$true;  Failure=$true  }
        @{ Subcategory='Other Object Access Events';      Success=$true;  Failure=$true  }
        @{ Subcategory='Removable Storage';               Success=$true;  Failure=$true  }
        @{ Subcategory='Authorization Policy Change';     Success=$true;  Failure=$false }
        @{ Subcategory='Sensitive Privilege Use';         Success=$true;  Failure=$true  }
        @{ Subcategory='IPsec Driver';                    Success=$false; Failure=$true  }
        @{ Subcategory='Security System Extension';       Success=$true;  Failure=$false }
        @{ Subcategory='Other Policy Change Events';      Success=$false; Failure=$true  }
        @{ Subcategory='Other Logon/Logoff Events';       Success=$true;  Failure=$true  }
        @{ Subcategory='Detailed File Share';             Success=$false; Failure=$true  }
        @{ Subcategory='MPSSVC Rule-Level Policy Change'; Success=$true;  Failure=$true  }
        @{ Subcategory='File System';                     Success=$true;  Failure=$true  }
        @{ Subcategory='Handle Manipulation';             Success=$true;  Failure=$true  }
        @{ Subcategory='Registry';                        Success=$true;  Failure=$true  }
    )

    foreach ($auditEntry in $auditMap) {
        Set-AuditPolicy -Subcategory $auditEntry.Subcategory -Success $auditEntry.Success -Failure $auditEntry.Failure
    }

    # ─────────────────────────────────────────────────────────────────────────
    # Local accounts / LAPS / certificates / time
    # ─────────────────────────────────────────────────────────────────────────
    Write-Section 'Applying account, LAPS, certificate, and time remediations'

    Rename-BuiltInAccounts
    Invoke-StigLapsPolicyProcessing
    Set-StigWindowsTime

    Import-StigCertificateIfMissing -StorePath 'Cert:\LocalMachine\Root'       -Thumbprint 'D73CA91102A2204A36459ED32213B467D7CE97FB' -SubjectLike 'DoD Root CA 3'
    Import-StigCertificateIfMissing -StorePath 'Cert:\LocalMachine\Root'       -Thumbprint 'B8269F25DBD937ECAFD4C35A9838571723F2D026' -SubjectLike 'DoD Root CA 4'
    Import-StigCertificateIfMissing -StorePath 'Cert:\LocalMachine\Root'       -Thumbprint '4ECB5CC3095670454DA1CBD410FC921F46B8564B' -SubjectLike 'DoD Root CA 5'
    Import-StigCertificateIfMissing -StorePath 'Cert:\LocalMachine\Root'       -Thumbprint 'D37ECF61C0B4ED88681EF3630C4E2FC787B37AEF' -SubjectLike 'DoD Root CA 6'
    Import-StigCertificateIfMissing -StorePath 'Cert:\LocalMachine\Root'       -Thumbprint '73E8BB08E337D6A5A6AEF90CFFDD97D9176CB582' -SubjectLike 'ECA Root CA 4'
    Import-StigCertificateIfMissing -StorePath 'Cert:\LocalMachine\Disallowed' -Thumbprint '49CBE933151872E17C8EAE7F0ABA97FB610F6477' -SubjectLike 'DoD Interop CA 2 -> DoD Root CA 3'
    Import-StigCertificateIfMissing -StorePath 'Cert:\LocalMachine\Disallowed' -Thumbprint 'AC06108CA348CC03B53795C64BF84403C1DBD341' -SubjectLike 'DoD Interop CA 2 -> DoD Root CA 3 (legacy)'
    Import-StigCertificateIfMissing -StorePath 'Cert:\LocalMachine\Disallowed' -Thumbprint '9B74964506C7ED9138070D08D5F8B969866560C8' -SubjectLike 'US DoD CCEB Interop CA 2 -> DoD Root CA 3'
    Import-StigCertificateIfMissing -StorePath 'Cert:\LocalMachine\Disallowed' -Thumbprint 'D471CA32F7A692CE6CBB6196BD3377FE4DBCD106' -SubjectLike 'US DoD CCEB Interop CA 2 -> DoD Root CA 6'

    # ─────────────────────────────────────────────────────────────────────────
    # BitLocker
    # ─────────────────────────────────────────────────────────────────────────
    if ($null -ne $StartupPin) {
        Suspend-StigTranscript
        try {
            Invoke-BitLockerRemediation -Pin $StartupPin
        }
        finally {
            Resume-StigTranscript
        }
    }
    else {
        $script:OutstandingItems.Add('BitLocker TPM+PIN was not fully remediated because -StartupPin was not supplied.')
        Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE' -Name 'UseAdvancedStartup' -Type DWord -Value 1
        Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE' -Name 'UseTPMPIN' -Type DWord -Value 1
        Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE' -Name 'UseTPMKeyPIN' -Type DWord -Value 1
        Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE' -Name 'MinimumPIN' -Type DWord -Value 6
    }

    Invoke-StigValidation

    Write-Section 'Windows 11 STIG remediation complete'

    if ($script:OutstandingItems.Count -gt 0) {
        Write-Warning 'The following items still require environment-specific input or post-check validation:'
        foreach ($item in $script:OutstandingItems) {
            Write-Warning " - $item"
        }
    }

    if ($script:RebootRequired) {
        Write-Warning 'A reboot is required to finalize one or more remediations.'
    }

    Write-Host "Transcript: $($script:TranscriptPath)" -ForegroundColor Green
    Write-Host "Backup path: $($script:BackupPath)" -ForegroundColor Green
}
finally {
    if ($script:TranscriptActive) {
        Stop-Transcript | Out-Null
        $script:TranscriptActive = $false
    }
}