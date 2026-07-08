<#
.SYNOPSIS
    Comprehensive local Windows 11 DISA STIG remediation helper for post-SCAP/SCC remediation.

.DESCRIPTION
    This script is designed to target the entire Windows 11 STIG SCAP XML, not only a small hard-coded
    subset. It does three things:
      1. Reads the SCAP/XCCDF/OVAL XML and builds a full rule inventory for every selected rule.
      2. Applies comprehensive remediations that are safe to automate locally: PowerSTIG DSC, local security
         policy, user rights, audit policy, registry policy, per-user registry, selected services/features,
         certificate store checks, Windows LAPS policy, BitLocker policy, and several Windows 11 STIG-specific fixes.
      3. Runs a local pre-check score, writes a coverage report, and lists rules that still require organization-specific review.
      4. Creates a rollback package before changes, including registry, secedit, audit policy, firewall, service, and inventory exports.
      5. Runs post-remediation validation against safe XML-driven registry and audit checks.
      6. Optionally imports SCC/XCCDF, DISA CKL, or CSV results and remediates only failed findings.
      7. Provides an interactive local operator menu, system-readiness checks, local admin review,
         firewall preview, certificate reporting, post-reboot validation resume support, and report export options.

    IMPORTANT:
      - Run from an elevated PowerShell prompt.
      - Place the latest SCAP XML beside this script or pass -ScapXmlPath.
      - If multiple Windows 11 STIG SCAP XML files are present, the highest benchmark version/date is auto-selected.
      - Some STIG items cannot be blindly remediated without local mission/organization decisions.
      - Test in a pilot group before broad deployment.

.EXAMPLE
    .\Win11_STIG_Comprehensive_SCAP_Remediation_v3_PostSCAP_Local.ps1 -InteractiveMenu

.EXAMPLE
    # Recommended after running SCC/SCAP and exporting CKL/XCCDF/CSV results.
    .\Win11_STIG_Comprehensive_SCAP_Remediation_v3_PostSCAP_Local.ps1 -ScapXmlPath .\U_MS_Windows_11_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV17-signed[1].xml -AssessmentResultPath .\SCC_Results.ckl

.EXAMPLE
    # Analyze/report only, no remediation.
    .\Win11_STIG_Comprehensive_SCAP_Remediation_v3_PostSCAP_Local.ps1 -ScapXmlPath .\U_MS_Windows_11_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV17-signed[1].xml -AnalyzeOnly

.EXAMPLE
    # Resume validation after a reboot.
    .\Win11_STIG_Comprehensive_SCAP_Remediation_v3_PostSCAP_Local.ps1 -ScapXmlPath .\U_MS_Windows_11_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV17-signed[1].xml -AssessmentResultPath .\SCC_Results.ckl -ResumePostRebootValidation

.EXAMPLE
    # Full remediation with BitLocker PIN and certificate source folder.
    $pin = Read-Host 'BitLocker Startup PIN' -AsSecureString
    .\Win11_STIG_Comprehensive_SCAP_Remediation_v3_PostSCAP_Local.ps1 -ScapXmlPath .\U_MS_Windows_11_V2R8_STIG_SCAP_1-4_Benchmark-enhancedV17-signed[1].xml -StartupPin $pin -CertSourcePath C:\Temp\DoD_Certs -AllowBroadRemediationWithResultTargeting
#>

# ─────────────────────────────────────────────────────────────────────────────
# FUNCTION INDEX (this file is single-file by design - copied onto and run
# directly on the machine it baselines - so it stays one file; the #region
# blocks below and this index exist purely to make ~2600 lines/76 functions
# navigable in an editor with folding, e.g. VS Code/ISE "Fold All").
#
#   Parameters, Elevation & Bootstrap ............ script params, self-elevation, script-scope state
#   Core Logging & Native Command Helpers ........ Write-Section, Add-OutstandingItem, transcript, Invoke-NativeCommand
#   Registry Value & Per-User Registry Helpers ... Set/Remove-StigRegistryValue, OVAL type conversion, safety allowlist,
#                                                   orphaned-hive cleanup, per-user (NTUSER.DAT) registry writes
#   Service, Feature, Capability & Audit Policy ... Disable-StigService/-OptionalFeature, Remove-StigWindowsCapability, Set-AuditPolicy
#   Domain, Security Template & Certificates ..... Get-DomainContext, Invoke-StigSecurityTemplate, Import-StigCertificateIfMissing,
#                                                   built-in account rename
#   BitLocker, Time & LAPS ........................ Invoke-BitLockerRemediation, Set-StigWindowsTime, LAPS policy processing
#   Interactive Menu .............................. Read-StigYesNo, Invoke-StigInteractiveMenu
#   System Readiness & Local Admin Review ........ Invoke-StigSystemReadiness, Invoke-LocalAdminGroupReview
#   Reporting Helpers ............................. certificate/firewall-preview reports, post-reboot resume script,
#                                                   operator summary, USB export
#   Backup ......................................... Export-StigBackup (registry/secedit/audit/firewall/service/inventory)
#   SCAP/XCCDF XML Import & OVAL Interpretation ... XML node helpers, benchmark version detection, SCAP XML signature
#                                                   verification (Test-ScapXmlSignature), Import-ScapContent, OVAL lookups
#   SCAP-Driven Remediation ....................... registry + audit policy actions derived directly from the loaded SCAP XML
#   PowerSTIG / Local Policy / Hard-Coded Remediation .. PowerSTIG DSC baseline, local security policy, hard-coded registry
#                                                   fallbacks, and the per-category remediation orchestrators
#   Rule Targeting & Assessment-Result Helpers ... CKL/XCCDF/CSV import, which rule IDs are in scope for this run
#   Validation, Coverage Reporting & Summary ...... post-remediation validation, coverage CSV/report, final operator summary
#   Main Execution ................................ the actual top-to-bottom run, see the banner further down
# ─────────────────────────────────────────────────────────────────────────────

#region Parameters, Elevation & Bootstrap
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ScapXmlPath,

    # DISA's official SCAP benchmark exports carry an embedded XML digital
    # signature (XMLDSig) - a different mechanism from Authenticode, since
    # that doesn't apply to XML content. This script drives real
    # registry/audit-policy changes from whatever SCAP XML it's given, so an
    # unsigned or tampered file placed beside it would otherwise be trusted
    # implicitly. Pass this to hard-fail when the loaded SCAP XML is missing
    # a signature or the certificate chain doesn't validate, instead of just
    # warning.
    [Parameter(Mandatory = $false)]
    [switch]$RequireSignedScap,

    [Parameter(Mandatory = $false)]
    [string]$OrgSettingsPath,

    [Parameter(Mandatory = $false)]
    [switch]$SkipPowerSTIG,

    [Parameter(Mandatory = $false)]
    [switch]$AnalyzeOnly,

    [Parameter(Mandatory = $false)]
    [string]$AssessmentResultPath,

    [Parameter(Mandatory = $false)]
    [switch]$RemediateOnlyFailedFindings,

    [Parameter(Mandatory = $false)]
    [switch]$AllowBroadRemediationWithResultTargeting,

    [Parameter(Mandatory = $false)]
    [switch]$SkipPreCheck,

    [Parameter(Mandatory = $false)]
    [switch]$SkipPostValidation,

    [Parameter(Mandatory = $false)]
    [switch]$SkipScapDrivenRegistry,

    [Parameter(Mandatory = $false)]
    [switch]$AllowComplexOvalRegistry,

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
    [string]$BackupRoot = 'C:\ProgramData\PowerSTIG\Backups',

    [Parameter(Mandatory = $false)]
    [string]$ReportRoot = 'C:\ProgramData\PowerSTIG\Reports',

    [Parameter(Mandatory = $false)]
    [string[]]$AuthorizedRemoteManagementHosts,

    [Parameter(Mandatory = $false)]
    [switch]$ApplyAuthorizedFirewallScope,

    [Parameter(Mandatory = $false)]
    [switch]$InteractiveMenu,

    [Parameter(Mandatory = $false)]
    [switch]$ResumePostRebootValidation,

    # -ResumePostRebootValidation on its own has nothing to verify against -
    # it just skips straight to post-validation/reporting. This checks for a
    # small marker file written right after remediation completed and a
    # reboot was scheduled, so a crashed/interrupted run doesn't get quietly
    # reported as if it had finished cleanly. Pass -Force to proceed anyway
    # (e.g. resuming by hand after independently confirming remediation did
    # complete).
    [Parameter(Mandatory = $false)]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [switch]$SkipSystemReadiness,

    [Parameter(Mandatory = $false)]
    [switch]$SkipLocalAdminReview,

    [Parameter(Mandatory = $false)]
    [string[]]$AuthorizedLocalAdministrators,

    [Parameter(Mandatory = $false)]
    [switch]$AllowLocalAdminRemoval,

    [Parameter(Mandatory = $false)]
    [switch]$SkipFirewallPreview,

    [Parameter(Mandatory = $false)]
    [switch]$OpenReportsAtEnd,

    [Parameter(Mandatory = $false)]
    [switch]$NoReportPrompts,

    [Parameter(Mandatory = $false)]
    [switch]$PromptUsbExport,

    [Parameter(Mandatory = $false)]
    [string]$UsbExportPath,

    [Parameter(Mandatory = $false)]
    [switch]$SkipCertificateReport,

    # Internal marker set by the elevation relaunch below when the original,
    # non-elevated invocation had -StartupPin bound. SecureString parameters
    # cannot be safely forwarded across a relaunch (there is no way to pass
    # one on a command line without writing the PIN out in plain text, which
    # would defeat the entire point of using a SecureString), so instead of
    # silently dropping it, the elevated instance re-prompts for the PIN
    # itself when it sees this switch.
    [Parameter(Mandatory = $false)]
    [switch]$PromptForStartupPin
)

# Prompt for elevation if not already running as administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning 'This script requires administrator privileges. Relaunching elevated...'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    $needsPinPrompt = $false
    foreach ($key in $PSBoundParameters.Keys) {
        $val = $PSBoundParameters[$key]
        if ($val -is [switch]) {
            if ($val.IsPresent) { $argList += "-$key" }
        } elseif ($val -is [securestring]) {
            Write-Warning "Parameter -$key (SecureString) cannot be forwarded when relaunching elevated - the elevated instance will prompt for it instead."
            if ($key -eq 'StartupPin') { $needsPinPrompt = $true }
        } elseif ($val -is [string[]]) {
            foreach ($item in $val) { $argList += "-$key", "`"$item`"" }
        } else {
            $argList += "-$key", "`"$val`""
        }
    }
    if ($needsPinPrompt) { $argList += '-PromptForStartupPin' }
    Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs
    exit
}

# If the non-elevated invocation had -StartupPin bound, the relaunch above
# could not forward the SecureString value itself - prompt for it now, in
# the elevated session, so BitLocker TPM+PIN remediation further down
# actually gets a PIN instead of silently treating this as "not supplied".
if ($PromptForStartupPin -and -not $StartupPin) {
    $StartupPin = Read-Host -Prompt 'Enter the BitLocker startup PIN' -AsSecureString
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:RebootRequired = $false
$script:OutstandingItems = New-Object System.Collections.Generic.List[string]
$script:ValidationResults = New-Object System.Collections.Generic.List[object]
$script:TranscriptActive = $false
$script:TranscriptPath = $null
$script:BackupPath = $null
$script:ReportPath = $null
$script:CoverageReportPath = $null
$script:Defs = @{}
$script:Tests = @{}
$script:Objects = @{}
$script:States = @{}
$script:RuleInventory = @()
$script:TargetRuleIds = $null
$script:AssessmentFilterPath = $null
$script:PreCheckReportPath = $null
$script:PreCheckSummaryPath = $null
$script:PostValidationReportPath = $null
$script:PostValidationSummaryPath = $null
$script:RollbackScriptPath = $null
$script:LoadedScapXmlPath = $null
$script:BenchmarkVersionText = $null
$script:BenchmarkReleaseInfo = $null
$script:SystemReadinessReportPath = $null
$script:SystemReadinessSummaryPath = $null
$script:LocalAdminReportPath = $null
$script:FirewallPreviewReportPath = $null
$script:CertificateReportPath = $null
$script:OperatorSummaryPath = $null
$script:RebootResumeScriptPath = $null
$script:UsbExportDestination = $null
$script:BackupOnly = $false
#endregion Parameters, Elevation & Bootstrap

#region Core Logging & Native Command Helpers
function Write-Section {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host ''
    Write-Host ('=' * 90) -ForegroundColor DarkCyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host ('=' * 90) -ForegroundColor DarkCyan
}

function Add-OutstandingItem {
    param([Parameter(Mandatory)][string]$Message)
    if (-not $script:OutstandingItems.Contains($Message)) {
        $script:OutstandingItems.Add($Message) | Out-Null
    }
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

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [switch]$IgnoreExitCode
    )

    $output = & $FilePath @ArgumentList 2>&1
    $exitCode = $LASTEXITCODE

    # Exposed for callers using -IgnoreExitCode who still need to know
    # whether the command actually succeeded (e.g. reg.exe load/unload in
    # Set-PerUserRegistryValue) without changing this function's existing
    # return-value contract for the other ~20 call sites.
    $script:LastNativeExitCode = $exitCode

    if ($output) {
        $output | ForEach-Object { Write-Verbose $_ }
    }

    if (-not $IgnoreExitCode -and $exitCode -ne 0) {
        throw "Command failed: ${FilePath} $($ArgumentList -join ' ') (ExitCode=${exitCode})"
    }

    return $output
}
#endregion Core Logging & Native Command Helpers

#region Registry Value & Per-User Registry Helpers
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

function Remove-StigRegistryValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    if (Test-Path -LiteralPath $Path) {
        Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
    }
}

function Convert-RegistryPathFromOval {
    param(
        [Parameter(Mandatory)][string]$Hive,
        [Parameter(Mandatory)][string]$Key
    )

    $normalizedHive = $Hive.Trim().ToUpperInvariant()
    $cleanKey = $Key.Trim('\')

    switch ($normalizedHive) {
        'HKEY_LOCAL_MACHINE' { return "Registry::HKEY_LOCAL_MACHINE\$cleanKey" }
        'HKLM'               { return "Registry::HKEY_LOCAL_MACHINE\$cleanKey" }
        'HKEY_CURRENT_USER'  { return "Registry::HKEY_CURRENT_USER\$cleanKey" }
        'HKCU'               { return "Registry::HKEY_CURRENT_USER\$cleanKey" }
        default              { return $null }
    }
}

function Convert-OvalDataTypeToRegistryType {
    <#
    .DESCRIPTION
        Only ever receives $DataType 'int' or 'string' in practice:
        Convert-OvalValueForRegistry (the only caller of this function's
        caller) already rejects every other OVAL datatype - including
        'boolean' - before a value gets this far, returning $null for
        anything it doesn't recognize. So DWord/String are the only
        registry types this function needs to produce; QWord/MultiString
        are supported by Set-StigRegistryValue but are simply never
        reachable via this OVAL-driven path today. If Convert-OvalValueForRegistry
        is ever extended to accept more OVAL datatypes, extend this
        function's mapping to match at that point - adding speculative
        handling for datatypes that can never arrive here isn't testable
        and isn't worth the risk in a script that writes real system
        registry values.

        The '$Key -notmatch 'Winlogon$'' carve-out below is intentional,
        not a gap: some Winlogon values (e.g. AutoAdminLogon) are
        legitimately stored as REG_SZ even though their content looks like
        a plain integer ("1"), so numeric-looking Winlogon values are left
        as String rather than being coerced to DWord.
    #>
    param(
        [string]$DataType,
        [object]$Value,
        [string]$Key,
        [string]$Name
    )

    $stringOnlyNames = @('LegalNoticeCaption', 'LegalNoticeText', 'SCRemoveOption', 'RestrictRemoteSAM', 'ShellSmartScreenLevel', 'OutputDirectory')
    if ($stringOnlyNames -contains $Name) { return 'String' }

    if ($DataType -eq 'int' -or ($Value -is [int]) -or ($Value -is [long])) { return 'DWord' }
    if ([string]$Value -match '^-?\d+$' -and $Key -notmatch 'Winlogon$') { return 'DWord' }
    return 'String'
}

function Test-SafeRegistryTarget {
    param(
        [Parameter(Mandatory)][string]$Hive,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Name
    )

    $normalized = $Key.Replace('/', '\').Trim('\')
    $lower = $normalized.ToLowerInvariant()

    # Do not try to remediate OS identity/build/inventory keys. These are evidence checks, not hardening knobs.
    if ($lower -like 'software\microsoft\windows nt\currentversion*' -and $lower -notlike '*\winlogon*') { return $false }
    if ($lower -like 'software\microsoft\windows\currentversion\uninstall*') { return $false }

    $safePrefixes = @(
        'software\policies\',
        'system\currentcontrolset\control\lsa',
        'system\currentcontrolset\control\securityproviders',
        'system\currentcontrolset\control\session manager',
        'system\currentcontrolset\services\lanmanworkstation\parameters',
        'system\currentcontrolset\services\lanmanserver\parameters',
        'system\currentcontrolset\services\mrxsmb10',
        'system\currentcontrolset\services\netbt\parameters',
        'system\currentcontrolset\services\tcpip\parameters',
        'system\currentcontrolset\services\tcpip6\parameters',
        'system\currentcontrolset\services\netlogon\parameters',
        'system\currentcontrolset\services\ldap',
        'system\currentcontrolset\policies\earlylaunch',
        'software\microsoft\windows\currentversion\policies',
        'software\microsoft\windows nt\currentversion\winlogon',
        'software\microsoft\windows\currentversion\deliveryoptimization\config',
        'software\microsoft\windows\currentversion\policies\laps',
        'software\microsoft\policymanager\current\device\connectivity',
        'software\microsoft\wcmsvc\wifinetworkmanager\config',
        # Narrowed from a blanket 'software\classes\' (which would have
        # allowlisted SCAP-driven writes to the entire COM/file-association
        # registration hive) to the specific "Run as different user"
        # suppression subkeys this script actually writes to elsewhere
        # (see the runasuser SuppressionPolicy fix in
        # Invoke-HardCodedRegistryRemediation) - those are the only
        # confirmed-necessary Classes-hive targets in this script.
        'software\classes\batfile\shell\runasuser',
        'software\classes\cmdfile\shell\runasuser',
        'software\classes\exefile\shell\runasuser',
        'software\classes\mscfile\shell\runasuser',
        'software\microsoft\bluetoothauthenticationagent'
    )

    foreach ($prefix in $safePrefixes) {
        if ($lower.StartsWith($prefix)) { return $true }
    }
    return $false
}

function Clear-OrphanedRegistryHives {
    <#
    .SYNOPSIS
        Finds and force-unloads leftover HKU\TEMP_* hive mounts from a
        previous run of this script that was interrupted before it could
        unload them (e.g. a crash between reg.exe load and unload in
        Set-PerUserRegistryValue).
    .DESCRIPTION
        A leftover mount keeps that user's NTUSER.DAT locked, which makes
        every subsequent reg.exe load for the same user fail silently -
        without this check, per-user remediation for that profile would
        just keep getting skipped on every run with no indication why.
        Run this once, early, before any per-user remediation.
    #>
    $orphans = Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -like 'TEMP_*' }

    foreach ($orphan in $orphans) {
        Write-Warning "Found an orphaned registry hive mount from a previous run: HKU\$($orphan.PSChildName) - attempting to unload it."
        try {
            Invoke-NativeCommand -FilePath reg.exe -ArgumentList @('unload', "HKU\$($orphan.PSChildName)") -IgnoreExitCode | Out-Null
            if ($script:LastNativeExitCode -eq 0) {
                Write-Section "Unloaded orphaned hive HKU\$($orphan.PSChildName)"
            } else {
                Add-OutstandingItem "Could not unload orphaned registry hive HKU\$($orphan.PSChildName) left over from a previous run (reg.exe unload exit code $script:LastNativeExitCode). Per-user remediation for the corresponding profile will keep being skipped until this is cleared manually."
            }
        } catch {
            Add-OutstandingItem "Error while attempting to unload orphaned registry hive HKU\$($orphan.PSChildName): $($_.Exception.Message)"
        }
    }
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
    $profiles = Get-ChildItem -Path $profileListPath -ErrorAction SilentlyContinue | Where-Object {
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
        if (-not $ntUser -or -not (Test-Path -LiteralPath $ntUser)) { continue }

        $mountName = 'TEMP_' + ($sid -replace '-', '_')
        $loaded = $false
        try {
            Invoke-NativeCommand -FilePath reg.exe -ArgumentList @('load', "HKU\$mountName", $ntUser) -IgnoreExitCode | Out-Null
            if ($script:LastNativeExitCode -ne 0) {
                Add-OutstandingItem "Could not load registry hive for user $sid ($ntUser) - reg.exe load exit code $script:LastNativeExitCode. Per-user setting '$Name' under $SubKey was not applied for this user."
                continue
            }
            $loaded = $true
            $mountedTarget = "Registry::HKEY_USERS\$mountName\$SubKey"
            Set-StigRegistryValue -Path $mountedTarget -Name $Name -Type $Type -Value $Value
        }
        finally {
            if ($loaded) {
                Invoke-NativeCommand -FilePath reg.exe -ArgumentList @('unload', "HKU\$mountName") -IgnoreExitCode | Out-Null
                if ($script:LastNativeExitCode -ne 0) {
                    Add-OutstandingItem "Could not unload registry hive HKU\$mountName for user $sid after remediation - it may still be mounted. Check Registry Editor and unload it manually (reg.exe unload HKU\$mountName) before this script runs again for this user."
                }
            }
        }
    }

    $defaultNtUser = 'C:\Users\Default\NTUSER.DAT'
    if (Test-Path -LiteralPath $defaultNtUser) {
        $mountName = 'TEMP_DEFAULT_USER'
        $loaded = $false
        try {
            Invoke-NativeCommand -FilePath reg.exe -ArgumentList @('load', "HKU\$mountName", $defaultNtUser) -IgnoreExitCode | Out-Null
            if ($script:LastNativeExitCode -ne 0) {
                Add-OutstandingItem "Could not load the Default user registry hive ($defaultNtUser) - reg.exe load exit code $script:LastNativeExitCode. Setting '$Name' under $SubKey was not applied to the Default user profile, so it will not take effect for new user accounts."
                return
            }
            $loaded = $true
            $target = "Registry::HKEY_USERS\$mountName\$SubKey"
            Set-StigRegistryValue -Path $target -Name $Name -Type $Type -Value $Value
        }
        finally {
            if ($loaded) {
                Invoke-NativeCommand -FilePath reg.exe -ArgumentList @('unload', "HKU\$mountName") -IgnoreExitCode | Out-Null
                if ($script:LastNativeExitCode -ne 0) {
                    Add-OutstandingItem "Could not unload registry hive HKU\$mountName (Default user) after remediation - it may still be mounted. Check Registry Editor and unload it manually (reg.exe unload HKU\$mountName) before this script runs again."
                }
            }
        }
    }
}
#endregion Registry Value & Per-User Registry Helpers

#region Service, Feature, Capability & Audit Policy Helpers
function Disable-StigService {
    param([Parameter(Mandatory)][string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { return }
    if ($svc.Status -ne 'Stopped') { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue }
    Set-Service -Name $Name -StartupType Disabled -ErrorAction SilentlyContinue
}

function Start-StigServiceAuto {
    param([Parameter(Mandatory)][string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { return }
    Set-Service -Name $Name -StartupType Automatic -ErrorAction SilentlyContinue
    if ($svc.Status -ne 'Running') { Start-Service -Name $Name -ErrorAction SilentlyContinue }
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

function Remove-StigWindowsCapability {
    param([Parameter(Mandatory)][string]$NamePattern)
    $capabilities = Get-WindowsCapability -Online -ErrorAction SilentlyContinue | Where-Object { $_.Name -like $NamePattern -and $_.State -eq 'Installed' }
    foreach ($capability in $capabilities) {
        try {
            Remove-WindowsCapability -Online -Name $capability.Name -ErrorAction Stop | Out-Null
            $script:RebootRequired = $true
        }
        catch {
            Add-OutstandingItem "Capability $($capability.Name) could not be removed automatically: $($_.Exception.Message)"
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
    Invoke-NativeCommand -FilePath auditpol.exe -ArgumentList @('/set', "/subcategory:$Subcategory", "/success:$successArg", "/failure:$failureArg") | Out-Null
}
#endregion Service, Feature, Capability & Audit Policy Helpers

#region Domain, Security Template & Certificates
function Get-DomainContext {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $partOfDomain = [bool]$cs.PartOfDomain
    $domainName = if ($partOfDomain) { [string]$cs.Domain } else { $null }
    $domainSid = $null

    if ($partOfDomain) {
        try {
            $domainAccount = New-Object System.Security.Principal.NTAccount("$domainName\Domain Admins")
            $domainAdminsSid = $domainAccount.Translate([System.Security.Principal.SecurityIdentifier])
            $domainSid = ($domainAdminsSid.Value -replace '-512$', '')
        }
        catch {
            Add-OutstandingItem 'Unable to derive domain SID from Domain Admins. Domain-specific deny rights may need manual validation.'
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

    $tempRoot = Join-Path $env:TEMP ('STIGSecEdit_' + [guid]::NewGuid().Guid)
    New-StigDirectory -Path $tempRoot
    $infPath = Join-Path $tempRoot 'stig.inf'
    $dbPath = Join-Path $tempRoot 'stig.sdb'

    $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1')

    if ($SystemAccess.Count -gt 0) {
        $lines += '[System Access]'
        foreach ($key in $SystemAccess.Keys) { $lines += "$key = $($SystemAccess[$key])" }
    }

    if ($PrivilegeRights.Count -gt 0) {
        $lines += '[Privilege Rights]'
        foreach ($key in $PrivilegeRights.Keys) {
            $value = $PrivilegeRights[$key]
            if ($null -eq $value -or @($value).Count -eq 0) {
                $lines += "$key ="
                continue
            }

            $joined = @($value) | Where-Object { $_ } | ForEach-Object {
                if ($_ -match '^S-1-') { "*$_" } else { $_ }
            }
            $lines += "$key = $($joined -join ',')"
        }
    }

    Set-Content -Path $infPath -Value $lines -Encoding Unicode

    $areas = @()
    if ($SystemAccess.Count -gt 0) { $areas += 'SECURITYPOLICY' }
    if ($PrivilegeRights.Count -gt 0) { $areas += 'USER_RIGHTS' }

    if ($areas.Count -gt 0) {
        Invoke-NativeCommand -FilePath secedit.exe -ArgumentList @('/configure', '/db', $dbPath, '/cfg', $infPath, '/areas', ($areas -join ' ')) | Out-Null
    }

    Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

function Import-StigCertificateIfMissing {
    param(
        [Parameter(Mandatory)][string]$StorePath,
        [Parameter(Mandatory)][string]$Thumbprint,
        [Parameter(Mandatory)][string]$SubjectLike
    )

    $normalizedThumb = ($Thumbprint -replace '\s', '').ToUpperInvariant()
    $existing = Get-ChildItem -Path $StorePath -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $normalizedThumb }
    if ($existing) { return }

    if (-not $CertSourcePath -or -not (Test-Path -LiteralPath $CertSourcePath)) {
        Add-OutstandingItem "Certificate missing ($SubjectLike / $normalizedThumb) in $StorePath. Supply -CertSourcePath to import it."
        return
    }

    $candidateFile = Get-ChildItem -Path $CertSourcePath -Recurse -File -Include *.cer, *.crt -ErrorAction SilentlyContinue | Where-Object {
        try { (Get-PfxCertificate -FilePath $_.FullName).Thumbprint -eq $normalizedThumb } catch { $false }
    } | Select-Object -First 1

    if (-not $candidateFile) {
        Add-OutstandingItem "Certificate file not found for $SubjectLike / $normalizedThumb in $CertSourcePath."
        return
    }

    Import-Certificate -FilePath $candidateFile.FullName -CertStoreLocation $StorePath -ErrorAction Stop | Out-Null
}

function Get-BuiltInLocalUserByRid {
    param([Parameter(Mandatory)][int]$Rid)
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue
    Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -match "-$Rid$" } | Select-Object -First 1
}

function Rename-BuiltInAccounts {
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue

    $admin = Get-BuiltInLocalUserByRid -Rid 500
    if ($admin -and $admin.Name -ne $BuiltInAdministratorNewName) {
        if (Get-LocalUser -Name $BuiltInAdministratorNewName -ErrorAction SilentlyContinue) {
            Add-OutstandingItem "Cannot rename built-in Administrator to '$BuiltInAdministratorNewName' because that account already exists."
        }
        else { Rename-LocalUser -Name $admin.Name -NewName $BuiltInAdministratorNewName }
    }

    $guest = Get-BuiltInLocalUserByRid -Rid 501
    if ($guest) {
        if ($guest.Enabled) { Disable-LocalUser -Name $guest.Name -ErrorAction SilentlyContinue }
        if ($guest.Name -ne $BuiltInGuestNewName) {
            if (Get-LocalUser -Name $BuiltInGuestNewName -ErrorAction SilentlyContinue) {
                Add-OutstandingItem "Cannot rename built-in Guest to '$BuiltInGuestNewName' because that account already exists."
            }
            else { Rename-LocalUser -Name $guest.Name -NewName $BuiltInGuestNewName }
        }
    }
}
#endregion Domain, Security Template & Certificates

#region BitLocker, Time & LAPS
function Invoke-BitLockerRemediation {
    param([Parameter(Mandatory)][securestring]$Pin)

    Write-Section 'Applying BitLocker policy and remediation'
    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE' -Name 'UseAdvancedStartup' -Type DWord -Value 1
    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE' -Name 'UseTPMPIN' -Type DWord -Value 1
    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE' -Name 'UseTPMKeyPIN' -Type DWord -Value 1
    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE' -Name 'MinimumPIN' -Type DWord -Value 6

    try { $secureBootOk = [bool](Confirm-SecureBootUEFI) } catch { $secureBootOk = $false }
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    if (-not $tpm -or -not $tpm.TpmPresent -or -not $tpm.TpmReady) {
        Add-OutstandingItem 'BitLocker TPM+PIN was not completed because TPM is absent or not ready.'
        return
    }
    if (-not $secureBootOk) {
        Add-OutstandingItem 'BitLocker TPM+PIN was not completed because Secure Boot is not confirmed as enabled.'
        return
    }

    $volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object { $_.VolumeType -in @('OperatingSystem', 'FixedData') }
    foreach ($volume in $volumes) {
        $mount = $volume.MountPoint
        if (-not $mount) { continue }

        if ($volume.ProtectionStatus -eq 'On') {
            if ($volume.VolumeType -eq 'OperatingSystem') {
                $hasTpmPin = $false
                foreach ($kp in $volume.KeyProtector) {
                    if ($kp.KeyProtectorType -match 'TpmPin') { $hasTpmPin = $true }
                }
                if (-not $hasTpmPin) {
                    Add-BitLockerKeyProtector -MountPoint $mount -Pin $Pin -TpmAndPinProtector -ErrorAction Stop | Out-Null
                }
            }
            continue
        }

        if ($volume.VolumeType -eq 'OperatingSystem') {
            Enable-BitLocker -MountPoint $mount -EncryptionMethod XtsAes256 -TpmAndPinProtector -Pin $Pin -RecoveryPasswordProtector -SkipHardwareTest -ErrorAction Stop | Out-Null
        }
        else {
            Enable-BitLocker -MountPoint $mount -EncryptionMethod XtsAes256 -RecoveryPasswordProtector -ErrorAction Stop | Out-Null
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
        Add-OutstandingItem 'Standalone system time source is outstanding. Supply -NtpServer with an authorized DoD/organization NTP source.'
        return
    }

    Invoke-NativeCommand -FilePath w32tm.exe -ArgumentList @('/config', "/manualpeerlist:$NtpServer", '/syncfromflags:manual', '/reliable:no', '/update') | Out-Null
    Restart-Service -Name W32Time -Force -ErrorAction SilentlyContinue
    Invoke-NativeCommand -FilePath w32tm.exe -ArgumentList @('/resync', '/force') -IgnoreExitCode | Out-Null
}

function Invoke-StigLapsPolicyProcessing {
    Write-Section 'Applying Windows LAPS policy'
    $lapsPolicyPath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
    Set-StigRegistryValue -Path $lapsPolicyPath -Name 'PasswordAgeDays' -Type DWord -Value 60
    Set-StigRegistryValue -Path $lapsPolicyPath -Name 'PasswordLength' -Type DWord -Value 14
    Set-StigRegistryValue -Path $lapsPolicyPath -Name 'PasswordComplexity' -Type DWord -Value 4

    $cmd = Get-Command -Name Invoke-LapsPolicyProcessing -ErrorAction SilentlyContinue
    if (-not $cmd) {
        Add-OutstandingItem 'Windows LAPS policy values were written, but Invoke-LapsPolicyProcessing is not available on this system.'
        return
    }

    try { Invoke-LapsPolicyProcessing | Out-Null } catch { Add-OutstandingItem "Windows LAPS policy processing failed: $($_.Exception.Message)" }
}
#endregion BitLocker, Time & LAPS

#region Interactive Menu
function Read-StigYesNo {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [bool]$DefaultYes = $true
    )
    $suffix = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
    try { $answer = Read-Host "$Prompt $suffix" } catch { return $DefaultYes }
    if ([string]::IsNullOrWhiteSpace($answer)) { return $DefaultYes }
    return ($answer.Trim() -match '^(y|yes)$')
}

function Invoke-StigInteractiveMenu {
    if (-not $InteractiveMenu) { return $null }

    Write-Section 'Local post-SCAP remediation menu'
    Write-Host 'Recommended workflow: run SCC/SCAP first, export the CKL/XCCDF/CSV result, then choose option 2.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '1. Analyze only / build reports, no changes'
    Write-Host '2. Import SCC/CKL/XCCDF/CSV result and remediate failed findings only'
    Write-Host '3. Full local remediation against the loaded Windows 11 STIG XML'
    Write-Host '4. Post-reboot validation only'
    Write-Host '5. Create rollback package only, no remediation'
    Write-Host '6. Exit'
    Write-Host ''

    $choice = Read-Host 'Select an option [1-6]'
    $result = @{}
    switch ($choice) {
        '1' { $result['AnalyzeOnly'] = $true }
        '2' {
            $result['RemediateOnlyFailedFindings'] = $true
            if (-not $AssessmentResultPath) {
                $p = Read-Host 'Enter SCC/CKL/XCCDF/CSV result path'
                if (-not [string]::IsNullOrWhiteSpace($p)) { $result['AssessmentResultPath'] = $p.Trim('"') }
            }
        }
        '3' {
            if ($AssessmentResultPath -and (Read-StigYesNo -Prompt 'Target only failed findings from the supplied result file?' -DefaultYes $true)) {
                $result['RemediateOnlyFailedFindings'] = $true
            }
            else {
                $result['AllowBroadRemediationWithResultTargeting'] = $true
            }
        }
        '4' { $result['ResumePostRebootValidation'] = $true }
        '5' { $script:BackupOnly = $true }
        '6' { Write-Host 'Exiting by operator selection.' -ForegroundColor Yellow; exit 0 }
        default { throw "Invalid menu option: $choice" }
    }

    if (-not $ScapXmlPath) {
        $xmlPath = Read-Host 'Optional SCAP XML path; press Enter to auto-select latest beside script/current folder'
        if (-not [string]::IsNullOrWhiteSpace($xmlPath)) { $result['ScapXmlPath'] = $xmlPath.Trim('"') }
    }

    return $result
}
#endregion Interactive Menu

#region System Readiness & Local Admin Review
function Invoke-StigSystemReadiness {
    param([Parameter(Mandatory)][string]$OutputRoot)

    Write-Section 'Checking Windows 11 STIG system readiness'
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $detailPath = Join-Path $OutputRoot "Win11_STIG_SystemReadiness_$stamp.csv"
    $summaryPath = Join-Path $OutputRoot "Win11_STIG_SystemReadiness_$stamp.txt"

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue

    $secureBoot = 'Unknown'
    if (Get-Command -Name Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
        try { $secureBoot = [string](Confirm-SecureBootUEFI) } catch { $secureBoot = "Unknown/Unsupported: $($_.Exception.Message)" }
    }

    $tpmPresent = 'Unknown'
    $tpmReady = 'Unknown'
    if (Get-Command -Name Get-Tpm -ErrorAction SilentlyContinue) {
        try {
            $tpm = Get-Tpm -ErrorAction Stop
            $tpmPresent = [string]$tpm.TpmPresent
            $tpmReady = [string]$tpm.TpmReady
        } catch { $tpmPresent = "Unknown: $($_.Exception.Message)" }
    }

    $bitLockerStatus = 'Unknown'
    if (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        try {
            $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
            $bitLockerStatus = "Protection=$($bl.ProtectionStatus); VolumeStatus=$($bl.VolumeStatus); Encryption=$($bl.EncryptionPercentage)%"
        } catch { $bitLockerStatus = "Unknown: $($_.Exception.Message)" }
    }

    $mdmEnrollment = 'Not detected'
    try {
        $enrollments = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue |
            Where-Object { (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).EnrollmentType -ne $null }
        if ($enrollments) { $mdmEnrollment = 'Detected' }
    } catch { $mdmEnrollment = 'Unknown' }

    $vbsState = 'Unknown'
    try {
        $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
        $vbsState = "SecurityServicesConfigured=$($dg.SecurityServicesConfigured -join ','); SecurityServicesRunning=$($dg.SecurityServicesRunning -join ','); VirtualizationBasedSecurityStatus=$($dg.VirtualizationBasedSecurityStatus)"
    } catch { $vbsState = 'Unknown or namespace unavailable' }

    $row = [pscustomobject]@{
        ComputerName       = $env:COMPUTERNAME
        UserContext        = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        OSName             = $os.Caption
        OSVersion          = $os.Version
        OSBuildNumber      = $os.BuildNumber
        InstallDate        = $os.InstallDate
        Manufacturer       = $cs.Manufacturer
        Model              = $cs.Model
        BIOSVersion        = ($bios.SMBIOSBIOSVersion -join ' ')
        DomainJoined       = $cs.PartOfDomain
        Domain             = $cs.Domain
        MDMEnrollment      = $mdmEnrollment
        SecureBoot         = $secureBoot
        TpmPresent         = $tpmPresent
        TpmReady           = $tpmReady
        BitLockerSystem    = $bitLockerStatus
        VBSDeviceGuard     = $vbsState
        PowerShellVersion  = $PSVersionTable.PSVersion.ToString()
        ScapXml            = $script:LoadedScapXmlPath
        BenchmarkVersion   = $script:BenchmarkVersionText
        AssessmentFilter   = $script:AssessmentFilterPath
    }

    $row | Export-Csv -Path $detailPath -NoTypeInformation -Encoding UTF8
    $lines = @(
        'Windows 11 STIG system readiness',
        "Generated: $(Get-Date -Format o)",
        "Computer: $env:COMPUTERNAME",
        "User context: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)",
        "OS: $($row.OSName) $($row.OSVersion) Build $($row.OSBuildNumber)",
        "Domain joined: $($row.DomainJoined) / $($row.Domain)",
        "MDM enrollment: $($row.MDMEnrollment)",
        "Secure Boot: $($row.SecureBoot)",
        "TPM present/ready: $($row.TpmPresent) / $($row.TpmReady)",
        "BitLocker system drive: $($row.BitLockerSystem)",
        "VBS/Device Guard: $($row.VBSDeviceGuard)",
        "SCAP XML: $($script:LoadedScapXmlPath)",
        "Benchmark version: $($script:BenchmarkVersionText)",
        "Detail CSV: $detailPath"
    )
    Set-Content -Path $summaryPath -Value $lines -Encoding UTF8
    $script:SystemReadinessReportPath = $detailPath
    $script:SystemReadinessSummaryPath = $summaryPath
    Write-Host "System readiness report: $detailPath" -ForegroundColor Green
}

function Invoke-LocalAdminGroupReview {
    param([Parameter(Mandatory)][string]$OutputRoot)

    Write-Section 'Reviewing local Administrators group'
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $path = Join-Path $OutputRoot "Win11_STIG_LocalAdministrators_$stamp.csv"
    $authorizedSet = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @($AuthorizedLocalAdministrators)) {
        if (-not [string]::IsNullOrWhiteSpace($name)) { [void]$authorizedSet.Add($name.Trim()) }
    }

    $members = @()
    try {
        $members = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object {
            $isAuthorized = if ($authorizedSet.Count -eq 0) { $null } else { $authorizedSet.Contains([string]$_.Name) -or $authorizedSet.Contains([string]$_.SID) }
            [pscustomobject]@{
                ComputerName    = $env:COMPUTERNAME
                Group           = 'Administrators'
                Name            = $_.Name
                ObjectClass     = $_.ObjectClass
                PrincipalSource = $_.PrincipalSource
                SID             = $_.SID.Value
                Authorized      = $isAuthorized
            }
        })
    }
    catch {
        Add-OutstandingItem "Could not enumerate local Administrators group: $($_.Exception.Message)"
    }

    if ($members.Count -gt 0) {
        $members | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        $script:LocalAdminReportPath = $path
        Write-Host "Local Administrators report: $path" -ForegroundColor Green
        $members | Format-Table Name,ObjectClass,PrincipalSource,Authorized -AutoSize | Out-Host

        if ($authorizedSet.Count -gt 0) {
            $unauthorized = @($members | Where-Object { $_.Authorized -eq $false })
            if ($unauthorized.Count -gt 0) {
                Add-OutstandingItem "Local Administrators group contains $($unauthorized.Count) member(s) not in -AuthorizedLocalAdministrators. See $path."
                if ($AllowLocalAdminRemoval) {
                    if (Read-StigYesNo -Prompt "Remove unauthorized local Administrators members listed in $path?" -DefaultYes $false) {
                        foreach ($member in $unauthorized) {
                            try { Remove-LocalGroupMember -Group 'Administrators' -Member $member.Name -ErrorAction Stop }
                            catch { Add-OutstandingItem "Failed removing local admin member '$($member.Name)': $($_.Exception.Message)" }
                        }
                    }
                }
            }
        }
        else {
            Add-OutstandingItem "Local Administrators group was exported for review. Provide -AuthorizedLocalAdministrators to flag unauthorized members automatically. Report: $path"
        }
    }
}
#endregion System Readiness & Local Admin Review

#region Reporting Helpers
function Get-StigCertificateRequirements {
    @(
        [pscustomobject]@{ StorePath='Cert:\LocalMachine\Root';       Thumbprint='D73CA91102A2204A36459ED32213B467D7CE97FB'; SubjectLike='DoD Root CA 3' },
        [pscustomobject]@{ StorePath='Cert:\LocalMachine\Root';       Thumbprint='B8269F25DBD937ECAFD4C35A9838571723F2D026'; SubjectLike='DoD Root CA 4' },
        [pscustomobject]@{ StorePath='Cert:\LocalMachine\Root';       Thumbprint='4ECB5CC3095670454DA1CBD410FC921F46B8564B'; SubjectLike='DoD Root CA 5' },
        [pscustomobject]@{ StorePath='Cert:\LocalMachine\Root';       Thumbprint='D37ECF61C0B4ED88681EF3630C4E2FC787B37AEF'; SubjectLike='DoD Root CA 6' },
        [pscustomobject]@{ StorePath='Cert:\LocalMachine\Root';       Thumbprint='73E8BB08E337D6A5A6AEF90CFFDD97D9176CB582'; SubjectLike='ECA Root CA 4' },
        [pscustomobject]@{ StorePath='Cert:\LocalMachine\Disallowed'; Thumbprint='49CBE933151872E17C8EAE7F0ABA97FB610F6477'; SubjectLike='DoD Interop CA 2 -> DoD Root CA 3' },
        [pscustomobject]@{ StorePath='Cert:\LocalMachine\Disallowed'; Thumbprint='AC06108CA348CC03B53795C64BF84403C1DBD341'; SubjectLike='DoD Interop CA 2 -> DoD Root CA 3 legacy' },
        [pscustomobject]@{ StorePath='Cert:\LocalMachine\Disallowed'; Thumbprint='9B74964506C7ED9138070D08D5F8B969866560C8'; SubjectLike='US DoD CCEB Interop CA 2 -> DoD Root CA 3' },
        [pscustomobject]@{ StorePath='Cert:\LocalMachine\Disallowed'; Thumbprint='D471CA32F7A692CE6CBB6196BD3377FE4DBCD106'; SubjectLike='US DoD CCEB Interop CA 2 -> DoD Root CA 6' }
    )
}

function Export-StigCertificateReport {
    param(
        [Parameter(Mandatory)][string]$OutputRoot,
        [Parameter(Mandatory)][string]$Phase
    )
    if ($SkipCertificateReport) { return }

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $path = Join-Path $OutputRoot "Win11_STIG_CertificateReport_${Phase}_$stamp.csv"
    $rows = foreach ($req in Get-StigCertificateRequirements) {
        $thumb = ($req.Thumbprint -replace '\s','').ToUpperInvariant()
        $cert = Get-ChildItem -Path $req.StorePath -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
        $candidate = $null
        if ($CertSourcePath -and (Test-Path -LiteralPath $CertSourcePath)) {
            $candidate = Get-ChildItem -Path $CertSourcePath -Recurse -File -Include *.cer,*.crt -ErrorAction SilentlyContinue | Where-Object {
                try { ((Get-PfxCertificate -FilePath $_.FullName).Thumbprint -replace '\s','').ToUpperInvariant() -eq $thumb } catch { $false }
            } | Select-Object -First 1
        }
        [pscustomobject]@{
            Phase              = $Phase
            StorePath          = $req.StorePath
            SubjectLike        = $req.SubjectLike
            Thumbprint         = $thumb
            StoreStatus        = if ($cert) { 'Present' } else { 'Missing' }
            Subject            = if ($cert) { $cert.Subject } else { $null }
            NotAfter           = if ($cert) { $cert.NotAfter } else { $null }
            Expired            = if ($cert) { ($cert.NotAfter -lt (Get-Date)) } else { $null }
            CandidateFile      = if ($candidate) { $candidate.FullName } else { $null }
            CandidateFileFound = [bool]$candidate
        }
    }
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    $script:CertificateReportPath = $path
    Write-Host "Certificate report: $path" -ForegroundColor Green
}

function Export-FirewallScopePreview {
    param([Parameter(Mandatory)][string]$OutputRoot)

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $path = Join-Path $OutputRoot "Win11_STIG_FirewallScopePreview_$stamp.csv"
    $proposed = if ($AuthorizedRemoteManagementHosts) { ($AuthorizedRemoteManagementHosts -join ',') } else { '<none supplied>' }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($rule in @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue)) {
        $currentAddress = '<unknown>'
        try {
            $addr = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
            $currentAddress = ($addr.RemoteAddress -join ',')
        } catch { }
        $rows.Add([pscustomobject]@{
            Name                  = $rule.Name
            DisplayName           = $rule.DisplayName
            Group                 = $rule.Group
            Profile               = $rule.Profile
            CurrentRemoteAddress  = $currentAddress
            ProposedRemoteAddress = $proposed
            WillChange            = ($ApplyAuthorizedFirewallScope -and $AuthorizedRemoteManagementHosts -and $currentAddress -ne $proposed)
        }) | Out-Null
    }
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    $script:FirewallPreviewReportPath = $path
    Write-Host "Firewall preview report: $path" -ForegroundColor Green
    return $path
}

function Get-StigResumeMarkerPath {
    param([Parameter(Mandatory)][string]$OutputRoot)
    Join-Path $OutputRoot '.stig_resume_state.json'
}

function New-PostRebootValidationScript {
    param([Parameter(Mandatory)][string]$OutputRoot)
    if (-not $PSCommandPath) { return }
    $path = Join-Path $OutputRoot 'Resume-PostReboot-STIG-Validation.ps1'
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("`$ErrorActionPreference = 'Stop'") | Out-Null
    $cmd = @('&', ('"' + $PSCommandPath + '"'), '-ResumePostRebootValidation', '-NoReportPrompts')
    if ($script:LoadedScapXmlPath) { $cmd += @('-ScapXmlPath', ('"' + $script:LoadedScapXmlPath + '"')) }
    if ($AssessmentResultPath) { $cmd += @('-AssessmentResultPath', ('"' + (Resolve-Path -LiteralPath $AssessmentResultPath).Path + '"')) }
    if ($RemediateOnlyFailedFindings) { $cmd += '-RemediateOnlyFailedFindings' }
    if ($SkipCertificateReport) { $cmd += '-SkipCertificateReport' }
    $lines.Add(($cmd -join ' ')) | Out-Null
    Set-Content -Path $path -Value $lines -Encoding UTF8
    $script:RebootResumeScriptPath = $path
    Write-Host "Post-reboot validation helper: $path" -ForegroundColor Green

    # Marker confirming remediation genuinely completed on THIS machine
    # before the reboot - -ResumePostRebootValidation checks for this so an
    # interrupted/crashed run doesn't get reported as if it had finished
    # cleanly.
    $markerPath = Get-StigResumeMarkerPath -OutputRoot $OutputRoot
    [pscustomobject]@{
        ComputerName  = $env:COMPUTERNAME
        CompletedUtc  = (Get-Date).ToUniversalTime().ToString('o')
        ScapXmlPath   = $script:LoadedScapXmlPath
    } | ConvertTo-Json | Set-Content -Path $markerPath -Encoding UTF8
}

function Get-StigStatusCountsFromCsv {
    param([string]$Path)
    $result = @{ Pass=0; Fail=0; Review=0; Skipped=0; Other=0 }
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $result }
    foreach ($group in (Import-Csv -LiteralPath $Path | Group-Object -Property Status)) {
        if ($result.ContainsKey($group.Name)) { $result[$group.Name] = $group.Count } else { $result['Other'] += $group.Count }
    }
    return $result
}

function Write-StigOperatorSummary {
    param([Parameter(Mandatory)][string]$OutputRoot)
    Write-Section 'Operator summary'
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $path = Join-Path $OutputRoot "Win11_STIG_OperatorSummary_$stamp.txt"
    $pre = Get-StigStatusCountsFromCsv -Path $script:PreCheckReportPath
    $post = Get-StigStatusCountsFromCsv -Path $script:PostValidationReportPath
    $targetCount = if ($script:RuleInventory) { @($script:RuleInventory | Where-Object { Test-StigRuleTargeted -Rule $_ }).Count } else { 0 }
    $mode = if ($ResumePostRebootValidation) { 'Post-reboot validation only' }
        elseif ($AnalyzeOnly) { 'Analyze only' }
        elseif ($RemediateOnlyFailedFindings) { 'Failed findings only' }
        elseif ($script:BackupOnly) { 'Rollback package only' }
        else { 'Full local remediation' }

    $lines = @(
        "Machine: $env:COMPUTERNAME",
        "Run mode: $mode",
        "Generated: $(Get-Date -Format o)",
        "SCAP XML: $($script:LoadedScapXmlPath)",
        "Benchmark version: $($script:BenchmarkVersionText)",
        "Assessment filter: $($script:AssessmentFilterPath)",
        "Total XML rules loaded: $($script:RuleInventory.Count)",
        "Targeted rules: $targetCount",
        "Pre-check counts: Pass=$($pre.Pass); Fail=$($pre.Fail); Review=$($pre.Review); Skipped=$($pre.Skipped); Other=$($pre.Other)",
        "Post-validation counts: Pass=$($post.Pass); Fail=$($post.Fail); Review=$($post.Review); Skipped=$($post.Skipped); Other=$($post.Other)",
        "Outstanding/manual/environment-specific items: $($script:OutstandingItems.Count)",
        "Reboot required: $script:RebootRequired",
        "Transcript: $($script:TranscriptPath)",
        "Backup path: $($script:BackupPath)",
        "Rollback script: $($script:RollbackScriptPath)",
        "Post-reboot validation helper: $($script:RebootResumeScriptPath)",
        "Coverage report: $($script:CoverageReportPath)",
        "System readiness report: $($script:SystemReadinessReportPath)",
        "Local admin report: $($script:LocalAdminReportPath)",
        "Firewall preview report: $($script:FirewallPreviewReportPath)",
        "Certificate report: $($script:CertificateReportPath)",
        "Outstanding summary: $($script:ReportPath)",
        "USB export destination: $($script:UsbExportDestination)"
    )
    Set-Content -Path $path -Value $lines -Encoding UTF8
    $script:OperatorSummaryPath = $path
    $lines | ForEach-Object { Write-Host $_ }
}

function Copy-StigRunArtifactsToUsb {
    param([string]$DestinationRoot)

    if ([string]::IsNullOrWhiteSpace($DestinationRoot)) {
        $removable = @(Get-Volume -DriveType Removable -ErrorAction SilentlyContinue | Where-Object DriveLetter | Select-Object -First 1)
        if ($removable.Count -gt 0) { $DestinationRoot = ($removable[0].DriveLetter + ':\') }
    }
    if ([string]::IsNullOrWhiteSpace($DestinationRoot)) {
        $DestinationRoot = Read-Host 'Enter destination path for report/backup export'
    }
    if ([string]::IsNullOrWhiteSpace($DestinationRoot)) { return }

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $dest = Join-Path $DestinationRoot "Win11_STIG_Run_$($env:COMPUTERNAME)_$stamp"
    New-StigDirectory -Path $dest

    foreach ($file in @(
        $script:TranscriptPath,
        $script:CoverageReportPath,
        $script:PreCheckReportPath,
        $script:PreCheckSummaryPath,
        $script:PostValidationReportPath,
        $script:PostValidationSummaryPath,
        $script:SystemReadinessReportPath,
        $script:SystemReadinessSummaryPath,
        $script:LocalAdminReportPath,
        $script:FirewallPreviewReportPath,
        $script:CertificateReportPath,
        $script:ReportPath,
        $script:OperatorSummaryPath,
        $script:RebootResumeScriptPath
    )) {
        if ($file -and (Test-Path -LiteralPath $file)) {
            Copy-Item -LiteralPath $file -Destination $dest -Force -ErrorAction SilentlyContinue
        }
    }
    if ($script:BackupPath -and (Test-Path -LiteralPath $script:BackupPath)) {
        Copy-Item -LiteralPath $script:BackupPath -Destination (Join-Path $dest 'BackupPackage') -Recurse -Force -ErrorAction SilentlyContinue
    }
    $script:UsbExportDestination = $dest
    Write-Host "Reports/backups exported to: $dest" -ForegroundColor Green
}

function Invoke-EndOfRunReportActions {
    if ($NoReportPrompts) { return }

    if ($OpenReportsAtEnd -or (Read-StigYesNo -Prompt 'Open the report folder now?' -DefaultYes $true)) {
        try { Invoke-Item -LiteralPath $ReportRoot } catch { Write-Warning "Could not open report folder: $($_.Exception.Message)" }
    }

    if ($UsbExportPath) {
        Copy-StigRunArtifactsToUsb -DestinationRoot $UsbExportPath
    }
    elseif ($PromptUsbExport -or (Read-StigYesNo -Prompt 'Copy reports and rollback package to a USB/removable drive or another folder?' -DefaultYes $false)) {
        Copy-StigRunArtifactsToUsb -DestinationRoot $UsbExportPath
    }
}
#endregion Reporting Helpers

#region Backup
function Export-StigBackup {
    param([Parameter(Mandatory)][string]$RootPath)
    Write-Section 'Exporting pre-change backups and rollback package'
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $backupPath = Join-Path $RootPath "PreChange_$stamp"
    New-StigDirectory -Path $backupPath

    $seceditPath = Join-Path $backupPath 'secedit_export.inf'
    $auditTextPath = Join-Path $backupPath 'auditpol_before.txt'
    $auditCsvPath = Join-Path $backupPath 'auditpol_before.csv'
    $bcdPath = Join-Path $backupPath 'bcdedit_before.txt'
    $firewallPath = Join-Path $backupPath 'firewall_before.wfw'

    Invoke-NativeCommand -FilePath secedit.exe -ArgumentList @('/export', '/cfg', $seceditPath) -IgnoreExitCode | Out-Null
    Invoke-NativeCommand -FilePath auditpol.exe -ArgumentList @('/get', '/category:*') -IgnoreExitCode | Set-Content -Path $auditTextPath
    Invoke-NativeCommand -FilePath auditpol.exe -ArgumentList @('/backup', "/file:$auditCsvPath") -IgnoreExitCode | Out-Null
    Invoke-NativeCommand -FilePath bcdedit.exe -ArgumentList @('/enum', 'all') -IgnoreExitCode | Set-Content -Path $bcdPath
    Invoke-NativeCommand -FilePath netsh.exe -ArgumentList @('advfirewall', 'export', $firewallPath) -IgnoreExitCode | Out-Null

    foreach ($reg in @(
        @{ Name='HKLM_SOFTWARE_Policies'; Path='HKLM\SOFTWARE\Policies' },
        @{ Name='HKCU_SOFTWARE_Policies'; Path='HKCU\SOFTWARE\Policies' },
        @{ Name='HKLM_System_CurrentControlSet_Control'; Path='HKLM\SYSTEM\CurrentControlSet\Control' },
        @{ Name='HKLM_System_CurrentControlSet_Services'; Path='HKLM\SYSTEM\CurrentControlSet\Services' },
        @{ Name='HKLM_Software_Microsoft_Windows_CurrentVersion_Policies'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies' },
        @{ Name='HKLM_Software_Microsoft_WindowsNT_CurrentVersion_Winlogon'; Path='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' },
        @{ Name='HKLM_Software_Classes'; Path='HKLM\SOFTWARE\Classes' }
    )) {
        Invoke-NativeCommand -FilePath reg.exe -ArgumentList @('export', $reg.Path, (Join-Path $backupPath "$($reg.Name).reg"), '/y') -IgnoreExitCode | Out-Null
    }

    Get-BitLockerVolume -ErrorAction SilentlyContinue | Out-File -FilePath (Join-Path $backupPath 'bitlocker_before.txt') -Width 240
    Get-Service | Select-Object Name,DisplayName,Status,StartType | Export-Csv -Path (Join-Path $backupPath 'services_before.csv') -NoTypeInformation -Encoding UTF8
    Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue | Select-Object FeatureName,State | Export-Csv -Path (Join-Path $backupPath 'windows_optional_features_before.csv') -NoTypeInformation -Encoding UTF8
    Get-WindowsCapability -Online -ErrorAction SilentlyContinue | Select-Object Name,State | Export-Csv -Path (Join-Path $backupPath 'windows_capabilities_before.csv') -NoTypeInformation -Encoding UTF8
    Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name,Enabled,SID,LastLogon | Export-Csv -Path (Join-Path $backupPath 'local_users_before.csv') -NoTypeInformation -Encoding UTF8
    Get-LocalGroup -ErrorAction SilentlyContinue | ForEach-Object {
        $group = $_
        Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{ Group=$group.Name; Name=$_.Name; ObjectClass=$_.ObjectClass; SID=$_.SID }
        }
    } | Export-Csv -Path (Join-Path $backupPath 'local_group_members_before.csv') -NoTypeInformation -Encoding UTF8
    Get-NetFirewallRule -ErrorAction SilentlyContinue | Select-Object Name,DisplayName,Enabled,Direction,Action,Profile | Export-Csv -Path (Join-Path $backupPath 'firewall_rules_before.csv') -NoTypeInformation -Encoding UTF8
    Get-ComputerInfo -ErrorAction SilentlyContinue | Out-File -FilePath (Join-Path $backupPath 'computer_info_before.txt') -Width 240
    gpresult.exe /h (Join-Path $backupPath 'gpresult_before.html') /f 2>$null | Out-Null

    $rollbackPath = Join-Path $backupPath 'Rollback-STIG-Changes.ps1'
    $rollback = @'
<#
.SYNOPSIS
    Best-effort rollback package generated before Windows 11 STIG remediation.

.DESCRIPTION
    Run elevated. This restores exported registry hives/keys, audit policy backup,
    local security policy/user rights from secedit export, and Windows Firewall policy.
    It cannot automatically undo every stateful action, such as BitLocker enablement,
    Windows capability removal, account renames, or manual changes made after backup.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSCommandPath
Write-Host "Rollback root: $Root"

Get-ChildItem -Path $Root -Filter '*.reg' -File | ForEach-Object {
    Write-Host "Importing registry backup: $($_.Name)"
    & reg.exe import $_.FullName
}

$AuditBackup = Join-Path $Root 'auditpol_before.csv'
if (Test-Path -LiteralPath $AuditBackup) {
    Write-Host 'Restoring audit policy backup'
    & auditpol.exe /restore /file:$AuditBackup
}

$SeceditBackup = Join-Path $Root 'secedit_export.inf'
if (Test-Path -LiteralPath $SeceditBackup) {
    Write-Host 'Restoring local security policy and user rights from secedit export'
    $db = Join-Path $Root 'rollback.sdb'
    & secedit.exe /configure /db $db /cfg $SeceditBackup /areas SECURITYPOLICY USER_RIGHTS
}

$FirewallBackup = Join-Path $Root 'firewall_before.wfw'
if (Test-Path -LiteralPath $FirewallBackup) {
    Write-Host 'Restoring Windows Firewall policy'
    & netsh.exe advfirewall import $FirewallBackup
}

$ServicesCsv = Join-Path $Root 'services_before.csv'
if (Test-Path -LiteralPath $ServicesCsv) {
    Import-Csv -LiteralPath $ServicesCsv | ForEach-Object {
        try {
            if ($_.StartType -and $_.StartType -ne 'Disabled') { Set-Service -Name $_.Name -StartupType $_.StartType -ErrorAction SilentlyContinue }
            elseif ($_.StartType -eq 'Disabled') { Set-Service -Name $_.Name -StartupType Disabled -ErrorAction SilentlyContinue }
        } catch { }
    }
}

Write-Warning 'Review bitlocker_before.txt, local_users_before.csv, local_group_members_before.csv, optional features, and capabilities before manually reverting those items.'
Write-Warning 'Reboot after rollback if registry, security policy, VBS, firewall, or service state was restored.'
'@
    Set-Content -Path $rollbackPath -Value $rollback -Encoding UTF8
    $script:RollbackScriptPath = $rollbackPath

    Write-Host "Backup path: $backupPath" -ForegroundColor Green
    Write-Host "Rollback script: $rollbackPath" -ForegroundColor Green
    return $backupPath
}
#endregion Backup

#region SCAP/XCCDF XML Import & OVAL Interpretation
function Get-LocalChild {
    param(
        [Parameter(Mandatory)][System.Xml.XmlNode]$Node,
        [Parameter(Mandatory)][string]$LocalName
    )
    foreach ($child in $Node.ChildNodes) {
        if ($child.LocalName -eq $LocalName) { return $child }
    }
    return $null
}

function Get-ChildText {
    param(
        [Parameter(Mandatory)][System.Xml.XmlNode]$Node,
        [Parameter(Mandatory)][string]$LocalName
    )
    $child = Get-LocalChild -Node $Node -LocalName $LocalName
    if ($child) { return [System.Net.WebUtility]::HtmlDecode($child.InnerText) }
    return $null
}

function Get-NodeAttribute {
    param(
        [Parameter(Mandatory)][System.Xml.XmlNode]$Node,
        [Parameter(Mandatory)][string]$Name
    )
    if ($Node.Attributes[$Name]) { return $Node.Attributes[$Name].Value }
    return $null
}

function Get-ScapBenchmarkVersionFromFile {
    param([Parameter(Mandatory)][string]$Path)

    try {
        [xml]$xml = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        $benchmark = $xml.SelectSingleNode("//*[local-name()='Benchmark']")
        if (-not $benchmark) { return [pscustomobject]@{ Version=[version]'0.0.0.0'; VersionText='0.0.0.0'; ReleaseDate=$null } }
        $versionText = Get-ChildText -Node $benchmark -LocalName 'version'
        $releaseInfo = $null
        $plainRelease = $benchmark.SelectSingleNode("./*[local-name()='plain-text' and @id='release-info']")
        if ($plainRelease) { $releaseInfo = $plainRelease.InnerText }

        $cleanVersionText = if ($versionText) { ($versionText -replace '[^0-9\.]', '') } else { '0.0.0.0' }
        if ([string]::IsNullOrWhiteSpace($cleanVersionText)) { $cleanVersionText = '0.0.0.0' }
        while (($cleanVersionText.Split('.')).Count -lt 2) { $cleanVersionText += '.0' }
        $parsedVersion = [version]$cleanVersionText

        $releaseDate = $null
        if ($releaseInfo -match '(?<date>20\d{2}-\d{2}-\d{2})') {
            $releaseDate = [datetime]$Matches.date
        }
        elseif ($benchmark.SelectSingleNode("./*[local-name()='status']") -and (Get-NodeAttribute -Node $benchmark.SelectSingleNode("./*[local-name()='status']") -Name 'date')) {
            $releaseDate = [datetime](Get-NodeAttribute -Node $benchmark.SelectSingleNode("./*[local-name()='status']") -Name 'date')
        }

        return [pscustomobject]@{ Version=$parsedVersion; VersionText=$versionText; ReleaseDate=$releaseDate }
    }
    catch {
        return [pscustomobject]@{ Version=[version]'0.0.0.0'; VersionText='Unreadable'; ReleaseDate=$null }
    }
}

function Resolve-ScapXmlPath {
    if ($ScapXmlPath) {
        if (-not (Test-Path -LiteralPath $ScapXmlPath)) { throw "SCAP XML not found: $ScapXmlPath" }
        $resolved = (Resolve-Path -LiteralPath $ScapXmlPath).Path
        $info = Get-ScapBenchmarkVersionFromFile -Path $resolved
        Write-Host "Using supplied SCAP XML: $resolved" -ForegroundColor Green
        Write-Host "Supplied benchmark version: $($info.VersionText)" -ForegroundColor Green
        return $resolved
    }

    $searchRoots = New-Object System.Collections.Generic.List[string]
    foreach ($root in @($PSScriptRoot, (Get-Location).Path, (Join-Path $env:ProgramData 'PowerSTIG'), (Join-Path $env:ProgramData 'PowerSTIG\SCAP'))) {
        if ($root -and (Test-Path -LiteralPath $root) -and -not $searchRoots.Contains($root)) { $searchRoots.Add($root) | Out-Null }
    }

    $candidates = foreach ($root in $searchRoots) {
        Get-ChildItem -Path $root -Filter 'U_MS_Windows_11*_STIG_SCAP*.xml' -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $info = Get-ScapBenchmarkVersionFromFile -Path $_.FullName
            [pscustomobject]@{ File=$_; Version=$info.Version; VersionText=$info.VersionText; ReleaseDate=$info.ReleaseDate; LastWriteTime=$_.LastWriteTime }
        }
    }

    $latest = $candidates | Sort-Object Version, ReleaseDate, LastWriteTime -Descending | Select-Object -First 1
    if ($latest) {
        Write-Host "Auto-selected latest SCAP XML: $($latest.File.FullName)" -ForegroundColor Green
        Write-Host "Detected benchmark version: $($latest.VersionText)" -ForegroundColor Green
        return $latest.File.FullName
    }

    throw 'SCAP XML was not supplied. Pass -ScapXmlPath or place the latest U_MS_Windows_11*_STIG_SCAP*.xml file beside this script.'
}

function Test-ScapXmlSignature {
    <#
    .SYNOPSIS
        Verifies the embedded XML digital signature (XMLDSig) on a SCAP
        benchmark file, when present, including whether the signing
        certificate chains to a trusted root.

    .DESCRIPTION
        DISA's official SCAP benchmark exports are digitally signed inline
        using the W3C XMLDSig standard (a <Signature> element within the
        document) - a different mechanism from Authenticode, which doesn't
        apply to XML content. This is the only thing standing between an
        unsigned or tampered SCAP file placed beside this script and having
        its contents trusted to drive real registry/audit-policy changes.
    #>
    param([Parameter(Mandatory)][string]$Path)

    [xml]$xmlDoc = Get-Content -LiteralPath $Path -Raw
    $sigNode = $xmlDoc.GetElementsByTagName('Signature') |
        Where-Object { $_.NamespaceURI -eq 'http://www.w3.org/2000/09/xmldsig#' } |
        Select-Object -First 1

    if (-not $sigNode) {
        return [pscustomobject]@{ Signed = $false; Valid = $false; Message = 'No embedded XML digital signature found in this SCAP file.' }
    }

    try {
        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

        $signedXml = New-Object System.Security.Cryptography.Xml.SignedXml($xmlDoc)
        $signedXml.LoadXml($sigNode)

        $cert = $null
        foreach ($clause in $signedXml.KeyInfo) {
            if ($clause -is [System.Security.Cryptography.Xml.KeyInfoX509Data]) {
                $cert = $clause.Certificates | Select-Object -First 1
                break
            }
        }

        if (-not $signedXml.CheckSignature()) {
            return [pscustomobject]@{ Signed = $true; Valid = $false; Message = 'XML signature check failed - the document does not match its embedded signature.' }
        }

        if (-not $cert) {
            return [pscustomobject]@{ Signed = $true; Valid = $false; Message = 'Signature is cryptographically valid, but no certificate was found in KeyInfo to verify trust against.' }
        }

        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        if (-not $chain.Build($cert)) {
            $statuses = ($chain.ChainStatus | ForEach-Object { $_.StatusInformation.Trim() }) -join '; '
            return [pscustomobject]@{ Signed = $true; Valid = $false; Message = "Signature is valid, but the certificate chain does not validate: $statuses" }
        }

        return [pscustomobject]@{ Signed = $true; Valid = $true; Message = "Signature verified. Signer: $($cert.Subject)" }
    } catch {
        return [pscustomobject]@{ Signed = $true; Valid = $false; Message = "Error while verifying signature: $($_.Exception.Message)" }
    }
}

function Import-ScapContent {
    param([Parameter(Mandatory)][string]$Path)

    $script:LoadedScapXmlPath = $Path

    $sigResult = Test-ScapXmlSignature -Path $Path
    if ($sigResult.Valid) {
        Write-Host "SCAP XML signature: VERIFIED - $($sigResult.Message)" -ForegroundColor Green
    } elseif ($RequireSignedScap) {
        throw "SCAP XML failed signature verification and -RequireSignedScap was specified: $($sigResult.Message)"
    } elseif ($sigResult.Signed) {
        Write-Host "WARNING: SCAP XML has a signature that failed verification: $($sigResult.Message)" -ForegroundColor Red
        Write-Host "Proceeding without -RequireSignedScap, but treat this file as unverified." -ForegroundColor Red
    } else {
        Write-Host "WARNING: SCAP XML is not digitally signed. Proceeding, but this file's origin/integrity is unverified." -ForegroundColor Yellow
    }

    Write-Section "Loading SCAP XML: $Path"
    [xml]$xml = Get-Content -LiteralPath $Path -Raw
    $benchmark = $xml.SelectSingleNode("//*[local-name()='Benchmark']")
    if (-not $benchmark) { throw 'No XCCDF Benchmark node was found in the SCAP XML.' }

    $version = Get-ChildText -Node $benchmark -LocalName 'version'
    $frontMatter = Get-ChildText -Node $benchmark -LocalName 'front-matter'
    $releaseInfoNode = $benchmark.SelectSingleNode("./*[local-name()='plain-text' and @id='release-info']")
    $script:BenchmarkVersionText = $version
    $script:BenchmarkReleaseInfo = if ($releaseInfoNode) { $releaseInfoNode.InnerText } else { $null }
    Write-Host "Benchmark version: $version" -ForegroundColor Green
    if ($frontMatter) {
        ($frontMatter -split "`r?`n") | Where-Object { $_ -match 'Total Rules|Automated Rules|Manual rules|SCAP Benchmark Version|Timestamp' } | ForEach-Object { Write-Host $_ }
    }

    foreach ($definition in $xml.SelectNodes("//*[local-name()='oval_definitions']/*[local-name()='definitions']/*[local-name()='definition']")) {
        $id = Get-NodeAttribute -Node $definition -Name 'id'
        if ($id) { $script:Defs[$id] = $definition }
    }
    foreach ($test in $xml.SelectNodes("//*[local-name()='oval_definitions']/*[local-name()='tests']/*")) {
        $id = Get-NodeAttribute -Node $test -Name 'id'
        if ($id) { $script:Tests[$id] = $test }
    }
    foreach ($object in $xml.SelectNodes("//*[local-name()='oval_definitions']/*[local-name()='objects']/*")) {
        $id = Get-NodeAttribute -Node $object -Name 'id'
        if ($id) { $script:Objects[$id] = $object }
    }
    foreach ($state in $xml.SelectNodes("//*[local-name()='oval_definitions']/*[local-name()='states']/*")) {
        $id = Get-NodeAttribute -Node $state -Name 'id'
        if ($id) { $script:States[$id] = $state }
    }

    $rules = New-Object System.Collections.Generic.List[object]
    foreach ($group in $benchmark.SelectNodes(".//*[local-name()='Group']")) {
        $groupId = Get-NodeAttribute -Node $group -Name 'id'
        foreach ($rule in $group.SelectNodes("./*[local-name()='Rule']")) {
            $defIds = New-Object System.Collections.Generic.List[string]
            $hasManual = $false
            foreach ($check in $rule.SelectNodes("./*[local-name()='check']")) {
                $system = Get-NodeAttribute -Node $check -Name 'system'
                $selector = Get-NodeAttribute -Node $check -Name 'selector'
                $ref = $check.SelectSingleNode("./*[local-name()='check-content-ref']")
                if ($system -eq 'http://oval.mitre.org/XMLSchema/oval-definitions-5' -and $ref) {
                    $name = Get-NodeAttribute -Node $ref -Name 'name'
                    if ($name -and -not $defIds.Contains($name)) { $defIds.Add($name) | Out-Null }
                }
                if ($system -eq 'http://scap.nist.gov/schema/ocil/2' -and $selector -eq 'manual') { $hasManual = $true }
            }

            $rules.Add([pscustomobject]@{
                GroupId          = $groupId
                RuleXmlId        = Get-NodeAttribute -Node $rule -Name 'id'
                Version          = Get-ChildText -Node $rule -LocalName 'version'
                Severity         = Get-NodeAttribute -Node $rule -Name 'severity'
                Title            = Get-ChildText -Node $rule -LocalName 'title'
                AutomatedDefIds  = @($defIds.ToArray())
                HasAutomatedOval = ($defIds.Count -gt 0)
                HasManualCheck   = $hasManual
            }) | Out-Null
        }
    }

    $script:RuleInventory = @($rules.ToArray())
    Write-Host "Rules loaded: $($script:RuleInventory.Count)" -ForegroundColor Green
    Write-Host "Rules with OVAL automation: $(($script:RuleInventory | Where-Object HasAutomatedOval).Count)" -ForegroundColor Green
    Write-Host "Manual-only rules: $(($script:RuleInventory | Where-Object { -not $_.HasAutomatedOval }).Count)" -ForegroundColor Yellow
}

function Get-OvalDefinitionInfo {
    param(
        [Parameter(Mandatory)][string]$DefinitionId,
        [hashtable]$Visited = @{}
    )

    if ($Visited.ContainsKey($DefinitionId)) {
        return [pscustomobject]@{ TestRefs=@(); HasOr=$false; HasNegate=$false; MissingDefinition=$false }
    }
    $Visited[$DefinitionId] = $true

    if (-not $script:Defs.ContainsKey($DefinitionId)) {
        return [pscustomobject]@{ TestRefs=@(); HasOr=$false; HasNegate=$false; MissingDefinition=$true }
    }

    $definition = $script:Defs[$DefinitionId]
    $refs = New-Object System.Collections.Generic.List[string]
    $hasOr = $false
    $hasNegate = $false
    $missing = $false

    foreach ($criteria in $definition.SelectNodes(".//*[local-name()='criteria']")) {
        $operator = Get-NodeAttribute -Node $criteria -Name 'operator'
        if ($operator -eq 'OR') { $hasOr = $true }
    }

    foreach ($criterion in $definition.SelectNodes(".//*[local-name()='criterion']")) {
        $testRef = Get-NodeAttribute -Node $criterion -Name 'test_ref'
        $negate = Get-NodeAttribute -Node $criterion -Name 'negate'
        if ($negate -eq 'true') { $hasNegate = $true }
        if ($testRef -and -not $refs.Contains($testRef)) { $refs.Add($testRef) | Out-Null }
    }

    foreach ($extend in $definition.SelectNodes(".//*[local-name()='extend_definition']")) {
        $extendedId = Get-NodeAttribute -Node $extend -Name 'definition_ref'
        if ($extendedId) {
            $nested = Get-OvalDefinitionInfo -DefinitionId $extendedId -Visited $Visited
            foreach ($testRef in $nested.TestRefs) {
                if (-not $refs.Contains($testRef)) { $refs.Add($testRef) | Out-Null }
            }
            if ($nested.HasOr) { $hasOr = $true }
            if ($nested.HasNegate) { $hasNegate = $true }
            if ($nested.MissingDefinition) { $missing = $true }
        }
    }

    return [pscustomobject]@{
        TestRefs          = @($refs.ToArray())
        HasOr             = $hasOr
        HasNegate         = $hasNegate
        MissingDefinition = $missing
    }
}

function Get-RuleOvalInfo {
    param([Parameter(Mandatory)][object]$Rule)
    $refs = New-Object System.Collections.Generic.List[string]
    $hasOr = $false
    $hasNegate = $false
    $missing = $false
    foreach ($defId in $Rule.AutomatedDefIds) {
        $info = Get-OvalDefinitionInfo -DefinitionId $defId
        foreach ($ref in $info.TestRefs) { if (-not $refs.Contains($ref)) { $refs.Add($ref) | Out-Null } }
        if ($info.HasOr) { $hasOr = $true }
        if ($info.HasNegate) { $hasNegate = $true }
        if ($info.MissingDefinition) { $missing = $true }
    }

    $types = New-Object System.Collections.Generic.List[string]
    foreach ($testRef in $refs) {
        if ($script:Tests.ContainsKey($testRef)) {
            $type = $script:Tests[$testRef].LocalName
            if (-not $types.Contains($type)) { $types.Add($type) | Out-Null }
        }
    }

    [pscustomobject]@{
        TestRefs          = @($refs.ToArray())
        TestTypes         = @($types.ToArray())
        HasOr             = $hasOr
        HasNegate         = $hasNegate
        MissingDefinition = $missing
    }
}

function Convert-OvalValueForRegistry {
    param(
        [Parameter(Mandatory)][System.Xml.XmlNode]$ValueNode
    )
    $text = $ValueNode.InnerText
    $datatype = Get-NodeAttribute -Node $ValueNode -Name 'datatype'
    $operation = Get-NodeAttribute -Node $ValueNode -Name 'operation'
    if (-not $operation) { $operation = 'equals' }
    if (-not $datatype) { $datatype = 'string' }

    if ($operation -notin @('equals', 'case insensitive equals', 'greater than or equal', 'less than or equal', 'greater than')) { return $null }
    if ($datatype -notin @('int', 'string')) { return $null }

    $value = $text
    if ($datatype -eq 'int') {
        try {
            [int]$intValue = [int]$text
            if ($operation -eq 'greater than') { $intValue++ }
            $value = $intValue
        }
        catch { return $null }
    }

    [pscustomobject]@{ DataType=$datatype; Operation=$operation; Value=$value }
}
#endregion SCAP/XCCDF XML Import & OVAL Interpretation

#region SCAP-Driven Remediation
function Get-ScapDrivenRegistryActions {
    $actions = New-Object System.Collections.Generic.List[object]

    foreach ($rule in $script:RuleInventory) {
        if (-not (Test-StigRuleTargeted -Rule $rule)) { continue }
        if (-not $rule.HasAutomatedOval) { continue }
        $ruleInfo = Get-RuleOvalInfo -Rule $rule
        if (($ruleInfo.HasOr -or $ruleInfo.HasNegate) -and -not $AllowComplexOvalRegistry) { continue }

        foreach ($testRef in $ruleInfo.TestRefs) {
            if (-not $script:Tests.ContainsKey($testRef)) { continue }
            $test = $script:Tests[$testRef]
            if ($test.LocalName -ne 'registry_test') { continue }

            $objectNode = Get-LocalChild -Node $test -LocalName 'object'
            if (-not $objectNode) { continue }
            $objectRef = Get-NodeAttribute -Node $objectNode -Name 'object_ref'
            if (-not $objectRef -or -not $script:Objects.ContainsKey($objectRef)) { continue }
            $object = $script:Objects[$objectRef]

            $hiveNode = Get-LocalChild -Node $object -LocalName 'hive'
            $keyNode = Get-LocalChild -Node $object -LocalName 'key'
            $nameNode = Get-LocalChild -Node $object -LocalName 'name'
            if (-not $hiveNode -or -not $keyNode -or -not $nameNode) { continue }
            if ((Get-NodeAttribute -Node $hiveNode -Name 'var_ref') -or (Get-NodeAttribute -Node $keyNode -Name 'var_ref') -or (Get-NodeAttribute -Node $nameNode -Name 'var_ref')) { continue }
            $objectHasUnsupportedOperation = $false
            foreach ($node in @($hiveNode, $keyNode, $nameNode)) {
                $op = Get-NodeAttribute -Node $node -Name 'operation'
                if ($op -and $op -notin @('equals', 'case insensitive equals')) { $objectHasUnsupportedOperation = $true }
            }
            if ($objectHasUnsupportedOperation) { continue }

            $hive = $hiveNode.InnerText
            $key = $keyNode.InnerText
            $name = $nameNode.InnerText
            if (-not (Test-SafeRegistryTarget -Hive $hive -Key $key -Name $name)) { continue }

            $stateNodes = $test.SelectNodes("./*[local-name()='state']")
            foreach ($stateNode in $stateNodes) {
                $stateRef = Get-NodeAttribute -Node $stateNode -Name 'state_ref'
                if (-not $stateRef -or -not $script:States.ContainsKey($stateRef)) { continue }
                $state = $script:States[$stateRef]
                $valueNode = Get-LocalChild -Node $state -LocalName 'value'
                if (-not $valueNode) { continue }
                $converted = Convert-OvalValueForRegistry -ValueNode $valueNode
                if (-not $converted) { continue }

                $registryType = Convert-OvalDataTypeToRegistryType -DataType $converted.DataType -Value $converted.Value -Key $key -Name $name
                $actions.Add([pscustomobject]@{
                    RuleId     = $rule.Version
                    Title      = $rule.Title
                    Hive       = $hive
                    Key        = $key
                    Name       = $name
                    Type       = $registryType
                    Value      = $converted.Value
                    Operation  = $converted.Operation
                    SourceTest = $testRef
                    Complex    = ($ruleInfo.HasOr -or $ruleInfo.HasNegate)
                }) | Out-Null
            }
        }
    }

    return @($actions.ToArray())
}

function Invoke-ScapDrivenRegistryRemediation {
    if ($SkipScapDrivenRegistry) { return }
    Write-Section 'Applying SCAP-driven registry remediations from XML'

    $actions = Get-ScapDrivenRegistryActions
    $conflicts = @{}
    $grouped = $actions | Group-Object -Property Hive,Key,Name
    foreach ($group in $grouped) {
        $distinctValues = @($group.Group | ForEach-Object { [string]$_.Value } | Select-Object -Unique)
        if ($distinctValues.Count -gt 1) {
            $sample = $group.Group | Select-Object -First 1
            $conflicts[$group.Name] = $true
            Add-OutstandingItem "Skipped conflicting SCAP registry target $($sample.Hive)\$($sample.Key) :: $($sample.Name). Values found: $($distinctValues -join ', ')."
        }
    }

    $applied = 0
    foreach ($action in $actions) {
        $keyName = "$($action.Hive), $($action.Key), $($action.Name)"
        if ($conflicts.ContainsKey($keyName)) { continue }

        $providerPath = Convert-RegistryPathFromOval -Hive $action.Hive -Key $action.Key
        if (-not $providerPath) { continue }

        try {
            if ($providerPath -like 'Registry::HKEY_CURRENT_USER*') {
                $subKey = $action.Key
                Set-PerUserRegistryValue -SubKey $subKey -Name $action.Name -Type $action.Type -Value $action.Value
            }
            else {
                Set-StigRegistryValue -Path $providerPath -Name $action.Name -Type $action.Type -Value $action.Value
            }
            $applied++
        }
        catch {
            Add-OutstandingItem "Failed SCAP registry remediation for $($action.RuleId) $($action.Hive)\$($action.Key)\$($action.Name): $($_.Exception.Message)"
        }
    }

    Write-Host "SCAP-driven registry actions applied: $applied" -ForegroundColor Green
}

function Get-ScapAuditActions {
    $auditNameMap = @{
        credential_validation          = 'Credential Validation'
        security_group_management     = 'Security Group Management'
        user_account_management       = 'User Account Management'
        pnp_activity                  = 'Plug and Play Events'
        process_creation              = 'Process Creation'
        group_membership              = 'Group Membership'
        logoff                        = 'Logoff'
        logon                         = 'Logon'
        special_logon                 = 'Special Logon'
        other_logon_logoff_events     = 'Other Logon/Logoff Events'
        account_lockout               = 'Account Lockout'
        file_share                    = 'File Share'
        detailed_file_share           = 'Detailed File Share'
        file_system                   = 'File System'
        handle_manipulation           = 'Handle Manipulation'
        registry                      = 'Registry'
        other_object_access_events    = 'Other Object Access Events'
        removable_storage             = 'Removable Storage'
        audit_policy_change           = 'Audit Policy Change'
        authentication_policy_change  = 'Authentication Policy Change'
        authorization_policy_change   = 'Authorization Policy Change'
        other_policy_change_events    = 'Other Policy Change Events'
        mpssvc_rule_level_policy_change = 'MPSSVC Rule-Level Policy Change'
        sensitive_privilege_use       = 'Sensitive Privilege Use'
        ipsec_driver                  = 'IPsec Driver'
        other_system_events           = 'Other System Events'
        security_state_change         = 'Security State Change'
        security_system_extension     = 'Security System Extension'
        system_integrity              = 'System Integrity'
    }

    $desired = @{}
    foreach ($rule in $script:RuleInventory) {
        if (-not (Test-StigRuleTargeted -Rule $rule)) { continue }
        if (-not $rule.HasAutomatedOval) { continue }
        $ruleInfo = Get-RuleOvalInfo -Rule $rule
        foreach ($testRef in $ruleInfo.TestRefs) {
            if (-not $script:Tests.ContainsKey($testRef)) { continue }
            $test = $script:Tests[$testRef]
            if ($test.LocalName -ne 'auditeventpolicysubcategories_test') { continue }
            foreach ($stateNode in $test.SelectNodes("./*[local-name()='state']")) {
                $stateRef = Get-NodeAttribute -Node $stateNode -Name 'state_ref'
                if (-not $stateRef -or -not $script:States.ContainsKey($stateRef)) { continue }
                $state = $script:States[$stateRef]
                foreach ($child in $state.ChildNodes) {
                    if (-not $auditNameMap.ContainsKey($child.LocalName)) { continue }
                    $subcategory = $auditNameMap[$child.LocalName]
                    if (-not $desired.ContainsKey($subcategory)) { $desired[$subcategory] = [pscustomobject]@{ Success=$false; Failure=$false } }
                    switch ($child.InnerText) {
                        'AUDIT_SUCCESS'         { $desired[$subcategory].Success = $true }
                        'AUDIT_FAILURE'         { $desired[$subcategory].Failure = $true }
                        'AUDIT_SUCCESS_FAILURE' { $desired[$subcategory].Success = $true; $desired[$subcategory].Failure = $true }
                    }
                }
            }
        }
    }
    return $desired
}

function Invoke-ScapDrivenAuditPolicy {
    Write-Section 'Applying audit policy from SCAP XML'
    $desired = Get-ScapAuditActions
    foreach ($subcategory in $desired.Keys) {
        try { Set-AuditPolicy -Subcategory $subcategory -Success $desired[$subcategory].Success -Failure $desired[$subcategory].Failure }
        catch { Add-OutstandingItem "Failed to set audit policy '$subcategory': $($_.Exception.Message)" }
    }
    Write-Host "Audit subcategories targeted: $($desired.Keys.Count)" -ForegroundColor Green
}
#endregion SCAP-Driven Remediation

#region PowerSTIG / Local Policy / Hard-Coded Remediation
function Invoke-PowerStigBaseline {
    if ($SkipPowerSTIG) { return }
    Write-Section 'Applying PowerSTIG DSC baseline when available'

    # DSC push mode requires WinRM - enable it if not already running
    try {
        Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction Stop | Out-Null
        if (-not (Get-NetFirewallRule -Name 'Allow-WSMan-AllProfiles' -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -Name 'Allow-WSMan-AllProfiles' -DisplayName 'Allow WS-Man Inbound (All Profiles)' `
                -Protocol TCP -LocalPort 5985 -Action Allow -Profile Any | Out-Null
        }
        Test-WSMan -ComputerName localhost -ErrorAction Stop | Out-Null
    }
    catch { Add-OutstandingItem "WinRM setup for DSC push failed: $($_.Exception.Message)" }

    $psStigModule = Get-Module -ListAvailable -Name PowerSTIG | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $psStigModule) {
        try {
            Install-PackageProvider -Name NuGet -Force -ErrorAction SilentlyContinue | Out-Null
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
            Install-Module -Name PowerSTIG -Scope AllUsers -Force -ErrorAction Stop
        }
        catch {
            Add-OutstandingItem "PowerSTIG could not be installed. Manual/SCAP-driven remediations continued. $($_.Exception.Message)"
        }
        $psStigModule = Get-Module -ListAvailable -Name PowerSTIG | Sort-Object Version -Descending | Select-Object -First 1
    }

    if (-not $psStigModule) { return }
    Import-Module PowerSTIG -ErrorAction Stop

    foreach ($required in $psStigModule.RequiredModules) {
        if (-not (Get-Module -ListAvailable -Name $required.Name)) {
            try { Install-Module -Name $required.Name -Scope AllUsers -Force -ErrorAction Stop }
            catch { Add-OutstandingItem "Failed to install PowerSTIG dependency $($required.Name): $($_.Exception.Message)" }
        }
    }

    if ($OrgSettingsPath) {
        if (-not (Test-Path -LiteralPath $OrgSettingsPath)) { throw "Specified OrgSettingsPath '$OrgSettingsPath' was not found." }
        $orgDefault = (Resolve-Path -LiteralPath $OrgSettingsPath).Path
    }
    else {
        $stigDataRoot = Join-Path $psStigModule.ModuleBase 'StigData\Processed'
        $candidateFiles = Get-ChildItem -Path $stigDataRoot -Filter 'WindowsClient-11-*.org.default.xml' -ErrorAction SilentlyContinue | ForEach-Object {
            $m = [regex]::Match($_.Name, 'WindowsClient-11-(?<ver>[0-9\.]+)\.org\.default\.xml', 'IgnoreCase')
            [pscustomobject]@{ File=$_; Version=if ($m.Success) { [version]$m.Groups['ver'].Value } else { [version]'0.0' } }
        } | Sort-Object Version -Descending
        if (-not $candidateFiles) {
            Add-OutstandingItem "PowerSTIG is installed, but no WindowsClient-11-*.org.default.xml was found under '$stigDataRoot'."
            return
        }
        $orgDefault = $candidateFiles[0].File.FullName
    }

    $stigVersion = '2.2'
    $m2 = [regex]::Match((Split-Path -Leaf $orgDefault), 'WindowsClient-11-(?<ver>[0-9\.]+)\.org\.default\.xml', 'IgnoreCase')
    if ($m2.Success) { $stigVersion = $m2.Groups['ver'].Value }

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
        param([Parameter(Mandatory)][string]$OrgSettings, [Parameter(Mandatory)][string]$StigVersion)
        Import-DscResource -ModuleName PowerSTIG
        Node 'localhost' {
            WindowsClient STIGBaseline {
                OsVersion   = '11'
                StigVersion = $StigVersion
                OrgSettings = $OrgSettings
            }
        }
    }

    $lcmPath = Join-Path $env:ProgramData 'PowerSTIG\LCM'
    $mofPath = Join-Path $env:ProgramData 'PowerSTIG\Mof'
    New-StigDirectory -Path $lcmPath
    New-StigDirectory -Path $mofPath
    LCM_PushConfig -OutputPath $lcmPath
    Set-DscLocalConfigurationManager -Path $lcmPath -Verbose -Force | Out-Null
    Win11_STIG_Baseline -OrgSettings $orgDefault -StigVersion $stigVersion -OutputPath $mofPath
    Start-DscConfiguration -Path $mofPath -Wait -Verbose -Force
}

function Invoke-LocalSecurityPolicyRemediation {
    Write-Section 'Applying local security policy and user rights'
    $domainContext = Get-DomainContext

    $admins = 'S-1-5-32-544'
    $users = 'S-1-5-32-545'
    $guests = 'S-1-5-32-546'
    $rdpUsers = 'S-1-5-32-555'
    $localService = 'S-1-5-19'
    $networkService = 'S-1-5-20'
    $service = 'S-1-5-6'
    $localAccount = 'S-1-5-113'
    $everyone = 'S-1-1-0'

    $domainAdmins = $null
    $enterpriseAdmins = $null
    if ($domainContext.PartOfDomain -and $domainContext.DomainSid) {
        $domainAdmins = "$($domainContext.DomainSid)-512"
        $enterpriseAdmins = "$($domainContext.DomainSid)-519"
    }

    $denyDomainAndLocal = @($guests)
    if ($domainAdmins) { $denyDomainAndLocal += $domainAdmins }
    if ($enterpriseAdmins) { $denyDomainAndLocal += $enterpriseAdmins }
    if ($domainContext.PartOfDomain) { $denyDomainAndLocal += $localAccount }

    $denyDomainOnly = @()
    if ($domainAdmins) { $denyDomainOnly += $domainAdmins }
    if ($enterpriseAdmins) { $denyDomainOnly += $enterpriseAdmins }

    $privilegeRights = [ordered]@{
        SeTrustedCredManAccessPrivilege = @()
        SeNetworkLogonRight             = @($admins, $rdpUsers)
        SeTcbPrivilege                  = @()
        SeInteractiveLogonRight         = @($admins, $users)
        SeBackupPrivilege               = @($admins)
        SeSystemtimePrivilege           = @($admins, $localService)
        SeCreatePagefilePrivilege       = @($admins)
        SeCreateTokenPrivilege          = @()
        SeCreateGlobalPrivilege         = @($admins, $service, $localService, $networkService)
        SeCreatePermanentPrivilege      = @()
        SeCreateSymbolicLinkPrivilege   = @($admins)
        SeDebugPrivilege                = @($admins)
        SeDenyNetworkLogonRight         = @($denyDomainAndLocal)
        SeDenyBatchLogonRight           = @($denyDomainOnly)
        SeDenyServiceLogonRight         = @($denyDomainOnly)
        SeDenyInteractiveLogonRight     = @($denyDomainAndLocal)
        SeDenyRemoteInteractiveLogonRight = $(if ($UseEveryoneForDenyRdp) { @($everyone) } else { @($denyDomainAndLocal) })
        SeEnableDelegationPrivilege     = @()
        SeRemoteShutdownPrivilege       = @($admins)
        SeImpersonatePrivilege          = @($admins, $service, $localService, $networkService)
        SeLoadDriverPrivilege           = @($admins)
        SeLockMemoryPrivilege           = @()
        SeSecurityPrivilege             = @($admins)
        SeSystemEnvironmentPrivilege    = @($admins)
        SeManageVolumePrivilege         = @($admins)
        SeProfileSingleProcessPrivilege = @($admins)
        SeRestorePrivilege              = @($admins)
        SeTakeOwnershipPrivilege        = @($admins)
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
        ClearTextPassword     = 0
    }

    Invoke-StigSecurityTemplate -SystemAccess $systemAccess -PrivilegeRights $privilegeRights

    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue
    Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -and $_.PasswordNeverExpires } | ForEach-Object {
        try { Set-LocalUser -Name $_.Name -PasswordNeverExpires:$false } catch { Add-OutstandingItem "Unable to clear PasswordNeverExpires for local account $($_.Name): $($_.Exception.Message)" }
    }
}

function Invoke-HardCodedRegistryRemediation {
    Write-Section 'Applying STIG-specific registry remediations not safely inferred from OVAL'

    $regDword = @(
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE'; Name='UseAdvancedStartup'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE'; Name='UseTPMPIN'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE'; Name='UseTPMKeyPIN'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE'; Name='MinimumPIN'; Value=6 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'; Name='DisableExceptionChainValidation'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name='SMB1'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10'; Name='Start'; Value=4 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='DisableIPSourceRouting'; Value=2 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'; Name='DisableIPSourceRouting'; Value=2 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='EnableICMPRedirect'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'; Name='NoNameReleaseOnDemand'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest'; Name='UseLogonCredential'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'; Name='EveryoneIncludesAnonymous'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'; Name='NoLMHash'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictAnonymous'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictAnonymousSAM'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'; Name='LmCompatibilityLevel'; Value=5 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'; Name='SCENoApplyLegacyAuditPolicy'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name='NTLMMinClientSec'; Value=537395200 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name='NTLMMinServerSec'; Value=537395200 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name='allownullsessionfallback'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\pku2u'; Name='AllowOnlineID'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy'; Name='Enabled'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name='RequireSignOrSeal'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name='SealSecureChannel'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name='SignSecureChannel'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name='DisablePasswordChange'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name='MaximumPasswordAge'; Value=30 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name='RequireStrongKey'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP'; Name='LDAPClientIntegrity'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='FilterAdministratorToken'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorAdmin'; Value=2 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorUser'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableInstallerDetection'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableLUA'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableSecureUIAPaths'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableVirtualization'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='PromptOnSecureDesktop'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ValidateAdminCodeSignatures'; Value=0 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='InactivityTimeoutSecs'; Value=900 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name='ProcessCreationIncludeCmdLine_Enabled'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; Name='SupportedEncryptionTypes'; Value=2147483640 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'; Name='\\*\NETLOGON'; Value='RequireMutualAuthentication=1, RequireIntegrity=1' ; Type='String' }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'; Name='\\*\SYSVOL'; Value='RequireMutualAuthentication=1, RequireIntegrity=1' ; Type='String' }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Wintrust\Config'; Name='EnableCertPaddingCheck'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config'; Name='EnableCertPaddingCheck'; Value=1 }
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System\PINComplexity'; Name='MinimumPINLength'; Value=6 }    # V-253401
        @{ Path='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'; Name='EnableCopilot'; Value=0 }              # V-268317
    )

    foreach ($entry in $regDword) {
        $type = if ($entry.ContainsKey('Type')) { $entry.Type } else { 'DWord' }
        Set-StigRegistryValue -Path $entry.Path -Name $entry.Name -Type $type -Value $entry.Value
    }

    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'EccCurves' -Type MultiString -Value @('NistP384', 'NistP256')
    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'OutputDirectory' -Type String -Value $PowerShellTranscriptOutput
    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'ShellSmartScreenLevel' -Type String -Value 'Block'
    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'SCRemoveOption' -Type String -Value '1'
    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictRemoteSAM' -Type String -Value 'O:BAG:BAD:(A;;RC;;;BA)'

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
    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LegalNoticeText' -Type String -Value $legalNoticeText
    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LegalNoticeCaption' -Type String -Value $LegalNoticeCaption

    foreach ($runAsPath in @(
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\batfile\shell\runasuser',
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\cmdfile\shell\runasuser',
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\exefile\shell\runasuser',
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\mscfile\shell\runasuser'
    )) {
        Set-StigRegistryValue -Path $runAsPath -Name 'SuppressionPolicy' -Type DWord -Value 4096
    }

    try {
        Invoke-NativeCommand -FilePath bcdedit.exe -ArgumentList @('/set', '{current}', 'nx', 'OptOut') -IgnoreExitCode | Out-Null             # V-253283 DEP
        Invoke-NativeCommand -FilePath bcdedit.exe -ArgumentList @('/set', '{current}', 'hypervisorlaunchtype', 'Auto') -IgnoreExitCode | Out-Null
        Invoke-NativeCommand -FilePath bcdedit.exe -ArgumentList @('/set', '{current}', 'vsmlaunchtype', 'Auto') -IgnoreExitCode | Out-Null
        $script:RebootRequired = $true
    }
    catch { Add-OutstandingItem "Unable to update BCDEdit for VBS/DEP startup: $($_.Exception.Message)" }

    try { Invoke-NativeCommand -FilePath netsh.exe -ArgumentList @('interface', 'portproxy', 'reset') -IgnoreExitCode | Out-Null }
    catch { Add-OutstandingItem "Unable to reset netsh portproxy entries: $($_.Exception.Message)" }

    # Event log minimum sizes - V-253337 (Application), V-253338 (Security), V-253339 (System)
    # MaxSize is in bytes: 32 MB for Application/System, 1 GB for Security
    foreach ($evtLog in @('Application', 'System')) {
        Set-StigRegistryValue -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\$evtLog" -Name 'MaxSize' -Type DWord -Value 33554432
    }
    Set-StigRegistryValue -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security' -Name 'MaxSize' -Type DWord -Value 1073741824
}

function Invoke-PerUserRegistryRemediation {
    Write-Section 'Applying per-user registry remediations'
    Set-PerUserRegistryValue -SubKey 'SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableThirdPartySuggestions' -Type DWord -Value 1
    Set-PerUserRegistryValue -SubKey 'SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'NoToastApplicationNotificationOnLockScreen' -Type DWord -Value 1
    Set-PerUserRegistryValue -SubKey 'Software\Microsoft\BluetoothAuthenticationAgent' -Name 'AcceptIncomingRequests' -Type DWord -Value 1
    Set-PerUserRegistryValue -SubKey 'SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Type DWord -Value 0
}

function Invoke-FeatureAndServiceRemediation {
    Write-Section 'Disabling insecure optional features, capabilities, and services'
    Disable-StigOptionalFeature -FeatureName @(
        'MicrosoftWindowsPowerShellV2',
        'MicrosoftWindowsPowerShellV2Root',
        'SMB1Protocol',
        'SMB1Protocol-Client',
        'SMB1Protocol-Server',
        'IIS-WebServerRole',
        'IIS-WebServer',
        'IIS-FTPServer',
        'IIS-ManagementConsole'
    )
    Remove-StigWindowsCapability -NamePattern 'SNMP.Client*'
    Disable-StigService -Name 'seclogon'
    Disable-StigService -Name 'SNMP'
    Disable-StigService -Name 'SNMPTRAP'

    if ($DisableBluetoothRadio) {
        Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' } | ForEach-Object {
            Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
        }
        Disable-StigService -Name 'bthserv'
        Get-Service -Name 'BluetoothUserService*' -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Status -ne 'Stopped') { Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue }
            Set-Service -Name $_.Name -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-CertificateRemediation {
    Write-Section 'Checking DoD/ECA certificate requirements'
    Export-StigCertificateReport -OutputRoot $ReportRoot -Phase 'BeforeImport'
    foreach ($req in Get-StigCertificateRequirements) {
        Import-StigCertificateIfMissing -StorePath $req.StorePath -Thumbprint $req.Thumbprint -SubjectLike $req.SubjectLike
    }
    Export-StigCertificateReport -OutputRoot $ReportRoot -Phase 'AfterImport'
}

function Invoke-FirewallScopeRemediation {
    if (-not $ApplyAuthorizedFirewallScope) {
        Export-FirewallScopePreview -OutputRoot $ReportRoot | Out-Null
        Add-OutstandingItem 'WN11-00-000140 firewall inbound exceptions were not changed. Use -ApplyAuthorizedFirewallScope with -AuthorizedRemoteManagementHosts after confirming approved management IPs/subnets.'
        return
    }
    if (-not $AuthorizedRemoteManagementHosts -or $AuthorizedRemoteManagementHosts.Count -eq 0) {
        Export-FirewallScopePreview -OutputRoot $ReportRoot | Out-Null
        Add-OutstandingItem 'Firewall scope remediation requested, but -AuthorizedRemoteManagementHosts was empty.'
        return
    }

    Write-Section 'Previewing firewall inbound allow-rule scope changes'
    $previewPath = Export-FirewallScopePreview -OutputRoot $ReportRoot
    $rulesToChange = @(Import-Csv -LiteralPath $previewPath | Where-Object { $_.WillChange -eq 'True' })
    Write-Host "Inbound allow rules that may be changed: $($rulesToChange.Count)" -ForegroundColor Yellow
    Write-Host "Proposed remote addresses: $($AuthorizedRemoteManagementHosts -join ',')" -ForegroundColor Yellow

    if (-not $SkipFirewallPreview) {
        if (-not (Read-StigYesNo -Prompt 'Apply these firewall scope changes now?' -DefaultYes $false)) {
            Add-OutstandingItem "Firewall scope preview was generated but changes were not applied by operator choice. Preview: $previewPath"
            return
        }
    }

    Write-Section 'Restricting inbound allow rules to authorized remote management hosts'
    Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            Set-NetFirewallRule -Name $_.Name -RemoteAddress $AuthorizedRemoteManagementHosts -ErrorAction Stop
        }
        catch { Add-OutstandingItem "Failed to scope firewall rule '$($_.DisplayName)': $($_.Exception.Message)" }
    }
}
#endregion PowerSTIG / Local Policy / Hard-Coded Remediation

#region Rule Targeting & Assessment-Result Helpers
function New-RuleIdHashSet {
    return (New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase))
}

function Add-RuleIdToSet {
    param([Parameter(Mandatory)]$Set, [string]$Value)
    if (-not [string]::IsNullOrWhiteSpace($Value)) { [void]$Set.Add($Value.Trim()) }
}

function Get-CklVulnAttribute {
    param([Parameter(Mandatory)][System.Xml.XmlNode]$Vuln, [Parameter(Mandatory)][string]$AttributeName)
    foreach ($stigData in $Vuln.SelectNodes("./*[local-name()='STIG_DATA']")) {
        $attr = $stigData.SelectSingleNode("./*[local-name()='VULN_ATTRIBUTE']")
        $data = $stigData.SelectSingleNode("./*[local-name()='ATTRIBUTE_DATA']")
        if ($attr -and $data -and $attr.InnerText -eq $AttributeName) { return $data.InnerText }
    }
    return $null
}

function Test-StigRuleTargeted {
    param([Parameter(Mandatory)]$Rule)
    if (-not $RemediateOnlyFailedFindings) { return $true }
    if ($null -eq $script:TargetRuleIds) { return $false }
    foreach ($id in @($Rule.Version, $Rule.GroupId, $Rule.RuleXmlId) + @($Rule.AutomatedDefIds)) {
        if ($id -and $script:TargetRuleIds.Contains($id)) { return $true }
    }
    return $false
}

function Import-AssessmentResultTargeting {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { throw "Assessment result file not found: $Path" }

    Write-Section "Importing failed-finding targeting from assessment result: $Path"
    $resolvedPath = (Resolve-Path -LiteralPath $Path).Path
    $script:AssessmentFilterPath = $resolvedPath
    $failedIds = New-RuleIdHashSet
    $extension = [System.IO.Path]::GetExtension($resolvedPath).ToLowerInvariant()

    if ($extension -in @('.xml', '.ckl')) {
        [xml]$resultXml = Get-Content -LiteralPath $resolvedPath -Raw
        foreach ($vuln in $resultXml.SelectNodes("//*[local-name()='VULN']")) {
            $statusNode = $vuln.SelectSingleNode("./*[local-name()='STATUS']")
            $status = if ($statusNode) { $statusNode.InnerText.Trim() } else { '' }
            if ($status -match '^(Open|Fail|Failed)$') {
                foreach ($attr in @('Vuln_Num','Rule_ID','Rule_Ver')) {
                    Add-RuleIdToSet -Set $failedIds -Value (Get-CklVulnAttribute -Vuln $vuln -AttributeName $attr)
                }
            }
        }
        foreach ($ruleResult in $resultXml.SelectNodes("//*[local-name()='rule-result']")) {
            $resultNode = $ruleResult.SelectSingleNode("./*[local-name()='result']")
            $result = if ($resultNode) { $resultNode.InnerText.Trim() } else { '' }
            if ($result -match '^(fail|error|unknown)$') { Add-RuleIdToSet -Set $failedIds -Value (Get-NodeAttribute -Node $ruleResult -Name 'idref') }
        }
    }
    elseif ($extension -eq '.csv') {
        foreach ($row in (Import-Csv -LiteralPath $resolvedPath)) {
            $properties = @($row.PSObject.Properties.Name)
            $statusName = @('Status','Result','Finding Status','Assessment Status') | Where-Object { $properties -contains $_ } | Select-Object -First 1
            $status = if ($statusName) { [string]$row.$statusName } else { '' }
            if ($status -match '(?i)^(open|fail|failed|error|unknown)$') {
                foreach ($idName in @('Vuln ID','V-ID','Vuln_Num','Rule ID','Rule_ID','Rule_Ver','Rule Version','STIG ID','idref')) {
                    if ($properties -contains $idName) { Add-RuleIdToSet -Set $failedIds -Value ([string]$row.$idName) }
                }
            }
        }
    }
    else { throw "Unsupported assessment result format '$extension'. Supported: .ckl, .xml, .csv." }

    $targetSet = New-RuleIdHashSet
    foreach ($rule in $script:RuleInventory) {
        $matches = $false
        foreach ($id in @($rule.Version, $rule.GroupId, $rule.RuleXmlId) + @($rule.AutomatedDefIds)) {
            if ($id -and $failedIds.Contains($id)) { $matches = $true }
        }
        if ($matches) {
            foreach ($id in @($rule.Version, $rule.GroupId, $rule.RuleXmlId) + @($rule.AutomatedDefIds)) { Add-RuleIdToSet -Set $targetSet -Value $id }
        }
    }

    $script:TargetRuleIds = $targetSet
    $targetedRules = @($script:RuleInventory | Where-Object { Test-StigRuleTargeted -Rule $_ })
    Write-Host "Failed IDs imported: $($failedIds.Count)" -ForegroundColor Green
    Write-Host "Matching STIG rules targeted: $($targetedRules.Count)" -ForegroundColor Green
    if ($targetedRules.Count -eq 0) { throw 'Assessment result file was read, but no failed findings matched the loaded Windows 11 STIG XML rule inventory.' }
}
#endregion Rule Targeting & Assessment-Result Helpers

#region Validation, Coverage Reporting & Summary
function Get-StigRegistryValue {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

function Test-StigRegistryActionState {
    param([Parameter(Mandatory)]$Action)
    $providerPath = Convert-RegistryPathFromOval -Hive $Action.Hive -Key $Action.Key
    if (-not $providerPath) { return [pscustomobject]@{ Status='Review'; Detail="Unsupported hive $($Action.Hive)" } }

    $actual = Get-StigRegistryValue -Path $providerPath -Name $Action.Name
    if ($null -eq $actual) { return [pscustomobject]@{ Status='Fail'; Detail="Missing registry value $providerPath :: $($Action.Name); expected $($Action.Operation) $($Action.Value)" } }

    $expected = $Action.Value
    $actualForCompare = $actual
    if ($expected -is [int] -or $expected -is [long] -or ([string]$expected -match '^-?\d+$')) {
        try { $actualForCompare = [int64]$actual; $expected = [int64]$expected } catch { }
    }

    $pass = $false
    switch ($Action.Operation) {
        'equals'                  { $pass = ([string]$actualForCompare -eq [string]$expected) }
        'case insensitive equals' { $pass = ([string]$actualForCompare).ToLowerInvariant() -eq ([string]$expected).ToLowerInvariant() }
        'greater than or equal'   { try { $pass = ([int64]$actualForCompare -ge [int64]$expected) } catch { $pass = $false } }
        'less than or equal'      { try { $pass = ([int64]$actualForCompare -le [int64]$expected) } catch { $pass = $false } }
        'greater than'            { try { $pass = ([int64]$actualForCompare -gt [int64]$expected) } catch { $pass = $false } }
        default                   { return [pscustomobject]@{ Status='Review'; Detail="Unsupported registry comparison operation $($Action.Operation)" } }
    }

    if ($pass) { return [pscustomobject]@{ Status='Pass'; Detail="Confirmed $providerPath :: $($Action.Name) = $actual" } }
    return [pscustomobject]@{ Status='Fail'; Detail="Registry mismatch $providerPath :: $($Action.Name); actual '$actual', expected $($Action.Operation) '$($Action.Value)'" }
}

function Get-AuditPolicySubcategoryState {
    param([Parameter(Mandatory)][string]$Subcategory)
    try {
        $output = Invoke-NativeCommand -FilePath auditpol.exe -ArgumentList @('/get', "/subcategory:$Subcategory") -IgnoreExitCode
        $line = $output | Where-Object { $_ -match [regex]::Escape($Subcategory) } | Select-Object -Last 1
        $text = if ($line) { [string]$line } else { ($output -join ' ') }
        return [pscustomobject]@{ Success=($text -match 'Success'); Failure=($text -match 'Failure'); Raw=$text.Trim() }
    }
    catch { return [pscustomobject]@{ Success=$false; Failure=$false; Raw="Unable to query audit policy: $($_.Exception.Message)" } }
}

function Get-ScapAuditNameMap {
    return @{
        credential_validation='Credential Validation'; security_group_management='Security Group Management'; user_account_management='User Account Management'; pnp_activity='Plug and Play Events'; process_creation='Process Creation'; group_membership='Group Membership'; logoff='Logoff'; logon='Logon'; special_logon='Special Logon'; other_logon_logoff_events='Other Logon/Logoff Events'; account_lockout='Account Lockout'; file_share='File Share'; detailed_file_share='Detailed File Share'; file_system='File System'; handle_manipulation='Handle Manipulation'; registry='Registry'; other_object_access_events='Other Object Access Events'; removable_storage='Removable Storage'; audit_policy_change='Audit Policy Change'; authentication_policy_change='Authentication Policy Change'; authorization_policy_change='Authorization Policy Change'; other_policy_change_events='Other Policy Change Events'; mpssvc_rule_level_policy_change='MPSSVC Rule-Level Policy Change'; sensitive_privilege_use='Sensitive Privilege Use'; ipsec_driver='IPsec Driver'; other_system_events='Other System Events'; security_state_change='Security State Change'; security_system_extension='Security System Extension'; system_integrity='System Integrity'
    }
}

function Get-ScapAuditRuleActions {
    $auditNameMap = Get-ScapAuditNameMap
    $actions = New-Object System.Collections.Generic.List[object]
    foreach ($rule in $script:RuleInventory) {
        if (-not (Test-StigRuleTargeted -Rule $rule)) { continue }
        if (-not $rule.HasAutomatedOval) { continue }
        $ruleInfo = Get-RuleOvalInfo -Rule $rule
        foreach ($testRef in $ruleInfo.TestRefs) {
            if (-not $script:Tests.ContainsKey($testRef)) { continue }
            $test = $script:Tests[$testRef]
            if ($test.LocalName -ne 'auditeventpolicysubcategories_test') { continue }
            foreach ($stateNode in $test.SelectNodes("./*[local-name()='state']")) {
                $stateRef = Get-NodeAttribute -Node $stateNode -Name 'state_ref'
                if (-not $stateRef -or -not $script:States.ContainsKey($stateRef)) { continue }
                $state = $script:States[$stateRef]
                foreach ($child in $state.ChildNodes) {
                    if (-not $auditNameMap.ContainsKey($child.LocalName)) { continue }
                    $success = $false; $failure = $false
                    switch ($child.InnerText) {
                        'AUDIT_SUCCESS' { $success = $true }
                        'AUDIT_FAILURE' { $failure = $true }
                        'AUDIT_SUCCESS_FAILURE' { $success = $true; $failure = $true }
                    }
                    $actions.Add([pscustomobject]@{ RuleId=$rule.Version; Title=$rule.Title; Subcategory=$auditNameMap[$child.LocalName]; Success=$success; Failure=$failure; SourceTest=$testRef }) | Out-Null
                }
            }
        }
    }
    return @($actions.ToArray())
}

function Invoke-StigXmlValidation {
    param([Parameter(Mandatory)][ValidateSet('PreCheck','PostValidation')][string]$Phase, [Parameter(Mandatory)][string]$ReportPath, [Parameter(Mandatory)][string]$SummaryPath)

    Write-Section "$Phase against SCAP XML"
    $rows = New-Object System.Collections.Generic.List[object]
    $registryActions = @(Get-ScapDrivenRegistryActions)
    $auditActions = @(Get-ScapAuditRuleActions)
    $registryByRule = @{}
    $auditByRule = @{}
    if ($registryActions.Count -gt 0) { $registryByRule = $registryActions | Group-Object -Property RuleId -AsHashTable -AsString }
    if ($auditActions.Count -gt 0) { $auditByRule = $auditActions | Group-Object -Property RuleId -AsHashTable -AsString }

    foreach ($rule in $script:RuleInventory | Sort-Object Version) {
        $targeted = Test-StigRuleTargeted -Rule $rule
        if (-not $targeted) {
            $rows.Add([pscustomobject]@{ Phase=$Phase; RuleId=$rule.Version; Severity=$rule.Severity; Title=$rule.Title; Targeted=$false; EvaluationType='Assessment filter'; Status='Skipped'; Detail='Skipped because the rule was not failed in the imported assessment result.' }) | Out-Null
            continue
        }
        $ruleRowsBefore = $rows.Count
        if ($registryByRule.ContainsKey($rule.Version)) {
            $actionResults = foreach ($action in @($registryByRule[$rule.Version])) { Test-StigRegistryActionState -Action $action }
            $status = if (@($actionResults | Where-Object Status -eq 'Fail').Count -gt 0) { 'Fail' } elseif (@($actionResults | Where-Object Status -eq 'Review').Count -gt 0) { 'Review' } else { 'Pass' }
            $rows.Add([pscustomobject]@{ Phase=$Phase; RuleId=$rule.Version; Severity=$rule.Severity; Title=$rule.Title; Targeted=$true; EvaluationType='SCAP registry'; Status=$status; Detail=(@($actionResults | ForEach-Object { $_.Detail }) -join ' | ') }) | Out-Null
        }
        if ($auditByRule.ContainsKey($rule.Version)) {
            $auditResults = foreach ($action in @($auditByRule[$rule.Version])) {
                $actual = Get-AuditPolicySubcategoryState -Subcategory $action.Subcategory
                $pass = (($actual.Success -eq $action.Success) -and ($actual.Failure -eq $action.Failure))
                [pscustomobject]@{ Status=if ($pass) { 'Pass' } else { 'Fail' }; Detail="$($action.Subcategory): actual='$($actual.Raw)', expected Success=$($action.Success), Failure=$($action.Failure)" }
            }
            $status = if (@($auditResults | Where-Object Status -eq 'Fail').Count -gt 0) { 'Fail' } else { 'Pass' }
            $rows.Add([pscustomobject]@{ Phase=$Phase; RuleId=$rule.Version; Severity=$rule.Severity; Title=$rule.Title; Targeted=$true; EvaluationType='SCAP audit policy'; Status=$status; Detail=(@($auditResults | ForEach-Object { $_.Detail }) -join ' | ') }) | Out-Null
        }
        if ($rows.Count -eq $ruleRowsBefore) {
            $info = if ($rule.HasAutomatedOval) { Get-RuleOvalInfo -Rule $rule } else { $null }
            $evalType = if ($info) { ($info.TestTypes -join ';') } else { 'Manual/OCIL' }
            $rows.Add([pscustomobject]@{ Phase=$Phase; RuleId=$rule.Version; Severity=$rule.Severity; Title=$rule.Title; Targeted=$true; EvaluationType=$evalType; Status='Review'; Detail='No safe local XML-driven validation was implemented for this test type. Use SCC/CKL, manual check, or specialized report output.' }) | Out-Null
        }
    }

    $rows | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
    $summary = $rows | Group-Object -Property Status | Sort-Object Name | ForEach-Object { "$($_.Name): $($_.Count)" }
    $targetCount = @($script:RuleInventory | Where-Object { Test-StigRuleTargeted -Rule $_ }).Count
    $lines = @("$Phase summary", "Generated: $(Get-Date -Format o)", "SCAP XML: $script:LoadedScapXmlPath", "Assessment filter: $script:AssessmentFilterPath", "Total XML rules: $($script:RuleInventory.Count)", "Targeted rules: $targetCount", "Registry actions evaluated: $($registryActions.Count)", "Audit actions evaluated: $($auditActions.Count)", '', 'Result counts:') + $summary + @('', "Detailed CSV: $ReportPath")
    Set-Content -Path $SummaryPath -Value $lines -Encoding UTF8

    if ($Phase -eq 'PreCheck') { $script:PreCheckReportPath = $ReportPath; $script:PreCheckSummaryPath = $SummaryPath }
    else { $script:PostValidationReportPath = $ReportPath; $script:PostValidationSummaryPath = $SummaryPath }
    Write-Host "$Phase detailed report: $ReportPath" -ForegroundColor Green
    Write-Host "$Phase summary: $SummaryPath" -ForegroundColor Green
}

function Export-ScapCoverageReport {
    param([Parameter(Mandatory)][string]$Path)

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($rule in $script:RuleInventory) {
        $info = if ($rule.HasAutomatedOval) { Get-RuleOvalInfo -Rule $rule } else { $null }
        $testTypes = if ($info) { ($info.TestTypes -join ';') } else { '' }
        $coverage = 'Manual required'
        if ($rule.HasAutomatedOval) {
            if ($testTypes -match 'registry_test') { $coverage = 'PowerSTIG/manual + SCAP-driven registry candidate' }
            if ($testTypes -match 'auditeventpolicysubcategories_test') { $coverage = 'SCAP-driven audit policy' }
            if ($testTypes -match 'passwordpolicy_test|lockoutpolicy_test|accesstoken_test|user_sid55_test|sid_sid_test|user_test') { $coverage = 'Local security policy/account remediation' }
            if ($testTypes -match 'wmi57_test|service_test|shellcommand_test|cmdlet_test|file_test|fileeffectiverights53_test|ntuser_test|variable_test') { $coverage = 'Specialized remediation or validation/outstanding item' }
        }

        $rows.Add([pscustomobject]@{
            RuleId            = $rule.Version
            Severity          = $rule.Severity
            Title             = $rule.Title
            HasAutomatedOval  = $rule.HasAutomatedOval
            HasManualCheck    = $rule.HasManualCheck
            TargetedForRun    = (Test-StigRuleTargeted -Rule $rule)
            TestTypes         = $testTypes
            CoverageCategory  = $coverage
            ComplexOval       = if ($info) { ($info.HasOr -or $info.HasNegate) } else { $false }
        }) | Out-Null
    }

    $rows | Sort-Object RuleId | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    $script:CoverageReportPath = $Path
}

function Add-ManualOutstandingItemsFromInventory {
    foreach ($rule in $script:RuleInventory | Where-Object { -not $_.HasAutomatedOval }) {
        Add-OutstandingItem "$($rule.Version): manual validation/remediation required - $($rule.Title)"
    }

    Add-OutstandingItem 'Application allowlisting/AppLocker/WDAC must be designed and validated against the authorized software baseline before enabling deny-by-default.'
    Add-OutstandingItem 'Local Administrators, Backup Operators, Hyper-V/VM rights, unused accounts, and admin browser-use rules require authorized account lists and local mission review.'
    Add-OutstandingItem 'Edge, Defender Antivirus, firewall product, and any third-party security tools may require their own STIGs or separate administrative baselines.'
}

function Invoke-StigValidationSummary {
    Write-Section 'Writing validation and coverage summary'
    $summaryPath = Join-Path $ReportRoot ("Win11_STIG_Outstanding_{0:yyyyMMdd_HHmmss}.txt" -f (Get-Date))
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("Transcript: $($script:TranscriptPath)") | Out-Null
    $lines.Add("Backup path: $($script:BackupPath)") | Out-Null
    $lines.Add("Rollback script: $($script:RollbackScriptPath)") | Out-Null
    $lines.Add("Coverage report: $($script:CoverageReportPath)") | Out-Null
    $lines.Add("Pre-check report: $($script:PreCheckReportPath)") | Out-Null
    $lines.Add("Pre-check summary: $($script:PreCheckSummaryPath)") | Out-Null
    $lines.Add("Post-validation report: $($script:PostValidationReportPath)") | Out-Null
    $lines.Add("Post-validation summary: $($script:PostValidationSummaryPath)") | Out-Null
    $lines.Add("System readiness report: $($script:SystemReadinessReportPath)") | Out-Null
    $lines.Add("System readiness summary: $($script:SystemReadinessSummaryPath)") | Out-Null
    $lines.Add("Local admin report: $($script:LocalAdminReportPath)") | Out-Null
    $lines.Add("Firewall preview report: $($script:FirewallPreviewReportPath)") | Out-Null
    $lines.Add("Certificate report: $($script:CertificateReportPath)") | Out-Null
    $lines.Add("Operator summary: $($script:OperatorSummaryPath)") | Out-Null
    $lines.Add("Post-reboot validation helper: $($script:RebootResumeScriptPath)") | Out-Null
    $lines.Add("USB export destination: $($script:UsbExportDestination)") | Out-Null
    $lines.Add("Assessment filter: $($script:AssessmentFilterPath)") | Out-Null
    $lines.Add("Reboot required: $script:RebootRequired") | Out-Null
    $lines.Add('') | Out-Null
    $lines.Add('Outstanding / manual / environment-specific items:') | Out-Null
    foreach ($item in $script:OutstandingItems) { $lines.Add(" - $item") | Out-Null }
    Set-Content -Path $summaryPath -Value $lines -Encoding UTF8
    $script:ReportPath = $summaryPath

    Write-Host "Coverage report: $script:CoverageReportPath" -ForegroundColor Green
    Write-Host "Outstanding summary: $script:ReportPath" -ForegroundColor Green
    if ($script:RebootRequired) { Write-Warning 'A reboot is required to finalize one or more remediations.' }
    if ($script:OutstandingItems.Count -gt 0) {
        Write-Warning "Outstanding/manual items: $($script:OutstandingItems.Count). See summary file."
    }
}
#endregion Validation, Coverage Reporting & Summary

#region Main Execution
# ─────────────────────────────────────────────────────────────────────────────
# Main execution
# ─────────────────────────────────────────────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Please run this script as Administrator.'
}

New-StigDirectory -Path (Join-Path $env:ProgramData 'PowerSTIG')
New-StigDirectory -Path $BackupRoot
New-StigDirectory -Path $ReportRoot

$script:TranscriptPath = Join-Path (Join-Path $env:ProgramData 'PowerSTIG') ("Win11_STIG_Remediation_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
Start-StigTranscript -Path $script:TranscriptPath

try {
    Clear-OrphanedRegistryHives

    $menuSettings = Invoke-StigInteractiveMenu
    if ($menuSettings) {
        foreach ($key in $menuSettings.Keys) {
            Set-Variable -Name $key -Value $menuSettings[$key] -Scope Local
        }
    }

    Write-Section 'Starting comprehensive Windows 11 STIG remediation'
    $resolvedScap = Resolve-ScapXmlPath
    Import-ScapContent -Path $resolvedScap

    if ($AssessmentResultPath -and -not $RemediateOnlyFailedFindings -and -not $AllowBroadRemediationWithResultTargeting) {
        Write-Warning 'AssessmentResultPath was supplied. Because this script is optimized for post-SCAP remediation, it will target failed findings only by default. Use -AllowBroadRemediationWithResultTargeting to run broad remediation anyway.'
        $RemediateOnlyFailedFindings = $true
    }

    if ($AssessmentResultPath) {
        Import-AssessmentResultTargeting -Path $AssessmentResultPath
        if (-not $RemediateOnlyFailedFindings) {
            Write-Warning 'AssessmentResultPath was supplied without -RemediateOnlyFailedFindings. The assessment result will be reported, but all XML rules remain targeted.'
        }
    }
    elseif ($RemediateOnlyFailedFindings) {
        throw '-RemediateOnlyFailedFindings requires -AssessmentResultPath with an SCC/XCCDF result, DISA CKL, or supported CSV export.'
    }

    $coveragePath = Join-Path $ReportRoot ("Win11_STIG_SCAP_Coverage_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date))
    Export-ScapCoverageReport -Path $coveragePath
    Add-ManualOutstandingItemsFromInventory

    if (-not $SkipSystemReadiness) {
        Invoke-StigSystemReadiness -OutputRoot $ReportRoot
    }
    if (-not $SkipLocalAdminReview) {
        Invoke-LocalAdminGroupReview -OutputRoot $ReportRoot
    }

    if ($ResumePostRebootValidation) {
        Write-Warning 'ResumePostRebootValidation was specified. No remediation will be performed; post-validation/reporting only.'

        $resumeMarkerPath = Get-StigResumeMarkerPath -OutputRoot $ReportRoot
        $resumeMarkerOk = $false
        if (Test-Path -LiteralPath $resumeMarkerPath) {
            try {
                $marker = Get-Content -LiteralPath $resumeMarkerPath -Raw | ConvertFrom-Json
                if ($marker.ComputerName -eq $env:COMPUTERNAME) { $resumeMarkerOk = $true }
                else { Write-Warning "Resume marker at $resumeMarkerPath was written for computer '$($marker.ComputerName)', not this machine ('$env:COMPUTERNAME')." }
            } catch {
                Write-Warning "Resume marker at $resumeMarkerPath could not be read: $($_.Exception.Message)"
            }
        } else {
            Write-Warning "No resume marker found at $resumeMarkerPath."
        }
        if (-not $resumeMarkerOk -and -not $Force) {
            throw "ResumePostRebootValidation could not confirm that a prior remediation run actually completed on this machine before the reboot (see warning above). Reporting post-reboot results without that confirmation risks treating an interrupted/crashed run as if it finished cleanly. Re-run with -Force to proceed anyway if you have independently confirmed remediation completed."
        }

        if (-not $SkipPostValidation) {
            $postReport = Join-Path $ReportRoot ("Win11_STIG_PostRebootValidation_Detail_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date))
            $postSummary = Join-Path $ReportRoot ("Win11_STIG_PostRebootValidation_Summary_{0:yyyyMMdd_HHmmss}.txt" -f (Get-Date))
            Invoke-StigXmlValidation -Phase PostRebootValidation -ReportPath $postReport -SummaryPath $postSummary
        }
        Export-StigCertificateReport -OutputRoot $ReportRoot -Phase 'PostRebootValidation'
        Invoke-StigValidationSummary
        Write-StigOperatorSummary -OutputRoot $ReportRoot
        Invoke-EndOfRunReportActions
        return
    }

    if (-not $SkipPreCheck) {
        $preReport = Join-Path $ReportRoot ("Win11_STIG_PreCheck_Detail_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date))
        $preSummary = Join-Path $ReportRoot ("Win11_STIG_PreCheck_Summary_{0:yyyyMMdd_HHmmss}.txt" -f (Get-Date))
        Invoke-StigXmlValidation -Phase PreCheck -ReportPath $preReport -SummaryPath $preSummary
    }

    if ($AnalyzeOnly) {
        Write-Warning 'AnalyzeOnly was specified. No remediation was performed.'
        Export-StigCertificateReport -OutputRoot $ReportRoot -Phase 'AnalyzeOnly'
        Invoke-StigValidationSummary
        Write-StigOperatorSummary -OutputRoot $ReportRoot
        Invoke-EndOfRunReportActions
        return
    }

    $script:BackupPath = Export-StigBackup -RootPath $BackupRoot

    if ($script:BackupOnly) {
        Write-Warning 'Rollback package only was selected. No remediation was performed.'
        Invoke-StigValidationSummary
        Write-StigOperatorSummary -OutputRoot $ReportRoot
        Invoke-EndOfRunReportActions
        return
    }

    if ($RemediateOnlyFailedFindings -and -not $AllowBroadRemediationWithResultTargeting) {
        Write-Warning 'Result-targeted mode is enabled. Broad PowerSTIG and hard-coded modules are skipped unless -AllowBroadRemediationWithResultTargeting is supplied.'
        Invoke-ScapDrivenRegistryRemediation
        Invoke-ScapDrivenAuditPolicy
    }
    else {
        Invoke-PowerStigBaseline
        Invoke-LocalSecurityPolicyRemediation
        Rename-BuiltInAccounts
        Invoke-FeatureAndServiceRemediation
        Invoke-HardCodedRegistryRemediation
        Invoke-ScapDrivenRegistryRemediation
        Invoke-PerUserRegistryRemediation
        Invoke-ScapDrivenAuditPolicy
        Set-StigWindowsTime
        Invoke-StigLapsPolicyProcessing
        Invoke-CertificateRemediation
        Invoke-FirewallScopeRemediation

        if ($null -ne $StartupPin) {
            Suspend-StigTranscript
            try { Invoke-BitLockerRemediation -Pin $StartupPin }
            finally { Resume-StigTranscript }
        }
        else {
            Add-OutstandingItem 'BitLocker TPM+PIN policy was written, but full BitLocker TPM+PIN enablement was not completed because -StartupPin was not supplied.'
        }
    }

    if (-not $SkipPostValidation) {
        $postReport = Join-Path $ReportRoot ("Win11_STIG_PostValidation_Detail_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date))
        $postSummary = Join-Path $ReportRoot ("Win11_STIG_PostValidation_Summary_{0:yyyyMMdd_HHmmss}.txt" -f (Get-Date))
        Invoke-StigXmlValidation -Phase PostValidation -ReportPath $postReport -SummaryPath $postSummary
    }

    if (-not $SkipCertificateReport -and -not $script:CertificateReportPath) {
        Export-StigCertificateReport -OutputRoot $ReportRoot -Phase 'Final'
    }
    if ($script:RebootRequired) {
        New-PostRebootValidationScript -OutputRoot $ReportRoot
    }

    Invoke-StigValidationSummary
    Write-StigOperatorSummary -OutputRoot $ReportRoot
    Invoke-EndOfRunReportActions
    Write-Section 'Windows 11 STIG remediation complete'
    Write-Host "Transcript: $($script:TranscriptPath)" -ForegroundColor Green
    Write-Host "Backup path: $($script:BackupPath)" -ForegroundColor Green
    Write-Host "Operator summary: $($script:OperatorSummaryPath)" -ForegroundColor Green
}
finally {
    if ($script:TranscriptActive) {
        Stop-Transcript | Out-Null
        $script:TranscriptActive = $false
    }
}
#endregion Main Execution
