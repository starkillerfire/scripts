<#
    .SYNOPSIS
    Checks Entra/MDM enrollment health: join state, enrollment records, client
    certificate validity, management service status, and recent sync events.

    .DESCRIPTION
    Read-only health check for "this machine won't check in / sync / receive
    policy" tickets - the enrollment-level complement to
    Invoke-IntuneWindowsUpdateDiagnostic.ps1, which focuses on Windows Update
    policy specifically. Produces a pass/warn/fail summary plus the
    supporting detail (dsregcmd output, enrollment registry records,
    certificate expiry, recent MDM sync events, optional endpoint
    reachability).

    .PARAMETER OutputPath
    Parent folder to write the diagnostic run's own timestamped subfolder
    into. If omitted, the script picks the logged-on user's Downloads
    folder (interactive runs) or C:\ProgramData\IntuneDiagnostics (SYSTEM /
    Intune-pushed runs) automatically.

    .PARAMETER OpenFolder
    Open the output folder in Explorer when done. Default on, but only
    takes effect for an interactive, non-SYSTEM session.

    .PARAMETER TestConnectivity
    Check TCP 443 reachability to a short list of well-known, public
    Microsoft Intune/Entra endpoints. Default on. These are fixed public
    service hostnames, not environment-specific secrets, so this
    intentionally triggers (and accepts) PSScriptAnalyzer's
    PSAvoidUsingComputerNameHardcoded rule the same way Autopilot-v2.ps1
    already does for the same reason.

    .PARAMETER DaysToSearch
    How many days of MDM sync-related event log history to search. Default 14.

    .EXAMPLE
    .\Invoke-IntuneEnrollmentDiagnostic.ps1

    .EXAMPLE
    .\Invoke-IntuneEnrollmentDiagnostic.ps1 -TestConnectivity:$false -OpenFolder:$false

    .NOTES
    dsregcmd output includes tenant and device identifiers. Review a
    diagnostic bundle before attaching it to an external or third-party
    ticket.
#>
[CmdletBinding()]
param(
    [string]$OutputPath,

    [bool]$OpenFolder = $true,

    [bool]$TestConnectivity = $true,

    [ValidateRange(1, 365)]
    [int]$DaysToSearch = 14
)

Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'IntuneDiag.Common.psm1') -Force

$TimeStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$FolderName = "Intune-Enrollment-Diagnostics-$TimeStamp"
$OutFolder = Resolve-DiagnosticOutputPath -FolderName $FolderName -RequestedPath $OutputPath

Write-Host ''
Write-Host '==============================================' -ForegroundColor Cyan
Write-Host ' Intune / Entra Enrollment Diagnostic' -ForegroundColor Cyan
Write-Host '==============================================' -ForegroundColor Cyan
Write-Host ''
Write-Host 'Diagnostic output folder:' -ForegroundColor Cyan
Write-Host $OutFolder -ForegroundColor Yellow
Write-Host ''

$healthRows = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-HealthRow {
    param(
        [string]$Area,
        [ValidateSet('Pass', 'Warn', 'Fail', 'Info')]
        [string]$Status,
        [string]$Detail
    )
    $healthRows.Add([PSCustomObject]@{ Area = $Area; Status = $Status; Detail = $Detail })
}

# ============================================================
# dsregcmd /status
# ============================================================

$dsregOutput = & dsregcmd.exe /status
$dsregOutput | Out-File (Join-Path $OutFolder 'DSREGCMD-Status.txt') -Encoding utf8

function Get-DsregField {
    param([string[]]$Lines, [string]$FieldName)
    $line = $Lines | Where-Object { $_ -match "^\s*$FieldName\s*:\s*(.+)$" } | Select-Object -First 1
    if ($line -and $line -match "^\s*$FieldName\s*:\s*(.+)$") { return $Matches[1].Trim() }
    return $null
}

$azureAdJoined = Get-DsregField -Lines $dsregOutput -FieldName 'AzureAdJoined'
$domainJoined = Get-DsregField -Lines $dsregOutput -FieldName 'DomainJoined'
$enterpriseJoined = Get-DsregField -Lines $dsregOutput -FieldName 'EnterpriseJoined'
$tenantId = Get-DsregField -Lines $dsregOutput -FieldName 'TenantId'
$deviceId = Get-DsregField -Lines $dsregOutput -FieldName 'DeviceId'

if ($azureAdJoined -eq 'YES' -or $enterpriseJoined -eq 'YES') {
    Add-HealthRow -Area 'Entra/Hybrid join' -Status 'Pass' -Detail "AzureAdJoined=$azureAdJoined DomainJoined=$domainJoined EnterpriseJoined=$enterpriseJoined"
}
else {
    Add-HealthRow -Area 'Entra/Hybrid join' -Status 'Fail' -Detail "Not Azure AD or Enterprise joined (AzureAdJoined=$azureAdJoined DomainJoined=$domainJoined EnterpriseJoined=$enterpriseJoined)"
}

if ($deviceId) {
    Add-HealthRow -Area 'Device identity' -Status 'Info' -Detail "DeviceId=$deviceId TenantId=$tenantId"
}

# ============================================================
# MDM enrollment registry records
# ============================================================

$enrollmentsRoot = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
$enrollments = @()

if (Test-Path $enrollmentsRoot) {
    $enrollments = @(Get-ChildItem $enrollmentsRoot -ErrorAction SilentlyContinue | Where-Object {
        $_.PSChildName -match '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
    } | ForEach-Object {
        # Not every enrollment subkey carries all three values (some are
        # near-empty container keys), and under StrictMode reading a
        # property that isn't there throws - so check before reading
        # rather than reading and hoping.
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            EnrollmentId    = $_.PSChildName
            ProviderID      = if ($props -and $props.PSObject.Properties['ProviderID']) { $props.ProviderID } else { $null }
            EnrollmentState = if ($props -and $props.PSObject.Properties['EnrollmentState']) { $props.EnrollmentState } else { $null }
            EnrollmentType  = if ($props -and $props.PSObject.Properties['EnrollmentType']) { $props.EnrollmentType } else { $null }
        }
    })
}

$enrollments | Export-Csv (Join-Path $OutFolder 'MDM-Enrollments.csv') -NoTypeInformation -Encoding utf8

$intuneEnrollment = $enrollments | Where-Object { $_.ProviderID -eq 'MS DM Server' }
if ($intuneEnrollment) {
    Add-HealthRow -Area 'MDM enrollment record' -Status 'Pass' -Detail "Found $($enrollments.Count) enrollment record(s); Intune (MS DM Server) present"
}
elseif ($enrollments.Count -gt 0) {
    Add-HealthRow -Area 'MDM enrollment record' -Status 'Warn' -Detail "Found $($enrollments.Count) enrollment record(s) but none from Intune (MS DM Server)"
}
else {
    Add-HealthRow -Area 'MDM enrollment record' -Status 'Fail' -Detail 'No MDM enrollment records found'
}

# ============================================================
# MDM client certificate health
# ============================================================

$mdmCerts = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {
    $_.Issuer -match 'Microsoft Intune|Microsoft Device CA|MS-Organization-Access'
})

$mdmCerts | Select-Object Subject, Issuer, NotBefore, NotAfter, Thumbprint |
    Export-Csv (Join-Path $OutFolder 'MDM-Client-Certificates.csv') -NoTypeInformation -Encoding utf8

if ($mdmCerts.Count -eq 0) {
    Add-HealthRow -Area 'MDM client certificate' -Status 'Fail' -Detail 'No MDM/enrollment client certificate found in LocalMachine\My'
}
else {
    foreach ($cert in $mdmCerts) {
        $daysLeft = ($cert.NotAfter - (Get-Date)).Days
        if ($daysLeft -lt 0) {
            Add-HealthRow -Area 'MDM client certificate' -Status 'Fail' -Detail "Certificate $($cert.Thumbprint) expired $($cert.NotAfter)"
        }
        elseif ($daysLeft -lt 30) {
            Add-HealthRow -Area 'MDM client certificate' -Status 'Warn' -Detail "Certificate $($cert.Thumbprint) expires in $daysLeft day(s) ($($cert.NotAfter))"
        }
        else {
            Add-HealthRow -Area 'MDM client certificate' -Status 'Pass' -Detail "Certificate $($cert.Thumbprint) valid until $($cert.NotAfter) ($daysLeft days)"
        }
    }
}

# ============================================================
# Management service status
# ============================================================

$managementServices = @('IntuneManagementExtension', 'dmwappushsvc')
$serviceStates = @(foreach ($svc in $managementServices) {
    Get-Service $svc -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType
})

$serviceStates | Export-Csv (Join-Path $OutFolder 'Management-Services.csv') -NoTypeInformation -Encoding utf8

foreach ($svc in $serviceStates) {
    if ($svc.Status -eq 'Running') {
        Add-HealthRow -Area "Service: $($svc.Name)" -Status 'Pass' -Detail "Status=$($svc.Status) StartType=$($svc.StartType)"
    }
    else {
        Add-HealthRow -Area "Service: $($svc.Name)" -Status 'Warn' -Detail "Status=$($svc.Status) StartType=$($svc.StartType)"
    }
}

$missingServices = $managementServices | Where-Object { $_ -notin $serviceStates.Name }
foreach ($missing in $missingServices) {
    if ($missing -eq 'dmwappushsvc') {
        # Microsoft removed this service from current Windows 10/11 builds
        # in favor of a different push-notification mechanism - its
        # absence is expected on an up-to-date machine, not a fault.
        Add-HealthRow -Area "Service: $missing" -Status 'Info' -Detail 'Not present - expected on current Windows builds (deprecated in favor of a different MDM push mechanism)'
    }
    else {
        Add-HealthRow -Area "Service: $missing" -Status 'Fail' -Detail 'Service not found on this machine'
    }
}

# ============================================================
# Recent MDM sync-related events
# ============================================================

$mdmLog = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
$startTime = (Get-Date).AddDays(-$DaysToSearch)

try {
    $syncEvents = @(Get-WinEvent -FilterHashtable @{ LogName = $mdmLog; StartTime = $startTime } -MaxEvents 2000 -ErrorAction Stop |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message)

    $syncEvents | Export-Csv (Join-Path $OutFolder 'MDM-Sync-Events.csv') -NoTypeInformation -Encoding utf8

    $recentErrors = @($syncEvents | Where-Object { $_.LevelDisplayName -eq 'Error' -and $_.TimeCreated -gt (Get-Date).AddDays(-1) })
    if ($recentErrors.Count -gt 0) {
        Add-HealthRow -Area 'Recent MDM sync events' -Status 'Warn' -Detail "$($recentErrors.Count) error-level event(s) in the last 24 hours"
    }
    else {
        Add-HealthRow -Area 'Recent MDM sync events' -Status 'Pass' -Detail "No error-level events in the last 24 hours ($($syncEvents.Count) total events in $DaysToSearch days)"
    }
}
catch {
    Add-HealthRow -Area 'Recent MDM sync events' -Status 'Warn' -Detail "Could not read $mdmLog`: $($_.Exception.Message)"
    $_ | Out-File (Join-Path $OutFolder 'MDM-EventLog-Error.txt') -Encoding utf8
}

# ============================================================
# Optional connectivity check
# ============================================================

if ($TestConnectivity) {
    # Fixed, public Microsoft service endpoints - not environment-specific,
    # so hardcoding them here is intentional (same accepted pattern used in
    # Autopilot\Autopilot-v2.ps1).
    $endpoints = @('enrollment.manage.microsoft.com', 'portal.manage.microsoft.com', 'login.microsoftonline.com')

    $connectivity = @(foreach ($endpoint in $endpoints) {
        $reachable = Test-NetConnection -ComputerName $endpoint -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        [PSCustomObject]@{ Endpoint = $endpoint; Port443Reachable = [bool]$reachable }
    })

    $connectivity | Export-Csv (Join-Path $OutFolder 'Endpoint-Connectivity.csv') -NoTypeInformation -Encoding utf8

    $unreachable = @($connectivity | Where-Object { -not $_.Port443Reachable })
    if ($unreachable.Count -gt 0) {
        Add-HealthRow -Area 'Endpoint connectivity' -Status 'Fail' -Detail "Unreachable on 443: $(($unreachable.Endpoint) -join ', ')"
    }
    else {
        Add-HealthRow -Area 'Endpoint connectivity' -Status 'Pass' -Detail "All $($endpoints.Count) checked endpoints reachable on 443"
    }
}

# ============================================================
# Summary
# ============================================================

Write-Host ''
Write-Host '==============================================' -ForegroundColor Cyan
Write-Host ' HEALTH SUMMARY' -ForegroundColor Cyan
Write-Host '==============================================' -ForegroundColor Cyan

foreach ($row in $healthRows) {
    $color = switch ($row.Status) {
        'Pass' { 'Green' }
        'Warn' { 'Yellow' }
        'Fail' { 'Red' }
        default { 'Gray' }
    }
    Write-Host ("[{0,-4}] {1,-24} {2}" -f $row.Status, $row.Area, $row.Detail) -ForegroundColor $color
}

$healthRows | Export-Csv (Join-Path $OutFolder '00-Health-Summary.csv') -NoTypeInformation -Encoding utf8

$summaryFile = Join-Path $OutFolder '00-Enrollment-Summary.txt'
@"
============================================================
INTUNE / ENTRA ENROLLMENT DIAGNOSTIC SUMMARY
============================================================

Computer:   $env:COMPUTERNAME
Date:       $(Get-Date)
Output:     $OutFolder

This bundle includes dsregcmd output, which contains tenant and device
identifiers. Review before attaching to an external or third-party ticket.

============================================================
HEALTH CHECKS
============================================================
"@ | Out-File $summaryFile -Encoding utf8

$healthRows | Format-Table Status, Area, Detail -AutoSize | Out-String -Width 200 | Add-Content $summaryFile -Encoding utf8

Write-Host ''
Write-Host 'Results saved to:' -ForegroundColor Cyan
Write-Host $OutFolder -ForegroundColor Yellow
Write-Host ''

Show-DiagnosticFolder -Path $OutFolder -OpenFolder $OpenFolder
