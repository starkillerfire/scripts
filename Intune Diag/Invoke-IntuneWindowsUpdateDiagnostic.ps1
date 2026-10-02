<#
    .SYNOPSIS
    Collects Intune/Windows Update policy and history diagnostics into one folder.

    .DESCRIPTION
    Gathers, in one pass:
      - Effective MDM (Intune) Windows Update policy
      - Windows Update GPO policy
      - Local Windows Update client state
      - Intune/MDM and Windows Update Client event log entries
      - Windows Update-related service status
      - GPResult and dsregcmd output
      - PolicyManager provider policies

    Read-only - makes no configuration changes. Intended for troubleshooting
    "why isn't this machine updating/deferring/pausing the way policy says
    it should" tickets.

    .PARAMETER DaysToSearch
    How many days of event log history to search. Default 30.

    .PARAMETER OutputPath
    Parent folder to write the diagnostic run's own timestamped subfolder
    into. If omitted, the script picks the logged-on user's Downloads
    folder (interactive runs) or C:\ProgramData\IntuneDiagnostics (SYSTEM /
    Intune-pushed runs) automatically.

    .PARAMETER OpenFolder
    Open the output folder in Explorer when done. Default on, but only
    takes effect for an interactive, non-SYSTEM session - an Intune-pushed
    run never pops a window regardless of this setting.

    .EXAMPLE
    .\Invoke-IntuneWindowsUpdateDiagnostic.ps1

    .EXAMPLE
    .\Invoke-IntuneWindowsUpdateDiagnostic.ps1 -DaysToSearch 7 -OutputPath D:\Tickets\12345 -OpenFolder:$false

    .NOTES
    GPResult and dsregcmd output can contain tenant/device/policy detail.
    Review a diagnostic bundle before attaching it to an external or
    third-party ticket.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 365)]
    [int]$DaysToSearch = 30,

    [string]$OutputPath,

    [bool]$OpenFolder = $true
)

Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'IntuneDiag.Common.psm1') -Force

$StartTime = (Get-Date).AddDays(-$DaysToSearch)
$TimeStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$FolderName = "Intune-WU-Diagnostics-$TimeStamp"

$OutFolder = Resolve-DiagnosticOutputPath -FolderName $FolderName -RequestedPath $OutputPath

Write-Host ''
Write-Host '==============================================' -ForegroundColor Cyan
Write-Host ' Intune / Windows Update Diagnostic' -ForegroundColor Cyan
Write-Host '==============================================' -ForegroundColor Cyan
Write-Host ''
Write-Host 'Diagnostic output folder:' -ForegroundColor Cyan
Write-Host $OutFolder -ForegroundColor Yellow
Write-Host ''

# ============================================================
# Check Admin
# ============================================================

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning 'PowerShell is NOT running as Administrator.'
    Write-Warning 'Some information may be unavailable.'
}

# ============================================================
# System Information
# ============================================================

$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$loggedOnUser = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UserName -ErrorAction SilentlyContinue

[PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    LoggedOnUser = $loggedOnUser
    OS           = $os.Caption
    Version      = $os.Version
    Build        = $os.BuildNumber
    InstallDate  = $os.InstallDate
    LastBoot     = $os.LastBootUpTime
    ScanStart    = $StartTime
    OutputFolder = $OutFolder
} | Format-List | Out-File (Join-Path $OutFolder 'SystemInfo.txt') -Encoding utf8

# ============================================================
# Registry helper
# ============================================================

function Get-RegistryValue {
    [OutputType([PSCustomObject])]
    param(
        [string]$Path,
        [string]$Source
    )

    if (-not (Test-Path $Path)) { return }

    $reg = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    if (-not $reg) { return }

    foreach ($property in $reg.PSObject.Properties) {
        if ($property.Name -notmatch '^PS') {
            [PSCustomObject]@{
                Source = $Source
                Path   = $Path
                Name   = $property.Name
                Value  = $property.Value
            }
        }
    }
}

# ============================================================
# Registry Locations
# ============================================================

$registryData = @(
    Get-RegistryValue 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update' 'MDM / Intune Effective Policy'
    Get-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'Windows Update GPO'
    Get-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'Windows Update AU GPO'
    Get-RegistryValue 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' 'Windows Update Local State'
    Get-RegistryValue 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings' 'Windows Update Policy State'
)

$registryData | Sort-Object Source, Name | Export-Csv (Join-Path $OutFolder 'All-WindowsUpdate-Registry.csv') -NoTypeInformation -Encoding utf8

# ============================================================
# Important Update Settings
# ============================================================

$interestingRegex = @(
    'Pause', 'Defer', 'TargetRelease', 'TargetReleaseVersion', 'ProductVersion',
    'Deadline', 'WUServer', 'WUStatusServer', 'UseWUServer', 'DisableDualScan',
    'DoNotConnectToWindowsUpdate', 'BranchReadiness', 'ActiveHours', 'AllowAutoUpdate',
    'ScheduledInstall', 'QualityUpdates', 'FeatureUpdates'
) -join '|'

$interesting = @($registryData | Where-Object { $_.Name -match $interestingRegex } | Sort-Object Source, Name)
$interesting | Export-Csv (Join-Path $OutFolder 'Important-WindowsUpdate-Policies.csv') -NoTypeInformation -Encoding utf8

Write-Host ''
Write-Host '==============================================' -ForegroundColor Cyan
Write-Host ' IMPORTANT WINDOWS UPDATE POLICY SETTINGS' -ForegroundColor Cyan
Write-Host '==============================================' -ForegroundColor Cyan

if ($interesting.Count -gt 0) {
    $interesting | Format-Table Source, Name, Value -AutoSize
}
else {
    Write-Host 'No obvious update policy values found.' -ForegroundColor Green
}

# ============================================================
# Explicit Pause Check
# ============================================================

$pauseSettings = @($registryData | Where-Object { $_.Name -match 'Pause|Paused' })

Write-Host ''
Write-Host '==============================================' -ForegroundColor Cyan
Write-Host ' PAUSE SETTINGS' -ForegroundColor Cyan
Write-Host '==============================================' -ForegroundColor Cyan

if ($pauseSettings.Count -gt 0) {
    $pauseSettings | Format-Table Source, Name, Value -AutoSize
    $pauseSettings | Export-Csv (Join-Path $OutFolder 'Pause-Settings.csv') -NoTypeInformation -Encoding utf8
}
else {
    Write-Host 'No pause-related registry values were found.' -ForegroundColor Green
    'No pause-related registry values were found.' | Out-File (Join-Path $OutFolder 'Pause-Settings.txt') -Encoding utf8
}

# ============================================================
# MDM / Intune Event Log
# ============================================================

$mdmLog = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'

Write-Host ''
Write-Host "Searching Intune / MDM events from the last $DaysToSearch days..."

$mdmUpdateEvents = @()
try {
    $mdmEvents = Get-WinEvent -FilterHashtable @{ LogName = $mdmLog; StartTime = $StartTime } -MaxEvents 5000 -ErrorAction Stop

    $mdmUpdateEvents = @($mdmEvents | Where-Object {
        $_.Message -match 'PauseQualityUpdates|PauseFeatureUpdates|DeferQualityUpdates|DeferFeatureUpdates|WindowsUpdate|Vendor/MSFT/Policy/Config/Update|Policy/Config/Update|Update/Configure|TargetRelease'
    } | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message)

    $mdmUpdateEvents | Export-Csv (Join-Path $OutFolder 'MDM-WindowsUpdate-Events.csv') -NoTypeInformation -Encoding utf8

    Write-Host ''
    Write-Host "MDM / Intune Update Events Found: $($mdmUpdateEvents.Count)" -ForegroundColor Yellow
    $mdmUpdateEvents | Select-Object -First 20 TimeCreated, Id, LevelDisplayName, Message | Format-Table -Wrap
}
catch {
    Write-Warning 'Could not read the MDM event log.'
    $_ | Out-File (Join-Path $OutFolder 'MDM-EventLog-Error.txt') -Encoding utf8
}

# ============================================================
# Windows Update Client Events
# ============================================================

$wuLog = 'Microsoft-Windows-WindowsUpdateClient/Operational'

Write-Host ''
Write-Host 'Searching Windows Update Client events...'

$wuEvents = @()
try {
    $wuEvents = @(Get-WinEvent -FilterHashtable @{ LogName = $wuLog; StartTime = $StartTime } -MaxEvents 2000 -ErrorAction Stop |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message)

    $wuEvents | Export-Csv (Join-Path $OutFolder 'WindowsUpdateClient-Events.csv') -NoTypeInformation -Encoding utf8
    Write-Host "Windows Update events collected: $($wuEvents.Count)" -ForegroundColor Yellow
}
catch {
    Write-Warning 'Could not read WindowsUpdateClient/Operational.'
    $_ | Out-File (Join-Path $OutFolder 'WindowsUpdateClient-Error.txt') -Encoding utf8
}

# ============================================================
# Policy-related WU events
# ============================================================

$wuInteresting = @($wuEvents | Where-Object { $_.Message -match 'pause|paused|policy|managed|defer|deferred|deadline|target' })

if ($wuInteresting.Count -gt 0) {
    $wuInteresting | Export-Csv (Join-Path $OutFolder 'WindowsUpdate-Policy-Related-Events.csv') -NoTypeInformation -Encoding utf8
}

# ============================================================
# Services
# ============================================================

$serviceNames = @('wuauserv', 'UsoSvc', 'BITS', 'WaaSMedicSvc', 'DoSvc')

$services = @(foreach ($service in $serviceNames) {
    Get-Service $service -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, Status, StartType
})

$services | Export-Csv (Join-Path $OutFolder 'WindowsUpdate-Services.csv') -NoTypeInformation -Encoding utf8

Write-Host ''
Write-Host '==============================================' -ForegroundColor Cyan
Write-Host ' WINDOWS UPDATE SERVICES' -ForegroundColor Cyan
Write-Host '==============================================' -ForegroundColor Cyan
$services | Format-Table -AutoSize

# ============================================================
# GPResult
# ============================================================

Write-Host ''
Write-Host 'Generating GPResult...'

gpresult.exe /Scope Computer /Z > (Join-Path $OutFolder 'GPResult-Computer.txt') 2>&1
gpresult.exe /Scope Computer /H (Join-Path $OutFolder 'GPResult-Computer.html') /F 2>&1 | Out-Null

# ============================================================
# Entra / MDM registration
# ============================================================

dsregcmd.exe /status > (Join-Path $OutFolder 'DSREGCMD-Status.txt')

# ============================================================
# PolicyManager Provider Search
# ============================================================

$providerRoot = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\providers'

if (Test-Path $providerRoot) {
    Write-Host ''
    Write-Host 'Searching PolicyManager providers...'

    $providerPolicies = @(Get-ChildItem $providerRoot -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -eq 'Update' } |
        ForEach-Object {
            $values = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            foreach ($property in $values.PSObject.Properties) {
                if ($property.Name -notmatch '^PS' -and $property.Name -match $interestingRegex) {
                    [PSCustomObject]@{
                        RegistryPath = $_.Name
                        Name         = $property.Name
                        Value        = $property.Value
                    }
                }
            }
        })

    $providerPolicies | Export-Csv (Join-Path $OutFolder 'PolicyManager-Provider-UpdatePolicies.csv') -NoTypeInformation -Encoding utf8
}

# ============================================================
# Summary report
# ============================================================

$summaryFile = Join-Path $OutFolder '00-WindowsUpdate-Summary.txt'

@"
============================================================
INTUNE / WINDOWS UPDATE DIAGNOSTIC SUMMARY
============================================================

Computer:         $env:COMPUTERNAME
Logged On User:   $loggedOnUser
Date:             $(Get-Date)
Output Folder:    $OutFolder
Days Searched:    $DaysToSearch

This bundle includes GPResult and dsregcmd output, which can contain
tenant/device/policy detail. Review before attaching to an external or
third-party ticket.

============================================================
PAUSE SETTINGS
============================================================
"@ | Out-File $summaryFile -Encoding utf8

if ($pauseSettings.Count -gt 0) {
    $pauseSettings | Format-Table Source, Name, Value -AutoSize | Out-String | Add-Content $summaryFile -Encoding utf8
}
else {
    'No pause-related registry values were detected.' | Add-Content $summaryFile -Encoding utf8
}

@"

============================================================
IMPORTANT WINDOWS UPDATE POLICIES
============================================================
"@ | Add-Content $summaryFile -Encoding utf8

$interesting | Format-Table Source, Name, Value -AutoSize | Out-String | Add-Content $summaryFile -Encoding utf8

# ============================================================
# Final Output
# ============================================================

Write-Host ''
Write-Host '==============================================' -ForegroundColor Green
Write-Host ' DIAGNOSTIC COMPLETE' -ForegroundColor Green
Write-Host '==============================================' -ForegroundColor Green
Write-Host ''
Write-Host 'Results saved to:' -ForegroundColor Cyan
Write-Host $OutFolder -ForegroundColor Yellow
Write-Host ''
Write-Host 'Start with:' -ForegroundColor Cyan
Write-Host '  00-WindowsUpdate-Summary.txt'
Write-Host '  Important-WindowsUpdate-Policies.csv'
Write-Host '  Pause-Settings.csv / .txt'
Write-Host '  MDM-WindowsUpdate-Events.csv'
Write-Host '  WindowsUpdate-Policy-Related-Events.csv'
Write-Host '  PolicyManager-Provider-UpdatePolicies.csv'
Write-Host ''

Show-DiagnosticFolder -Path $OutFolder -OpenFolder $OpenFolder
