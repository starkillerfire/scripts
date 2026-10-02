<#
    .SYNOPSIS
    Reports the state of every Win32 app Intune has tried to install on this
    machine - a read-only companion to Intune Sync Fix\grsremediation.ps1.

    .DESCRIPTION
    Enumerates HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps,
    reads each app's EnforcementStateMessage, and classifies it as Success,
    SuccessRebootRequired, or Failed using the same ErrorCode convention
    Intune Sync Fix\grsremediation.ps1 already uses (0 and 3010 are success;
    anything else is a failure). Also pulls recent error-level lines from
    IntuneManagementExtension.log, if present, for the actual failure text
    behind each error code.

    This script only reads state - it never deletes registry keys or
    touches the IME log. If this run shows apps that would be flagged as
    failed, Intune Sync Fix\grsremediation.ps1 is the tool that clears their
    registry state so Intune retries the install; run that separately and
    deliberately, not as a side effect of this diagnostic.

    .PARAMETER OutputPath
    Parent folder to write the diagnostic run's own timestamped subfolder
    into. If omitted, the script picks the logged-on user's Downloads
    folder (interactive runs) or C:\ProgramData\IntuneDiagnostics (SYSTEM /
    Intune-pushed runs) automatically.

    .PARAMETER OpenFolder
    Open the output folder in Explorer when done. Default on, but only
    takes effect for an interactive, non-SYSTEM session.

    .PARAMETER LogDaysToSearch
    How many days of IntuneManagementExtension.log to scan for error-level
    lines. Default 7.

    .EXAMPLE
    .\Invoke-IntuneAppDiagnostic.ps1

    .NOTES
    See also: Intune Sync Fix\grsremediation.ps1 (remediates the failures
    this script only reports).
#>
[CmdletBinding()]
param(
    [string]$OutputPath,

    [bool]$OpenFolder = $true,

    [ValidateRange(1, 90)]
    [int]$LogDaysToSearch = 7
)

Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'IntuneDiag.Common.psm1') -Force

$TimeStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$FolderName = "Intune-App-Diagnostics-$TimeStamp"
$OutFolder = Resolve-DiagnosticOutputPath -FolderName $FolderName -RequestedPath $OutputPath

Write-Host ''
Write-Host '==============================================' -ForegroundColor Cyan
Write-Host ' Intune Win32 App Deployment Diagnostic' -ForegroundColor Cyan
Write-Host '==============================================' -ForegroundColor Cyan
Write-Host ''
Write-Host 'Diagnostic output folder:' -ForegroundColor Cyan
Write-Host $OutFolder -ForegroundColor Yellow
Write-Host ''

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning 'PowerShell is NOT running as Administrator - some Win32Apps registry subkeys may be unreadable, making results incomplete.'
}

# ============================================================
# Enumerate Win32 app state
# ============================================================

$win32AppsKeyPath = 'HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps'
$appStates = [System.Collections.Generic.List[PSCustomObject]]::new()
$registryReadErrors = $null

if (Test-Path $win32AppsKeyPath) {
    # -Recurse against this tree can hit subkeys ACL'd to SYSTEM only (per-
    # user report-cache keys, mainly). The registry provider still prints
    # its own access-denied error for each one straight to the console,
    # ignoring -ErrorAction SilentlyContinue and 2>$null - that was tried
    # and traded away completeness for quiet (scoping $ErrorActionPreference
    # around the call made Get-ChildItem abort the whole enumeration on the
    # first denied subkey instead of skipping past it). So the message is
    # left visible: it's an accurate, per-subkey diagnostic, not noise worth
    # losing results over. -ErrorVariable still captures how many were
    # skipped so an incomplete scan is reported as incomplete instead of
    # looking like a clean "nothing failed."
    $appSubKeys = Get-ChildItem -Path $win32AppsKeyPath -Recurse -ErrorAction SilentlyContinue -ErrorVariable registryReadErrors

    if ($registryReadErrors.Count -gt 0) {
        Write-Warning "$($registryReadErrors.Count) registry subkey(s) under Win32Apps could not be read (access denied) - results may be incomplete. Run as Administrator or SYSTEM for a complete scan."
    }

    foreach ($subKey in $appSubKeys) {
        $enforcementStateMessage = Get-ItemProperty -Path $subKey.PSPath -Name EnforcementStateMessage -ErrorAction SilentlyContinue
        if (-not $enforcementStateMessage) { continue }

        $status = 'Unknown'
        $errorCode = $null

        if ($enforcementStateMessage.EnforcementStateMessage -match '"ErrorCode":(-?\d+|null)') {
            $errorCodeRaw = $Matches[1]
            if ($errorCodeRaw -eq 'null') {
                $status = 'Pending'
            }
            else {
                $parsed = 0
                if ([int]::TryParse($errorCodeRaw, [ref]$parsed)) {
                    $errorCode = $parsed
                    $status = switch ($errorCode) {
                        0 { 'Success' }
                        3010 { 'SuccessRebootRequired' }
                        default { 'Failed' }
                    }
                }
                else {
                    $status = "Unparseable ($errorCodeRaw)"
                }
            }
        }

        $appStates.Add([PSCustomObject]@{
            SubKeyPath = $subKey.PSPath
            KeyName    = $subKey.PSChildName
            Status     = $status
            ErrorCode  = $errorCode
        })
    }
}
else {
    Write-Warning "Registry path not found: $win32AppsKeyPath (Intune Management Extension may not have run a Win32 app install on this machine yet)"
}

$appStates | Export-Csv (Join-Path $OutFolder 'Win32App-States.csv') -NoTypeInformation -Encoding utf8

$counts = $appStates | Group-Object Status | Select-Object Name, Count
$failedApps = @($appStates | Where-Object { $_.Status -eq 'Failed' })

Write-Host ''
Write-Host '==============================================' -ForegroundColor Cyan
Write-Host ' APP STATE SUMMARY' -ForegroundColor Cyan
Write-Host '==============================================' -ForegroundColor Cyan
if ($registryReadErrors.Count -gt 0) {
    Write-Host "Incomplete scan - $($registryReadErrors.Count) registry subkey(s) could not be read. Re-run elevated for a complete picture." -ForegroundColor Yellow
}
$counts | Format-Table -AutoSize

if ($failedApps.Count -gt 0) {
    Write-Host ''
    Write-Host "$($failedApps.Count) app registry entr$(if ($failedApps.Count -eq 1) { 'y is' } else { 'ies are' }) in a failed state:" -ForegroundColor Yellow
    $failedApps | Format-Table KeyName, ErrorCode -AutoSize
    Write-Host 'Intune Sync Fix\grsremediation.ps1 can clear these so Intune retries the install.' -ForegroundColor Yellow
}
else {
    Write-Host ''
    Write-Host 'No apps are in a failed state.' -ForegroundColor Green
}

# ============================================================
# IntuneManagementExtension.log - recent errors
# ============================================================

$imeLogPath = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log'
$logErrors = @()

if (Test-Path $imeLogPath) {
    Write-Host ''
    Write-Host "Scanning $imeLogPath for recent error-level lines..."

    $cutoff = (Get-Date).AddDays(-$LogDaysToSearch)

    # IME log lines look like: [date][time][LEVEL] message. Only lines whose
    # embedded timestamp parses and falls inside the window are kept - this
    # is best-effort text scraping of a log format Microsoft doesn't publish
    # a schema for, so a line that doesn't match the expected shape is
    # skipped rather than guessed at.
    $logErrors = @(Get-Content -Path $imeLogPath -ErrorAction SilentlyContinue | Where-Object {
        if ($_ -notmatch '\[(?<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\].*\b(ERROR|FAILED|Exception)\b') { return $false }
        $ts = [datetime]::MinValue
        if (-not [datetime]::TryParse($Matches.ts, [ref]$ts)) { return $false }
        return $ts -ge $cutoff
    })

    $logErrors | Out-File (Join-Path $OutFolder 'IME-Log-RecentErrors.txt') -Encoding utf8
    Write-Host "Error-level lines found in the last $LogDaysToSearch day(s): $($logErrors.Count)" -ForegroundColor Yellow
}
else {
    Write-Warning "IntuneManagementExtension.log not found at $imeLogPath"
}

# ============================================================
# Summary report
# ============================================================

$summaryFile = Join-Path $OutFolder '00-AppDiagnostic-Summary.txt'

@"
============================================================
INTUNE WIN32 APP DEPLOYMENT DIAGNOSTIC SUMMARY
============================================================

Computer:  $env:COMPUTERNAME
Date:      $(Get-Date)
Output:    $OutFolder
$(if ($registryReadErrors.Count -gt 0) { "`nIncomplete scan: $($registryReadErrors.Count) registry subkey(s) could not be read (access denied).`nRe-run elevated (Administrator or SYSTEM) for a complete picture.`n" })

App state counts:
"@ | Out-File $summaryFile -Encoding utf8

$counts | Format-Table -AutoSize | Out-String | Add-Content $summaryFile -Encoding utf8

if ($failedApps.Count -gt 0) {
    @"

Failed app registry entries (see Win32App-States.csv for full detail):
"@ | Add-Content $summaryFile -Encoding utf8
    $failedApps | Format-Table KeyName, ErrorCode -AutoSize | Out-String | Add-Content $summaryFile -Encoding utf8
    'Intune Sync Fix\grsremediation.ps1 can clear these so Intune retries the install.' | Add-Content $summaryFile -Encoding utf8
}

@"

IntuneManagementExtension.log error-level lines (last $LogDaysToSearch day(s)): $($logErrors.Count)
See IME-Log-RecentErrors.txt for the full list.
"@ | Add-Content $summaryFile -Encoding utf8

Write-Host ''
Write-Host 'Results saved to:' -ForegroundColor Cyan
Write-Host $OutFolder -ForegroundColor Yellow
Write-Host ''

Show-DiagnosticFolder -Path $OutFolder -OpenFolder $OpenFolder
