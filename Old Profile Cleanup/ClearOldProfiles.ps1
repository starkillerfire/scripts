#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Delete user profiles that have not been used in the last N days on one or more computers.

.DESCRIPTION
    Uses DCOM/WMI (Win32_UserProfile) - no WinRM or PSRemoting required.
    Skips special/built-in profiles and profiles with no recorded last-use time.
    Supports -WhatIf to preview deletions without making changes.

.PARAMETER ComputerName
    Single target computer name. Can be combined with -CsvPath.

.PARAMETER CsvPath
    Path to a CSV file with a "ComputerName" column. Can be combined with -ComputerName.

.PARAMETER DaysInactive
    Profiles unused for this many days or more will be removed. Default: 60.
    Must be at least 14, to guard against an accidental low value (e.g. 0)
    wiping out recently-used profiles fleet-wide.

.PARAMETER LogPath
    Optional path to write a plaintext log. If omitted, output goes to the console only.

.EXAMPLE
    .\ClearOldProfiles.ps1 -ComputerName PC001 -DaysInactive 30 -WhatIf

.EXAMPLE
    .\ClearOldProfiles.ps1 -CsvPath C:\computers.csv -DaysInactive 60 -LogPath C:\Logs\profiles.log
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string] $ComputerName,
    [string] $CsvPath,
    [ValidateRange(14, [int]::MaxValue)]
    [int]    $DaysInactive = 60,
    [string] $LogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Helpers ---

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line -ForegroundColor $(if ($Level -eq 'WARN') { 'Yellow' } elseif ($Level -eq 'ERROR') { 'Red' } else { 'White' })
    if ($LogPath) { Add-Content -Path $LogPath -Value $line -Encoding UTF8 }
}

function Clear-OldProfilesOnMachine {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([string]$TargetComputer)

    Write-Log "Processing: $TargetComputer"

    if (-not (Test-Connection -ComputerName $TargetComputer -Count 1 -Quiet)) {
        Write-Log "$TargetComputer is not reachable - skipping." 'WARN'
        return
    }

    $cimSession = $null
    try {
        # Win32_UserProfile via DCOM - no WinRM required, per this script's
        # design. Get-CimInstance defaults to WSMan for remote calls though,
        # so the session has to explicitly request the Dcom protocol or
        # this silently starts depending on WinRM being enabled.
        $cimOption  = New-CimSessionOption -Protocol Dcom
        $cimSession = New-CimSession -ComputerName $TargetComputer -SessionOption $cimOption -ErrorAction Stop

        # Derive the remote system drive instead of assuming C: - Windows
        # can legitimately be installed elsewhere, and Win32_OperatingSystem
        # is a cheap, always-available way to ask the remote machine
        # directly rather than guessing.
        $systemDrive = (Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $cimSession -ErrorAction Stop).WindowsDirectory |
                       Split-Path -Qualifier
        if (-not $systemDrive) { $systemDrive = 'C:' }

        $profiles = Get-CimInstance -ClassName Win32_UserProfile -CimSession $cimSession -ErrorAction Stop |
                    Where-Object { -not $_.Special -and $_.LocalPath -like "$systemDrive\Users\*" -and $_.LastUseTime }
    } catch {
        Write-Log "CIM query failed on ${TargetComputer}: $($_.Exception.Message)" 'ERROR'
        if ($cimSession) { Remove-CimSession $cimSession -ErrorAction SilentlyContinue }
        return
    }

    $cutoff = (Get-Date).AddDays(-$DaysInactive)

    foreach ($userProfile in $profiles) {
        $lastUse = $userProfile.LastUseTime
        $age     = [int]((Get-Date) - $lastUse).TotalDays

        if ($userProfile.Loaded) {
            Write-Log "KEPT     $($userProfile.LocalPath) on $TargetComputer (currently loaded/logged on - never deleted regardless of age)"
            continue
        }

        if ($lastUse -lt $cutoff) {
            if ($PSCmdlet.ShouldProcess("$TargetComputer - $($userProfile.LocalPath)", "Delete profile (last used $($lastUse.ToString('yyyy-MM-dd')), $age days ago)")) {
                try {
                    Invoke-CimMethod -InputObject $userProfile -MethodName Delete -ErrorAction Stop | Out-Null
                    Write-Log "DELETED  $($userProfile.LocalPath) on $TargetComputer (last used $($lastUse.ToString('yyyy-MM-dd')), $age days)"
                } catch {
                    Write-Log "Failed to delete $($userProfile.LocalPath) on ${TargetComputer}: $($_.Exception.Message)" 'ERROR'
                }
            }
        } else {
            Write-Log "KEPT     $($userProfile.LocalPath) on $TargetComputer (last used $($lastUse.ToString('yyyy-MM-dd')), $age days)"
        }
    }

    Remove-CimSession $cimSession -ErrorAction SilentlyContinue
}

# --- Build target list ---
$computers = [System.Collections.Generic.List[string]]::new()
if ($ComputerName) { $computers.Add($ComputerName) }
if ($CsvPath)      { (Import-Csv -Path $CsvPath).ComputerName | ForEach-Object { $computers.Add($_) } }
if ($computers.Count -eq 0) { throw 'Provide -ComputerName or -CsvPath.' }

# --- Initialize log file ---
if ($LogPath) {
    $logDir = Split-Path $LogPath
    if ($logDir -and -not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
}

Write-Log "=== ClearOldProfiles started - threshold: $DaysInactive days ==="

foreach ($computer in $computers) {
    Clear-OldProfilesOnMachine -TargetComputer $computer
}

Write-Log "=== ClearOldProfiles completed ==="
