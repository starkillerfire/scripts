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
# 'Medium' here matches the fix already applied to the nested
# Clear-OldProfilesOnMachine function below (which is the one that actually
# calls ShouldProcess) - this outer scope doesn't call ShouldProcess itself,
# so 'High' here was harmless today, but left as-is it's a trap for a future
# maintainer who adds a ShouldProcess call up here and reintroduces the same
# non-interactive hang.
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
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
    # FIX 2: ConfirmImpact = 'High' matched the default $ConfirmPreference of
    # 'High', so ShouldProcess auto-prompted on every deletion unless the
    # caller passed -Confirm:$false - which hangs/throws under a
    # non-interactive SYSTEM/Intune context. 'Medium' is below the default
    # $ConfirmPreference threshold, so ShouldProcess no longer prompts
    # automatically while -WhatIf/-Confirm still work if explicitly requested.
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([string]$TargetComputer)

    Write-Log "Processing: $TargetComputer"

    # No ICMP ping pre-check here on purpose: this script's whole design is
    # to talk over DCOM/WMI, not WinRM/ping, and ICMP is commonly blocked by
    # firewall/GPO on locked-down networks even when DCOM/WMI (port 135 +
    # RPC) works fine - a ping-based gate would skip those machines as
    # "unreachable" when they're actually reachable. New-CimSession below is
    # the real connectivity test, and its failure is already caught.
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
        # FIX 2 (continued): the try/catch used to wrap only the
        # Invoke-CimMethod call, so a ShouldProcess-related terminating
        # error (e.g. still thrown if a caller forces -Confirm under a host
        # that can't prompt) escaped uncaught and aborted every remaining
        # profile/machine. Widening it around ShouldProcess itself means one
        # bad prompt/profile no longer takes down the rest of the run.
        try {
            $lastUse = $userProfile.LastUseTime
            $age     = [int]((Get-Date) - $lastUse).TotalDays

            if ($userProfile.Loaded) {
                Write-Log "KEPT     $($userProfile.LocalPath) on $TargetComputer (currently loaded/logged on - never deleted regardless of age)"
                continue
            }

            if ($lastUse -lt $cutoff) {
                if ($PSCmdlet.ShouldProcess("$TargetComputer - $($userProfile.LocalPath)", "Delete profile (last used $($lastUse.ToString('yyyy-MM-dd')), $age days ago)")) {
                    Invoke-CimMethod -InputObject $userProfile -MethodName Delete -ErrorAction Stop | Out-Null
                    Write-Log "DELETED  $($userProfile.LocalPath) on $TargetComputer (last used $($lastUse.ToString('yyyy-MM-dd')), $age days)"
                }
            } else {
                Write-Log "KEPT     $($userProfile.LocalPath) on $TargetComputer (last used $($lastUse.ToString('yyyy-MM-dd')), $age days)"
            }
        } catch {
            Write-Log "Failed to process $($userProfile.LocalPath) on ${TargetComputer}: $($_.Exception.Message)" 'ERROR'
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
