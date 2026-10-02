#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Check BitLocker protection status on remote computers via PsExec and export results.

.PARAMETER InputCsv
    CSV file with a "ComputerName" column. Defaults to ComputerList.csv beside this script.

.PARAMETER OutputCsv
    Destination for results. Defaults to BitLockerResults.csv beside this script.

.PARAMETER PsExecPath
    Path to PsExec.exe. Defaults to C:\PSTools\PsExec.exe.

.EXAMPLE
    .\Bitlocker Check Script.ps1 -InputCsv .\laptops.csv
#>
[CmdletBinding()]
param(
    [string] $InputCsv   = (Join-Path $PSScriptRoot 'ComputerList.csv'),
    [string] $OutputCsv  = (Join-Path $PSScriptRoot 'BitLockerResults.csv'),
    [string] $PsExecPath = 'C:\PSTools\PsExec.exe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $InputCsv))   { throw "Input CSV not found: $InputCsv" }
if (-not (Test-Path $PsExecPath)) { throw "PsExec not found: $PsExecPath" }

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($row in (Import-Csv -Path $InputCsv)) {
    $computer = $row.ComputerName

    # $computer ends up embedded in a remote command line below (via PsExec)
    # and in UNC/local file paths. Anything that doesn't look like a real
    # computer name is rejected here, before it reaches any of that, rather
    # than trusting the input CSV.
    if ($computer -notmatch '^[A-Za-z0-9\-\.]{1,63}$') {
        Write-Warning "Skipping row with invalid ComputerName: '$computer'"
        $results.Add([PSCustomObject]@{
            ComputerName         = $computer
            ProtectionStatus     = 'Invalid Name'
            EncryptionPercentage = 'N/A'
        })
        continue
    }

    Write-Host "[$computer] Checking BitLocker..."

    if (-not (Test-Connection -ComputerName $computer -Count 1 -Quiet)) {
        Write-Warning "[$computer] Offline or unreachable."
        $results.Add([PSCustomObject]@{
            ComputerName         = $computer
            ProtectionStatus     = 'Offline'
            EncryptionPercentage = 'N/A'
        })
        continue
    }

    try {
        # The remote-side output path is fixed, not built from $computer -
        # the remote command already only ever runs on that one target, so
        # there's nothing to disambiguate locally on it. $computer is only
        # needed on this (orchestrating) side, to read the result back over
        # UNC below.
        $remoteOut = 'C:\Temp\BitLockerOutput.csv'
        $uncOut    = "\\$computer\C$\Temp\BitLockerOutput.csv"

        # Built as a fixed string literal (no $computer, or any other
        # variable, interpolated into it) and sent via -EncodedCommand
        # rather than -Command, so a hostile value read from the input CSV
        # has no string-interpolation point to break out of, even though
        # $computer is already validated above. -Command built the command
        # line by interpolating $computer-derived text directly into a
        # single-quoted string, which let a comma/quote in the CSV close
        # that string early and inject arbitrary PowerShell.
        $scriptBlockString = "Get-BitLockerVolume -MountPoint 'C:' | Select-Object ProtectionStatus,EncryptionPercentage | Export-Csv -Path '$remoteOut' -NoTypeInformation -Force"
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptBlockString))

        # Clear any leftover file from a previous run against this same
        # computer first - otherwise, if PsExec fails to execute the remote
        # command this run (bad creds, firewall, remote-exec blocked), a
        # stale file from before would still pass the Test-Path check below
        # and get reported as current data.
        Remove-Item -Path $uncOut -Force -ErrorAction SilentlyContinue

        & $PsExecPath "\\$computer" -s -h -nobanner cmd.exe /c "if not exist C:\Temp mkdir C:\Temp" 2>&1 | Out-Null
        & $PsExecPath "\\$computer" -s -h -nobanner powershell.exe -ExecutionPolicy Bypass -EncodedCommand $encodedCommand 2>&1 | Out-Null

        if (-not (Test-Path $uncOut)) {
            Write-Warning "[$computer] Output file not found - BitLocker data unavailable."
            $results.Add([PSCustomObject]@{
                ComputerName         = $computer
                ProtectionStatus     = 'Not Available'
                EncryptionPercentage = 'N/A'
            })
            continue
        }

        $data = Import-Csv -Path $uncOut -ErrorAction Stop
        Remove-Item -Path $uncOut -Force -ErrorAction SilentlyContinue

        $status = $data.ProtectionStatus
        $pct    = $data.EncryptionPercentage

        $results.Add([PSCustomObject]@{
            ComputerName         = $computer
            ProtectionStatus     = $status
            EncryptionPercentage = $pct
        })

        if ($status -eq 'On') {
            Write-Host "[$computer] BitLocker ON ($pct% encrypted)." -ForegroundColor Green
        } else {
            Write-Warning "[$computer] BitLocker NOT enabled (status: $status)."
        }
    } catch {
        Write-Warning "[$computer] Error: $($_.Exception.Message)"
        $results.Add([PSCustomObject]@{
            ComputerName         = $computer
            ProtectionStatus     = 'Error'
            EncryptionPercentage = 'N/A'
        })
    }
}

$results | Export-Csv -Path $OutputCsv -NoTypeInformation -Force
Write-Host ""
Write-Host "BitLocker check complete. Results saved to $OutputCsv"
$notProtected = @($results | Where-Object { $_.ProtectionStatus -notin @('On','Offline') })
if ($notProtected.Count) {
    Write-Warning "$($notProtected.Count) machine(s) do not have BitLocker enabled."
}
