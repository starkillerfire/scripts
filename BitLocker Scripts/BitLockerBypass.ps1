#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Suspend BitLocker on a drive for one reboot. Protection resumes automatically.

.PARAMETER MountPoint
    Drive to suspend. Defaults to C:.

.PARAMETER RebootCount
    Number of reboots before BitLocker re-enables. Defaults to 1. Must be between 1 and 15 -
    0 would suspend protection indefinitely, contradicting the automatic-resume behavior above.

.PARAMETER Justification
    Required. Reason BitLocker is being suspended on this machine, logged alongside the action
    for after-the-fact audit.

.EXAMPLE
    .\BitLockerBypass.ps1 -Justification 'Firmware update requires BitLocker suspended'
    .\BitLockerBypass.ps1 -MountPoint D: -RebootCount 2 -Justification 'Driver install, ticket #1234'
#>
[CmdletBinding()]
param(
    [string] $MountPoint  = 'C:',

    [ValidateRange(1, 15)]
    [int]    $RebootCount = 1,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $Justification
)

try {
    Write-Host "Justification: $Justification" -ForegroundColor Cyan
    Suspend-BitLocker -MountPoint $MountPoint -RebootCount $RebootCount -ErrorAction Stop
    Write-Host "BitLocker suspended on $MountPoint for $RebootCount reboot(s). Protection resumes automatically." -ForegroundColor Green
} catch {
    Write-Error "Failed to suspend BitLocker on ${MountPoint}: $($_.Exception.Message)"
    exit 1
}
