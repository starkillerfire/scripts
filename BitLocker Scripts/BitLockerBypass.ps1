#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Suspend BitLocker on a drive for one reboot. Protection resumes automatically.

.PARAMETER MountPoint
    Drive to suspend. Defaults to C:.

.PARAMETER RebootCount
    Number of reboots before BitLocker re-enables. Defaults to 1.

.EXAMPLE
    .\BitLockerBypass.ps1
    .\BitLockerBypass.ps1 -MountPoint D: -RebootCount 2
#>
[CmdletBinding()]
param(
    [string] $MountPoint  = 'C:',
    [int]    $RebootCount = 1
)

try {
    Suspend-BitLocker -MountPoint $MountPoint -RebootCount $RebootCount -ErrorAction Stop
    Write-Host "BitLocker suspended on $MountPoint for $RebootCount reboot(s). Protection resumes automatically." -ForegroundColor Green
} catch {
    Write-Error "Failed to suspend BitLocker on ${MountPoint}: $($_.Exception.Message)"
    exit 1
}
