#Requires -RunAsAdministrator
try {
    Suspend-BitLocker -MountPoint "C:" -RebootCount 1 -ErrorAction Stop
    Write-Host "BitLocker suspended on C:. Protection resumes automatically after the next reboot." -ForegroundColor Green
} catch {
    Write-Error "Failed to suspend BitLocker: $($_.Exception.Message)"
    exit 1
}
