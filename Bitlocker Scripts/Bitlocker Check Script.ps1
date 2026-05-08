# Define parameters for input file, output file, and PsExec path
param (
    [string]$InputCsv    = "C:\Users\scarman\Downloads\LaptopCPN.csv",
    [string]$OutputCsv   = "C:\Users\scarman\NonBitLockerLaptopCPNComputers.csv",
    [string]$PsExecPath  = "C:\Sysinternals\PsExec.exe"
)

# Import computer names from the CSV file
$Computers = Import-Csv -Path $InputCsv -ErrorAction Stop

# Initialize an array to store computers without BitLocker enabled
$NonBitLockerComputers = @()

foreach ($Computer in $Computers) {
    $ComputerName = $Computer.ComputerName
    Write-Host "Processing computer: $ComputerName"

    if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)) {
        Write-Host "$ComputerName is offline or unreachable." -ForegroundColor Gray
        $NonBitLockerComputers += [PSCustomObject]@{
            ComputerName         = $ComputerName
            ProtectionStatus     = "Offline"
            EncryptionPercentage = "N/A"
        }
        continue
    }

    try {
        # PsExec writes a CSV to C:\Temp on the remote machine.
        # We read it back via the admin share (no WinRM needed).
        $RemoteOutputFile = "C:\Temp\BitLockerOutput_$ComputerName.csv"
        $UNCOutputFile    = "\\$ComputerName\C$\Temp\BitLockerOutput_$ComputerName.csv"

        # Ensure C:\Temp exists on the remote machine
        & $PsExecPath "\\$ComputerName" -s -h -nobanner cmd.exe /c "if not exist C:\Temp mkdir C:\Temp" 2>&1 | Out-Null

        # Run Get-BitLockerVolume on the remote machine and export results as CSV
        $psCommand = "Get-BitLockerVolume -MountPoint 'C:' | " +
                     "Select-Object -Property ProtectionStatus,EncryptionPercentage | " +
                     "Export-Csv -Path '$RemoteOutputFile' -NoTypeInformation -Force"

        & $PsExecPath "\\$ComputerName" -s -h -nobanner powershell.exe `
            -ExecutionPolicy Bypass -Command $psCommand 2>&1 | Out-Null

        if (-not (Test-Path $UNCOutputFile)) {
            Write-Host "No output file found for $ComputerName — BitLocker data unavailable." -ForegroundColor Yellow
            $NonBitLockerComputers += [PSCustomObject]@{
                ComputerName         = $ComputerName
                ProtectionStatus     = "Not Available"
                EncryptionPercentage = "N/A"
            }
            continue
        }

        $BitLockerData = Import-Csv -Path $UNCOutputFile -ErrorAction Stop
        Remove-Item -Path $UNCOutputFile -Force -ErrorAction SilentlyContinue

        # ProtectionStatus exports as "On" (protected) or "Off" (not protected)
        $ProtectionStatus     = $BitLockerData.ProtectionStatus
        $EncryptionPercentage = $BitLockerData.EncryptionPercentage

        if ($ProtectionStatus -ne "On") {
            $NonBitLockerComputers += [PSCustomObject]@{
                ComputerName         = $ComputerName
                ProtectionStatus     = $ProtectionStatus
                EncryptionPercentage = $EncryptionPercentage
            }
            Write-Host "$ComputerName does NOT have BitLocker enabled." -ForegroundColor Yellow
        } else {
            Write-Host "$ComputerName has BitLocker ON and the drive is protected." -ForegroundColor Green
        }

    } catch {
        Write-Host "Error checking $ComputerName`: $_" -ForegroundColor Red
        $NonBitLockerComputers += [PSCustomObject]@{
            ComputerName         = $ComputerName
            ProtectionStatus     = "Error"
            EncryptionPercentage = "N/A"
        }
    }
}

# Export results
$NonBitLockerComputers | Export-Csv -Path $OutputCsv -NoTypeInformation -Force
Write-Host "BitLocker check completed. Results saved to $OutputCsv"
