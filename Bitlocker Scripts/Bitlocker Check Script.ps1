# Define parameters for input file, output file, and PsExec path  
param (
    [string]$InputCsv = "C:\Users\scarman\Downloads\LaptopCPN.csv", # Path to the input CSV file
    [string]$OutputCsv = "C:\Users\scarman\NonBitLockerLaptopCPNComputers.csv", # Path to the output CSV file
    [string]$PsExecPath = "C:\Sysinternals\PsExec.exe" # Path to PsExec.exe
)

# Import computer names from the CSV file
$Computers = Import-Csv -Path $InputCsv -ErrorAction Stop

# Initialize an array to store computers without BitLocker enabled
$NonBitLockerComputers = @()

# Loop through each computer
foreach ($Computer in $Computers) {
    $ComputerName = $Computer.ComputerName
    Write-Host "Processing computer: $ComputerName"

    # Check if the computer is reachable
    if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet) {
        try {
            # Define paths for temporary output and error log files on the remote machine
            $RemoteTranscriptFile = "C:\Temp\BitLockerTranscript_$ComputerName.txt"

            # Run Get-BitLockerVolume remotely using PsExec and capture output/errors in transcript
            $BitLockerCommand = "& '$PsExecPath' \\$ComputerName -s -h -nobanner powershell -ExecutionPolicy Bypass -Command `"Start-Transcript -Path $RemoteTranscriptFile -Force; Get-BitLockerVolume -MountPoint 'C:' | Select-Object -Property ProtectionStatus, EncryptionPercentage; Stop-Transcript`""
            Invoke-Expression $BitLockerCommand

            # Retrieve and parse the transcript file if available
            if (Test-Path $RemoteTranscriptFile) {
                $BitLockerStatus = Get-Content -Path $RemoteTranscriptFile
                Remove-Item -Path $RemoteTranscriptFile -Force

                $ProtectionStatus, $EncryptionPercentage = $null, "N/A"
                
                if ($BitLockerStatus -match "ProtectionStatus\s*:\s*(\w+)") {
                    $ProtectionStatus = $matches[1]
                }

                # Only add to NonBitLockerComputers if BitLocker is not protecting the drive
                if ($ProtectionStatus -ne "1" -and $ProtectionStatus -ne "On") {
                    if ($BitLockerStatus -match "EncryptionPercentage\s*:\s*(\d+)") {
                        $EncryptionPercentage = [int]$matches[1]
                    }
                    $NonBitLockerComputers += [PSCustomObject]@{
                        ComputerName = $ComputerName
                        ProtectionStatus = $ProtectionStatus
                        EncryptionPercentage = $EncryptionPercentage
                    }
                    Write-Host "$ComputerName does not have BitLocker enabled."
                } else {
                    Write-Host "$ComputerName has BitLocker enabled and protecting the drive."
                }
            } else {
                # No valid BitLocker information found
                Write-Host "No valid BitLocker information for $ComputerName."
                $NonBitLockerComputers += [PSCustomObject]@{
                    ComputerName = $ComputerName
                    ProtectionStatus = "Not Available"
                    EncryptionPercentage = "N/A"
                }
            }
        } catch {
            Write-Host "Could not connect to $ComputerName or error occurred during BitLocker check." -ForegroundColor Red
            Write-Host "Error details: $_" -ForegroundColor Yellow
            $NonBitLockerComputers += [PSCustomObject]@{
                ComputerName = $ComputerName
                ProtectionStatus = "Error"
                EncryptionPercentage = "N/A"
            }
        }
    } else {
        # Computer is offline or unreachable
        Write-Host "$ComputerName is offline or unreachable." -ForegroundColor Gray
        $NonBitLockerComputers += [PSCustomObject]@{
            ComputerName = $ComputerName
            ProtectionStatus = "Offline"
            EncryptionPercentage = "N/A"
        }
    }
}

# Add export date and time to the results
$ExportTime = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
$NonBitLockerComputers += [PSCustomObject]@{
    ComputerName = "Export Date and Time"
    ProtectionStatus = $ExportTime
    EncryptionPercentage = ""
}

# Export the results to a CSV file
$NonBitLockerComputers | Export-Csv -Path $OutputCsv -NoTypeInformation -Force

Write-Host "BitLocker check completed. Results saved to $OutputCsv"
