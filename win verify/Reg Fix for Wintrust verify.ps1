# Enable hardening changes for WinVerifyTrust Signature Validation Vulnerability (CVE-2013-3900)
# Reference: Microsoft Security Advisory

# Define the registry paths and values
$registryPath = "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config"
$keyName = "EnableCertPaddingCheck"
$keyValue = 1  # Enable hardening changes

# Function to enable the hardening changes for a single system
function Enable-WinVerifyTrustHardening {
    param (
        [string]$TargetSystem
    )

    try {
        if ($TargetSystem -eq $null -or $TargetSystem -eq "localhost") {
            # Local system
            $targetRegistryPath = $registryPath
        } else {
            # Remote system
            $targetRegistryPath = "\\$TargetSystem\$registryPath"
        }

        # Check if the registry path exists, create it if not
        if (-not (Test-Path -Path $targetRegistryPath)) {
            Write-Output "Registry path does not exist on $TargetSystem. Creating: $targetRegistryPath"
            New-Item -Path $targetRegistryPath -Force | Out-Null
        }

        # Set the registry key to enable hardening changes
        Write-Output "Setting registry key on $TargetSystem: $keyName to $keyValue"
        Set-ItemProperty -Path $targetRegistryPath -Name $keyName -Value $keyValue -Force

        Write-Output "Hardening changes for WinVerifyTrust enabled successfully on $TargetSystem."
        return [PSCustomObject]@{
            System = $TargetSystem
            Status = "Success"
        }
    } catch {
        Write-Error "Failed to enable hardening changes on $TargetSystem: $_"
        return [PSCustomObject]@{
            System = $TargetSystem
            Status = "Failed"
            ErrorMessage = $_.Exception.Message
        }
    }
}

# Main logic for execution
if ($env:USERNAME -ne "SYSTEM") {
    Write-Output "This script must be run as SYSTEM. Use PsExec or a similar tool."
    exit 1
}

# Import CSV
$inputCsvPath = "systems.csv"  # Path to the input CSV
$outputCsvPath = "results.csv"  # Path to the output CSV

if (-not (Test-Path -Path $inputCsvPath)) {
    Write-Error "Input CSV file not found: $inputCsvPath"
    exit 1
}

$systems = Import-Csv -Path $inputCsvPath
$resultList = @()

foreach ($system in $systems) {
    $TargetSystem = $system.SystemName
    $result = Enable-WinVerifyTrustHardening -TargetSystem $TargetSystem
    $resultList += $result
}

# Export results to CSV
$resultList | Export-Csv -Path $outputCsvPath -NoTypeInformation -Force
Write-Output "Results exported to: $outputCsvPath"
