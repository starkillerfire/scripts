# Script to delete user profiles not used in the last 60 days on specified computers

# Parameters
param(
    [string]$ComputerName = $null,   # Specify a single computer name
    [string]$CSVFilePath = $null     # Specify a CSV file path containing computer names in a "ComputerName" column
)

# Number of days to check for inactivity
$DaysInactive = 60

# Get today's date
$CurrentDate = Get-Date

# Function to clear old profiles on a specified computer
function Clear-OldProfiles {
    param (
        [string]$TargetComputer
    )

    Write-Host "Processing computer: $TargetComputer"

    # Get list of local profiles
    $Profiles = Get-WmiObject Win32_UserProfile -ComputerName $TargetComputer | Where-Object {
        $_.Special -eq $false -and $_.LocalPath -like "C:\Users\*"
    }

    foreach ($Profile in $Profiles) {
        # Calculate the last logon date
        $LastUseTime = [Management.ManagementDateTimeConverter]::ToDateTime($Profile.LastUseTime)

        # Calculate the number of days since last use
        $DaysSinceLastUse = ($CurrentDate - $LastUseTime).Days

        if ($DaysSinceLastUse -ge $DaysInactive) {
            Write-Host "Deleting profile for user:" $Profile.LocalPath "Last used:" $LastUseTime
            Remove-WmiObject -InputObject $Profile
        } else {
            Write-Host "Profile for user:" $Profile.LocalPath "is still active, last used:" $LastUseTime
        }
    }
}

# Main logic to determine input type
if ($ComputerName) {
    # Process a single computer
    Clear-OldProfiles -TargetComputer $ComputerName
} elseif ($CSVFilePath) {
    # Load computer names from CSV and process each one
    $ComputerList = Import-Csv -Path $CSVFilePath
    foreach ($Computer in $ComputerList) {
        Clear-OldProfiles -TargetComputer $Computer.ComputerName
    }
} else {
    Write-Host "Please provide either a ComputerName or a CSVFilePath containing computer names."
}
