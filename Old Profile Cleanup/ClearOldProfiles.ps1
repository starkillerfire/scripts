# Script to delete user profiles not used in the last N days on specified computers

# Parameters
param(
    [string]$ComputerName  = $null,   # Specify a single computer name
    [string]$CSVFilePath   = $null,   # Specify a CSV file path containing computer names in a "ComputerName" column
    [int]   $DaysInactive  = 60       # Profiles unused longer than this will be removed
)

# Get today's date
$CurrentDate = Get-Date

# Function to clear old profiles on a specified computer
function Clear-OldProfiles {
    param (
        [string]$TargetComputer
    )

    Write-Host "Processing computer: $TargetComputer"

    if (-not (Test-Connection -ComputerName $TargetComputer -Count 1 -Quiet)) {
        Write-Host "$TargetComputer is not reachable — skipping." -ForegroundColor Yellow
        return
    }

    # Get-WmiObject uses DCOM (RPC) — no WinRM required
    $UserProfiles = Get-WmiObject Win32_UserProfile -ComputerName $TargetComputer | Where-Object {
        -not $_.Special -and $_.LocalPath -like "C:\Users\*"
    }

    foreach ($UserProfile in $UserProfiles) {
        if (-not $UserProfile.LastUseTime) { continue }

        # LastUseTime is a DMTF datetime string — must convert before comparing
        $LastUseTime      = [Management.ManagementDateTimeConverter]::ToDateTime($UserProfile.LastUseTime)
        $DaysSinceLastUse = ($CurrentDate - $LastUseTime).Days

        if ($DaysSinceLastUse -ge $DaysInactive) {
            Write-Host "Deleting profile: $($UserProfile.LocalPath)  Last used: $LastUseTime"
            $UserProfile.Delete()
        } else {
            Write-Host "Active profile : $($UserProfile.LocalPath)  Last used: $LastUseTime"
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
