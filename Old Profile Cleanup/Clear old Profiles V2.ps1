# Define the path to the CSV file with the list of computers
$csvPath = "C:\Users\scarman\Downloads\Laptops.csv"

# Specify the maximum age (in days) of profiles to keep
$maxProfileAgeDays = 30
$cutoffDate = (Get-Date).AddDays(-$maxProfileAgeDays)

# Import the list of computers from the CSV file
$computers = Import-Csv -Path $csvPath

# Loop through each computer
foreach ($computer in $computers) {
    $computerName = $computer.ComputerName

    Write-Output "Processing $computerName..."

    # Test if the computer is reachable
    if (Test-Connection -ComputerName $computerName -Count 1 -Quiet) {
        try {
            # Get the list of user profiles on the remote computer
            $profiles = Get-WmiObject -Class Win32_UserProfile -ComputerName $computerName

            foreach ($profile in $profiles) {
                # Check if the profile has been used in the last 30 days
                if ($profile.LastUseTime -lt $cutoffDate) {
                    # Delete the profile if it's older than the specified time
                    if ($profile.Special -eq $false) { # Skip system profiles
                        $profilePath = $profile.LocalPath
                        Write-Output "Deleting profile at $profilePath on $computerName..."

                        # Delete the profile
                        Remove-WmiObject -InputObject $profile
                    }
                }
            }
        } catch {
            $errorMessage = $_.Exception.Message
            Write-Output ("Error processing {0}: {1}" -f $computerName, $errorMessage)
        }
    } else {
        Write-Output "$computerName is not reachable."
    }
}
