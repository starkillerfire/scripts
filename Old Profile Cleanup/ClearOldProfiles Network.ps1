# Path to PsExec executable
$psExecPath = "C:\Sysinternals\PsExec.exe"

# Path to the CSV file with the list of computers
$csvFilePath = "C:\Users\scarman\Downloads\Laptops.csv"

# Specify the number of days for the threshold
$daysThreshold = 30

# Calculate the date threshold
$dateThreshold = (Get-Date).AddDays(-$daysThreshold).ToFileTime()

# Import the list of computers from the CSV
$computers = Import-Csv -Path $csvFilePath

foreach ($computer in $computers) {
    $computerName = $computer.ComputerName
    try {
        Write-Output "Processing $computerName..."

        # Define the PowerShell command to run on the remote machine as a single line
        $remoteCommand = "Get-WmiObject Win32_UserProfile | Where-Object { `$_.LastUseTime -lt $dateThreshold -and -not `$_.Special } | ForEach-Object { Write-Output `"Deleting profile for: `$($_.LocalPath)`"; `$_.Delete() }"

        # Run the command on the remote machine using PsExec
        & "$psExecPath" -accepteula -s \\$computerName powershell -Command $remoteCommand

        Write-Output "Profiles older than $daysThreshold days cleared on $computerName."
    }
    catch {
        Write-Output ("Error processing {0}: {1}" -f $computerName, $_)
    }
}
