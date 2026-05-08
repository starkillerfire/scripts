# Path to PsExec executable
$psExecPath = "C:\Sysinternals\PsExec.exe"

# Path to the CSV file with the list of computers
$csvFilePath = "C:\Users\scarman\Downloads\Laptops.csv"

# Specify the number of days for the threshold
$daysThreshold = 30

# Embed the cutoff date as a string so the remote side can parse it cleanly.
# Using a sortable format avoids locale/timezone ambiguity.
$cutoffDateString = (Get-Date).AddDays(-$daysThreshold).ToString('yyyy-MM-dd HH:mm:ss')

$computers = Import-Csv -Path $csvFilePath

foreach ($computer in $computers) {
    $computerName = $computer.ComputerName
    try {
        Write-Output "Processing $computerName..."

        # The remote command converts each profile's DMTF LastUseTime to a real DateTime
        # before comparing it against the cutoff — this avoids the FILETIME/string mismatch.
        $remoteCommand = @"
`$cutoff = [datetime]'$cutoffDateString'
Get-WmiObject Win32_UserProfile |
    Where-Object { -not `$_.Special -and `$_.LastUseTime } |
    Where-Object { [Management.ManagementDateTimeConverter]::ToDateTime(`$_.LastUseTime) -lt `$cutoff } |
    ForEach-Object { Write-Output "Deleting profile: `$(`$_.LocalPath)"; `$_.Delete() }
"@

        & "$psExecPath" -accepteula -s "\\$computerName" powershell.exe -ExecutionPolicy Bypass -Command $remoteCommand

        Write-Output "Profiles older than $daysThreshold days cleared on $computerName."
    } catch {
        Write-Output ("Error processing {0}: {1}" -f $computerName, $_)
    }
}
