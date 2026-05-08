param (
    [string]$CsvPath          = "C:\Users\scarman\Downloads\Laptops.csv",
    [int]   $MaxProfileAgeDays = 30
)

$cutoffDate = (Get-Date).AddDays(-$MaxProfileAgeDays)

# Import the list of computers from the CSV file
$computers = Import-Csv -Path $CsvPath

# Loop through each computer
foreach ($computer in $computers) {
    $computerName = $computer.ComputerName

    Write-Output "Processing $computerName..."

    if (-not (Test-Connection -ComputerName $computerName -Count 1 -Quiet)) {
        Write-Output "$computerName is not reachable."
        continue
    }

    try {
        # Get-WmiObject uses DCOM (RPC) — no WinRM required
        $profiles = Get-WmiObject -Class Win32_UserProfile -ComputerName $computerName

        foreach ($userProfile in $profiles) {
            if ($userProfile.Special) { continue }   # skip built-in system profiles

            # LastUseTime is a DMTF datetime string — must convert before comparing
            if (-not $userProfile.LastUseTime) { continue }
            $lastUse = [Management.ManagementDateTimeConverter]::ToDateTime($userProfile.LastUseTime)

            if ($lastUse -lt $cutoffDate) {
                $profilePath = $userProfile.LocalPath
                Write-Output "Deleting profile at $profilePath on $computerName (last used $lastUse)..."
                $userProfile.Delete()
            }
        }
    } catch {
        Write-Output ("Error processing {0}: {1}" -f $computerName, $_.Exception.Message)
    }
}
