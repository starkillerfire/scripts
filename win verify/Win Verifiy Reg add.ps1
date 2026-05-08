# Path to CSV file containing the list of computers
$csvPath = "C:\Users\scarman\Downloads\Winverify.csv"

# Path to PsExec executable (change this to your path if needed)
$psexecPath = "C:\Sysinternals\PsExec.exe"

# Define the registry fix command to apply the WinVerifyTrust patch
$regCommand = 'reg add "HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" /v EnableCertPaddingCheck /t REG_DWORD /d 1 /f'

# Import computer names from CSV
$computers = Import-Csv -Path $csvPath

# Loop through each computer and apply the registry fix using PsExec
foreach ($computer in $computers) {
    $computerName = $computer.ComputerName
    Write-Host "Processing $computerName..." -ForegroundColor Cyan

    try {
        # Run PsExec to execute the registry command on the remote computer
        $process = Start-Process -FilePath $psexecPath `
            -ArgumentList @("\\$computerName", '-s', 'cmd.exe', '/c', $regCommand) `
            -NoNewWindow -Wait -PassThru -ErrorAction Stop

        if ($process.ExitCode -eq 0) {
            Write-Host "$($computerName): WinVerifyTrust fix applied successfully." -ForegroundColor Green
        }
        else {
            Write-Host "$($computerName): Failed to apply the patch. Exit Code: $($process.ExitCode)" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "$($computerName): Error - $_" -ForegroundColor Red
    }
}

Write-Host "Script completed." -ForegroundColor Magenta
