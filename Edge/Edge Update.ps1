# Define variables
$DownloadURL = "https://go.microsoft.com/fwlink/?LinkID=2093437"  # Permanent link to the latest Microsoft Edge Enterprise x64 MSI
$InstallerName = "MicrosoftEdgeEnterpriseX64.msi"
$Arguments = "/qn /norestart"  # Silent install arguments
$InputCSV = "C:\Users\scarman\Downloads\EdgeComputerList.csv"  # Path to CSV with computer names (Column: ComputerName)
$FailedCSV = "C:\Users\scarman\Downloads\FailedComputers.csv"  # Path to export failed installations
$PSToolsPath = "C:\PSTools"  # Path to PSTools directory

# Import computer list from CSV
$ComputerList = Import-Csv -Path $InputCSV | Select-Object -ExpandProperty ComputerName
$FailedComputers = @()

# Function to Install Edge via PSTools
Function Install-EdgePSTools {
    param (
        [string]$ComputerName,
        [string]$DownloadURL,
        [string]$InstallerName,
        [string]$InstallArguments,
        [string]$PSToolsPath
    )
    
    Write-Host "Attempting to install Edge on $ComputerName..." -ForegroundColor Cyan
    try {
        # Download the installer locally if not already present
        if (-not (Test-Path "$PSToolsPath\$InstallerName")) {
            Invoke-WebRequest -Uri $DownloadURL -OutFile "$PSToolsPath\$InstallerName" -ErrorAction Stop
            Write-Host "Installer downloaded locally." -ForegroundColor Green
        }
        
        # Copy the installer to the remote computer using PSTools
        & "$PSToolsPath\psexec.exe" -accepteula \\$ComputerName cmd /c "mkdir C:\Temp" 2>&1 | Out-Null
        & "$PSToolsPath\psexec.exe" -accepteula \\$ComputerName cmd /c "copy \\$env:COMPUTERNAME\$PSToolsPath\$InstallerName C:\Temp\$InstallerName" 2>&1 | Out-Null
        
        # Run the installer remotely
        & "$PSToolsPath\psexec.exe" -accepteula \\$ComputerName cmd /c "msiexec /i C:\Temp\$InstallerName $InstallArguments" 2>&1 | Out-Null
        
        Write-Host "Edge installed successfully on $ComputerName." -ForegroundColor Green
    }
    catch {
        # Extract error details explicitly
        $ErrorDetail = $_.Exception.Message
        $ErrorMessage = "Failed to install Edge on " + $ComputerName + ": " + $ErrorDetail

        # Output the error message
        Write-Host $ErrorMessage -ForegroundColor Red

        # Add the computer name to the failed list
        $FailedComputers += $ComputerName
    }
}

# Main Execution Loop
foreach ($Computer in $ComputerList) {
    Install-EdgePSTools -ComputerName $Computer -DownloadURL $DownloadURL -InstallerName $InstallerName -InstallArguments $Arguments -PSToolsPath $PSToolsPath
}

# Export failed computers to CSV
if ($FailedComputers.Count -gt 0) {
    $FailedComputers | ForEach-Object { [PSCustomObject]@{ ComputerName = $_ } } | Export-Csv -Path $FailedCSV -NoTypeInformation -Force
    Write-Host "Failed installations exported to $FailedCSV." -ForegroundColor Yellow
} else {
    Write-Host "All installations completed successfully!" -ForegroundColor Green
}

Write-Host "Script execution completed." -ForegroundColor Yellow
