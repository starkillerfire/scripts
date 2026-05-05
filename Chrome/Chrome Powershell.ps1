### PowerShell Script to Remotely Install Google Chrome latest Version via PSTools with CSV Input and Export Failures

# Define variables
$DownloadURL = "https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise64.msi"  # Chrome official download link
$InstallerName = "GoogleChromeStandaloneEnterprise64.msi"
$Arguments = "/qn /norestart"  # Silent install arguments
$InputCSV = "C:\Users\scarman\Downloads\ComputerList.csv"  # Path to CSV with computer names (Column: ComputerName)
$FailedCSV = "C:\Users\scarman\Downloads\FailedComputers.csv"  # Path to export failed installations
$LogFile = "C:\Users\scarman\Downloads\ChromeInstallLog.txt"  # Log file path
$PSToolsPath = "C:\Sysinternals"  # Path to PSTools directory
$FailedComputers = @()

# Function to log messages
Function Write-Log {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -Append -FilePath $LogFile
    Write-Host $Message
}

# Function to get the installed Chrome version
Function Get-ChromeVersion {
    param ([string]$ComputerName)
    try {
        $ChromeVersion = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $ChromePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome"
            if (Test-Path $ChromePath) {
                (Get-ItemProperty -Path $ChromePath).DisplayVersion
            } else {
                return $null
            }
        } -ErrorAction Stop
        return $ChromeVersion
    } catch {
        Write-Log "WARNING: Failed to retrieve Chrome version on ${ComputerName} - $_"
        return $null
    }
}

# Function to Install Chrome via PSTools
Function Install-ChromePSTools {
    param (
        [string]$ComputerName,
        [string]$DownloadURL,
        [string]$InstallerName,
        [string]$InstallArguments,
        [string]$PSToolsPath
    )
    
    Write-Log "Checking Chrome version on ${ComputerName}..."
    $CurrentVersion = Get-ChromeVersion -ComputerName $ComputerName

    if ($CurrentVersion) {
        Write-Log "Current Chrome Version on ${ComputerName}: $CurrentVersion"
    } else {
        Write-Log "Chrome is not installed on ${ComputerName}. Proceeding with installation."
    }

    Write-Log "Attempting to install/update Chrome on ${ComputerName}..."
    try {
        # Download the installer if not already present
        if (-not (Test-Path "$PSToolsPath\$InstallerName")) {
            Write-Log "Downloading Chrome installer..."
            Invoke-WebRequest -Uri $DownloadURL -OutFile "$PSToolsPath\$InstallerName" -ErrorAction Stop
            Write-Log "Installer downloaded successfully."
        }

        # Verify network connectivity
        if (-not (Test-Connection -ComputerName $ComputerName -Count 2 -Quiet)) {
            Write-Log "ERROR: ${ComputerName} is unreachable. Skipping."
            $FailedComputers += $ComputerName
            return
        }

        # Copy the installer to the remote computer
        Write-Log "Copying installer to ${ComputerName}..."
        & "$PSToolsPath\psexec.exe" -accepteula \\$ComputerName cmd /c "mkdir C:\Temp" 2>&1 | Out-Null
        & "$PSToolsPath\psexec.exe" -accepteula \\$ComputerName cmd /c "copy \\$env:COMPUTERNAME\$PSToolsPath\$InstallerName C:\Temp\$InstallerName" 2>&1 | Out-Null
        
        # Verify that the installer was copied successfully
        $FileCheck = & "$PSToolsPath\psexec.exe" -accepteula \\$ComputerName cmd /c "if exist C:\Temp\$InstallerName echo Exists"
        if ($FileCheck -notmatch "Exists") {
            Write-Log "ERROR: Installer was not copied to ${ComputerName}. Skipping."
            $FailedComputers += $ComputerName
            return
        }

        # Run the installer remotely and capture exit code
        Write-Log "Executing installation on ${ComputerName}..."
        & "$PSToolsPath\psexec.exe" -accepteula \\$ComputerName cmd /c "msiexec /i C:\Temp\$InstallerName $InstallArguments" 2>&1 | Out-Null
        $ExitCode = $LASTEXITCODE

        # Verify installation success
        if ($ExitCode -eq 0) {
            Write-Log "Chrome update process initiated successfully on ${ComputerName}."

            # Validate update by checking version again
            Start-Sleep -Seconds 10
            $UpdatedVersion = Get-ChromeVersion -ComputerName $ComputerName

            if ($UpdatedVersion -and ($UpdatedVersion -ne $CurrentVersion)) {
                Write-Log "SUCCESS: Chrome successfully updated to version $UpdatedVersion on ${ComputerName}."
            } else {
                Write-Log "ERROR: Chrome update may have failed on ${ComputerName}. Version remains $CurrentVersion."
                $FailedComputers += $ComputerName
            }
        } else {
            Write-Log "ERROR: Installation failed on ${ComputerName}. Exit code: $ExitCode"
            $FailedComputers += $ComputerName
        }
    } catch {
        Write-Log "ERROR: An error occurred while updating Chrome on ${ComputerName}: $_"
        $FailedComputers += $ComputerName
    }
}

# Main Execution Loop
Write-Log "Starting Google Chrome update process..."
$ComputerList = Import-Csv -Path $InputCSV | Select-Object -ExpandProperty ComputerName

foreach ($Computer in $ComputerList) {
    Install-ChromePSTools -ComputerName $Computer -DownloadURL $DownloadURL -InstallerName $InstallerName -InstallArguments $Arguments -PSToolsPath $PSToolsPath
}

# Export failed computers to CSV
if ($FailedComputers.Count -gt 0) {
    $FailedComputers | ForEach-Object { [PSCustomObject]@{ ComputerName = $_ } } | Export-Csv -Path $FailedCSV -NoTypeInformation -Force
    Write-Log "Failed installations exported to $FailedCSV."
} else {
    Write-Log "All installations completed successfully!"
}

Write-Log "Script execution completed."
