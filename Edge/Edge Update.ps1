# Remotely install/update Microsoft Edge via PsExec with CSV input and failure export.
# PsExec is used intentionally — WinRM/PSRemoting is not available in this environment.

param (
    [string]$DownloadURL   = "https://go.microsoft.com/fwlink/?LinkID=2093437",
    [string]$InstallerName = "MicrosoftEdgeEnterpriseX64.msi",
    [string]$Arguments     = "/qn /norestart",
    [string]$InputCSV      = "C:\Users\scarman\Downloads\EdgeComputerList.csv",
    [string]$FailedCSV     = "C:\Users\scarman\Downloads\FailedComputers.csv",
    [string]$LogFile       = "C:\Users\scarman\Downloads\EdgeInstallLog.txt",
    [string]$PSToolsPath   = "C:\PSTools"
)

$script:FailedComputers = @()

function Write-Log {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -Append -FilePath $LogFile
    Write-Host $Message
}

function Install-EdgePSTools {
    param (
        [string]$ComputerName,
        [string]$DownloadURL,
        [string]$InstallerName,
        [string]$InstallArguments,
        [string]$PSToolsPath
    )

    Write-Log "Attempting to install Edge on ${ComputerName}..."
    try {
        # Download installer to local PSTools folder if not already present
        $LocalInstallerPath = Join-Path $PSToolsPath $InstallerName
        if (-not (Test-Path $LocalInstallerPath)) {
            Write-Log "Downloading Edge installer..."
            Invoke-WebRequest -Uri $DownloadURL -OutFile $LocalInstallerPath -UseBasicParsing -ErrorAction Stop
            Write-Log "Installer downloaded to $LocalInstallerPath"
        }

        # Verify the remote machine is reachable
        if (-not (Test-Connection -ComputerName $ComputerName -Count 2 -Quiet)) {
            Write-Log "ERROR: ${ComputerName} is unreachable. Skipping."
            $script:FailedComputers += $ComputerName
            return
        }

        # Copy installer via admin share (\\host\C$\Temp) — no WinRM needed
        $RemoteTempUNC      = "\\$ComputerName\C$\Temp"
        $RemoteInstallerUNC = "$RemoteTempUNC\$InstallerName"

        Write-Log "Copying installer to ${ComputerName} via admin share..."
        & "$PSToolsPath\psexec.exe" -accepteula "\\$ComputerName" cmd.exe /c "if not exist C:\Temp mkdir C:\Temp" 2>&1 | Out-Null
        Copy-Item -Path $LocalInstallerPath -Destination $RemoteInstallerUNC -Force -ErrorAction Stop

        if (-not (Test-Path $RemoteInstallerUNC)) {
            Write-Log "ERROR: Installer was not copied to ${ComputerName}. Skipping."
            $script:FailedComputers += $ComputerName
            return
        }

        # Run the installer remotely via PsExec and check the exit code
        Write-Log "Executing installation on ${ComputerName}..."
        & "$PSToolsPath\psexec.exe" -accepteula "\\$ComputerName" msiexec.exe /i "C:\Temp\$InstallerName" $InstallArguments 2>&1 | Out-Null
        $ExitCode = $LASTEXITCODE

        if ($ExitCode -in @(0, 3010, 1641)) {
            Write-Log "Edge installed successfully on ${ComputerName} (exit $ExitCode)."
            if ($ExitCode -ne 0) { Write-Log "NOTE: A reboot is required on ${ComputerName} to complete the update." }
        } else {
            Write-Log "ERROR: Installation failed on ${ComputerName}. msiexec exit code: $ExitCode"
            $script:FailedComputers += $ComputerName
        }

        # Clean up the remote temp file
        Remove-Item -Path $RemoteInstallerUNC -Force -ErrorAction SilentlyContinue

    } catch {
        $ErrorDetail = $_.Exception.Message
        Write-Log "ERROR: Failed to install Edge on ${ComputerName}: $ErrorDetail"
        $script:FailedComputers += $ComputerName
    }
}

# Main
$ComputerList = Import-Csv -Path $InputCSV | Select-Object -ExpandProperty ComputerName

foreach ($Computer in $ComputerList) {
    Install-EdgePSTools -ComputerName $Computer `
                        -DownloadURL $DownloadURL `
                        -InstallerName $InstallerName `
                        -InstallArguments $Arguments `
                        -PSToolsPath $PSToolsPath
}

if ($script:FailedComputers.Count -gt 0) {
    $script:FailedComputers | ForEach-Object { [PSCustomObject]@{ ComputerName = $_ } } |
        Export-Csv -Path $FailedCSV -NoTypeInformation -Force
    Write-Log "Failed installations exported to $FailedCSV."
} else {
    Write-Log "All installations completed successfully!"
}

Write-Log "Script execution completed."
