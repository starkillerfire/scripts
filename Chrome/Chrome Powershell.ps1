# Remotely install/update Google Chrome via PsExec with CSV input and failure export.
# PsExec is used intentionally — WinRM/PSRemoting is not available in this environment.

param (
    [string]$DownloadURL  = "https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise64.msi",
    [string]$InstallerName = "GoogleChromeStandaloneEnterprise64.msi",
    [string]$Arguments    = "/qn /norestart",
    [string]$InputCSV     = "C:\Users\scarman\Downloads\ComputerList.csv",
    [string]$FailedCSV    = "C:\Users\scarman\Downloads\FailedComputers.csv",
    [string]$LogFile      = "C:\Users\scarman\Downloads\ChromeInstallLog.txt",
    [string]$PSToolsPath  = "C:\Sysinternals"
)

$script:FailedComputers = @()

function Write-Log {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -Append -FilePath $LogFile
    Write-Host $Message
}

function Get-ChromeVersion {
    param ([string]$ComputerName)
    # Read the registry remotely via the .NET API (DCOM — no WinRM needed)
    try {
        $remoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine, $ComputerName)
        $key = $remoteReg.OpenSubKey(
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome')
        if ($key) {
            $ver = $key.GetValue('DisplayVersion')
            $key.Close()
            $remoteReg.Close()
            return $ver
        }
        $remoteReg.Close()
        return $null
    } catch {
        Write-Log "WARNING: Failed to retrieve Chrome version on ${ComputerName} - $_"
        return $null
    }
}

function Install-ChromePSTools {
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
        Write-Log "Current Chrome version on ${ComputerName}: $CurrentVersion"
    } else {
        Write-Log "Chrome not installed on ${ComputerName}. Proceeding with installation."
    }

    Write-Log "Attempting to install/update Chrome on ${ComputerName}..."
    try {
        # Download installer to local PSTools folder if not already present
        $LocalInstallerPath = Join-Path $PSToolsPath $InstallerName
        if (-not (Test-Path $LocalInstallerPath)) {
            Write-Log "Downloading Chrome installer..."
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
        $RemoteTempUNC = "\\$ComputerName\C$\Temp"
        $RemoteInstallerUNC = "$RemoteTempUNC\$InstallerName"

        Write-Log "Copying installer to ${ComputerName} via admin share..."
        & "$PSToolsPath\psexec.exe" -accepteula "\\$ComputerName" cmd.exe /c "if not exist C:\Temp mkdir C:\Temp" 2>&1 | Out-Null
        Copy-Item -Path $LocalInstallerPath -Destination $RemoteInstallerUNC -Force -ErrorAction Stop

        # Verify the copy landed
        if (-not (Test-Path $RemoteInstallerUNC)) {
            Write-Log "ERROR: Installer was not copied to ${ComputerName}. Skipping."
            $script:FailedComputers += $ComputerName
            return
        }

        # Run the installer remotely via PsExec and capture the exit code
        Write-Log "Executing installation on ${ComputerName}..."
        & "$PSToolsPath\psexec.exe" -accepteula "\\$ComputerName" msiexec.exe /i "C:\Temp\$InstallerName" $InstallArguments 2>&1 | Out-Null
        $ExitCode = $LASTEXITCODE

        if ($ExitCode -eq 0) {
            Write-Log "Chrome install initiated on ${ComputerName} (exit 0). Verifying version..."
            Start-Sleep -Seconds 10
            $UpdatedVersion = Get-ChromeVersion -ComputerName $ComputerName
            if ($UpdatedVersion -and ($UpdatedVersion -ne $CurrentVersion)) {
                Write-Log "SUCCESS: Chrome updated to $UpdatedVersion on ${ComputerName}."
            } else {
                Write-Log "ERROR: Version unchanged on ${ComputerName} after install (still $CurrentVersion)."
                $script:FailedComputers += $ComputerName
            }
        } else {
            Write-Log "ERROR: Installation failed on ${ComputerName}. msiexec exit code: $ExitCode"
            $script:FailedComputers += $ComputerName
        }

        # Clean up the remote temp file
        Remove-Item -Path $RemoteInstallerUNC -Force -ErrorAction SilentlyContinue

    } catch {
        Write-Log "ERROR: An error occurred while updating Chrome on ${ComputerName}: $_"
        $script:FailedComputers += $ComputerName
    }
}

# Main
Write-Log "Starting Google Chrome update process..."
$ComputerList = Import-Csv -Path $InputCSV | Select-Object -ExpandProperty ComputerName

foreach ($Computer in $ComputerList) {
    Install-ChromePSTools -ComputerName $Computer `
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
