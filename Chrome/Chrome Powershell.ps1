#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Remotely install/update Google Chrome via PsExec with CSV input and failure export.
    PsExec is used intentionally — WinRM/PSRemoting is not available in this environment.

.PARAMETER DownloadURL
    Direct URL to the Chrome Enterprise MSI.

.PARAMETER InstallerName
    Filename for the local cached copy of the installer.

.PARAMETER Arguments
    msiexec arguments passed to the remote install. Default: /qn /norestart.

.PARAMETER InputCSV
    CSV file with a "ComputerName" column listing target machines.

.PARAMETER FailedCSV
    Output CSV for machines that failed. Defaults to FailedComputers.csv beside this script.

.PARAMETER LogFile
    Log file path. Defaults to ChromeInstallLog.txt beside this script.

.PARAMETER PSToolsPath
    Folder containing psexec.exe. Defaults to C:\PSTools.

.EXAMPLE
    .\Chrome Powershell.ps1 -InputCSV .\computers.csv
#>
[CmdletBinding()]
param(
    [string] $DownloadURL   = 'https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise64.msi',
    [string] $InstallerName = 'GoogleChromeStandaloneEnterprise64.msi',
    [string] $Arguments     = '/qn /norestart',
    [Parameter(Mandatory)]
    [string] $InputCSV,
    [string] $FailedCSV     = (Join-Path $PSScriptRoot 'FailedComputers.csv'),
    [string] $LogFile       = (Join-Path $PSScriptRoot 'ChromeInstallLog.txt'),
    [string] $PSToolsPath   = 'C:\PSTools'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Preflight ---
if (-not (Test-Path $InputCSV))                       { throw "Input CSV not found: $InputCSV" }
if (-not (Test-Path (Join-Path $PSToolsPath 'psexec.exe'))) { throw "PsExec not found in: $PSToolsPath" }

$script:FailedComputers = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param([string]$Message)
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    $line | Out-File -Append -FilePath $LogFile -Encoding UTF8
    Write-Host $line
}

function Get-ChromeVersion {
    param([string]$ComputerName)
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
        Write-Log "WARNING: Could not read Chrome version on ${ComputerName}: $_"
        return $null
    }
}

function Install-ChromeRemote {
    param([string]$ComputerName)

    $currentVersion = Get-ChromeVersion -ComputerName $ComputerName
    Write-Log "[$ComputerName] Chrome before: $(if ($currentVersion) { $currentVersion } else { 'not installed' })"

    try {
        # Cache installer locally once
        $localPath = Join-Path $PSToolsPath $InstallerName
        if (-not (Test-Path $localPath)) {
            Write-Log "[$ComputerName] Downloading installer..."
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $DownloadURL -OutFile $localPath -UseBasicParsing -ErrorAction Stop
        }

        if (-not (Test-Connection -ComputerName $ComputerName -Count 2 -Quiet)) {
            Write-Log "[$ComputerName] Unreachable — skipping."
            $script:FailedComputers.Add($ComputerName)
            return
        }

        $uncTemp     = "\\$ComputerName\C$\Temp"
        $uncInstaller = "$uncTemp\$InstallerName"

        & "$PSToolsPath\psexec.exe" -accepteula "\\$ComputerName" cmd.exe /c "if not exist C:\Temp mkdir C:\Temp" 2>&1 | Out-Null
        Copy-Item -Path $localPath -Destination $uncInstaller -Force -ErrorAction Stop

        if (-not (Test-Path $uncInstaller)) {
            Write-Log "[$ComputerName] Copy failed — skipping."
            $script:FailedComputers.Add($ComputerName)
            return
        }

        & "$PSToolsPath\psexec.exe" -accepteula "\\$ComputerName" msiexec.exe /i "C:\Temp\$InstallerName" $Arguments 2>&1 | Out-Null
        $rc = $LASTEXITCODE

        if ($rc -in @(0, 3010, 1641)) {
            Start-Sleep -Seconds 15
            $newVersion = Get-ChromeVersion -ComputerName $ComputerName
            if ($newVersion -and $newVersion -ne $currentVersion) {
                Write-Log "[$ComputerName] SUCCESS — Chrome updated to $newVersion (exit $rc)."
            } else {
                Write-Log "[$ComputerName] WARNING — version unchanged after install (exit $rc, was: $currentVersion)."
                $script:FailedComputers.Add($ComputerName)
            }
            if ($rc -ne 0) { Write-Log "[$ComputerName] NOTE: Reboot pending to complete update." }
        } else {
            Write-Log "[$ComputerName] ERROR — msiexec exit code: $rc"
            $script:FailedComputers.Add($ComputerName)
        }

        Remove-Item -Path $uncInstaller -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log "[$ComputerName] ERROR: $_"
        $script:FailedComputers.Add($ComputerName)
    }
}

# --- Main ---
Write-Log "=== Chrome remote install started ==="
$computers = Import-Csv -Path $InputCSV | Select-Object -ExpandProperty ComputerName

foreach ($computer in $computers) { Install-ChromeRemote -ComputerName $computer }

if ($script:FailedComputers.Count -gt 0) {
    $script:FailedComputers | ForEach-Object { [PSCustomObject]@{ ComputerName = $_ } } |
        Export-Csv -Path $FailedCSV -NoTypeInformation -Force
    Write-Log "Failed list saved to $FailedCSV."
} else {
    Write-Log "All installations completed successfully."
}
Write-Log "=== Chrome remote install complete ==="
