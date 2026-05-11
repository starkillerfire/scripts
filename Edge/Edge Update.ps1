#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Remotely install/update Microsoft Edge via PsExec with CSV input and failure export.
    PsExec is used intentionally — WinRM/PSRemoting is not available in this environment.

.PARAMETER DownloadURL
    Direct URL to the Edge Enterprise MSI.

.PARAMETER InstallerName
    Filename for the local cached copy of the installer.

.PARAMETER Arguments
    msiexec arguments passed to the remote install. Default: /qn /norestart.

.PARAMETER InputCSV
    CSV file with a "ComputerName" column listing target machines.

.PARAMETER FailedCSV
    Output CSV for machines that failed. Defaults to FailedComputers.csv beside this script.

.PARAMETER LogFile
    Log file path. Defaults to EdgeInstallLog.txt beside this script.

.PARAMETER PSToolsPath
    Folder containing psexec.exe. Defaults to C:\PSTools.

.EXAMPLE
    .\Edge Update.ps1 -InputCSV .\computers.csv
#>
[CmdletBinding()]
param(
    [string] $DownloadURL   = 'https://go.microsoft.com/fwlink/?LinkID=2093437',
    [string] $InstallerName = 'MicrosoftEdgeEnterpriseX64.msi',
    [string] $Arguments     = '/qn /norestart',
    [Parameter(Mandatory)]
    [string] $InputCSV,
    [string] $FailedCSV     = (Join-Path $PSScriptRoot 'FailedComputers.csv'),
    [string] $LogFile       = (Join-Path $PSScriptRoot 'EdgeInstallLog.txt'),
    [string] $PSToolsPath   = 'C:\PSTools'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Preflight ---
if (-not (Test-Path $InputCSV))                            { throw "Input CSV not found: $InputCSV" }
if (-not (Test-Path (Join-Path $PSToolsPath 'psexec.exe'))) { throw "PsExec not found in: $PSToolsPath" }

$script:FailedComputers = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param([string]$Message)
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    $line | Out-File -Append -FilePath $LogFile -Encoding UTF8
    Write-Host $line
}

function Install-EdgeRemote {
    param([string]$ComputerName)

    Write-Log "[$ComputerName] Starting Edge install..."
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

        $uncTemp      = "\\$ComputerName\C$\Temp"
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
            Write-Log "[$ComputerName] SUCCESS — Edge installed (exit $rc)."
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
Write-Log "=== Edge remote install started ==="
$computers = Import-Csv -Path $InputCSV | Select-Object -ExpandProperty ComputerName

foreach ($computer in $computers) { Install-EdgeRemote -ComputerName $computer }

if ($script:FailedComputers.Count -gt 0) {
    $script:FailedComputers | ForEach-Object { [PSCustomObject]@{ ComputerName = $_ } } |
        Export-Csv -Path $FailedCSV -NoTypeInformation -Force
    Write-Log "Failed list saved to $FailedCSV."
} else {
    Write-Log "All installations completed successfully."
}
Write-Log "=== Edge remote install complete ==="
