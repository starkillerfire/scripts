#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Remotely install/update Microsoft Edge via PsExec with CSV input and failure export.
    PsExec is used intentionally - WinRM/PSRemoting is not available in this environment.

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
    [string] $PSToolsPath   = 'C:\PSTools',
    [int]    $MaxCacheAgeHours = 24
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

function Get-VerifiedInstaller {
    # Downloads the installer once and verifies it's validly signed by
    # Microsoft before it's ever pushed to a single machine. Without this, a
    # compromised CDN response or DNS hijack on $DownloadURL would get
    # copied out to every computer in $InputCSV via PsExec as SYSTEM - this
    # is the only thing standing between that and a fleet-wide compromise.
    $localPath = Join-Path $PSToolsPath $InstallerName
    $isStale = (Test-Path $localPath) -and
               ((Get-Item $localPath).LastWriteTime -lt (Get-Date).AddHours(-$MaxCacheAgeHours))
    if ($isStale) {
        Write-Log "Cached installer is older than $MaxCacheAgeHours hour(s) - re-downloading rather than pushing a stale build to the whole fleet."
        Remove-Item -Path $localPath -Force -ErrorAction SilentlyContinue
    }
    if (-not (Test-Path $localPath)) {
        Write-Log "Downloading installer from $DownloadURL ..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $DownloadURL -OutFile $localPath -UseBasicParsing -ErrorAction Stop
    }

    $sig = Get-AuthenticodeSignature -FilePath $localPath
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        Remove-Item -Path $localPath -Force -ErrorAction SilentlyContinue
        throw "Installer at $localPath failed Authenticode validation (status: $($sig.Status)) - refusing to deploy it to any machine."
    }
    Write-Log "Installer Authenticode signature verified (Microsoft Corporation): $localPath"
    return $localPath
}

function Install-EdgeRemote {
    param([string]$ComputerName, [string]$LocalInstallerPath)

    Write-Log "[$ComputerName] Starting Edge install..."
    try {
        $localPath = $LocalInstallerPath

        if (-not (Test-Connection -ComputerName $ComputerName -Count 2 -Quiet)) {
            Write-Log "[$ComputerName] Unreachable - skipping."
            $script:FailedComputers.Add($ComputerName)
            return
        }

        $uncTemp      = "\\$ComputerName\C$\Temp"
        $uncInstaller = "$uncTemp\$InstallerName"

        & "$PSToolsPath\psexec.exe" -accepteula "\\$ComputerName" cmd.exe /c "if not exist C:\Temp mkdir C:\Temp" 2>&1 | Out-Null
        Copy-Item -Path $localPath -Destination $uncInstaller -Force -ErrorAction Stop

        if (-not (Test-Path $uncInstaller)) {
            Write-Log "[$ComputerName] Copy failed - skipping."
            $script:FailedComputers.Add($ComputerName)
            return
        }

        # $Arguments is one scalar string (e.g. '/qn /norestart'). Passed as
        # a single token, PowerShell re-quotes it as ONE argument because it
        # contains a space, so msiexec would receive "/qn /norestart" as a
        # single unparseable switch instead of two. Splitting on whitespace
        # passes each flag through as its own argument.
        & "$PSToolsPath\psexec.exe" -accepteula "\\$ComputerName" msiexec.exe /i "C:\Temp\$InstallerName" ($Arguments -split '\s+') 2>&1 | Out-Null
        $rc = $LASTEXITCODE

        if ($rc -in @(0, 3010, 1641)) {
            Write-Log "[$ComputerName] SUCCESS - Edge installed (exit $rc)."
            if ($rc -ne 0) { Write-Log "[$ComputerName] NOTE: Reboot pending to complete update." }
        } else {
            Write-Log "[$ComputerName] ERROR - msiexec exit code: $rc"
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
$verifiedInstallerPath = Get-VerifiedInstaller

foreach ($computer in $computers) { Install-EdgeRemote -ComputerName $computer -LocalInstallerPath $verifiedInstallerPath }

if ($script:FailedComputers.Count -gt 0) {
    $script:FailedComputers | ForEach-Object { [PSCustomObject]@{ ComputerName = $_ } } |
        Export-Csv -Path $FailedCSV -NoTypeInformation -Force
    Write-Log "Failed list saved to $FailedCSV."
} else {
    Write-Log "All installations completed successfully."
}
Write-Log "=== Edge remote install complete ==="
exit ($(if ($script:FailedComputers.Count -gt 0) { 1 } else { 0 }))
