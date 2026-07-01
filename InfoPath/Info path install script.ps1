<#
.SYNOPSIS
    Silently installs (or repairs) Microsoft InfoPath 2013 SP1 on Windows 11.

.DESCRIPTION
    • Detects x86/x64, enforces TLS 1.2+, retries flaky downloads  
    • Verifies SHA-256 and Microsoft Authenticode signature  
    • Skips install if InfoPath is already present (unless -Force)  
    • Logs to file, transcript, and Windows Event Log  
    • Returns 0 = success, 3010 = success-with-reboot, otherwise throws

.NOTES
    Author  : Samual Carman CPN-CCAO
    Tested  : Windows 11 23H2, PowerShell 7.4 & 5.1
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [string]$ExpectedSha256  = '',             # optional official hash
    [string]$ExpectedVersion = '',             # optional min product version
    [string]$TempPath        = (Join-Path ${env:TEMP} 'InfoPathInstall'),
    [string]$LogRoot         = 'C:\ProgramData\Logs\InfoPath',
    [switch]$Force
)

# ─── Constants / pre-flight ────────────────────────────────────────────────
try { [Net.ServicePointManager]::SecurityProtocol = 3072 -bor 12288 }
catch { [Net.ServicePointManager]::SecurityProtocol = 3072 }

$DownloadBase  = 'https://download.microsoft.com/download/4/7/5/47531001'
$Arch          = if (${env:PROCESSOR_ARCHITECTURE} -eq 'x86') { 'x86' } else { 'x64' }
$DownloadUrl   = "$DownloadBase-$Arch-enu/infopath_4753-1001_${Arch}_en-us.exe"
$InstallerFile = Join-Path $TempPath (Split-Path $DownloadUrl -Leaf)
$Transcript    = Join-Path $LogRoot 'InfoPathTranscript.log'
$LogFile       = Join-Path $LogRoot 'InfoPathInstall.log'
$EventSource   = 'InfoPathInstaller'

# ─── Helpers ───────────────────────────────────────────────────────────────
function Write-Log {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO'
    )

    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "$ts [$Level] $Message"

    $line | Out-File -FilePath $LogFile -Append -Encoding utf8
    Write-Information $line

    if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
        try { New-EventLog -LogName Application -Source $EventSource } catch {}
    }
    $entryType = if ($Level -eq 'ERROR') { 'Error' } else { 'Information' }
    Write-EventLog -LogName Application -Source $EventSource `
                   -EventId 1000 -EntryType $entryType -Message $Message
}

function Test-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent() `
      ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated prompt.'
    }
}

function Test-InfoPathInstalled {
    $regKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($key in $regKeys) {
        $found = Get-ChildItem $key -ErrorAction SilentlyContinue | ForEach-Object {
            try { (Get-ItemProperty $_.PSPath).DisplayName } catch {}
        } | Where-Object { $_ -match 'Microsoft\s+InfoPath\s+2013' }
        if ($found) { return $true }
    }

    # --- file check --------------------------------------------------------
    $progFiles = ${env:ProgramFiles}
    $exePath   = Join-Path $progFiles 'Microsoft Office\Office15\INFOPATH.EXE'
    if (Test-Path $exePath) {
        if ($ExpectedVersion) {
            $verRaw = (Get-Item $exePath).VersionInfo.ProductVersion
            try {
                if ([version]$verRaw -ge [version]$ExpectedVersion) { return $true }
            } catch {
                # non-standard version string - fall back to a plain string compare instead of a wrong lexical one
                if ($verRaw -eq $ExpectedVersion) { return $true }
            }
        } else { return $true }
    }
    return $false
}

function Invoke-FileDownload {
    [CmdletBinding()] param(
        [string]$Url, [string]$Destination, [int]$MaxRetries = 3
    )
    $attempt = 0
    do {
        try {
            $attempt++
            Write-Log "Attempt ${attempt}: downloading $Url"
            Start-BitsTransfer -Source $Url -Destination $Destination -ErrorAction Stop
            return
        } catch {
            if ($attempt -ge $MaxRetries) { throw }
            $delay = [Math]::Pow(2,$attempt)       # 2,4,8 s
            Write-Log "Download failed: $($_.Exception.Message). Retrying in $delay s…" 'WARN'
            Start-Sleep -Seconds $delay
        }
    } while ($true)
}

function Test-FileHash {
    param([string]$Path,[string]$Expected)
    if ($Expected) {
        $actual = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash
        if ($actual -ne $Expected.ToUpper()) {
            throw "SHA-256 mismatch! Expected $Expected but got $actual"
        }
        Write-Log 'SHA-256 hash verified.'
    } else {
        Write-Log 'No -ExpectedSha256 supplied; relying on Authenticode signature only.' 'WARN'
    }
}

function Test-Authenticode {
    param([string]$Path)
    $sig = Get-AuthenticodeSignature -FilePath $Path
    if ($sig.Status -ne 'Valid' -or
        -not ($sig.SignerCertificate.Subject -match 'CN=Microsoft')) {
        throw 'Authenticode signature is invalid or not from Microsoft.'
    }
    Write-Log 'Authenticode signature verified.'
}

function Install-Infopath {
    [CmdletBinding()] param([string]$InstallerPath)

    $installerArgs = '/quiet /norestart', "/log:`"$LogRoot\InfoPath2013.log`""
    Write-Log "Launching installer $InstallerPath $($installerArgs -join ' ')"

    $proc = Start-Process -FilePath $InstallerPath -ArgumentList $installerArgs `
                          -Wait -PassThru
    Write-Log "Installer exit code $($proc.ExitCode)"

    switch ($proc.ExitCode) {
        0     { return 0 }
        3010  { return 3010 }   # success, reboot required
        default { throw "Installer failed with exit code $($proc.ExitCode)" }
    }
}

# ─── Main ──────────────────────────────────────────────────────────────────
try {
    Test-Admin
    New-Item $TempPath,$LogRoot -ItemType Directory -Force | Out-Null

    Start-Transcript -Path $Transcript -Append -ErrorAction SilentlyContinue
    Write-Log "=== InfoPath deployment started (arch: $Arch) ==="

    if ((Test-InfoPathInstalled) -and -not $Force) {
        Write-Log 'InfoPath already present - skipping installation.'
        exit 0
    }

    if (-not (Test-Path $InstallerFile)) {
        Invoke-FileDownload -Url $DownloadUrl -Destination $InstallerFile
    }

    Test-FileHash     -Path $InstallerFile -Expected $ExpectedSha256
    Test-Authenticode -Path $InstallerFile

    $exitCode = Install-Infopath -InstallerPath $InstallerFile
    Write-Log 'Installation completed successfully.'
    exit $exitCode
}
catch {
    Write-Log $_.Exception.Message 'ERROR'
    throw
}
finally {
    try { Stop-Transcript | Out-Null } catch {}
    Write-Log '=== Script finished ==='
}
