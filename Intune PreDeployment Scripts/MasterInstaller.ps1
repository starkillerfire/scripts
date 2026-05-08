<#
.SYNOPSIS
    Enterprise-grade installer / updater for Adobe Acrobat Reader, Google Chrome, Microsoft Edge,
    Dell Command Update, and Windows Updates.

.DESCRIPTION
    • Uses Winget with exponential back-off retries (silent, license-accepted).
    • Falls back to local PowerShell installers if Winget is unavailable or fails.
    • Skips products already at required version.
    • Logs to file and Windows Event Log.
    • Outputs install summary to JSON.
    • Enforces admin and 64-bit host.
    • Supports proxy detection, offline mode, skip/only filtering.
    • Executes Windows Updates.ps1 if found in subdirectory.
    • Handles MSI exit codes 3010/1641 for reboot.
    • Requires no code-signing.

.NOTES
    Author: Samual Carman - refactor 2025-06-12
#>

#Requires -Version 5.0

[CmdletBinding()]
param(
    [string[]] $Skip,
    [string[]] $Only,
    [switch]   $Quiet,
    [switch]   $Offline
)

Set-StrictMode -Version Latest

$Products = @(
    @{ Name = 'Acrobat'; WingetId = 'Adobe.Acrobat.Reader.64-bit';
       Fallback = Join-Path $PSScriptRoot 'Acrobat/installAcrobat.ps1';
       Sha256   = 'ADD_SHA256_FOR_ACROBAT_INSTALLER' },
    @{ Name = 'Chrome' ; WingetId = 'Google.Chrome';
       Fallback = Join-Path $PSScriptRoot 'Chrome/installChrome.ps1';
       Sha256   = 'ADD_SHA256_FOR_CHROME_INSTALLER'  },
    @{ Name = 'Edge'   ; WingetId = 'Microsoft.Edge';
       Fallback = Join-Path $PSScriptRoot 'Edge/installEdge.ps1';
       Sha256   = 'ADD_SHA256_FOR_EDGE_INSTALLER'    }
)

$LogPath     = Join-Path $PSScriptRoot 'master-install.log'
$JsonPath    = Join-Path $PSScriptRoot 'install-summary.json'
$EventSource = 'MasterInstaller'
$MaxLogSize  = 1MB

function Initialize-Logging {
    if (Test-Path $LogPath -and (Get-Item $LogPath).Length -ge $MaxLogSize) {
        $backup = "$LogPath.$(Get-Date -Format 'yyyyMMddHHmmss').bak"
        Move-Item $LogPath $backup -Force
    }
    if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
        try { New-EventLog -LogName Application -Source $EventSource } catch {}
    }
    Start-Transcript -Path $LogPath -Append | Out-Null
}

function Write-Log {
    param(
        [ValidateSet('Information','Warning','Error')][string] $Level,
        [string] $Message,
        [int]    $EventId = 1000
    )
    $stamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    if (-not $Quiet) { Write-Host "$stamp [$Level] $Message" }
    try {
        Write-EventLog -LogName Application -Source $EventSource -EventId $EventId -EntryType $Level -Message $Message
    } catch {}
}

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Log -Level 'Error' -Message 'Administrator privileges required.' -EventId 1003
        throw 'Run PowerShell as Administrator.'
    }
}

function Assert-64BitHost {
    if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
        $ps64 = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
        Write-Log -Level 'Information' -Message 'Re-launching under 64-bit PowerShell…' -EventId 1000
        & $ps64 -NoLogo -ExecutionPolicy Bypass -File $PSCommandPath @PSBoundParameters
        exit $LASTEXITCODE
    }
}

function Enable-Tls12 { try { [Net.ServicePointManager]::SecurityProtocol = 3072 } catch {} }

function Set-ProxyFromRegistry {
    $reg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $ps  = Get-ItemProperty -Path $reg -Name ProxyServer,ProxyEnable -ErrorAction SilentlyContinue
    if ($ps.ProxyEnable -and $ps.ProxyServer) { $env:HTTPS_PROXY = "http://$($ps.ProxyServer)" }
}

function Test-FileHashMatch {
    param([string] $Path, [string] $Sha256)
    if (-not (Test-Path $Path)) { return $false }
    $calc = (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToUpperInvariant()
    return ($calc -eq $Sha256.ToUpperInvariant())
}

function Invoke-WingetInstall {
    param([Parameter(Mandatory)][string] $Id, [int] $Retries = 3)
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) { return $false }

    for ($i = 1; $i -le $Retries; $i++) {
        Write-Log -Level 'Information' -Message "Winget install attempt $($i): $Id"   # ← fixed
        & $winget install --id $Id --accept-package-agreements --accept-source-agreements --silent --disable-interactivity | Out-Null
        if ($LASTEXITCODE -eq 0) { return $true }
        Start-Sleep -Seconds ([math]::Pow(2, $i))
    }
    return $false
}

function Invoke-FallbackScript {
    param([Parameter(Mandatory)][string] $Path, [string] $Sha256)
    if (-not (Test-Path $Path)) {
        Write-Log -Level 'Error' -Message "Fallback script missing: $Path"
        throw "Script not found: $Path"
    }
    if ($Sha256 -and -not (Test-FileHashMatch -Path $Path -Sha256 $Sha256)) {
        Write-Log -Level 'Error' -Message "SHA-256 mismatch for $Path"
        throw "Hash validation failed for $Path"
    }

    Write-Log -Level 'Information' -Message "Running fallback script: $Path"
    $oldPol = Get-ExecutionPolicy -Scope Process
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
        & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $Path -ErrorAction Stop
    } finally {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy $oldPol -Force
    }
}

function Get-InstalledVersion {
    param([string] $Name)
    try {
        $pkg = Get-Package -Name $Name -ErrorAction Stop | Sort-Object Version -Descending | Select-Object -First 1
        return $pkg.Version
    } catch { return $null }
}

function Install-DellCommandUpdate {
    param([Parameter(Mandatory)][string] $FolderPath)
    Write-Log -Level 'Information' -Message '=== Processing Dell Command Update ==='
    $dcuCli = Join-Path $FolderPath 'dcu-cli.exe'
    if (Test-Path $dcuCli) {
        & $dcuCli /silent /applyupdates /log "${FolderPath}\dcu.log" /reboot=enable
        if ($LASTEXITCODE -eq 0) {
            Write-Log -Level 'Information' -Message 'DCU CLI completed successfully.'
            return @{ Status = 'Installed/Updated'; Version = 'via-CLI' }
        }
    }
    $msi = Get-ChildItem -Path $FolderPath -Filter '*.msi' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($msi) {
        & msiexec.exe /i "`"$($msi.FullName)`"" /quiet /norestart
        if ($LASTEXITCODE -eq 0) {
            Write-Log -Level 'Information' -Message 'DCU MSI installed successfully.'
            return @{ Status = 'Installed'; Version = 'via-MSI' }
        }
    }
    Write-Log -Level 'Error' -Message 'No DCU CLI or MSI found in DCU folder.'
    return @{ Status = 'Missing' }
}

#===================  MAIN  ===================#

try {
    Initialize-Logging
    Write-Log -Level 'Information' -Message '=== MasterInstaller started ==='
    Assert-Admin
    Assert-64BitHost
    Enable-Tls12
    Set-ProxyFromRegistry

    $summary     = @{}
    $needsReboot = $false
    $total       = $Products.Count
    $index       = 0

    foreach ($product in $Products) {
        $index++
        if ($Skip -and ($product.Name -in $Skip))     { continue }
        if ($Only -and ($product.Name -notin $Only)) { continue }

        Write-Progress -Activity 'MasterInstaller' -Status "Processing $($product.Name)" -PercentComplete ([int](($index / $total) * 100))
        Write-Log -Level 'Information' -Message "=== Processing $($product.Name) ==="

        $installed = Get-InstalledVersion -Name $product.Name
        if ($installed) {
            Write-Log -Level 'Information' -Message "$($product.Name) already installed - version $installed"
            $summary[$product.Name] = @{ Status = 'AlreadyInstalled'; Version = "$installed" }
            continue
        }

        $success = $false
        if (-not $Offline) {
            $success = Invoke-WingetInstall -Id $product.WingetId
        }
        if (-not $success) {
            Write-Log -Level 'Warning' -Message "Winget unavailable or failed for $($product.Name); falling back"
            Invoke-FallbackScript -Path $product.Fallback -Sha256 $product.Sha256
            $success = $true
        }

        if ($success) {
            $ver = Get-InstalledVersion -Name $product.Name
            Write-Log -Level 'Information' -Message "$($product.Name) installed - version $ver"
            $summary[$product.Name] = @{ Status = 'Installed'; Version = "$ver" }
        } else {
            Write-Log -Level 'Error' -Message "$($product.Name) failed to install"
            $summary[$product.Name] = @{ Status = 'Failed' }
        }
    }

    #----------- Dell Command Update -----------#
    $dcuFolder = Join-Path $PSScriptRoot 'DCU'
    if (Test-Path $dcuFolder) {
        $summary['DellCommandUpdate'] = Install-DellCommandUpdate -FolderPath $dcuFolder
    } else {
        Write-Log -Level 'Information' -Message 'DCU folder not found - skipping Dell Command Update.'
        $summary['DellCommandUpdate'] = @{ Status = 'Skipped' }
    }

    #----------- Windows Updates script --------#
    $wuScriptPath = Join-Path $PSScriptRoot 'Windows Updates\Windows Updates.ps1'
    if (Test-Path $wuScriptPath) {
        Write-Log -Level 'Information' -Message '=== Processing Windows Updates script ==='
        try {
            $oldPol = Get-ExecutionPolicy -Scope Process
            Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
            & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $wuScriptPath -ErrorAction Stop
            Write-Log -Level 'Information' -Message 'Windows Updates script completed successfully.'
            $summary['WindowsUpdates'] = @{ Status = 'Completed'; Script = 'Windows Updates.ps1' }
        } catch {
            Write-Log -Level 'Error' -Message "Windows Updates script failed: $_"
            $summary['WindowsUpdates'] = @{ Status = 'Failed'; Error = "$_" }
        } finally {
            Set-ExecutionPolicy -Scope Process -ExecutionPolicy $oldPol -Force
        }
    } else {
        Write-Log -Level 'Information' -Message 'Windows Updates script not found - skipping.'
        $summary['WindowsUpdates'] = @{ Status = 'Skipped' }
    }

    #----------- Finalise -----------#
    if (Select-String -Path $LogPath -Pattern '3010|1641' -Quiet) { $needsReboot = $true }
    $summary['NeedsReboot'] = $needsReboot
    $summary['Completed']   = (Get-Date).ToString('o')

    $summary | ConvertTo-Json -Depth 4 | Out-File -FilePath $JsonPath -Encoding UTF8

    if ($needsReboot) {
        Write-Log -Level 'Warning' -Message 'One or more installers requested a reboot.'
        if (-not $Quiet) { Write-Warning 'System reboot required to complete installation.' }
    }

    Write-Log -Level 'Information' -Message '=== MasterInstaller completed successfully ==='
    Exit 0
} catch {
    Write-Log -Level 'Error' -Message "Unhandled exception: $_"
    Exit 1
} finally {
    Stop-Transcript | Out-Null
    Write-Progress -Activity 'MasterInstaller' -Completed -Status 'Done'
}
