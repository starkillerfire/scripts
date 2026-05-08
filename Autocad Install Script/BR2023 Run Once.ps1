<#
.SYNOPSIS
  BR Civil 3D 2023 deployment toolkit - fully automated (no external config).

.DEFAULTS
  ShareSrc  = \\dsl\SMSSource\DRO\AutoDesk\2023\BR2023
  LocalDst  = C:\Autodesk\BR2023
  Mode      = Full
  MinFreeGB = 5 GB
  Language  = en-US

.REQUIREMENTS  PowerShell 5.1+, Windows 11 x64
.LASTUPDATED   2025-06-25
#>
#Requires -RunAsAdministrator
#requires -Version 5.1

########################################################################
# --------------- CLI PARAMETERS (must precede any code) --------------#
########################################################################
param(
    [string]$ShareSrc,
    [string]$LocalDst,
    [ValidateSet('CopyOnly','ConfigOnly','Full','Cleanup')][string]$Mode,
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$VerifyHash,
    [switch]$UseBits,
    [switch]$Incremental,
    [switch]$Silent,
    [string[]]$ComputerName,
    [int]$MinFreeGB,
    [string]$Language = 'en-US',
    [switch]$InstallCleanupTask
)

########################################################################
# ----------------------  Early-exit remote wrapper -------------------#
########################################################################
if ($PSBoundParameters.ContainsKey('ComputerName')) {
    $remoteParams = $PSBoundParameters.Clone()
    [void]$remoteParams.Remove('ComputerName')
    # Use a scriptblock so named parameters splat correctly on the remote machine
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        & $using:PSCommandPath @using:remoteParams
    } -AsJob
    return
}

########################################################################
# -------------------------  House-keeping ----------------------------#
########################################################################
if ($Env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    Write-Warning 'Civil 3D requires x64; exiting.'
    exit 0
}

Set-StrictMode -Version Latest

########################################################################
# -----------------------  Helper functions ---------------------------#
########################################################################
function Get-BrConfig {
    param([System.Collections.IDictionary]$Cli)
    $defaults = @{
        ShareSrc  = '\\dsl\SMSSource\DRO\AutoDesk\2023\BR2023'
        LocalDst  = 'C:\Autodesk\BR2023'
        Mode      = 'Full'
        MinFreeGB = 5
        Language  = 'en-US'
    }
    return $defaults + $Cli
}

function Copy-BrPayload {
    [CmdletBinding()]
    param(
        [string]$ShareSrc,[string]$LocalDst,[switch]$VerifyHash,[switch]$UseBits,
        [switch]$Incremental,[int]$MinFreeGB = 5,
        [System.Management.Automation.PSCredential]$Credential,
        [switch]$Silent,[string]$LogRoot,
        [scriptblock]$ProgressAction,[scriptblock]$LogAction
    )
    & $LogAction 'Copy-Start'

    # Free-space guard
    $drive = (Split-Path $LocalDst -Qualifier).TrimEnd(':')
    $free  = [math]::Round((Get-PSDrive $drive).Free/1GB,2)
    if ($free -lt $MinFreeGB) { throw "Insufficient space ${free} GB" }

    # Resolve share (optional credentials)
    $share = $ShareSrc; $drv = $null
    if ($Credential) {
        $server = ($ShareSrc -replace '^\\\\([^\\]+)\\.*','$1')
        $drv    = New-PSDrive BRPAY FileSystem "\\$server" -Credential $Credential
        $rel    = $ShareSrc.Substring($server.Length + 3)
        $share  = "$($drv.Name):\$rel"   # single backslash — double was a path construction bug
    }

    try {
        if (-not (Test-Path "$share\*")) { throw 'Share unreachable' }

        # Integrity check
        if ($VerifyHash) {
            & $ProgressAction 'Validating files' 10
            $cat  = Join-Path $share 'BR2023.cat'
            $hash = Join-Path $share 'hashes.json'
            if (Test-Path $cat) {
                if (-not (Test-FileCatalog -Path $share -CatalogFilePath $cat -Detailed)) {
                    throw 'Catalog verification failed'
                }
            } elseif (Test-Path $hash) {
                $tbl = Get-Content $hash | ConvertFrom-Json
                foreach ($kv in $tbl) {
                    $p = Join-Path $share $kv.Key
                    if (-not (Test-Path $p)) { throw "Missing $($kv.Key)" }
                    if ((Get-FileHash $p -Algorithm SHA256).Hash.ToLower() -ne
                        $kv.Value.ToLower()) { throw "Hash mismatch $($kv.Key)" }
                }
            }
        }

        & $ProgressAction 'Copying payload' 30
        New-Item $LocalDst -ItemType Directory -Force | Out-Null

        if (-not $UseBits) {
            # /COPY:DAT only — S(ecurity) and O(wner) require SeRestorePrivilege and fail silently as SYSTEM
            $flags = '/MIR','/Z','/MT:32','/W:3','/R:3','/COPY:DAT','/NP'
            if ($Incremental) { $flags += '/XO','/XN','/XC' }
            robocopy $share $LocalDst @flags | Out-Null
            if ($LASTEXITCODE -ge 8) { throw "Robocopy failed ($LASTEXITCODE)" }
        } else {
            $bits = Start-BitsTransfer -Source (Join-Path $share '*') `
                                       -Destination $LocalDst `
                                       -TransferType Download `
                                       -Asynchronous -DisplayName 'BR2023'
            $terminalStates = 'Transferred','Error','TransientError','Fatal'
            while ($bits.JobState -notin $terminalStates) {
                $pct = if ($bits.BytesTotal -gt 0) { [math]::Round(($bits.BytesTransferred/$bits.BytesTotal)*100) } else { 0 }
                & $ProgressAction "BITS $pct%" 40
                Start-Sleep 15
            }
            if ($bits.JobState -ne 'Transferred') {
                throw "BITS transfer failed with state: $($bits.JobState) - $($bits.ErrorDescription)"
            }
            Complete-BitsTransfer -BitsJob $bits -ErrorAction Stop
        }

        & $ProgressAction 'Copy complete' 50
        & $LogAction 'Copy-End'
    } finally {
        if ($drv) { Remove-PSDrive $drv -Force -ErrorAction SilentlyContinue }
    }
}

function Invoke-BrConfig {
    [CmdletBinding()]
    param(
        [string]$LocalDst,[string]$Language='en-US',
        [scriptblock]$ProgressAction,[scriptblock]$LogAction
    )
    & $LogAction 'Config-Start'
    & $ProgressAction 'Configuring Civil 3D' 60

    Get-Process explorer,OneDrive -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue

    $acad = Get-ChildItem 'HKLM:\SOFTWARE\Autodesk\AutoCAD' -ea 0 |
            Sort-Object Name -Descending |
            ForEach-Object {
                Get-ChildItem $_.PsPath -ea 0 |
                  Where-Object { $_.PSChildName -match '^ACAD.*:409$' } |
                  ForEach-Object {
                      (Get-ItemProperty $_.PsPath -Name 'AcadLocation' -ea 0).AcadLocation
                  }
            } |
            Where-Object { Test-Path (Join-Path $_ 'acad.exe') } |
            Select-Object -First 1
    if (-not $acad) { throw 'Civil 3D not installed' }

    $exe = Join-Path $acad 'acad.exe'
    foreach ($scr in 'BR_End','BR_C3D_config') {
        $acadProc = Start-Process $exe -ArgumentList '/product','C3D','/language',$Language,
                                                     '/b',"$LocalDst\Brutil\$scr" `
                              -Wait -NoNewWindow -PassThru
        if ($acadProc.ExitCode -ne 0) { throw "acad exited $($acadProc.ExitCode)" }
    }

    if ($Env:ONEDRIVECOMMERCIAL) {
        Copy-Item "$LocalDst\BRsupprt\Civil 3D 2023 as AutoCAD.lnk" `
                  "$Env:ONEDRIVECOMMERCIAL\Desktop" -Force -ea 0
    }

    & $ProgressAction 'Config complete' 90
    & $LogAction 'Config-End'
}

function Remove-BrPayload {
    param([string]$LocalDst,[string]$LogRoot)
    Remove-Item $LocalDst -Recurse -Force -ea 0
    Remove-Item "$LogRoot\$Env:COMPUTERNAME*" -Force -ea 0
}

function Install-BrCleanupTask {
    param([string]$ScriptPath,[int]$Days=30)
    Register-ScheduledTask -TaskName 'BR_Civil3D_Cleanup' `
        -Action  (New-ScheduledTaskAction -Execute 'powershell.exe' `
                   -Argument "-File `"$ScriptPath`" -Mode Cleanup -Silent") `
        -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddDays($Days)) `
        -RunLevel Highest -Force
}

########################################################################
# -------------------------  Main execution ---------------------------#
########################################################################
function ShowProg { param($s,$p) if(-not $Silent){Write-Progress -Activity 'BR Civil 3D' -Status $s -PercentComplete $p} }

$logRoot = "$Env:ProgramData\BR2023-Logs"
New-Item $logRoot -ItemType Directory -Force -ea 0 | Out-Null
function LogMsg { param($m) Add-Content (Join-Path $logRoot 'deploy.log') `
                  "$(Get-Date -f o) [$Env:COMPUTERNAME] $m" }

$cfg = Get-BrConfig -Cli $PSBoundParameters

# Build Copy-BrPayload splat explicitly — $cfg also contains Mode/Language which the function doesn't accept
$copyArgs = @{
    ShareSrc       = $cfg.ShareSrc
    LocalDst       = $cfg.LocalDst
    MinFreeGB      = $cfg.MinFreeGB
    LogRoot        = $logRoot
    ProgressAction = ${function:ShowProg}
    LogAction      = ${function:LogMsg}
}
if ($cfg.VerifyHash)  { $copyArgs['VerifyHash']  = $true }
if ($cfg.UseBits)     { $copyArgs['UseBits']      = $true }
if ($cfg.Incremental) { $copyArgs['Incremental']  = $true }
if ($cfg.Silent)      { $copyArgs['Silent']        = $true }
if ($cfg.Credential)  { $copyArgs['Credential']   = $cfg.Credential }

try {
    switch ($cfg.Mode) {
        'Cleanup' {
            Remove-BrPayload -LocalDst $cfg.LocalDst -LogRoot $logRoot
            LogMsg 'Cleanup done'; ShowProg 'Cleanup' 100; exit 0
        }
        'CopyOnly' {
            Copy-BrPayload @copyArgs
            LogMsg 'Copy only done'
        }
        'ConfigOnly' {
            Invoke-BrConfig -LocalDst $cfg.LocalDst -Language $cfg.Language `
                            -ProgressAction ${function:ShowProg} `
                            -LogAction      ${function:LogMsg}
            LogMsg 'Config only done'
        }
        'Full' {
            Copy-BrPayload @copyArgs -ErrorAction Stop
            Invoke-BrConfig -LocalDst $cfg.LocalDst -Language $cfg.Language `
                            -ProgressAction ${function:ShowProg} `
                            -LogAction      ${function:LogMsg} -ErrorAction Stop
            LogMsg 'Full deploy done'
        }
    }

    if ($InstallCleanupTask) { Install-BrCleanupTask -ScriptPath $PSCommandPath }
    ShowProg 'Done' 100
    exit 0
}
catch {
    LogMsg "ERROR $($_.Exception.Message)"
    Write-Error $_
    exit 1
}
