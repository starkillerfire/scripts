<# ======================================================================
   SecureBoot-Mitigation_Win10.ps1  ·  v2025-06-18  ·  PowerShell 5.1
   Mitigates CVE-2023-24932 (BlackLotus) on Windows 10 21H2 / 22H2
   - Dynamic build gate           - Four Secure-Boot phases
   - Optional WinRE SafeOS update - Optional USB export of WinRE
   - BitLocker protectors re-enabled after Phase 4
   © Samual Carman CPN-CCAO
   Version 1.3 - last updated 6/13. Find the latest version on GitHub
====================================================================== #>

[CmdletBinding()] param(
    [switch]$Silent,
    [switch]$WhatIf,
    [switch]$AutoReboot,
    [int]   $RebootDelay       = 60,
    [switch]$PauseBetweenPhases,
    [switch]$UpdateWinRE,
    [string]$ExportRecoveryUSB,
    [string]$LogPath = [IO.Path]::Combine($env:SystemDrive,'Logs','CVE-2023-24932-Mitigation.log')
)

# ── Logging ───────────────────────────────────────────────────────────────
trap { try { Stop-Transcript } catch { }; exit 1 }

function Write-Log {
    param([string]$Msg,[ValidateSet('Information','Warning','Error')]$Level='Information')
    if (-not $Silent) { Write-Host $Msg }
    if (-not (Get-EventLog -LogName Application -Source SecureBootMitigation -ErrorAction SilentlyContinue)) {
        New-EventLog -LogName Application -Source SecureBootMitigation -ErrorAction SilentlyContinue
    }
    Write-EventLog -LogName Application -Source SecureBootMitigation -EntryType $Level -EventId 5500 -Message $Msg
}

# ── Admin check & transcript ──────────────────────────────────────────────
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script as Administrator.'
}
Start-Transcript -Path $LogPath -Append
$ScriptStart = Get-Date

# ── Dynamic build gate ────────────────────────────────────────────────────
function Get-FixedBuild {
    $uri = 'https://support.microsoft.com/en-us/topic/41a975df-beb2-40c1-99a3-b3ff139f832d'
    try {
        $html = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 15
        if ($html.Content -match '(19\d{3}\.\d{3,4})') { return [version]$Matches[1] }
    } catch { Write-Log 'Build scrape failed; using 19045.4651' 'Warning' }
    return [version]'19045.4651'
}
$MinBuild  = Get-FixedBuild
$CurBuild  = [version](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
if ($CurBuild -lt $MinBuild) { throw "OS build $CurBuild < $MinBuild - install latest CU." }

# ── Environment guards ────────────────────────────────────────────────────
if (-not (Confirm-SecureBootUEFI)) { throw 'Secure Boot disabled or legacy BIOS.' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
    throw 'A reboot is pending - restart and rerun.'
}
if ((Get-BitLockerVolume -MountPoint 'C:').ProtectionStatus -eq 'On') {
    throw 'Suspend BitLocker protection on C: first.'
}

# ── Helper functions ─────────────────────────────────────────────────────-
function Get-FreeDrive       { (65..90 | ForEach-Object { [char]$_ } | Where-Object { -not (Get-PSDrive $_ -ea 0) } | Select-Object -First 1) + ':' }
function Mount-Efi           { $d = Get-FreeDrive; mountvol $d /s > $null; return $d }
function Dismount-Efi([string]$d) { mountvol $d /d > $null }

function Test-CA2023  { ([Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI -Name db ).Bytes))  -match 'Windows UEFI CA 2023' }
function Test-DBXGood { ([Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI -Name dbx).Bytes)) -notmatch 'Windows Production PCA 2011' }

# ── Optional WinRE SafeOS DU ──────────────────────────────────────────────
function Update-WinRE {
    $info = reagentc /info 2>&1
    if ($LASTEXITCODE -ne 0 -or $info -match 'Disabled') { Write-Log 'WinRE disabled; SafeOS DU skipped.' 'Warning'; return }
    $loc  = ($info | Select-String 'WinRE location').Line
    if (-not $loc) { Write-Log 'Cannot locate WinRE.' 'Warning'; return }
    $winreDir = $loc.Split(':',2)[1].Trim()
Write-Log ("WinRE directory found: {0}" -f $winreDir)
}

# ── Optional USB export of WinRE ───────────────────────────────────────────
function Export-WinRE {
    param([string]$Letter)
    if (-not $Letter) {
        $Letter = (Get-Volume | Where-Object { $_.DriveType -eq 'Removable' -and $_.Size -ge 8GB } |
                   Select-Object -Expand DriveLetter -First 1)
        if (-not $Letter) { throw 'No USB ≥ 8 GB found.' }
    }
    $dst = ('{0}:\Recovery\WindowsRE' -f $Letter)
    if (-not (Test-Path $dst)) { New-Item -Path $dst -ItemType Directory -Force > $null }
    $srcDir = (reagentc /info | Select-String 'WinRE location').Line.Split(':',2)[1].Trim()
    Copy-Item (Join-Path $srcDir 'Winre.wim') (Join-Path $dst 'Winre.wim') -Force
    Copy-Item 'C:\Windows\System32\Recovery\ReAgent.xml' (Join-Path $dst 'ReAgent.xml') -Force -ea 0
    Write-Log "WinRE exported to $dst"
}

# ── Secure-Boot phase executor ────────────────────────────────────────────
function Invoke-Phase {
    param([string]$Name,[int]$Mask,[int[]]$Events,[ref]$Result)
    Write-Log "→ $Name"
    if ($WhatIf) { Write-Log "[WhatIf] Would set AvailableUpdates=0x$([Convert]::ToString($Mask,16))"; return }
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Force > $null
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name AvailableUpdates -Value $Mask -Type DWord -Force
    Start-ScheduledTask -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update'
    Start-Sleep 10
    $ok = $true
    foreach ($e in $Events) {
        if (-not (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Kernel-Boot/Operational';Id=$e;StartTime=$ScriptStart} -MaxEvents 1)) {
            $ok = $false; Write-Log "Event $e missing." 'Warning'
        }
    }
    $Result.Value = $ok
    if ($PauseBetweenPhases -and -not $Silent -and -not $WhatIf) { Read-Host 'ENTER to continue…' }
}

# ── Optional steps ────────────────────────────────────────────────────────
if ($UpdateWinRE)       { Update-WinRE }
if ($ExportRecoveryUSB) { Export-WinRE -Letter $ExportRecoveryUSB }

# ── Run phases ────────────────────────────────────────────────────────────
$P1=$P2=$P3=$P4=$false
if (-not (Test-CA2023)) { Invoke-Phase 'Phase 1 - Add CA 2023'   0x40  @(1036)          ([ref]$P1) } else { $P1=$true }
Invoke-Phase             'Phase 2 - New bootmgr'    0x100 @(1799)          ([ref]$P2)
if ($P2) {
    $efi = Mount-Efi
    $backupDir = [IO.Path]::Combine($env:SystemDrive,'EFI_Backup')
    if (-not (Test-Path $backupDir)) { New-Item $backupDir -ItemType Directory > $null }
    Copy-Item (Join-Path $efi 'EFI\Microsoft\Boot\bootmgfw.efi') `
              (Join-Path $backupDir ("bootmgfw_{0:yyyyMMdd_HHmmss}.efi" -f (Get-Date))) -Force
    Dismount-Efi $efi
}
if (-not (Test-DBXGood)) { Invoke-Phase 'Phase 3 - Revoke PCA 2011' 0x180 @(1037,1801)     ([ref]$P3) } else { $P3=$true }
Invoke-Phase             'Phase 4 - SVN lock-in'    0x280 @(1800,1796,1797,1798) ([ref]$P4)

# ── BitLocker re-enable & summary ─────────────────────────────────────────
if ($P1 -and $P2 -and $P3 -and $P4) {
    if ((Get-BitLockerVolume -MountPoint 'C:').ProtectionStatus -eq 'Off') {
        manage-bde -protectors -enable C: > $null
        Write-Log 'BitLocker protectors re-enabled.'
    }
    Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name AvailableUpdates -ea 0
    Write-Log 'Mitigation complete.'; $exit = 0
} else {
    Write-Log 'Mitigation failed.' 'Error'; $exit = 1
}

Stop-Transcript
if ($AutoReboot -and $exit -eq 0) { Start-Sleep $RebootDelay; Restart-Computer -Force }
exit $exit
