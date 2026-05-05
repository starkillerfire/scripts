<#
.SYNOPSIS
    Apply the Microsoft Windows 11 DISA STIG baseline with PowerSTIG DSC
    and then run additional manual remediations.

.DESCRIPTION
    Merged/updated script:

    - Uses PowerSTIG for Windows 11 with latest OrgSettings XML (autodetected).
    - Configures LCM for push mode and ApplyAndAutoCorrect.
    - Applies the Windows 11 STIG DSC baseline if PowerSTIG is available.
    - Runs manual registry and OS hardening steps for specific STIG IDs,
      including additional CAT I items from the latest SCC report.

.PARAMETER OrgSettingsPath
    Optional explicit path to a WindowsClient-11-*.org.default.xml file. If this
    is not supplied, the script will automatically pick the latest available
    WindowsClient-11 OrgSettings file from the installed PowerSTIG module.

.NOTES
    - Requires PowerShell running as Administrator.
    - Intended for unmanaged Windows 11 systems.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OrgSettingsPath
)

# ─────────────────────────────────────────────────────────────────────────────
# Ensure running as Administrator
# ─────────────────────────────────────────────────────────────────────────────
If (-not ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent() `
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please run this script as Administrator."
    Exit 1
}

Write-Host "Starting Windows 11 STIG enforcement (PowerSTIG + manual remediations)..." -ForegroundColor Cyan

# ─────────────────────────────────────────────────────────────────────────────
# Execution Policy and PowerSTIG Installation
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "Setting execution policy and ensuring PowerSTIG is available..." -ForegroundColor Cyan

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force

# Try to get PowerSTIG; if missing, attempt to install
$psStigModule = Get-Module -ListAvailable -Name PowerSTIG

if (-not $psStigModule) {
    try {
        Install-Module -Name PowerSTIG -Scope AllUsers -Force -ErrorAction Stop
        Write-Host "PowerSTIG module installed." -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to install PowerSTIG from PSGallery: $($_.Exception.Message)"
    }
    $psStigModule = Get-Module -ListAvailable -Name PowerSTIG
}

# Install dependencies if we now have PowerSTIG
if ($psStigModule) {
    $psStigModule.RequiredModules | ForEach-Object {
        if (-not (Get-Module -ListAvailable -Name $_.Name)) {
            try {
                Install-Module -Name $_.Name -Scope AllUsers -Force -ErrorAction Stop
                Write-Host "Installed dependency: $($_.Name)" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to install dependency $($_.Name): $($_.Exception.Message)"
            }
        }
    }
}
else {
    Write-Warning "PowerSTIG module is still not available. DSC baseline will be skipped; manual remediations will still run."
}

# ─────────────────────────────────────────────────────────────────────────────
# Configure WinRM and Firewall for DSC Push
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "Configuring WinRM/WS-Man for DSC Push..." -ForegroundColor Cyan

Enable-PSRemoting -Force -SkipNetworkProfileCheck

if (-not (Get-NetFirewallRule -Name 'Allow-WSMan-AllProfiles' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule `
        -Name 'Allow-WSMan-AllProfiles' `
        -DisplayName 'Allow WS-Man Inbound (All Profiles)' `
        -Protocol TCP `
        -LocalPort 5985 `
        -Action Allow `
        -Profile Any | Out-Null
    Write-Host "Firewall opened on port 5985 for all profiles." -ForegroundColor Green
}

try {
    Test-WSMan -ComputerName localhost | Out-Null
    Write-Host "WS-Man connectivity OK." -ForegroundColor Green
}
catch {
    Write-Warning "WS-Man still not reachable. Check service/firewall."
}

# ─────────────────────────────────────────────────────────────────────────────
# Configure LCM for Push Mode and AutoCorrect
# ─────────────────────────────────────────────────────────────────────────────
[DSCLocalConfigurationManager()]
Configuration LCM_PushConfig {
    Settings {
        ConfigurationMode    = 'ApplyAndAutoCorrect'
        AllowModuleOverwrite = $true
        RefreshMode          = 'Push'
        RebootNodeIfNeeded   = $true
    }
}

$LCMPath = Join-Path $env:ProgramData 'PowerSTIG\LCM'
LCM_PushConfig -OutputPath $LCMPath
Set-DscLocalConfigurationManager -Path $LCMPath -Verbose -Force | Out-Null
Write-Host "Local Configuration Manager configured for push mode." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────────────────────
# Apply PowerSTIG Windows 11 Baseline (if module available)
# ─────────────────────────────────────────────────────────────────────────────
if ($psStigModule) {

    Import-Module PowerSTIG -ErrorAction Stop
    Write-Host "Imported PowerSTIG module." -ForegroundColor Cyan

    if ($OrgSettingsPath) {
        if (-not (Test-Path $OrgSettingsPath)) {
            throw "Specified OrgSettingsPath '$OrgSettingsPath' was not found."
        }
        $orgDefault = (Resolve-Path $OrgSettingsPath).Path
    }
    else {
        $psMod = Get-Module -ListAvailable -Name PowerSTIG |
                 Sort-Object Version -Descending |
                 Select-Object -First 1

        if (-not $psMod) {
            throw "PowerSTIG module is not available after install. Cannot locate STIG data."
        }

        $stigDataRoot = Join-Path $psMod.ModuleBase 'StigData\Processed'
        $candidateFiles = Get-ChildItem -Path $stigDataRoot -Filter 'WindowsClient-11-*.org.default.xml' -ErrorAction SilentlyContinue

        if (-not $candidateFiles) {
            throw "No WindowsClient-11-*.org.default.xml files were found under '$stigDataRoot'. Verify that the PowerSTIG data files are present."
        }

        $candidateFiles = $candidateFiles |
            ForEach-Object {
                $m = [regex]::Match($_.Name, 'WindowsClient-11-(?<ver>[0-9\.]+)\.org\.default\.xml', 'IgnoreCase')
                [pscustomobject]@{
                    File    = $_
                    Version = if ($m.Success) { [version]$m.Groups['ver'].Value } else { [version]'0.0' }
                }
            } |
            Sort-Object Version -Descending

        $orgDefault = $candidateFiles[0].File.FullName
    }

    # Derive STIG version from filename, fallback to 2.2 if not parseable
    $stigVersion = '2.2'
    $m2 = [regex]::Match((Split-Path $orgDefault -Leaf), 'WindowsClient-11-(?<ver>[0-9\.]+)\.org\.default\.xml', 'IgnoreCase')
    if ($m2.Success) {
        $stigVersion = $m2.Groups['ver'].Value
    }

    Write-Host "Using OrgSettings: $orgDefault" -ForegroundColor Green
    Write-Host "Detected Windows 11 STIG version: $stigVersion" -ForegroundColor Green

    Configuration Win11_STIG_v2_2 {
        param (
            [Parameter(Mandatory)]
            [string] $OrgSettingsPath,

            [Parameter(Mandatory)]
            [string] $StigVersion
        )

        Import-DscResource -ModuleName PowerSTIG

        Node 'localhost' {
            WindowsClient STIGBaseline {
                OsVersion   = '11'
                StigVersion = $StigVersion
                OrgSettings = $OrgSettingsPath
            }
        }
    }

    $MofPath = Join-Path $env:ProgramData 'PowerSTIG\Mof'
    if (-not (Test-Path $MofPath)) {
        New-Item -Path $MofPath -ItemType Directory -Force | Out-Null
    }

    Write-Host "Compiling DSC configuration (Windows 11 STIG v$stigVersion)..." -ForegroundColor Cyan
    Win11_STIG_v2_2 -OrgSettingsPath $orgDefault -StigVersion $stigVersion -OutputPath $MofPath

    Write-Host "Applying STIG baseline via DSC (push mode)..." -ForegroundColor Cyan
    Start-DscConfiguration -Path $MofPath -Wait -Force -Verbose

    Write-Host "✅ PowerSTIG baseline enforcement on Windows 11 complete." -ForegroundColor Green
}
else {
    Write-Warning "Skipping PowerSTIG DSC baseline because the module is not available."
}

# ─────────────────────────────────────────────────────────────────────────────
# Manual Windows 11 STIG remediations
# (original + new CAT I fixes merged)
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "Starting post-DSC manual STIG remediation..." -ForegroundColor Cyan

# 1) Data Execution Prevention — OptOut (V-253283)
bcdedit /set "{current}" nx OptOut
Write-Host "Configured DEP to OptOut."

# 2) Account Lockout Policies (V-253297, V-253298, V-253299)
net accounts /lockoutduration:15
net accounts /lockoutthreshold:3
net accounts /lockoutwindow:15
Write-Host "Account lockout policies applied."

# 3) Password Policies (V-253300, V-253302, V-253303)
net accounts /uniquepw:24
net accounts /minpwage:1
net accounts /minpwlen:14
Write-Host "Password policies applied."

# 4) Event Log Sizes (V-253337, V-253338, V-253339)
$evtSizes = @{
    'Application' = '32KB'
    'Security'    = '1024MB'
    'System'      = '32KB'
}

foreach ($log in $evtSizes.Keys) {
    $raw = $evtSizes[$log]
    $sizeValue = switch -Regex ($raw) {
        'KB$' { [int]($raw -replace 'KB','') * 1KB; break }
        'MB$' { [int]($raw -replace 'MB','') * 1MB; break }
        default { 0 }
    }

    if ($sizeValue -gt 0) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\$log" `
            -Name "MaxSize" -Type DWord -Value $sizeValue
    }
}
Write-Host "Event log sizes configured."

# 5) Early Launch Antimalware Boot-Start Driver Initialization Policy (V-253372)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\EarlyLaunch" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\EarlyLaunch" `
    -Name "RequireBootStartDriverInitializationPolicy" -Type DWord -Value 2
Write-Host "ELAM Boot-Start Driver Initialization Policy set."

# 6) Windows Hello PIN Complexity (V-253401)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\PINComplexity" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\PINComplexity" `
    -Name "MinimumPINLength" -Type DWord -Value 6
Write-Host "Windows Hello PIN complexity enforced."

# 7) Disable & Rename Built-In Accounts (V-253432, V-253435, V-253436)
Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue

Disable-LocalUser -Name "Administrator"
Rename-LocalUser  -Name "Administrator" -NewName "Admin_$((Get-Random) % 10000)"
Rename-LocalUser  -Name "Guest"         -NewName "Guest_$((Get-Random) % 10000)"
Write-Host "Built-in Administrator and Guest accounts updated."

# 8) Machine Inactivity Timeout (V-253444)
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "InactivityTimeoutSecs" -Type DWord -Value 900
Write-Host "Machine inactivity timeout configured (900 seconds)."

# 9) Legal Notice Banner (V-253445)
$caption = "Warning"
$text    = @"
-The USG routinely intercepts and monitors communications on this IS for purposes including,
but not limited to, penetration testing, COMSEC monitoring, network operations and defense,
personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
"@
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "LegalNoticeCaption" -Type String -Value $caption
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "LegalNoticeText"    -Type String -Value $text
Write-Host "Legal notice banner configured."

# 10) Smart-Card Removal Behavior (V-253448)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    -Name "SCRemoveOption" -Type String -Value "1"
Write-Host "Smart-card removal behavior set to Lock Workstation."

# 11) Command-Line Process Auditing (V-257770)
auditpol.exe /set /subcategory:"Process Creation" /failure:enable
Write-Host "Process Creation failure auditing enabled."

# 12) Disable Windows Copilot (V-268317)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" `
    -Name "EnableCopilot" -Type DWord -Value 0
Write-Host "Windows Copilot disabled."

# 13) Block Third-Party Suggestions (V-253425)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
    -Name "DisableSuggestions" -Type DWord -Value 1
Write-Host "Third-party suggestions blocked."

# 14) Disable Lock-Screen Toast Notifications (V-253477)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Notifications\Settings" `
    -Name "DisableLockScreenToast" -Type DWord -Value 1
Write-Host "Lock-screen toast notifications disabled."

# 15) SEHOP must be enabled (V-253284)
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
    -Name "DisableExceptionChainValidation" -Type DWord -Value 0
Write-Host "SEHOP (Exception Chain Validation) enabled."

# 16) Solicited Remote Assistance must not be allowed (V-253382)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    -Name "fAllowToGetHelp" -Type DWord -Value 0
Write-Host "Solicited Remote Assistance disabled."

# 17) Autoplay must be turned off for non-volume devices (V-253386)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
    -Name "NoAutoplayfornonVolume" -Type DWord -Value 1
Write-Host "Autoplay disabled for non-volume devices."

# 18) Default autorun behavior must prevent autorun commands (V-253387)
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -Name "NoAutorun" -Type DWord -Value 1
Write-Host "Autorun disabled."

# 19) Autoplay must be disabled for all drives (V-253388)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -Name "NoDriveTypeAutoRun" -Type DWord -Value 0x000000ff
Write-Host "Autoplay disabled for all drive types."

# 20) 'Always install with elevated privileges' must be disabled (V-253411)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" `
    -Name "AlwaysInstallElevated" -Type DWord -Value 0
New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" `
    -Name "AlwaysInstallElevated" -Type DWord -Value 0
Write-Host "Windows Installer 'AlwaysInstallElevated' disabled (machine and user)."

# 21) WinRM client must not use Basic authentication (V-253416)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
    -Name "AllowBasic" -Type DWord -Value 0
Write-Host "WinRM client Basic authentication disabled."

# 22) WinRM service must not use Basic authentication (V-253418)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
    -Name "AllowBasic" -Type DWord -Value 0
Write-Host "WinRM service Basic authentication disabled."

# 23) Anonymous enumeration of shares must be restricted (V-253454)
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RestrictAnonymous" -Type DWord -Value 1
Write-Host "Anonymous enumeration of shares restricted."

# 24) LAN Manager authentication level must be NTLMv2 only (V-253462)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" -Type DWord -Value 5
Write-Host "LAN Manager authentication level set to NTLMv2 only."

Write-Host "STIG remediation complete." -ForegroundColor Green
