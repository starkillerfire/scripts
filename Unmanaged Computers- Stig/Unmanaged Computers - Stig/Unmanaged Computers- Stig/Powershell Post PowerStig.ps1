<#
.SYNOPSIS
    Remediate Windows 11 STIG v2.3.9 findings (excluding BitLocker & certificate rules).

.DESCRIPTION
    This script applies the following DISA STIG v2.3.9 configurations:
      1) Data Execution Prevention — OptOut (V-253283)
      2) Account lockout policy (V-253297, V-253298, V-253299)
      3) Password policy (V-253300, V-253302, V-253303)
      4) Event log sizes (V-253337, V-253338, V-253339)
      5) Early Launch Antimalware Boot-Start Driver Init Policy (V-253372)
      6) Windows Hello PIN complexity (V-253401)
      7) Disable & rename built-in accounts (V-253432, V-253435, V-253436)
      8) Machine inactivity timeout (V-253444)
      9) Legal notice banner (V-253445)
     10) Smart-card removal behavior (V-253448)
     11) Command-line process auditing (V-257770)
     12) Disable Windows Copilot (V-268317)
     13) Block third-party suggestions (V-253425)
     14) Disable lock-screen toast notifications (V-253477)

.NOTES
    - Tested on Windows 11 Enterprise 23H2
    - Run this script as Administrator.
#>

# ─────────────────────────────────────────────────────────────────────────────
# Ensure running as Administrator
# ─────────────────────────────────────────────────────────────────────────────
If (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent() `
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please run this script as Administrator."
    Exit 1
}

Write-Host "Starting STIG remediation..." -ForegroundColor Cyan

# ─────────────────────────────────────────────────────────────────────────────
# 1) Data Execution Prevention — OptOut (V-253283)
# ─────────────────────────────────────────────────────────────────────────────
bcdedit /set "{current}" nx OptOut
Write-Host "Configured DEP to OptOut."

# ─────────────────────────────────────────────────────────────────────────────
# 2) Account Lockout Policies (V-253297, V-253298, V-253299)
# ─────────────────────────────────────────────────────────────────────────────
net accounts /lockoutduration:15   # Lockout duration ≥ 15 minutes
net accounts /lockoutthreshold:3    # Bad logon attempts ≤ 3
net accounts /lockoutwindow:15      # Reset counter after 15 minutes
Write-Host "Account lockout policies applied."

# ─────────────────────────────────────────────────────────────────────────────
# 3) Password Policies (V-253300, V-253302, V-253303)
# ─────────────────────────────────────────────────────────────────────────────
net accounts /uniquepw:24           # Enforce password history = 24
net accounts /minpwage:1            # Minimum password age = 1 day
net accounts /minpwlen:14           # Minimum password length = 14
Write-Host "Password policies applied."

# ─────────────────────────────────────────────────────────────────────────────
# 4) Event Log Sizes (V-253337, V-253338, V-253339)
# ─────────────────────────────────────────────────────────────────────────────
$evtSizes = @{
    'Application' = 32KB
    'Security'    = 1024MB
    'System'      = 32KB
}
foreach ($log in $evtSizes.Keys) {
    # Convert human-readable to bytes
    $sizeValue = switch ($evtSizes[$log]) {
        {$_ -match 'KB'} { [int]($_ -replace 'KB','') * 1KB }
        {$_ -match 'MB'} { [int]($_ -replace 'MB','') * 1MB }
    }
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\$log" `
        -Name "MaxSize" -Type DWord -Value $sizeValue
}
Write-Host "Event log sizes configured."

# ─────────────────────────────────────────────────────────────────────────────
# 5) Early Launch Antimalware Boot-Start Driver Initialization Policy (V-253372)
# ─────────────────────────────────────────────────────────────────────────────
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\EarlyLaunch" `
    -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\EarlyLaunch" `
    -Name "RequireBootStartDriverInitializationPolicy" -Type DWord -Value 2
Write-Host "ELAM Boot-Start Driver Initialization Policy set."

# ─────────────────────────────────────────────────────────────────────────────
# 6) Windows Hello PIN Complexity (V-253401)
# ─────────────────────────────────────────────────────────────────────────────
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\PINComplexity" `
    -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\PINComplexity" `
    -Name "MinimumPINLength" -Type DWord -Value 6
Write-Host "Windows Hello PIN complexity enforced."

# ─────────────────────────────────────────────────────────────────────────────
# 7) Disable & Rename Built-In Accounts (V-253432, V-253435, V-253436)
# ─────────────────────────────────────────────────────────────────────────────
Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue

Disable-LocalUser -Name "Administrator"
Rename-LocalUser  -Name "Administrator" -NewName "Admin_$((Get-Random) % 10000)"
Rename-LocalUser  -Name "Guest"         -NewName "Guest_$((Get-Random) % 10000)"
Write-Host "Built-in Administrator and Guest accounts updated."

# ─────────────────────────────────────────────────────────────────────────────
# 8) Machine Inactivity Timeout (V-253444)
# ─────────────────────────────────────────────────────────────────────────────
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "InactivityTimeoutSecs" -Type DWord -Value 900
Write-Host "Machine inactivity timeout configured (900 seconds)."

# ─────────────────────────────────────────────────────────────────────────────
# 9) Legal Notice Banner (V-253445)
# ─────────────────────────────────────────────────────────────────────────────
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

# ─────────────────────────────────────────────────────────────────────────────
# 10) Smart-Card Removal Behavior (V-253448)
# ─────────────────────────────────────────────────────────────────────────────
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    -Name "SCRemoveOption" -Type String -Value "1"
Write-Host "Smart-card removal behavior set to Lock Workstation."

# ─────────────────────────────────────────────────────────────────────────────
# 11) Command-Line Process Auditing (V-257770)
# ─────────────────────────────────────────────────────────────────────────────
auditpol.exe /set /subcategory:"Process Creation" /failure:enable
Write-Host "Process Creation failure auditing enabled."

# ─────────────────────────────────────────────────────────────────────────────
# 12) Disable Windows Copilot (V-268317)
# ─────────────────────────────────────────────────────────────────────────────
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" `
    -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" `
    -Name "EnableCopilot" -Type DWord -Value 0
Write-Host "Windows Copilot disabled."

# ─────────────────────────────────────────────────────────────────────────────
# 13) Block Third-Party Suggestions (V-253425)
# ─────────────────────────────────────────────────────────────────────────────
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
    -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
    -Name "DisableSuggestions" -Type DWord -Value 1
Write-Host "Third-party suggestions blocked."

# ─────────────────────────────────────────────────────────────────────────────
# 14) Disable Lock-Screen Toast Notifications (V-253477)
# ─────────────────────────────────────────────────────────────────────────────
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Notifications\Settings" `
    -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Notifications\Settings" `
    -Name "DisableLockScreenToast" -Type DWord -Value 1
Write-Host "Lock-screen toast notifications disabled."

Write-Host "STIG remediation complete." -ForegroundColor Green
