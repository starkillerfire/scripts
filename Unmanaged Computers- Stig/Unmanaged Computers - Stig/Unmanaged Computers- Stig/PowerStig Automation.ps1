<#
.SYNOPSIS
    Fully automate DISA STIG v2.2 on a standalone Windows 11 workstation via PowerSTIG DSC.
.DESCRIPTION
    This script performs the following steps:
        1. Set execution policy and install PowerSTIG + dependencies.
        2. Enable WinRM/PSRemoting and open firewall for WS-Man.
        3. Configure LCM for Push-based DSC and AutoCorrect.
        4. Import PowerSTIG module and locate OrgSettings XML.
        5. Define, compile, and push the WindowsClient STIG v2.2 configuration.
.PARAMETER OrgSettingsPath
    Specifies the path to the OrgSettings XML used by PowerSTIG.
.EXAMPLE
    .\Apply-StigWin11.ps1
    Executes the script using the default OrgSettings from the PowerSTIG module.
#>

#region Execution Policy and Module Installation
Write-Host "Setting execution policy and installing PowerSTIG + dependencies..." -ForegroundColor Cyan
# Allow DSC to import unsigned modules locally
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force

# Install PowerSTIG if not present
if (-not (Get-Module -ListAvailable -Name PowerSTIG)) {
    Install-Module -Name PowerSTIG -Scope AllUsers -Force
    Write-Host "PowerSTIG module installed." -ForegroundColor Green
}

# Install all PowerSTIG dependencies
(Get-Module -ListAvailable -Name PowerSTIG).RequiredModules | ForEach-Object {
    Install-Module -Name $_.Name -Scope AllUsers -Force
    Write-Host "Installed dependency: $($_.Name)" -ForegroundColor Green
}
#endregion

#region Configure WinRM and Firewall for DSC Push
Write-Host "Configuring WinRM/WS-Man for DSC Push..." -ForegroundColor Cyan
# Enable PSRemoting (WinRM) and skip network profile check for this standalone machine
Enable-PSRemoting -Force -SkipNetworkProfileCheck

# Open firewall port 5985 for WS-Man if the rule does not exist
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

# Test WS-Man connectivity to localhost
Try {
    Test-WSMan -ComputerName localhost | Out-Null
    Write-Host "WS-Man connectivity OK." -ForegroundColor Green
} Catch {
    Write-Warning "WS-Man still not reachable. Check service/firewall."
}
#endregion

#region Configure LCM for Push Mode and AutoCorrect
[DSCLocalConfigurationManager()]
Configuration LCM_PushConfig {
    Settings {
        ConfigurationMode    = 'ApplyAndAutoCorrect'  # Auto-correct non-compliance
        AllowModuleOverwrite = $true                 # Overwrite existing modules if needed
        RefreshMode          = 'Push'                # Use push model (Start-DscConfiguration)
        RebootNodeIfNeeded   = $true                 # Reboot if configuration requires it
    }
}

# Output path for the LCM configuration MOF
$LCMPath = Join-Path $env:ProgramData 'PowerSTIG\LCM'
# Generate the LCM MOF at the specified path
LCM_PushConfig -OutputPath $LCMPath
# Apply the LCM settings to the local node
Set-DscLocalConfigurationManager -Path $LCMPath -Verbose -Force | Out-Null
Write-Host "Local Configuration Manager configured for push mode." -ForegroundColor Green
#endregion

#region Import PowerSTIG Module and Locate OrgSettings XML
Import-Module PowerSTIG -ErrorAction Stop
Write-Host "Imported PowerSTIG module." -ForegroundColor Cyan

# Determine module base path and OrgSettings default file
$psMod      = Get-Module -ListAvailable -Name PowerSTIG
$orgDefault = Join-Path $psMod.ModuleBase 'StigData\Processed\WindowsClient-11-2.2.org.default.xml'

# Validate that the OrgSettings XML exists
if (-not (Test-Path $orgDefault)) {
    Throw "OrgSettings XML not found at $orgDefault. Ensure PowerSTIG v4.25+ is installed."
}
Write-Host "Using OrgSettings: $orgDefault" -ForegroundColor Green
#endregion

#region Define, Compile, and Push the STIG DSC Configuration
<#
.SYNOPSIS
    DSC configuration for Windows 11 DISA STIG v2.2 baseline.
.PARAMETER OrgSettingsPath
    Path to the OrgSettings XML file.
#>
Configuration Win11_STIG_v2_2 {
    param (
        [Parameter(Mandatory)]
        [string] $OrgSettingsPath
    )

    # Import the DSC resource provided by PowerSTIG
    Import-DscResource -ModuleName PowerSTIG

    Node 'localhost' {
        # Apply the WindowsClient STIG baseline
        WindowsClient STIGBaseline {
            OsVersion   = '11'
            StigVersion = '2.2'
            OrgSettings = $OrgSettingsPath
        }
    }
}

# Path for the generated STIG baseline MOF files
$MofPath = Join-Path $env:ProgramData 'PowerSTIG\Mof'
# Ensure the output directory exists
if (-not (Test-Path $MofPath)) {
    New-Item -Path $MofPath -ItemType Directory -Force | Out-Null
}

Write-Host "Compiling DSC configuration…" -ForegroundColor Cyan
# Generate the configuration MOF using the OrgSettings XML
Win11_STIG_v2_2 -OrgSettingsPath $orgDefault -OutputPath $MofPath

Write-Host "Applying STIG baseline (Push)…" -ForegroundColor Cyan
# Push the DSC configuration to the local node
Start-DscConfiguration -Path $MofPath -Wait -Force -Verbose

Write-Host "✅ STIG v2.2 enforcement on Windows 11 complete." -ForegroundColor Green
#endregion
