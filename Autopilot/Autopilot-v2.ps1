<#
.SYNOPSIS
    Registers a Windows device with Microsoft Intune Autopilot

.DESCRIPTION
    Intended to run from OOBE or Audit Mode on a freshly imaged Dell device. The script:

      - Verifies network connectivity and installs required dependencies
        (NuGet provider, Get-WindowsAutopilotInfo script, PSWindowsUpdate module).
      - Collects the device serial number and prompts for shared-computer status,
        region group tag (CGB, CPN, DRO, LCB, MB, UCB, WRO), and an optional
        device name (must start with "IBR").
      - Generates an Autopilot hardware-hash CSV in the script's execution directory
        (typically the flash drive) for separate manual import.
      - Authenticates to Microsoft Graph using OAuth device code
      - Checks whether the device is already registered in Autopilot. If a single
        exact serial-number match is found, prompts to remove it and waits for
        Intune to confirm deletion before re-adding. Hard-stops if multiple exact
        matches are found
      - Uploads the device to Autopilot with the constructed group tag and, if a
        device name was provided, polls for the new Autopilot record and sets the
        displayName via updateDeviceProperties.
      - Stages a separate RunWindowsUpdate.ps1 / RunWindowsUpdate.bat pair in
        C:\Temp and launches updates in a new window so the USB drive can be
        removed beforehand. The .bat is also retained for re-runs after reboot
        if any updates fail mid-install.


.NOTES
	Author: jeromero@ios.doi.gov
#>

[CmdletBinding()]
param()

BEGIN {
    # Was missing here, unlike almost every other script in this repo -
    # catches referencing an undefined/misspelled variable immediately
    # instead of silently treating it as $null (the exact bug class that
    # caused the Bluebeam "Warn" vs "Write-Warn" incident elsewhere in the
    # library). Deliberately NOT also setting $ErrorActionPreference='Stop'
    # here: this script's existing error handling relies in several places
    # (e.g. the hardware-hash CSV generation below) on a cmdlet call failing
    # softly and being detected afterward via Test-Path rather than a
    # terminating exception, and flipping the global default would change
    # that behavior at call sites not audited for it.
    Set-StrictMode -Version Latest
    $script:shouldContinue = $true

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "This script must be run as Administrator." -ForegroundColor Red
        $script:shouldContinue = $false
        return
    }

    $clientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
    $tenantId = "0693b5ba-4b18-4d7b-9341-f32f400a5494"

    $executionRoot = (Get-Location).Path
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    if (-not (Test-Path -Path "C:\Temp")) {
        New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null
    }

    $networkTest = Test-NetConnection -ComputerName "1.1.1.1" -Port 443 -WarningAction SilentlyContinue
    if (-not $networkTest.TcpTestSucceeded) {
        Write-Host "No internet connection detected. Please verify connection." -ForegroundColor Red
        $script:shouldContinue = $false
        return
    }
    Write-Verbose "Network connection verified."

#region ConfigureDNS
    $publicDnsServers = @(
        # IPv4
        "1.1.1.1",              # Cloudflare primary
        "1.0.0.1",              # Cloudflare secondary
        "8.8.8.8",              # Google primary
        "8.8.4.4",              # Google secondary
        "9.9.9.9",              # Quad9 primary
        "149.112.112.112",      # Quad9 secondary
        "208.67.222.222",       # OpenDNS primary
        "208.67.220.220",       # OpenDNS secondary
        # IPv6
        "2606:4700:4700::1111", # Cloudflare primary
        "2606:4700:4700::1001", # Cloudflare secondary
        "2001:4860:4860::8888", # Google primary
        "2001:4860:4860::8844", # Google secondary
        "2620:fe::fe",          # Quad9 primary
        "2620:fe::9",           # Quad9 secondary
        "2620:119:35::35",      # OpenDNS primary
        "2620:119:53::53"       # OpenDNS secondary
    )

    try {
        $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
            Sort-Object -Property RouteMetric |
            Select-Object -First 1

        $targetInterfaceIndexes = if ($defaultRoute) {
            @($defaultRoute.InterfaceIndex)
        } else {
            Get-NetAdapter |
                Where-Object { $_.Status -eq "Up" -and $_.InterfaceType -ne 24 -and $_.InterfaceType -ne 131 } |
                Select-Object -ExpandProperty InterfaceIndex
        }

        # Record the pre-existing DNS config (almost always DHCP-assigned at
        # OOBE) before overriding it with public resolvers, purely so a
        # technician can inspect what was there if this device ends up on a
        # network where the original servers actually mattered (e.g. an
        # internal-only resolver). The dump below is a human-readable
        # Format-Table, not structured data, so it isn't used for the
        # automatic restore in the generated update script (see
        # #region WindowsUpdate below) - that restore just resets each
        # affected interface back to DHCP-assigned DNS, which matches what's
        # here in the overwhelming majority of OOBE cases anyway.
        $dnsBackupPath = "C:\Temp\Autopilot-DNS-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
        $dnsBackup = foreach ($ifIndex in $targetInterfaceIndexes) {
            Get-DnsClientServerAddress -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue
        }
        $dnsBackup | Format-Table -AutoSize | Out-File -FilePath $dnsBackupPath -Force -ErrorAction SilentlyContinue
        Write-Verbose "Pre-existing DNS configuration backed up to $dnsBackupPath"

        foreach ($ifIndex in $targetInterfaceIndexes) {
            Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ServerAddresses $publicDnsServers
        }
        Write-Verbose "Public DNS resolvers configured on interface index(es): $($targetInterfaceIndexes -join ', ')."
    }
    catch {
        Write-Host "Warning: Could not configure DNS resolvers: $($_.Exception.Message)" -ForegroundColor Yellow
        # Ensure this is always defined even if the try block threw before
        # reaching its assignment above. The generated update script (see
        # #region WindowsUpdate below) references $targetInterfaceIndexes
        # inside a $(...) subexpression, which throws under StrictMode if the
        # variable was never set - that would crash the whole script well
        # after this point, long after this DNS step was meant to have failed
        # softly. An empty array just means the DNS-restore step in the
        # generated script iterates zero interfaces, which is a safe degrade.
        if (-not (Test-Path variable:targetInterfaceIndexes)) {
            $targetInterfaceIndexes = @()
        }
    }

#endregion ConfigureDNS

    $graphTest = Test-NetConnection -ComputerName "graph.microsoft.com" -Port 443 -WarningAction SilentlyContinue
    if (-not $graphTest.TcpTestSucceeded) {
        Write-Host "Cannot reach graph.microsoft.com:443. Please verify firewall or proxy settings." -ForegroundColor Red
        $script:shouldContinue = $false
        return
    }
    Write-Verbose "Microsoft Graph endpoint reachable."

#region installDependencies
    $nugetProvider = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    try {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
    }
    catch {
        Write-Host "Warning: Could not set PSGallery as trusted: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    if ($nugetProvider) {
        Write-Verbose "NuGet PackageProvider is already installed (Version: $($nugetProvider.Version))"
        Write-Verbose "Checking dependencies..." 

        try {
            if (Get-Command Get-WindowsAutopilotInfo -ErrorAction SilentlyContinue) {
                Write-Verbose "Get-WindowsAutopilotInfo script is already installed." 
            }
            else {
                Write-Verbose "Installing Get-WindowsAutopilotInfo script..."
                Install-Script -Name Get-WindowsAutopilotInfo -MinimumVersion 3.9 -Force -ErrorAction Stop
                Write-Verbose "Get-WindowsAutopilotInfo script installed successfully." 
            }

            if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
                Write-Verbose "PSWindowsUpdate module is already installed."
            }
            else {
                Write-Verbose "Installing PSWindowsUpdate module..."
                Install-Module -Name PSWindowsUpdate -MinimumVersion 2.2.0.3 -Force -AllowClobber -Confirm:$false -ErrorAction Stop
                Write-Verbose "PSWindowsUpdate module installed successfully."
            }

        }
        catch {
            # Deliberately not falling back to a certificate-validation
            # bypass here. An earlier version of this script retried with
            # [System.Net.ServicePointManager]::CertificatePolicy set to
            # trust-all-certs whenever the initial install attempt hit a TLS
            # error - that papers over a real cert-store or PSGallery issue
            # and leaves this OOBE flow open to a MITM'd module/script
            # download. Whatever's causing the failure needs to be fixed on
            # the machine/network, not routed around.
            Write-Host "Failed to install dependencies: $($_.Exception.Message)" -ForegroundColor Red
            $script:shouldContinue = $false
            return
        }
    }
    else {
        Write-Host "NuGet PackageProvider not found. Attempting to install..." -ForegroundColor Yellow
        $nugetInstalled = $false

        try {
            Write-Verbose "Installing NuGet PackageProvider..."
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -InformationAction SilentlyContinue -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null

            $installedProvider = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
            if ($installedProvider) {
                Write-Verbose "NuGet installed successfully."
                $nugetInstalled = $true
            }
            else {
                throw "Installation verification failed"
            }
        }
        catch {
            # No certificate-bypass retry here on purpose - see note above.
            Write-Host "Failed to install NuGet PackageProvider: $($_.Exception.Message)" -ForegroundColor Red
            $nugetInstalled = $false
        }

        if ($nugetInstalled) {
            Write-Verbose "Checking dependencies..." 

            try {
                if (Get-Command Get-WindowsAutopilotInfo -ErrorAction SilentlyContinue) {
                    Write-Verbose "Get-WindowsAutopilotInfo script is already installed."
                }
                else {
                    Write-Verbose "Installing Get-WindowsAutopilotInfo script..."
                    Install-Script -Name Get-WindowsAutopilotInfo -MinimumVersion 3.9 -Force -ErrorAction Stop
                    Write-Verbose "Get-WindowsAutopilotInfo script installed successfully."
                }

                if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
                    Write-Verbose "PSWindowsUpdate module is already installed."
                }
                else {
                    Write-Verbose "Installing PSWindowsUpdate module..."
                    Install-Module -Name PSWindowsUpdate -MinimumVersion 2.2.0.3 -Force -AllowClobber -Confirm:$false -ErrorAction Stop
                    Write-Verbose "PSWindowsUpdate module installed successfully."
                }

            }
            catch {
                Write-Host "Failed to install dependencies: $($_.Exception.Message)" -ForegroundColor Red
                $script:shouldContinue = $false
                return
            }
        }
        else {
            Write-Verbose "Skipping dependency installation due to NuGet installation failure."
            $script:shouldContinue = $false
            return
        }
    }

    $env:Path += ";C:\Program Files\WindowsPowerShell\Scripts"

#endregion installDependencies    


#region WindowsUpdate
    $updateScriptPath = "C:\Temp\RunWindowsUpdate.ps1"

@"
Write-Host "==============================================="
Write-Host "Windows Update Installation Process"
Write-Host "==============================================="

Import-Module PSWindowsUpdate

Write-Host "Starting Windows Updates..."
try {
    Get-WindowsUpdate -NotCategory "FeaturePacks","Upgrades" -AcceptAll -Install -ErrorAction Stop
}
catch {
    if (`$_.Exception.Message -like "*Value does not fall within the expected range*") {
        Write-Host "Windows Update agent error detected. Resetting and retrying..." -ForegroundColor Yellow

        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        Stop-Service -Name cryptSvc -Force -ErrorAction SilentlyContinue
        Stop-Service -Name bits -Force -ErrorAction SilentlyContinue
        Stop-Service -Name msiserver -Force -ErrorAction SilentlyContinue

        Remove-Item "C:\Windows\SoftwareDistribution" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\Windows\System32\catroot2" -Recurse -Force -ErrorAction SilentlyContinue

        Start-Service wuauserv
        Start-Service cryptSvc
        Start-Service bits
        Start-Service msiserver

        Start-Sleep -Seconds 5
        Write-Host "Retrying Windows Updates..." -ForegroundColor Yellow
        Get-WindowsUpdate -NotCategory "FeaturePacks","Upgrades" -AcceptAll -Install
    }
    else {
        Write-Host "An error occurred: `$(`$_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "==============================================="
Write-Host "Windows Update process completed."
Write-Host "NOTE: If some updates failed during installation," -ForegroundColor Yellow
Write-Host "reboot and rerun the .bat file from C:\Temp\RunWindowsUpdate.bat" -ForegroundColor Yellow
Write-Host "==============================================="

Write-Host "Restoring DHCP-assigned DNS configuration..." -ForegroundColor Yellow
foreach (`$ifIndex in @($($targetInterfaceIndexes -join ','))) {
    try {
        Set-DnsClientServerAddress -InterfaceIndex `$ifIndex -ResetServerAddresses -ErrorAction Stop
    }
    catch {
        Write-Host "Could not restore DNS on interface `$ifIndex : `$(`$_.Exception.Message)" -ForegroundColor Yellow
    }
}

Start-Sleep -Seconds 30
Restart-Computer -Force

"@ | Out-File -FilePath $updateScriptPath -Force

        $batFilePath = "C:\Temp\RunWindowsUpdate.bat"
        Set-Content -Path $batFilePath -Value "@echo off" -Encoding ASCII
        Add-Content -Path $batFilePath -Value "echo Starting Windows Update Process..." -Encoding ASCII
        Add-Content -Path $batFilePath -Value "powershell.exe -NoExit -ExecutionPolicy Bypass -File `"$updateScriptPath`"" -Encoding ASCII

#endregion WindowsUpdate


}
PROCESS {
    if (-not $script:shouldContinue) { return }

    $serialNumber = ((Get-CimInstance -ClassName Win32_BIOS).SerialNumber).Trim()
    Write-Host "Serial Number: $serialNumber" -ForegroundColor Gray
    Write-Host ""    

    do {
        $sharedComputer = (Read-Host "Is this a shared computer? (Y/N)").ToUpper()
        if ($sharedComputer -notin @('Y','N')) {
            Write-Host "Please enter Y or N only." -ForegroundColor Red
        }
    } while ($sharedComputer -notin @('Y','N'))

    Write-Host ""
    Write-Host "Available regions:" -ForegroundColor Gray
    Write-Host "  CGB | CPN | DRO | LCB | MB | UCB | WRO" -ForegroundColor Gray
    Write-Host ""

    do {
        $groupTag = (Read-Host "Enter region").ToUpper()
        if ($groupTag -notin @('CGB','CPN','DRO','LCB','MB','UCB','WRO')) {
            Write-Host "Please enter a valid region code." -ForegroundColor Red
        }
    } while ($groupTag -notin @('CGB','CPN','DRO','LCB','MB','UCB','WRO'))

    if ($sharedComputer -eq 'Y') { 
        $groupTag = "BOR-$groupTag-SDP" 
    } else { 
        $groupTag = "BOR-$groupTag" 
    }    

    Write-Host ""
    $deviceName = ""
    $validName = $false
    while (-not $validName) {
        $deviceName = Read-Host "Enter device name (must start with IBR, max 15 chars, or press Enter to skip)"
        if ($deviceName -eq "") {
            $validName = $true
        }
        elseif (-not $deviceName.ToUpper().StartsWith("IBR")) {
            Write-Host "Device name must start with IBR." -ForegroundColor Red
        }
        elseif ($deviceName.Length -gt 15) {
            Write-Host "Device name must be 15 characters or fewer (entered: $($deviceName.Length))." -ForegroundColor Red
        }
        else {
            $deviceName = $deviceName.ToUpper()
            $validName = $true
        }
    }

    Write-Host ""
    Write-Host "Generating hardware hash CSV... " -NoNewline
    $csvPath = Join-Path $executionRoot "AutopilotHWID-$serialNumber.csv"
    Get-WindowsAutopilotInfo -OutputFile $csvPath

    if (-not (Test-Path $csvPath)) {
        Write-Host ""
        Write-Host "Failed to generate hardware hash CSV. Cannot continue." -ForegroundColor Red
        $script:shouldContinue = $false
        return
    }
    
    try {
        $csvData = Import-Csv -Path $csvPath

        if ($csvData) {
            $UpdatedCSVData = [System.Collections.Generic.List[object]]::new()

            foreach ($row in $csvData) {
                $newRow = [ordered]@{
                    "Device Serial Number" = $serialNumber
                    "Windows Product ID"   = $row."Windows Product ID"
                    "Hardware Hash"        = $row."Hardware Hash"
                    "Group Tag"            = $groupTag
                    "Assigned User"        = "" # intentionally blank; user is assigned post-enrollment in Intune
                }

                $UpdatedCSVData.Add((New-Object PSObject -Property $newRow))
            }

            $UpdatedCSVData | Export-Csv -Path $csvPath -NoTypeInformation -Force
            Write-Host "done" -ForegroundColor Green
            Write-Host "CSV file saved to: $csvPath"
        } 
        else {
            Write-Host ""
            Write-Host "Unable to update CSV, no data found." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host ""
        Write-Host "An error occurred: $_" -ForegroundColor Red
    }    

}
END {
    if (-not $script:shouldContinue) { return }

    Write-Host ""
    Write-Host "-- Authentication --" -ForegroundColor Cyan

    try {
        Write-Verbose "Requesting device code..."
        $deviceCodeRequest = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/devicecode" -Body @{
            client_id = $clientId
            scope     = "https://graph.microsoft.com/.default"
        }

        Write-Host "====================================" -ForegroundColor Cyan
        Write-Host " Go to $($deviceCodeRequest.verification_uri)" -ForegroundColor Cyan
        Write-Host "  Enter code: $($deviceCodeRequest.user_code)" -ForegroundColor Cyan
        Write-Host "====================================" -ForegroundColor Cyan

        $tokenAcquired = $false
        $pollInterval = $deviceCodeRequest.interval
        if (-not $pollInterval) { $pollInterval = 5 }
        $maxWait = 600
        $elapsed = 0
        $lastStatusPrint = 0

        while (-not $tokenAcquired -and $elapsed -lt $maxWait) {
            Start-Sleep -Seconds $pollInterval
            $elapsed += $pollInterval

            try {
                $tokenResponse = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body @{
                    client_id   = $clientId
                    grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
                    device_code = $deviceCodeRequest.device_code
                }

                $token = $tokenResponse.access_token
                $tokenAcquired = $true
            }
            catch {
                $errorMessage = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($null -eq $errorMessage) {
                    # No parseable JSON error body means this wasn't an OAuth
                    # error response at all - e.g. a transient network
                    # blip/timeout on the request itself. Previously this fell
                    # into the same branch as a real fatal OAuth error
                    # (invalid_grant, expired_token, etc.) and aborted the
                    # whole run; now it's treated as transient and the loop
                    # keeps polling until $maxWait, same as authorization_pending.
                    # This null-check must run before any ".error" access below -
                    # under StrictMode, indexing a property off $null throws,
                    # which previously aborted registration on the very first
                    # transient network error instead of retrying.
                    if (($elapsed - $lastStatusPrint) -ge 60) {
                        $lastStatusPrint = $elapsed
                        $remaining = $maxWait - $elapsed
                        Write-Host "Transient error polling for token, retrying... ($remaining`s remaining): $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
                elseif ($errorMessage.error -eq "authorization_pending") {
                    if (($elapsed - $lastStatusPrint) -ge 60) {
                        $lastStatusPrint = $elapsed
                        $remaining = $maxWait - $elapsed
                        Write-Host "Waiting for authentication... ($remaining`s remaining)" -ForegroundColor Gray
                    }
                }
                elseif ($errorMessage.error -eq "slow_down") {
                    $pollInterval += 5
                }
                else {
                    if ($errorMessage.PSObject.Properties['error_description']) {
                        Write-Host "Authentication error: $($errorMessage.error_description)" -ForegroundColor Red
                    }
                    else {
                        Write-Host "Authentication error: $($errorMessage.error)" -ForegroundColor Red
                    }
                    return
                }
            }
        }

        if (-not $tokenAcquired) {
            Write-Host "Authentication timed out. Please run the script again." -ForegroundColor Red
            return
        }

        Write-Host "Authenticated successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Authentication failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    } 
    
    $headers = @{
        Authorization  = "Bearer $token"
        "Content-Type" = "application/json"
    }

#region AutopilotCheck
    Write-Host ""
    Write-Host "-- Autopilot Status --" -ForegroundColor Cyan

    $proceedWithUpload = $true
    $existingDevice = $null

    try {
        $checkResult = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$serialNumber')&`$top=999" -Headers $headers
        
        $exactMatches = @($checkResult.value | Where-Object { $_.serialNumber -eq $serialNumber })

        if ($exactMatches.Count -eq 1) {
            $existingDevice = $exactMatches[0]
            Write-Host "Device found in Autopilot:"
            Write-Host "    Serial Number: $($existingDevice.serialNumber)" -ForegroundColor Gray
            Write-Host "    Model:         $($existingDevice.model)" -ForegroundColor Gray
            Write-Host "    Group Tag:     $($existingDevice.groupTag)" -ForegroundColor Gray
            Write-Host "    Autopilot ID:  $($existingDevice.id)" -ForegroundColor Gray
            Write-Host ""

            do {
                $removeChoice = (Read-Host "Remove this device from Autopilot and re-add with fresh info? (Y/N)").ToUpper()
                if ($removeChoice -notin @('Y','N')) {
                    Write-Host "Please enter Y or N only." -ForegroundColor Red
                }
            } while ($removeChoice -notin @('Y','N'))

            if ($removeChoice -eq 'Y') {
                Write-Host ""
                Write-Host "Removing device from Autopilot... " -NoNewline

                try {
                    Invoke-RestMethod -Method DELETE -Uri "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities/$($existingDevice.id)" -Headers $headers

                    $deleteConfirmed = $false
                    $deleteWait = 0
                    $deleteMaxWait = 300

                    while (-not $deleteConfirmed -and $deleteWait -lt $deleteMaxWait) {
                        Start-Sleep -Seconds 10
                        $deleteWait += 10

                        try {
                            Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities/$($existingDevice.id)" -Headers $headers | Out-Null
                            if ($deleteWait % 60 -eq 0) {
                                Write-Host ""
                                Write-Host "  Still waiting... ($deleteWait`s elapsed)" -ForegroundColor Gray -NoNewline
                            }
                        }
                        catch {
                            # Only a real 404 actually confirms the device is
                            # gone. Treating ANY exception here as "deleted"
                            # meant a transient network blip, throttling
                            # (429), or an expired token would look
                            # identical to a genuine deletion - masking a
                            # failed/incomplete delete as success and
                            # risking a duplicate-serial conflict on upload.
                            $statusCode = $null
                            if ($_.Exception.Response) {
                                try { $statusCode = [int]$_.Exception.Response.StatusCode } catch { Write-Verbose "Could not extract HTTP status code: $($_.Exception.Message)" }
                            }
                            if ($statusCode -eq 404) {
                                $deleteConfirmed = $true
                            } elseif ($deleteWait % 60 -eq 0) {
                                Write-Host ""
                                Write-Host "  Still waiting... ($deleteWait`s elapsed; last check error: $($_.Exception.Message))" -ForegroundColor Gray -NoNewline
                            }
                        }
                    }

                    if ($deleteConfirmed) {
                        Write-Host "done ($deleteWait`s)" -ForegroundColor Green
                    }
                    else {
                        Write-Host "timed out" -ForegroundColor Yellow
                        Write-Host "Removal is still processing. Proceeding with upload -- Intune may take a moment to fully sync." -ForegroundColor Yellow
                    }
                }
                catch {
                    Write-Host "failed" -ForegroundColor Red
                    Write-Host "Failed to remove device: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Host "Proceeding with upload anyway..." -ForegroundColor Yellow
                }
            }
            else {
                Write-Host ""
                do {
                    $uploadAnyway = (Read-Host "Device is already registered. Upload fresh hardware info anyway? (Y/N)").ToUpper()
                    if ($uploadAnyway -notin @('Y','N')) {
                        Write-Host "Please enter Y or N only." -ForegroundColor Red
                    }
                } while ($uploadAnyway -notin @('Y','N'))

                if ($uploadAnyway -eq 'N') {
                    Write-Host "No changes made. Exiting." -ForegroundColor Green
                    $proceedWithUpload = $false
                }
            }
        }
        elseif ($exactMatches.Count -gt 1) {
            Write-Host "WARNING: Multiple Autopilot entries found for serial '$serialNumber' ($($exactMatches.Count) devices)." -ForegroundColor Red
            Write-Host "Please review manually in the Intune portal." -ForegroundColor Red
            foreach ($device in $exactMatches) {
                Write-Host "    ID: $($device.id)  |  SN: $($device.serialNumber)  |  Model: $($device.model)  |  Group Tag: $($device.groupTag)" -ForegroundColor Gray
            }
            Write-Host "The script will NOT delete any devices. Exiting for safety." -ForegroundColor Red
            $proceedWithUpload = $false
        }
        else {
            Write-Host "Device is not currently in Autopilot." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Could not check Autopilot enrollment: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "Proceeding with upload anyway..." -ForegroundColor Yellow
    }

#endregion AutopilotCheck

    if (-not $proceedWithUpload) { return }

#region AutopilotUpload
    Write-Host ""
    Write-Host "Uploading to Autopilot... " -NoNewline

    try {
        $csvData = Import-Csv -Path $csvPath

        if (-not $csvData) {
            Write-Host "failed" -ForegroundColor Red
            Write-Host "No data found in CSV. Please verify $csvPath" -ForegroundColor Red
            return
        }

        $hardwareHash = $csvData[0]."Hardware Hash"

        $uploadBody = @{
            serialNumber       = $serialNumber
            groupTag           = $groupTag
            hardwareIdentifier = $hardwareHash
        } | ConvertTo-Json

        $uploadAttempt = 0
        $importResult = $null
        while ($uploadAttempt -lt 3 -and -not $importResult) {
            $uploadAttempt++
            try {
                $importResult = Invoke-RestMethod -Method POST -Uri "https://graph.microsoft.com/v1.0/deviceManagement/importedWindowsAutopilotDeviceIdentities" -Headers $headers -Body $uploadBody
            }
            catch {
                if ($uploadAttempt -lt 3) {
                    Write-Host ""
                    Write-Host "  Attempt $uploadAttempt failed, retrying in 10s..." -ForegroundColor Yellow -NoNewline
                    Start-Sleep -Seconds 10
                }
                else {
                    throw
                }
            }
        }
        Write-Host "done" -ForegroundColor Green
    }
    catch {
        Write-Host "failed" -ForegroundColor Red
        Write-Host "Failed to upload device: $($_.Exception.Message)" -ForegroundColor Red
        if (Test-Path $csvPath) {
            Write-Host "Please upload $csvPath manually to Autopilot." -ForegroundColor Yellow
        }
        else {
            Write-Host "CSV file was not created. Please re-run the script." -ForegroundColor Red
        }
        return
    }
#endregion AutopilotUpload

#region SetDeviceName
    $deviceNameSet = $false

    if ($deviceName) {
        Write-Host "Setting device name... " -NoNewline

        $maxNameWait = 300
        $nameElapsed = 0
        $nameInterval = 15
        $autopilotDeviceId = $null
        $lastNameStatusPrint = 0

        while (-not $autopilotDeviceId -and $nameElapsed -lt $maxNameWait) {
            Start-Sleep -Seconds $nameInterval
            $nameElapsed += $nameInterval

            if (($nameElapsed - $lastNameStatusPrint) -ge 60) {
                $lastNameStatusPrint = $nameElapsed
                Write-Host ""
                Write-Host "  Still waiting for Intune... ($nameElapsed`s elapsed)" -ForegroundColor Gray -NoNewline
            }

            try {
                $deviceLookup = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$serialNumber')&`$top=999" -Headers $headers

                $exactLookup = @($deviceLookup.value | Where-Object { $_.serialNumber -eq $serialNumber })
                if ($exactLookup.Count -gt 0) {
                    $autopilotDeviceId = $exactLookup[0].id
                }
            }
            catch {
                Write-Verbose "Autopilot device lookup failed (will retry): $($_.Exception.Message)"
            }
        }

        if ($autopilotDeviceId) {
            try {
                $nameBody = @{
                    displayName = $deviceName
                } | ConvertTo-Json

                Invoke-RestMethod -Method POST -Uri "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities/$autopilotDeviceId/updateDeviceProperties" -Headers $headers -Body $nameBody -ContentType "application/json"

                Write-Host "done ($nameElapsed`s)" -ForegroundColor Green
                $deviceNameSet = $true
            }
            catch {
                Write-Host "failed" -ForegroundColor Red
                Write-Host "Failed to set device name: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "Please set device name manually in Intune Autopilot." -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "timed out" -ForegroundColor Yellow
            Write-Host "Please set device name manually in Intune Autopilot." -ForegroundColor Yellow
        }
    }
#endregion SetDeviceName

    Write-Host ""
    Write-Host "-- Complete --" -ForegroundColor Cyan
    Write-Host "  Serial Number: $serialNumber" -ForegroundColor Gray
    Write-Host "  Group Tag:     $groupTag" -ForegroundColor Gray
    if ($deviceNameSet) {
        Write-Host "  Device Name:   $deviceName" -ForegroundColor Gray
    }
    Write-Host "  Import ID:     $($importResult.id)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Please allow a few minutes for Intune to finish processing." -ForegroundColor Green

    Write-Host ""
    Write-Host "USB Drive can now be safely removed." -ForegroundColor Green
    Write-Host ""
    Read-Host "Press Enter when ready to begin Windows Updates"

    Write-Host ""
    Write-Host "Starting Windows Updates in a separate window..." -ForegroundColor Yellow
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$batFilePath`"" -WindowStyle Normal

    Write-Host ""
    Write-Host "NEXT STEPS:" -ForegroundColor Yellow
    Write-Host "    Updates are running in a separate window" -ForegroundColor Yellow
    Write-Host "    Check the other window to monitor progress" -ForegroundColor Yellow
    Write-Host "    DO NOT restart until updates are complete" -ForegroundColor Red
    Write-Host ""
}