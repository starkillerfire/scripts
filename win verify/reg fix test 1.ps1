# Script to Apply WinVerifyTrust Hardening on Remote Systems Using PsExec
# Ensures file copy, registry application, and log retrieval with robust error handling.

# Configuration
$psexecPath       = "C:\Tools\PsExec.exe"             # Path to PsExec
$localScriptPath  = "C:\Temp\RemoteRegistryScript.ps1" # Local script to run on remote machines
$inputCsvPath     = "C:\Users\scarman\Downloads\Winverify.csv"    # Input CSV with target systems
$outputCsvPath    = "C:\Users\scarman\results.csv"    # Results CSV
$failedCsvPath    = "C:\Users\scarman\failed.csv"     # Failed systems CSV
$localLogFolder   = "C:\Temp\RemoteLogs"              # Folder for retrieved logs
$remoteFolderPath = "C:\Temp"                         # Remote folder for file execution

# Registry Key Configuration
$registryPath = "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config"
$keyName      = "EnableCertPaddingCheck"
$keyValue     = 1

# Ensure Required Folders Exist
if (-not (Test-Path -Path $localLogFolder)) {
    New-Item -Path $localLogFolder -ItemType Directory -Force | Out-Null
}

# Ensure Local Script Exists
if (-not (Test-Path -Path $localScriptPath)) {
    Write-Error "Local script not found: $localScriptPath. Exiting."
    exit 1
}

# Create Remote Script Content
$remoteScriptContent = @"
param ([string]`$regPath, [string]`$key, [int]`$value, [string]`$logPath)

try {
    if (-not (Test-Path -Path `$regPath)) {
        Add-Content -Path `$logPath -Value "Creating registry path: `$regPath"
        New-Item -Path `$regPath -Force | Out-Null
    }
    Set-ItemProperty -Path `$regPath -Name `$key -Value `$value -Force
    `$currentValue = (Get-ItemProperty -Path `$regPath).`$key
    if (`$currentValue -eq `$value) {
        Add-Content -Path `$logPath -Value "Success"
    } else {
        Add-Content -Path `$logPath -Value "Failed"
    }
} catch {
    Add-Content -Path `$logPath -Value "Error: `$($_.Exception.Message)"
}
"@
Set-Content -Path $localScriptPath -Value $remoteScriptContent -Force

# Function to Apply Registry Key and Retrieve Logs
function Apply-RegistryKey {
    param ([string]$TargetSystem)

    try {
        Write-Output "Processing: ${TargetSystem}"

        # Define Paths
        $remoteScript = "\\${TargetSystem}\C$\Temp\RemoteRegistryScript.ps1"
        $remoteLog    = "\\${TargetSystem}\C$\Temp\output.log"
        $localLog     = "$localLogFolder\output_${TargetSystem}.log"

        # Step 1: Ensure Remote Folder Exists
        Write-Output "Ensuring remote folder exists on ${TargetSystem}..."
        Start-Process -FilePath $psexecPath `
            -ArgumentList "\\${TargetSystem} -accepteula cmd /c mkdir C:\Temp" `
            -NoNewWindow -Wait -ErrorAction Stop

        # Step 2: Retry File Copy
        $copySuccess = $false
        for ($i = 0; $i -lt 3; $i++) {
            Write-Output "Copying script to ${TargetSystem} (attempt $($i+1))..."
            try {
                Copy-Item -Path $localScriptPath -Destination $remoteScript -Force -ErrorAction Stop
                $copySuccess = $true
                break
            } catch {
                Write-Warning "Failed to copy script to ${TargetSystem}. Retrying..."
                Start-Sleep -Seconds 2
            }
        }
        if (-not $copySuccess) { throw "Unable to copy script to ${TargetSystem} after multiple attempts." }

        # Step 3: Execute Script
        Write-Output "Executing script on ${TargetSystem}..."
        $command = "powershell.exe -ExecutionPolicy Bypass -File C:\Temp\RemoteRegistryScript.ps1 -regPath '$registryPath' -key '$keyName' -value $keyValue -logPath C:\Temp\output.log"
        Start-Process -FilePath $psexecPath `
            -ArgumentList "\\${TargetSystem} -accepteula $command" `
            -NoNewWindow -Wait -ErrorAction Stop

        # Step 4: Retrieve Logs
        Write-Output "Retrieving logs from ${TargetSystem}..."
        Copy-Item -Path $remoteLog -Destination $localLog -Force -ErrorAction Stop

        # Step 5: Analyze Logs
        if (Select-String -Path $localLog -Pattern "Success") {
            Write-Output "Registry key applied successfully on ${TargetSystem}."
            return [PSCustomObject]@{ System = $TargetSystem; Status = "Success"; ErrorMessage = "" }
        } else {
            throw "Registry key verification failed. Check logs at ${localLog}."
        }
    } catch {
        Write-Error "Failed on ${TargetSystem}: $($_.Exception.Message)"
        return [PSCustomObject]@{ System = $TargetSystem; Status = "Failed"; ErrorMessage = $_.Exception.Message }
    }
}

# Main Execution Logic
if (-not (Test-Path -Path $inputCsvPath)) {
    Write-Error "Input CSV not found: ${inputCsvPath}"
    exit 1
}

$systems = Import-Csv -Path $inputCsvPath
$resultList = @()
$failedList = @()

foreach ($system in $systems) {
    if (-not $system.SystemName) {
        Write-Warning "Skipping missing SystemName entry."
        continue
    }

    $TargetSystem = $system.SystemName.Trim()
    if (Test-Connection -ComputerName $TargetSystem -Count 2 -Quiet) {
        $result = Apply-RegistryKey -TargetSystem $TargetSystem
        if ($result.Status -eq "Success") {
            $resultList += $result
        } else {
            $failedList += $result
        }
    } else {
        Write-Error "Skipping ${TargetSystem}: System unreachable."
        $failedList += [PSCustomObject]@{ System = $TargetSystem; Status = "Unreachable"; ErrorMessage = "System not reachable." }
    }
}

# Export Results
$resultList | Export-Csv -Path $outputCsvPath -NoTypeInformation -Force
$failedList | Export-Csv -Path $failedCsvPath -NoTypeInformation -Force
Write-Output "Results saved to: ${outputCsvPath} and ${failedCsvPath}"

Write-Output "Script complete."
