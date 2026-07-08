#### BEGIN FUNCTIONS ####

<#
    .SYNOPSIS
    Retrieves the failed Win32 app states from the Intune registry.
    
    .DESCRIPTION
    This function searches the Intune Win32 apps registry key for subkeys containing an EnforcementStateMessage property.
    It extracts the error codes from these properties and identifies failed installations.

    .OUTPUTS
    PSCustomObject representing the failed app states.
#>
function Get-FailedWin32AppStates {
    $win32AppsKeyPath = 'HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps'
    $appSubKeys = Get-ChildItem -Path $win32AppsKeyPath -Recurse -ErrorAction SilentlyContinue

    $failedStates = @()
    foreach ($subKey in $appSubKeys) {
        $enforcementStateMessage = Get-ItemProperty -Path $subKey.PSPath -Name EnforcementStateMessage -ErrorAction SilentlyContinue
        if ($enforcementStateMessage) {
            if ($enforcementStateMessage.EnforcementStateMessage -match '"ErrorCode":(-?\d+|null)') {
                $errorCode = $matches[1]
                if ($errorCode -ne "null") {
                    $errorCode = [int]$errorCode
                    if (($errorCode -ne 0) -and ($errorCode -ne 3010)) {
                        $failedStates += [PSCustomObject]@{
                            SubKeyPath = $subKey.PSPath
                            ErrorCode  = $errorCode
                        }
                    }
                }
            }
        }
    }

    return $failedStates
}


<#
    .SYNOPSIS
    Retrieves the last hash value for a specific user and app ID.
    
    .DESCRIPTION
    This function gets the LastHashValue property from the registry for a given user and app ID.

    .PARAMETER userObjectId
    The object ID of the user.

    .PARAMETER appId
    The ID of the app.

    .OUTPUTS
    The last hash value as a string.
#>
function Get-LastHashValue {
    param (
        [string]$userObjectId,
        [string]$appId
    )

    $reportingKeyPath = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\Reporting\$userObjectId\$appId\ReportCache\$userObjectId"
    if (Test-Path -Path $reportingKeyPath) {
        $reportingKey = Get-ItemProperty -Path $reportingKeyPath -Name LastHashValue -ErrorAction SilentlyContinue
        return $reportingKey.LastHashValue
    }

    return $null
}

<#
    .SYNOPSIS
    Removes the registry keys for a failed app installation.
    
    .DESCRIPTION
    This function removes the registry keys associated with a failed app installation to trigger a reinstallation attempt.

    .PARAMETER userObjectId
    The object ID of the user.

    .PARAMETER appId
    The ID of the app.

    .PARAMETER lastHashValue
    The last hash value for the app.
#>
function Remove-FailedAppRegistryKeys {
    param (
        [string]$userObjectId,
        [string]$appId,
        [string]$lastHashValue
    )

    $pathsToRemove = @(
        "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\$userObjectId\$appId", # App status per user
        "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\Reporting\$userObjectId\$appId", # Reporting key
        "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\$userObjectId\GRS\$lastHashValue" # GRS using last hash value
    )

    foreach ($path in $pathsToRemove) {
        if (Test-Path -Path $path) {
            Remove-Item -Path $path -Recurse -Force
            Write-Host "Removed registry key: $path"
        }
        else {
            Write-Host "Registry key not found: $path"
        }
    }
}

<#
    .SYNOPSIS
    Retrieves the username from an object ID.
    
    .DESCRIPTION
    This function maps a user object ID to a username by searching the registry.

    .PARAMETER ObjectID
    The object ID of the user.

    .OUTPUTS
    The username as a string.
#>
function Get-UsernameFromObjectID {
    param (
        [string]$ObjectID
    )

    $userSIDs = Get-ChildItem -Path 'Registry::HKEY_USERS\'

    foreach ($userSID in $userSIDs) {
        $identityKeyPath = "Registry::HKEY_USERS\$($userSID.PSChildName)\Software\Microsoft\Office\16.0\Common\Identity"
        if (Test-Path -Path $identityKeyPath) {
            $identityKey = Get-ItemProperty -Path $identityKeyPath
            if ($identityKey.ConnectedAccountWamAad -eq $ObjectID) {
                return $identityKey.ADUserName
            }
        }
    }

    return $null
}

<#
    .SYNOPSIS
    Retrieves the error description for a given error code.
    
    .DESCRIPTION
    This function maps an error code to a descriptive message.

    .PARAMETER errorCode
    The error code as an integer.

    .OUTPUTS
    The error description as a string.
#>
# Loaded once at script scope instead of rebuilding a 60+ entry hashtable
# literal on every single Get-ErrorDescription call. The full table lives
# in MsiErrorCodes.json beside this script so it can be extended without
# touching the script itself; a small embedded fallback covers the most
# common codes if that file is ever missing (e.g. someone copied just the
# .ps1), so error lookups degrade instead of going fully blank.
$script:MsiErrorCodes = $null
function Get-MsiErrorCodeTable {
    if ($null -ne $script:MsiErrorCodes) { return $script:MsiErrorCodes }

    $jsonPath = Join-Path $PSScriptRoot 'MsiErrorCodes.json'
    if (Test-Path -LiteralPath $jsonPath) {
        try {
            $loaded = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
            $table = @{}
            foreach ($prop in $loaded.PSObject.Properties) { $table[$prop.Name] = $prop.Value }
            $script:MsiErrorCodes = $table
            return $script:MsiErrorCodes
        } catch {
            Write-Warning "Could not parse ${jsonPath}: $($_.Exception.Message). Falling back to a minimal built-in error code table."
        }
    }

    $script:MsiErrorCodes = @{
        '0x00000000' = "The action completed successfully."
        '0x80070642' = "The user canceled installation."
        '0x80070643' = "A fatal error occurred during installation."
        '0x80070652' = "Another installation is already in progress. Complete that installation before proceeding with this install."
        '0x80070666' = "Another version of this product is already installed. Installation of this version can't continue."
        '0x80070BB8' = "A restart is required to complete the install. This message indicates success."
    }
    return $script:MsiErrorCodes
}

function Get-ErrorDescription {
    param (
        [int]$errorCode
    )

    $errorCodes = Get-MsiErrorCodeTable
    $hexCode = [convert]::ToString($errorCode, 16).ToUpper()
    $hexCode = '0x' + $hexCode.PadLeft(8, '0')

    if ($errorCodes.ContainsKey($hexCode)) {
        return $errorCodes[$hexCode]
    }
    else {
        return "Unknown error code."
    }
}

#### SCRIPT ENTRY POINT ####

#Requires -RunAsAdministrator

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'This script must be run as Administrator.'
    exit 1
}

# Start Logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
Start-Transcript "C:\Windows\Logs\App_Failure_Remediation_$timestamp.log"

try {
    # Get the failed Win32 app states
    $failedStates = Get-FailedWin32AppStates

    # Process each failed state
    foreach ($state in $failedStates) {
        try {
            # Parse the subkey path to extract User and App ID
            # Expected structure: SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\<userObjId>\<appId>\...
            $subKeyPath = $state.SubKeyPath -replace 'HKLM:\\', ''
            $splitPath  = $subKeyPath -split '\\'

            # Index 6 = userObjectId, index 7 = appId (validate before accessing)
            if ($splitPath.Count -lt 8) {
                Write-Warning "Unexpected registry path structure (expected >=8 segments, got $($splitPath.Count)): $subKeyPath"
                continue
            }

            $userObjectId = $splitPath[6]
            $appId        = $splitPath[7]

            if ([string]::IsNullOrWhiteSpace($userObjectId) -or [string]::IsNullOrWhiteSpace($appId)) {
                Write-Warning "Could not extract userObjectId or appId from path: $subKeyPath"
                continue
            }

            # Get the username
            $userName = Get-UsernameFromObjectID -ObjectID $userObjectId

            # Get the error description
            $errorDescription = Get-ErrorDescription -errorCode $state.ErrorCode

            Write-Host "AppID: $appId failed for user $userName - error $($state.ErrorCode): $errorDescription"

            # Get the LastHashValue and remove registry keys to force re-evaluation
            $lastHashValue = Get-LastHashValue -userObjectId $userObjectId -appId $appId

            if ($lastHashValue) {
                Remove-FailedAppRegistryKeys -userObjectId $userObjectId -appId $appId -lastHashValue $lastHashValue
            } else {
                Remove-FailedAppRegistryKeys -userObjectId $userObjectId -appId $appId
            }
        } catch {
            Write-Warning "Error processing state for $($state.SubKeyPath): $($_.Exception.Message)"
        }
    }

    # Restart the Intune Management Extension if any failures were remediated
    if ($failedStates.Count -gt 0) {
        Write-Host "Remediated $($failedStates.Count) failure(s). Restarting IntuneManagementExtension..."
        Restart-Service -Name 'IntuneManagementExtension' -Force -PassThru
    } else {
        Write-Host "No failures detected."
    }
} catch {
    Write-Error "Unhandled error in remediation script: $($_.Exception.Message)"
} finally {
    Stop-Transcript
}
