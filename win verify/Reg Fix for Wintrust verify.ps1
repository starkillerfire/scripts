# Enable WinVerifyTrust signature hardening (CVE-2013-3900)
# Uses .NET remote registry API (DCOM/RPC) - no WinRM required.

$keyPath  = 'SOFTWARE\Microsoft\Cryptography\Wintrust\Config'
$keyName  = 'EnableCertPaddingCheck'
$keyValue = 1

function Enable-WinVerifyTrustHardening {
    param ([string]$TargetSystem)

    try {
        if ($null -eq $TargetSystem -or $TargetSystem -eq 'localhost' -or $TargetSystem -eq $env:COMPUTERNAME) {
            # Local machine - use PS provider directly
            $localPath = 'HKLM:\' + $keyPath
            if (-not (Test-Path $localPath)) {
                New-Item -Path $localPath -Force | Out-Null
            }
            Set-ItemProperty -Path $localPath -Name $keyName -Value $keyValue -Force
        } else {
            # Remote machine - use .NET OpenRemoteBaseKey (DCOM, not WinRM)
            $remoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine, $TargetSystem)
            $regKey = $remoteReg.OpenSubKey($keyPath, $true)
            if ($null -eq $regKey) {
                $regKey = $remoteReg.CreateSubKey($keyPath)
            }
            $regKey.SetValue($keyName, $keyValue, [Microsoft.Win32.RegistryValueKind]::DWord)
            $regKey.Close()
            $remoteReg.Close()
        }

        Write-Output ('Hardening applied successfully on {0}.' -f $TargetSystem)
        return [PSCustomObject]@{ System = $TargetSystem; Status = 'Success' }
    } catch {
        Write-Error ('Failed on {0}: {1}' -f $TargetSystem, $_.Exception.Message)
        return [PSCustomObject]@{ System = $TargetSystem; Status = 'Failed'; ErrorMessage = $_.Exception.Message }
    }
}

# Must run as SYSTEM or with remote registry access rights
if ($env:USERNAME -ne 'SYSTEM') {
    Write-Output 'WARNING: This script is designed to run as SYSTEM (e.g. via PsExec -s or Intune).'
    Write-Output ('Running as "{0}" - remote registry writes may fail without sufficient rights.' -f $env:USERNAME)
}

$inputCsvPath  = 'systems.csv'
$outputCsvPath = 'results.csv'

if (-not (Test-Path -Path $inputCsvPath)) {
    Write-Error "Input CSV not found: $inputCsvPath"
    exit 1
}

$systems    = Import-Csv -Path $inputCsvPath
$resultList = @()

foreach ($system in $systems) {
    $resultList += Enable-WinVerifyTrustHardening -TargetSystem $system.SystemName
}

$resultList | Export-Csv -Path $outputCsvPath -NoTypeInformation -Force
Write-Output "Results exported to: $outputCsvPath"
