$Name  = "EnableCertPaddingCheck"
$Value = 1   # Must be DWORD integer, not string

foreach ($RegistryPath in @(
    "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config",
    "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"
)) {
    if (-not (Test-Path $RegistryPath)) {
        # Create the parent and the key with -Force to avoid errors if parent is missing
        New-Item -Path $RegistryPath -Force | Out-Null
        New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    } elseif ((Get-ItemProperty -Path $RegistryPath -Name $Name -ErrorAction SilentlyContinue).$Name -ne $Value) {
        Set-ItemProperty -Path $RegistryPath -Name $Name -Value $Value
    } else {
        Write-Output "$RegistryPath\$Name is already set to $Value"
        continue
    }
    Write-Output "Set $RegistryPath\$Name = $Value"
}
