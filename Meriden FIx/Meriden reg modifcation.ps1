<# 
.SYNOPSIS
  Sets WorkspaceDB=8 for Meridian client in both 64-bit and WOW6432Node registry paths.
  Forces reboot after 5 minutes.

.NOTES
  Run from an elevated PowerShell prompt.
#>

[CmdletBinding()]
param()

# --- Require admin ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$targets = @(
    "Cyco\AutoManager Meridian\CurrentVersion\Client",
    "WOW6432Node\Cyco\AutoManager Meridian\CurrentVersion\Client"
)

$hive  = [Microsoft.Win32.RegistryHive]::LocalMachine
$view  = [Microsoft.Win32.RegistryView]::Registry64

function Set-DwordValue {
    param(
        [Microsoft.Win32.RegistryKey]$rootKey,
        [string]$relativePath,
        [string]$name,
        [int]$value
    )

    $current = $rootKey.OpenSubKey("SOFTWARE", $true)
    foreach ($part in $relativePath -split '\\') {
        $next = $current.OpenSubKey($part, $true)
        if (-not $next) { $next = $current.CreateSubKey($part) }
        $current.Dispose()
        $current = $next
    }

    $current.SetValue($name, $value, [Microsoft.Win32.RegistryValueKind]::DWord)
    $current.Dispose()
}

try {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)

    foreach ($relPath in $targets) {
        Set-DwordValue -rootKey $base -relativePath $relPath -name "WorkspaceDB" -value 8
        Write-Host "Set HKLM\SOFTWARE\$relPath -> WorkspaceDB (DWORD) = 8"
    }

    $base.Dispose()

    Write-Host "✅ Registry updated successfully."
    Write-Host "⚠️ System will reboot in 5 minutes..."

    # Schedule reboot in 5 minutes (300 seconds)
    shutdown.exe /r /t 300 /c "System changes applied for Meridian Client. Rebooting in 5 minutes."

    exit 0
}
catch {
    Write-Error "Failed to update registry: $($_.Exception.Message)"
    exit 2
}
