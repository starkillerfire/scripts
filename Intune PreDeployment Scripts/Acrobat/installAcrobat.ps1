<#
.SYNOPSIS
    Installs/updates Adobe Acrobat DC **64-bit only** to the latest Continuous-track build.

.NOTES
    • Tested on Windows 10/11 x64 - run from an elevated PowerShell session.
    • Creates C:\Patches\Acrobat for temp work; cleans up when done.
    • Logs to C:\Patches\Logs\Acrobat-YYYY-MM-DD.log
#>

# ───────────────────────── BEGIN ─────────────────────────
BEGIN {
    $Software   = 'Acrobat'
    $date       = Get-Date -Format 'yyyy-MM-dd'
    $logPath    = "C:\Patches\Logs\$Software-$date.log"
    $acroPath   = "${env:ProgramFiles}\Adobe\Acrobat DC\Acrobat\Acrobat.exe"   # x64 location
    $dirs       = @("C:\Patches\Logs","C:\Patches\$Software")

    function TimeStamp ($msg) {
        $ts = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $msg"
        Add-Content -Path $logPath -Value $ts
        $ts
    }

    foreach ($d in $dirs) { if (!(Test-Path $d)) { New-Item $d -ItemType Directory -Force | Out-Null } }

    TimeStamp "=== $Software 64-bit deployment started ==="
}

# ──────────────────────── PROCESS ────────────────────────
PROCESS {

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # ----------- prerequisite: VC++ 2013 x64 -----------
    TimeStamp "Checking for Microsoft Visual C++ 2013 Redistributable (x64)…"
    $vc2013 = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* `
             | Where-Object { $_.DisplayName -like '*Visual C++*2013*' -and $_.DisplayName -like '*x64*' }

    if (!$vc2013) {
        $vcUrl  = 'https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x64.exe'
        $vcFile = "C:\Patches\$Software\vcredist_x64_2013.exe"
        TimeStamp "Downloading VC++ 2013 x64…"
        Invoke-WebRequest -Uri $vcUrl -OutFile $vcFile -UseBasicParsing
        TimeStamp "Installing VC++ 2013 x64…"
        Start-Process $vcFile -ArgumentList '/install /quiet /norestart' -Wait
    } else {
        TimeStamp "VC++ 2013 x64 already present (v$($vc2013.DisplayVersion))."
    }

    # ----------- install base Acrobat if absent -----------
    $acroExists = Test-Path $acroPath
    if ($acroExists) {
        TimeStamp "Found Acrobat at $acroPath - will patch to latest."
    } else {
        # Remove any lingering 32-bit install first
        $legacy = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match 'Adobe Acrobat' -and $_.Version -lt  '20' }
        if ($legacy) {
            TimeStamp "Uninstalling legacy 32-bit Acrobat before 64-bit deployment…"
            foreach ($app in $legacy) { $app.Uninstall() | Out-Null }
        }

        $zipUrl  = 'https://ardownload3.adobe.com/pub/adobe/acrobat/win/AcrobatDC/Acrobat_Pro_x64_Web_WWMUI.zip'  # 64-bit unified installer
        $zipFile = "C:\Patches\$Software\Acrobat_Pro_x64_Web_WWMUI.zip"
        TimeStamp "Downloading Acrobat 64-bit base media…"
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile -UseBasicParsing
        TimeStamp "Extracting base media…"
        Expand-Archive -LiteralPath $zipFile -DestinationPath "C:\Patches\$Software" -Force

        $msi = Get-ChildItem "C:\Patches\$Software" -Recurse -Filter 'AcroPro.msi' | Select-Object -First 1
        if (!$msi) { TimeStamp "ERROR - AcroPro.msi not found after extraction."; exit 1 }

        TimeStamp "Installing Acrobat 64-bit base (silent)…"
        Start-Process msiexec.exe -ArgumentList "/i `"$($msi.FullName)`" /qn" -Wait
    }
}

# ───────────────────────── END ──────────────────────────
END {

    # ----------- locate newest 64-bit patch -----------
    $relUrl   = 'https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/continuous/index.html'
    TimeStamp "Querying Adobe release notes for latest x64 patch…"
    $html     = Invoke-WebRequest -Uri $relUrl -UseBasicParsing | Select-Object -ExpandProperty Content
    $m = [regex]::Matches($html, 'https://ardownload3\.adobe\.com[^"]+AcrobatDCx64Upd(?<ver>\d{10})\.msp')
    if ($m.Count -eq 0) { TimeStamp "No x64 MSP link found - aborting update."; exit }
    $latest   = $m | Sort-Object { $_.Groups['ver'].Value } -Descending | Select-Object -First 1

    $mspUrl   = $latest.Value
    $mspVer   = $latest.Groups['ver'].Value
    $mspPath  = "C:\Patches\$Software\AcrobatDCx64Upd${mspVer}.msp"

    TimeStamp "Latest patch identified: $mspVer - downloading…"
    Invoke-WebRequest -Uri $mspUrl -OutFile $mspPath -UseBasicParsing

    TimeStamp "Applying patch $mspVer…"
    $proc = Start-Process msiexec.exe -ArgumentList "/update `"$mspPath`" /qn /norestart /l*v `"$logPath`"" -Wait -PassThru
    switch ($proc.ExitCode) {
        0     { TimeStamp "Update succeeded." }
        3010  { TimeStamp "Update succeeded - reboot required (3010)." }
        1641  { TimeStamp "Update succeeded - installer initiated reboot (1641)." }
        default{ TimeStamp "Update failed with exit code $($proc.ExitCode)." }
    }

    TimeStamp "Cleaning up temp files…"
    Remove-Item "C:\Patches\$Software" -Recurse -Force -ErrorAction SilentlyContinue
    TimeStamp "=== Deployment finished ==="
}
