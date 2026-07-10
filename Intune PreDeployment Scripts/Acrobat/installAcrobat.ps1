#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Installs/updates Adobe Acrobat DC 64-bit to the latest Continuous-track build.
    Primary method: winget. Falls back to direct Adobe download + MSP patch if winget
    is unavailable or fails.

.NOTES
    • Tested on Windows 10/11 x64 - run from an elevated PowerShell session.
    • Creates C:\Patches\Acrobat for temp work; cleans up when done.
    • Logs to C:\Patches\Logs\Acrobat-YYYY-MM-DD.log
    • Full transcript saved to C:\Patches\Logs\Acrobat-YYYY-MM-DD-transcript.log
#>

# This script has no pipeline input, so it's plain top-level code rather
# than BEGIN/PROCESS/END blocks - those only run PROCESS once per pipeline
# item, and with zero items piped in (the normal "-File installAcrobat.ps1"
# invocation used everywhere this is called), PROCESS never ran at all.
$ProgressPreference = 'SilentlyContinue'   # suppress IWR progress bar; dramatically speeds up downloads
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $Software        = 'Acrobat'
    $WingetId        = 'Adobe.Acrobat.Pro'
    $date            = Get-Date -Format 'yyyy-MM-dd'
    $logDir          = 'C:\Patches\Logs'
    $logPath         = Join-Path $logDir "$Software-$date.log"
    $transcriptPath  = Join-Path $logDir "$Software-$date-transcript.log"
    $acroPath        = Join-Path $env:ProgramFiles 'Adobe\Acrobat DC\Acrobat\Acrobat.exe'
    $workDir         = Join-Path 'C:\Patches' $Software
    $dirs            = @($logDir, $workDir)
    $needsPatch      = $false   # true only when manual base MSI path is taken
    $usedWinget      = $false

    function Write-Log ($msg) {
        $ts = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $msg"
        Add-Content -Path $logPath -Value $ts -ErrorAction SilentlyContinue
        Write-Host $ts
    }

    function Get-AcrobatVersion {
        if (Test-Path $acroPath) { (Get-Item $acroPath).VersionInfo.ProductVersion }
        else { 'Not installed' }
    }

    # Called before every exit to ensure temp files and transcript are always cleaned up
    function Invoke-Cleanup {
        Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue
        Stop-Transcript -ErrorAction SilentlyContinue
    }

    function Exit-Script ([int]$Code) {
        Invoke-Cleanup
        exit $Code
    }

    # Resolves winget.exe in both user sessions and SYSTEM context (Intune)
    function Get-WingetExe {
        $wg = Get-Command winget -ErrorAction SilentlyContinue
        if ($wg) { return $wg.Source }
        # Under SYSTEM, winget lives in WindowsApps but isn't on PATH
        $candidates = Get-ChildItem 'C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe' `
                      -ErrorAction SilentlyContinue |
                      Sort-Object LastWriteTime -Descending
        if ($candidates) { return $candidates[0].FullName }
        return $null
    }

    # Retries a download up to $MaxAttempts times with back-off
    function Invoke-Download {
        param([string]$Uri, [string]$OutFile, [int]$MaxAttempts = 3)
        for ($i = 1; $i -le $MaxAttempts; $i++) {
            try {
                Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -ErrorAction Stop
                return
            } catch {
                if ($i -eq $MaxAttempts) { throw }
                Write-Log "Download attempt $i of $MaxAttempts failed - retrying in 10s... ($_)"
                Start-Sleep 10
            }
        }
    }

    # Launches a process with a hard timeout; returns exit code or -1 if killed for timeout
    function Invoke-Process {
        param(
            [string]$FilePath,
            $ArgumentList,
            [int]$TimeoutSeconds = 1800
        )
        $proc   = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -PassThru -ErrorAction Stop
        $exited = $proc.WaitForExit($TimeoutSeconds * 1000)
        if (!$exited) {
            $proc.Kill()
            Write-Log "ERROR - '$FilePath' did not complete within ${TimeoutSeconds}s and was terminated."
            return -1
        }
        return $proc.ExitCode
    }

    function Stop-AcrobatProcesses {
        $procs = Get-Process -Name 'Acrobat', 'AcroBroker', 'AcroRd32', 'AcroRd32Info' -ErrorAction SilentlyContinue
        if ($procs) {
            Write-Log "Stopping running Acrobat processes to avoid file locks..."
            $procs | Stop-Process -Force -ErrorAction SilentlyContinue
            # Wait up to 10s for actual termination rather than assuming a fixed sleep is enough
            $procs | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
        }
    }

    # Returns $false and logs a warning if the drive hosting $Path has less than $RequiredMB free
    function Test-DiskSpace {
        param([string]$Path, [int]$RequiredMB)
        $drive  = Split-Path -Qualifier $Path
        $disk   = Get-PSDrive -Name $drive.TrimEnd(':') -ErrorAction SilentlyContinue
        if (!$disk) { return $true }   # can't determine; proceed optimistically
        $freeMB = [math]::Floor($disk.Free / 1MB)
        if ($freeMB -lt $RequiredMB) {
            Write-Log "ERROR - Insufficient disk space: ${freeMB}MB free on $drive, need ${RequiredMB}MB."
            return $false
        }
        Write-Log "Disk space OK: ${freeMB}MB free on $drive (need ${RequiredMB}MB)."
        return $true
    }

    foreach ($d in $dirs) {
        if (!(Test-Path $d)) { New-Item $d -ItemType Directory -Force | Out-Null }
    }

    Start-Transcript -Path $transcriptPath -Append -ErrorAction SilentlyContinue

    # Last-resort handler: logs the error location and exits cleanly so Intune sees a failure code
    trap {
        Write-Log "FATAL - Unhandled error: $_"
        Write-Log "  At: $($_.InvocationInfo.PositionMessage)"
        Exit-Script 1
    }

    # Rotate logs older than 30 days to keep C:\Patches\Logs tidy
    Get-ChildItem $logDir -Filter "$Software-*.log" -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
        Remove-Item -Force -ErrorAction SilentlyContinue

    $isSystem   = [Security.Principal.WindowsIdentity]::GetCurrent().Name -eq 'NT AUTHORITY\SYSTEM'
    $runContext = if ($isSystem) { 'SYSTEM' } else { $env:USERNAME }
    Write-Log "=== $Software 64-bit deployment started on $env:COMPUTERNAME (context: $runContext) ==="
    Write-Log "Version before: $(Get-AcrobatVersion)"

    # =========================================================
    # PRIMARY: winget
    # =========================================================
    $wingetExe = Get-WingetExe
    if ($wingetExe) {
        Write-Log "winget found at: $wingetExe"

        # Refresh sources so stale package lists don't cause "not found" on long-idle machines
        Write-Log "Refreshing winget sources..."
        $srcExit = Invoke-Process -FilePath $wingetExe `
                   -ArgumentList @('source', 'update', '--disable-interactivity') `
                   -TimeoutSeconds 120
        if ($srcExit -ne 0) {
            Write-Log "WARNING - winget source update returned exit code $srcExit - continuing anyway."
        }

        $wingetLog  = Join-Path $workDir 'winget.log'
        $commonArgs = @(
            '--id',    $WingetId
            '--silent'
            '--accept-package-agreements'
            '--accept-source-agreements'
            '--scope', 'machine'
            '--architecture', 'x64'
            '--source', 'winget'
            '--disable-interactivity'
            '--log',   $wingetLog
        )

        $acroInstalled = Test-Path $acroPath

        if ($acroInstalled) {
            # Upgrade path: exit 0 = upgraded; -1978335189 = already at latest version
            Write-Log "Existing install detected - attempting winget upgrade..."
            $wgExit = Invoke-Process -FilePath $wingetExe `
                      -ArgumentList (@('upgrade') + $commonArgs) `
                      -TimeoutSeconds 1800
            Write-Log "winget upgrade exit code: $wgExit"
            if ($wgExit -in @(0, -1978335189)) {
                Write-Log "winget upgrade succeeded."
                $usedWinget = $true
            } else {
                Write-Log "winget upgrade failed (exit $wgExit) - will fall back to manual MSP patch."
                $needsPatch = $true
            }
        } else {
            # Fresh install path
            Write-Log "No existing install - attempting winget install..."
            $wgExit = Invoke-Process -FilePath $wingetExe `
                      -ArgumentList (@('install') + $commonArgs) `
                      -TimeoutSeconds 1800
            Write-Log "winget install exit code: $wgExit"
            if ($wgExit -eq 0 -and (Test-Path $acroPath)) {
                Write-Log "winget install succeeded."
                $usedWinget = $true
            } else {
                Write-Log "winget install failed (exit $wgExit) - falling back to manual install."
            }
        }
    } else {
        Write-Log "winget not available - proceeding with manual install."
    }

    # =========================================================
    # FALLBACK: manual download + MSI base install
    # =========================================================
    if (!$usedWinget -and !$needsPatch) {

        # ----------- prerequisite: VC++ 2013 x64 -----------
        Write-Log "Checking for Microsoft Visual C++ 2013 Redistributable (x64)..."
        $vc2013 = @(
            Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                             'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
                -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like '*Visual C++*2013*' -and $_.DisplayName -like '*x64*' }
        )

        if (!$vc2013) {
            $vcUrl  = 'https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x64.exe'
            $vcFile = Join-Path $workDir 'vcredist_x64_2013.exe'
            Write-Log "Downloading VC++ 2013 x64..."
            try { Invoke-Download -Uri $vcUrl -OutFile $vcFile }
            catch { Write-Log "ERROR downloading VC++ 2013: $_"; Exit-Script 1 }

            $vcSig = Get-AuthenticodeSignature -FilePath $vcFile
            if ($vcSig.Status -ne 'Valid' -or $vcSig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
                Write-Log "ERROR - VC++ redistributable failed Authenticode validation (status: $($vcSig.Status)) - refusing to run it."
                Exit-Script 1
            }
            Write-Log "Installing VC++ 2013 x64..."
            $vcExit = Invoke-Process -FilePath $vcFile -ArgumentList '/install /quiet /norestart' -TimeoutSeconds 300
            if ($vcExit -notin @(0, 3010)) {
                Write-Log "WARNING - VC++ 2013 install returned exit code $vcExit."
            }
        } else {
            Write-Log "VC++ 2013 x64 already present (v$($vc2013[0].DisplayVersion))."
        }

        # ----------- install base Acrobat if absent -----------
        if (Test-Path $acroPath) {
            Write-Log "Found existing Acrobat - will apply MSP patch."
            $needsPatch = $true
        } else {
            # Query registry directly - avoids Win32_Product which triggers MSI repair on every installed app
            $legacy = @(
                Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                                 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
                    -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.DisplayName -match 'Adobe Acrobat' -and
                    $_.DisplayVersion -and [Version]$_.DisplayVersion -lt [Version]'20.0'
                }
            )

            if ($legacy) {
                Write-Log "Uninstalling legacy 32-bit Acrobat before 64-bit deployment..."
                foreach ($app in $legacy) {
                    $guid = [regex]::Match($app.UninstallString, '\{[0-9A-F\-]+\}').Value
                    if ($guid) {
                        $unExit = Invoke-Process -FilePath 'msiexec.exe' `
                                  -ArgumentList "/x $guid /qn /norestart" `
                                  -TimeoutSeconds 600
                        # 1605 = product not registered (already removed); treat as success
                        if ($unExit -notin @(0, 3010, 1605)) {
                            Write-Log "WARNING - Legacy uninstall of $guid returned exit code $unExit."
                        }
                    }
                }
            }

            # Base zip is ~700 MB extracted to ~1.4 GB; require 1500 MB free before proceeding
            if (!(Test-DiskSpace -Path $workDir -RequiredMB 1500)) { Exit-Script 1 }

            $zipUrl  = 'https://ardownload3.adobe.com/pub/adobe/acrobat/win/AcrobatDC/Acrobat_Pro_x64_Web_WWMUI.zip'
            $zipFile = Join-Path $workDir 'Acrobat_Pro_x64_Web_WWMUI.zip'
            Write-Log "Downloading Acrobat 64-bit base media..."
            try { Invoke-Download -Uri $zipUrl -OutFile $zipFile }
            catch { Write-Log "ERROR downloading Acrobat base media: $_"; Exit-Script 1 }

            Write-Log "Extracting base media..."
            try {
                Expand-Archive -LiteralPath $zipFile -DestinationPath $workDir -Force -ErrorAction Stop
            } catch {
                Write-Log "ERROR extracting base media: $_"; Exit-Script 1
            }

            $msi = Get-ChildItem $workDir -Recurse -Filter 'AcroPro.msi' | Select-Object -First 1
            if (!$msi) { Write-Log "ERROR - AcroPro.msi not found after extraction."; Exit-Script 1 }

            $msiSig = Get-AuthenticodeSignature -FilePath $msi.FullName
            if ($msiSig.Status -ne 'Valid' -or $msiSig.SignerCertificate.Subject -notmatch 'O=Adobe') {
                Write-Log "ERROR - AcroPro.msi failed Authenticode validation (status: $($msiSig.Status)) - refusing to install it."
                Exit-Script 1
            }

            Stop-AcrobatProcesses
            Write-Log "Installing Acrobat 64-bit base (silent)..."
            $msiExit = Invoke-Process -FilePath 'msiexec.exe' `
                       -ArgumentList "/i `"$($msi.FullName)`" /qn /norestart /l*v `"$logPath`"" `
                       -TimeoutSeconds 1800
            if ($msiExit -notin @(0, 3010, 1641)) {
                Write-Log "ERROR - Base install failed with exit code $msiExit."; Exit-Script 1
            }
            $needsPatch = $true
        }
    }

    if ($needsPatch) {
        # ----------- locate and apply newest 64-bit MSP patch -----------
        Stop-AcrobatProcesses

        $relUrl = 'https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/continuous/index.html'
        Write-Log "Querying Adobe release notes for latest x64 patch..."
        try {
            $html = Invoke-WebRequest -Uri $relUrl -UseBasicParsing -ErrorAction Stop |
                    Select-Object -ExpandProperty Content
        } catch {
            Write-Log "ERROR querying Adobe release notes: $_"; Exit-Script 1
        }

        $m = [regex]::Matches($html, 'https://ardownload3\.adobe\.com[^"]+AcrobatDCx64Upd(?<ver>\d{10})\.msp')
        if ($m.Count -eq 0) { Write-Log "No x64 MSP link found - aborting update."; Exit-Script 1 }

        $latest  = $m | Sort-Object { $_.Groups['ver'].Value } -Descending | Select-Object -First 1
        $mspUrl  = $latest.Value
        $mspVer  = $latest.Groups['ver'].Value
        $mspPath = Join-Path $workDir "AcrobatDCx64Upd${mspVer}.msp"

        Write-Log "Latest patch identified: $mspVer - downloading..."
        try { Invoke-Download -Uri $mspUrl -OutFile $mspPath }
        catch { Write-Log "ERROR downloading patch: $_"; Exit-Script 1 }

        # MSP patches aren't always Authenticode-signed by Adobe the way
        # the base MSI is, so this can't hard-fail on "NotSigned" the way
        # the checks above do without risking false failures on a
        # legitimate patch. If a signature IS present, though, it must be
        # valid and from Adobe - a present-but-invalid/wrong-publisher
        # signature is a clear tamper signal worth stopping on.
        $mspSig = Get-AuthenticodeSignature -FilePath $mspPath
        if ($mspSig.Status -eq 'NotSigned') {
            Write-Log "WARNING - MSP patch $mspVer has no Authenticode signature to verify. Proceeding, but consider validating this download out-of-band."
        } elseif ($mspSig.Status -ne 'Valid' -or $mspSig.SignerCertificate.Subject -notmatch 'O=Adobe') {
            Write-Log "ERROR - MSP patch failed Authenticode validation (status: $($mspSig.Status)) - refusing to apply it."
            Exit-Script 1
        }

        Write-Log "Applying patch $mspVer..."
        $patchExit = Invoke-Process -FilePath 'msiexec.exe' `
                     -ArgumentList "/update `"$mspPath`" /qn /norestart /l*v `"$logPath`"" `
                     -TimeoutSeconds 1800
        switch ($patchExit) {
            0       { Write-Log "Patch applied successfully." }
            3010    { Write-Log "Patch applied - reboot required (3010)." }
            1641    { Write-Log "Patch applied - installer initiated reboot (1641)." }
            default { Write-Log "ERROR - Patch failed with exit code $patchExit."; Exit-Script 1 }
        }
    }

    # Verify the executable is present before declaring success
    if (!(Test-Path $acroPath)) {
        Write-Log "ERROR - Deployment completed but Acrobat.exe not found. Installation may have failed."
        Exit-Script 1
    }

    $method = if ($usedWinget) { 'winget' } else { 'manual' }
    Write-Log "Version after:  $(Get-AcrobatVersion)"
    Write-Log "Cleaning up temp files..."
    Write-Log "=== Deployment finished (via $method) on $env:COMPUTERNAME ==="
    Exit-Script 0
