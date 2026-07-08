# Cobbler: Brian Lamb
# brian_lamb@firenet.gov
# Date: 29-Oct-2020 Version 1.0
# Date: 16-Jul-2021 Version 1.1
# Date: 7-Sep-2021  Version 1.2
# Date: 13-May-2026 Version 2.0 - Bug fixes, admin check, Chromium Edge, transcript logging
# Date: 13-May-2026 Version 2.1 - Chrome/Edge all-profiles, Firefox/IE all-users, OneDrive
#   null ref guard, Teams v2 wildcard fix, PinnedItems loop safety, try/finally transcript,
#   reboot hint; added Windows Temp, credentials, RDP, clipboard, print queue, CleanMgr
#   expansion, DISM component cleanup.
# Date: 13-May-2026 Version 2.2 - Chrome/Edge single-traversal optimization, COM object
#   release in finally block, stop Windows Update before SoftwareDistribution wipe,
#   CleanMgr/DISM/shutdown exit code checks, Outlook OST/PST/NK2 file cleanup,
#   Explorer history (Run MRU, TypedPaths, WordWheelQuery), Prefetch, Event Log clearing,
#   all-users temp cache, Invoke-Step wrapper for per-step timestamps, completion summary.
# Date: 13-May-2026 Version 2.3 - Invoke-Step failure tracking with per-step error list in
#   summary; Teams/PinnedItems/Clipboard expanded to all users; Outlook Documents PST added;
#   Prefetch -Recurse; CleanMgr null-safe ExitCode check; Chrome/Edge regex filter replaces
#   nested Where-Object (fixes PSUseDeclaredVarsMoreThanAssignments); quoted -Exclude values.
# Date: 13-May-2026 Version 2.4 - All registry operations now cover all user hives via
#   Invoke-ForEachUserHive (fixes HKCU-only scope for OneDrive, RDP, Outlook, Explorer history);
#   Edge regex gains Archived History; shared BrowserDataRegex constant eliminates duplication;
#   StateFlags0001 cleaned up post-CleanMgr; shutdown commands moved inside transcript scope;
#   Quick Access unpin 300ms settle delay; Firefox filter broadened + sessionstore-backups added;
#   PST search extended to Downloads/Desktop; browser extension local storage and IndexedDB
#   cleared; cmdkey parsing hardened; DISM /ResetBase option documented in comment;
#   Security log clearing note added.
# Date: 13-May-2026 Version 2.5 - Invoke-ForEachUserHive now checks reg load exit code and
#   skips profiles whose hive cannot be mounted; wuauserv/bits/spooler only restarted if they
#   were running before the script stopped them (avoids re-enabling GPO-disabled services);
#   RecentDocs registry key added to Clear-WindowsHistory; DNS cache flush step added;
#   -SkipReboot switch added for log-review workflows; cmdkey current-user-only limitation
#   documented in Clear-NetworkCredentials.
# Date: 13-May-2026 Version 2.6 - [CmdletBinding(SupportsShouldProcess)] enables -WhatIf
#   dry-run mode; native commands guarded with $WhatIfPreference; transcript skipped in WhatIf
#   mode; Read-Host prompt suppressed in WhatIf mode; hardcoded C:\ replaced with
#   $env:SystemDrive/$env:SystemRoot/$env:ProgramData throughout; $UsersBase convenience
#   variable introduced; PSReadLine command history added to Clear-WindowsHistory; per-user
#   thumbnail cache added to Clear-WindowsHistory; Teams meeting recordings added to
#   Remove-TeamsProfile; Clear-WER step added for Windows Error Reporting data (per-user and
#   system-wide); Clear-EventLogs now dynamically clears all non-empty logs via
#   EventLogSession.ClearLog; .bat updated to forward %* so -SkipReboot/-WhatIf work from
#   the launcher.

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$SkipReboot,
    # Clearing the Security log on a domain-joined machine can trigger SIEM
    # alerts or conflict with GPO audit-retention policy - pass this to skip
    # it specifically while still clearing everything else, rather than
    # having to coordinate with the security team every single time.
    [switch]$PreserveSecurityLog,
    # PST files found under Documents/Downloads/Desktop are deleted outright
    # by default. Pass this to copy them to $PstBackupPath first instead of
    # just deleting - a user may have intentionally archived a PST outside
    # the default Outlook data file location.
    [switch]$BackupPst,
    [string]$PstBackupPath = "$env:SystemDrive\PstBackup"
)

#region Admin check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')) {
    Write-Error "This script must be run as Administrator. Exiting."
    exit 1
}
#endregion

#region Transcript - skipped in WhatIf mode (nothing to log, log dir may not exist)
if (-not $WhatIfPreference) {
    $LogDir = "$env:SystemDrive\Logs"
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    $LogPath = "$LogDir\Reset_Fire_Laptop_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Start-Transcript -Path $LogPath
    Write-Host "Logging to $LogPath`n"
}
#endregion

# Base path for all user profiles - avoids hardcoding C:\Users throughout.
# $env:SystemDrive is set by Windows (e.g. C:) and is correct even on non-C installs.
$UsersBase = "$env:SystemDrive\Users"

# Shared regex for Chromium-based browser data - used by both Clear-Chrome and Clear-Edge.
# Includes extension local storage so cached auth tokens are also cleared.
$script:BrowserDataRegex = 'Archived History|Cache|Cookies|History|IndexedDB|Local Extension Settings|Login Data|Top Sites|Visited Links|Web Data'

# Stop a process by name and wait for it to fully exit before continuing
function Stop-ProcessAndWait {
    param([string]$Name)
    $proc = Get-Process $Name -ErrorAction SilentlyContinue
    if ($proc) {
        $proc | Stop-Process -Force
        $proc | Wait-Process -Timeout 15 -ErrorAction SilentlyContinue
        Write-Host "$Name processes stopped..." -ForegroundColor Green
    }
    else {
        Write-Host "$Name not running..." -ForegroundColor Yellow
    }
}

# Collects names of any steps that threw - read by the summary block.
$script:stepErrors = [System.Collections.Generic.List[string]]::new()

# Run a named cleanup step with a timestamp header and elapsed time footer.
# Errors are caught and logged per-step so a single failure doesn't abort the rest.
function Invoke-Step {
    param([string]$Name, [scriptblock]$Action)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host "`n[$( Get-Date -Format 'HH:mm:ss')]  $Name" -ForegroundColor Cyan
    try   { & $Action }
    catch {
        Write-Host "  ERROR: $_" -ForegroundColor Red
        $script:stepErrors.Add($Name)
    }
    finally {
        $sw.Stop()
        Write-Host "  ($([math]::Round($sw.Elapsed.TotalSeconds, 1))s)" -ForegroundColor DarkGray
    }
}

# Enumerates every local user profile (SID S-1-5-21-*), loads their NTUSER.DAT hive under
# HKU\<SID> if it is not already mounted, calls $Action with -Sid and -ProfilePath, then
# unloads any hive this function mounted.  Forces GC before unload to release .NET registry
# handles that would otherwise cause "Access is denied" from reg.exe.
function Invoke-ForEachUserHive {
    param([scriptblock]$Action)
    $profileList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    Get-ChildItem $profileList -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^S-1-5-21' } |
        ForEach-Object {
            $sid  = $_.PSChildName
            $path = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
            if (-not $path -or -not (Test-Path $path)) { return }
            $ntuser        = Join-Path $path 'NTUSER.DAT'
            $alreadyLoaded = Test-Path "Registry::HKU\$sid"
            $loaded        = $false
            if (-not $alreadyLoaded -and (Test-Path $ntuser)) {
                reg load "HKU\$sid" $ntuser 2>$null | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning "  Could not load hive for $(Split-Path $path -Leaf) - skipping"
                    return
                }
                $loaded = $true
            }
            try { & $Action -Sid $sid -ProfilePath $path }
            finally {
                if ($loaded) {
                    [gc]::Collect()
                    [gc]::WaitForPendingFinalizers()
                    reg unload "HKU\$sid" 2>$null | Out-Null
                    if ($LASTEXITCODE -ne 0) {
                        Write-Warning "  Could not unload hive for $(Split-Path $path -Leaf) (HKU\$sid) - it may still be mounted and could affect this user's next logon."
                    }
                }
            }
        }
}

Function Clear-Chrome {
    Stop-ProcessAndWait -Name 'chrome'

    # Single traversal - covers all users and all Chrome profiles (Default, Profile 1, …).
    # BrowserDataRegex includes extension local storage for cached auth tokens.
    Get-ChildItem "$UsersBase\*\AppData\Local\Google\Chrome\User Data" -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $script:BrowserDataRegex } |
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Yellow "Google Chrome Cache Removal - COMPLETE`r`n"
}

Function Clear-IE {
    Stop-ProcessAndWait -Name 'iexplore'

    # IE was EOL June 2022 and removed from Windows 11; retained for legacy machines
    $bases = @(
        "$UsersBase\*\AppData\Local\Microsoft\Windows\Temporary Internet Files",
        "$UsersBase\*\AppData\Local\Microsoft\Windows\Caches"
    )
    foreach ($base in $bases) {
        Get-ChildItem $base -Force -Recurse -ErrorAction SilentlyContinue |
            Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }

    Write-Host -ForegroundColor Yellow "IE Cache Removal - COMPLETE`r`n"
}

Function Clear-FireFox {
    Stop-ProcessAndWait -Name 'firefox'

    # Cache in AppData\Local; profile data in AppData\Roaming. $UsersBase covers all accounts.
    $ProfileBases = @(
        "$UsersBase\*\AppData\Local\Mozilla\Firefox\Profiles",
        "$UsersBase\*\AppData\Roaming\Mozilla\Firefox\Profiles"
    )

    $Items = @(
        'cache', 'cache2\entries', 'thumbnails',
        'cookies.sqlite', 'webappsstore.sqlite', 'chromeappsstore.sqlite',
        'places.sqlite',          # browsing history + bookmarks
        'formhistory.sqlite',     # autofill form data
        'logins.json',            # saved passwords
        'key4.db',                # password encryption key
        'sessionstore.jsonlz4',   # saved session tabs
        'sessionstore-backups'    # session backup folder
    )

    foreach ($base in $ProfileBases) {
        Get-ChildItem $base -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '\.default|\.dev-edition-default' } |
            ForEach-Object {
                $profilePath = $_.FullName
                foreach ($item in $Items) {
                    Remove-Item -Path (Join-Path $profilePath $item) -Force -Recurse -ErrorAction SilentlyContinue
                }
            }
    }

    Write-Host -ForegroundColor Yellow "Firefox Cache Removal - COMPLETE`r`n"
}

Function Clear-Edge {
    Stop-ProcessAndWait -Name 'msedge'

    # Single traversal - covers all users and all Edge profiles.
    # BrowserDataRegex includes Archived History and extension local storage.
    Get-ChildItem "$UsersBase\*\AppData\Local\Microsoft\Edge\User Data" -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $script:BrowserDataRegex } |
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

    # Legacy EdgeHTML (UWP) - kept for any machines that still have it
    Remove-Item "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\#!*" -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Yellow "Edge Cache Removal - COMPLETE`r`n"
}

Function Remove-OneDriveBusinessAccounts {
    Write-Host "Clearing OneDrive Business accounts (all users)..."
    Stop-ProcessAndWait -Name 'OneDrive'

    Invoke-ForEachUserHive {
        param([string]$Sid, [string]$ProfilePath)
        $accountsRegKeyPath = "Registry::HKU\$Sid\Software\Microsoft\OneDrive\Accounts"
        $accountsKey = Get-Item $accountsRegKeyPath -ErrorAction SilentlyContinue
        if (-not $accountsKey) { return }

        $businessSubKeys = $accountsKey.GetSubKeyNames() -match '^Business'
        if (-not $businessSubKeys) { return }

        foreach ($subkey in $businessSubKeys) {
            $oneDriveAccountKeyPath = Join-Path -Path $accountsRegKeyPath -ChildPath $subkey
            $userEmail   = (Get-ItemProperty -Path $oneDriveAccountKeyPath -Name UserEmail   -ErrorAction SilentlyContinue).UserEmail
            $displayName = (Get-ItemProperty -Path $oneDriveAccountKeyPath -Name DisplayName -ErrorAction SilentlyContinue).DisplayName
            $oneDriveName = "OneDrive - $displayName"

            Write-Host "  Removing: $userEmail ($displayName) for $(Split-Path $ProfilePath -Leaf)"

            $desktopPath = "Registry::HKU\$Sid\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace"
            Get-ChildItem $desktopPath -ErrorAction SilentlyContinue |
                Where-Object { (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).'(Default)' -eq $oneDriveName } |
                ForEach-Object {
                    Remove-Item -Path $_.PSPath -Recurse -ErrorAction SilentlyContinue
                    Write-Host "  Removed Explorer namespace key for ""$oneDriveName"""
                }

            Remove-Item -Path $oneDriveAccountKeyPath -Recurse -ErrorAction SilentlyContinue
            Write-Host "  Removed $oneDriveAccountKeyPath"
        }
    }

    Write-Host -ForegroundColor Yellow "OneDrive Business Account Removal - COMPLETE`r`n"
}

Function Remove-UserCache {
    Write-Host "Clearing user temp caches (all users)..."
    # $UsersBase covers every profile on the machine, not just the current session
    Remove-Item "$UsersBase\*\AppData\Local\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host -ForegroundColor Yellow "User Cache Removal - COMPLETE`r`n"
}

Function Clear-WER {
    Write-Host "Clearing Windows Error Reporting data (all users and system)..."
    # Per-user crash reports can contain stack traces, env variables, and partial memory dumps
    Remove-Item "$UsersBase\*\AppData\Local\Microsoft\Windows\WER\*"    -Recurse -Force -ErrorAction SilentlyContinue
    # System-wide WER queue and report archive ($env:ProgramData avoids hardcoded C:\)
    Remove-Item "$env:ProgramData\Microsoft\Windows\WER\ReportQueue\*"   -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:ProgramData\Microsoft\Windows\WER\ReportArchive\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host -ForegroundColor Yellow "WER Cleanup - COMPLETE`r`n"
}

Function Clear-WindowsTemp {
    Write-Host "Clearing Windows Temp and SoftwareDistribution Download cache..."

    # Capture original state - only restart services that were running before we stopped them
    $wuWasRunning   = (Get-Service wuauserv -ErrorAction SilentlyContinue).Status -eq 'Running'
    $bitsWasRunning = (Get-Service bits     -ErrorAction SilentlyContinue).Status -eq 'Running'

    # Stop Windows Update and BITS - SoftwareDistribution files may be locked while
    # an update is downloading or staging
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Stop-Service -Name bits     -Force -ErrorAction SilentlyContinue

    Remove-Item "$env:SystemRoot\Temp\*"                          -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue

    if ($wuWasRunning)   { Start-Service -Name wuauserv -ErrorAction SilentlyContinue }
    if ($bitsWasRunning) { Start-Service -Name bits     -ErrorAction SilentlyContinue }

    Write-Host -ForegroundColor Yellow "Windows Temp Removal - COMPLETE`r`n"
}

Function Clear-NetworkCredentials {
    Write-Host "Clearing stored network credentials..."

    # Note: cmdkey only operates on the current user's DPAPI-protected credential vault.
    # Other users' stored credentials cannot be enumerated or deleted without their
    # password or a domain recovery key - this is a Windows platform limitation.
    # Split on 'Target:' to handle output format variations across Windows versions.
    $targets = (cmdkey /list) -match 'Target:' |
        ForEach-Object { ($_ -split 'Target:\s*')[1].Trim() }

    if ($targets) {
        foreach ($target in $targets) {
            if ($WhatIfPreference) {
                Write-Host "  What if: would delete credential: $target" -ForegroundColor DarkYellow
            }
            else {
                cmdkey /delete:"$target" | Out-Null
                Write-Host "Removed credential: $target"
            }
        }
    }
    else {
        Write-Host "No stored credentials found." -ForegroundColor Yellow
    }

    Write-Host -ForegroundColor Yellow "Network Credential Removal - COMPLETE`r`n"
}

Function Clear-RDPHistory {
    Write-Host "Clearing RDP connection history (all users)..."

    Invoke-ForEachUserHive {
        param([string]$Sid, [string]$ProfilePath)
        $rdpKey = "Registry::HKU\$Sid\Software\Microsoft\Terminal Server Client"
        Remove-Item "$rdpKey\Servers" -Recurse -Force -ErrorAction SilentlyContinue

        $mruKey = "$rdpKey\Default"
        if (Test-Path $mruKey) {
            Get-ItemProperty $mruKey -ErrorAction SilentlyContinue |
                Get-Member -MemberType NoteProperty |
                Where-Object { $_.Name -like 'MRU*' } |
                ForEach-Object { Remove-ItemProperty -Path $mruKey -Name $_.Name -ErrorAction SilentlyContinue }
        }
        Write-Host "  RDP history cleared for: $(Split-Path $ProfilePath -Leaf)"
    }

    Write-Host -ForegroundColor Yellow "RDP History Removal - COMPLETE`r`n"
}

Function Clear-ClipboardHistory {
    Write-Host "Clearing clipboard history (all users)..."
    # $UsersBase covers all profiles. Live clipboard clears automatically on reboot.
    Remove-Item "$UsersBase\*\AppData\Local\Microsoft\Windows\Clipboard\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host -ForegroundColor Yellow "Clipboard History Removal - COMPLETE`r`n"
}

Function Clear-PrintQueue {
    Write-Host "Clearing print queue..."
    $spoolerWasRunning = (Get-Service spooler -ErrorAction SilentlyContinue).Status -eq 'Running'
    Stop-Service -Name spooler -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:SystemRoot\System32\spool\PRINTERS\*" -Recurse -Force -ErrorAction SilentlyContinue
    if ($spoolerWasRunning) { Start-Service -Name spooler -ErrorAction SilentlyContinue }
    Write-Host -ForegroundColor Yellow "Print Queue Removal - COMPLETE`r`n"
}

Function Clear-WindowsHistory {
    Write-Host "Clearing Windows Explorer and system histories (all users)..."

    Invoke-ForEachUserHive {
        param([string]$Sid, [string]$ProfilePath)
        $base = "Registry::HKU\$Sid\Software\Microsoft\Windows\CurrentVersion\Explorer"
        # Run dialog MRU
        Remove-Item "$base\RunMRU"         -Recurse -Force -ErrorAction SilentlyContinue
        # File Explorer address bar typed paths
        Remove-Item "$base\TypedPaths"     -Recurse -Force -ErrorAction SilentlyContinue
        # Start menu / taskbar search history
        Remove-Item "$base\WordWheelQuery" -Recurse -Force -ErrorAction SilentlyContinue
        # Recently opened files list (by file type - Word docs, PDFs, etc.)
        Remove-Item "$base\RecentDocs"     -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  Explorer history cleared for: $(Split-Path $ProfilePath -Leaf)"
    }

    # Prefetch reveals program execution history; Windows rebuilds it automatically
    Remove-Item "$env:SystemRoot\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue

    # Thumbnail cache reveals image browsing history - per-user, not covered by CleanMgr
    Remove-Item "$UsersBase\*\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db" `
        -Force -ErrorAction SilentlyContinue

    # PowerShell command history can contain credentials typed in the terminal
    Remove-Item "$UsersBase\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" `
        -Force -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Yellow "Windows History Removal - COMPLETE`r`n"
}

Function Clear-EventLogs {
    Write-Host "Clearing Windows Event Logs (all logs with content)..."

    # Note: clearing the Security log on domain-joined machines may trigger SIEM alerts
    # or conflict with GPO audit-retention policies - coordinate with the security team,
    # or pass -PreserveSecurityLog to skip just that log.
    $cleared = 0
    $skipped = 0
    Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
        Where-Object { $_.RecordCount -gt 0 } |
        ForEach-Object {
            if ($PreserveSecurityLog -and $_.LogName -eq 'Security') {
                Write-Host "  Preserved: '$($_.LogName)' (per -PreserveSecurityLog)" -ForegroundColor DarkYellow
                $skipped++
                return
            }
            if ($WhatIfPreference) {
                Write-Host "  What if: would clear log '$($_.LogName)'" -ForegroundColor DarkYellow
                $cleared++
            }
            else {
                try {
                    [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName)
                    $cleared++
                }
                catch { $skipped++ }
            }
        }
    Write-Host "  Cleared: $cleared log(s)   Skipped (protected/locked): $skipped" -ForegroundColor Cyan
    Write-Host -ForegroundColor Yellow "Event Log Clearing - COMPLETE`r`n"
}

Function Remove-TeamsProfile {
    # Classic Teams (v1) - stop process, then clear data for ALL users on the machine
    Stop-ProcessAndWait -Name 'teams'

    Get-Item "$UsersBase\*\AppData\Roaming\Microsoft\Teams" -ErrorAction SilentlyContinue |
        ForEach-Object {
            Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Classic Teams removed for: $($_.FullName.Split('\')[2])" -ForegroundColor Cyan
        }
    Get-Item "$UsersBase\*\AppData\Local\Microsoft\Teams" -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    # AAD Broker Plugin caches Azure AD auth tokens shared by Teams and other apps
    Get-Item "$UsersBase\*\AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_*" -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    # New Teams (v2) - process: ms-teams, data: LocalAppData\Packages\MSTeams_* (all users)
    Stop-ProcessAndWait -Name 'ms-teams'

    Get-Item "$UsersBase\*\AppData\Local\Packages\MSTeams_*" -ErrorAction SilentlyContinue |
        ForEach-Object {
            Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "New Teams (v2) removed for: $($_.FullName.Split('\')[2])" -ForegroundColor Cyan
        }

    # Meeting recordings saved locally - can be large and contain sensitive operational content
    Remove-Item "$UsersBase\*\Videos\Microsoft Teams\*" -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Yellow "Teams Profile Removal - COMPLETE`r`n"
}

Function Remove-OutlookProfile {
    Stop-ProcessAndWait -Name 'outlook'

    # Registry profile key - clear for every user hive, not just the running user
    Invoke-ForEachUserHive {
        param([string]$Sid, [string]$ProfilePath)
        Remove-Item "Registry::HKU\$Sid\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles" `
            -Force -Recurse -ErrorAction SilentlyContinue
        Write-Host "  Outlook profile registry cleared for: $(Split-Path $ProfilePath -Leaf)"
    }

    # OST files can be gigabytes of cached email/calendar/contacts - remove across all users
    Remove-Item "$UsersBase\*\AppData\Local\Microsoft\Outlook\*.ost"     -Force -ErrorAction SilentlyContinue
    Remove-Item "$UsersBase\*\AppData\Local\Microsoft\Outlook\*.ost.old" -Force -ErrorAction SilentlyContinue
    Remove-Item "$UsersBase\*\AppData\Local\Microsoft\Outlook\*.nk2"     -Force -ErrorAction SilentlyContinue

    # PST files - search Documents, Downloads, and Desktop across all users.
    # These can be intentionally-archived mailboxes a user moved out of the
    # default Outlook data file location, not just cache - so back them up
    # first when -BackupPst is passed instead of deleting outright.
    $pstFiles = Get-ChildItem "$UsersBase\*\Documents", "$UsersBase\*\Downloads", "$UsersBase\*\Desktop" `
        -Filter '*.pst' -Recurse -Force -ErrorAction SilentlyContinue

    $pstFilesToDelete = $pstFiles
    if ($BackupPst -and $pstFiles) {
        if (-not (Test-Path $PstBackupPath)) { New-Item -Path $PstBackupPath -ItemType Directory -Force | Out-Null }
        $failedBackups = New-Object System.Collections.Generic.List[string]
        foreach ($pst in $pstFiles) {
            $userName = ($pst.FullName -split '\\')[$UsersBase.Split('\\').Count]
            $destName = "$userName-$($pst.Name)"
            try {
                Copy-Item -Path $pst.FullName -Destination (Join-Path $PstBackupPath $destName) -Force -ErrorAction Stop
                Write-Host "  Backed up: $($pst.FullName) -> $(Join-Path $PstBackupPath $destName)"
            } catch {
                Write-Host "  WARNING: Could not back up $($pst.FullName): $($_.Exception.Message) - this file will NOT be deleted." -ForegroundColor Yellow
                $failedBackups.Add($pst.FullName)
            }
        }
        # A failed backup must not still result in deleting the only copy
        # of what may be an intentionally archived mailbox - only PSTs that
        # were actually backed up successfully get removed below.
        $pstFilesToDelete = $pstFiles | Where-Object { $_.FullName -notin $failedBackups }
    }

    $pstFilesToDelete | Remove-Item -Force -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Yellow "Outlook Profile Removal - COMPLETE`r`n"
}

Function Clear-PinnedItems {
    Write-Host "Clearing Pinned Items (all users)..."

    # $UsersBase covers all profiles, not just the current session
    Get-ChildItem "$UsersBase\*\AppData\Roaming\Microsoft\Windows\Recent\*" -File -Force -Exclude 'desktop.ini' |
        Remove-Item -Force -ErrorAction SilentlyContinue

    Get-ChildItem "$UsersBase\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*" -File -Force `
        -Exclude 'desktop.ini', 'f01b4d95cf55d32a.automaticDestinations-ms' |
        Remove-Item -Force -ErrorAction SilentlyContinue

    Get-ChildItem "$UsersBase\*\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*" -File -Force -Exclude 'desktop.ini' |
        Remove-Item -Force -ErrorAction SilentlyContinue

    # Unpin Quick Access folders one at a time; break and restart enumeration after each
    # DoIt() call because the COM collection becomes stale once an item is removed.
    # The 300 ms settle delay prevents re-seeing a just-removed item on rapid re-enumeration.
    # Release the COM object in finally to avoid handle leaks.
    $shell = New-Object -ComObject Shell.Application
    try {
        if ($WhatIfPreference) {
            # InvokeVerb is a raw COM call and does NOT honor
            # $WhatIfPreference the way native cmdlets do - without this
            # explicit check, -WhatIf would still really unpin every Quick
            # Access item despite the "no changes will be made" banner. This
            # is a single preview pass rather than reusing the retry loop
            # below (which exists to handle the COM collection going stale
            # after a REAL removal - not applicable when nothing is removed).
            foreach ($item in $shell.Namespace("shell:::{679f85cb-0220-4080-b29b-5540cc05aab6}").Items()) {
                if (-not $item.IsFolder) { continue }
                Write-Host "  What if: would unpin '$($item.Name)' from Quick access" -ForegroundColor DarkYellow
            }
            return
        }

        $maxIterations = 50
        $iteration = 0
        $found = $true
        while ($found -and $iteration -lt $maxIterations) {
            $iteration++
            $found = $false
            foreach ($item in $shell.Namespace("shell:::{679f85cb-0220-4080-b29b-5540cc05aab6}").Items()) {
                if (-not $item.IsFolder) { continue }
                # 'unpinfromhome' is the shell's canonical, locale-independent
                # verb for this action - matching the display text "Remove
                # from Quick access" only works on English Windows and
                # silently no-ops (nothing ever gets unpinned, no error) on
                # any other display language.
                try {
                    $item.InvokeVerb('unpinfromhome')
                    Start-Sleep -Milliseconds 300
                    $found = $true
                    break
                } catch {
                    continue
                }
            }
        }
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
    }

    Write-Host -ForegroundColor Yellow "Pinned Items Removal - COMPLETE`r`n"
}

Function Clear-Disk {
    Write-Host 'Configuring CleanMgr.exe automation settings...'

    $volCacheBase = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'

    Get-ItemProperty -Path "$volCacheBase\*" -Name StateFlags0001 -ErrorAction SilentlyContinue |
        Remove-ItemProperty -Name StateFlags0001 -ErrorAction SilentlyContinue

    Write-Host 'Enabling Cleanup Options...'
    $categories = @(
        'Downloaded Program Files',
        'Delivery Optimization Files',
        'Internet Cache Files',
        'Memory Dump Files',
        'Old ChkDsk Files',
        'Recycle Bin',
        'System error memory dump files',
        'System error minidump files',
        'Temporary Files',
        'Temporary Setup Files',
        'Thumbnail Cache',
        'Update Cleanup',
        'Windows Error Reporting Archive Files',
        'Windows Error Reporting Files',
        'Windows Error Reporting Queue Files',
        'Windows Upgrade Log Files'
    )
    foreach ($cat in $categories) {
        New-ItemProperty -Path "$volCacheBase\$cat" -Name StateFlags0001 -Type DWORD -Value 2 -Force -ErrorAction SilentlyContinue | Out-Null
    }

    if ($WhatIfPreference) {
        Write-Host '  What if: would run CleanMgr.exe /sagerun:1' -ForegroundColor DarkYellow
    }
    else {
        Write-Host 'Starting CleanMgr.exe...'
        $cleanProc = Start-Process -FilePath CleanMgr.exe -ArgumentList '/sagerun:1' -WindowStyle Hidden -Wait -PassThru
        if ($null -ne $cleanProc.ExitCode -and $cleanProc.ExitCode -ne 0) {
            Write-Warning "CleanMgr.exe exited with code $($cleanProc.ExitCode)"
        }
        Write-Host 'Waiting for CleanMgr and DismHost to finish...'
        Get-Process -Name cleanmgr, dismhost -ErrorAction SilentlyContinue | Wait-Process
    }

    # Remove the flags we set so interactive CleanMgr runs start with a clean slate
    Get-ItemProperty -Path "$volCacheBase\*" -Name StateFlags0001 -ErrorAction SilentlyContinue |
        Remove-ItemProperty -Name StateFlags0001 -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Yellow "Disk Cleanup - COMPLETE`r`n"
}

Function Invoke-DISMCleanup {
    Write-Host 'Running DISM component store cleanup (this may take several minutes)...'
    # To also remove all superseded update rollback data and reclaim more space, add /ResetBase
    # (one-way operation - disables uninstalling already-installed updates afterwards):
    #   Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
    if ($WhatIfPreference) {
        Write-Host '  What if: would run Dism.exe /online /Cleanup-Image /StartComponentCleanup' -ForegroundColor DarkYellow
        Write-Host -ForegroundColor Yellow "DISM Component Cleanup - COMPLETE`r`n"
        return
    }
    Dism.exe /online /Cleanup-Image /StartComponentCleanup
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "DISM exited with code $LASTEXITCODE - component cleanup may be incomplete."
    }
    else {
        Write-Host -ForegroundColor Yellow "DISM Component Cleanup - COMPLETE`r`n"
    }
}

# ── Main ────────────────────────────────────────────────────────────────────────

Write-Host "Series of commands to clear browser profile information, Teams and OneDrive"
Write-Host "Pulled from various web sources. This is a " -NoNewline
Write-Host "DESTRUCTIVE" -ForegroundColor Red -NoNewline
Write-Host " process - data will not be recoverable. Proceed accordingly."

if ($WhatIfPreference) {
    Write-Host "`nRunning in -WhatIf mode - no changes will be made.`n" -ForegroundColor DarkYellow
}
else {
    Read-Host "`nEnter Ctrl-C to cancel, or press Enter to continue"
}

$startTime = Get-Date

try {
    Invoke-Step 'Clear Chrome'               { Clear-Chrome }
    Invoke-Step 'Clear IE'                   { Clear-IE }
    Invoke-Step 'Clear Firefox'              { Clear-FireFox }
    Invoke-Step 'Clear Edge'                 { Clear-Edge }
    Invoke-Step 'Remove OneDrive Business'   { Remove-OneDriveBusinessAccounts }
    Invoke-Step 'Clear User Temp'            { Remove-UserCache }
    Invoke-Step 'Clear WER'                  { Clear-WER }
    Invoke-Step 'Clear Windows Temp'         { Clear-WindowsTemp }
    Invoke-Step 'Clear Network Credentials'  { Clear-NetworkCredentials }
    Invoke-Step 'Clear RDP History'          { Clear-RDPHistory }
    Invoke-Step 'Clear Clipboard History'    { Clear-ClipboardHistory }
    Invoke-Step 'Clear Print Queue'          { Clear-PrintQueue }
    Invoke-Step 'Clear Windows History'      { Clear-WindowsHistory }
    Invoke-Step 'Clear Event Logs'           { Clear-EventLogs }
    Invoke-Step 'Remove Teams Profile'       { Remove-TeamsProfile }
    Invoke-Step 'Remove Outlook Profile'     { Remove-OutlookProfile }
    Invoke-Step 'Clear Pinned Items'         { Clear-PinnedItems }
    Invoke-Step 'Flush DNS Cache'            {
        if ($WhatIfPreference) { Write-Host '  What if: would run ipconfig /flushdns' -ForegroundColor DarkYellow }
        else { ipconfig /flushdns | Out-Null }
    }
    Invoke-Step 'Disk Cleanup'               { Clear-Disk }
    Invoke-Step 'DISM Component Cleanup'     { Invoke-DISMCleanup }

    $elapsed = (Get-Date) - $startTime
    Write-Host "`n$('=' * 60)" -ForegroundColor Cyan
    if ($script:stepErrors.Count -eq 0) {
        Write-Host ' ALL STEPS COMPLETE' -ForegroundColor Green
    }
    else {
        Write-Host " COMPLETED WITH $($script:stepErrors.Count) ERROR(S):" -ForegroundColor Yellow
        $script:stepErrors | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
    }
    Write-Host "  Started : $($startTime.ToString('HH:mm:ss'))"
    Write-Host "  Finished: $(Get-Date -Format 'HH:mm:ss')"
    Write-Host "  Elapsed : $([math]::Round($elapsed.TotalMinutes, 1)) min"
    Write-Host "$('=' * 60)`n" -ForegroundColor Cyan

    if ($WhatIfPreference) {
        Write-Host "WhatIf run complete - no changes were made." -ForegroundColor DarkYellow
    }
    elseif ($SkipReboot) {
        Write-Host "Reboot suppressed (-SkipReboot). Reboot manually when ready." -ForegroundColor Yellow
    }
    else {
        Write-Host "Process complete. Computer will reboot in 30 seconds."
        Write-Host "Run 'shutdown /a' in a command prompt to cancel the reboot." -ForegroundColor Cyan
        SHUTDOWN.EXE /r /f /t 30 /c 'Rebooting to complete Reset_Fire_Laptop cleanup....'
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Shutdown command failed with exit code $LASTEXITCODE"
        }
    }
}
finally {
    if (-not $WhatIfPreference) { Stop-Transcript }
}
