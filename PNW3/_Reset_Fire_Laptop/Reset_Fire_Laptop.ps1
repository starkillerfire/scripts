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
# Date: 15-Aug-2026 Version 2.7 - Legacy EdgeHTML cleanup now covers all user profiles
#   (was only clearing the elevated session's own $env:LOCALAPPDATA); target machine
#   (computer name, serial, running-as account) now printed before the confirmation
#   prompt; transcript log and -BackupPst output are now copied to this thumbdrive (when
#   running from removable media) and then purged from the target machine, instead of
#   being left behind on a laptop about to be reissued to someone else.
# Date: 15-Aug-2026 Version 2.8 - Removed -WhatIf/dry-run support (SupportsShouldProcess
#   and all $WhatIfPreference branches) - this script now always runs live.
# Date: 15-Aug-2026 Version 2.9 - Self-elevates via UAC and relaunches itself if not
#   already Administrator, forwarding all bound parameters - so this can be run directly
#   (e.g. from PowerShell ISE or F5/Run) without going through Reset_Fire_Laptop.bat first.
# Date: 15-Aug-2026 Version 2.10 - Self-elevation now caps at one retry (-ElevationRetry,
#   internal use only) - if the relaunched elevated copy still isn't Administrator, it now
#   fails with a diagnostic error instead of relaunching again forever.
# Date: 15-Aug-2026 Version 2.11 - Admin check now compares against the raw
#   BUILTIN\Administrators SID (S-1-5-32-544) instead of IsInRole('Administrator'), to rule
#   out name-resolution quirks as a cause of false negatives on already-elevated sessions.
# Date: 15-Aug-2026 Version 2.12 - Deeper cleanup: saved Wi-Fi network profiles, Windows
#   Search index (rebuilds automatically), per-user crash dumps, Activity Timeline history,
#   Sticky Notes, and Office (Word/Excel/PowerPoint/etc.) recent-file MRU across all users;
#   CleanMgr now also reclaims "Previous Windows installation(s)" (Windows.old) if present.
#   Added opt-in -WipeUserFiles switch (off by default) that deletes the actual contents of
#   Desktop/Documents/Downloads/Pictures/Videos/Music for every profile - unlike everything
#   else in this script, that's real user files, not cache/app data, so it stays behind an
#   explicit flag instead of running unconditionally.
# Date: 15-Aug-2026 Version 2.13 - Personal file wipe (Desktop/Documents/Downloads/Pictures/
#   Videos/Music) is no longer opt-in - -WipeUserFiles is removed and Remove-UserPersonalFiles
#   now always runs, same as every other step. The pre-run warning banner now unconditionally
#   calls out that user files, not just cache/app data, are being deleted.
# Date: 15-Aug-2026 Version 2.14 - Further deeper cleanup: USB/Bluetooth device history,
#   direct Recycle Bin wipe (all drives), all-user VPN connections, plaintext autologon
#   credential removal, network/remote printer connections (virtual printers excluded by
#   name), Adobe/Bluebeam recent-file history and cache, and Box/Dropbox/Google Drive app
#   cache and sign-in data (synced content folders themselves are left untouched). Held back
#   Windows Hello/biometric enrollment removal and BitLocker/TPM handling - both can lock out
#   or break boot for the next user if mishandled and need to be scoped as their own task.
# Date: 15-Aug-2026 Version 2.15 - Further deeper cleanup: per-user certificate store
#   (Personal/My store + orphaned Crypto key files), SSH keys, Git config/credentials,
#   persisted network drive mappings, Zoom/WebEx cache, and Start Menu/Taskbar
#   layout + wallpaper/theme reset to default. Held back non-Microsoft scheduled task
#   removal and WSL distro cleanup - both need filtering logic worked out first so they
#   don't remove something IT-deployed or miss data inside a WSL home directory.
# Date: 15-Aug-2026 Version 2.16 - Remove-OneDriveBusinessAccounts renamed to
#   Remove-OneDriveAccounts and now also clears Personal (consumer Microsoft account)
#   OneDrive sign-ins, not just Business - previously anything signed in with a personal
#   MSA was left untouched. Added Windows network location history (NetworkList profiles/
#   signatures - distinct from the Wi-Fi profiles already cleared), proxy settings reset
#   (WinHTTP + per-user IE/WinINET), notification history database, and typing/handwriting
#   personalization data. Restored a [CmdletBinding()] attribute that had been dropped from
#   above param() in an earlier edit this session.
# Date: 15-Aug-2026 Version 2.17 - Forensic-level cleanup, run last, after everything else
#   (including PST relocation) has already deleted what it's going to delete: Volume Shadow
#   Copy/System Restore point removal (previously anything else this script deleted was
#   potentially still recoverable from an existing shadow copy), NTFS USN Journal reset,
#   Amcache.hve/ShimCache (AppCompatCache) application-execution history, and Windows
#   setup/OOBE + servicing logs. Added opt-in -SecureWipe switch (off by default, purely for
#   time cost - not risk) that runs 'cipher /w' on every drive at the very end; without it,
#   everything this script deletes is only unlinked, not overwritten, and stays recoverable
#   with undelete tools until that disk space gets reused.
# Date: 15-Aug-2026 Version 2.18 - Pagefile/hibernation cleanup: sets ClearPageFileAtShutdown
#   (takes effect on the reboot this script already triggers) and regenerates hiberfil.sys if
#   hibernation is enabled - neither is covered by cipher /w, since both are live system files
#   rather than free space, and either can hold raw RAM contents that were ever paged out.
#   Also: legacy WebCacheV01.dat (shared WinINet cache, written to by non-browser apps too)
#   added to Clear-IE; DNS flush step also clears ARP and NetBIOS caches.
# Date: 15-Aug-2026 Version 2.19 - Added Phone Link/Your Phone (synced messages/call
#   history/photos from a paired phone), Windows Mail/Calendar app cache, OneNote local
#   notebook cache, and consumer Skype. Added the two lower-risk deferred items:
#   non-Microsoft scheduled task removal (excludes anything under \Microsoft\, best-effort -
#   see the function's own comment on that limitation) and WSL distro removal via
#   `wsl --unregister`. Deliberately did NOT add Windows Hello/biometric enrollment removal or
#   BitLocker/TPM handling - direct file/registry manipulation of NGC containers isn't the
#   supported removal path and risks a TPM key-wrapping lockout, which can cascade into
#   BitLocker requiring recovery-key entry or a full TPM clear to recover from. That's a
#   materially different risk tier from everything else in this script and needs its own
#   explicit, scoped decision rather than being bundled in here.
# Date: 15-Aug-2026 Version 2.20 - Removed WSL distro cleanup (Clear-WslDistros) - not used
#   in this fleet, so it was unnecessary run time and log noise on every machine.
# Date: 15-Aug-2026 Version 2.21 - Major changes:
#   - GUI task checklist (Show-TaskSelectionDialog, WinForms) replaces the old plain
#     Read-Host confirmation - every task is now listed individually, all checked by
#     default, and a technician can uncheck anything they don't want to run on a given
#     machine instead of every run being all-or-nothing. All tasks were refactored from
#     hardcoded Invoke-Step calls into a single ordered $script:AllTasks dictionary, which
#     is now the one source of truth for both the checklist and the run order. Falls back
#     to running every task with the old text-prompt confirmation if WinForms can't load.
#   - Reset-Personalization no longer touches wallpaper/theme at all (was resetting both to
#     default); Remove-UserPersonalFiles now specifically preserves each user's current
#     desktop background picture file even when it lives inside Desktop/Pictures/etc, by
#     stashing it outside the wipe target before deleting and restoring it to its original
#     path afterward.
#   - Added Clear-OfficeSignIn ("Sign Out of Office Apps") - clears the Office identity/
#     token cache (distinct from Clear-OfficeHistory, which only clears recent-file MRU) so
#     Word/Excel/PowerPoint/Outlook/etc. prompt for sign-in again on next launch.
# Date: 15-Aug-2026 Version 2.22 - Prefer official Microsoft-supported functions over manual
#   registry/file manipulation where one actually exists for this use case:
#   - Remove-OneDriveAccounts now runs OneDrive.exe /reset (Microsoft's own documented reset
#     command) for the current interactive session first; the existing registry-based removal
#     stays as-is to cover every other profile, since /reset has no supported way to target a
#     non-interactive user.
#   - Recycle Bin cleanup now uses the official Clear-RecycleBin cmdlet instead of deleting
#     $Recycle.Bin folder contents directly. This required renaming this script's own
#     same-named function to Invoke-RecycleBinCleanup, since a custom function sharing a real
#     cmdlet's name would otherwise shadow it and recurse into itself.
#   - Also caught and fixed a second, more serious instance of the same naming problem found
#     while doing this: this script's Clear-Disk function (CleanMgr automation) shared its
#     name with the real Storage module Clear-Disk cmdlet, which does something completely
#     different and far more dangerous (wipes every partition off a physical disk). Renamed to
#     Invoke-CleanMgrAutomation. PowerShell resolved calls to this script's own function safely
#     either way (function definitions take precedence over not-yet-loaded module cmdlets), so
#     this was never a live bug, but the ambiguity wasn't worth leaving in a script like this.
#   - Everything else in this script (browsers, Teams, Adobe, etc.) was deliberately left as
#     manual file/registry cleanup - Microsoft doesn't ship a single supported reset command
#     for most of these, and in most cases (e.g. Teams cache) manual folder deletion IS
#     Microsoft's own documented troubleshooting guidance, just not exposed as a dedicated flag.
# Date: 15-Aug-2026 Version 2.23 - Full ambiguity/anchoring pass across all 47 cleanup
#   functions: audited every step against real Microsoft cmdlets/commands (found none else
#   worth swapping - VPN/printer/scheduled-task/network-cache/DISM/USN/shadow-copy/cipher
#   steps already use the correct official command, and nothing else in this script has one).
#   Confirmed via Get-Command that no function name other than the two already fixed in 2.22
#   collides with a real cmdlet. Two concrete changes:
#   - Clear-UserCertificates now clears Cert:\CurrentUser\My via the PowerShell Certificate
#     provider (Remove-Item) as the preferred method for the current session, same
#     current-session-only caveat as OneDrive.exe /reset - registry/file cleanup across all
#     other profiles is unchanged and still does the real work fleet-wide.
#   - Clear-EventLogs now documents why it uses EventLogSession.ClearLog (the .NET equivalent
#     of `wevtutil cl`) instead of the built-in Clear-EventLog cmdlet: Clear-EventLog only
#     reaches classic Application/System/Security/Setup logs, not the modern "Applications and
#     Services Logs" channels this step also clears.
# Date: 15-Aug-2026 Version 2.24 - Verified every Microsoft command/cmdlet this script relies
#   on against current Microsoft Learn documentation (Clear-RecycleBin, the Cert: provider,
#   Remove-VpnConnection, Clear-EventLog's classic-log-only limitation, OneDrive.exe /reset,
#   fsutil usn, Win32_ShadowCopy/Remove-CimInstance, Dism.exe /StartComponentCleanup, netsh
#   winhttp) - all confirmed accurate as documented, no corrections needed. Two refinements
#   from that pass:
#   - Clear-UserCertificates now passes -DeleteKey to Remove-Item on Cert:\CurrentUser\My, so
#     the Certificate provider itself removes the private key, not just the store entry -
#     confirmed via Microsoft's own docs that -DeleteKey only needs delegated credentials for a
#     REMOTE computer's store, and this always runs locally. (The Crypto\RSA/Crypto\Keys folder
#     deletion below it is unchanged and still needed - it also catches orphaned key files with
#     no matching store entry, which -DeleteKey wouldn't touch.)
#   - Clear-ShadowCopies now notes that deleting Win32_ShadowCopy via WMI/CIM is the same
#     technique ransomware uses, so EDR tooling (Defender for Endpoint, CrowdStrike, etc.) may
#     flag or block it on a managed machine - a real, Microsoft-acknowledged interaction, not a
#     bug, so it's documented instead of being mistaken for one during troubleshooting.
# Date: 15-Aug-2026 Version 2.25 - Second Microsoft Learn pass, looking for more official
#   cmdlets to swap in (not just verifying ones already in use). Ruled out one candidate
#   (Clear-Clipboard isn't a real cmdlet - confirmed against the Microsoft.PowerShell.Management
#   Clipboard docs; only Get-Clipboard/Set-Clipboard exist, and Set-Clipboard only reaches the
#   live in-memory clipboard of the current session, not the persisted Clipboard History files
#   this step actually targets - Clear-ClipboardHistory was already correct as manual cleanup).
#   Also checked Get-PnpDevice/Remove-PnpDevice as a Bluetooth alternative to the BTHPORT
#   registry cleanup and deliberately did NOT switch: it operates on currently-present PnP
#   device instances, and a laptop reissue is exactly the scenario where a previously-paired
#   phone/headset won't be present to enumerate, so it wouldn't reliably reach what actually
#   needs clearing here. Three real swaps made:
#   - Clear-PrintQueue now tries Get-PrintJob | Remove-PrintJob (PrintManagement module) first,
#     as the graceful official method - the existing stop-spooler-and-delete-files approach
#     stays as the fallback, since a stuck/corrupted job can still be unremovable through the
#     API while the spooler has its .SHD/.SPL files locked.
#   - Clear-MappedDrives now runs Get-SmbMapping | Remove-SmbMapping -Force -UpdateProfile
#     first, for the current session (same current-session-only caveat as every other official-
#     cmdlet swap here) - the per-hive registry cleanup is unchanged and still covers every
#     other profile.
#   - Clear-WindowsTemp now matches Microsoft's own documented "reset Windows Update
#     components" steps more closely: also stops cryptsvc (not just wuauserv/bits), clears
#     SoftwareDistribution\DataStore and System32\catroot2 (not just \Download), and removes
#     the legacy BITS qmgr*.dat job queue database. Microsoft's guidance is to rename these
#     folders to *.bak instead of deleting them, so there's a rollback path if the reset doesn't
#     fix the original problem - not applicable here since this laptop is being wiped, not
#     troubleshot, so this deletes them outright instead of leaving renamed backups behind.
# Date: 15-Aug-2026 Version 2.26 - Documentation pass, no functional changes. Every one of the
#   53 functions (6 helpers + 47 cleanup steps) now has standard PowerShell comment-based help
#   (.SYNOPSIS/.DESCRIPTION/.PARAMETER/.OUTPUTS/.NOTES, placed as the first statement in the
#   function body per PowerShell convention) - confirmed via
#   FunctionDefinitionAst.GetHelpContent() that all 53 are recognized, so `Get-Help
#   <FunctionName> -Full` works for any of them if this script is dot-sourced. Where a function
#   already had a standalone comment immediately above it explaining its purpose (e.g.
#   Show-TaskSelectionDialog's three-way return contract, Invoke-ForEachUserHive's mounting
#   behavior), that content was folded into the new help block instead of being left duplicated
#   in two places. Existing line-level "why" comments inside function bodies were left as-is.
#   Also added a one-line inline comment to every entry in the $script:AllTasks dictionary
#   (the GUI checklist label -> scriptblock mapping) describing what each call actually does,
#   and a short comment at each of the two places in Main that drive the whole task-execution
#   flow: the Show-TaskSelectionDialog call (pointing at its .OUTPUTS contract) and the
#   Invoke-Step loop (the one place every cleanup function actually gets invoked).
# Date: 15-Aug-2026 Version 2.27 - Third Microsoft Learn pass. Two real swaps found and made,
#   both confirmed against Microsoft Learn: the 'Flush Network Caches' task previously ran three
#   inline native commands (ipconfig /flushdns, arp -d *, nbtstat -R) - promoted to a new
#   documented function, Clear-NetworkCaches, which now uses Clear-DnsClientCache (DnsClient
#   module) in place of ipconfig /flushdns and Get-NetNeighbor | Remove-NetNeighbor -Confirm:$false
#   (NetTCPIP module) in place of arp -d *. nbtstat -R is unchanged - no PowerShell cmdlet
#   equivalent exists for the NetBIOS name cache. Also checked and ruled out two more candidates:
#   Import-StartLayout as a possible replacement for Reset-Personalization's file-deletion
#   approach - real cmdlet, but it's for provisioning a mounted image or new user's default
#   profile (not resetting an existing live user's layout) and is explicitly deprecated with no
#   effect on Start/Taskbar in Windows 11, so it doesn't fit this use case. And
#   Remove-NetConnectionProfile as a possible replacement for Clear-NetworkHistory's registry
#   cleanup - this cmdlet doesn't exist at all (only Get-/Set-NetConnectionProfile do), so that
#   function's registry approach is confirmed as the only option, not a gap.
# Date: 15-Aug-2026 Version 2.28 - Bug fix: browser cleanup was leaving site session/storage
#   data behind despite clearing cookies. Verified against a live Chrome/Edge profile on this
#   machine: the literal Cookies file (now under a Network\ subfolder in both browsers) WAS
#   already being matched and deleted by $script:BrowserDataRegex, but 'Local Storage' - where
#   many modern web apps put session/auth tokens instead of cookies - matched nothing in the
#   old regex and was surviving every run, along with the newer partitioned 'Storage' container
#   Chromium now uses for per-site IndexedDB/Cache/LocalStorage, 'Service Worker' (Cache Storage
#   API), 'File System' (File System Access API data), 'Extension State', and Edge's own
#   'Sync Data'/'Sync App Settings'/'Sync Extension Settings' folders. Added all of these to
#   $script:BrowserDataRegex (shared by Clear-Chrome and Clear-Edge) using bare substrings
#   ('Storage', 'Sync') where that safely catches multiple real folder names at once - confirmed
#   against the actual folder listing that this doesn't also catch anything that should be left
#   alone (Extensions/Extension Rules/Extension Scripts - installed extension code, not user
#   data - and Bookmarks stay untouched). Clear-FireFox had the same class of gap: its file list
#   only covered the LEGACY webappsstore.sqlite localStorage format, not current Firefox's LSNG
#   (LocalStorage Next Generation) format, IndexedDB, or Service Worker Cache - all of which live
#   under the profile's 'storage' folder, added to the cleanup list. Not verified against a live
#   Firefox profile (none installed on this machine) - based on Mozilla's documented profile
#   layout.
# Date: 15-Aug-2026 Version 2.29 - Gap analysis using the same live-inspection approach that
#   found the 2.28 browser-storage bug: checked this machine for newer Windows/Microsoft 365
#   app architectures the script's cleanup list predates. Found and fixed a real gap:
#   - New Outlook for Windows (Microsoft.OutlookForWindows) IS installed on this machine - a
#     separate UWP app from classic Win32 Outlook, with its own independent LocalCache/LocalState
#     mail/calendar/contacts store that Remove-OutlookProfile never touched. Confirmed its process
#     name (olk.exe) and package folder name by reading its AppxManifest.xml directly rather than
#     assuming, then added stopping olk.exe and deleting the package folder to
#     Remove-OutlookProfile, all users.
#   - Also confirmed present and added to Clear-MiscAppData: the Widgets board
#     (MicrosoftWindows.Client.WebExperience - personalized feed cache tied to the signed-in
#     Microsoft account) and Snipping Tool/Screen Sketch (Microsoft.ScreenSketch - keeps its own
#     recent-screenshot history separate from wherever a screenshot was actually saved). Also
#     added Xbox Game Bar's Videos\Captures folder (Win+G screen/window recordings - same
#     sensitivity tier as the Teams meeting recordings already cleared elsewhere).
#   - Checked for Windows Copilot as another possible gap - not installed on this machine, so no
#     addition was made rather than guessing at an unverified data location; worth re-checking on
#     a machine that has it if this comes up again.
#   New Teams (already covered), classic Office apps (still Win32/Click-to-Run, not UWP), and
#   OneDrive (still a classic Win32 exe, no UWP variant on desktop) were all confirmed NOT to have
#   this same class of gap.
# Date: 15-Aug-2026 Version 2.30 - Critical bug fix: Remove-UserPersonalFiles (the personal-file
#   wipe - this script's whole reason for existing) and Remove-OutlookProfile's PST search both
#   assumed Desktop/Documents/Pictures always live at "<profile>\Desktop" etc. Confirmed by
#   inspecting this machine's own registry that this is FALSE whenever OneDrive Known Folder Move
#   (KFM) is active - a standard enterprise M365 configuration: this machine's classic Desktop and
#   Pictures folders don't exist AT ALL (KFM redirected them into "OneDrive - DOI\..."), and its
#   classic Documents folder exists as a near-empty (4-item) leftover sitting alongside the real,
#   populated (84-item) OneDrive-redirected one. Concretely, this meant Remove-UserPersonalFiles
#   was either silently doing nothing (Test-Path on a folder that doesn't exist) or wiping a stale
#   leftover folder while the user's ACTUAL files at the redirected location were never touched -
#   on any KFM-enabled machine, the "wipe personal files" step was not wiping the user's personal
#   files. Remove-OutlookProfile's PST search had the identical bug: a PST archived into a
#   KFM-redirected Documents folder was never found.
#   Fixed with a new shared helper, Resolve-UserShellFolder, that reads each user's actual
#   Desktop/Documents ("Personal")/Pictures ("My Pictures") location from their own User Shell
#   Folders registry key (read while their hive is mounted, same mechanism as every other
#   per-user registry function in this script) instead of assuming the classic path, falling back
#   to the classic path only if the registry value is missing. Downloads/Videos/Music are left as
#   classic-path joins in both functions, since OneDrive KFM has never supported redirecting those
#   three. Verified end-to-end against this machine's real registry values: the fixed logic now
#   resolves to the actual populated OneDrive-redirected folders instead of the empty/nonexistent
#   classic ones.
# Date: 15-Aug-2026 Version 2.31 - Follow-on risk found while reviewing the 2.30 fix itself: once
#   Remove-UserPersonalFiles correctly resolves Desktop/Documents/Pictures to their real,
#   OneDrive Known Folder Move-redirected location, deleting files there is only safe if OneDrive
#   is no longer actively signed in and syncing - otherwise the local deletion syncs straight up
#   to the user's actual cloud storage, destroying their real files on every device, not just this
#   one laptop being reissued. In the default full run this is already safe, since 'Remove
#   OneDrive Accounts' (which stops and unlinks OneDrive) runs well before 'Wipe Personal Files'
#   in task order - but the GUI checklist lets a technician deselect 'Remove OneDrive Accounts'
#   while leaving 'Wipe Personal Files' checked, and that combination was NOT safe: this
#   function's safety implicitly depended on a different, independently-selectable checkbox.
#   Fixed by having Remove-UserPersonalFiles stop OneDrive.exe itself, unconditionally, as its own
#   first action - it no longer relies on another task having already run.
# Date: 15-Aug-2026 Version 2.32 - Found a gap in the 2.30 fix itself while re-checking its own
#   reasoning: Resolve-UserShellFolder's callers assumed Downloads/Videos/Music were always at
#   the classic path because "OneDrive Known Folder Move never redirects them" - true, but
#   incomplete. Classic Group Policy Folder Redirection is a separate, independent mechanism
#   (common in federal/enterprise environments) that writes to the SAME User Shell Folders
#   registry key and DOES support redirecting all six folders, not just the three OneDrive KFM
#   covers. Confirmed the registry value names for the other three ('My Video', 'My Music', and
#   the GUID-keyed '{374DE290-123F-4565-9164-39C4925E467B}' for Downloads) and extended both
#   Remove-UserPersonalFiles and Remove-OutlookProfile's PST search to resolve all six folders
#   through Resolve-UserShellFolder instead of assuming half of them are always classic.
#   Also hardened $UsersBase itself: it was hardcoded to "$env:SystemDrive\Users", which every
#   single cleanup function in this script depends on being correct. Now reads the authoritative
#   ProfilesDirectory value from HKLM's ProfileList key instead (falling back to the hardcoded
#   default if that read fails) - matched the hardcoded default when checked on this machine, but
#   some hardened/custom-imaged machines relocate the profile base directory, and Windows itself
#   already exposes exactly where it actually put it rather than this script needing to guess.
#   Verified all six folder resolutions and the ProfilesDirectory read against this machine's live
#   registry.
# Date: 15-Aug-2026 Version 2.33 - Found an interaction bug in the 2.31 fix itself while doing a
#   correctness re-read of Remove-UserPersonalFiles rather than more live-system inspection: the
#   2.31 fix added Stop-ProcessAndWait -Name 'OneDrive' as the function's first action, running
#   BEFORE the wallpaper file got copied to its stash location. If the current wallpaper's source
#   image is a OneDrive Files On-Demand placeholder that hasn't been downloaded locally yet,
#   reading its content requires OneDrive.exe to still be running to service the on-demand fetch -
#   with OneDrive already stopped, that copy fails silently (Copy-Item -ErrorAction
#   SilentlyContinue), and the "preserve wallpaper" guarantee this function advertises quietly
#   breaks for that user. Reordered so the wallpaper stash copy (and the six folder-path
#   resolutions, which were already there) happen first, while hives are mounted, and OneDrive is
#   only stopped afterward, immediately before the actual file deletion - preserving both
#   guarantees instead of trading one for the other. Verified no stale variable references were
#   left over from the restructuring.
# Date: 15-Aug-2026 Version 2.34 - Critical bug fix in Resolve-UserShellFolder itself, found by
#   directly inspecting the actual registry value TYPE and content (not just the already-expanded
#   string Get-ItemProperty normally returns) rather than assuming: 'My Video', 'My Music', and
#   the Downloads GUID value are stored as REG_EXPAND_SZ containing a literal, unexpanded
#   "%USERPROFILE%" token (e.g. "%USERPROFILE%\Videos") - NOT a resolved path. Desktop/Personal/
#   My Pictures happened to already be fully-resolved absolute paths on this machine only because
#   OneDrive KFM writes the literal path when it redirects them, which masked this bug for those
#   three.
#   [Environment]::ExpandEnvironmentVariables(), used to expand this value, resolves tokens
#   against the CURRENT PROCESS's own environment - i.e. the ELEVATED TECHNICIAN'S account running
#   this script, not the target user whose hive Invoke-ForEachUserHive has mounted. For every
#   local profile on the machine other than whoever happens to be running the script (confirmed a
#   second real profile, WsiAccount, exists on this machine), Resolve-UserShellFolder was silently
#   resolving Downloads/Videos/Music to the TECHNICIAN'S OWN folders instead of that user's -
#   meaning Remove-UserPersonalFiles never actually wiped another user's Downloads/Videos/Music,
#   and Remove-OutlookProfile's PST search never actually searched another user's real Downloads.
#   Fixed by replacing the "%USERPROFILE%" token with the target user's actual $ProfilePath
#   (already an available parameter, always correct for that specific user) before any other
#   environment-variable expansion runs. Verified against both the current session's own profile
#   and a simulated different user's profile that the fix now resolves to the correct account in
#   both cases, and that already-fully-resolved values (Desktop/Documents/Pictures) are unaffected.
#   Also used this round to verify, empirically rather than by inference, that the
#   Get-ChildItem -Recurse | Where-Object {match} | Remove-Item -Recurse pattern used throughout
#   this script (including the browser cleanup regex from Version 2.28) does not truncate or skip
#   later siblings/profiles when an earlier match deletes a parent folder mid-enumeration - built a
#   representative test tree and confirmed complete, correct deletion across multiple profiles.
# Date: 15-Aug-2026 Version 2.35 - Serious pre-existing bug found, unrelated to anything touched
#   earlier this session: Remove-OutlookProfile's -BackupPst naming logic computed
#   $userName = ($pst.FullName -split '\\')[$UsersBase.Split('\\').Count] - but $UsersBase.Split
#   ('\\') uses the .NET method, where the 2-character string '\\' is a literal two-backslash
#   separator that no real path ever contains, so it never splits and .Count was ALWAYS 1,
#   regardless of $UsersBase. That made $userName always resolve to the literal string "Users"
#   (index [1] of the correctly-split FullName) for every single backed-up PST, on every machine,
#   since this naming logic was written - confirmed empirically, not just reasoned about. Every
#   backed-up PST got renamed "Users-<filename>.pst" instead of "<actual-user>-<filename>.pst".
#   Since Copy-Item -Force overwrites silently, two different users' PSTs sharing a filename (e.g.
#   both named "archive.pst" - not an unusual name) would collide at the same backup destination,
#   and the second one copied would silently overwrite the first - defeating the entire purpose of
#   -BackupPst, which exists specifically to avoid losing exactly this kind of data.
#   Fixed with a new shared helper, Get-ProfileNameFromPath, that strips the actual $UsersBase
#   prefix from a path and returns the next segment, rather than computing a split index at all.
#   Also used to fix three more instances of the same fragile "hardcoded split index" shape
#   (Path.Split('\')[2]) in Remove-TeamsProfile's two log messages and Remove-OutlookProfile's New
#   Outlook log message - cosmetic-only bugs (log text, not actual deletion targets) that were safe
#   by coincidence only because $UsersBase was hardcoded to exactly two path segments before
#   Version 2.32 made it dynamic. Verified the fix against both a standard and a deliberately
#   deeper/non-standard $UsersBase.
#   Also hit and fixed an unrelated but instructive bug while writing this helper's own
#   documentation: a wrapped line in its .DESCRIPTION happened to start with ".NET", which
#   PowerShell's comment-based help parser reads as an unrecognized help keyword and silently
#   fails to recognize the ENTIRE help block for - confirmed by isolating the exact text and
#   testing it standalone. Reworded to avoid any line starting with a period, and scanned every
#   other function in the script to confirm none of them have the same latent issue.
# Date: 15-Aug-2026 Version 2.36 - Added Clear-WindowsRecall: removes Windows Recall (Copilot+ PC
#   snapshot history - periodic desktop screenshots, OCRed and semantically indexed for search) and
#   its per-user data. No-ops with a status message on non-Copilot+ hardware, which is most of this
#   fleet. Uses the official Disable-WindowsOptionalFeature -FeatureName "Recall" -Remove (Dism
#   module) as the primary method - Microsoft's own documented removal command, confirmed to also
#   delete existing snapshots per their docs, taking effect on the reboot this script already
#   triggers. Also directly deletes each user's CoreAIPlatform.00\UKP folder (confirmed data
#   location: ukg.db database + ImageStore screenshot JPEGs) as belt-and-suspenders, matching how
#   this script handles every other packaged Windows feature's data. Deliberately does NOT touch
#   local user profiles/accounts themselves (considered and explicitly declined per user
#   direction - this fleet keeps existing profiles, including non-obvious ones like the WsiAccount
#   service account found on this machine, rather than having this script decide what to remove).
# Date: 15-Aug-2026 Version 2.37 - Added six more cleanup steps for third-party tools found
#   actually installed on a real fleet machine (all eight recommended candidates from that
#   inventory happened to be present here, letting most of these be verified by direct
#   inspection rather than documentation alone):
#   - Clear-RemoteAccessToolData: PuTTY (registry-only, Sessions + SshHostKeys under
#     HKCU\Software\SimonTatham\PuTTY) and WinSCP (HKCU\Software\Martin Prikryl\WinSCP 2 - saved
#     sites include an obfuscated, not securely encrypted, stored password per WinSCP's own docs)
#     verified against current documentation since this account had never used either. MobaXterm
#     (AppData\Roaming\MobaXterm - MobaXterm.ini plus a virtual "home"/"slash" filesystem
#     including a RemoteFiles folder) verified by direct inspection. All three disclose internal
#     hostnames/IPs via saved sessions - real recon value for whoever gets this laptop next.
#   - Clear-CiscoJabberData: chat history/contacts/config under AppData\Local and Roaming
#     Cisco\Unified Communications - same sensitivity tier as Teams/Skype.
#   - Clear-PowerAutomateDesktopData: flow run logs, designer cache, and signed-in account/token
#     cache under AppData\Local\Microsoft\Power Automate Desktop - deliberately clears the
#     Account/msalcache.bin3 files Microsoft's own cache-troubleshooting guidance says to
#     preserve, since this script's goal is signing the account OUT, not just fixing a cache.
#   - Clear-Windows365ClientData: Cloud PC connection/session history, confirmed present as
#     Packages\MicrosoftCorporationII.Windows365_*, same UWP package pattern as Phone Link/Widgets.
#   - Clear-SnagitData: only the Thumbnails subfolder (recent-capture preview cache, confirmed via
#     direct inspection) - deliberately leaves License (would force volume-license reactivation
#     for no privacy benefit) and TrackerbirdFiles (vendor analytics) alone.
#   - Clear-KeePassData: KeePass.config.xml (confirmed present) and the legacy HKCU\Software\
#     KeePass registry key - clears the Most-Recently-Used database list (discloses WHERE this
#     user's credential vaults are kept) without touching any actual .kdbx file, which is real
#     user data already covered by Remove-UserPersonalFiles wherever it lives.
# Date: 15-Aug-2026 Version 2.38 - Found and fixed an argument-injection gap in the self-elevation
#   relaunch logic, during a dedicated static+dynamic pass over the whole script. The
#   foreach ($key in $PSBoundParameters.Keys) loop that rebuilds $argList for the elevated child
#   process wraps each string value in literal double-quotes ("`"$val`"") but did not account for
#   the value itself containing a double-quote. Confirmed empirically, not just by inspection: built
#   an actual malicious value (D:\Backup" ; calc.exe ; ") and launched a real child PowerShell
#   process with an echo-script to observe genuine argv splitting - the embedded quote broke the
#   value apart into multiple separate tokens instead of staying one string. Also tested the
#   textbook fix (doubling the embedded quote) and confirmed, empirically, that it does NOT resolve
#   the splitting in this specific relaunch path. Fixed at the trust boundary instead: confirmed via
#   .NET's GetInvalidFileNameChars() and by actually triggering a real Windows IOException trying to
#   create a folder with a literal " in its name that this character can never legally appear in any
#   real Windows path - so any string parameter value containing one is rejected outright, with a
#   clear error, before the relaunch is attempted. Applies generically to every current and future
#   string parameter, not just -PstBackupPath. Verified the fix rejects the malicious test value
#   while still accepting normal values, including ones with legitimate spaces and the default
#   -PstBackupPath. Same pass also cross-checked the whole script via AST: all 63 functions are
#   referenced at least once (no dead code) and every function-shaped call resolves to a real
#   function or cmdlet (no stale references from cumulative edits) - both came back clean. Considered
#   and deliberately declined adding Set-StrictMode: this script's design leans on
#   (Get-ItemProperty ... -ErrorAction SilentlyContinue).Property style null-propagation hundreds of
#   times, which strict mode would break: the cost of retrofitting it works against the script's core
#   "never crash, keep going" resilience design.
# Date: 15-Aug-2026 Version 2.39 - Found the same class of bug already fixed once for OneDrive in
#   Version 2.31, in a new spot: while -BackupPst is on, 'Relocate PST Backups' was its own
#   independently-uncheckable item in the GUI checklist, separate from 'Remove Outlook Profile' (the
#   task that actually populates $PstBackupPath by copying discovered PSTs there instead of deleting
#   them). A technician could leave 'Remove Outlook Profile' checked while unchecking 'Relocate PST
#   Backups' - leaving plaintext copies of the previous user's PST archive sitting in
#   $PstBackupPath on the machine being handed to a new user, which is worse than the default
#   (no -BackupPst) behavior of just deleting them outright, since it silently defeats the entire
#   point of a "wipe machine for reissue" script. Fixed the same way the transcript log's relocation
#   was already handled: removed 'Relocate PST Backups' from $script:AllTasks/the GUI checklist
#   entirely and made it run unconditionally whenever -BackupPst is set, right after the selected-
#   task loop and before the reboot trigger (same ordering as before - still needs the full run
#   rather than racing the 30-second reboot countdown, since a PST backup can be multiple GB).
#   Verified the fix parses clean and that Move-ArtifactOffMachine's existing Test-Path guard still
#   no-ops safely if 'Remove Outlook Profile' itself was unchecked and $PstBackupPath was never
#   created.
#   Same pass also empirically confirmed, rather than assumed, that Show-TaskSelectionDialog's
#   WinForms usage is safe to run without an explicit [STAThread]/ApartmentState call: Windows
#   PowerShell 5.1's console host (which is what this script requires and how it's launched, both
#   directly and via its own self-elevation relaunch) defaults to STA, confirmed by spawning a real
#   child powershell.exe process and reading GetApartmentState() back - not a gap. Also swept every
#   Remove-Item call in the script (100+) and confirmed each one carries -ErrorAction
#   SilentlyContinue, whether path-based or piped from Get-ChildItem - no missing error handling
#   found.
# Date: 16-Aug-2026 Version 2.40 - Independent static+dynamic audit (fresh review, not
#   self-reported) found four real bugs, all confirmed by isolated dynamic repro before
#   fixing rather than by inspection alone:
#   - Reset_Fire_Laptop.bat's own -ArgumentList string-building for its Start-Process -Verb
#     RunAs relaunch broke under cmd.exe's quoting the moment any argument was forwarded via
#     %* (confirmed against a real cmd.exe run: the built argument string ended up with an
#     unterminated quote, and the child process never launched) - directly contradicting the
#     Version 2.6 changelog claim that %* forwarding already worked. Fixed by simplifying the
#     .bat to just launch the .ps1 unelevated and let its own already-audited self-elevation
#     logic (Version 2.9-2.11, 2.38) do the elevation and argument handling instead of
#     duplicating that logic a second time in batch.
#   - The Version 2.38 self-elevation argList fix only rejected embedded double-quotes, not a
#     value ending in an odd number of trailing backslashes (e.g. -PstBackupPath 'D:\Backup\')
#     - confirmed by spawning a real elevated child process that a trailing backslash escapes
#     the closing quote, silently absorbing the next parameter (e.g. -SkipReboot) into the
#     string value instead of it binding as its own switch. Fixed with the same
#     validate-and-reject approach as the existing quote check.
#   - Remove-OutlookProfile's -BackupPst naming (`$userName-$($pst.Name)`) had no folder
#     component, so the same user having two same-named PSTs in different searched folders
#     (e.g. Desktop and Documents) still collided and Copy-Item -Force silently overwrote the
#     first backup - confirmed by reproducing the exact collision. Fixed with a numeric
#     suffix fallback when the destination name is already taken.
#   - Both early-exit paths before the main try/finally (computer-name-mismatch and
#     no-tasks-selected) called Stop-Transcript directly instead of going through the
#     finally block, so Move-ArtifactOffMachine never ran for those runs and the transcript
#     log - which already contains the computer name/serial/account banner - was left behind
#     on the machine instead of relocated, contradicting the Version 2.7 changelog's stated
#     purpose for that relocation. Fixed by adding the same Move-ArtifactOffMachine call to
#     both early-exit branches.
#   All four fixes verified by direct dynamic repro (real child process argv inspection, real
#   cmd.exe launch, synthetic collision reproduction) in a scratch temp directory, and the
#   full script re-parsed clean via the PowerShell AST parser afterward. No changes made to
#   any Clear-*/Remove-* cleanup function bodies.
# Date: 16-Aug-2026 Version 2.41 - Two cosmetic-only cleanups from the same audit's low-
#   severity findings, no functional changes: removed a stale/misplaced comment above the
#   Shadow Copies/USN Journal checklist entries that actually described the unrelated
#   'Relocate PST Backups' logic further down (which already has its own correct comment at
#   its real call site); dropped the unused -ProfilePath parameter from Clear-KeePassData's
#   Invoke-ForEachUserHive scriptblock (only -Sid is used) - confirmed by direct testing that
#   Invoke-ForEachUserHive's `& $Action -Sid $sid -ProfilePath $path` call still binds fine
#   against a scriptblock that only declares -Sid, since unmatched named arguments to a plain
#   scriptblock are silently ignored rather than raising a binding error.
# Date: 06-Sep-2026 Version 2.42 - Fixed a real user report: running this script was breaking
#   application/network shortcuts on the Desktop and in the Start Menu/taskbar. Two distinct
#   causes, both fixed:
#   - Remove-UserPersonalFiles' Desktop wipe deleted every file in the folder indiscriminately,
#     including .lnk/.url shortcuts - only the wallpaper picture was ever special-cased for
#     preservation. Desktop shortcuts are pointers, not personal data, so the wipe now skips
#     .lnk/.url specifically on the Desktop target while still fully wiping Documents/Pictures/
#     Downloads/Videos/Music and everything else on the Desktop.
#   - Reset-Personalization deleted LayoutModification.xml, the Start Menu Experience Host's
#     LocalState, and the legacy taskbar pinned-items folder to force Windows to regenerate a
#     default Start Menu/taskbar layout - which also destroyed any app deliberately pinned to
#     Start or the taskbar (including org-deployed pins, not just the previous user's own
#     customizations). Removed the function and its checklist entry entirely rather than leaving
#     a neutered no-op behind; Clear-PinnedItems (Jump Lists/Recent Items/Quick Access pins) is
#     unrelated and unaffected.
# Date: 06-Sep-2026 Version 2.43 - Independent audit (fresh review, not self-reported) of the
#   areas that had gotten the least scrutiny across 42 prior passes - the WinForms checklist, the
#   Main execution flow, and the two most-reused helpers (Invoke-ForEachUserHive, Stop-
#   ProcessAndWait) - found and fixed four real issues plus two cosmetic ones:
#   - Invoke-ForEachUserHive had no per-profile error isolation: confirmed empirically that
#     PowerShell aborts an entire ForEach-Object pipeline on one iteration's unhandled terminating
#     exception, so a single profile's scriptblock throwing (e.g. a hive with unusual enumeration
#     ACLs) silently skipped every remaining profile for that task, with only one logged error to
#     show for it. Nearly every per-user cleanup function is built on this helper. Fixed by
#     wrapping the per-profile action in its own try/catch (log-and-continue), separate from the
#     existing finally that unloads the hive.
#   - Invoke-CleanMgrAutomation's `Get-Process cleanmgr, dismhost | Wait-Process` had no timeout,
#     unlike every other process-wait in this script (Stop-ProcessAndWait caps at 15s for exactly
#     this reason) - dismhost.exe is known to occasionally wedge, which would stall ~20 remaining
#     steps and the final reboot indefinitely. Bounded to 10 minutes with a logged warning on
#     timeout instead of hanging.
#   - The final reboot's `shutdown /r /f /t 30` is fire-and-forget and used to run inside the same
#     try block whose finally then copies the transcript log to the thumbdrive - so the 30-second
#     forced-shutdown countdown ran concurrently with that copy, and /f could kill this process
#     mid-copy on a long run or slow removable media. This is the identical race already reasoned
#     through for PST backups (2.39), which deliberately run before the countdown starts - the
#     transcript just never got the same treatment. Fixed by moving the actual SHUTDOWN.EXE call
#     to after the try/finally block, gated on a $script:shouldReboot flag set inside try, so it
#     only fires once transcript relocation has actually finished.
#   - Remove-TeamsProfile's meeting-recording cleanup and Clear-MiscAppData's Game Bar capture
#     cleanup both still hardcoded the classic "<profile>\Videos" path, never migrated to
#     Resolve-UserShellFolder despite Videos being one of the six folders Version 2.32 established
#     can be independently redirected by classic GPO Folder Redirection - on a redirected machine,
#     recorded Teams meetings and Win+G screen captures survived the "wipe" while the step reported
#     success. Both now resolve the real per-user Videos location the same way
#     Remove-UserPersonalFiles already does.
#   - Cosmetic: Move-ArtifactOffMachine's Copy-Item, when relocating a directory (the -BackupPst
#     case) into the already-created $destRoot, was copying the source directory itself as a
#     subfolder rather than its contents - producing an extra "PstBackup_<machine>_<timestamp>\
#     PstBackup\*.pst" nesting level instead of landing the files directly under the timestamped
#     folder. Fixed by copying "$SourcePath\*" for directory sources (with an empty-directory
#     guard, since that wildcard resolves to nothing and Copy-Item would otherwise throw).
#   - Cosmetic: Clear-PinnedItems only released the outer Shell.Application COM object; the
#     per-iteration Namespace folder object and each enumerated FolderItem were never explicitly
#     released, a minor non-fatal RCW leak scoped to that one step's up-to-50 loop iterations. Both
#     are now released via Marshal.ReleaseComObject as they go out of scope.
# Date: 06-Sep-2026 Version 2.44 - Third independent audit pass, targeting the ~30 individual
#   cleanup functions and GUI/Main-flow areas the first two passes hadn't examined closely. Found
#   and fixed four real issues:
#   - Clear-UserCertificates ran `Get-ChildItem Cert:\CurrentUser\My | Remove-Item -DeleteKey`
#     "for the current session" before the per-hive registry/file cleanup that covers every real
#     profile - but CurrentUser inside this elevated session is the TECHNICIAN's own profile (or
#     whatever admin account is running the script), never the departing employee's. Unlike this
#     script's other current-session-only conveniences (OneDrive.exe /reset, Get-SmbMapping, etc.),
#     which are merely inconvenient if scoped wrong, this one ran with -DeleteKey - meaning every
#     run of this step permanently deleted the OPERATOR's own Personal certificate store entries
#     and any software-backed private keys, a real cost in a PIV/CAC-standard federal environment,
#     for zero benefit toward wiping the actual target profiles. Removed that block entirely; the
#     per-hive cleanup below it was never affected and still does the real work fleet-wide.
#   - Remove-OutlookProfile's -BackupPst naming used Get-ProfileNameFromPath on the found PST's own
#     FullName to derive the backup filename prefix, which assumes the path starts with $UsersBase
#     and silently returns the whole path unchanged when it doesn't - a real possibility here, since
#     Resolve-UserShellFolder (used to find these PSTs in the first place) can legitimately resolve
#     Documents/Desktop/Downloads to a UNC share or another drive via classic GPO Folder
#     Redirection. That produced an unusable destination filename, Copy-Item threw, and the PST was
#     silently left un-backed-up AND un-deleted - not data loss, but a wipe goal quietly defeated for
#     any redirected profile. Fixed by recording which resolved search root belongs to which user
#     ($pstPathOwners) at resolution time, and looking up the owner by matching the found PST's path
#     against those known roots instead of re-deriving it from the path afterward.
#   - Invoke-RecycleBinCleanup, Clear-UsnJournal, and Invoke-SecureFreeSpaceWipe (-SecureWipe) all
#     iterated every FileSystem PSDrive with no awareness that $script:RunningFromRemovableMedia
#     already exists specifically because this script runs FROM a thumbdrive against many laptops -
#     meaning the technician's own reusable USB drive got swept in as an ordinary target drive on
#     every single run. Most costly for -SecureWipe's cipher /w pass (30-60+ minutes per drive per
#     its own doc) - pointless against an IT tool with nothing needing forensic protection, and
#     compounding across every machine in a stack. Added a shared Get-TargetFileSystemDrives helper
#     that excludes the drive backing $PSScriptRoot when running from removable media, used by all
#     three.
#   - Clear-FireFox filtered profile folders with `-match '\.default|\.dev-edition-default'`, which
#     only matches Firefox's auto-created default profile(s) - any additional profile a user created
#     via about:profiles, or one with a custom/provisioned name, never matched and was left
#     completely untouched (cache, history, and saved logins included) while the step still reported
#     "COMPLETE". Since $ProfileBases already scopes to exactly the Profiles folder, every child
#     directory there is a genuine profile - removed the name filter entirely rather than trying to
#     maintain a naming-convention allowlist.
# Date: 06-Sep-2026 Version 2.45 - Fourth pass: a genuine line-by-line close read of the entire
#   file (not a targeted issue hunt this time), split across four overlapping ranges. One finding
#   from that pass turned out to be WRONG on direct empirical test - a reviewer flagged
#   Clear-KeePassData's Invoke-ForEachUserHive scriptblock (only declares -Sid, not -ProfilePath)
#   as a parameter-binding error, contradicting the Version 2.41 changelog's own claim (also
#   "confirmed by direct testing") that this binds fine. Re-tested directly rather than trusting
#   either claim: `& { param([string]$Sid) ... } -Sid 'x' -ProfilePath 'y'` does NOT throw - an
#   unmatched named argument to a plain (non-advanced) scriptblock is silently ignored. 2.41 was
#   right; this pass's finding was discarded rather than "fixed", since there was nothing to fix.
#   Five real issues DID survive verification and are fixed:
#   - The most significant: Shadow Copies/USN Journal/Secure Free-Space Wipe were appended to the
#     same ordered $script:AllTasks that the main task loop iterates, so they ran as the tail of
#     that SAME loop - which finishes entirely before the separate, unconditional 'Relocate PST
#     Backups' step that follows it. That's the reverse of both this file's own stated intent (the
#     comment above these entries, and Clear-ShadowCopies's own .DESCRIPTION, both assert they run
#     "after PST relocation") and of what -SecureWipe is FOR: with -BackupPst -SecureWipe both set,
#     cipher /w's free-space overwrite completed before the local PST backup copy was deleted, so
#     the blocks it freed were never covered by the wipe and stayed undelete-recoverable - directly
#     defeating -SecureWipe's purpose for arguably the single most sensitive artifact this script
#     produces. Fixed by recording those three task names in $script:TrailingTasks and explicitly
#     deferring them to a second loop that runs after 'Relocate PST Backups', not as part of the
#     first.
#   - Invoke-ForEachUserHive fell through silently, with NO warning at all, when a profile folder
#     exists but has no NTUSER.DAT (a corrupted/incompletely-provisioned profile) and isn't already
#     mounted - it would invoke $Action against a HKU\<sid> hive that was never loaded, so every
#     registry read/write in the caller just quietly found nothing via its own
#     -ErrorAction SilentlyContinue. This directly contradicted the function's own .DESCRIPTION
#     ("skips WITH A WARNING any profile whose hive fails to load"). Added the missing warning-and-
#     return branch, matching the existing pattern for a failed `reg load`.
#   - Clear-EventLogs filtered logs via an unguarded `Where-Object { $_.RecordCount -gt 0 }` - some
#     disabled Analytic/Debug channels are documented to throw the moment RecordCount is accessed,
#     even past Get-WinEvent's own -ErrorAction SilentlyContinue, which (the same pipeline-abort
#     class of bug already fixed once in Invoke-ForEachUserHive) could silently leave every log
#     after the throwing one uncleared. Moved the RecordCount check into a per-item try/catch
#     inside the ForEach-Object instead of a preceding Where-Object.
#   - Two cosmetic doc-comment fixes: Clear-PinnedItems had a duplicated "The The" from a prior
#     edit, and separately was missing Marshal.ReleaseComObject on the FolderItems collection
#     object itself (only the Namespace and each individual FolderItem were released) - now
#     captured in its own variable and released. Clear-AmcacheAndShimCache's .DESCRIPTION had the
#     registry path backwards ("Session Manager\Control" vs. the code's correct
#     "Control\Session Manager"). Move-ArtifactOffMachine logged "Copied ... to thumbdrive" even
#     when the source directory was empty and nothing was actually copied - now logs accurately for
#     that case. The self-elevation trailing-backslash rejection's error text said "a single
#     trailing backslash" even though the check (and the underlying corruption) fires for any odd
#     count - reworded.
#   Two more candidates were considered and deliberately NOT changed: $pstPathOwners could
#   theoretically collide if two different users' GPO-redirected folders resolved to the exact same
#   path (extremely unlikely on this fleet, and the existing behavior - last-write-wins on the
#   owner mapping - is a reasonable fallback, not a crash); and Resolve-UserShellFolder only
#   special-cases the %USERPROFILE% token before expanding, so a different per-user token (e.g.
#   %HOMESHARE%) would in theory hit the same class of bug already fixed for %USERPROFILE% - no
#   evidence this fleet's GPOs ever use such a token, so this is noted rather than spent effort
#   guarding against a token that's never actually been observed in this registry value.

[CmdletBinding()]
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
    [string]$PstBackupPath = "$env:SystemDrive\PstBackup",
    # Runs 'cipher /w' (Windows' built-in 3-pass free-space overwrite) on
    # every drive at the very end. Off by default because of the time cost,
    # not the risk - it can take 30-60+ minutes depending on drive size and
    # how much free space there is, on top of everything else this script
    # already does. Without it, everything this script deletes (here and via
    # ordinary Remove-Item in general) is only unlinked, not overwritten, and
    # stays recoverable with undelete tools until that disk space gets reused.
    [switch]$SecureWipe,
    # Internal use only - set automatically when this script relaunches
    # itself elevated. Do not pass this by hand. It caps self-elevation at
    # one attempt: if the relaunched copy still isn't Administrator, that
    # means elevation isn't actually taking effect on this machine, and
    # retrying would just spawn another UAC prompt and relaunch forever
    # instead of failing loudly.
    [switch]$ElevationRetry
)

#region Admin check / self-elevate
# Checked against the raw BUILTIN\Administrators SID (S-1-5-32-544) rather
# than IsInRole('Administrator') - the string overload resolves the name via
# enum/NTAccount lookup, which is one more thing that can misbehave on a
# hardened or domain-trust-quirky machine. Comparing the SID directly is the
# same check .NET ultimately does, without that resolution step.
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
if (-not $isAdmin) {
    if ($ElevationRetry) {
        Write-Error @"
Still not running as Administrator after already relaunching elevated once - not
retrying again (that would just loop, spawning UAC prompts indefinitely).

Common causes:
  - The UAC prompt was cancelled, denied, or timed out
  - This account isn't a member of the local Administrators group - elevation
    may require a separate admin account (e.g. a "-adm" account) rather than
    entering this account's own credentials at the UAC prompt
  - Endpoint privilege-management software (BeyondTrust, CyberArk EPM, etc.)
    is intercepting the elevation request instead of native UAC, and isn't
    granting a full admin token to the relaunched process

Current user: $env:USERDOMAIN\$env:USERNAME
"@
        exit 1
    }

    if (-not $PSCommandPath) {
        Write-Error "This script must be run as Administrator, and can't self-elevate from an unsaved editor tab - save this file, then re-run it (or launch it as Administrator directly). Exiting."
        exit 1
    }

    Write-Host "Not running as Administrator - relaunching elevated (accept the UAC prompt)..." -ForegroundColor Yellow

    # Rebuild from $PSBoundParameters so -SkipReboot/-PreserveSecurityLog/
    # -BackupPst/-PstBackupPath actually carry through to the elevated
    # instance instead of silently reverting to defaults.
    #
    # String values are wrapped in "..." as their own $argList element - this
    # is safe for spaces (confirmed empirically) but NOT safe if the value
    # itself contains a literal double-quote: that breaks out of the intended
    # single argument and gets re-split into several separate tokens by the
    # elevated process's own command-line parsing, confirmed by direct testing
    # rather than assumed. A doubled-quote escape ("" for one embedded ")
    # - the usual textbook fix for this - was also tested and does NOT
    # resolve it in this specific relaunch path. Rather than depend on getting
    # Windows' notoriously fiddly argv-quoting rules exactly right, this
    # validates instead: a literal " can never legally appear in a real
    # Windows path component anyway (confirmed - Windows itself refuses to
    # create one), so any string parameter containing one is rejected
    # outright with a clear error before attempting elevation, rather than
    # silently corrupting the relaunch. Applies generically to every string
    # parameter, not just -PstBackupPath, so it also protects any string
    # parameter added to this script in the future.
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-ElevationRetry')
    foreach ($key in $PSBoundParameters.Keys) {
        $val = $PSBoundParameters[$key]
        if ($val -is [switch]) { if ($val.IsPresent) { $argList += "-$key" } }
        else {
            if ($val -is [string] -and $val.Contains('"')) {
                Write-Error "-$key contains a double-quote character, which can never legally appear in a real Windows path and cannot be safely passed through to the elevated relaunch. Remove it and try again. Value: $val"
                exit 1
            }
            # A run of backslashes immediately before the closing quote below is
            # only safe if there's an EVEN number of them (CommandLineToArgvW
            # pairs them off as literal backslashes and still treats the quote as
            # a real closing quote) - an ODD number leaves one backslash that
            # escapes the closing quote instead, so the string never closes and
            # whatever comes after (e.g. -SkipReboot) gets silently absorbed into
            # this value instead of binding as its own argument. Confirmed by
            # direct testing against a real elevated child process. Same
            # validate-rather-than-escape approach as the embedded-quote check
            # above.
            if ($val -is [string] -and $val -match '\\+$' -and ($Matches[0].Length % 2) -eq 1) {
                Write-Error "-$key ends in an odd number of trailing backslashes, which escapes the closing quote when passed through to the elevated relaunch and corrupts the argument list. Remove the trailing backslash (or double it) and try again. Value: $val"
                exit 1
            }
            $argList += "-$key", "`"$val`""
        }
    }

    try {
        $elevatedProc = Start-Process powershell.exe -ArgumentList $argList -Verb RunAs -Wait -PassThru
        exit $elevatedProc.ExitCode
    }
    catch {
        Write-Error "Elevation was cancelled or failed: $($_.Exception.Message)"
        exit 1
    }
}
#endregion

#region Transcript
$LogDir = "$env:SystemDrive\Logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$LogPath = "$LogDir\Reset_Fire_Laptop_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $LogPath
Write-Host "Logging to $LogPath`n"
#endregion

# Base path for all user profiles - avoids hardcoding C:\Users throughout.
# Read from the authoritative ProfilesDirectory registry value (what Windows
# itself actually uses to place new profiles) rather than assumed outright -
# this defaults to "%SystemDrive%\Users" on a stock install and matched that
# default when checked on this machine, but some hardened/custom-imaged
# machines relocate it (e.g. to a separate partition), and every cleanup
# function in this script depends on $UsersBase actually being correct.
# Falls back to the stock default if the registry read fails for any reason.
$profilesDirRaw = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name ProfilesDirectory -ErrorAction SilentlyContinue).ProfilesDirectory
$UsersBase = if ($profilesDirRaw) { [Environment]::ExpandEnvironmentVariables($profilesDirRaw) } else { "$env:SystemDrive\Users" }

# Shared regex for Chromium-based browser data - used by both Clear-Chrome and Clear-Edge.
# Includes extension local storage so cached auth tokens are also cleared.
#
# 'Storage' is deliberately a bare substring, not the full folder name - -match is
# unanchored, so it also catches 'Local Storage', 'Session Storage', and 'WebStorage'
# in one term. This matters because a live inspection of an actual Chrome/Edge
# profile on this machine (Aug 2026) showed the literal Cookies file (now under a
# Network\ subfolder) WAS already being matched and deleted, but 'Local Storage' -
# where many modern web apps put session/auth tokens instead of cookies - was not
# matched by anything in the old regex and was being left behind, along with the
# newer partitioned 'Storage' container Chromium now uses for IndexedDB/Cache/
# LocalStorage per-site, 'Service Worker' (its own Cache Storage), and 'File System'
# (File System Access API data). 'Sync' is also a bare substring so it catches Edge's
# 'Sync Data'/'Sync App Settings'/'Sync Extension Settings' together.
#
# 'Local State' is a separate later finding: it lives at the ROOT of "User Data",
# not inside any profile folder, so Clear-Chrome/Clear-Edge's traversal reaches it
# but nothing in the regex matched it until this was added - confirmed by directly
# reading this machine's own Local State file, which is JSON containing a
# profile.info_cache entry per profile with that profile's signed-in account email
# (user_name) and display name (gaia_name). Without this, a departed user's account
# identity could still surface in the browser's profile picker after a "wipe" even
# though their actual profile data was cleared. Safe to delete outright - Chrome/Edge
# regenerate it fresh on next launch, same as everything else this regex targets.
$script:BrowserDataRegex = 'Archived History|Cache|Cookies|Extension State|File System|History|IndexedDB|Local Extension Settings|Local State|Login Data|Service Worker|Storage|Sync|Top Sites|Visited Links|Web Data'

function Test-OnRemovableMedia {
    <#
    .SYNOPSIS
        Tests whether a path is on removable (thumbdrive) media.
    .DESCRIPTION
        Resolves the drive letter of the given path and checks its Win32_LogicalDisk
        DriveType via CIM (DriveType 2 = Removable Disk). This script is dropped on a
        thumbdrive and run against many different laptops before each is reissued, so
        this is checked once at startup against $PSScriptRoot - the result tells
        Move-ArtifactOffMachine whether the transcript log and any -BackupPst output can
        be relocated to the thumbdrive instead of being left behind on the machine.
    .PARAMETER Path
        Any filesystem path; only its drive letter is examined.
    .OUTPUTS
        System.Boolean - $true if the path's drive is removable media, $false otherwise
        (including on any error, e.g. a UNC path with no drive letter).
    #>
    param([string]$Path)
    try {
        $driveLetter = (Get-Item $Path -ErrorAction Stop).PSDrive.Name
        return (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$driveLetter`:'" -ErrorAction Stop).DriveType -eq 2
    }
    catch { return $false }
}
$script:RunningFromRemovableMedia = Test-OnRemovableMedia -Path $PSScriptRoot
# Drive letter this script itself is running from - used by the drive-iterating
# cleanup steps below (Recycle Bin, USN Journal, secure free-space wipe) to skip
# the technician's own reusable thumbdrive when $RunningFromRemovableMedia is
# true, rather than treating it like one of the target machine's internal
# drives. Most concretely matters for -SecureWipe's cipher /w pass, which is
# genuinely expensive (30-60+ minutes per drive per its own doc) and pointless
# to run against an IT tool that gets reused across every machine in a stack.
$script:ScriptDriveLetter = (Get-Item $PSScriptRoot -ErrorAction SilentlyContinue).PSDrive.Name

function Get-TargetFileSystemDrives {
    <#
    .SYNOPSIS
        Returns the machine's FileSystem drives to run whole-drive cleanup
        against, excluding the removable drive this script is itself running
        from when applicable.
    .DESCRIPTION
        Wraps `Get-PSDrive -PSProvider FileSystem`, filtering out
        $script:ScriptDriveLetter when $script:RunningFromRemovableMedia is
        true - used by Recycle Bin cleanup, USN Journal reset, and the
        -SecureWipe free-space overwrite, none of which should treat the
        technician's own reusable thumbdrive as one of the target machine's
        internal drives.
    .OUTPUTS
        System.Management.Automation.PSDriveInfo[]
    #>
    Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
        Where-Object { -not ($script:RunningFromRemovableMedia -and $_.Name -eq $script:ScriptDriveLetter) }
}

function Move-ArtifactOffMachine {
    <#
    .SYNOPSIS
        Relocates a file or folder off the machine being wiped, or purges it.
    .DESCRIPTION
        If this script is running from removable media (per $script:RunningFromRemovableMedia,
        set once at startup by Test-OnRemovableMedia), copies $SourcePath to
        <thumbdrive>\Collected\<DestFolderName> and only deletes $SourcePath from the target
        machine once that copy has actually succeeded - if the copy fails (drive full,
        unplugged, permissions), $SourcePath is left in place rather than deleted with no
        off-machine copy, so a PST backup or transcript can't be silently lost. When not
        running from removable media there's nowhere safe to copy to, so this just purges
        $SourcePath outright. Used in the script's finally block for its own transcript log,
        and (when -BackupPst is passed) for the PST backup folder.
    .PARAMETER SourcePath
        The file or directory to relocate/purge. No-ops if it doesn't exist.
    .PARAMETER DestFolderName
        Subfolder name under <thumbdrive>\Collected\ to copy into when relocation is possible.
    #>
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DestFolderName
    )
    if (-not (Test-Path $SourcePath)) { return }

    $copyOk = $true
    if ($script:RunningFromRemovableMedia) {
        $copyOk = $false
        try {
            $destRoot = Join-Path $PSScriptRoot "Collected\$DestFolderName"
            New-Item -Path $destRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
            if ((Get-Item $SourcePath -ErrorAction Stop).PSIsContainer) {
                # $destRoot already exists (created above), so copying the source
                # directory itself into it would nest an extra "<destRoot>\
                # <SourceDirName>\..." level instead of landing directly under
                # $destRoot - copy its contents instead. Guard against an empty
                # source directory, where the "\*" wildcard would otherwise match
                # nothing and Copy-Item would throw "Cannot find path".
                if (Get-ChildItem $SourcePath -Force -ErrorAction SilentlyContinue) {
                    Copy-Item -Path "$SourcePath\*" -Destination $destRoot -Recurse -Force -ErrorAction Stop
                    Write-Host "  Copied $SourcePath to thumbdrive: $destRoot" -ForegroundColor Green
                }
                else {
                    Write-Host "  $SourcePath was empty - nothing to copy, removing it." -ForegroundColor Green
                }
            }
            else {
                Copy-Item -Path $SourcePath -Destination $destRoot -Force -ErrorAction Stop
                Write-Host "  Copied $SourcePath to thumbdrive: $destRoot" -ForegroundColor Green
            }
            $copyOk = $true
        }
        catch {
            Write-Host "  WARNING: could not copy $SourcePath to thumbdrive ($($_.Exception.Message)) - leaving it in place on the machine instead of deleting it with no off-machine copy." -ForegroundColor Yellow
        }
    }

    if ($copyOk) {
        Remove-Item -Path $SourcePath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Stop-ProcessAndWait {
    <#
    .SYNOPSIS
        Force-stops a process by name and waits for it to fully exit.
    .DESCRIPTION
        Looks up the process by name, force-stops it if running, and waits up to 15
        seconds for it to actually exit before returning - callers rely on this so a
        file/registry cleanup step that runs immediately after doesn't race a process
        that's still shutting down and still holding its files/handles open (e.g.
        clearing a browser cache right after closing the browser). No-ops quietly if
        the process isn't running.
    .PARAMETER Name
        Process name without the .exe extension (as used by Get-Process), e.g. 'chrome'.
    #>
    param([string]$Name)
    $proc = Get-Process $Name -ErrorAction SilentlyContinue
    if ($proc) {
        $proc | Stop-Process -Force -ErrorAction SilentlyContinue
        $proc | Wait-Process -Timeout 15 -ErrorAction SilentlyContinue
        Write-Host "$Name processes stopped..." -ForegroundColor Green
    }
    else {
        Write-Host "$Name not running..." -ForegroundColor Yellow
    }
}

# Collects names of any steps that threw - read by the summary block.
$script:stepErrors = [System.Collections.Generic.List[string]]::new()

function Invoke-Step {
    <#
    .SYNOPSIS
        Runs one named cleanup step with timing and per-step error isolation.
    .DESCRIPTION
        Wraps a single cleanup task: prints a timestamped header, invokes $Action inside
        try/catch so one step throwing doesn't abort the rest of the run, records the step
        name in $script:stepErrors on failure (read by the completion summary printed at
        the end of the script), and prints elapsed time in a finally block regardless of
        success or failure. This is what the main task loop calls for every entry in
        $script:AllTasks the technician selected in the GUI checklist.
    .PARAMETER Name
        Display name for the step, used in the console header and in $script:stepErrors.
    .PARAMETER Action
        Scriptblock to execute - normally a single function call, e.g. { Clear-Chrome }.
    #>
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

function Show-TaskSelectionDialog {
    <#
    .SYNOPSIS
        Shows a WinForms checklist of every cleanup task for the technician to select.
    .DESCRIPTION
        Displays a modal dialog listing every key in $Tasks (all checked by default,
        with Select All/Select None buttons) so a technician can uncheck anything they
        don't want to run on this specific machine, rather than having to edit the
        script or pass a pile of switches. The dialog header shows the target
        computer name and serial number so a tech working through a stack of laptops
        can confirm it's the right machine before proceeding.
    .PARAMETER Tasks
        The ordered dictionary of task name -> scriptblock ($script:AllTasks) whose
        keys populate the checklist, in order.
    .PARAMETER ComputerName
        Displayed in the dialog header.
    .PARAMETER SerialNumber
        Displayed in the dialog header.
    .OUTPUTS
        System.String[] - the array of selected task names, if the tech clicked Run
        Selected.

        An EMPTY array, if the tech clicked Cancel/closed the dialog (means "run
        nothing" - deliberately distinct from the case below).

        $null, only if WinForms itself couldn't load (means "GUI unavailable, fall
        back to running every task with the old text-prompt confirmation" - this
        script is always run interactively on a physical laptop, but a headless edge
        case shouldn't hard-crash the whole run).
    #>
    param(
        [Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Tasks,
        [string]$ComputerName,
        [string]$SerialNumber
    )

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not load Windows Forms ($($_.Exception.Message)) - falling back to running every task."
        return $null
    }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Reset Fire Laptop - Select Tasks to Run'
    $form.Size = New-Object System.Drawing.Size(440, 600)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true

    $infoLabel = New-Object System.Windows.Forms.Label
    $infoLabel.Text = "Target: $ComputerName  (S/N: $SerialNumber)`r`nUncheck anything you don't want to run, then click Run Selected."
    $infoLabel.Location = New-Object System.Drawing.Point(12, 10)
    $infoLabel.Size = New-Object System.Drawing.Size(404, 40)
    $form.Controls.Add($infoLabel)

    $checklist = New-Object System.Windows.Forms.CheckedListBox
    $checklist.Location = New-Object System.Drawing.Point(12, 55)
    $checklist.Size = New-Object System.Drawing.Size(404, 460)
    $checklist.CheckOnClick = $true
    foreach ($name in $Tasks.Keys) { [void]$checklist.Items.Add($name, $true) }
    $form.Controls.Add($checklist)

    $selectAllBtn = New-Object System.Windows.Forms.Button
    $selectAllBtn.Text = 'Select All'
    $selectAllBtn.Location = New-Object System.Drawing.Point(12, 522)
    $selectAllBtn.Size = New-Object System.Drawing.Size(90, 26)
    $selectAllBtn.Add_Click({ for ($i = 0; $i -lt $checklist.Items.Count; $i++) { $checklist.SetItemChecked($i, $true) } })
    $form.Controls.Add($selectAllBtn)

    $selectNoneBtn = New-Object System.Windows.Forms.Button
    $selectNoneBtn.Text = 'Select None'
    $selectNoneBtn.Location = New-Object System.Drawing.Point(108, 522)
    $selectNoneBtn.Size = New-Object System.Drawing.Size(90, 26)
    $selectNoneBtn.Add_Click({ for ($i = 0; $i -lt $checklist.Items.Count; $i++) { $checklist.SetItemChecked($i, $false) } })
    $form.Controls.Add($selectNoneBtn)

    $okBtn = New-Object System.Windows.Forms.Button
    $okBtn.Text = 'Run Selected'
    $okBtn.Location = New-Object System.Drawing.Point(216, 522)
    $okBtn.Size = New-Object System.Drawing.Size(100, 26)
    $okBtn.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($okBtn)
    $form.AcceptButton = $okBtn

    $cancelBtn = New-Object System.Windows.Forms.Button
    $cancelBtn.Text = 'Cancel'
    $cancelBtn.Location = New-Object System.Drawing.Point(322, 522)
    $cancelBtn.Size = New-Object System.Drawing.Size(90, 26)
    $cancelBtn.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($cancelBtn)
    $form.CancelButton = $cancelBtn

    $result = $form.ShowDialog()
    $form.Dispose()

    if ($result -ne [System.Windows.Forms.DialogResult]::OK) { return @() }
    return @($checklist.CheckedItems | ForEach-Object { $_.ToString() })
}

function Invoke-ForEachUserHive {
    <#
    .SYNOPSIS
        Runs a scriptblock against every local user's registry hive, including
        users who aren't currently logged in.
    .DESCRIPTION
        Enumerates every local user profile (SID matching S-1-5-21-*) under
        HKLM:\...\ProfileList, loads that user's NTUSER.DAT under HKU\<SID> via
        `reg load` if it isn't already mounted (i.e. the user isn't logged in right
        now), invokes $Action with -Sid and -ProfilePath so it can read/write that
        user's registry data, then unloads any hive this function mounted. This is
        the mechanism nearly every per-user registry cleanup function in this script
        is built on - without it, cleanup would only ever reach whichever single
        account happens to be running this elevated session, not every user who has
        ever logged into the machine. Skips (with a warning) any profile whose hive
        fails to load, and forces a full garbage collection before unloading so
        lingering .NET registry handles don't cause "Access is denied" from
        `reg unload`. A terminating exception thrown by $Action for one profile is
        caught and logged rather than allowed to propagate - PowerShell aborts the
        entire enumeration pipeline on an unhandled terminating error, which would
        otherwise silently skip every remaining profile for that one task (e.g. a
        registry key with unusual ACLs throwing on one profile would leave every
        profile after it in enumeration order untouched, with no indication beyond
        one logged error that coverage was incomplete).
    .PARAMETER Action
        Scriptblock invoked once per local user profile, receiving -Sid <string> (the
        user's SID, for building "Registry::HKU\$Sid\..." paths) and -ProfilePath
        <string> (the user's profile directory).
    #>
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
            if (-not $alreadyLoaded) {
                if (-not (Test-Path $ntuser)) {
                    # A profile folder with no NTUSER.DAT (corrupted/incompletely
                    # provisioned profile) used to fall through silently here with
                    # no warning at all, then invoke $Action against a HKU\<sid>
                    # hive that was never mounted - every registry read/write in
                    # the caller would just quietly find nothing via its own
                    # -ErrorAction SilentlyContinue, with zero indication in the
                    # log that this profile's registry cleanup never happened.
                    Write-Warning "  No NTUSER.DAT found for $(Split-Path $path -Leaf) - skipping"
                    return
                }
                reg load "HKU\$sid" $ntuser 2>$null | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning "  Could not load hive for $(Split-Path $path -Leaf) - skipping"
                    return
                }
                $loaded = $true
            }
            try {
                try { & $Action -Sid $sid -ProfilePath $path }
                catch { Write-Warning "  Action failed for $(Split-Path $path -Leaf) (HKU\$sid): $($_.Exception.Message)" }
            }
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

function Get-ProfileNameFromPath {
    <#
    .SYNOPSIS
        Extracts the username segment from a path known to start with
        "$UsersBase\<username>\...".
    .DESCRIPTION
        Strips the $UsersBase prefix (plus its trailing separator) from Path and
        returns the next path segment - the username. Written as a real prefix
        strip rather than a fixed split-index. A fixed index (e.g.
        Path.Split('\')[2]) silently breaks if $UsersBase doesn't have exactly
        the number of path segments that index assumes - confirmed as a real,
        pre-existing bug in this script's PST-backup naming logic: it computed
        the split index as $UsersBase.Split('\\').Count, but a two-character
        Split() separator string never matches, since paths don't contain
        double backslashes, so that index was always 1 regardless of
        $UsersBase, making every backed-up PST's filename prefix the literal
        string "Users" instead of the actual username - silently overwriting
        one user's backed-up PST with another's if both had a same-named file.
        See Version 2.35 changelog.
    .PARAMETER Path
        A full path beginning with "$UsersBase\<username>\...".
    .OUTPUTS
        System.String - the username segment, or the original Path unchanged if
        it doesn't actually start with $UsersBase (defensive fallback).
    #>
    param([Parameter(Mandatory)][string]$Path)
    if ($Path.StartsWith($UsersBase, [StringComparison]::OrdinalIgnoreCase)) {
        $remainder = $Path.Substring($UsersBase.Length).TrimStart('\')
        return ($remainder -split '\\')[0]
    }
    return $Path
}

function Resolve-UserShellFolder {
    <#
    .SYNOPSIS
        Resolves a user's actual Desktop/Documents/Pictures folder path, honoring
        OneDrive Known Folder Move (KFM) redirection.
    .DESCRIPTION
        Reads the given value from that user's own User Shell Folders registry
        key (the hive must already be mounted, e.g. inside an
        Invoke-ForEachUserHive scriptblock) and expands any environment
        variables in it. OneDrive Known Folder Move redirects Desktop,
        Documents, and Pictures out of the profile root into a OneDrive sync
        folder (e.g. "OneDrive - <org>\Desktop") by writing the new absolute
        path directly into this registry value - a function that assumes these
        three folders are always at "<profile>\Desktop" etc. will silently miss
        the real, current location on any machine where KFM is active. Falls
        back to the classic "<ProfilePath>\<ClassicName>" path if the registry
        value is missing or blank.
    .PARAMETER Sid
        The user's SID, as passed by Invoke-ForEachUserHive.
    .PARAMETER ProfilePath
        The user's profile directory, as passed by Invoke-ForEachUserHive - used
        for the classic-path fallback.
    .PARAMETER RegValueName
        The User Shell Folders value name: 'Desktop', 'Personal' (Documents), or
        'My Pictures'.
    .PARAMETER ClassicName
        The folder name to fall back to under ProfilePath, e.g. 'Desktop'.
    .OUTPUTS
        System.String - the resolved absolute folder path. Not guaranteed to
        exist on disk; callers should still Test-Path before using it.
    .NOTES
        Also works for Downloads ('{374DE290-123F-4565-9164-39C4925E467B}' /
        'Downloads'), Videos ('My Video'), and Music ('My Music') - OneDrive
        Known Folder Move only ever redirects Desktop/Documents/Pictures, but
        classic Group Policy Folder Redirection is a separate, independent
        mechanism that writes to this same registry key and DOES support
        redirecting all six of these folders. An earlier version of this
        function's callers assumed Downloads/Videos/Music were always classic
        because they're never OneDrive-redirected, without accounting for GPO
        Folder Redirection doing the same thing through a different mechanism -
        see Version 2.32 changelog.

        IMPORTANT: this value is stored as REG_EXPAND_SZ and can contain a
        literal, unexpanded "%USERPROFILE%" token instead of a resolved path -
        confirmed on this machine, where Desktop/Personal/My Pictures happen to
        already be fully-resolved (because OneDrive KFM writes the absolute path
        when it redirects them) but My Video/My Music/the Downloads GUID value
        are still literally "%USERPROFILE%\Videos" etc. [Environment]::
        ExpandEnvironmentVariables() expands using the CURRENT PROCESS's own
        environment - i.e. the elevated technician's own account - which would
        silently resolve "%USERPROFILE%" to the WRONG user's profile for every
        local account other than whoever happens to be running this script.
        "%USERPROFILE%" is therefore replaced with the target user's actual
        $ProfilePath directly (the one value here that's always correct for
        that specific user) before any other environment-variable expansion
        runs - see Version 2.34 changelog.
    #>
    param(
        [Parameter(Mandatory)][string]$Sid,
        [Parameter(Mandatory)][string]$ProfilePath,
        [Parameter(Mandatory)][string]$RegValueName,
        [Parameter(Mandatory)][string]$ClassicName
    )
    $key = "Registry::HKU\$Sid\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    $raw = (Get-ItemProperty -Path $key -Name $RegValueName -ErrorAction SilentlyContinue).$RegValueName
    if ($raw) {
        # Replace the user-specific token with the TARGET user's own profile
        # path first - ExpandEnvironmentVariables below would otherwise resolve
        # it against this (elevated technician's) process's own environment.
        $substituted = $raw -replace [regex]::Escape('%USERPROFILE%'), $ProfilePath
        $expanded    = [Environment]::ExpandEnvironmentVariables($substituted)
        if ($expanded) { return $expanded }
    }
    return (Join-Path $ProfilePath $ClassicName)
}

Function Clear-Chrome {
    <#
    .SYNOPSIS
        Clears Google Chrome cache, cookies, history, and saved logins for all users.
    .DESCRIPTION
        Stops chrome.exe, then does a single recursive traversal of every user's
        Chrome "User Data" folder (covering every Chrome profile - Default,
        Profile 1, etc. - for every user, not just the current session) and deletes
        any item matching $script:BrowserDataRegex: cache, cookies (including the
        Network\Cookies file Chrome moved cookies into years ago), history, saved
        logins, IndexedDB, Local/Session Storage and the newer partitioned Storage
        container (where many modern sites now put session/auth tokens instead of
        cookies), Service Worker cache, File System Access API data, and extension
        local storage. No official Microsoft cmdlet exists for third-party browser
        data; this is Chrome's own documented profile-data layout.
    #>
    Stop-ProcessAndWait -Name 'chrome'

    # Single traversal - covers all users and all Chrome profiles (Default, Profile 1, …).
    # BrowserDataRegex includes extension local storage for cached auth tokens.
    Get-ChildItem "$UsersBase\*\AppData\Local\Google\Chrome\User Data" -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $script:BrowserDataRegex } |
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Yellow "Google Chrome Cache Removal - COMPLETE`r`n"
}

Function Clear-IE {
    <#
    .SYNOPSIS
        Clears Internet Explorer cache and the shared WinINet cache database.
    .DESCRIPTION
        Stops iexplore.exe, then clears Temporary Internet Files and the WinINet
        Caches folder for every user. Also clears WebCacheV01.dat, the shared
        WinINet cache database - some non-browser apps still write cookies/cache
        into it via WinINet APIs even on machines where IE itself is gone (IE was
        EOL June 2022 and removed from Windows 11; this step is retained for any
        legacy machines still in the fleet).
    #>
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

    # WebCacheV01.dat is the shared WinINet cache database - some non-browser
    # apps still write cookies/cache into it via WinINet APIs even though IE
    # itself is gone, so this is broader than just IE cleanup.
    Remove-Item "$UsersBase\*\AppData\Local\Microsoft\Windows\WebCache\*" -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Yellow "IE Cache Removal - COMPLETE`r`n"
}

Function Clear-FireFox {
    <#
    .SYNOPSIS
        Clears Firefox cache, cookies, history, saved logins, and session data for
        all users.
    .DESCRIPTION
        Stops firefox.exe, then walks every directory directly under each user's
        Firefox Profiles folder (cache under AppData\Local, profile data under
        AppData\Roaming) - every such directory is a real profile regardless of
        name, so none are filtered out by name - and deletes a fixed list of
        known cache/history/login/session files and folders within each profile
        (places.sqlite for history+bookmarks, logins.json for saved passwords,
        key4.db for the password encryption key, the 'storage' folder for
        IndexedDB/Cache API (Service Worker)/modern LocalStorage, etc). No
        official Microsoft cmdlet exists for third-party browser data; this
        follows Mozilla's own documented profile-folder layout.
    .NOTES
        An earlier version filtered profile folders with
        `-match '\.default|\.dev-edition-default'`, which only matches Firefox's
        auto-created default profile(s) - any additional profile a user created
        via about:profiles, or one with a custom/provisioned name, never matched
        and was left completely untouched (cache, history, and saved logins
        included) while this step still reported success. Since $ProfileBases
        already scopes to exactly the Profiles folder, every child directory
        there is a genuine profile - no name filter is needed at all.

        webappsstore.sqlite only covers Firefox's LEGACY localStorage format -
        current Firefox versions store localStorage in the newer LSNG (LocalStorage
        Next Generation) format under the 'storage' folder alongside IndexedDB and
        Service Worker Cache API data, so 'storage' is included as well. Not
        verified against a live Firefox profile on this specific machine (none
        installed here as of this check) - based on Mozilla's documented profile
        layout.
    #>
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
        'sessionstore-backups',   # session backup folder
        'storage'                 # IndexedDB, Service Worker Cache API, modern (LSNG) localStorage
    )

    foreach ($base in $ProfileBases) {
        Get-ChildItem $base -Directory -ErrorAction SilentlyContinue |
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
    <#
    .SYNOPSIS
        Clears Chromium Edge (and legacy EdgeHTML) cache, cookies, history, and
        saved logins for all users.
    .DESCRIPTION
        Stops msedge.exe, then does a single recursive traversal of every user's
        Edge "User Data" folder (all Edge profiles, all users) deleting anything
        matching $script:BrowserDataRegex - same pattern and same shared regex as
        Clear-Chrome (including Local/Session/partitioned Storage, Service Worker,
        and File System data, plus Edge's own Sync Data/Sync App Settings/Sync
        Extension Settings folders), since Edge and Chrome are both Chromium-based
        and use the same profile-data layout. Also clears the legacy EdgeHTML (UWP)
        app container data under Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe,
        kept for any machines that still have it, using $UsersBase rather than
        $env:LOCALAPPDATA so it reaches every profile, not just the current
        elevated session's own account.
    #>
    Stop-ProcessAndWait -Name 'msedge'

    # Single traversal - covers all users and all Edge profiles.
    # BrowserDataRegex includes Archived History and extension local storage.
    Get-ChildItem "$UsersBase\*\AppData\Local\Microsoft\Edge\User Data" -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $script:BrowserDataRegex } |
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

    # Legacy EdgeHTML (UWP) - kept for any machines that still have it.
    # $UsersBase (not $env:LOCALAPPDATA) so this covers every profile on the
    # machine, not just whichever account is running this elevated session.
    Remove-Item "$UsersBase\*\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\AC\#!*" -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Yellow "Edge Cache Removal - COMPLETE`r`n"
}

Function Remove-OneDriveAccounts {
    <#
    .SYNOPSIS
        Unlinks OneDrive Business and Personal account sign-ins for all users.
    .DESCRIPTION
        Runs OneDrive.exe /reset - Microsoft's own documented reset command - for
        whichever user is running this session interactively right now, as the
        preferred/official method. /reset only works for the currently logged-in
        session (OneDrive has to already be running as that user for the signal to
        reach it), so it cannot target a different, non-interactive profile.
        Registry-based removal (walking every user's OneDrive\Accounts key via
        Invoke-ForEachUserHive, matching both 'Business*' and 'Personal' sub-keys,
        and removing the matching Explorer namespace entry) covers every other
        profile on the machine, and doubles as a safety net for the current session
        too.
    .NOTES
        Official command used: OneDrive.exe /reset (current session only).
    #>
    Write-Host "Clearing OneDrive accounts - Business and Personal (all users)..."
    Stop-ProcessAndWait -Name 'OneDrive'

    # OneDrive.exe /reset is Microsoft's own documented reset command - it
    # unlinks the account and returns OneDrive to an unconfigured state. The
    # catch: it only works in the context of whichever user is actually
    # interactively logged into THIS session right now - OneDrive has to
    # already be running as that user for /reset to signal it, and there's
    # no supported way to invoke it for a different, non-interactive
    # profile. So this covers the current session as the preferred method;
    # the registry-based removal below still covers every other profile on
    # the machine (and doubles as a safety net for this one too).
    $oneDriveExe = "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
    if (Test-Path $oneDriveExe) {
        Start-Process -FilePath $oneDriveExe -ArgumentList '/reset' -WindowStyle Hidden -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        Stop-ProcessAndWait -Name 'OneDrive'
        Write-Host "  Ran official OneDrive.exe /reset for the current session ($env:USERNAME)." -ForegroundColor Green
    }

    Invoke-ForEachUserHive {
        param([string]$Sid, [string]$ProfilePath)
        $accountsRegKeyPath = "Registry::HKU\$Sid\Software\Microsoft\OneDrive\Accounts"
        $accountsKey = Get-Item $accountsRegKeyPath -ErrorAction SilentlyContinue
        if (-not $accountsKey) { return }

        # Business accounts are named 'Business1', 'Business2', etc.; a
        # consumer/personal Microsoft account sign-in is named 'Personal'.
        # Originally this only matched Business, on the assumption nobody
        # would sign into OneDrive with a personal MSA on a work laptop -
        # but nothing here actually prevents that, so both are covered now.
        $subKeys = $accountsKey.GetSubKeyNames() -match '^(Business|Personal)'
        if (-not $subKeys) { return }

        foreach ($subkey in $subKeys) {
            $oneDriveAccountKeyPath = Join-Path -Path $accountsRegKeyPath -ChildPath $subkey
            $userEmail   = (Get-ItemProperty -Path $oneDriveAccountKeyPath -Name UserEmail   -ErrorAction SilentlyContinue).UserEmail
            $displayName = (Get-ItemProperty -Path $oneDriveAccountKeyPath -Name DisplayName -ErrorAction SilentlyContinue).DisplayName
            # Consumer OneDrive's Explorer namespace entry is just "OneDrive"
            # (no " - <name>" suffix) unlike Business accounts.
            $oneDriveName = if ($subkey -match '^Personal') { 'OneDrive' } else { "OneDrive - $displayName" }

            Write-Host "  Removing: $userEmail ($displayName) [$subkey] for $(Split-Path $ProfilePath -Leaf)"

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

    Write-Host -ForegroundColor Yellow "OneDrive Account Removal - COMPLETE`r`n"
}

Function Remove-UserCache {
    <#
    .SYNOPSIS
        Clears every user's %LOCALAPPDATA%\Temp folder.
    .DESCRIPTION
        Deletes the contents of AppData\Local\Temp for every profile under
        $UsersBase, not just the current session's own account.
    #>
    Write-Host "Clearing user temp caches (all users)..."
    # $UsersBase covers every profile on the machine, not just the current session
    Remove-Item "$UsersBase\*\AppData\Local\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host -ForegroundColor Yellow "User Cache Removal - COMPLETE`r`n"
}

Function Clear-WER {
    <#
    .SYNOPSIS
        Clears Windows Error Reporting (WER) queues and per-user crash reports.
    .DESCRIPTION
        Deletes each user's per-user WER folder (crash reports can contain stack
        traces, environment variables, and partial memory dumps) plus the
        machine-wide WER ReportQueue and ReportArchive under $env:ProgramData. This
        is Windows Error Reporting's own report queue/archive - distinct from the
        raw crash dump files apps write directly via WerFault/LocalDumps, which
        Clear-DiagnosticArtifacts handles separately.
    #>
    Write-Host "Clearing Windows Error Reporting data (all users and system)..."
    # Per-user crash reports can contain stack traces, env variables, and partial memory dumps
    Remove-Item "$UsersBase\*\AppData\Local\Microsoft\Windows\WER\*"    -Recurse -Force -ErrorAction SilentlyContinue
    # System-wide WER queue and report archive ($env:ProgramData avoids hardcoded C:\)
    Remove-Item "$env:ProgramData\Microsoft\Windows\WER\ReportQueue\*"   -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:ProgramData\Microsoft\Windows\WER\ReportArchive\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host -ForegroundColor Yellow "WER Cleanup - COMPLETE`r`n"
}

Function Clear-WindowsTemp {
    <#
    .SYNOPSIS
        Clears Windows Temp and resets Windows Update components.
    .DESCRIPTION
        Clears $env:SystemRoot\Temp, then follows Microsoft's own documented "reset
        Windows Update components" troubleshooting steps: stops wuauserv, bits, and
        cryptsvc (files under SoftwareDistribution/catroot2 can be locked while an
        update is downloading, staging, or being signature-checked), clears
        SoftwareDistribution\DataStore and \Download, clears System32\catroot2, and
        removes the legacy BITS qmgr*.dat job queue database. Only restarts
        whichever of those services were actually running beforehand, so a
        GPO-disabled service doesn't get re-enabled as a side effect. Microsoft's
        own guidance is to RENAME these folders to *.bak instead of deleting them,
        so there's a rollback path if the reset doesn't fix the original problem -
        that doesn't apply here (the machine is being wiped, not troubleshot), so
        this deletes them outright instead of leaving renamed backups behind for
        the next user.
    .NOTES
        Matches Microsoft's documented WU component reset procedure (stop
        wuauserv/bits/cryptsvc; clear DataStore/Download/catroot2/qmgr*.dat;
        restart services) - see the Version 2.25 changelog entry.
    #>
    Write-Host "Clearing Windows Temp and resetting Windows Update components..."

    # Same service set (and same intent) as Microsoft's own documented
    # "reset Windows Update components" troubleshooting steps - stop
    # wuauserv/bits/cryptsvc before touching anything under
    # SoftwareDistribution or catroot2, since files there can be locked
    # while an update is downloading, staging, or being signature-checked.
    # Microsoft's guidance is to RENAME DataStore/Download/catroot2 to
    # *.bak instead of deleting them, so there's a fallback to roll back to
    # if the reset doesn't fix the original problem - that doesn't apply
    # here (this laptop is being wiped, not troubleshot), so this deletes
    # them outright rather than leaving renamed backup folders behind for
    # whoever gets the machine next.
    $wuWasRunning     = (Get-Service wuauserv -ErrorAction SilentlyContinue).Status -eq 'Running'
    $bitsWasRunning   = (Get-Service bits     -ErrorAction SilentlyContinue).Status -eq 'Running'
    $cryptWasRunning  = (Get-Service cryptsvc -ErrorAction SilentlyContinue).Status -eq 'Running'

    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Stop-Service -Name bits     -Force -ErrorAction SilentlyContinue
    Stop-Service -Name cryptsvc -Force -ErrorAction SilentlyContinue

    Remove-Item "$env:SystemRoot\Temp\*"                            -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:SystemRoot\SoftwareDistribution\DataStore\*"  -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:SystemRoot\SoftwareDistribution\Download\*"   -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:SystemRoot\System32\catroot2\*"               -Recurse -Force -ErrorAction SilentlyContinue
    # BITS job queue database for the legacy Background Intelligent Transfer
    # download manager - also part of Microsoft's documented reset steps.
    Remove-Item "$env:ProgramData\Microsoft\Network\Downloader\qmgr*.dat" -Force -ErrorAction SilentlyContinue

    if ($wuWasRunning)    { Start-Service -Name wuauserv -ErrorAction SilentlyContinue }
    if ($bitsWasRunning)  { Start-Service -Name bits     -ErrorAction SilentlyContinue }
    if ($cryptWasRunning) { Start-Service -Name cryptsvc -ErrorAction SilentlyContinue }

    Write-Host -ForegroundColor Yellow "Windows Temp / Windows Update Reset - COMPLETE`r`n"
}

Function Clear-NetworkCredentials {
    <#
    .SYNOPSIS
        Removes every stored credential from the current user's Credential Manager
        vault.
    .DESCRIPTION
        Lists every target in the current user's Windows Credential Manager vault
        via `cmdkey /list` and deletes each one via `cmdkey /delete`. No PowerShell
        cmdlet exists for Credential Manager in stock Windows PowerShell 5.1;
        cmdkey.exe is Microsoft's own command-line tool for this.
    .NOTES
        Platform limitation, not a script gap: cmdkey only operates on the CURRENT
        user's DPAPI-protected credential vault. Other users' stored credentials
        cannot be enumerated or deleted without their password or a domain recovery
        key.
    #>
    Write-Host "Clearing stored network credentials..."

    # Note: cmdkey only operates on the current user's DPAPI-protected credential vault.
    # Other users' stored credentials cannot be enumerated or deleted without their
    # password or a domain recovery key - this is a Windows platform limitation.
    # Split on 'Target:' to handle output format variations across Windows versions.
    $targets = (cmdkey /list) -match 'Target:' |
        ForEach-Object { ($_ -split 'Target:\s*')[1].Trim() }

    if ($targets) {
        foreach ($target in $targets) {
            cmdkey /delete:"$target" | Out-Null
            Write-Host "Removed credential: $target"
        }
    }
    else {
        Write-Host "No stored credentials found." -ForegroundColor Yellow
    }

    Write-Host -ForegroundColor Yellow "Network Credential Removal - COMPLETE`r`n"
}

Function Clear-RDPHistory {
    <#
    .SYNOPSIS
        Clears saved RDP server list and connection MRU for all users.
    .DESCRIPTION
        For every local user hive, deletes the Terminal Server Client\Servers
        registry key (saved RDP connection history) and every MRU* value under
        Terminal Server Client\Default (the most-recently-used server list shown
        in Remote Desktop Connection's dropdown).
    #>
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
    <#
    .SYNOPSIS
        Clears every user's persisted Clipboard History files.
    .DESCRIPTION
        Deletes the Clipboard History database under
        AppData\Local\Microsoft\Windows\Clipboard for every profile under
        $UsersBase. This targets the persisted history feature (Win+V), not the
        live in-memory clipboard - the live clipboard clears automatically on the
        reboot this script already triggers.
    .NOTES
        No official cmdlet exists for this. Set-Clipboard only clears the CURRENT
        session's live in-memory clipboard, not the persisted history files this
        function targets, and there is no Clear-Clipboard cmdlet in Windows
        PowerShell 5.1 or PowerShell 7 - confirmed against Microsoft's own
        Set-Clipboard/Get-Clipboard documentation (see Version 2.25 changelog).
    #>
    Write-Host "Clearing clipboard history (all users)..."
    # $UsersBase covers all profiles. Live clipboard clears automatically on reboot.
    Remove-Item "$UsersBase\*\AppData\Local\Microsoft\Windows\Clipboard\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host -ForegroundColor Yellow "Clipboard History Removal - COMPLETE`r`n"
}

Function Clear-PrintQueue {
    <#
    .SYNOPSIS
        Clears all queued print jobs, gracefully then forcefully.
    .DESCRIPTION
        First tries Get-PrintJob | Remove-PrintJob (PrintManagement module) against
        every printer - the official, graceful way to clear queued jobs. Then, as a
        fallback for anything that method can't reach, stops the Print Spooler
        service, deletes every file under System32\spool\PRINTERS, and restarts the
        spooler only if it was already running. The fallback exists because a
        stuck or corrupted job can be unremovable through the API while the
        spooler still has its .SHD/.SPL files locked.
    .NOTES
        Official cmdlets used: Get-PrintJob, Remove-PrintJob (PrintManagement
        module) - see Version 2.25 changelog.
    #>
    Write-Host "Clearing print queue..."

    # Get-PrintJob/Remove-PrintJob (PrintManagement module) is the official,
    # graceful way to clear queued jobs and is tried first - but a stuck or
    # corrupted job can be unremovable through the API while the spooler
    # still has the .SHD/.SPL files locked, which is exactly the case the
    # stop-spooler-and-delete-files fallback below still exists to catch.
    Get-Printer -ErrorAction SilentlyContinue |
        Get-PrintJob -ErrorAction SilentlyContinue |
        Remove-PrintJob -ErrorAction SilentlyContinue

    $spoolerWasRunning = (Get-Service spooler -ErrorAction SilentlyContinue).Status -eq 'Running'
    Stop-Service -Name spooler -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:SystemRoot\System32\spool\PRINTERS\*" -Recurse -Force -ErrorAction SilentlyContinue
    if ($spoolerWasRunning) { Start-Service -Name spooler -ErrorAction SilentlyContinue }
    Write-Host -ForegroundColor Yellow "Print Queue Removal - COMPLETE`r`n"
}

Function Clear-WindowsHistory {
    <#
    .SYNOPSIS
        Clears Windows Explorer/shell usage history for all users and the system.
    .DESCRIPTION
        For every local user hive: clears RunMRU (Run dialog history), TypedPaths
        (File Explorer address bar history), WordWheelQuery (Start menu/taskbar
        search history), and RecentDocs (recently opened files, by type). Also
        clears the system-wide Prefetch folder (program execution history; Windows
        rebuilds it automatically), each user's Explorer thumbnail cache database
        (image browsing history, not covered by CleanMgr), and each user's
        PSReadLine console history file (can contain credentials typed into a
        PowerShell terminal).
    #>
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
    <#
    .SYNOPSIS
        Clears every non-empty Windows Event Log, classic and modern channels alike.
    .DESCRIPTION
        Enumerates every log via Get-WinEvent -ListLog * (this reaches both classic
        logs like Application/System/Security and modern "Applications and
        Services Logs" channels), skips any with zero events, and clears each
        remaining one via EventLogSession.ClearLog - the .NET equivalent of
        Microsoft's own `wevtutil cl <log>` command. Honors the script-level
        -PreserveSecurityLog switch by skipping just the Security log while still
        clearing everything else, for domain-joined machines where clearing it
        could trigger SIEM alerts or conflict with GPO audit-retention policy.
    .NOTES
        Deliberately does NOT use the built-in Clear-EventLog cmdlet:
        Clear-EventLog only reaches the small set of classic Win32 logs, not the
        many modern channels Get-WinEvent -ListLog * also finds and that this
        function means to clear too.
    #>
    Write-Host "Clearing Windows Event Logs (all logs with content)..."

    # Note: clearing the Security log on domain-joined machines may trigger SIEM alerts
    # or conflict with GPO audit-retention policies - coordinate with the security team,
    # or pass -PreserveSecurityLog to skip just that log.
    $cleared = 0
    $skipped = 0
    # RecordCount is checked inside this ForEach-Object rather than via a
    # preceding Where-Object filter - some log entries (certain disabled
    # Analytic/Debug channels) are known to throw a terminating error the
    # moment RecordCount is accessed, even with -ListLog's own
    # -ErrorAction SilentlyContinue. PowerShell aborts an entire pipeline on
    # one iteration's unhandled terminating exception (the same class of bug
    # already found and fixed in Invoke-ForEachUserHive), so an unguarded
    # Where-Object here could silently leave every log after the throwing one
    # in enumeration order uncleared. Guarding it per-item keeps that failure
    # scoped to just the one log.
    Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
        ForEach-Object {
            try { if ($_.RecordCount -le 0) { return } }
            catch { $skipped++; return }

            if ($PreserveSecurityLog -and $_.LogName -eq 'Security') {
                Write-Host "  Preserved: '$($_.LogName)' (per -PreserveSecurityLog)" -ForegroundColor DarkYellow
                $skipped++
                return
            }
            try {
                # EventLogSession.ClearLog is the .NET equivalent of
                # Microsoft's own `wevtutil cl <log>` command - used here
                # (via the Get-WinEvent enumeration above) instead of the
                # built-in Clear-EventLog cmdlet because Clear-EventLog only
                # reaches the small set of classic Win32 logs (Application/
                # System/Security/Setup), not the many modern "Applications
                # and Services Logs" channels (e.g. Microsoft-Windows-*) that
                # Get-WinEvent -ListLog * also finds and that this script
                # means to clear too.
                [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName)
                $cleared++
            }
            catch { $skipped++ }
        }
    Write-Host "  Cleared: $cleared log(s)   Skipped (protected/locked): $skipped" -ForegroundColor Cyan
    Write-Host -ForegroundColor Yellow "Event Log Clearing - COMPLETE`r`n"
}

Function Remove-TeamsProfile {
    <#
    .SYNOPSIS
        Removes both classic Teams (v1) and new Teams (v2) profile data, plus
        shared auth token cache and local meeting recordings, for all users.
    .DESCRIPTION
        Stops teams.exe, then for every user deletes classic Teams' Roaming and
        Local AppData folders, and the AAD Broker Plugin package (caches Azure AD
        auth tokens shared by Teams and other apps). Then stops ms-teams.exe and
        deletes new Teams (v2)'s package folder (Packages\MSTeams_*) for every
        user. Finally deletes locally saved Teams meeting recordings under each
        user's Videos folder, which can be large and contain sensitive operational
        content.
    .NOTES
        No official Microsoft reset command exists for Teams; manual folder
        deletion here matches Microsoft's own documented Teams troubleshooting
        guidance.
    #>
    # Classic Teams (v1) - stop process, then clear data for ALL users on the machine
    Stop-ProcessAndWait -Name 'teams'

    Get-Item "$UsersBase\*\AppData\Roaming\Microsoft\Teams" -ErrorAction SilentlyContinue |
        ForEach-Object {
            Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Classic Teams removed for: $(Get-ProfileNameFromPath $_.FullName)" -ForegroundColor Cyan
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
            Write-Host "New Teams (v2) removed for: $(Get-ProfileNameFromPath $_.FullName)" -ForegroundColor Cyan
        }

    # Meeting recordings saved locally - can be large and contain sensitive
    # operational content. Resolved per-user via Resolve-UserShellFolder rather
    # than assumed at the classic "<profile>\Videos" path - classic GPO Folder
    # Redirection can relocate Videos independently of OneDrive KFM (same gap
    # already fixed for Desktop/Documents/Pictures/Downloads/Videos/Music in
    # Remove-UserPersonalFiles; this step had never been migrated to match).
    Invoke-ForEachUserHive {
        param([string]$Sid, [string]$ProfilePath)
        $videos = Resolve-UserShellFolder -Sid $Sid -ProfilePath $ProfilePath -RegValueName 'My Video' -ClassicName 'Videos'
        Remove-Item (Join-Path $videos 'Microsoft Teams\*') -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host -ForegroundColor Yellow "Teams Profile Removal - COMPLETE`r`n"
}

Function Remove-OutlookProfile {
    <#
    .SYNOPSIS
        Removes classic Outlook profile registry data/OST/NK2 cache, New Outlook's
        package data, and PST files (optionally backing PSTs up first) for all
        users.
    .DESCRIPTION
        Stops outlook.exe, then for every user clears the Outlook profile registry
        key (Windows Messaging Subsystem\Profiles) and deletes OST/OST.OLD/NK2
        files under AppData\Local\Microsoft\Outlook (these can be gigabytes of
        cached email/calendar/contacts). Also stops olk.exe and deletes the
        package folder for New Outlook for Windows (Microsoft.OutlookForWindows) -
        a separate UWP app with its own independent cached mail/calendar/contacts
        store, entirely unaffected by clearing classic Outlook's data. Also
        searches every user's REAL Documents/Desktop/Downloads location
        (resolved via Resolve-UserShellFolder, honoring both OneDrive Known
        Folder Move and classic GPO Folder Redirection) for *.pst files, since
        these can be intentionally-archived mailboxes moved outside the default
        Outlook data file location rather than mere cache. When the script-level
        -BackupPst switch is set, each found PST is copied to $PstBackupPath first
        (named "<user>-<filename>.pst") and only PSTs that were actually backed up
        successfully are then deleted - a failed backup never results in deleting
        the only copy of a file.
    .NOTES
        No official Microsoft cmdlet exists for Outlook profile management in
        stock Windows; the registry key and file locations here are Microsoft's
        own documented data locations. New Outlook's executable name (olk.exe) and
        package folder were confirmed by reading its AppxManifest.xml directly
        rather than assumed - see Version 2.29 changelog. The Documents/Desktop
        KFM-redirection handling was added after confirming a PST search assuming
        the classic path would miss a PST filed under a KFM-redirected Documents
        folder - see Version 2.30 changelog.
    #>
    Stop-ProcessAndWait -Name 'outlook'

    # Registry profile key - clear for every user hive, not just the running user.
    # Also resolves each user's REAL Documents/Desktop location (for the PST
    # search below) while their hive is mounted - OneDrive Known Folder Move
    # redirects both (along with Pictures) out of the profile root, and a PST a
    # user deliberately archived into a KFM-redirected Documents folder would
    # otherwise never be found by a path search that assumes "<profile>\Documents".
    # $pstPathOwners maps each resolved search root to the username it belongs
    # to, recorded at resolution time - used below instead of
    # Get-ProfileNameFromPath, which assumes a found file's path starts with
    # $UsersBase. That assumption breaks for classic GPO Folder Redirection
    # (a real possibility here, same as everywhere else this script resolves
    # shell folders), which can point Documents/Desktop/Downloads at a UNC
    # share or another drive entirely outside $UsersBase - Get-ProfileNameFromPath
    # would then return the whole path unchanged, producing an unusable
    # (and Copy-Item-breaking) backup filename and silently leaving that PST
    # un-backed-up and un-deleted. Knowing the search root -> username mapping
    # up front sidesteps needing to infer it from the file's path at all.
    $pstSearchPaths = New-Object System.Collections.Generic.List[string]
    $pstPathOwners  = @{}
    Invoke-ForEachUserHive {
        param([string]$Sid, [string]$ProfilePath)
        Remove-Item "Registry::HKU\$Sid\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles" `
            -Force -Recurse -ErrorAction SilentlyContinue
        $userName = Split-Path $ProfilePath -Leaf
        Write-Host "  Outlook profile registry cleared for: $userName"

        $documents = Resolve-UserShellFolder -Sid $Sid -ProfilePath $ProfilePath -RegValueName 'Personal' -ClassicName 'Documents'
        $desktop   = Resolve-UserShellFolder -Sid $Sid -ProfilePath $ProfilePath -RegValueName 'Desktop'  -ClassicName 'Desktop'
        # Downloads isn't OneDrive KFM-eligible, but classic GPO Folder Redirection
        # can still redirect it independently - resolve it the same way rather than
        # assuming it's always classic.
        $downloads = Resolve-UserShellFolder -Sid $Sid -ProfilePath $ProfilePath -RegValueName '{374DE290-123F-4565-9164-39C4925E467B}' -ClassicName 'Downloads'

        foreach ($p in @($documents, $desktop, $downloads)) {
            $pstSearchPaths.Add($p)
            $pstPathOwners[$p] = $userName
        }
    }

    # OST files can be gigabytes of cached email/calendar/contacts - remove across all users
    Remove-Item "$UsersBase\*\AppData\Local\Microsoft\Outlook\*.ost"     -Force -ErrorAction SilentlyContinue
    Remove-Item "$UsersBase\*\AppData\Local\Microsoft\Outlook\*.ost.old" -Force -ErrorAction SilentlyContinue
    Remove-Item "$UsersBase\*\AppData\Local\Microsoft\Outlook\*.nk2"     -Force -ErrorAction SilentlyContinue

    # New Outlook for Windows - a separate UWP app (Microsoft.OutlookForWindows)
    # with its own independent LocalCache/LocalState mail/calendar/contacts store.
    # Confirmed installed and process name confirmed as olk.exe via AppxManifest.xml
    # during this script's own development - clearing classic Outlook above does
    # NOT touch this app's data at all.
    Stop-ProcessAndWait -Name 'olk'
    Get-Item "$UsersBase\*\AppData\Local\Packages\Microsoft.OutlookForWindows_*" -ErrorAction SilentlyContinue |
        ForEach-Object {
            Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "  New Outlook data removed for: $(Get-ProfileNameFromPath $_.FullName)"
        }

    # PST files - search each user's REAL Documents/Desktop (resolved above,
    # honoring OneDrive Known Folder Move) plus the always-classic Downloads.
    # These can be intentionally-archived mailboxes a user moved out of the
    # default Outlook data file location, not just cache - so back them up
    # first when -BackupPst is passed instead of deleting outright.
    $pstFiles = Get-ChildItem $pstSearchPaths -Filter '*.pst' -Recurse -Force -ErrorAction SilentlyContinue

    $pstFilesToDelete = $pstFiles
    if ($BackupPst -and $pstFiles) {
        if (-not (Test-Path $PstBackupPath)) { New-Item -Path $PstBackupPath -ItemType Directory -Force | Out-Null }
        $failedBackups = New-Object System.Collections.Generic.List[string]
        foreach ($pst in $pstFiles) {
            # Find which resolved search root this PST was found under, and use
            # its recorded owner - not Get-ProfileNameFromPath, which assumes
            # the path starts with $UsersBase and silently fails that assumption
            # for a GPO Folder Redirection target outside it (see comment above
            # $pstPathOwners). Falls back to Get-ProfileNameFromPath only if no
            # recorded root matches, which shouldn't happen since $pstFiles was
            # itself found by searching exactly these roots.
            $ownerRoot = $pstPathOwners.Keys | Where-Object { $pst.FullName.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
            $userName = if ($ownerRoot) { $pstPathOwners[$ownerRoot] } else { Get-ProfileNameFromPath $pst.FullName }
            $destName = "$userName-$($pst.Name)"
            $destPath = Join-Path $PstBackupPath $destName
            # $destName has no folder component, so the same user having two
            # same-named PSTs in different searched folders (e.g. one on the
            # Desktop, one in Documents) would otherwise collide here and
            # Copy-Item -Force would silently overwrite the first backup with
            # the second - confirmed by reproducing this exact collision.
            # Disambiguate with a numeric suffix instead of trusting the name
            # to be unique.
            if (Test-Path $destPath) {
                $baseName = [System.IO.Path]::GetFileNameWithoutExtension($destName)
                $extension = [System.IO.Path]::GetExtension($destName)
                $suffix = 2
                do {
                    $destPath = Join-Path $PstBackupPath "$baseName`_$suffix$extension"
                    $suffix++
                } while (Test-Path $destPath)
            }
            try {
                Copy-Item -Path $pst.FullName -Destination $destPath -Force -ErrorAction Stop
                Write-Host "  Backed up: $($pst.FullName) -> $destPath"
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
    <#
    .SYNOPSIS
        Clears Jump List/Recent Items history and unpins every Quick Access folder,
        for all users.
    .DESCRIPTION
        For every user, deletes Recent Items shortcuts and Jump List data
        (AutomaticDestinations and CustomDestinations, excluding the taskbar's own
        pinned-items file f01b4d95cf55d32a.automaticDestinations-ms). Then, via a
        Shell.Application COM object, unpins every folder pinned to Quick Access by
        invoking the shell's 'unpinfromhome' verb in a loop (re-enumerating after
        each removal since the COM collection goes stale, with a 300ms settle
        delay to avoid re-seeing a just-removed item, capped at 50 iterations). The
        outer Shell.Application COM object, the per-iteration Namespace folder
        object and its Items() collection, and each enumerated FolderItem are all
        released via Marshal.ReleaseComObject to avoid leaking RCWs across the
        up-to-50 loop iterations this can run.
    .NOTES
        Uses the shell's canonical verb ID ('unpinfromhome') rather than matching
        the display text "Remove from Quick access" - matching display text only
        works on English Windows and silently no-ops on any other display
        language. No PowerShell cmdlet exists for Quick Access management.
    #>
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
        $maxIterations = 50
        $iteration = 0
        $found = $true
        while ($found -and $iteration -lt $maxIterations) {
            $iteration++
            $found = $false
            $ns = $shell.Namespace("shell:::{679f85cb-0220-4080-b29b-5540cc05aab6}")
            try {
                $folderItems = $ns.Items()
                foreach ($item in $folderItems) {
                    if (-not $item.IsFolder) {
                        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($item) | Out-Null
                        continue
                    }
                    # 'unpinfromhome' is the shell's canonical, locale-independent
                    # verb for this action - matching the display text "Remove
                    # from Quick access" only works on English Windows and
                    # silently no-ops (nothing ever gets unpinned, no error) on
                    # any other display language.
                    try {
                        $item.InvokeVerb('unpinfromhome')
                        Start-Sleep -Milliseconds 300
                        $found = $true
                        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($item) | Out-Null
                        break
                    } catch {
                        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($item) | Out-Null
                        continue
                    }
                }
            }
            finally {
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($folderItems) | Out-Null
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ns) | Out-Null
            }
        }
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
    }

    Write-Host -ForegroundColor Yellow "Pinned Items Removal - COMPLETE`r`n"
}

Function Clear-WifiProfiles {
    <#
    .SYNOPSIS
        Deletes every saved Wi-Fi network profile (SSID + password), machine-wide.
    .DESCRIPTION
        Runs `netsh wlan delete profile name=*` if the WLAN AutoConfig service is
        present, so a laptop that moves to a different site doesn't retain saved
        networks from wherever it was used before. Wi-Fi profiles are stored
        machine-wide by WLAN AutoConfig, not per-user.
    .NOTES
        netsh wlan is the only supported way to manage Wi-Fi profiles from the
        command line/PowerShell on Windows PowerShell 5.1 - no built-in cmdlet
        exists.
    #>
    Write-Host "Clearing saved Wi-Fi network profiles..."
    # Wi-Fi profiles (SSID + password) are stored machine-wide by WLAN
    # AutoConfig, not per-user - a laptop that moves to a different site
    # shouldn't retain saved networks from wherever it was used before.
    if (-not (Get-Service WlanSvc -ErrorAction SilentlyContinue)) {
        Write-Host "  No WLAN AutoConfig service on this machine - skipping." -ForegroundColor Yellow
    }
    else {
        netsh wlan delete profile name=* | Out-Null
    }
    Write-Host -ForegroundColor Yellow "Wi-Fi Profile Removal - COMPLETE`r`n"
}

Function Clear-NetworkHistory {
    <#
    .SYNOPSIS
        Clears Windows' record of every network this machine has ever joined.
    .DESCRIPTION
        Deletes the NetworkList Profiles and Signatures (Managed/Unmanaged)
        registry keys - Windows' own record of every network (wired, wireless, or
        VPN) this machine has ever joined, including friendly name, category
        (Public/Private/Domain), and last-connected time. Distinct from
        Clear-WifiProfiles: this history survives even after the Wi-Fi
        profile/password itself is deleted.
    #>
    Write-Host "Clearing Windows network location history..."
    # Distinct from Clear-WifiProfiles above: this is Windows' own record of
    # every network (wired, wireless, or VPN) this machine has ever joined -
    # friendly name, category (Public/Private/Domain), last-connected time -
    # which survives even after the Wi-Fi profile/password itself is deleted.
    Remove-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*'            -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\*'   -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged\*' -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host -ForegroundColor Yellow "Network History Cleanup - COMPLETE`r`n"
}

Function Clear-ProxySettings {
    <#
    .SYNOPSIS
        Resets both the machine-wide WinHTTP proxy and each user's IE/WinINET
        proxy settings.
    .DESCRIPTION
        Runs `netsh winhttp reset proxy` (Microsoft's documented command, resets
        the WinHTTP proxy to DIRECT) for the machine-wide setting, then for every
        user disables ProxyEnable and clears ProxyServer/AutoConfigURL under
        Internet Settings. A proxy left over from one site can silently break
        connectivity at the next site this laptop is used at.
    .NOTES
        Official command used: netsh winhttp reset proxy. No cmdlet equivalent
        exists; the per-user Internet Settings registry edit is the standard,
        Microsoft-documented method for IE/WinINET proxy configuration.
    #>
    Write-Host "Resetting proxy configuration (all users)..."
    # A proxy left over from one site can silently break connectivity at the
    # next one this laptop is used at - reset both the machine-wide WinHTTP
    # proxy and each user's own IE/WinINET proxy settings.
    netsh winhttp reset proxy | Out-Null

    Invoke-ForEachUserHive {
        param([string]$Sid, [string]$ProfilePath)
        $settingsKey = "Registry::HKU\$Sid\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        Set-ItemProperty -Path $settingsKey -Name ProxyEnable -Value 0 -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $settingsKey -Name ProxyServer -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $settingsKey -Name AutoConfigURL -ErrorAction SilentlyContinue
        Write-Host "  Proxy settings reset for: $(Split-Path $ProfilePath -Leaf)"
    }

    Write-Host -ForegroundColor Yellow "Proxy Settings Reset - COMPLETE`r`n"
}

Function Clear-DeviceHistory {
    <#
    .SYNOPSIS
        Clears USB device history and Bluetooth paired-device records, machine-wide.
    .DESCRIPTION
        Deletes the USBSTOR enumeration key (Windows recreates entries
        automatically the next time a device is plugged in) and the BTHPORT
        paired-device list plus stored pairing keys, so the next user doesn't
        inherit a stranger's paired Bluetooth devices. Both are machine-wide, not
        per-user.
    .NOTES
        Get-PnpDevice/Remove-PnpDevice was considered as an official-cmdlet
        alternative for the Bluetooth portion and deliberately NOT used: it only
        operates on currently-present PnP device instances, and a laptop reissue is
        exactly the scenario where a previously-paired phone/headset won't be
        present to enumerate - it wouldn't reliably reach what needs clearing here.
        See Version 2.25 changelog.
    #>
    Write-Host "Clearing USB and Bluetooth device history..."

    # USB device history (USBSTOR) - machine-wide, not per-user. Windows
    # recreates entries automatically the next time a device is plugged in.
    Remove-Item 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*' -Recurse -Force -ErrorAction SilentlyContinue

    # Bluetooth paired-device list and stored pairing keys - so the next user
    # doesn't inherit a stranger's paired devices.
    Remove-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices\*' -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Keys\*'    -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Yellow "Device History Cleanup - COMPLETE`r`n"
}

Function Invoke-RecycleBinCleanup {
    <#
    .SYNOPSIS
        Empties the Recycle Bin on every drive, all users' subfolders included.
    .DESCRIPTION
        Uses the official Clear-RecycleBin cmdlet (module-qualified as
        Microsoft.PowerShell.Management\Clear-RecycleBin so it can't accidentally
        resolve back to this function, since a same-named custom function would
        otherwise shadow the real cmdlet and recurse into itself) against every
        filesystem drive. When run elevated, this empties the whole volume's
        Recycle Bin including every user's $Recycle.Bin\<SID> subfolder. Falls back
        to deleting $Recycle.Bin contents directly if the cmdlet isn't present
        (e.g. an unusually stripped-down PowerShell install). Runs as
        belt-and-suspenders alongside CleanMgr's own "Recycle Bin" cleanup
        category (Invoke-CleanMgrAutomation), which occasionally misses a user's
        subfolder.
    .NOTES
        Official cmdlet used: Clear-RecycleBin (Microsoft.PowerShell.Management) -
        confirmed present in Windows PowerShell 5.1. This function was renamed from
        Clear-RecycleBin to Invoke-RecycleBinCleanup specifically to avoid the
        name collision described above.
    #>
    Write-Host "Clearing Recycle Bin (all drives)..."
    # Belt-and-suspenders alongside CleanMgr's "Recycle Bin" category below,
    # which occasionally misses a user's $Recycle.Bin\<SID> subfolder.
    #
    # Uses the official Clear-RecycleBin cmdlet (module-qualified so it
    # can't accidentally resolve back to this function, since they'd
    # otherwise share the same name) rather than deleting $Recycle.Bin
    # folder contents directly - when run elevated it empties the whole
    # volume's Recycle Bin, all users' subfolders included, the same
    # effective scope as the manual approach it replaces, just through the
    # supported API. Falls back to the manual approach if the cmdlet isn't
    # present for some reason (e.g. an unusually stripped-down PowerShell
    # install).
    if (Get-Command Microsoft.PowerShell.Management\Clear-RecycleBin -ErrorAction SilentlyContinue) {
        Get-TargetFileSystemDrives | ForEach-Object {
            Microsoft.PowerShell.Management\Clear-RecycleBin -DriveLetter $_.Name -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        Get-TargetFileSystemDrives | ForEach-Object {
            Remove-Item "$($_.Root)`$Recycle.Bin\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host -ForegroundColor Yellow "Recycle Bin Cleanup - COMPLETE`r`n"
}

Function Clear-VpnConnections {
    <#
    .SYNOPSIS
        Removes every all-user (machine-wide) built-in Windows VPN connection.
    .DESCRIPTION
        Enumerates and removes every VPN connection in the -AllUserConnection
        scope via the official VpnClient module cmdlets.
    .NOTES
        Official cmdlets used: Get-VpnConnection, Remove-VpnConnection
        (-AllUserConnection). Platform limitation, not a script gap: per-user VPN
        connections can't be enumerated or removed for another account without
        running as that user - the same limitation documented in
        Clear-NetworkCredentials.
    #>
    Write-Host "Clearing all-user VPN connections..."
    # Only covers -AllUserConnection scope (built-in Windows VPN profiles
    # shared machine-wide). Per-user VPN connections can't be enumerated or
    # removed for another account without running as that user - the same
    # Windows platform limitation documented in Clear-NetworkCredentials.
    Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-VpnConnection -Name $_.Name -AllUserConnection -Force -ErrorAction SilentlyContinue
        Write-Host "  Removed VPN connection: $($_.Name)"
    }
    Write-Host -ForegroundColor Yellow "VPN Connection Removal - COMPLETE`r`n"
}

Function Clear-AutologonCredentials {
    <#
    .SYNOPSIS
        Removes a plaintext autologon credential from the Winlogon registry key,
        if one is configured.
    .DESCRIPTION
        Checks HKLM Winlogon for a DefaultPassword value - if autologon was ever
        configured on this machine, that password is stored in PLAINTEXT in the
        registry. If present, removes DefaultPassword/DefaultUserName/
        DefaultDomainName and sets AutoAdminLogon back to '0', rather than leaving
        a live plaintext credential behind for whoever gets this laptop next.
        No-ops with a status message if no autologon credential is found.
    .NOTES
        No built-in PowerShell cmdlet exists for this; direct registry editing is
        the only way to manage autologon configuration outside of interactive
        tools like netplwiz.
    #>
    Write-Host "Checking for autologon credentials..."
    $winlogonKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $current = Get-ItemProperty -Path $winlogonKey -ErrorAction SilentlyContinue

    if ($current.DefaultPassword) {
        # DefaultPassword is stored in PLAINTEXT if autologon was ever
        # configured on this machine - remove it along with the autologon
        # flag itself rather than leaving a live credential behind for
        # whoever gets this laptop next.
        Write-Host "  Autologon was configured - clearing stored plaintext credential." -ForegroundColor Yellow
        Remove-ItemProperty -Path $winlogonKey -Name 'DefaultPassword'   -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $winlogonKey -Name 'DefaultUserName'   -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $winlogonKey -Name 'DefaultDomainName' -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $winlogonKey -Name 'AutoAdminLogon' -Value '0' -ErrorAction SilentlyContinue
    }
    else {
        Write-Host "  No autologon credential found." -ForegroundColor Yellow
    }

    Write-Host -ForegroundColor Yellow "Autologon Credential Cleanup - COMPLETE`r`n"
}

Function Remove-NetworkPrinters {
    <#
    .SYNOPSIS
        Removes network/remote printer connections, excluding built-in virtual
        printers.
    .DESCRIPTION
        Enumerates printers via Get-Printer, filters to Type -eq 'Connection'
        (network/remote printers, as opposed to locally attached ones) and
        excludes a known list of virtual printer names (Microsoft Print to PDF,
        Microsoft XPS Document Writer, Fax, and the various OneNote printer
        entries) so those built-ins aren't stripped, then removes each remaining
        printer via Remove-Printer.
    .NOTES
        Official cmdlets used: Get-Printer, Remove-Printer (PrintManagement
        module). Scope limitation, not a script gap: only removes connections
        visible to this elevated session (machine-wide or this account's own) - a
        standard user's own per-user printer connection added without admin rights
        isn't visible here, the same limitation documented in
        Clear-NetworkCredentials.
    #>
    Write-Host "Removing network/remote printer connections..."
    # Only removes connections visible to this elevated session (machine-wide
    # or this account's own) - a standard user's own per-user printer
    # connection added without admin rights isn't visible here, the same
    # limitation as Clear-NetworkCredentials. Virtual printers are excluded
    # by name so this doesn't strip built-in "Print to PDF"/Fax/OneNote.
    $virtualPrinters = 'Microsoft Print to PDF', 'Microsoft XPS Document Writer', 'Fax', 'OneNote (Desktop)', 'OneNote for Windows 10', 'Send To OneNote 2016'

    Get-Printer -ErrorAction SilentlyContinue |
        Where-Object { $_.Type -eq 'Connection' -and $_.Name -notin $virtualPrinters } |
        ForEach-Object {
            Remove-Printer -Name $_.Name -ErrorAction SilentlyContinue
            Write-Host "  Removed printer: $($_.Name)"
        }

    Write-Host -ForegroundColor Yellow "Network Printer Removal - COMPLETE`r`n"
}

Function Remove-NonMicrosoftScheduledTasks {
    <#
    .SYNOPSIS
        Removes scheduled tasks not registered under the \Microsoft\ task-path
        namespace.
    .DESCRIPTION
        Enumerates all scheduled tasks via Get-ScheduledTask, filters out anything
        whose TaskPath starts with \Microsoft\ (covers the OS's own tasks and the
        common case of management-tool tasks registered under a vendor subfolder
        there), and unregisters everything remaining.
    .NOTES
        Official cmdlets used: Get-ScheduledTask, Unregister-ScheduledTask
        (ScheduledTasks module). Best-effort, not a guarantee: if your own
        management stack registers tasks OUTSIDE \Microsoft\ (some do), review
        this step's log output before relying on it blindly - the target here is
        leftovers from whatever the previous user personally installed, not a
        vetted allowlist of every legitimate task publisher.
    #>
    Write-Host "Removing non-Microsoft scheduled tasks..."
    # Excludes anything nested under \Microsoft\ - that covers the OS's own
    # tasks and the common case of management-tool tasks registered under a
    # vendor subfolder there. This is still best-effort, not a guarantee: if
    # your own management stack registers tasks OUTSIDE \Microsoft\ (some
    # do), review this step's log output before relying on it blindly - the
    # target here is leftovers from whatever the previous user personally
    # installed, not a vetted allowlist of every legitimate task publisher.
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' } |
        ForEach-Object {
            Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "  Removed scheduled task: $($_.TaskPath)$($_.TaskName)"
        }
    Write-Host -ForegroundColor Yellow "Scheduled Task Cleanup - COMPLETE`r`n"
}

Function Clear-SearchIndex {
    <#
    .SYNOPSIS
        Deletes the Windows Search index database so it rebuilds from scratch.
    .DESCRIPTION
        Stops the WSearch service (no-ops with a status message if the service
        isn't present at all), deletes Windows.edb and the GatherLogs folder under
        the Search index data path, then restarts WSearch only if it was already
        running. The index can retain indexed metadata/content excerpts of files
        that get deleted elsewhere in this script, so deleting it removes that
        residue; it rebuilds automatically in the background once the service
        restarts.
    .NOTES
        No PowerShell cmdlet exists for a targeted index reset; stopping the
        service and deleting Windows.edb is the method Microsoft's own
        troubleshooting guidance for a corrupted search index uses.
    #>
    Write-Host "Resetting Windows Search index..."
    $svc = Get-Service WSearch -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Host "  Windows Search service not present - skipping." -ForegroundColor Yellow
        return
    }

    # The index (Windows.edb) can retain indexed metadata/content excerpts of
    # files that get deleted elsewhere in this script - deleting it removes
    # that residue. It rebuilds automatically once the service restarts, so
    # this doesn't need to wait for that to finish.
    $wasRunning = $svc.Status -eq 'Running'
    Stop-Service WSearch -Force -ErrorAction SilentlyContinue

    $indexPath = "$env:ProgramData\Microsoft\Search\Data\Applications\Windows"
    Remove-Item "$indexPath\Windows.edb" -Force -ErrorAction SilentlyContinue
    Remove-Item "$indexPath\GatherLogs" -Recurse -Force -ErrorAction SilentlyContinue

    if ($wasRunning) { Start-Service WSearch -ErrorAction SilentlyContinue }
    Write-Host -ForegroundColor Yellow "Search Index Reset - COMPLETE (rebuilds automatically in the background)`r`n"
}

Function Clear-DiagnosticArtifacts {
    <#
    .SYNOPSIS
        Clears per-user crash dumps, Activity Timeline history, Sticky Notes,
        notification history, and typing/handwriting personalization for all users.
    .DESCRIPTION
        For every user, deletes: raw crash dump files under CrashDumps (apps write
        these directly via WerFault/LocalDumps and can contain in-memory
        secrets/credentials - separate from, and not covered by, the WER
        queue/archive Clear-WER handles); the Windows Timeline/Activity History
        database (per-app usage history and content excerpts); Sticky Notes
        content; the Action Center notification history database (retains text
        previews - email subjects, chat snippets - not just the fact a
        notification fired); and the typing/handwriting personalization
        dictionary Windows builds per-user from everything typed, across any
        app/field.
    #>
    Write-Host "Clearing per-user crash dumps, activity history, Sticky Notes, notification history, and input personalization (all users)..."

    # Full crash dumps can contain in-memory secrets/credentials from
    # whatever process crashed - separate from, and not covered by, Clear-WER
    # above (that's Windows Error Reporting's own queue/archive; this is the
    # raw dump files apps write directly via WerFault/LocalDumps).
    Remove-Item "$UsersBase\*\AppData\Local\CrashDumps\*" -Recurse -Force -ErrorAction SilentlyContinue

    # Windows Timeline / Activity History - per-app usage history and content excerpts
    Remove-Item "$UsersBase\*\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db*" -Force -ErrorAction SilentlyContinue

    # Sticky Notes content
    Remove-Item "$UsersBase\*\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_*\LocalState\*" -Recurse -Force -ErrorAction SilentlyContinue

    # Action Center notification history - retains text previews (email
    # subjects, chat message snippets, etc.), not just the fact a notification fired.
    Remove-Item "$UsersBase\*\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db*" -Force -ErrorAction SilentlyContinue

    # Typing/handwriting personalization - Windows builds this per-user
    # dictionary from what's actually typed over time, across any app/field,
    # not just documents.
    Remove-Item "$UsersBase\*\AppData\Roaming\Microsoft\InputPersonalization\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$UsersBase\*\AppData\Local\Microsoft\InputPersonalization\*"   -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Yellow "Diagnostic Artifact Cleanup - COMPLETE`r`n"
}

Function Clear-OfficeHistory {
    <#
    .SYNOPSIS
        Clears Office's recent-file MRU lists (File/Place/User MRU) for all users.
    .DESCRIPTION
        For every user, recursively walks the whole Software\Microsoft\Office
        registry key (rather than hardcoding version numbers, which drift release
        to release) and removes any File MRU/Place MRU/User MRU sub-key found,
        across every installed Office version and app. This only clears the
        recent-file list, not the app sign-in itself - see Clear-OfficeSignIn for
        that.
    #>
    Write-Host "Clearing Office recent-file history (all users)..."

    Invoke-ForEachUserHive {
        param([string]$Sid, [string]$ProfilePath)
        $officeKey = "Registry::HKU\$Sid\Software\Microsoft\Office"
        if (-not (Test-Path $officeKey)) { return }

        # File MRU / Place MRU / User MRU live under
        # HKU\<Sid>\Software\Microsoft\Office\<version>\<App>\... across every
        # Office version and app - walk the whole Office key rather than
        # hardcoding version numbers, which drift release to release.
        Get-ChildItem $officeKey -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match '^(File MRU|Place MRU|User MRU)$' } |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

        Write-Host "  Office recent-file history cleared for: $(Split-Path $ProfilePath -Leaf)"
    }

    Write-Host -ForegroundColor Yellow "Office History Removal - COMPLETE`r`n"
}

Function Clear-OfficeSignIn {
    <#
    .SYNOPSIS
        Signs every user out of Office apps by clearing cached identity/sign-in
        tokens.
    .DESCRIPTION
        For every user, clears the Office 16.0 Identity and Roaming\Identities
        registry keys, and the shared IdentityCRL registry key (a modern-auth
        token cache used jointly by Office/OneDrive/Teams). Also clears the
        OfficeFileCache, IdentityCache, and OneAuth folders under each user's
        AppData\Local. Distinct from Clear-OfficeHistory, which only clears the
        recent-file MRU list, not the sign-in - after this runs,
        Word/Excel/PowerPoint/Outlook/etc. prompt for sign-in again on next
        launch.
    #>
    Write-Host "Signing out of Office apps (clearing cached identity/sign-in tokens, all users)..."
    # Distinct from Clear-OfficeHistory above (which only clears the
    # recent-file MRU list, not the sign-in itself) - this clears the
    # identity/token cache so Word/Excel/PowerPoint/Outlook/etc. prompt for
    # sign-in again on next launch instead of reopening already signed in.

    Invoke-ForEachUserHive {
        param([string]$Sid, [string]$ProfilePath)
        Remove-Item "Registry::HKU\$Sid\Software\Microsoft\Office\16.0\Common\Identity\*"           -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "Registry::HKU\$Sid\Software\Microsoft\Office\16.0\Common\Roaming\Identities\*" -Recurse -Force -ErrorAction SilentlyContinue
        # Shared modern-auth token cache used jointly by Office/OneDrive/Teams
        Remove-Item "Registry::HKU\$Sid\Software\Microsoft\IdentityCRL\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  Office sign-in cleared for: $(Split-Path $ProfilePath -Leaf)"
    }

    Remove-Item "$UsersBase\*\AppData\Local\Microsoft\Office\16.0\OfficeFileCache\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$UsersBase\*\AppData\Local\Microsoft\IdentityCache\*"               -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$UsersBase\*\AppData\Local\Microsoft\OneAuth\*"                     -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Yellow "Office Sign-Out - COMPLETE`r`n"
}

Function Clear-AdobeHistory {
    <#
    .SYNOPSIS
        Clears Adobe/Bluebeam recent-file history and app cache for all users.
    .DESCRIPTION
        For every user, recursively walks the whole Software\Adobe registry key
        (same approach as Clear-OfficeHistory, to avoid hardcoding version
        numbers across Acrobat/Reader releases) and removes any
        RecentFiles/RecentFolder sub-key found. Also clears the app-level cache
        folders under AppData\Local\Adobe and Bluebeam's recent-file data under
        AppData\Roaming.
    #>
    Write-Host "Clearing Adobe/Bluebeam recent-file history and cache (all users)..."

    Invoke-ForEachUserHive {
        param([string]$Sid, [string]$ProfilePath)
        $adobeKey = "Registry::HKU\$Sid\Software\Adobe"
        if (Test-Path $adobeKey) {
            # cRecentFiles/RecentFolder MRU keys live at varying depths across
            # Acrobat/Reader versions - walk the whole Adobe key rather than
            # hardcoding version numbers, same approach as Clear-OfficeHistory.
            Get-ChildItem $adobeKey -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -match 'RecentFiles|RecentFolder' } |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-Host "  Adobe history cleared for: $(Split-Path $ProfilePath -Leaf)"
    }

    # App-level cache/sign-in token data (not the registry MRU above)
    Remove-Item "$UsersBase\*\AppData\Local\Adobe\*\Cache*"                -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$UsersBase\*\AppData\Roaming\Bluebeam Software\*\Recent*" -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Yellow "Adobe/Bluebeam History Removal - COMPLETE`r`n"
}

Function Clear-SyncClientCaches {
    <#
    .SYNOPSIS
        Clears Box/Dropbox/Google Drive app cache and sign-in data for all users,
        without touching synced content.
    .DESCRIPTION
        For every user, deletes the app cache/config folders for Dropbox, Box, and
        Google Drive (DriveFS) under AppData. Deliberately does NOT touch the
        synced content folders themselves (e.g. $UsersBase\<user>\Dropbox), which
        live under the profile root - same principle as this script never
        touching a user's actual cloud-synced files anywhere, only app data/cache.
    #>
    Write-Host "Clearing Box/Dropbox/Google Drive app cache and sign-in data (all users)..."
    # App cache/config only - NOT the synced content folders themselves
    # (those live under the profile root, e.g. $UsersBase\<user>\Dropbox, and
    # are left alone here, same as this script never touching a user's
    # actual cloud-synced files, only app data/cache).
    Remove-Item "$UsersBase\*\AppData\Local\Dropbox\*"        -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$UsersBase\*\AppData\Local\Box\Box\*"        -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$UsersBase\*\AppData\Roaming\Box\Box\*"      -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$UsersBase\*\AppData\Local\Google\DriveFS\*" -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Yellow "Sync Client Cache Cleanup - COMPLETE`r`n"
}

Function Clear-UserCertificates {
    <#
    .SYNOPSIS
        Clears each user's personal ("My") certificate store, including private
        keys.
    .DESCRIPTION
        For every
        user, removes the SystemCertificates\My\Certificates registry key
        directly, plus the orphaned private-key files under each profile's
        Crypto\RSA and Crypto\Keys folders (the registry entries are just the
        store index; the actual key material lives in these separate files and
        would otherwise be left behind even after the certificate itself is
        gone). Only the Personal ("My") store is touched - Root/CA/trust stores
        are left alone since those are typically trusted-authority certs the
        system needs, not anything tied to the specific user.
    .NOTES
        Deliberately does NOT use the Cert:\CurrentUser\My provider path that an
        earlier version of this function ran "for the current session" (the same
        pattern used elsewhere in this script for OneDrive.exe /reset, Get-SmbMapping,
        etc.) - CurrentUser inside this elevated session is the TECHNICIAN's own
        profile (or whatever admin account is running the script), never the
        departing employee's, and unlike those other current-session conveniences
        this one was run with -DeleteKey. In a PIV/CAC-standard environment that
        meant every run of this step permanently deleted the operator's own Personal
        certificate store entries and any software-backed private keys - a real cost
        to the technician, not just an inconvenience, for zero benefit toward wiping
        the actual target profiles. The per-hive registry/file cleanup below is what
        actually reaches every real profile on the machine and was never affected by
        this.
    #>
    Write-Host "Clearing per-user certificate store (all users)..."

    Invoke-ForEachUserHive {
        param([string]$Sid, [string]$ProfilePath)
        Remove-Item "Registry::HKU\$Sid\Software\Microsoft\SystemCertificates\My\Certificates\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  Personal certificate store cleared for: $(Split-Path $ProfilePath -Leaf)"
    }

    # The registry entries above (and Cert:\CurrentUser\My) are just the
    # store index - the actual private key material lives in separate files
    # under each profile's Crypto folder, which would otherwise be left
    # behind as orphaned keys even after the certificate itself is gone.
    Remove-Item "$UsersBase\*\AppData\Roaming\Microsoft\Crypto\RSA\*"  -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$UsersBase\*\AppData\Roaming\Microsoft\Crypto\Keys\*" -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Yellow "Certificate Store Cleanup - COMPLETE`r`n"
}

Function Clear-DevCredentials {
    <#
    .SYNOPSIS
        Clears SSH private keys and Git configuration/credentials for all users.
    .DESCRIPTION
        For every user, deletes the .ssh folder (private keys and known_hosts -
        lives outside Desktop/Documents/etc, so the personal file wipe elsewhere
        in this script doesn't already catch it), the .gitconfig file (carries the
        previous user's name/email), and the Git Credential Manager cache (caches
        sign-in tokens for whatever remotes the previous user used).
    #>
    Write-Host "Clearing SSH keys and Git configuration/credentials (all users)..."

    # Private keys and known_hosts - lives outside Desktop/Documents/etc, so
    # the personal file wipe elsewhere in this script doesn't already catch it.
    Remove-Item "$UsersBase\*\.ssh\*" -Recurse -Force -ErrorAction SilentlyContinue

    # .gitconfig carries the previous user's name/email; Git Credential
    # Manager caches sign-in tokens for whatever remotes they used.
    Remove-Item "$UsersBase\*\.gitconfig" -Force -ErrorAction SilentlyContinue
    Remove-Item "$UsersBase\*\AppData\Local\GitCredentialManager\*" -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Yellow "Dev Credential Cleanup - COMPLETE`r`n"
}

Function Clear-MappedDrives {
    <#
    .SYNOPSIS
        Removes persisted (reconnect-at-logon) network drive mappings for all
        users.
    .DESCRIPTION
        Runs Get-SmbMapping | Remove-SmbMapping -Force -UpdateProfile first, for
        the current session - the official cmdlet pair for this, which also
        removes mappings made the old way via `net use` or New-PSDrive, and
        -UpdateProfile makes the removal persistent instead of just ending the
        live connection. Same current-session-only caveat as every other
        official-cmdlet swap in this script though: it only ever sees the session
        actually running this script. Then, for every user, removes the Network
        registry key directly (reconnect-at-logon mappings created via
        `net use X: \\server\share /persistent:yes` are stored per-user under
        HKU\<Sid>\Network) - leftover mappings can point at a previous
        site/server this laptop no longer has any business reaching.
    .NOTES
        Official cmdlets used: Get-SmbMapping, Remove-SmbMapping -UpdateProfile
        (current session only) - see Version 2.25 changelog.
    #>
    Write-Host "Clearing persisted network drive mappings (all users)..."
    # Reconnect-at-logon drive mappings ('net use X: \\server\share /persistent:yes')
    # are stored per-user under HKU\<Sid>\Network - leftover mappings can point
    # at a previous site/server this laptop no longer has any business reaching.

    # Get-SmbMapping/Remove-SmbMapping is the official cmdlet pair for this
    # (it also removes mappings made the old way, via 'net use' or
    # New-PSDrive) - -UpdateProfile is what makes the removal persistent
    # instead of just ending the live session's connection. Same
    # current-session-only caveat as every other "official cmdlet" swap in
    # this script though: it only ever sees the session actually running
    # this script, so the per-hive registry cleanup below is still what
    # covers every other profile.
    Get-SmbMapping -ErrorAction SilentlyContinue |
        Remove-SmbMapping -Force -UpdateProfile -ErrorAction SilentlyContinue

    Invoke-ForEachUserHive {
        param([string]$Sid, [string]$ProfilePath)
        Remove-Item "Registry::HKU\$Sid\Network\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  Mapped drive persistence cleared for: $(Split-Path $ProfilePath -Leaf)"
    }
    Write-Host -ForegroundColor Yellow "Mapped Drive Cleanup - COMPLETE`r`n"
}

Function Clear-MeetingAppCaches {
    <#
    .SYNOPSIS
        Clears Zoom and WebEx local app cache for all users.
    .DESCRIPTION
        Deletes each user's Zoom (AppData\Roaming) and WebEx (AppData\Local)
        cache folders.
    #>
    Write-Host "Clearing Zoom/WebEx local cache (all users)..."
    Remove-Item "$UsersBase\*\AppData\Roaming\Zoom\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$UsersBase\*\AppData\Local\WebEx\*"  -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host -ForegroundColor Yellow "Meeting App Cache Cleanup - COMPLETE`r`n"
}

Function Clear-MiscAppData {
    <#
    .SYNOPSIS
        Clears Phone Link, built-in Windows Mail/Calendar, OneNote local cache,
        consumer Skype, Widgets board, Snipping Tool history, and Game Bar screen
        recordings for all users.
    .DESCRIPTION
        For every user, clears: Phone Link ("Your Phone") package data, which
        caches messages, call history, and photos synced from whatever phone was
        paired to this laptop - someone else's phone data living on this machine,
        not just app cache, so this matters more than most of what this function
        clears; the built-in Windows Mail/Calendar app's package cache (entirely
        separate from desktop Outlook, already handled by Remove-OutlookProfile);
        OneNote's local notebook cache (separate from the Office recent-file MRU
        Clear-OfficeHistory clears - some content here may be un-synced); consumer
        Skype's Roaming data folder; the Widgets board's package cache (feed
        personalization tied to whatever Microsoft account was signed in);
        Snipping Tool/Screen Sketch's package cache (retains a recent-screenshot
        history separate from wherever an actual saved screenshot file ended up);
        and Xbox Game Bar screen recordings under each user's
        Videos\Captures folder (Win+G can record any window/desktop content -
        same sensitivity tier as the Teams meeting recordings Remove-TeamsProfile
        already clears).
    #>
    Write-Host "Clearing Phone Link, Windows Mail/Calendar, OneNote cache, Skype, Widgets, Snipping Tool, and Game Bar recordings (all users)..."

    # Phone Link ("Your Phone") caches messages, call history, and photos
    # synced from whatever phone was paired to this laptop - that's someone
    # else's phone data living on this machine, not just app cache, so this
    # one matters more than most of what this function clears.
    Remove-Item "$UsersBase\*\AppData\Local\Packages\Microsoft.YourPhone_*\LocalState\*" -Recurse -Force -ErrorAction SilentlyContinue

    # Built-in Windows Mail/Calendar app has its own cache, entirely separate
    # from desktop Outlook (already handled by Remove-OutlookProfile).
    Remove-Item "$UsersBase\*\AppData\Local\Packages\microsoft.windowscommunicationsapps_*\LocalState\*" -Recurse -Force -ErrorAction SilentlyContinue

    # OneNote's local notebook cache - separate from the Office recent-file
    # MRU already cleared by Clear-OfficeHistory; some content here may be
    # un-synced.
    Remove-Item "$UsersBase\*\AppData\Local\Microsoft\OneNote\*" -Recurse -Force -ErrorAction SilentlyContinue

    # Consumer Skype
    Remove-Item "$UsersBase\*\AppData\Roaming\Skype\*" -Recurse -Force -ErrorAction SilentlyContinue

    # Widgets board (MicrosoftWindows.Client.WebExperience) - personalized
    # news/weather feed cache tied to whichever Microsoft account was signed in.
    Remove-Item "$UsersBase\*\AppData\Local\Packages\MicrosoftWindows.Client.WebExperience_*\LocalState\*" -Recurse -Force -ErrorAction SilentlyContinue

    # Snipping Tool / Screen Sketch keeps its own recent-screenshot history in
    # package data, separate from wherever the user actually saved a screenshot.
    Remove-Item "$UsersBase\*\AppData\Local\Packages\Microsoft.ScreenSketch_*\LocalState\*" -Recurse -Force -ErrorAction SilentlyContinue

    # Xbox Game Bar (Win+G) screen/window recordings - can capture meeting or
    # work content, same sensitivity tier as Teams meeting recordings above.
    # Resolved per-user via Resolve-UserShellFolder rather than assumed at the
    # classic "<profile>\Videos" path - same GPO Folder Redirection gap already
    # fixed for Remove-TeamsProfile's meeting-recording cleanup.
    Invoke-ForEachUserHive {
        param([string]$Sid, [string]$ProfilePath)
        $videos = Resolve-UserShellFolder -Sid $Sid -ProfilePath $ProfilePath -RegValueName 'My Video' -ClassicName 'Videos'
        Remove-Item (Join-Path $videos 'Captures\*') -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host -ForegroundColor Yellow "Misc App Data Cleanup - COMPLETE`r`n"
}

Function Remove-UserPersonalFiles {
    <#
    .SYNOPSIS
        Deletes the actual contents of Desktop/Documents/Downloads/Pictures/
        Videos/Music for every user, preserving each user's current desktop
        background picture and any Desktop shortcuts (.lnk/.url).
    .DESCRIPTION
        Unlike every other function in this script, this deletes real user files,
        not cache/app data, and runs unconditionally (there is no opt-out switch).
        On the Desktop folder specifically, .lnk and .url files are skipped -
        shortcuts to installed applications/network locations are pointers, not
        personal data, and a previous version of this function was deleting them
        along with everything else, which broke application/network shortcuts on
        the Desktop for the next user (confirmed as the actual cause after a user
        report of "broken shortcuts" post-run). This exclusion is Desktop-only -
        Documents/Pictures/Downloads/Videos/Music are still wiped in full, since a
        stray .lnk in one of those isn't the taskbar/desktop launcher surface.
        For each user (while their hive is mounted via Invoke-ForEachUserHive),
        FIRST reads the current Wallpaper registry value, copies that file's
        content to a temporary stash location, and resolves the REAL current
        location of all six folders (Desktop, Documents, Pictures, Downloads,
        Videos, Music) via Resolve-UserShellFolder - honoring both OneDrive
        Known Folder Move and classic GPO Folder Redirection instead of assuming
        "<profile>\Desktop" etc. for any of them. ONLY AFTER that collection
        pass completes does it stop OneDrive.exe: if Desktop/Documents/Pictures
        are OneDrive Known Folder Move-redirected and OneDrive is still actively
        signed in and syncing when the files are actually deleted, that deletion
        would otherwise sync up to the user's actual cloud storage, not just
        remove them from this one laptop. Stopping OneDrive doesn't rely on the
        separate 'Remove OneDrive Accounts' task having also run, since the GUI
        checklist allows either one to be deselected independently. Finally,
        wipes all six resolved folders and restores the stashed wallpaper back
        to its original path - guaranteeing it survives regardless of how deep
        inside Pictures/Desktop/etc. it's nested, rather than trying to
        special-case the exclusion during the wipe itself. Skips the
        Public/Default/Default User/All Users pseudo-profiles.
    .NOTES
        The KFM-redirection handling was added after confirming on this
        machine's own profile that the classic Desktop and Pictures paths don't
        exist AT ALL (redirected into "OneDrive - DOI\..."), and the classic
        Documents folder exists as a near-empty leftover alongside the real,
        populated OneDrive-redirected one - meaning an earlier version of this
        function silently wiped nothing (or the wrong, stale folder) on any
        machine with KFM active, while the user's actual files at the redirected
        location were left completely untouched (Version 2.30). The wallpaper
        stash-BEFORE-stopping-OneDrive ordering was added after tracing through
        that a wallpaper sourced from a not-yet-downloaded OneDrive Files
        On-Demand placeholder would fail to copy once OneDrive.exe was already
        stopped, silently losing the preservation guarantee (Version 2.33).
    #>
    Write-Host "Wiping personal files (Desktop/Documents/Downloads/Pictures/Videos/Music) for all users..." -ForegroundColor Red
    Write-Host "  Each user's current desktop background picture is preserved, even if it lives in one of these folders." -ForegroundColor Yellow
    Write-Host "  Desktop shortcuts (.lnk/.url) are preserved; everything else on the Desktop is wiped." -ForegroundColor Yellow
    Write-Host "  Desktop/Documents/Pictures are resolved to their real current location, honoring OneDrive Known Folder Move." -ForegroundColor Yellow

    # Wallpaper (path AND a stashed copy of its actual content) and the real
    # (redirection-aware) folder locations can only be read while each user's
    # hive is mounted, so this happens up front, before the wipe below runs -
    # and, just as importantly, BEFORE OneDrive is stopped further down. If the
    # wallpaper's source file is a OneDrive Files On-Demand placeholder that
    # hasn't been downloaded locally yet, reading its content requires
    # OneDrive.exe to still be running to service the on-demand fetch; stopping
    # OneDrive first (needed for the wipe itself, see below) would make that
    # copy fail silently and quietly break the "preserve wallpaper" guarantee
    # this function advertises.
    $profileData = @{}
    Invoke-ForEachUserHive {
        param([string]$Sid, [string]$ProfilePath)
        $wp = (Get-ItemProperty "Registry::HKU\$Sid\Control Panel\Desktop" -Name Wallpaper -ErrorAction SilentlyContinue).Wallpaper
        $wallpaperStash = $null
        if ($wp -and (Test-Path $wp)) {
            $stash = Join-Path $env:TEMP "WallpaperStash_$(Split-Path $ProfilePath -Leaf)_$([guid]::NewGuid().ToString('N'))$([IO.Path]::GetExtension($wp))"
            Copy-Item -Path $wp -Destination $stash -Force -ErrorAction SilentlyContinue
            if (Test-Path $stash) { $wallpaperStash = $stash }
        }
        $profileData[$ProfilePath] = [pscustomobject]@{
            WallpaperPath  = $wp
            WallpaperStash = $wallpaperStash
            Desktop        = Resolve-UserShellFolder -Sid $Sid -ProfilePath $ProfilePath -RegValueName 'Desktop'     -ClassicName 'Desktop'
            Documents      = Resolve-UserShellFolder -Sid $Sid -ProfilePath $ProfilePath -RegValueName 'Personal'    -ClassicName 'Documents'
            Pictures       = Resolve-UserShellFolder -Sid $Sid -ProfilePath $ProfilePath -RegValueName 'My Pictures' -ClassicName 'Pictures'
            Downloads      = Resolve-UserShellFolder -Sid $Sid -ProfilePath $ProfilePath -RegValueName '{374DE290-123F-4565-9164-39C4925E467B}' -ClassicName 'Downloads'
            Videos         = Resolve-UserShellFolder -Sid $Sid -ProfilePath $ProfilePath -RegValueName 'My Video'    -ClassicName 'Videos'
            Music          = Resolve-UserShellFolder -Sid $Sid -ProfilePath $ProfilePath -RegValueName 'My Music'    -ClassicName 'Music'
        }
    }

    # Stopped here, AFTER the wallpaper has already been safely stashed above -
    # not just relied on from Remove-OneDriveAccounts running earlier: the
    # tech-facing GUI checklist lets 'Remove OneDrive Accounts' be deselected
    # while 'Wipe Personal Files' stays checked. If Desktop/Documents/Pictures
    # are OneDrive Known Folder Move-redirected and OneDrive is still actively
    # signed in and syncing when the wipe below deletes those local files, that
    # deletion WILL sync up to the user's actual cloud storage - deleting their
    # real files everywhere, not just on this one laptop being reissued. This
    # function's safety must not depend on another checkbox having also been ticked.
    Stop-ProcessAndWait -Name 'OneDrive'

    Get-ChildItem $UsersBase -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') } |
        ForEach-Object {
            $profileDir = $_.FullName
            $data       = $profileData[$profileDir]

            # All six folders use the resolved (redirection-aware) paths
            # collected above - OneDrive Known Folder Move only ever redirects
            # Desktop/Documents/Pictures, but classic GPO Folder Redirection can
            # independently redirect Downloads/Videos/Music too, so none of the
            # six can safely be assumed classic. If a profile's hive couldn't be
            # mounted, fall back to the classic path for all six rather than
            # skipping the profile entirely.
            if ($data) {
                $targets = @(
                    [pscustomobject]@{ Name = 'Desktop';   Path = $data.Desktop }
                    [pscustomobject]@{ Name = 'Documents'; Path = $data.Documents }
                    [pscustomobject]@{ Name = 'Pictures';  Path = $data.Pictures }
                    [pscustomobject]@{ Name = 'Downloads'; Path = $data.Downloads }
                    [pscustomobject]@{ Name = 'Videos';    Path = $data.Videos }
                    [pscustomobject]@{ Name = 'Music';     Path = $data.Music }
                )
            }
            else {
                $targets = 'Desktop', 'Documents', 'Pictures', 'Downloads', 'Videos', 'Music' |
                    ForEach-Object { [pscustomobject]@{ Name = $_; Path = (Join-Path $profileDir $_) } }
            }

            # On the Desktop specifically, .lnk/.url shortcuts are skipped -
            # see the function's .DESCRIPTION for why (this was previously
            # wiping application/network shortcuts along with real files).
            foreach ($target in $targets) {
                if (Test-Path $target.Path) {
                    $items = Get-ChildItem $target.Path -Force -ErrorAction SilentlyContinue
                    if ($target.Name -eq 'Desktop') {
                        $items = $items | Where-Object { $_.Extension -notin '.lnk', '.url' }
                    }
                    $items | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                }
            }

            if ($data -and $data.WallpaperStash -and (Test-Path $data.WallpaperStash)) {
                New-Item -Path (Split-Path $data.WallpaperPath) -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
                Copy-Item -Path $data.WallpaperStash -Destination $data.WallpaperPath -Force -ErrorAction SilentlyContinue
                Remove-Item -Path $data.WallpaperStash -Force -ErrorAction SilentlyContinue
                Write-Host "  Personal files wiped for: $($_.Name) (desktop background preserved)"
            }
            else {
                Write-Host "  Personal files wiped for: $($_.Name)"
            }
        }

    Write-Host -ForegroundColor Yellow "Personal File Wipe - COMPLETE`r`n"
}

Function Invoke-CleanMgrAutomation {
    <#
    .SYNOPSIS
        Runs Windows' Disk Cleanup (CleanMgr.exe) unattended across a fixed set
        of cleanup categories.
    .DESCRIPTION
        Clears any leftover StateFlags0001 values under the VolumeCaches registry
        key, sets StateFlags0001=2 on a fixed list of CleanMgr categories
        (Downloaded Program Files, Delivery Optimization Files, Internet Cache
        Files, memory dump files, "Previous Windows installation(s)"/Windows.old,
        Recycle Bin, Temporary Files, Thumbnail Cache, Update Cleanup, WER
        archive/queue files, Windows Upgrade Log Files, etc.), runs
        `CleanMgr.exe /sagerun:1` to execute against exactly those categories,
        waits for both cleanmgr.exe and its dismhost.exe helper process to finish,
        then removes the StateFlags0001 values it set so a technician's own
        interactive CleanMgr runs afterward start from a clean slate rather than
        this script's category selection.
    .NOTES
        No PowerShell cmdlet wraps Disk Cleanup on Windows client editions;
        CleanMgr.exe with the registry-driven /sagerun automation is Microsoft's
        own documented way to run it unattended. Named Invoke-CleanMgrAutomation
        (not Clear-Disk) specifically to avoid any resemblance to the real Storage
        module's Clear-Disk cmdlet, which does something completely different and
        far more dangerous - wipes every partition off a physical disk.
    #>
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
        'Previous Windows installation(s)',
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

    Write-Host 'Starting CleanMgr.exe...'
    $cleanProc = Start-Process -FilePath CleanMgr.exe -ArgumentList '/sagerun:1' -WindowStyle Hidden -Wait -PassThru
    if ($null -ne $cleanProc.ExitCode -and $cleanProc.ExitCode -ne 0) {
        Write-Warning "CleanMgr.exe exited with code $($cleanProc.ExitCode)"
    }
    Write-Host 'Waiting for CleanMgr and DismHost to finish...'
    # DismHost (CleanMgr's WinSxS/Windows.old helper) is known to occasionally wedge on
    # real machines. Unlike every other process-wait in this script (Stop-ProcessAndWait
    # caps at 15s for exactly this reason), this used to have no timeout at all, which
    # could stall every remaining step - and the final reboot - forever. Bounded to 10
    # minutes; a genuine timeout is logged and the run continues rather than hanging.
    $cleanupProcs = Get-Process -Name cleanmgr, dismhost -ErrorAction SilentlyContinue
    if ($cleanupProcs) {
        $cleanupProcs | Wait-Process -Timeout 600 -ErrorAction SilentlyContinue
        $stillRunning = $cleanupProcs | Where-Object { -not $_.HasExited }
        if ($stillRunning) {
            Write-Warning "CleanMgr/DismHost still running after 10 minutes - continuing without waiting further ($(($stillRunning | ForEach-Object { $_.ProcessName }) -join ', '))."
        }
    }

    # Remove the flags we set so interactive CleanMgr runs start with a clean slate
    Get-ItemProperty -Path "$volCacheBase\*" -Name StateFlags0001 -ErrorAction SilentlyContinue |
        Remove-ItemProperty -Name StateFlags0001 -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Yellow "Disk Cleanup - COMPLETE`r`n"
}

Function Invoke-DISMCleanup {
    <#
    .SYNOPSIS
        Runs DISM's WinSxS component store cleanup.
    .DESCRIPTION
        Runs `Dism.exe /online /Cleanup-Image /StartComponentCleanup`, which
        removes old superseded component packages that are no longer necessary -
        similar to the OS's own scheduled StartComponentCleanup task, but without
        that task's 30-day grace period or 1-hour timeout. Warns (rather than
        throwing) on a non-zero exit code, since component cleanup can partially
        succeed.
    .NOTES
        Official command used: Dism.exe /online /Cleanup-Image
        /StartComponentCleanup. No PowerShell cmdlet wraps this operation. The
        /ResetBase option (documented in an inline comment but not used here)
        would reclaim more space by removing ALL superseded component versions,
        but is a one-way operation that disables uninstalling already-installed
        updates afterward.
    #>
    Write-Host 'Running DISM component store cleanup (this may take several minutes)...'
    # To also remove all superseded update rollback data and reclaim more space, add /ResetBase
    # (one-way operation - disables uninstalling already-installed updates afterwards):
    #   Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
    Dism.exe /online /Cleanup-Image /StartComponentCleanup
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "DISM exited with code $LASTEXITCODE - component cleanup may be incomplete."
    }
    else {
        Write-Host -ForegroundColor Yellow "DISM Component Cleanup - COMPLETE`r`n"
    }
}

Function Clear-ShadowCopies {
    <#
    .SYNOPSIS
        Deletes every Volume Shadow Copy / System Restore point on the machine.
    .DESCRIPTION
        Enumerates and removes every Win32_ShadowCopy instance via CIM. Runs near
        the very end of the task list (after PST relocation and every other
        cleanup step) because everything deleted by any other step in this script
        is potentially still recoverable from an existing shadow copy (e.g. via
        ShadowExplorer) until this runs - this is what actually makes the rest of
        the cleanup in this script stick, rather than just hiding the data.
    .NOTES
        Official mechanism used: Get-CimInstance Win32_ShadowCopy |
        Remove-CimInstance. Operational note: this is the exact technique
        ransomware uses to delete shadow copies before encrypting, so EDR tooling
        (Defender for Endpoint, CrowdStrike, etc.) may flag or block it on a
        managed machine - a real, Microsoft-acknowledged interaction, not a bug in
        this script.
    #>
    Write-Host "Deleting Volume Shadow Copies / System Restore points..."
    # Everything deleted by every other step in this script is potentially
    # still recoverable from an existing shadow copy (e.g. via ShadowExplorer)
    # until these are purged - this is what actually makes the rest of the
    # cleanup in this script stick, rather than just hiding the data.
    #
    # Note for anyone troubleshooting an unexpected block on a managed
    # machine: enumerating/removing Win32_ShadowCopy via WMI/CIM is the
    # exact technique ransomware uses to delete shadow copies before
    # encrypting, so EDR tooling (Defender for Endpoint, CrowdStrike, etc.)
    # can flag or block it even though it's legitimate here - this is a
    # real, Microsoft-acknowledged interaction, not a bug in this script.
    Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | Remove-CimInstance -ErrorAction SilentlyContinue
    Write-Host -ForegroundColor Yellow "Shadow Copy Cleanup - COMPLETE`r`n"
}

Function Clear-UsnJournal {
    <#
    .SYNOPSIS
        Resets the NTFS USN Change Journal on every drive.
    .DESCRIPTION
        Runs `fsutil usn deletejournal /D` against every filesystem drive's root.
        The USN journal tracks a running history of file creates/renames/deletes -
        filenames of things that no longer exist can still surface here. Windows
        rebuilds the journal automatically as soon as anything writes to the
        volume again, so this is a no-risk reset, not a permanent disable.
    .NOTES
        Official command used: fsutil usn deletejournal /D. No PowerShell cmdlet
        equivalent exists in Windows PowerShell 5.1.
    #>
    Write-Host "Resetting NTFS USN Journal (all drives)..."
    # Tracks a running history of file creates/renames/deletes - filenames of
    # things that no longer exist can still surface here. Windows rebuilds
    # the journal automatically as soon as anything writes to the volume
    # again, so this is a no-risk reset, not a permanent disable.
    Get-TargetFileSystemDrives | ForEach-Object {
        fsutil usn deletejournal /D $_.Root.TrimEnd('\') 2>$null | Out-Null
    }
    Write-Host -ForegroundColor Yellow "USN Journal Reset - COMPLETE`r`n"
}

Function Clear-AmcacheAndShimCache {
    <#
    .SYNOPSIS
        Clears Amcache.hve and the AppCompatCache (ShimCache) registry value.
    .DESCRIPTION
        Deletes Amcache.hve under System32\AppCompat\Programs and removes the
        AppCompatCache value under Control\Session Manager. Both record the full
        path, hash, and first-run timestamp of every .exe ever run on this
        machine - richer and more persistent application-execution history than
        Prefetch (already cleared by Clear-WindowsHistory). Amcache.hve may still
        be open by the OS at runtime, so the delete is best-effort - if blocked, it
        silently no-ops and gets picked up on next boot.
    .NOTES
        No official Microsoft removal method is documented for either artifact;
        both are more commonly discussed in forensic/incident-response contexts
        than in Microsoft's own support documentation.
    #>
    Write-Host "Clearing Amcache/ShimCache (application execution history)..."
    # Amcache.hve and the AppCompatCache registry value both record the full
    # path, hash, and first-run timestamp of every .exe ever run on this
    # machine - richer and more persistent than Prefetch (already cleared in
    # Clear-WindowsHistory). Amcache.hve may still be open by the OS at
    # runtime, so this is best-effort; if the delete is blocked it just
    # silently no-ops and gets picked up on next boot.
    Remove-Item "$env:SystemRoot\AppCompat\Programs\Amcache.hve*" -Force -ErrorAction SilentlyContinue

    Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -Name AppCompatCache -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Yellow "Amcache/ShimCache Cleanup - COMPLETE`r`n"
}

Function Clear-SetupLogs {
    <#
    .SYNOPSIS
        Clears Windows setup/OOBE and servicing log files.
    .DESCRIPTION
        Deletes the Panther folder (setup/OOBE logs, can contain deployment
        configuration details), the Logs\CBS folder (servicing/component-based
        servicing logs), and setupapi*.log files under System32\inf.
    #>
    Write-Host "Clearing Windows setup/OOBE and servicing logs..."
    Remove-Item "$env:SystemRoot\Panther\*"         -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:SystemRoot\Logs\CBS\*"        -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:SystemRoot\inf\setupapi*.log" -Force -ErrorAction SilentlyContinue
    Write-Host -ForegroundColor Yellow "Setup/Servicing Log Cleanup - COMPLETE`r`n"
}

Function Clear-PagefileAndHibernation {
    <#
    .SYNOPSIS
        Configures pagefile clear-at-shutdown and regenerates the hibernation
        file, if hibernation is enabled.
    .DESCRIPTION
        Sets the ClearPageFileAtShutdown registry flag under Memory Management -
        takes effect on the reboot this script already triggers, so no immediate
        action is needed. If hiberfil.sys exists (hibernation enabled), toggles
        hibernation off then back on via `powercfg /h`, which regenerates
        hiberfil.sys, preserving whatever the original enabled/disabled setting
        was rather than turning on a disabled feature as a side effect (same
        "restore prior state" convention Clear-WindowsTemp and Clear-PrintQueue
        use for the services they stop). Neither pagefile.sys nor hiberfil.sys is
        touched by `cipher /w` (Invoke-SecureFreeSpaceWipe) - both are live,
        in-use system files, not free space, and either can hold raw RAM contents
        (plaintext typed before encryption, decrypted document data, session
        tokens) that happened to get paged out or snapshotted.
    .NOTES
        Official command used: powercfg /h off / powercfg /h on. No PowerShell
        cmdlet equivalent exists for hibernation file regeneration.
    #>
    Write-Host "Configuring pagefile clear-at-shutdown and regenerating hibernation file..."

    # Neither pagefile.sys nor hiberfil.sys is touched by cipher /w - both
    # are live, in-use system files, not free space. Either can hold raw RAM
    # contents (plaintext typed before encryption, decrypted document data,
    # session tokens) that happened to get paged out or snapshotted.
    #
    # This only sets the flag - it takes effect on next shutdown/reboot,
    # which this script already triggers, so no immediate action is needed.
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name ClearPageFileAtShutdown -Value 1 -Type DWord -ErrorAction SilentlyContinue

    # hiberfil.sys only exists when hibernation is enabled - only regenerate
    # it if that's actually the case here; toggling it off then back on
    # preserves whatever the original setting was rather than turning on a
    # disabled feature as a side effect (same "restore prior state"
    # convention Clear-WindowsTemp/Clear-PrintQueue use for their services).
    if (Test-Path "$env:SystemDrive\hiberfil.sys") {
        powercfg /h off
        powercfg /h on
        Write-Host "  Hibernation file regenerated."
    }
    else {
        Write-Host "  Hibernation not enabled - nothing to regenerate." -ForegroundColor Yellow
    }

    Write-Host -ForegroundColor Yellow "Pagefile/Hibernation Cleanup - COMPLETE`r`n"
}

Function Invoke-SecureFreeSpaceWipe {
    <#
    .SYNOPSIS
        Securely overwrites free disk space on every drive with Windows' built-in
        3-pass wipe.
    .DESCRIPTION
        Runs `cipher /w:<drive>` against every filesystem drive. Everything
        deleted anywhere in this script (like any ordinary Remove-Item call) is
        only unlinked, not overwritten, and stays recoverable with undelete tools
        until that disk space gets reused - cipher /w is what actually makes all
        of the preceding cleanup stick instead of just being hidden. Only runs
        when the script-level -SecureWipe switch is passed (off by default purely
        for the time cost - 30-60+ minutes per drive - not the risk), and runs
        last in the task order, after Clear-ShadowCopies and Clear-UsnJournal.
    .NOTES
        Official command used: cipher /w:<drive>. No PowerShell cmdlet equivalent
        exists; this is Windows' own documented free-space overwrite tool.
    #>
    Write-Host "Securely overwriting free disk space (cipher /w) on all drives..." -ForegroundColor Yellow
    Write-Host "  This can take 30-60+ minutes per drive depending on size and free space - this is expected." -ForegroundColor Yellow
    # Everything deleted anywhere in this script (like any ordinary
    # Remove-Item) is only unlinked, not overwritten - recoverable with
    # undelete tools until the space is reused. cipher /w is Windows' own
    # built-in 3-pass free-space overwrite, and is what actually makes all
    # of the preceding cleanup stick instead of just being hidden.
    Get-TargetFileSystemDrives | ForEach-Object {
        $drive = $_.Root.TrimEnd('\')
        Write-Host "  Wiping free space on $drive ..."
        cipher /w:$drive | Out-Null
    }
    Write-Host -ForegroundColor Yellow "Secure Free-Space Wipe - COMPLETE`r`n"
}

Function Clear-NetworkCaches {
    <#
    .SYNOPSIS
        Flushes the DNS resolver cache, the ARP/neighbor cache, and the NetBIOS
        name cache.
    .DESCRIPTION
        Clears the DNS client cache via the official Clear-DnsClientCache cmdlet
        (equivalent to `ipconfig /flushdns`), removes every ARP/neighbor cache
        entry via Get-NetNeighbor | Remove-NetNeighbor -Confirm:$false (the
        official NetTCPIP cmdlets, equivalent to `arp -d *`), and purges the
        NetBIOS name cache via `nbtstat -R` - no PowerShell cmdlet equivalent
        exists for NetBIOS, so that one stays a native command.
    .NOTES
        Official cmdlets used: Clear-DnsClientCache (DnsClient module),
        Get-NetNeighbor/Remove-NetNeighbor (NetTCPIP module). Both confirmed
        against Microsoft Learn documentation - see Version 2.27 changelog.
        Remove-NetConnectionProfile was also checked as a possible official
        replacement for Clear-NetworkHistory's registry-based network-location
        cleanup and does not exist (only Get-/Set-NetConnectionProfile do), so
        that function's registry approach is unchanged.
    #>
    Write-Host "Flushing DNS/ARP/NetBIOS caches..."
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    Get-NetNeighbor -ErrorAction SilentlyContinue | Remove-NetNeighbor -Confirm:$false -ErrorAction SilentlyContinue
    nbtstat -R | Out-Null
    Write-Host -ForegroundColor Yellow "Network Cache Flush - COMPLETE`r`n"
}

Function Clear-WindowsRecall {
    <#
    .SYNOPSIS
        Removes Windows Recall (Copilot+ PC snapshot history) and its per-user
        screenshot/database content.
    .DESCRIPTION
        Recall periodically screenshots the desktop and OCRs/semantically
        indexes the content for later search - only present on Copilot+ PCs
        with the required NPU hardware, so this is a no-op with a status
        message on every other machine. If present, runs the official
        Disable-WindowsOptionalFeature -FeatureName "Recall" -Remove (Dism
        module) - Microsoft's own documented removal command, which per their
        docs also deletes existing snapshots, and takes effect on the reboot
        this script already triggers (-NoRestart avoids an early reboot from
        inside this step). As belt-and-suspenders, also directly deletes each
        user's CoreAIPlatform.00\UKP folder (the actual per-user ukg.db
        database and ImageStore screenshot JPEGs) the same way this script
        handles every other packaged Windows feature's data, in case the
        feature-level removal doesn't reach every profile on its own.
    .NOTES
        Official cmdlet used: Disable-WindowsOptionalFeature -FeatureName
        "Recall" -Remove (Dism module) - confirmed against Microsoft Learn and
        current how-to documentation. Data location confirmed as
        %LOCALAPPDATA%\CoreAIPlatform.00\UKP\<GUID>\ (ukg.db + ImageStore).
    #>
    Write-Host "Checking for Windows Recall..."

    $recallFeature = Get-WindowsOptionalFeature -Online -FeatureName 'Recall' -ErrorAction SilentlyContinue
    if (-not $recallFeature) {
        Write-Host "  Recall isn't present on this machine (requires Copilot+ PC hardware) - skipping." -ForegroundColor Yellow
    }
    else {
        if ($recallFeature.State -ne 'Disabled') {
            Disable-WindowsOptionalFeature -Online -FeatureName 'Recall' -Remove -NoRestart -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  Ran official Disable-WindowsOptionalFeature -FeatureName Recall -Remove (takes full effect on reboot)." -ForegroundColor Green
        }
        else {
            Write-Host "  Recall feature already disabled." -ForegroundColor Yellow
        }
    }

    # Belt-and-suspenders per-user cleanup of the actual snapshot content.
    Remove-Item "$UsersBase\*\AppData\Local\CoreAIPlatform.00\UKP\*" -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Yellow "Windows Recall Cleanup - COMPLETE`r`n"
}

Function Clear-RemoteAccessToolData {
    <#
    .SYNOPSIS
        Clears saved sessions/host keys for PuTTY, WinSCP, and MobaXterm for
        every user.
    .DESCRIPTION
        All three are portable-friendly SSH/SFTP/terminal clients commonly
        carried over from a previous machine or user, and all three store
        SAVED SESSION CONFIGS that disclose internal hostnames/IPs the user has
        connected to - exactly the kind of internal recon information a laptop
        being reissued to someone else shouldn't retain. For every user:
        removes PuTTY's Sessions and SshHostKeys registry keys (PuTTY stores
        everything in the registry, nothing under AppData); removes WinSCP's
        whole "WinSCP 2" registry key (saved sites include an obfuscated - not
        securely encrypted - stored password per session, per WinSCP's own
        documentation); and removes MobaXterm's AppData folder (MobaXterm.ini
        holds saved sessions/settings, and its "home"/"slash" virtual
        filesystem folders - including a RemoteFiles folder - can hold files
        actually transferred during past SFTP/SSH sessions).
    .NOTES
        No official Microsoft cmdlet applies to any of these three third-party
        tools. Registry paths and folder contents confirmed via a mix of live
        inspection on this machine (MobaXterm's AppData folder and file
        contents were directly observed) and current documentation (PuTTY's
        and WinSCP's registry locations, since this specific account had never
        used either) - see Version 2.37 changelog.
    #>
    Write-Host "Clearing PuTTY/WinSCP/MobaXterm saved sessions (all users)..."

    Invoke-ForEachUserHive {
        param([string]$Sid, [string]$ProfilePath)
        Remove-Item "Registry::HKU\$Sid\Software\SimonTatham\PuTTY\Sessions"     -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "Registry::HKU\$Sid\Software\SimonTatham\PuTTY\SshHostKeys"  -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "Registry::HKU\$Sid\Software\Martin Prikryl\WinSCP 2"        -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  PuTTY/WinSCP session data cleared for: $(Split-Path $ProfilePath -Leaf)"
    }

    Remove-Item "$UsersBase\*\AppData\Roaming\MobaXterm\*" -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor Yellow "Remote Access Tool Cleanup - COMPLETE`r`n"
}

Function Clear-CiscoJabberData {
    <#
    .SYNOPSIS
        Clears Cisco Jabber chat history, contacts, and configuration for every
        user.
    .DESCRIPTION
        Jabber is an enterprise chat/softphone client - locally cached chat
        history is a SQLite database at
        AppData\Local\Cisco\Unified Communications\Jabber\CSF\History\
        (confirmed via current documentation, filename format
        <username>@<domain>.db), alongside a browser cache (cef_cache) and
        cached Contacts. Clears both the Local (history/cache/contacts) and
        Roaming (Config, including server/service location settings) Cisco
        Unified Communications folders for every user - same sensitivity tier
        as Teams/Skype, both already covered elsewhere in this script.
    .NOTES
        No official Microsoft/Cisco cmdlet exists for this. Base folder
        structure (Unified Communications\Jabber\CSF\...) confirmed present on
        this machine; the specific History subfolder wasn't populated on this
        particular account (never signed into Jabber here), so its exact
        content was confirmed via current documentation instead - see Version
        2.37 changelog.
    #>
    Write-Host "Clearing Cisco Jabber chat history and configuration (all users)..."
    Remove-Item "$UsersBase\*\AppData\Local\Cisco\Unified Communications\*"   -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$UsersBase\*\AppData\Roaming\Cisco\Unified Communications\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host -ForegroundColor Yellow "Cisco Jabber Cleanup - COMPLETE`r`n"
}

Function Clear-PowerAutomateDesktopData {
    <#
    .SYNOPSIS
        Clears Power Automate Desktop's local flow data, run logs, and signed-in
        account cache for every user.
    .DESCRIPTION
        Deletes each user's entire "Power Automate Desktop" folder under
        AppData\Local\Microsoft - this covers desktop flow run logs
        (Console\Scripts\<FlowId>\Runs\<RunId>), designer-cached flow data, RDP
        automation agent state, and the signed-in account/auth token cache.
        Microsoft's own troubleshooting guidance for this app's Cache folder
        specifically calls out preserving the Account folder and
        msalcache.bin3 file when just clearing a stuck cache - deliberately
        NOT done here, since this script's goal is a full wipe (the account
        should be signed OUT for the next user), not a targeted cache fix.
    .NOTES
        No official Microsoft cmdlet exists for a full data reset of this app;
        the folder layout is Microsoft's own documented troubleshooting/
        migration guidance - see Version 2.37 changelog.
    #>
    Write-Host "Clearing Power Automate Desktop data (all users)..."
    Remove-Item "$UsersBase\*\AppData\Local\Microsoft\Power Automate Desktop\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host -ForegroundColor Yellow "Power Automate Desktop Cleanup - COMPLETE`r`n"
}

Function Clear-Windows365ClientData {
    <#
    .SYNOPSIS
        Clears the Windows 365 (Cloud PC) client's local connection/session
        data for every user.
    .DESCRIPTION
        Deletes the LocalState folder of the Windows 365 client's package
        (Packages\MicrosoftCorporationII.Windows365_*, confirmed present on
        this machine) for every user - same UWP packaged-app data pattern used
        elsewhere in this script (Phone Link, Widgets, etc.). Covers cached
        Cloud PC connection history and session state for whichever Cloud PC
        this user connected to.
    #>
    Write-Host "Clearing Windows 365 client data (all users)..."
    Remove-Item "$UsersBase\*\AppData\Local\Packages\MicrosoftCorporationII.Windows365_*\LocalState\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host -ForegroundColor Yellow "Windows 365 Client Cleanup - COMPLETE`r`n"
}

Function Clear-SnagitData {
    <#
    .SYNOPSIS
        Clears Snagit's recent-capture thumbnail cache for every user.
    .DESCRIPTION
        Confirmed via direct inspection of this machine's own Snagit data
        folder (AppData\Local\TechSmith\Snagit): the Thumbnails subfolder holds
        preview images of recent screen captures - the actual privacy-relevant
        piece, since it reveals recent screen activity even if the full-
        resolution original was saved elsewhere (and possibly already removed
        by Remove-UserPersonalFiles if it landed under Documents/Pictures).
        Deliberately does NOT touch the License subfolder (license activation
        state - removing it would force the next user to re-activate a
        volume-licensed install for no privacy benefit) or TrackerbirdFiles
        (vendor analytics, not user content).
    #>
    Write-Host "Clearing Snagit recent-capture thumbnail cache (all users)..."
    Remove-Item "$UsersBase\*\AppData\Local\TechSmith\Snagit\Thumbnails\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host -ForegroundColor Yellow "Snagit Cleanup - COMPLETE`r`n"
}

Function Clear-KeePassData {
    <#
    .SYNOPSIS
        Clears KeePass's application config and recently-opened-database list
        for every user.
    .DESCRIPTION
        Does NOT touch any actual .kdbx password database file (those are real
        user files, already caught by Remove-UserPersonalFiles wherever they
        happen to live, and KeePass never stores the master password itself in
        its own config regardless). What this clears is KeePass.config.xml
        under AppData\Roaming\KeePass (confirmed present on this machine) -
        specifically its Most-Recently-Used list, which discloses the file
        paths of every database this user has opened, i.e. WHERE their
        credential vaults are kept, information the next user of this laptop
        has no legitimate reason to see. Also clears the legacy
        HKCU\Software\KeePass registry key some older versions used, for
        completeness, even though it wasn't present on this particular
        installation.
    #>
    Write-Host "Clearing KeePass configuration and recent-file list (all users)..."
    Remove-Item "$UsersBase\*\AppData\Roaming\KeePass\*" -Recurse -Force -ErrorAction SilentlyContinue
    Invoke-ForEachUserHive {
        param([string]$Sid)
        Remove-Item "Registry::HKU\$Sid\Software\KeePass" -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host -ForegroundColor Yellow "KeePass Cleanup - COMPLETE`r`n"
}

# ── Main ────────────────────────────────────────────────────────────────────────

Write-Host "Series of commands to clear browser profile information, Teams and OneDrive"
Write-Host "Pulled from various web sources. This is a " -NoNewline
Write-Host "DESTRUCTIVE" -ForegroundColor Red -NoNewline
Write-Host " process - data will not be recoverable. Proceed accordingly."
Write-Host "`nThis includes deleting the actual CONTENTS of Desktop/Documents/Downloads/" -ForegroundColor Red
Write-Host "Pictures/Videos/Music for every user on this machine, not just cache/app data" -ForegroundColor Red
Write-Host "(each user's current desktop background picture and setting are preserved)." -ForegroundColor Red

if ($SecureWipe) {
    Write-Host "`n-SecureWipe is set: " -NoNewline -ForegroundColor Red
    Write-Host "free disk space will be securely overwritten at the end." -ForegroundColor Red
    Write-Host "This can add 30-60+ minutes to the total run time." -ForegroundColor Red
}

# This script is dropped on a thumbdrive and run against different physical
# laptops by different technicians - print what's about to be wiped so a
# tech mid-way through a stack of machines can confirm it's the right one
# before answering the prompt below.
$serial = (Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue).SerialNumber
Write-Host "`n$('=' * 60)" -ForegroundColor Cyan
Write-Host "  TARGET MACHINE" -ForegroundColor Cyan
Write-Host "  Computer Name : $env:COMPUTERNAME" -ForegroundColor White
Write-Host "  Serial Number : $(if ($serial) { $serial } else { 'Unknown' })" -ForegroundColor White
Write-Host "  Running As    : $env:USERDOMAIN\$env:USERNAME" -ForegroundColor White
Write-Host "$('=' * 60)" -ForegroundColor Cyan

# Single source of truth for both the GUI task-selection checklist below and
# the actual run order - conditional tasks (PST relocation, secure wipe) are
# only added when their switch was actually passed, so the checklist doesn't
# show a task that wouldn't do anything if selected.
# Each entry: GUI checklist label -> scriptblock invoked by Invoke-Step when
# that label is selected. Order here is also execution order.
$script:AllTasks = [ordered]@{
    'Clear Chrome'               = { Clear-Chrome }                          # Chrome cache/cookies/history/logins, all users
    'Clear IE'                   = { Clear-IE }                              # IE cache + shared WebCacheV01.dat
    'Clear Firefox'              = { Clear-FireFox }                         # Firefox cache/cookies/history/logins, all users
    'Clear Edge'                 = { Clear-Edge }                            # Edge (Chromium + legacy EdgeHTML) cache, all users
    'Remove OneDrive Accounts'   = { Remove-OneDriveAccounts }               # OneDrive.exe /reset + registry, Business+Personal
    'Clear User Temp'            = { Remove-UserCache }                      # %LOCALAPPDATA%\Temp, all users
    'Clear WER'                  = { Clear-WER }                             # Windows Error Reporting queue/archive
    'Clear Diagnostic Artifacts' = { Clear-DiagnosticArtifacts }             # Crash dumps, Timeline, Sticky Notes, notifications
    'Clear Windows Temp'         = { Clear-WindowsTemp }                     # System Temp + WU component reset
    'Clear Network Credentials'  = { Clear-NetworkCredentials }              # Credential Manager vault (cmdkey), current user
    'Clear Wi-Fi Profiles'       = { Clear-WifiProfiles }                    # Saved Wi-Fi SSIDs/passwords, machine-wide
    'Clear Network History'      = { Clear-NetworkHistory }                  # NetworkList profile/signature history
    'Clear Proxy Settings'       = { Clear-ProxySettings }                   # WinHTTP + per-user IE/WinINET proxy
    'Clear VPN Connections'      = { Clear-VpnConnections }                  # All-user VPN connection profiles
    'Clear Device History'       = { Clear-DeviceHistory }                   # USBSTOR + Bluetooth paired-device registry
    'Clear Autologon Creds'      = { Clear-AutologonCredentials }            # Plaintext Winlogon autologon password, if set
    'Remove Network Printers'    = { Remove-NetworkPrinters }                # Network/remote printer connections
    'Clear RDP History'          = { Clear-RDPHistory }                     # Saved RDP server list + MRU, all users
    'Clear Clipboard History'    = { Clear-ClipboardHistory }                # Persisted Clipboard History files, all users
    'Clear Print Queue'          = { Clear-PrintQueue }                      # Queued print jobs, graceful then forced
    'Clear Windows History'      = { Clear-WindowsHistory }                  # Run/TypedPaths/search/RecentDocs MRU, Prefetch
    'Clear Office History'       = { Clear-OfficeHistory }                   # Office File/Place/User MRU, all users
    'Sign Out of Office Apps'    = { Clear-OfficeSignIn }                    # Office identity/token cache, all users
    'Clear Adobe History'        = { Clear-AdobeHistory }                    # Adobe/Bluebeam recent-file MRU + cache
    'Clear Sync Client Caches'   = { Clear-SyncClientCaches }                # Box/Dropbox/Google Drive app cache/sign-in
    'Clear User Certificates'    = { Clear-UserCertificates }                # Personal cert store + private keys, all users
    'Clear Dev Credentials'      = { Clear-DevCredentials }                  # SSH keys, .gitconfig, Git Credential Manager
    'Clear Mapped Drives'        = { Clear-MappedDrives }                    # Persisted network drive mappings, all users
    'Clear Meeting App Caches'   = { Clear-MeetingAppCaches }                # Zoom/WebEx local cache
    'Clear Misc App Data'        = { Clear-MiscAppData }                     # Phone Link, Mail/Calendar, OneNote, Skype
    'Remove Scheduled Tasks'     = { Remove-NonMicrosoftScheduledTasks }     # Tasks outside \Microsoft\ task-path
    'Clear Event Logs'           = { Clear-EventLogs }                       # Every non-empty event log, classic + modern
    'Remove Teams Profile'       = { Remove-TeamsProfile }                   # Teams v1+v2 data, all users
    'Remove Outlook Profile'     = { Remove-OutlookProfile }                 # Outlook profile registry, OST/NK2, PST (+backup)
    'Clear Pinned Items'         = { Clear-PinnedItems }                     # Jump Lists, Recent Items, Quick Access pins
    'Wipe Personal Files'        = { Remove-UserPersonalFiles }              # Desktop/Documents/Downloads/Pictures/Videos/Music
    'Clear Recycle Bin'          = { Invoke-RecycleBinCleanup }              # Clear-RecycleBin cmdlet, all drives/users
    'Flush Network Caches'       = { Clear-NetworkCaches }                   # DNS (cmdlet) + ARP (cmdlet) + NetBIOS (nbtstat)
    'Reset Search Index'         = { Clear-SearchIndex }                     # Windows.edb (rebuilds automatically)
    'Disk Cleanup'               = { Invoke-CleanMgrAutomation }             # CleanMgr.exe /sagerun across fixed categories
    'DISM Component Cleanup'     = { Invoke-DISMCleanup }                    # WinSxS component store cleanup
    'Clear Setup Logs'           = { Clear-SetupLogs }                       # Panther/CBS/setupapi logs
    'Clear Amcache/ShimCache'    = { Clear-AmcacheAndShimCache }             # Application execution history
    'Clear Pagefile/Hibernation' = { Clear-PagefileAndHibernation }          # Clear-at-shutdown flag + hiberfil.sys regen
    'Clear Windows Recall'       = { Clear-WindowsRecall }                   # Copilot+ snapshot history, no-op on non-Copilot+ hardware
    'Clear Remote Access Tools'  = { Clear-RemoteAccessToolData }            # PuTTY/WinSCP/MobaXterm saved sessions + host keys
    'Clear Cisco Jabber'         = { Clear-CiscoJabberData }                 # Chat history, contacts, config
    'Clear Power Automate'       = { Clear-PowerAutomateDesktopData }        # Flow run logs, designer cache, signed-in account
    'Clear Windows 365 Client'   = { Clear-Windows365ClientData }            # Cloud PC connection/session history
    'Clear Snagit Thumbnails'    = { Clear-SnagitData }                      # Recent-capture thumbnail cache
    'Clear KeePass Config'       = { Clear-KeePassData }                     # Recent-database list, app config
}

# Shadow copies/USN journal/free-space wipe are meant to run last, deliberately
# after every other task INCLUDING PST relocation (which itself deletes the
# local backup copy once it's safely off the machine) - so nothing gets deleted
# afterward that a shadow copy could still contain, or that the free-space wipe
# wouldn't cover. Being appended here to the same ordered $script:AllTasks that
# the GUI checklist is built from only guarantees they run last AMONG the main
# task loop - 'Relocate PST Backups' is invoked separately, in its own
# Invoke-Step call after that loop finishes (see Main, below), so appending
# them here does NOT by itself make them run after PST relocation too. Their
# names are recorded in $script:TrailingTasks so Main can explicitly defer
# running them until after PST relocation has already happened - see the
# comment there for why this split exists.
$script:AllTasks['Clear Shadow Copies'] = { Clear-ShadowCopies }
$script:AllTasks['Reset USN Journal']   = { Clear-UsnJournal }
if ($SecureWipe) {
    $script:AllTasks['Secure Free-Space Wipe'] = { Invoke-SecureFreeSpaceWipe }
}
$script:TrailingTasks = @('Clear Shadow Copies', 'Reset USN Journal', 'Secure Free-Space Wipe')

# Call: Show-TaskSelectionDialog. See its three-way $null / empty-array /
# populated-array return contract documented in its own .OUTPUTS help above -
# each of the three branches below handles exactly one of those cases.
$selectedTasks = Show-TaskSelectionDialog -Tasks $script:AllTasks -ComputerName $env:COMPUTERNAME -SerialNumber $(if ($serial) { $serial } else { 'Unknown' })

if ($null -eq $selectedTasks) {
    # GUI unavailable - fall back to a text-prompt confirmation and run everything.
    # Requires typing the computer name back (already printed above) rather than a bare
    # Enter-to-proceed, so a tech mid-way through a stack of machines has to actually read
    # and match the target instead of reflexively hitting Enter - there's still no automated
    # identity check, but this at least forces a deliberate read.
    $typed = Read-Host "`nGUI unavailable - type this machine's computer name ($env:COMPUTERNAME) to run all tasks, or Ctrl-C to cancel"
    if ($typed -ne $env:COMPUTERNAME) {
        Write-Host "`nInput did not match computer name '$env:COMPUTERNAME' - exiting without making any changes." -ForegroundColor Yellow
        Stop-Transcript
        # Must run after Stop-Transcript releases the log file handle - same
        # ordering as the main try/finally below, which this early-exit path
        # bypasses. Without this call the log (already containing the
        # computer name/serial/account banner) would be left behind on the
        # machine instead of relocated, defeating the whole point of that
        # relocation.
        Move-ArtifactOffMachine -SourcePath $LogPath -DestFolderName 'Logs'
        exit 1
    }
    $selectedTasks = @($script:AllTasks.Keys)
}
elseif ($selectedTasks.Count -eq 0) {
    Write-Host "`nNo tasks selected - exiting without making any changes." -ForegroundColor Yellow
    Stop-Transcript
    # See comment on the identical call in the name-mismatch branch above.
    Move-ArtifactOffMachine -SourcePath $LogPath -DestFolderName 'Logs'
    exit 0
}
else {
    Write-Host "`n$($selectedTasks.Count) of $($script:AllTasks.Count) tasks selected." -ForegroundColor Cyan
}

$startTime = Get-Date

# Call: Invoke-Step, once per selected task, in $script:AllTasks order. This
# is the one place every cleanup function in this script actually gets
# invoked - each iteration hands Invoke-Step the task's display name (for its
# timestamped header and, on failure, $script:stepErrors) and its scriptblock
# (normally a single function call, e.g. { Clear-Chrome }).
try {
    # $script:TrailingTasks (Shadow Copies/USN Journal/Secure Free-Space Wipe)
    # are skipped in this first pass and run afterward instead - see below.
    foreach ($taskName in $script:AllTasks.Keys) {
        if ($taskName -notin $selectedTasks) { continue }
        if ($taskName -in $script:TrailingTasks) { continue }
        Invoke-Step $taskName $script:AllTasks[$taskName]
    }

    # Deliberately unconditional and NOT part of the GUI checklist, even
    # though 'Remove Outlook Profile' (which is checklist-selectable) is what
    # actually populates $PstBackupPath under -BackupPst. Making relocation
    # its own independently-uncheckable checkbox item was found to be a real
    # gap: a technician could leave 'Remove Outlook Profile' checked while
    # unchecking 'Relocate PST Backups', leaving plaintext PST backups sitting
    # on the machine being handed to a new user - worse than the default
    # (no -BackupPst) behavior of just deleting them outright, and the same
    # class of bug as the OneDrive-checkbox-independence issue fixed in
    # Version 2.31. Runs here (after every selected non-trailing task, before
    # the reboot trigger below, not inside the transcript-closing finally
    # block) because a PST backup can be multiple GB - it needs the full run
    # rather than racing the 30-second reboot countdown or a closed transcript
    # handle.
    #
    # Deliberately runs BEFORE $script:TrailingTasks, not after: an earlier
    # version ran Shadow Copies/USN Journal/Secure Free-Space Wipe as the tail
    # of the same single loop this whole block used to be part of, which meant
    # they actually executed BEFORE this point - the local PST backup copy
    # (arguably the most sensitive artifact this script produces) got deleted
    # by Move-ArtifactOffMachine AFTER the free-space wipe had already run,
    # so the freed disk blocks were never covered by it and stayed
    # undelete-recoverable, exactly contradicting -SecureWipe's whole purpose.
    if ($BackupPst) {
        Invoke-Step 'Relocate PST Backups' {
            Move-ArtifactOffMachine -SourcePath $PstBackupPath -DestFolderName "PstBackup_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        }
    }

    # Now run the deferred trailing tasks, in their original $script:AllTasks
    # order, so they genuinely run last - after PST relocation has already
    # deleted its local copy - rather than merely last among the main loop.
    foreach ($taskName in $script:TrailingTasks) {
        if ($taskName -notin $script:AllTasks.Keys) { continue }
        if ($taskName -notin $selectedTasks) { continue }
        Invoke-Step $taskName $script:AllTasks[$taskName]
    }

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

    if ($SkipReboot) {
        Write-Host "Reboot suppressed (-SkipReboot). Reboot manually when ready." -ForegroundColor Yellow
    }
    else {
        Write-Host "Process complete. Reboot will be scheduled once the log is relocated."
        $script:shouldReboot = $true
    }
}
finally {
    Stop-Transcript
    # Must run after Stop-Transcript releases the log file handle -
    # otherwise the copy/delete below would fail while it's still open.
    Move-ArtifactOffMachine -SourcePath $LogPath -DestFolderName 'Logs'
}

# The actual reboot trigger is deliberately OUTSIDE the try/finally above,
# scheduled only after transcript relocation has already finished - not
# alongside it. `shutdown /r /f /t 30` is fire-and-forget: it schedules a
# forced reboot 30 seconds out and returns immediately, so the countdown used
# to run concurrently with the finally block's transcript copy to the
# thumbdrive. `/f` force-closes this very PowerShell process once the
# deadline hits, which could kill it mid-copy on a long/verbose run or slow
# removable media - the identical race already reasoned through for PST
# backups (see the 'Relocate PST Backups' comment above), which is why that
# copy runs before this point too.
if ($script:shouldReboot) {
    Write-Host "Computer will reboot in 30 seconds."
    Write-Host "Run 'shutdown /a' in a command prompt to cancel the reboot." -ForegroundColor Cyan
    SHUTDOWN.EXE /r /f /t 30 /c 'Rebooting to complete Reset_Fire_Laptop cleanup....'
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Shutdown command failed with exit code $LASTEXITCODE"
    }
}
