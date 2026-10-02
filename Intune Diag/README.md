# Intune Diag

Read-only diagnostic scripts for Intune/MDM-managed machines. Nothing in
this folder changes system state - every script here only collects and
reports. Remediation (e.g. clearing a failed Win32 app's registry state so
Intune retries it) lives elsewhere, such as `Intune Sync Fix\grsremediation.ps1`.

## Scripts

- **Invoke-IntuneWindowsUpdateDiagnostic.ps1** - Windows Update policy and
  history: effective MDM/GPO update policy, pause/defer settings, Windows
  Update Client and MDM event history, update service status, GPResult,
  dsregcmd, and PolicyManager provider policies. Use for "why isn't this
  machine updating/deferring/pausing the way policy says it should" tickets.

- **Invoke-IntuneEnrollmentDiagnostic.ps1** - Entra/MDM enrollment health:
  join state, MDM enrollment registry records, MDM client certificate
  expiry, IntuneManagementExtension/dmwappushsvc service status, recent
  MDM sync events, and optional connectivity checks to Microsoft's
  enrollment/login endpoints. Use for "this machine won't check in or sync"
  tickets. Produces a Pass/Warn/Fail summary up front.

- **Invoke-IntuneAppDiagnostic.ps1** - Win32 app deployment state: reads
  every app's status under the IntuneManagementExtension registry tree and
  classifies it Success / SuccessRebootRequired / Failed / Pending, plus
  recent error-level lines from IntuneManagementExtension.log. Run this
  first when an app won't install - if it shows failed entries,
  `Intune Sync Fix\grsremediation.ps1` is the tool that clears them so
  Intune retries the install.

- **IntuneDiag.Common.psm1** - shared helper functions the three scripts
  above import automatically (output-folder resolution, SYSTEM-context
  detection). Not meant to be run directly.

## Output

Each script creates its own timestamped subfolder under:

- the logged-on user's Downloads folder, for an interactive run, or
- `C:\ProgramData\IntuneDiagnostics`, when running as SYSTEM (an
  Intune-pushed run) or when no interactive user is detected

Pass `-OutputPath` to any script to override this.

**Review a diagnostic bundle before attaching it to an external or
third-party ticket.** GPResult and dsregcmd output in particular can
contain tenant, device, and policy detail.
