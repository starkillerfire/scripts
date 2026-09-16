# Browser Install Archive

Superseded local Chrome/Edge installers, kept for reference only - not referenced
by anything in this repo anymore.

Replaced 2026-09-16 by [`..\Browsers\Install-Browsers.ps1`](../Browsers/Install-Browsers.ps1),
which consolidates Chrome, Edge, and (new) Firefox into one implementation shared
via `..\Common\BrowserDeploy.Common.psm1`. `MasterInstaller.ps1` and
`NewImageInstalls.ps1` were both updated to call the new script instead of these.

**Not archived here, and still active:** the top-level `Chrome\` and `Edge\`
folders at the repo root. Those are a different tool - remote fleet-push to
*other* machines via PsExec (CSV/`-ComputerName` driven) - which
`Install-Browsers.ps1` does not replace; it only installs on the local machine
it's run on.
