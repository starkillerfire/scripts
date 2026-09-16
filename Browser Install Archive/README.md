# Browser Install Archive

Superseded remote-push Chrome/Edge installers, kept for reference only - not
referenced by anything in this repo anymore.

Replaced 2026-09-16 by [`..\Browsers\Push-Browsers.ps1`](../Browsers/Push-Browsers.ps1),
which consolidates Chrome, Edge, and (new) Firefox remote pushes into one
implementation, unifying what used to be two separate approaches:
`ChromeInstall23.ps1`/`EdgeInstall23.ps1` (push from an already-staged share via
`-SourcePath`) and `Chrome Powershell.ps1`/`Edge Update.ps1` (download fresh
then push, the default when `-SourcePath` is omitted) - both are still
supported as modes of the one script.

**Not the same tool as** `Intune PreDeployment Scripts\Browser Install Archive\`
(a separate archive folder) - that one holds the superseded *local* installers
(`installChrome.ps1`, `Edge.ps1`), replaced by
`Intune PreDeployment Scripts\Browsers\Install-Browsers.ps1`.
