# Signed remote updates

The library checks internal GitLab first, using `powershell-group/GitLab-Script-Library` on `gitlab.bor.doi.net`. GitHub `starkillerfire/scripts` is the secondary source, queried only when the GitLab metadata request fails. A reachable GitLab remains authoritative even when it has no newer version. Invalid metadata, failed downloads, and rejected signatures do not trigger mirror installation.

PowerShell files verify their own Authenticode signature before original operational code runs. Updates must have a valid Windows Authenticode signature from DOI certificate `CEFA4DF2F31F5218A3F3B28144AFD9A96770A315`, pass syntax checks, and retain update support. Clients need the appropriate Windows certificate trust. The certificate expires November 6, 2027; these signatures have no trusted timestamp because no approved timestamp service was supplied. Plan certificate renewal and a signed pin change before expiration.

Downloads are pinned to a commit and use HTTPS without redirects. Replacement retains a `.bak` copy; new PowerShell code runs on the next invocation. Batch launcher updates must match a SHA-256 hash carried in their signed PowerShell companion. A running launcher stages its replacement for the next launch, when the signed companion validates it again. Publish companion scripts and launchers together.

Checks use each server's default branch unless `SCRIPT_LIBRARY_GITLAB_REF` or `SCRIPT_LIBRARY_GITHUB_REF` is set. Optional private-repository credentials come from `SCRIPT_LIBRARY_GITLAB_TOKEN` and `SCRIPT_LIBRARY_GITHUB_TOKEN`; use separate, read-only tokens. Git is not required on client machines. Set `SCRIPT_LIBRARY_SKIP_UPDATE=1` to skip network updates; installed-file signature verification still applies. Update failures warn and leave the installed signed version available. WhatIf skips updating.

After editing scripts or launchers, run `maintenance/Install-RemoteUpdate.ps1`, then the isolated `maintenance/Test-RemoteUpdate.ps1`, then `maintenance/Sign-Library.ps1` in Windows PowerShell 5.1. The signer can accept an approved `-TimestampServer`. Do not edit signed files afterward. The Git attributes preserve signed bytes and launcher hashes. Publish the signed files to GitLab and synchronize the approved GitHub mirror; unsigned remote versions will be rejected. No remote publication is performed by these maintenance tools.

Signature checks inside scripts are defense in depth: someone able to rewrite the file can also remove its check. Protect installation directories and use centrally managed execution policy or application control as appropriate. This addition does not certify the library against DOI, DISA STIG, or CIS requirements.

Autopilot retains its existing public-DNS fallback when current DNS resolution fails. This change does not configure DNS on the development computer.
