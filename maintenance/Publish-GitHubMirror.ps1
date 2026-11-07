#Requires -Version 5.1

<#
.SYNOPSIS
    Publishes the library to the public GitHub mirror, leaving out the files
    listed in maintenance/github-mirror-exclude.txt.

.DESCRIPTION
    GitLab holds the full repository. GitHub is public, so it gets a filtered
    copy: one new commit whose content is SourceRef minus the excluded paths,
    with GitHub's current branch as its parent. The push is a normal
    fast-forward, so nothing on GitHub is overwritten. GitLab is not touched;
    push to it as usual.

    Before pushing, the filtered content is checked for any document,
    installer, archive or key file, and the push is refused if one is found.

.PARAMETER SourceRef
    Branch or commit to publish. Default 'main'.

.PARAMETER Remote
    The GitHub remote. Default 'github'.

.PARAMETER Branch
    Branch to update on GitHub. Default 'main'.

.EXAMPLE
    .\maintenance\Publish-GitHubMirror.ps1 -WhatIf

.EXAMPLE
    .\maintenance\Publish-GitHubMirror.ps1
#>
# Invoke-Git passes git's own arguments straight through, so they are positional by design.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Justification = 'Invoke-Git forwards raw git arguments.')]
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SourceRef = 'main',
    [string]$Remote = 'github',
    [string]$Branch = 'main'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path $PSScriptRoot -Parent
$blockedPattern = '\.(xlsx?|docx?|pptx?|exe|msi|zip|pdf|pfx|p12|pem|key)$'

# No param block on purpose: git switches like -p must pass straight
# through instead of binding to PowerShell's common parameters.
function Invoke-Git {
    $output = & git -C $root @args
    if ($LASTEXITCODE -ne 0) { throw "git $($args -join ' ') failed with exit code $LASTEXITCODE." }
    $output
}

$excluded = @(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'github-mirror-exclude.txt') |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -and -not $_.StartsWith('#') })

$sourceCommit = [string](Invoke-Git rev-parse --verify "$SourceRef^{commit}")
$null = Invoke-Git fetch --quiet $Remote $Branch
$parent = [string](Invoke-Git rev-parse --verify 'FETCH_HEAD^{commit}')

# Build the filtered tree in a throwaway index so the real index and
# working copy are never touched.
$indexFile = Join-Path ([IO.Path]::GetTempPath()) ('github-mirror-index-' + [guid]::NewGuid().ToString('N'))
$previousIndex = $env:GIT_INDEX_FILE
try {
    $env:GIT_INDEX_FILE = $indexFile
    $null = Invoke-Git read-tree $sourceCommit
    foreach ($path in $excluded) {
        $null = Invoke-Git rm -r --cached --quiet --ignore-unmatch -- $path
    }
    $tree = [string](Invoke-Git write-tree)
}
finally {
    # Cleanup must run even under -WhatIf, or later git commands in this
    # session would keep using the throwaway index.
    [Environment]::SetEnvironmentVariable('GIT_INDEX_FILE', $previousIndex, 'Process')
    Remove-Item -LiteralPath $indexFile -Force -ErrorAction SilentlyContinue -WhatIf:$false
}

$leaks = @(Invoke-Git ls-tree -r --name-only $tree | Where-Object { $_ -match $blockedPattern })
if ($leaks.Count) {
    throw "Refusing to publish. These files would reach GitHub; add them to maintenance/github-mirror-exclude.txt:`n  $($leaks -join "`n  ")"
}

if ($tree -eq [string](Invoke-Git rev-parse "$parent^{tree}")) {
    Write-Host "GitHub $Branch already matches $SourceRef (filtered). Nothing to publish."
    return
}

$shortSource = $sourceCommit.Substring(0, 12)
$message = "Mirror of $SourceRef at $shortSource`n`nFiles listed in maintenance/github-mirror-exclude.txt are kept on GitLab only."
$mirrorCommit = [string](Invoke-Git commit-tree $tree -p $parent -m $message)

if ($PSCmdlet.ShouldProcess("$Remote/$Branch", "Push filtered mirror of $shortSource")) {
    $null = Invoke-Git push $Remote "${mirrorCommit}:refs/heads/$Branch"
    Write-Host "Published $shortSource to $Remote/$Branch as $($mirrorCommit.Substring(0, 12)), without $($excluded.Count) excluded path(s)."
}

# SIG # Begin signature block
# MIIsWQYJKoZIhvcNAQcCoIIsSjCCLEYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC6RuakSKu+Dmeh
# QFc+Jg8aiQQByDBRJjz2/rhquD41o6CCJX4wggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYg
# MjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphB
# cr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6p
# vF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHe
# HYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEd
# gkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjU
# jsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bR
# VFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeS
# LsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIV
# NSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL
# 6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2Zd
# SoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFU
# eEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEw
# DQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/
# T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQ
# E7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9r
# EVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y
# 1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gx
# dEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3t
# y9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcy
# tL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEB
# YTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud
# /v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiS
# uEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZP
# ubdcMIIG7TCCBNWgAwIBAgIQCE/cM09+RU7bww+P+ZIYNTANBgkqhkiG9w0BAQsF
# ADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hB
# MjU2IDIwMjUgQ0ExMB4XDTI2MDgwNTAwMDAwMFoXDTM3MTEwNDIzNTk1OVowYzEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJE
# aWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjYg
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALZ7pvLJ/s1K+NSbTGWz
# /TjGMPh8CQ6RucZCLv5anHzWJjF/NWJrFIhy24fcpKXlgRiky4WAawDfU3YP0BMx
# t9l3Dm5oCG5Z69AqEN1kgHg2epx+l+lZBcmJCcN0ASURML5uFIS80sZsDwO3BSkU
# xDjLJhBI+qiZP3aixAC/qEGLjsBNlLol9VZ7pfGEXiMlneJIC5/YKuizVzNFKZZE
# eoy/0B8Zm+nzKBgSWG52lCO1w+nCg6XpCtklTJXeIg283hw7TmmsZXR+SMbjbrEO
# vZ3fP2VxIgeR28Y90ZStd3F9VuA5RVynb/whITPAo9b75Zr4Ta6Mj3URm26QZYMn
# /FnbuTegcoRcFEZ9FOqM5T6MTdtr/n74lIT/ug0eeOzmZ6QTFg33otX+bFRsIolv
# ykE1jive4PuESaT8zzVeFWDAMDtozNgLctkGD1ZjkEyZtJrLl5ya0m5doH/ScpaZ
# CZVl6pNUOCybMc/kxC6EAmSJY24L0yYKD1Nkddsnb/ItVKi/2nXpQNMu1PT5prW8
# 3vV8d67WowuUs0HdY4H8AMLGvdL/WHEj3ZnqMqAQQP9u3Ai9t+5eQ02GDwy0ODjd
# zi0xlp70W+ow63/0++YDEX1M0iwgUHwbrJvfpklkZQvw3+kv3vUPItdwroczk9ic
# flf55W1zOEKAcJVAIXpcMCU9AgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0G
# A1UdDgQWBBQUyWOKMC7USvtulPPm40B+9ezN4jAfBgNVHSMEGDAWgBTvb1NK6eQG
# fHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEy
# NTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hB
# MjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQCNxTphHp1SCt+ZrAmAfn0oQLFr0mLywSLaDXQI
# ENoyKqxrFbJblzCVP/pkXmwXOdrOpWygLzlT12os5ipDCy35RBCg2UMeApEtrfGh
# z45F4Wt4WGdNdIbRWt3YTYJmpR+b7lr4d7Uwn+H600u4D7RnOGf8Wj4UNgAdZkfH
# hHv1mx9EVh71SJelcEN/oORSjXzdjfw1iZH9d8Nh/thn6hH23d+VsPAr6GAYyzSA
# 02nXD1nYLI7Ijmiv+xLCiYC41DSFYL3GhTiy0PxpawPtGRyaBVGzq+UiTfM8pD7K
# VyF5aQyWP4KhVGUUTnmm/RlYJoW3TiXA/+t0YcT2oRVBm3JETjajHug2AL+v5jht
# KVnd3D0rbHXEu27o+Q8p4sEWPMqKDB+qbceb6T/6WcwTwXmQ9lOCLLYcsQeSWmvK
# qzpAec9etE14jOQAzLKWdE3w/TCaKtLRaRT7LCkRYVnhA2D73FLje1O5b3HR5eHs
# 0NzU/+xX7NbEdcofy0W3Wdwd1XOqtlpg/JgwtKfZM5dqO94lbUveOiJBI+xZEbGR
# sMNbXmMREUTgu+Oca7Y73MPWcslIx2VhkSKSXjDbD6rgg39H5Mh7QfieAIjWagkJ
# Nt68Yfim6cjEzVSiLSeZfdkr5dtFPTW6jATlWJdYeeDRGCyatf8R1hSjzSvdN8yW
# QPT9gzCCB4kwggZxoAMCAQICExIAI8GhPULglG3PUeAAAAAjwaEwDQYJKoZIhvcN
# AQELBQAwPjETMBEGCgmSJomT8ixkARkWA25ldDETMBEGCgmSJomT8ixkARkWA2Rv
# aTESMBAGA1UEAxMJRE9JSU1DQTMxMB4XDTI2MTEwNjIwMTA1OVoXDTI3MTEwNjIw
# MTA1OVowgYsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEPMA0GA1UEBxMGWWFr
# aW1hMR8wHQYDVQQKExZEZXBhcnRtZW50IG9mIEludGVyaW9yMRMwEQYDVQQDEwpT
# YW0gQ2FybWFuMSgwJgYJKoZIhvcNAQkBFhlzYW11YWxfY2FybWFuQGlvcy5kb2ku
# Z292MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAswHrlCEAF//oRE2y
# E+hgqXP9MB7F4Tzc9r1pMupaEsER6vJxyCmXsoBjHE1g/Tp7dKtls9fTagTGMd1w
# wVhCiFend30dYqF9FywoQCUvxaaAjdMb0WktLUfF/5ulJdchrcVLXfdRUDqapfQe
# 0KdficqSfyBWsND8CvUbRkyDamwelMXF8ScZV/PUJONcEIpQTS6re1l5FkmQ9uqK
# EZcJ2TbqXsEicUokcTGkcODYz0Em7fz/ZBe8BD+t23j2oBBG9ZiNtuU6OLSCvSIw
# 6k9Vj71gq4OM61ZDG6KfP3iypameMAYVW99sa9FXSjgg1bjlEqhcizFLP1g0nl7k
# d0wDqj2xejmC1EnX1FvrH0y2YEESvwUUpcRcUP7JjxvLle3nqzOJ+o83D0Bxuu6H
# HDWsPDUKW+1AaDspLTV6oj0iy3p7daES7c3TM6/4iQrYKoYKm1ujZcQK49bm3WzY
# 71WN0AiYSAB4MzBD3qDzRhepZILkN4UGiKkK1H1I5AZ+OiRWVGzVvxmyEDtKOBjB
# 27oGYTQk5dnGvCJLact0dxDADF8E5YtRR57y+jAgOuk88cadCQ0Eup9lXwT28A2j
# fHWb7LhBVGSK7ZhyLTblpCfQKc/XL0Jb6LtLuvjdnCsfPbuzZTve3jaFeNYgXki+
# 1ND0QvUdqXrxdXQqqDBK5kO/8y0CAwEAAaOCAzAwggMsMAsGA1UdDwQEAwIHgDA9
# BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiF3tVJooJoh6mHI4fdh0yDtdcogSCH
# mKZNh7yeHgIBZAIBITAdBgNVHQ4EFgQU4al/vMfOhBmsEOeH/LjW9Wy4kOswHwYD
# VR0jBBgwFoAUnXdWAF7QaXl7W8AVZ23zWfFAYFQwggEwBgNVHR8EggEnMIIBIzCC
# AR+gggEboIIBF4aBsWxkYXA6Ly8vQ049RE9JSU1DQTMxLENOPUlJTkRFTklNQ0Ez
# MSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMs
# Q049Q29uZmlndXJhdGlvbixEQz1kb2ksREM9bmV0P2NlcnRpZmljYXRlUmV2b2Nh
# dGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludIY0
# aHR0cDovL0lJTkRFTklNQ0EzMS5kb2kubmV0L0NlcnRFbnJvbGwvRE9JSU1DQTMx
# LmNybIYraHR0cDovL3BraS5kb2kubmV0L0NlcnRFbnJvbGwvRE9JSU1DQTMxLmNy
# bDCCATYGCCsGAQUFBwEBBIIBKDCCASQwgaQGCCsGAQUFBzAChoGXbGRhcDovLy9D
# Tj1ET0lJTUNBMzEsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENO
# PVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9ZG9pLERDPW5ldD9jQUNlcnRp
# ZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTBV
# BggrBgEFBQcwAoZJaHR0cDovL0lJTkRFTklNQ0EzMS5kb2kubmV0L0NlcnRFbnJv
# bGwvSUlOREVOSU1DQTMxLmRvaS5uZXRfRE9JSU1DQTMxLmNydDAkBggrBgEFBQcw
# AYYYaHR0cDovL29jc3AuZG9pLmdvdi9vY3NwMBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYBBQUHAwMwDQYJKoZIhvcNAQELBQADggEB
# AAnLSgi8PVhQIdpgzOqaSYB/d8aAqXktevievNVRDw3Ko5U6h9LnIkV5UfVLcxh1
# B13Lq3apasyt2kS4On3VWZFM4kbI1kHKPbbdUqgG2WZU+0TaWkqaKg6+9Fyh1NNt
# YWy3FYFVccC1T3MInrAhCieOnLP2oJy1o3/Szu6twPZhSTsy9zAoQlDEZUPLG3yr
# Gmm0VCVml0hsCpVpzqW+ghT3cZI6vn92QhZogL1M2xNbYzHG6Fonz6Uuyp4Cq35M
# fXT8J5kd8x14GAFLtAlEUfQ3HsfVVwvWmU4oCcrPsJFz5M0Oo6a96yYsbi3Sx9SY
# xzKVYsFh7JTvZqyqabVR8NkwggqzMIIIm6ADAgECAhNMAAAAQk/heR1/eELxAAAA
# AABCMA0GCSqGSIb3DQEBCwUAMBUxEzARBgNVBAMTCkRPSVJvb3RDQTIwHhcNMjMw
# NjI2MTkyMTIyWhcNMjgwNjI2MTkzMTIyWjA+MRMwEQYKCZImiZPyLGQBGRYDbmV0
# MRMwEQYKCZImiZPyLGQBGRYDZG9pMRIwEAYDVQQDEwlET0lJTUNBMzEwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtHqFuPS36YqB1wlzOXNTo5Zx8yylH
# WLMzZjmea2NypX7LOfM7ce8JJ88PJk32x6q746aO/9rFBIkMcpv3KfK3l/1Rp8L0
# +gMrEa5yYhCp9gwz8JG1LcXi5TdLnABc1O9E59umJ4ZZEr8CBoQh4huAcGBb001L
# 6StASEbZNNwF2fc3M1VESMp7NjCL+hDflIN4+7VPyu3ItsGroksjmAYJ/JxftmBB
# xcrMFAml/Si+WBhJJ1a+WJFFMiI28l7HGMQcIuEfeokwqBiQkCWpD1Cr0k8W6t3B
# C/cT+4j7ppk/lL/0fJP5nI32Wl2U9AxkHInsfq5ZKwi+1e2dlUxB7d7/AgMBAAGj
# ggbRMIIGzTAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQUnXdWAF7QaXl7W8AV
# Z23zWfFAYFQwggTrBgNVHSAEggTiMIIE3jCCAg4GCWCGSAFlAwIBEzCCAf8wLwYI
# KwYBBQUHAgEWI2h0dHA6Ly9wa2kyLmRvaS5uZXQvbGVnYWxwb2xpY3kuYXNwMIIB
# ygYIKwYBBQUHAgIwggG8HoIBuABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABpAHMA
# cwB1AGUAZAAgAGIAeQAgAHQAaABlACAARABlAHAAYQByAHQAbQBlAG4AdAAgAG8A
# ZgAgAHQAaABlACAASQBuAHQAZQByAGkAbwByACAAYQByAGUAIABvAG4AbAB5ACAA
# ZgBvAHIAIABpAG4AdABlAHIAbgBhAGwAIAB1AG4AYwBsAGEAcwBzAGkAZgBpAGUA
# ZAAgAFUAUwAgAEcAbwB2AGUAcgBuAG0AZQBuAHQAIAB1AHMAZQAgAGEAbABsACAA
# bwB0AGgAZQByACAAdQBzAGUAIABpAHMAIABwAHIAbwBoAGkAYgBpAHQAZQBkAC4A
# IABVAG4AYQB1AHQAaABvAHIAaQB6AGUAZAAgAHUAcwBlACAAbQBhAHkAIABzAHUA
# YgBqAGUAYwB0ACAAdgBpAG8AbABhAHQAbwByAHMAIAB0AG8AIABjAHIAaQBtAGkA
# bgBhAGwALAAgAGMAaQB2AGkAbAAgAGEAbgBkAC8AbwByACAAZABpAHMAYwBpAHAA
# bABpAG4AYQByAHkAIABhAGMAdABpAG8AbgAuMIICyAYKYIZIAWUDAgETATCCArgw
# NAYIKwYBBQUHAgEWKGh0dHA6Ly9wa2kyLmRvaS5uZXQvbGltaXRlZHVzZXBvbGlj
# eS5hc3AwggJ+BggrBgEFBQcCAjCCAnAeggJsAFUAcwBlACAAbwBmACAAdABoAGkA
# cwAgAEMAZQByAHQAaQBmAGkAYwBhAHQAZQAgAGkAcwAgAGwAaQBtAGkAdABlAGQA
# IAB0AG8AIABJAG4AdABlAHIAbgBhAGwAIABHAG8AdgBlAHIAbgBtAGUAbgB0ACAA
# dQBzAGUAIABiAHkAIAAvACAAZgBvAHIAIAB0AGgAZQAgAEQAZQBwAGEAcgB0AG0A
# ZQBuAHQAIABvAGYAIAB0AGgAZQAgAEkAbgB0AGUAcgBpAG8AcgAgAG8AbgBsAHkA
# IQAgAEUAeAB0AGUAcgBuAGEAbAAgAHUAcwBlACAAbwByACAAcgBlAGMAZQBpAHAA
# dAAgAG8AZgAgAHQAaABpAHMAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABzAGgA
# bwB1AGwAZAAgAG4AbwB0ACAAYgBlACAAdAByAHUAcwB0AGUAZAAuACAAQQBsAGwA
# IABzAHUAcwBwAGUAYwB0AGUAZAAgAG0AaQBzAHUAcwBlACAAbwByACAAYwBvAG0A
# cAByAG8AbQBpAHMAZQAgAG8AZgAgAHQAaABpAHMAIABjAGUAcgB0AGkAZgBpAGMA
# YQB0AGUAIABzAGgAbwB1AGwAZAAgAGIAZQAgAHIAZQBwAG8AcgB0AGUAZAAgAGkA
# bQBtAGUAZABpAGEAdABlAGwAeQAgAHQAbwAgAGEAIABEAGUAcABhAHIAdABtAGUA
# bgB0ACAAbwBmACAAdABoAGUAIABJAG4AdABlAHIAaQBvAHIAIABTAGUAYwB1AHIA
# aQB0AHkAIABPAGYAZgBpAGMAZQByAC4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBD
# AEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUv4Yr
# yvNsbT5fHDtOTtiN52rHak8wgfgGA1UdHwSB8DCB7TCB6qCB56CB5IaBsmxkYXA6
# Ly8vQ049RE9JUm9vdENBMixDTj1JSU5ERU5PUkNBMDEsQ049Q0RQLENOPVB1Ymxp
# YyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24s
# REM9ZG9pLERDPW5ldD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2Jq
# ZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnSGLWh0dHA6Ly9wa2kyLmRvaS5u
# ZXQvQ2VydEVucm9sbC9ET0lSb290Q0EyLmNybDBWBggrBgEFBQcBAQRKMEgwRgYI
# KwYBBQUHMAKGOmh0dHA6Ly9wa2kyLmRvaS5uZXQvQ2VydEVucm9sbC9JSU5ERU5P
# UkNBMDFfRE9JUm9vdENBMi5jcnQwDQYJKoZIhvcNAQELBQADggIBAMbtHUPT3Ocf
# H5/9kVgDdyf1HFB027B+OSxmoscIkz7DnLzO81etLLuw0V96cr860q8LzxInZOhI
# vCBng5cK9ha4qq9kawGxjT9qwUsFja6K3Ch84cchR87ftm0bedzi8OW4eCE1hp89
# 0+7Uh61tYLplfShqxVXbc6IB4bS1jO3axUw1TmypGgtnEu2poBX8pvqxyckf5H/D
# ERTFKCdmTGVX/gr4+dhaZ4CAzX88pc1GTczqBlhn0SQG3jQW1Hwz300X/liKe/Jo
# SENa6KUbxyPFiZjrPyrWuu/5M0vaul9SLrltHboX/SMety1OmnVqcBIAfO1pK3l1
# QwPDeyTy2JilsZu+7rzn0HoGA/RxspvdPvlI628mNydllpqk8PEw+/6K0fvOvOtw
# fUJftOKXFQIAUp3oaLMitII77VF+XnNyssu/FvijE7PTvrdf/p7wJdhkz3a9fNmW
# JxLCT3SppcDofYElY1fF5zxjMXDns4ZMkEzuXNQVqA+RxJSFdkN6x1CKT3h0W/GA
# zPw1UHQS4krX7xfBCN+hB8AS0VbSedkdSBnKflOSoUW9VsgFFDpTV9RLeDlbNh9h
# +eZgobVUKTZf7jcply4LsBb8nHACJz6ErFIh7ltNHZ/GlCBRP8mvYZRMAg3XgUtc
# 50DYYTKR0le9oluxLNSKnSXN6A8p7Ne4MYIGMTCCBi0CAQEwVTA+MRMwEQYKCZIm
# iZPyLGQBGRYDbmV0MRMwEQYKCZImiZPyLGQBGRYDZG9pMRIwEAYDVQQDEwlET0lJ
# TUNBMzECExIAI8GhPULglG3PUeAAAAAjwaEwDQYJYIZIAWUDBAIBBQCggYQwGAYK
# KwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIB
# BDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg
# SK/riC8xUtaaySZwNlW5NQXtIhGhovzjOd3ptM1SLZ8wDQYJKoZIhvcNAQEBBQAE
# ggIAZFqvDRNwcio6g7XOGGoYqqyfPmzkKEUztx9+ImcU6vDY0XEsfQ1T7UQMssqA
# uqHlK6NvTwTUW5+Inebc12N9sLoEPfvlFcCVaXZR/j/o7YfHpMCAXn1oxjKeE5Gu
# uavGOe2+tu+ZhMb6qX3uDz//tdJH/jCqYr6OimmdYGeRdxLNu74kLZEV26GRNl5q
# b19WSQ/A2++iEJAHS7RM+n/SvaEcNlI2WnkVx75mAufx8FzdzR0YuVNyJAgDGfzV
# HViyyxCp4ytp/YhLpXHj1XyV6df18d2PiFdVlfHNXCrxtXo/6QQYsraO5LTZ7WGo
# ZSjEVPZfmO2CdQ4eXeNxuIhBCrUehmNqG/Po+bcoMUs1OH+CHwWjBmzauNpvhBhz
# 6UK04JyC3moDQOYAcWzSvLpqltHrIKjywP465iJm8yXo/VCd3cc5AAgHZCa2G9Gm
# MPYd0vxsy2RX4XRHKra/2qBkN6jg7K1FulAt3HTOvAnvjPMXvQ8onaOgaH0MZdgj
# 3tuKLBsIVdePX9Cuos/hqcGCcz4qiHHv6ZBlzVqI0puEaz4Avc/9M3gWGCDIzsKo
# qwZdFMxD/qaZJb7E0LfOjjXmncm0OciO31WHkuEv/A2/+pkjVbq3PuKQjXHv4hS/
# EjXefuVzQlziz6VMIFcM/dsLwzyeVno7ZQ5zBpZ3O3lLKjGhggMmMIIDIgYJKoZI
# hvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0
# YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAIT9wzT35FTtvDD4/5khg1
# MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkq
# hkiG9w0BCQUxDxcNMjYxMTA2MjM1ODUyWjAvBgkqhkiG9w0BCQQxIgQgwBDRcwWD
# x3CSux/3WTcBjEKATfMDbraweaOQ/ZDmzG8wDQYJKoZIhvcNAQEBBQAEggIAK58U
# 5RS2N0eP+9XiWLeb7uHoa3wWvWQ0Ng9t93pN0DIOIhtHY+PWNM1mYUzaRpQaZEdU
# 7gD0zSu1TlDcj2dimZcJ3hBin8eSjdPHoW5aQvfyBTfnxUsz8I2pTmQvIAydkbpj
# t9kXvo8qd2RwZvsbip4DN8+WuDx+DiArjmel+Nb05nycYv6L70wtwf9pFZOVuPUU
# p3zTciGwIEvtwIgWcQMs8bYLRVTY5KVSW+xnoEi8fyHr/umZB+lsReErMSi/WOsh
# 0afWZc2pM2W6rHjkFG0u7XhGw7VmOBweZ/xx51CoLBHkgqXFh2ONzx5tRuRoX0VU
# i+EAhjmE5sPn9ZH+lEDm/FFLFODxjj/cbtGy4PHn85YMcE78X7WUi2KVf2Qy5iOl
# hp7xBsWy5FVBWNRpNhh4zvTcLahK3Qtbafm/KjlP1C/BASdp8CTMiv7EHp07OTeW
# GOOl7WovZ5g6OpXg4u8avCigcAZospp9m6fMH5nrH+b6J+LyLfLfcbm4dn7Wg8ir
# 0Ly+PEH9K8gnex3VbJxcDcUWomma0aLjW9rVcSwaIp4DRDfkXZmLIB1xvKsbRodc
# /rwRVIkbWTnkCSMHFtsi6xpfL/Fzv3O6f4063m58hORz38gUdpvh6J05uroEwBAn
# 4HtfEPWWUFjpecmMc2kA2ZSSujMxszZ7GjldfH4=
# SIG # End signature block
