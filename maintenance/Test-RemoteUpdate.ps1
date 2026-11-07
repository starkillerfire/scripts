[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$template = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'RemoteUpdate.template.ps1'))
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseInput($template, [ref]$tokens, [ref]$errors)
$functionAst = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Update-LibraryScript' }, $true)
. ([scriptblock]::Create($functionAst.Extent.Text))
$sandbox = Join-Path $root ('ScriptLibraryUpdateTests-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $sandbox
$originalSkip = $env:SCRIPT_LIBRARY_SKIP_UPDATE
$originalLauncher = $env:SCRIPT_LIBRARY_ACTIVE_LAUNCHER
$originalGithubToken = $env:SCRIPT_LIBRARY_GITHUB_TOKEN
$originalGitlabToken = $env:SCRIPT_LIBRARY_GITLAB_TOKEN
$originalSigners = $env:SCRIPT_LIBRARY_SIGNER_THUMBPRINTS
$script:checks = 0
function Assert-True($Condition, [string]$Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
    $script:checks++
}
function Invoke-RestMethod {
    [CmdletBinding()]
    param($Uri, $Headers, $TimeoutSec, $MaximumRedirection)
    $script:requests += [pscustomobject]@{ Uri = $Uri; Headers = $Headers }
    $github = $Uri -like 'https://api.github.com/*'
    if ($script:scenario -eq 'offline' -or ($script:scenario -eq 'gitlab' -and $github) -or ($script:scenario -eq 'github' -and -not $github)) { throw 'Mock offline' }
    if ($script:scenario -eq 'emptyPrimary' -and -not $github) { return }
    $date = if ($script:scenario -eq 'old' -or ($script:scenario -eq 'authoritativeOld' -and -not $github)) { '2026-01-01T00:00:00Z' }
        elseif ($github) { '2026-11-07T00:00:00Z' } else { '2026-11-08T00:00:00Z' }
    if ($script:scenario -eq 'secondUpdate') { $date=$script:secondUpdateDate }
    if ($github) { [pscustomobject]@{ sha = ('a' * 40); commit = @{ committer = @{ date = $date } } } }
    elseif ($script:scenario -eq 'malformedPrimary') { [pscustomobject]@{ id = 'invalid'; committed_date = $date } }
    else { [pscustomobject]@{ id = ('b' * 40); committed_date = $date } }
}
function Get-AuthenticodeSignature {
    [CmdletBinding()]
    param($LiteralPath)
    $isDownload = $LiteralPath -match '\.download\.'
    if ($script:scenario -eq 'localInvalid') { return [pscustomobject]@{Status='HashMismatch';SignerCertificate=$null} }
    if ($script:scenario -eq 'localUnsigned') { return [pscustomobject]@{Status='NotSigned';SignerCertificate=$null} }
    if ($script:scenario -eq 'localWrong') { return [pscustomobject]@{Status='Valid';SignerCertificate=@{Thumbprint=('D'*40)}} }
    if ($script:scenario -eq 'signedDowngrade' -and $isDownload) {
        [pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null }
    } elseif ($script:scenario -eq 'signedDowngrade' -and -not $isDownload) {
        [pscustomobject]@{ Status = 'Valid'; SignerCertificate = @{ Thumbprint = 'CEFA4DF2F31F5218A3F3B28144AFD9A96770A315' } }
    } elseif ($script:scenario -eq 'signedApproved') {
        [pscustomobject]@{ Status = 'Valid'; SignerCertificate = @{ Thumbprint = 'CEFA4DF2F31F5218A3F3B28144AFD9A96770A315' } }
    } elseif ($script:scenario -eq 'signedWrong' -and $isDownload) {
        [pscustomobject]@{ Status = 'Valid'; SignerCertificate = @{ Thumbprint = ('D' * 40) } }
    } else { [pscustomobject]@{ Status = 'Valid'; SignerCertificate = @{ Thumbprint = 'CEFA4DF2F31F5218A3F3B28144AFD9A96770A315' } } }
}
function Invoke-WebRequest {
    [CmdletBinding()]
    param($Uri, $Headers, [switch]$UseBasicParsing, $OutFile, $TimeoutSec, $MaximumRedirection)
    $script:downloads += $Uri
    if ($script:scenario -eq 'fallback' -and $Uri -like 'https://gitlab*') { throw 'Mock failed download' }
    $payload = switch ($script:scenario) {
        'html' { '<html>Login required</html>' }
        'invalid' { "# BEGIN SCRIPT LIBRARY REMOTE UPDATE`nfunction {" }
        'legacy' { 'Write-Output legacy' }
        'identical' { $script:original }
        'batch' { $script:batchPayload }
        'secondUpdate' { $script:secondUpdatePayload }
        default { "# BEGIN SCRIPT LIBRARY REMOTE UPDATE`nWrite-Output 'updated'" }
    }
    [IO.File]::WriteAllText($OutFile, $payload)
}
try {
    $env:SCRIPT_LIBRARY_SKIP_UPDATE = $null
    $env:SCRIPT_LIBRARY_ACTIVE_LAUNCHER = $null
    $env:SCRIPT_LIBRARY_GITHUB_TOKEN = 'mock-github-token'
    $env:SCRIPT_LIBRARY_GITLAB_TOKEN = 'mock-gitlab-token'
    $env:SCRIPT_LIBRARY_SIGNER_THUMBPRINTS = $null
    foreach ($scenario in @('offline', 'old', 'newest', 'gitlab', 'github', 'fallback', 'authoritativeOld', 'emptyPrimary', 'malformedPrimary', 'html', 'invalid', 'legacy', 'identical', 'signedDowngrade', 'signedWrong', 'signedApproved')) {
        $script:scenario = $scenario
        $script:requests = @()
        $script:downloads = @()
        $file = Join-Path $sandbox ($scenario + '.ps1')
        $script:original = "# BEGIN SCRIPT LIBRARY REMOTE UPDATE`nWrite-Output 'original'"
        [IO.File]::WriteAllText($file, $script:original)
        $env:SCRIPT_LIBRARY_SIGNER_THUMBPRINTS = if ($scenario -eq 'signedWrong') { 'C' * 40 } else { $null }
        Update-LibraryScript -LocalPath $file -RepositoryPath 'Folder With Spaces/Script.ps1' -Baseline '2026-11-06T00:00:00Z' -WarningAction SilentlyContinue
        $expectedChecks = if ($scenario -in @('offline','github')) { 2 } else { 1 }
        Assert-True ($script:requests.Count -eq $expectedChecks) "$scenario checks secondary only when primary is unavailable"
        Assert-True ($script:requests[0].Uri -like 'https://gitlab.bor.doi.net/*') 'GitLab checked first'
        foreach ($request in $script:requests) {
            if ($request.Uri -like 'https://api.github.com/*') { Assert-True (-not $request.Headers.ContainsKey('PRIVATE-TOKEN')) 'GitLab token never sent to GitHub' }
            else { Assert-True (-not $request.Headers.ContainsKey('Authorization')) 'GitHub token never sent to GitLab' }
        }
        if ($scenario -in @('newest', 'gitlab', 'github', 'signedApproved')) {
            Assert-True (([IO.File]::ReadAllText($file)) -match 'updated') "$scenario replaces installed script"
            Assert-True (([IO.File]::ReadAllText($file + '.bak')) -eq $script:original) "$scenario preserves backup"
            $state = Get-Content -LiteralPath ($file + '.update.json') -Raw | ConvertFrom-Json
            $expected = if ($scenario -eq 'github') { 'GitHub' } else { 'GitLab' }
            Assert-True ($state.Source -eq $expected) "$scenario selects correct provider"
            $script:downloads = @()
            Update-LibraryScript -LocalPath $file -RepositoryPath 'Folder With Spaces/Script.ps1' -Baseline '2026-11-06T00:00:00Z' -WarningAction SilentlyContinue
            Assert-True ($script:downloads.Count -eq 0) "$scenario avoids reinstalling recorded commit"
        } else {
            Assert-True (([IO.File]::ReadAllText($file)) -eq $script:original) "$scenario preserves existing script"
            Assert-True (-not (Test-Path -LiteralPath ($file + '.bak'))) "$scenario does not create backup"
        }
    }
    $env:SCRIPT_LIBRARY_SKIP_UPDATE = '1'
    $script:requests = @()
    Update-LibraryScript -LocalPath $file -RepositoryPath 'skip.ps1' -Baseline '2026-11-06T00:00:00Z'
    Assert-True ($script:requests.Count -eq 0) 'Disable flag prevents network requests'
    $env:SCRIPT_LIBRARY_SKIP_UPDATE = $null
    $env:SCRIPT_LIBRARY_SIGNER_THUMBPRINTS = $null
    $guard=[regex]::Match($template,'(?ms)^# Verify the installed file.*?(?=^& \{)').Value.Replace('$PSCommandPath',"'fixture.ps1'")
    foreach($scenario in @('localInvalid','localUnsigned','localWrong')) {
        $script:scenario=$scenario;$script:operationalReached=$false;$blocked=$false
        try { & ([scriptblock]::Create($guard+"`n"+'$script:operationalReached=$true')) } catch { $blocked=$true }
        Assert-True ($blocked -and -not $script:operationalReached) "$scenario rejected before operational code"
    }
    $script:scenario='newest';$script:operationalReached=$false
    & ([scriptblock]::Create($guard+"`n"+'$script:operationalReached=$true'))
    Assert-True $script:operationalReached 'Approved local signature allows operational code'
    $script:scenario='secondUpdate';$script:secondUpdateDate='2026-11-10T00:00:00Z'
    $script:secondUpdatePayload="# BEGIN SCRIPT LIBRARY REMOTE UPDATE`nWrite-Output 'first revision'"
    $twiceFile=Join-Path $sandbox 'two-updates.ps1'
    [IO.File]::WriteAllText($twiceFile,$script:original)
    Update-LibraryScript -LocalPath $twiceFile -RepositoryPath 'two-updates.ps1' -Baseline '2026-11-06T00:00:00Z'
    $firstRevision=$script:secondUpdatePayload
    $script:secondUpdateDate='2026-11-11T00:00:00Z';$script:secondUpdatePayload="# BEGIN SCRIPT LIBRARY REMOTE UPDATE`nWrite-Output 'second revision'"
    Update-LibraryScript -LocalPath $twiceFile -RepositoryPath 'two-updates.ps1' -Baseline '2026-11-06T00:00:00Z'
    Assert-True (([IO.File]::ReadAllText($twiceFile)) -eq $script:secondUpdatePayload) 'Second update replaces first revision'
    Assert-True (([IO.File]::ReadAllText($twiceFile+'.bak')) -eq $firstRevision) 'Second update retains the prior revision'
    $twiceState=Get-Content -LiteralPath ($twiceFile+'.update.json') -Raw | ConvertFrom-Json
    Assert-True ([datetimeoffset]$twiceState.CommittedAt -eq [datetimeoffset]$script:secondUpdateDate) 'State advances on subsequent updates'
    $script:requests = @()
    Update-LibraryScript -LocalPath $file -RepositoryPath 'preview.ps1' -Baseline '2026-11-06T00:00:00Z' -WhatIf
    Assert-True ($script:requests.Count -eq 0) 'WhatIf does not check, download, or replace updates'

    # Exercise the actual CMD preamble without running any administrative script.
    $batchText = [IO.File]::ReadAllText((Join-Path $root 'Autopilot/Autopilot-v2.bat'))
    $preamble = [regex]::Match($batchText, '(?ms)^REM BEGIN SCRIPT LIBRARY REMOTE UPDATE.*?^REM END SCRIPT LIBRARY REMOTE UPDATE\r?\n').Value
    Assert-True ($preamble.Length -gt 0) 'Batch launcher contains safe-update preamble'
    $batch = Join-Path $sandbox 'launcher.bat'
    $oldBatch = $preamble + "@echo off`r`necho OLD`r`nexit /b 7`r`n"
    $script:batchPayload = $preamble + "@echo off`r`necho NEW`r`nexit /b 9`r`n"
    # A synthetic signed companion exercises the actual authenticated CMD callback.
    $fixtureHashPath=Join-Path $sandbox 'callback-payload.txt'
    [IO.File]::WriteAllText($fixtureHashPath,$script:batchPayload)
    $fixtureHash=(Get-FileHash -LiteralPath $fixtureHashPath -Algorithm SHA256).Hash
    $callback=Join-Path $sandbox 'Autopilot-v2.ps1'
    $callbackText=@'
param([string]$LibraryPendingBatch)
if((Get-FileHash -LiteralPath ($LibraryPendingBatch+'.update.pending') -Algorithm SHA256).Hash -ne '__HASH__'){throw 'Invalid fixture hash'}
[IO.File]::Replace(($LibraryPendingBatch+'.update.pending'),$LibraryPendingBatch,($LibraryPendingBatch+'.bak'))
exit 0
'@
    [IO.File]::WriteAllText($callback,$callbackText.Replace('__HASH__',$fixtureHash),(New-Object Text.UTF8Encoding($true)))
    $fixtureCertificate=Get-Item Cert:/CurrentUser/My/CEFA4DF2F31F5218A3F3B28144AFD9A96770A315
    $fixtureSignature=Set-AuthenticodeSignature -LiteralPath $callback -Certificate $fixtureCertificate -HashAlgorithm SHA256
    Assert-True ($fixtureSignature.Status -eq 'Valid') 'Synthetic batch companion signature validates'
    [IO.File]::WriteAllText($batch, $oldBatch)
    $script:scenario = 'batch'
    $env:SCRIPT_LIBRARY_ACTIVE_LAUNCHER = $batch
    $hashPath = Join-Path $sandbox 'approved-batch.txt'
    [IO.File]::WriteAllText($hashPath, $script:batchPayload)
    $batchHash = (Get-FileHash -LiteralPath $hashPath -Algorithm SHA256).Hash
    Update-LibraryScript -LocalPath $batch -RepositoryPath 'launcher.bat' -Baseline '2026-11-06T00:00:00Z' -ExpectedSha256 ('0' * 64) -WarningAction SilentlyContinue
    Assert-True (-not (Test-Path -LiteralPath ($batch + '.update.pending'))) 'Unapproved batch hash is rejected'
    Update-LibraryScript -LocalPath $batch -RepositoryPath 'launcher.bat' -Baseline '2026-11-06T00:00:00Z' -ExpectedSha256 $batchHash
    Assert-True (([IO.File]::ReadAllText($batch)) -eq $oldBatch) 'Running batch remains unchanged'
    Assert-True (Test-Path -LiteralPath ($batch + '.update.pending')) 'Running batch update is staged'
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $env:ComSpec
    $start.Arguments = '/d /c .\launcher.bat'
    $start.WorkingDirectory = $sandbox
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    $output = $process.StandardOutput.ReadToEnd() + $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    $batchExit = $process.ExitCode
    $process.Dispose()
    Assert-True ($batchExit -eq 9) "Updated batch preserves exit code (actual $batchExit; output $output)"
    Assert-True ($output -match '(?m)^NEW\r?$') 'Next batch launch executes updated body'
    Assert-True (([IO.File]::ReadAllText($batch + '.bak')) -eq $oldBatch) 'Batch update retains backup'
    Assert-True (-not (Test-Path -LiteralPath ($batch + '.update.pending'))) 'Staged update consumed'

    $tracked = @(git -C $root ls-files '*.ps1' '*.psm1' | Where-Object { $_ -notlike 'maintenance/*' })
    foreach ($relative in $tracked) {
        $path = Join-Path $root $relative
        $text = [IO.File]::ReadAllText($path)
        $null = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
        Assert-True ($errors.Count -eq 0) "Syntax valid: $relative"
        Assert-True (([regex]::Matches($text, '(?m)^# BEGIN SCRIPT LIBRARY REMOTE UPDATE')).Count -eq 1) "Exactly one update block: $relative"
    }
    Write-Host "PASS: $script:checks assertions; mocked update and batch tests; all library scripts parsed."
} finally {
    $env:SCRIPT_LIBRARY_SKIP_UPDATE = $originalSkip
    $env:SCRIPT_LIBRARY_ACTIVE_LAUNCHER = $originalLauncher
    $env:SCRIPT_LIBRARY_GITHUB_TOKEN = $originalGithubToken
    $env:SCRIPT_LIBRARY_GITLAB_TOKEN = $originalGitlabToken
    $env:SCRIPT_LIBRARY_SIGNER_THUMBPRINTS = $originalSigners
    # Delete only the unique test directory verified beneath this workspace.
    $resolved = [IO.Path]::GetFullPath($sandbox)
    $tempRoot = [IO.Path]::GetFullPath($root) + [IO.Path]::DirectorySeparatorChar
    if ($resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -and (Split-Path $resolved -Leaf) -like 'ScriptLibraryUpdateTests-*') {
        for ($attempt = 1; $attempt -le 5; $attempt++) {
            try { Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction Stop; break }
            catch { if ($attempt -eq 5) { throw }; Start-Sleep -Milliseconds 300 }
        }
    }
}


# SIG # Begin signature block
# MIIsWQYJKoZIhvcNAQcCoIIsSjCCLEYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDLJ6H1GQxtj9Br
# LxGALZhiNRXjZ+3xVpjUopFwRIIPUaCCJX4wggWNMIIEdaADAgECAhAOmxiO+dAt
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
# WQe+JDIDVnRRRK1ZD5dAQpLiWZkaF3E7fUcmU16LIawwDQYJKoZIhvcNAQEBBQAE
# ggIAEUu9qdY5wF2xS2s3/gS6QVql8UiBGPhJwsTlCCqBH+OUuZ/qgVRZW8/GciqN
# oxs+Ew8ABf8P1cE/mEHhLz9iuyJm5Sv+tPTXhTWeeNTRWQYCR+6uD8axJm1sa1G6
# GjFmUb6+wxX5oALh8zYalbYPwbTanpMF8+AHUy9bni3OMM90Cl8CWlyjHQ/h3Dvc
# FOAcgDqIYCfRjIWjhBXV81p6szmcfGuczrKeJZbhXINl5F7dwfxKE46jAiCDtyM0
# VS/B6N/oOsFRlBOCCA/yTsaRZutQAzcrWunG9HYQKA+DUmb2kmo76uakyEdFLswc
# OazjDqL0yZOnGTy1o0k2qmIkflkt5GUJNlhyo35vFwJDji1j5buTS4pnzuW0m9Ec
# zlk88DFmCRRAyDs4ckragEd6SitzLsq/+HjwryLMPv24H1TWNliD+3zD4scSbirg
# QiYaZjfPt0lIyjICIooo0zWOcHCCCgrJr6VILxOYHkGJ+AqV3d2Gcz+tmPGc6Hsu
# Rger/DGKxGEjou4s5QKB2oNlae8kKtF+xAeSj1PmeWssJPsgxywDoGbJnrh2DZkS
# Et5xNi15oBvUUVNEkOZJ1nhUng2qe21WUqxY0AjX47hdGekbPbuyOm4HbFDXWeDi
# 4TDs2/2q5BSUDXmfobe+Xv/6JA2TMv4SA13QLOc2BCMkCN6hggMmMIIDIgYJKoZI
# hvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0
# YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAIT9wzT35FTtvDD4/5khg1
# MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkq
# hkiG9w0BCQUxDxcNMjYxMTA2MjM1ODUzWjAvBgkqhkiG9w0BCQQxIgQgS/lFnAtU
# 0SzvvL4QKxjDrz/n6/uCdZWHMHXKoQ3Y4uIwDQYJKoZIhvcNAQEBBQAEggIAmFEN
# uzrKurrVsK46XkF2JzzAKMAujSkMdUTKO3NeiR6bnE+xV/yNu7FByhbg5DBcf6q5
# h3n2puGsFHrRxzyrlKF4mzpdSp1e7vpsOyDb1pV6O8X57W8J048cqmZXJc2Zh455
# 0Tf9lauwzCX1VYHNGm4qiJf7hvn1faaxZeoiTyWBQU/d7LHGoDf1bOvTeg9Zpenz
# WvdLIAfHQA+YuUZSILToWpjHOqpEtnx9hqNkDiN8SPojTcqtcz+DLo3xUT5b1sMk
# S/t+3XesztDRMuJBzo58FKh3YP8B03vMWoDrjwJaNlB9w/6gBwnlidSURV45ue5c
# kKJb5u+p7QTtt9OJjW5Ur/w4Z7ul03dTRXanvOsLkSoZQBrmfdKXbtIu5h3fJ+2n
# jjO+k8RYZtqwE8wTEmF3i1t7MDgWnDKgjK1Mv+sbSPJi/uK1T/x1l0z/2euMQhXW
# HZXMGb4mW2Iwv+MUyAPC4tmLLmLSD0C/cTzBWfGxDAQ48jlQTMisqCwDgJhklYrH
# G+YdlNDASwF/bzJ3jApZTRY3S3jBJSA+GuGK8HotuD6ITi7KygxA02qmehR3P1Fx
# sNukb4ufutnSlmJ893IYUVwuk5HeltWEOR0mGTWmzD7QiDaNe22CvT1bhSg+2rWw
# QZ/f+l6t+bpZKfSgiSg3lKOcKQiVy42VItsPb6k=
# SIG # End signature block
