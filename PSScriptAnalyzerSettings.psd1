@{
    # PSAvoidUsingWriteHost is excluded because Write-Host is this repo's
    # deliberate, consistent convention for interactive console output
    # (paired with Write-Log/transcript logging for the real audit trail) -
    # not an oversight. Leaving the rule on drowns real findings: as of
    # 2026-09-07 it alone accounted for ~550 of 755 PSScriptAnalyzer results
    # across the library.
    #
    # PSReviewUnusedParameter is excluded because it only looks for a
    # parameter's use in the same scope. Script parameters here are usually
    # read inside helper functions, so on 2026-11-06 it reported 39 findings
    # and only 1 was real. Tests/Library.Tests.ps1 replaces it with a check
    # for parameters that are never referenced anywhere in the file.
    ExcludeRules = @('PSAvoidUsingWriteHost', 'PSReviewUnusedParameter')
}
