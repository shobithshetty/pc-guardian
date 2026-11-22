function Test-YaraRuleUsesExternals {
    <#
    .SYNOPSIS
        $true when a rule file depends on values only a full scanner supplies (file name, path, extension...).
    .DESCRIPTION
        pc-guardian runs yara with no external variables. A rule that tests `filename`, `filepath`,
        `extension`, `filetype` or `owner` then compares against an empty value, which can match everything
        or nothing. Such files are left out of the compiled set.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $text = Get-Content -Path $Path -Raw -ErrorAction SilentlyContinue
    if (-not $text) { return $false }

    # Strip // line comments and /* */ blocks so a word in a comment does not count.
    $code = [regex]::Replace($text, '(?s)/\*.*?\*/', ' ')
    $code = [regex]::Replace($code, '(?m)//.*$', ' ')
    # An external is used when its bare name is followed by an operator (==, !=, matches, contains,
    # icontains, startswith, endswith, iequals), as in `filename matches /x/` or `extension == ".dll"`.
    $ops = '(==|!=|matches|contains|icontains|startswith|istartswith|endswith|iendswith|iequals)'
    return [bool]($code -match "(?m)(?<![\w`"/.\$#@])(filename|filepath|extension|filetype|owner)\s+$ops\b" -or
                  $code -match "(?m)(?<![\w`"/.\$#@])(filename|filepath|extension|filetype|owner)\s*(==|!=)")
}
