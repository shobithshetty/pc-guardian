function Find-Yara {
    <#
    .SYNOPSIS
        Locates yara64.exe and the compiled rule set in <data folder>\yara. $null if missing.
    #>
    [CmdletBinding()]
    param()
    $base = Join-Path (Get-GuardianDataPath) 'yara'
    $exe  = Join-Path $base 'bin\yara64.exe'
    if (-not (Test-Path $exe)) { return $null }
    [pscustomobject]@{
        Yara     = $exe
        Yarac    = (Join-Path $base 'bin\yarac64.exe')
        Rules    = (Join-Path $base 'rules.yarc')
        RuleDir  = (Join-Path $base 'rules')
    }
}

function Invoke-YaraScan {
    <#
    .SYNOPSIS
        Scans paths with YARA (read-only) and returns Malware findings for rule matches.
    .DESCRIPTION
        Uses a pre-compiled rule set. Rules that test filename or path run with placeholder values,
        so they stay quiet instead of guessing. Public rule sets can false-positive: treat a match as
        "look at this file", not proof of infection.
    .PARAMETER RulesPath
        Override the compiled rules file (used by tests).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Path,
        [string]$RulesPath
    )

    $y = Find-Yara
    if (-not $y) {
        return New-Finding -Category 'Scanner' -Key 'YARA:NotInstalled' -Detail 'YARA not found; rule scan skipped.'
    }
    $rules = if ($RulesPath) { $RulesPath } else { $y.Rules }
    if (-not (Test-Path $rules)) {
        return New-Finding -Category 'Scanner' -Key 'YARA:NoRules' -Detail 'Compiled YARA rules missing; rule scan skipped.'
    }

    $found = 0
    foreach ($p in $Path) {
        Write-GuardianProgress -Type file -Value $p
        # -r recurse, -w no warnings, -f fast mode, -a per-file timeout (s), -z skip files over ~50 MB
        # -m prints rule metadata so the rule author can be kept (required by the Detection Rule License).
        $yargs = @('-C', '-r', '-w', '-f', '-m', '-a', '30', '-z', '52428800', $rules, $p)
        $output = & $y.Yara @yargs 2>&1
        foreach ($line in $output) {
            $text = "$line"
            if ($text -match '^(error|warning)') { continue }
            if ($text -match '^(?<rule>[A-Za-z0-9_]+) (\[(?<meta>.*)\] )?(?<file>[A-Za-z]:\\.+|\\\\.+)$') {
                $found++
                $rule = $Matches.rule; $file = $Matches.file; $meta = $Matches.meta
                $author = 'unknown'
                if ($meta -and $meta -match 'author="(?<a>[^"]*)"') { $author = $Matches.a }
                $f = New-Finding -Category 'Malware' -Key "Malware:YARA:$file" `
                    -Detail "YARA rule $rule (author: $author) matched; public rules can false-positive, review the file"
                Write-GuardianFound -Finding $f
                $f
            }
        }
    }
    if ($found -eq 0 -and $LASTEXITCODE -gt 1) {
        New-Finding -Category 'Scanner' -Key 'YARA:Error' -Detail "yara exited with code $LASTEXITCODE"
    }
}
