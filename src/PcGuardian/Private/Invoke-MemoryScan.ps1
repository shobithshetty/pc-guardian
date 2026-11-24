function ConvertFrom-HollowsHunterReport {
    <#
    .SYNOPSIS
        Turns HollowsHunter's JSON summary into findings.
    .DESCRIPTION
        The summary always has the counts. When something is suspicious the report may also name the processes
        (an object with a pid and a name); those are listed when present. If the counts say something is
        suspicious but no names can be read, one generic finding is returned so the result is never lost.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Json)

    $start = $Json.IndexOf('{')
    if ($start -lt 0) { return }
    try { $doc = $Json.Substring($start) | ConvertFrom-Json -ErrorAction Stop } catch { return }
    $count = 0
    if ($doc.PSObject.Properties['suspicious_count']) { $count = [int]$doc.suspicious_count }
    if ($count -le 0) { return }

    $names = New-Object System.Collections.Generic.List[string]
    $walk = $null
    $walk = {
        param($node)
        if ($null -eq $node) { return }
        if ($node -is [System.Collections.IEnumerable] -and $node -isnot [string]) { foreach ($n in $node) { & $walk $n }; return }
        if ($node -isnot [psobject] -or $node -is [string] -or $node.GetType().IsPrimitive) { return }
        $props = @($node.PSObject.Properties | ForEach-Object { $_.Name })
        if ($props -contains 'pid') {
            $nm = foreach ($p in 'name', 'process_name', 'proc_name') { if ($props -contains $p -and "$($node.$p)") { "$($node.$p)"; break } }
            if ($nm) { $leaf = Split-Path "$nm" -Leaf; if ($leaf -and -not $names.Contains($leaf)) { $names.Add($leaf) } }
        }
        foreach ($p in $props) { & $walk $node.$p }
    }
    & $walk $doc

    if ($names.Count -gt 0) {
        foreach ($n in $names) {
            New-Finding -Category 'Memory' -Key "Memory:$n" -Detail "Code in memory of the running program $n looks injected, hollowed or patched. Sometimes legitimate (security tools, game anti-cheat, some installers); unexpected if you don't run anything like that."
        }
    } else {
        New-Finding -Category 'Memory' -Key 'Memory:Suspicious' -Detail "$count running program(s) have code in memory that looks injected or patched. The scanner did not name them; run it again as administrator or see the scanner's own report."
    }
}

function Invoke-MemoryScan {
    <#
    .SYNOPSIS
        Looks for injected or hollowed code inside running programs with HollowsHunter (read-only).
    .DESCRIPTION
        Runs the downloaded, hash-checked HollowsHunter with options that write nothing, kill nothing and suspend
        nothing. Without administrator rights, protected programs cannot be inspected; those are skipped.
    .PARAMETER ReportJson
        Use this report text instead of running the scanner (used by tests).
    #>
    [CmdletBinding()]
    param([string]$ReportJson)

    if (-not $PSBoundParameters.ContainsKey('ReportJson')) {
        $d = Find-GuardianDetector
        if (-not $d.HollowsHunter) {
            return New-Finding -Category 'Scanner' -Key 'Memory:NotInstalled' -Detail 'The in-memory scanner is not downloaded; memory check skipped.'
        }
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('pcg-hh-' + [guid]::NewGuid())
        New-Item -ItemType Directory -Force -Path $tmp | Out-Null
        try {
            Write-GuardianProgress -Type file -Value 'Inspecting running programs (about two minutes)'
            # /ofilter 2 = write no dump files. /dnet 4 = skip normal .NET behavior that looks like injection.
            # Never /kill or /suspend.
            $ReportJson = (& $d.HollowsHunter /json /quiet /ofilter 2 /dnet 4 /dir $tmp 2>&1 | Out-String)
        }
        finally { Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $findings = @(ConvertFrom-HollowsHunterReport -Json $ReportJson)
    foreach ($f in $findings) { Write-GuardianFound -Finding $f }
    $findings
}
