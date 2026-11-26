function ConvertFrom-HayabusaTimeline {
    <#
    .SYNOPSIS
        Turns Hayabusa's JSON-lines timeline into one finding per detection rule.
    .DESCRIPTION
        Many log events usually match the same rule, so they are grouped: "rule name, how many times, most recent".
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][AllowEmptyString()][string[]]$Line)

    $rows = foreach ($l in @($Line)) {
        if (-not $l -or -not $l.TrimStart().StartsWith('{')) { continue }
        try { $l | ConvertFrom-Json -ErrorAction Stop } catch { }
    }
    $rows = @($rows | Where-Object { $_ -and $_.RuleTitle })
    foreach ($g in ($rows | Group-Object RuleTitle)) {
        $items = @($g.Group)
        $level = "$($items[0].Level)"
        $latest = ($items | ForEach-Object { "$($_.Timestamp)" } | Sort-Object | Select-Object -Last 1)
        $title = ("$($g.Name)" -replace '[\r\n]+', ' ')
        $detail = "{0} event(s) matched this detection rule (level: {1}), most recent {2}. Detection rules can false-positive; see the event details in the Windows Event Viewer." -f $items.Count, $level, $latest
        New-Finding -Category 'EventLog' -Key "EventLog:$title" -Detail $detail
    }
}

function Invoke-EventLogScan {
    <#
    .SYNOPSIS
        Hunts the last 30 days of Windows event logs for suspicious activity with Hayabusa (read-only).
    .DESCRIPTION
        Runs the downloaded, hash-checked Hayabusa with its bundled Sigma-based rules against this PC's own logs,
        high and critical rules only. It writes only a temporary timeline file, which is deleted afterwards.
        Without administrator rights it cannot read the Security log, so some detections are not possible.
    .PARAMETER TimelineLine
        Use these timeline lines instead of running the scanner (used by tests).
    #>
    [CmdletBinding()]
    param([string[]]$TimelineLine)

    if (-not $PSBoundParameters.ContainsKey('TimelineLine')) {
        $d = Find-GuardianDetector
        if (-not $d.Hayabusa) {
            return New-Finding -Category 'Scanner' -Key 'EventLog:NotInstalled' -Detail 'The event-log scanner is not downloaded; event-log check skipped.'
        }
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('pcg-hb-' + [guid]::NewGuid())
        New-Item -ItemType Directory -Force -Path $tmp | Out-Null
        $outFile = Join-Path $tmp 'timeline.jsonl'
        Push-Location $d.HayabusaDir
        try {
            Write-GuardianProgress -Type file -Value 'Reading the last 30 days of Windows event logs'
            & $d.Hayabusa dfir-timeline -l -w -q -N -K -Q -C -m high --time-offset 30d -t jsonl -o $outFile 2>&1 | Out-Null
            # No detections means no file or an empty one; an `if` that yields @() would give $null, so wrap it.
            $TimelineLine = @(if (Test-Path $outFile) { Get-Content -Path $outFile })
        }
        finally { Pop-Location; Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $findings = @(ConvertFrom-HayabusaTimeline -Line $TimelineLine)
    foreach ($f in $findings) { Write-GuardianFound -Finding $f }
    $findings
}
