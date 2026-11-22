function Invoke-GuardianRun {
    <#
    .SYNOPSIS
        Runs the read-only audit and compares it with the saved baseline.
    .DESCRIPTION
        First run saves a baseline. Later runs report findings that are new or removed since the baseline.
        Nothing on the system is modified; only files under -DataPath are written.
    .PARAMETER DataPath
        Where baseline.json, safe.json and last-report.txt are stored. Default: %LOCALAPPDATA%\PcGuardian
    .PARAMETER ResetBaseline
        Replace the baseline with the current snapshot.
    .PARAMETER AsObject
        Return one structured result (used by the app) instead of text lines.
    #>
    [CmdletBinding()]
    param(
        [string]$DataPath = (Join-Path $env:LOCALAPPDATA 'PcGuardian'),
        [switch]$ResetBaseline,
        # Also scan high-risk locations with ClamAV and YARA. Detections are always reported, never baselined.
        [switch]$Scan,
        # Opt-in: look up SHA-256 hashes (only hashes) of new unsigned executables on VirusTotal.
        # Needs a key from Set-GuardianVirusTotalKey. Sends data to virustotal.com.
        [switch]$VirusTotal,
        # Also list apps with newer winget versions (needs network). Config exposure checks always run.
        [switch]$CheckUpdates,
        # Hide the one-line support note printed after a run (it is never written to the report file).
        [switch]$NoDonateNote,
        [switch]$AsObject
    )

    $donateNote = if ($NoDonateNote -or $AsObject) { @() } else {
        @('', 'pc-guardian is free and open source. Support it: see the Sponsor button on the GitHub repo. Hide this line with -NoDonateNote.')
    }

    New-Item -ItemType Directory -Force -Path $DataPath | Out-Null
    $baselineFile = Join-Path $DataPath 'baseline.json'
    $reportFile   = Join-Path $DataPath 'last-report.txt'
    $safeKeys     = @(Get-GuardianSafeItem -DataPath $DataPath | ForEach-Object { $_.Key })
    # Findings you marked safe are hidden, except malware, which is always reported.
    $notSafe = { param($f) $f.Category -eq 'Malware' -or $f.Key -notin $safeKeys }

    $current = @(
        Get-DefenderAudit
        Get-StartupAudit
        Get-TaskAudit
        Get-PortAudit
        Get-AccountAudit
    )

    # Malware detections are never part of the baseline: a threat present on the first run must not become "normal".
    $scanFindings = @()
    if ($Scan -or $VirusTotal) {
        $scanPaths = @(Get-ClamAvScanPath -Findings $current)
        if ($Scan) {
            $scanFindings += @(Invoke-ClamAvScan -Path $scanPaths) + @(Invoke-YaraScan -Path $scanPaths)
        }
        if ($VirusTotal) {
            $scanFindings += @(Invoke-VirusTotalCheck -Path $scanPaths -DataPath $DataPath)
        }
    }
    # Exposures are reported on every run too, for the same reason: a day-one weakness must not become "normal".
    $exposureFindings = @(Get-ExposureAudit)
    if ($CheckUpdates) { $exposureFindings += @(Get-AppUpdateAudit) }
    $scanFindings     = @($scanFindings     | Where-Object { & $notSafe $_ })
    $exposureFindings = @($exposureFindings | Where-Object { & $notSafe $_ })

    $items = [System.Collections.Generic.List[object]]::new()
    function Add-RunItem($kind, $f) {
        $items.Add([pscustomobject]@{
            Kind = $kind; Severity = (Get-FindingSeverity -Finding $f)
            Category = $f.Category; Key = $f.Key; Detail = $f.Detail })
    }
    foreach ($f in $scanFindings)     { Add-RunItem 'Scan' $f }
    foreach ($f in $exposureFindings) { Add-RunItem 'Exposed' $f }

    $scanLines = @(
        $scanFindings | ForEach-Object {
            "[{0}] SCAN    {1} - {2}" -f (Get-FindingSeverity -Finding $_), $_.Key, $_.Detail
        }
        $exposureFindings | ForEach-Object {
            "[{0}] EXPOSED {1} - {2}" -f (Get-FindingSeverity -Finding $_), $_.Key, $_.Detail
        }
    )

    if ($ResetBaseline -or -not (Test-Path $baselineFile)) {
        ConvertTo-Json -InputObject @($current) -Depth 4 | Set-Content -Path $baselineFile -Encoding UTF8
        $msg = @("Baseline saved with $($current.Count) findings at $baselineFile. Run again later to see changes.") + $scanLines
        $msg | Set-Content -Path $reportFile -Encoding UTF8
        if ($AsObject) {
            return [pscustomobject]@{ Generated = (Get-Date -Format 's'); FirstRun = $true; BaselineCount = $current.Count; Items = @($items) }
        }
        $msg + $donateNote
        return
    }

    # Windows PowerShell 5.1 returns a JSON array as ONE object; the ForEach-Object unrolls it so
    # the baseline is a flat list on both 5.1 and 7 (without this every item showed as New).
    $baseline = @(Get-Content -Path $baselineFile -Raw | ConvertFrom-Json | ForEach-Object { $_ })
    $diff = Compare-Baseline -Baseline $baseline -Current $current
    $newItems     = @($diff.New     | Where-Object { & $notSafe $_ })
    $removedItems = @($diff.Removed)

    $lines = @("pc-guardian report $(Get-Date -Format 's')", "New: $($newItems.Count)  Removed: $($removedItems.Count)", '')
    foreach ($f in $newItems) {
        Add-RunItem 'New' $f
        $lines += "[{0}] NEW     {1} - {2}" -f (Get-FindingSeverity -Finding $f), $f.Key, $f.Detail
    }
    foreach ($f in $removedItems) {
        Add-RunItem 'Removed' $f
        $lines += "[Info] REMOVED {0} - {1}" -f $f.Key, $f.Detail
    }
    if ($lines.Count -eq 3) { $lines += 'No changes since baseline.' }
    $lines += $scanLines

    $lines | Set-Content -Path $reportFile -Encoding UTF8
    if ($AsObject) {
        return [pscustomobject]@{ Generated = (Get-Date -Format 's'); FirstRun = $false; BaselineCount = $baseline.Count; Items = @($items) }
    }
    $lines + $donateNote
}
