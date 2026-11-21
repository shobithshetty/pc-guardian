function Invoke-GuardianRun {
    <#
    .SYNOPSIS
        Runs the read-only audit and compares it with the saved baseline.
    .DESCRIPTION
        First run saves a baseline. Later runs report findings that are new or removed since the baseline.
        Nothing on the system is modified; only files under -DataPath are written.
    .PARAMETER DataPath
        Where baseline.json and last-report.txt are stored. Default: %LOCALAPPDATA%\PcGuardian
    .PARAMETER ResetBaseline
        Replace the baseline with the current snapshot.
    #>
    [CmdletBinding()]
    param(
        [string]$DataPath = (Join-Path $env:LOCALAPPDATA 'PcGuardian'),
        [switch]$ResetBaseline,
        # Also scan high-risk locations with ClamAV and YARA. Detections are always reported, never baselined.
        [switch]$Scan,
        # Also list apps with newer winget versions (needs network). Config exposure checks always run.
        [switch]$CheckUpdates
    )

    New-Item -ItemType Directory -Force -Path $DataPath | Out-Null
    $baselineFile = Join-Path $DataPath 'baseline.json'
    $reportFile   = Join-Path $DataPath 'last-report.txt'

    $current = @(
        Get-DefenderAudit
        Get-StartupAudit
        Get-TaskAudit
        Get-PortAudit
        Get-AccountAudit
    )

    # Malware detections are never part of the baseline: a threat present on the first run must not become "normal".
    $scanFindings = @()
    if ($Scan) {
        $scanPaths = @(Get-ClamAvScanPath -Findings $current)
        $scanFindings = @(Invoke-ClamAvScan -Path $scanPaths) + @(Invoke-YaraScan -Path $scanPaths)
    }
    # Exposures are reported on every run too, for the same reason: a day-one weakness must not become "normal".
    $exposureFindings = @(Get-ExposureAudit)
    if ($CheckUpdates) { $exposureFindings += @(Get-AppUpdateAudit) }

    $scanLines = @(
        $scanFindings | ForEach-Object {
            "[{0}] SCAN    {1} - {2}" -f (Get-FindingSeverity -Finding $_), $_.Key, $_.Detail
        }
        $exposureFindings | ForEach-Object {
            "[{0}] EXPOSED {1} - {2}" -f (Get-FindingSeverity -Finding $_), $_.Key, $_.Detail
        }
    )

    if ($ResetBaseline -or -not (Test-Path $baselineFile)) {
        $current | ConvertTo-Json -Depth 4 | Set-Content -Path $baselineFile -Encoding UTF8
        $msg = @("Baseline saved with $($current.Count) findings at $baselineFile. Run again later to see changes.") + $scanLines
        $msg | Set-Content -Path $reportFile -Encoding UTF8
        $msg
        return
    }

    $baseline = @(Get-Content -Path $baselineFile -Raw | ConvertFrom-Json)
    $diff = Compare-Baseline -Baseline $baseline -Current $current

    $lines = @("pc-guardian report $(Get-Date -Format 's')", "New: $($diff.New.Count)  Removed: $($diff.Removed.Count)", '')
    foreach ($f in $diff.New) {
        $lines += "[{0}] NEW     {1} - {2}" -f (Get-FindingSeverity -Finding $f), $f.Key, $f.Detail
    }
    foreach ($f in $diff.Removed) {
        $lines += "[Info] REMOVED {0} - {1}" -f $f.Key, $f.Detail
    }
    if ($lines.Count -eq 3) { $lines += 'No changes since baseline.' }
    $lines += $scanLines

    $lines | Set-Content -Path $reportFile -Encoding UTF8
    $lines
}
