function Invoke-GuardianRun {
    <#
    .SYNOPSIS
        Runs the read-only audit and compares it with the saved baseline.
    .DESCRIPTION
        First run saves a baseline. Later runs report findings that are new or removed since the baseline.
        Nothing on the system is modified; only files under -DataPath are written.
    .PARAMETER DataPath
        Where baseline.json, safe.json and last-report.txt are stored. Default: the pc-guardian data folder (%LOCALAPPDATA%\PcGuardian, or PCGUARDIAN_DATA)
    .PARAMETER ResetBaseline
        Replace the baseline with the current snapshot.
    .PARAMETER AsObject
        Return one structured result (used by the app) instead of text lines.
    #>
    [CmdletBinding()]
    param(
        [string]$DataPath = (Get-GuardianDataPath),
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
        [switch]$AsObject,
        # Print PCG| progress lines (phase, current file, counts, findings) for the app to display live.
        [switch]$Progress,
        # Opt-in: check package-lock.json / requirements.txt in code folders against osv.dev (sends package names
        # and versions only). Also runs during full scans when turned on in Settings.
        [switch]$CheckPackages,
        # Opt-in: compare installed programs with the US known-exploited-vulnerabilities list (downloads a public file).
        # Also runs during full scans when turned on in Settings.
        [switch]$CheckKnownExploited
    )

    $script:ProgressEnabled = [bool]$Progress
    $script:PhaseIndex = 0
    # Always: audit, settings check, baseline compare. Optional: ClamAV + YARA, VirusTotal, app updates.
    # VirusTotal runs when asked for, or during a full scan if the person turned it on in Settings.
    $useVt = [bool]$VirusTotal -or ([bool]$Scan -and [bool](Get-GuardianSetting -DataPath $DataPath).virusTotal)
    $usePkg = [bool]$CheckPackages -or ([bool]$Scan -and [bool](Get-GuardianSetting -DataPath $DataPath).osv)
    # A full scan also looks for stolen-credential and ClickFix traces (one more step).
    $useKev = [bool]$CheckKnownExploited -or ([bool]$Scan -and [bool](Get-GuardianSetting -DataPath $DataPath).knownExploited)
    # A full scan also runs whichever extra detectors were downloaded (drivers, memory, event logs), one step each.
    $det = Find-GuardianDetector -DataPath $DataPath
    $detSteps = if ($Scan) { [int][bool]$det.LolDrivers + [int][bool]$det.HollowsHunter + [int][bool]$det.Hayabusa } else { 0 }
    $script:PhaseTotal = 3 + 2 * [int][bool]$Scan + [int][bool]$Scan + $detSteps + [int]$useVt + [int]$usePkg + [int]$useKev + [int][bool]$CheckUpdates

    $donateNote = if ($NoDonateNote -or $AsObject) { @() } else {
        @('', 'pc-guardian is free and open source. Support it: see the Sponsor button on the GitHub repo. Hide this line with -NoDonateNote.')
    }

    New-Item -ItemType Directory -Force -Path $DataPath | Out-Null
    $baselineFile = Join-Path $DataPath 'baseline.json'
    $reportFile   = Join-Path $DataPath 'last-report.txt'
    $safeKeys     = @(Get-GuardianSafeItem -DataPath $DataPath | ForEach-Object { $_.Key })
    # Findings you marked safe are hidden, except malware, which is always reported.
    $notSafe = { param($f) $f.Category -eq 'Malware' -or $f.Key -notin $safeKeys }

    Start-GuardianPhase -Name 'Checking startup items, tasks, services, certificates and other hiding places'
    $current = @(
        Write-GuardianProgress -Type file -Value 'Microsoft Defender status'
        Get-DefenderAudit
        Write-GuardianProgress -Type file -Value 'Startup items'
        Get-StartupAudit
        Write-GuardianProgress -Type file -Value 'Scheduled tasks'
        Get-TaskAudit
        Write-GuardianProgress -Type file -Value 'Listening ports'
        Get-PortAudit
        Write-GuardianProgress -Type file -Value 'User accounts'
        Get-AccountAudit
        Get-PersistenceAudit
    )

    # Risky browser extensions, Defender exclusions and WMI consumers are reported on every run until you mark them
    # safe, never baselined: one that existed before the baseline was saved must not become "normal".
    $alwaysReport = @($current | Where-Object { $_.Category -in 'ExtensionRisk', 'Persistence' })
    $current      = @($current | Where-Object { $_.Category -notin 'ExtensionRisk', 'Persistence' })

    # Malware detections are never part of the baseline: a threat present on the first run must not become "normal".
    $scanFindings = @()
    if ($Scan -or $useVt) {
        $scanPaths = @(Get-ClamAvScanPath -Findings $current)
        if ($Scan) {
            Start-GuardianPhase -Name 'Scanning files with ClamAV'
            $scanFindings += @(Invoke-ClamAvScan -Path $scanPaths)
            Start-GuardianPhase -Name 'Scanning files with YARA rules'
            $scanFindings += @(Invoke-YaraScan -Path $scanPaths)
            if ($det.LolDrivers) {
                Start-GuardianPhase -Name 'Checking drivers against the vulnerable-driver list'
                $scanFindings += @(Invoke-DriverCheck -ListPath $det.LolDrivers)
            }
            if ($det.HollowsHunter) {
                Start-GuardianPhase -Name 'Looking for injected code inside running programs'
                $scanFindings += @(Invoke-MemoryScan)
            }
            if ($det.Hayabusa) {
                Start-GuardianPhase -Name 'Hunting suspicious activity in Windows event logs'
                $scanFindings += @(Invoke-EventLogScan)
            }
        }
        if ($useVt) {
            Start-GuardianPhase -Name 'Looking up file hashes on VirusTotal'
            $scanFindings += @(Invoke-VirusTotalCheck -Path $scanPaths -DataPath $DataPath)
        }
    }
    # Exposures are reported on every run too, for the same reason: a day-one weakness must not become "normal".
    Start-GuardianPhase -Name 'Checking Windows security settings'
    $exposureFindings = @(Get-ExposureAudit) + $alwaysReport
    if ($Scan) {
        Start-GuardianPhase -Name 'Looking for stolen-credential risks and pasted-command traces'
        Write-GuardianProgress -Type file -Value 'Plain-text secrets in your profile and code folders'
        $exposureFindings += @(Get-CredentialExposureAudit)
        Write-GuardianProgress -Type file -Value 'Run box and PowerShell history'
        $exposureFindings += @(Get-ClickFixTraceAudit)
    }
    if ($useKev) {
        Start-GuardianPhase -Name 'Checking installed apps against the known-exploited list'
        Write-GuardianProgress -Type file -Value 'Downloading the public known-exploited list (cached for a day)'
        $exposureFindings += @(Get-KnownExploitedAudit -DataPath $DataPath)
    }
    if ($usePkg) {
        Start-GuardianPhase -Name 'Checking code packages against osv.dev'
        $exposureFindings += @(Get-PackageRiskAudit)
    }
    if ($CheckUpdates) {
        Start-GuardianPhase -Name 'Checking for app updates'
        $exposureFindings += @(Get-AppUpdateAudit)
    }
    Start-GuardianPhase -Name 'Comparing with your baseline'
    # pc-guardian's own rule files are not findings, and a file you chose to ignore stays quiet while unchanged.
    $scanFindings     = @(Remove-SuppressedMalware -Finding $scanFindings -DataPath $DataPath)
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

    # Checks added after a baseline was saved are absorbed into it once, so an upgrade does not report every
    # existing certificate, service and extension as new. checks.json records which check groups the baseline has.
    $checksFile = Join-Path $DataPath 'baseline-checks.json'
    $persistenceCategories = 'Service', 'Certificate', 'Hosts', 'Extension'

    if ($ResetBaseline -or -not (Test-Path $baselineFile)) {
        ConvertTo-Json -InputObject @($current) -Depth 4 | Set-Content -Path $baselineFile -Encoding UTF8
        '{ "persistence": true }' | Set-Content -Path $checksFile -Encoding UTF8
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
    $upgradeNote = $null
    $hasPersistence = $false
    if (Test-Path $checksFile) {
        try { $hasPersistence = [bool](Get-Content -Path $checksFile -Raw | ConvertFrom-Json).persistence } catch { $hasPersistence = $false }
    }
    if (-not $hasPersistence) {
        $absorbed = @($current | Where-Object { $_.Category -in $persistenceCategories })
        $baseline = @($baseline) + $absorbed
        ConvertTo-Json -InputObject @($baseline) -Depth 4 | Set-Content -Path $baselineFile -Encoding UTF8
        '{ "persistence": true }' | Set-Content -Path $checksFile -Encoding UTF8
        $upgradeNote = "New checks added to your baseline: $($absorbed.Count) existing services, certificates, extensions and similar items were recorded as normal."
    }
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
    if ($upgradeNote) { $lines += $upgradeNote }
    $lines += $scanLines

    $lines | Set-Content -Path $reportFile -Encoding UTF8
    if ($AsObject) {
        return [pscustomobject]@{ Generated = (Get-Date -Format 's'); FirstRun = $false; BaselineCount = $baseline.Count; Items = @($items) }
    }
    $lines + $donateNote
}
