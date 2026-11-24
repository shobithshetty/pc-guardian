function Get-ClamAvScanPath {
    <#
    .SYNOPSIS
        Default high-risk locations to scan: Downloads, Temp, Startup folders, and
        executables named by Startup/Task findings. Existing paths only.
    #>
    [CmdletBinding()]
    param([object[]]$Findings = @())

    $paths = @(
        (Join-Path $env:USERPROFILE 'Downloads'),
        $env:TEMP,
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    )
    foreach ($f in $Findings) {
        if ($f.Category -in 'Startup', 'Task' -and "$($f.Detail)" -match '"?([A-Za-z]:\\[^"]+?\.(exe|dll|bat|cmd|ps1|vbs|js|scr))"?') {
            $paths += $Matches[1]
        }
    }
    $paths | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
}

function Invoke-ClamAvScan {
    <#
    .SYNOPSIS
        Scans paths with ClamAV (read-only: --infected, never --remove) and returns Malware findings.
    .DESCRIPTION
        Returns a single Info finding if ClamAV or its virus database is missing, so the report says why
        no scan happened instead of silently reporting "clean".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Path,
        # Override the virus database folder (used by tests with a custom signature).
        [string]$DatabasePath,
        # Scan everything under the paths now: no memory of clean files and no pre-count. Used for whole folders and drives.
        [switch]$Deep,
        # Where the clean-file memory lives (default: the data folder).
        [string]$CachePath = (Join-Path (Get-GuardianDataPath) 'scan-cache.json'),
        # Days a clean, unchanged file is trusted before it is checked again.
        [int]$CacheDays = 7
    )

    $clam = Find-ClamAv
    if (-not $clam) {
        return New-Finding -Category 'Scanner' -Key 'ClamAV:NotInstalled' -Detail 'ClamAV not found; second-engine scan skipped.'
    }
    $db = if ($DatabasePath) { $DatabasePath } else { $clam.Database }
    $hasDb = (Test-Path $db) -and
        (Get-ChildItem -Path (Join-Path $db '*') -Include '*.cvd', '*.cld', '*.hdb' -ErrorAction SilentlyContinue)
    if (-not $hasDb) {
        return New-Finding -Category 'Scanner' -Key 'ClamAV:NoDatabase' -Detail 'ClamAV virus database missing; run freshclam first.'
    }

    # Limits keep one huge or booby-trapped file from stalling the whole scan: a time limit per file, a smaller
    # size cap, and bounds on how deep and how wide archives are opened.
    $limits = @('--max-filesize=50M', '--max-scansize=100M', '--max-files=2000', '--max-recursion=8', '--max-scantime=60000')
    $cache   = @{}
    $skipped = 0
    $listFile = $null
    $total = 0
    if ($Deep) {
        # Whole folders and drives: let clamscan walk them. Counting a drive first would take longer than scanning.
        Write-GuardianProgress -Type file -Value 'Loading virus signatures (about 20 seconds)...'
        $scanArgs = @('--database', $db, '--recursive', '--no-summary') + $limits + $Path
    }
    else {
        # Count the files first so the app can show a real percentage, and skip files that were found clean
        # recently and have not changed since (same size and modified time). Everything is rechecked every
        # $CacheDays days, so a file is never trusted for long.
        Write-GuardianProgress -Type file -Value 'Looking for new or changed files...'
        if (Test-Path -LiteralPath $CachePath) {
            try {
                foreach ($e in @(Get-Content -LiteralPath $CachePath -Raw | ConvertFrom-Json | ForEach-Object { $_ })) { $cache[[string]$e.p] = $e }
            } catch { $cache = @{} }
        }
        $now = (Get-Date).ToUniversalTime()
        $todo = New-Object System.Collections.Generic.List[string]
        $keep = New-Object System.Collections.Generic.List[object]
        $meta = @{}
        $all = 0
        foreach ($p in $Path) {
            $files = if (Test-Path -LiteralPath $p -PathType Leaf) { @(Get-Item -LiteralPath $p -Force) }
                     else { @(Get-ChildItem -LiteralPath $p -Recurse -File -Force -ErrorAction SilentlyContinue) }
            foreach ($f in $files) {
                $all++
                $e = $cache[$f.FullName.ToLowerInvariant()]
                $fresh = $false
                if ($e) {
                    try { $fresh = ([int64]$e.s -eq $f.Length) -and ([int64]$e.m -eq $f.LastWriteTimeUtc.Ticks) -and (($now - [datetime]::new([int64]$e.w, 'Utc')).TotalDays -lt $CacheDays) } catch { $fresh = $false }
                }
                if ($fresh) { $skipped++; $keep.Add($e) }
                else {
                    $todo.Add($f.FullName)
                    $meta[$f.FullName.ToLowerInvariant()] = [pscustomobject]@{ Len = $f.Length; Ticks = $f.LastWriteTimeUtc.Ticks }
                }
            }
        }
        $total = $todo.Count
        if ($total -eq 0) {
            Write-GuardianProgress -Type file -Value "All $($all.ToString('N0')) files are unchanged since they were last found clean."
            Write-GuardianProgress -Type count -Value $all
            return
        }
        $listFile = Join-Path ([IO.Path]::GetTempPath()) ('pcg-clam-' + [guid]::NewGuid() + '.txt')
        [IO.File]::WriteAllLines($listFile, $todo)
        # ClamAV loads about 3 million signatures before the first file, which takes ~20 seconds.
        Write-GuardianProgress -Type file -Value "Loading virus signatures for $($total.ToString('N0')) new or changed files ($($skipped.ToString('N0')) unchanged files skipped)..."
        $scanArgs = @('--database', $db, '--no-summary') + $limits + @("--file-list=$listFile")
    }

    $found = 0
    $done  = 0
    $cleanNow = New-Object System.Collections.Generic.List[string]
    & $clam.ClamScan @scanArgs 2>&1 | ForEach-Object {
        $text = "$_"
        if ($text -match '^(?<file>.+): (?<sig>\S+) FOUND$') {
            $found++
            $f = New-Finding -Category 'Malware' -Key "Malware:$($Matches.file)" -Detail "ClamAV detected $($Matches.sig)"
            Write-GuardianFound -Finding $f
            $f
        }
        elseif ($text -match "^WARNING: Can't open file (?<file>.+): Invalid argument$") {
            # Windows error 225: another scanner (normally Defender) refused to let ClamAV read the file.
            $found++
            $f = New-Finding -Category 'Malware' -Key "Malware:$($Matches.file)" -Detail 'File blocked by another scanner (likely Defender flagged it)'
            Write-GuardianFound -Finding $f
            $f
        }
        elseif ($text -match '^(?<file>.+): (OK|Empty file)$') {
            $done++
            if ($listFile) { $cleanNow.Add($Matches.file) }
            # Report every 10th file so a fast scan does not flood the app with lines.
            if ($done % 10 -eq 0) {
                Write-GuardianProgress -Type file -Value $Matches.file
                Write-GuardianProgress -Type count -Value $done
                # Never show 100% until clamscan itself has finished; the count is an estimate.
                if ($total -gt 0) { Write-GuardianProgress -Type percent -Value ([int][math]::Min(99, [math]::Floor($done * 100 / $total))) }
            }
        }
    }
    $code = $LASTEXITCODE
    Write-GuardianProgress -Type count -Value ($done + $skipped)

    if ($listFile) {
        Remove-Item -LiteralPath $listFile -Force -ErrorAction SilentlyContinue
        # Remember the files that were just found clean. Exit code 2 only means some file could not be opened; the
        # files ClamAV did report as OK are still valid. A crash (anything else) remembers nothing. Infected files are
        # never remembered (they are not "OK" lines), and unchanged ones keep their old date.
        if ($code -le 2) {
            $stamp = (Get-Date).ToUniversalTime().Ticks
            $out = New-Object System.Collections.Generic.List[object]
            foreach ($e in $keep) { $out.Add($e) }
            foreach ($p in $cleanNow) {
                $m = $meta[$p.ToLowerInvariant()]
                if ($m) { $out.Add([pscustomobject]@{ p = $p.ToLowerInvariant(); s = $m.Len; m = $m.Ticks; w = $stamp }) }
            }
            try {
                $json = ConvertTo-Json -InputObject ([object[]]$out.ToArray()) -Depth 3 -Compress
                [IO.File]::WriteAllText($CachePath, $json, (New-Object System.Text.UTF8Encoding($false)))
            }
            catch { Write-Warning "Could not save the list of clean files: $($_.Exception.Message)" }
        }
    }
    if ($code -gt 1 -and $found -eq 0) {
        New-Finding -Category 'Scanner' -Key 'ClamAV:Error' -Detail "clamscan exited with code $code"
    }
}
