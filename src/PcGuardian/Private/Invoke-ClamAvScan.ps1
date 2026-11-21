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
        [string]$DatabasePath
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

    $scanArgs = @('--database', $db, '--infected', '--recursive', '--no-summary', '--max-filesize=100M') + $Path
    $output = & $clam.ClamScan @scanArgs 2>&1
    $code = $LASTEXITCODE

    $found = 0
    foreach ($line in $output) {
        $text = "$line"
        if ($text -match '^(?<file>.+): (?<sig>\S+) FOUND$') {
            $found++
            New-Finding -Category 'Malware' -Key "Malware:$($Matches.file)" -Detail "ClamAV detected $($Matches.sig)"
        }
        elseif ($text -match "^WARNING: Can't open file (?<file>.+): Invalid argument$") {
            # Windows error 225: another scanner (normally Defender) refused to let ClamAV read the file.
            $found++
            New-Finding -Category 'Malware' -Key "Malware:$($Matches.file)" -Detail 'File blocked by another scanner (likely Defender flagged it)'
        }
    }
    if ($code -gt 1 -and $found -eq 0) {
        New-Finding -Category 'Scanner' -Key 'ClamAV:Error' -Detail "clamscan exited with code $code"
    }
}
