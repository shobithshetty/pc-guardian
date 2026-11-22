function ConvertFrom-VirusTotalFile {
    <#
    .SYNOPSIS
        Turns a VirusTotal v3 "files/{hash}" response into a simple verdict object.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$Response)

    $stats = $null
    if ($Response -and $Response.data -and $Response.data.attributes) { $stats = $Response.data.attributes.last_analysis_stats }
    if (-not $stats) { return [pscustomobject]@{ Known = $false; Malicious = 0; Suspicious = 0 } }
    [pscustomobject]@{ Known = $true; Malicious = [int]$stats.malicious; Suspicious = [int]$stats.suspicious }
}

function Get-VirusTotalCandidate {
    <#
    .SYNOPSIS
        Picks the files worth a reputation lookup: recently changed executables/scripts that are not validly signed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Path,
        [int]$MaxFiles = 25,
        [int]$DaysBack = 30
    )
    $exts = '.exe', '.dll', '.scr', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.com'
    $since = (Get-Date).AddDays(-$DaysBack)
    $files = foreach ($p in $Path) {
        if (Test-Path -LiteralPath $p -PathType Leaf) { Get-Item -LiteralPath $p -ErrorAction SilentlyContinue }
        else { Get-ChildItem -LiteralPath $p -Recurse -File -ErrorAction SilentlyContinue }
    }
    $files | Where-Object { $_.Extension -in $exts -and $_.LastWriteTime -ge $since } |
        Sort-Object LastWriteTime -Descending |
        Where-Object { (Get-AuthenticodeSignature -LiteralPath $_.FullName -ErrorAction SilentlyContinue).Status -ne 'Valid' } |
        Select-Object -First $MaxFiles
}

function Invoke-VirusTotalCheck {
    <#
    .SYNOPSIS
        Looks up SHA-256 hashes of new unsigned executables on VirusTotal. Opt-in; needs an API key.
    .DESCRIPTION
        PRIVACY: only the SHA-256 hash of each file is sent to virustotal.com, never the file or its path.
        Results are cached by hash so a file is looked up once. Free keys allow 4 lookups/minute, so the
        function waits between calls and stops cleanly if VirusTotal answers 429.
    .PARAMETER MinDetections
        Engines that must flag the file before it becomes a finding. Single detections are often false positives.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Path,
        [string]$DataPath = (Get-GuardianDataPath),
        [int]$MinDetections = 3,
        [int]$MaxFiles = 25,
        [int]$DelaySeconds = 16
    )

    $key = Get-VirusTotalKey -DataPath $DataPath
    if (-not $key) {
        return New-Finding -Category 'Scanner' -Key 'VirusTotal:NoKey' -Detail 'No VirusTotal key; run Set-GuardianVirusTotalKey. Lookup skipped.'
    }

    $cacheFile = Join-Path $DataPath 'vt-cache.json'
    $cache = @{}
    if (Test-Path $cacheFile) {
        try { (Get-Content $cacheFile -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $cache[$_.Name] = $_.Value } } catch { $cache = @{} }
    }

    $first = $true
    foreach ($file in @(Get-VirusTotalCandidate -Path $Path -MaxFiles $MaxFiles)) {
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        if (-not $hash) { continue }
        $hash = $hash.ToLower()

        if (-not $cache.ContainsKey($hash)) {
            if (-not $first) { Start-Sleep -Seconds $DelaySeconds }
            $first = $false
            try {
                $resp = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$hash" -Headers @{ 'x-apikey' = $key } -Method Get -ErrorAction Stop
                $v = ConvertFrom-VirusTotalFile -Response $resp
            } catch {
                $status = $_.Exception.Response.StatusCode.value__
                if ($status -eq 404) { $v = ConvertFrom-VirusTotalFile -Response $null }
                elseif ($status -eq 429) {
                    New-Finding -Category 'Scanner' -Key 'VirusTotal:RateLimited' -Detail 'VirusTotal rate limit reached; remaining files will be checked next run.'
                    break
                }
                else {
                    New-Finding -Category 'Scanner' -Key 'VirusTotal:Error' -Detail "VirusTotal request failed (HTTP $status)."
                    break
                }
            }
            $cache[$hash] = [pscustomobject]@{ Known = $v.Known; Malicious = $v.Malicious; Suspicious = $v.Suspicious; Checked = (Get-Date).ToString('s') }
        }

        $v = $cache[$hash]
        if ($v.Known -and ($v.Malicious + $v.Suspicious) -ge $MinDetections) {
            New-Finding -Category 'Malware' -Key "Malware:VirusTotal:$($file.FullName)" `
                -Detail "VirusTotal: $($v.Malicious) malicious, $($v.Suspicious) suspicious engines (sha256 $hash)"
        }
    }

    New-Item -ItemType Directory -Force -Path $DataPath | Out-Null
    $cache | ConvertTo-Json -Depth 4 | Set-Content -Path $cacheFile -Encoding UTF8
}
