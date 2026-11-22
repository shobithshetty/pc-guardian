function Get-GuardianUpdateInfo {
    <#
    .SYNOPSIS
        Asks GitHub whether a newer pc-guardian release exists. Never downloads or installs anything.
    .DESCRIPTION
        Opt-in (the app calls it only when "tell me about new versions" is on). Checks at most about once a day
        and caches the answer. Sends nothing about you except what any web request reveals (your IP address).
    .PARAMETER Repository
        owner/name of the GitHub project.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Repository,
        [Parameter(Mandatory)][string]$CurrentVersion,
        [string]$DataPath = (Get-GuardianDataPath),
        [int]$MaxAgeHours = 20
    )

    if ($Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { throw 'Repository must look like owner/name.' }
    $cache = Join-Path $DataPath 'update-check.json'
    $info = $null
    if ((Test-Path $cache) -and (((Get-Date) - (Get-Item $cache).LastWriteTime).TotalHours -lt $MaxAgeHours)) {
        try { $info = Get-Content -Path $cache -Raw | ConvertFrom-Json } catch { $info = $null }
    }
    if (-not $info -or $info.Repository -ne $Repository) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            $r = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repository/releases/latest" -TimeoutSec 30 `
                -Headers @{ 'User-Agent' = 'pc-guardian'; Accept = 'application/vnd.github+json' }
            $info = [pscustomobject]@{ Repository = $Repository; Latest = ("$($r.tag_name)" -replace '^v', ''); Url = "$($r.html_url)" }
            New-Item -ItemType Directory -Force -Path $DataPath | Out-Null
            $info | ConvertTo-Json | Set-Content -Path $cache -Encoding UTF8
        } catch {
            # No release yet, no network, or rate-limited: say "no update" rather than failing the app.
            return [pscustomobject]@{ Available = $false; Current = $CurrentVersion; Latest = $null; Url = $null; Error = $_.Exception.Message }
        }
    }

    $available = $false
    try { $available = ([version](("$($info.Latest)" -split '[-+]')[0])) -gt ([version](($CurrentVersion -split '[-+]')[0])) } catch { $available = $false }
    # Only an https link to github.com is ever offered to the app.
    $url = if ("$($info.Url)" -match '^https://github\.com/') { "$($info.Url)" } else { $null }
    [pscustomobject]@{ Available = $available; Current = $CurrentVersion; Latest = "$($info.Latest)"; Url = $url; Error = $null }
}
