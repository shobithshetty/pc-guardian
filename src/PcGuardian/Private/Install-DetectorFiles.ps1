function Install-DetectorFiles {
    <#
    .SYNOPSIS
        Downloads the three extra detectors (Hayabusa, HollowsHunter, the LOLDrivers list) into <DataPath>\detectors.
    .DESCRIPTION
        Programs are fetched at the exact version in data\pins.json and refused unless their SHA-256 matches.
        The LOLDrivers list is data, not code: it is size-capped and checked for shape, and refreshed weekly.
        Uses three progress phases (one per tool). Skips a tool that is already current.
    #>
    [CmdletBinding()]
    param([string]$DataPath = (Get-GuardianDataPath))

    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $pins  = Get-Content -Path (Join-Path $script:ModuleRoot 'data\pins.json') -Raw | ConvertFrom-Json
    $d     = Find-GuardianDetector -DataPath $DataPath
    $base  = $d.Base
    New-Item -ItemType Directory -Force -Path $base | Out-Null
    $state = if (Test-Path $d.StatePath) { Get-Content -Path $d.StatePath -Raw | ConvertFrom-Json } else { $null }
    $have  = @{ hayabusaSha256 = ''; hollowsHunterSha256 = ''; lolDriversFetched = '' }
    if ($state) { foreach ($k in @($have.Keys)) { if ($state.PSObject.Properties[$k]) { $have[$k] = "$($state.$k)" } } }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('pcg-det-' + [guid]::NewGuid())
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    try {
        # --- Hayabusa (event-log hunting; bundled rules are covered by the zip's hash) -------------------
        Start-GuardianPhase -Name "Event-log scanner (Hayabusa $($pins.hayabusa.version))"
        if ($d.Hayabusa -and $have.hayabusaSha256 -eq $pins.hayabusa.sha256) {
            Write-Host 'Hayabusa is already at the pinned version; nothing to download.'
        } else {
            $zip = Join-Path $tmp $pins.hayabusa.asset
            $url = 'https://github.com/{0}/releases/download/{1}/{2}' -f $pins.hayabusa.repo, $pins.hayabusa.version, $pins.hayabusa.asset
            Save-GuardianDownload -Uri $url -OutFile $zip -Label 'Event-log scanner' -ExpectedBytes ([long]$pins.hayabusa.approxBytes)
            $got = (Get-FileHash -Path $zip -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($got -ne $pins.hayabusa.sha256) { throw "Hayabusa download does not match the pinned SHA-256 (expected $($pins.hayabusa.sha256), got $got). Nothing was installed." }
            Write-GuardianProgress -Type file -Value 'Checked the download against its pinned hash'
            $x = Join-Path $tmp 'hb'
            Expand-Archive -Path $zip -DestinationPath $x -Force
            if (-not (Test-Path (Join-Path $x $pins.hayabusa.exe))) { throw 'The Hayabusa download does not contain the expected program.' }
            if (Test-Path $d.HayabusaDir) { Remove-Item -Path $d.HayabusaDir -Recurse -Force }
            New-Item -ItemType Directory -Force -Path $d.HayabusaDir | Out-Null
            Copy-Item -Path (Join-Path $x '*') -Destination $d.HayabusaDir -Recurse -Force
            $have.hayabusaSha256 = $pins.hayabusa.sha256
        }

        # --- HollowsHunter (injected code inside running programs) --------------------------------------
        Start-GuardianPhase -Name "In-memory scanner (HollowsHunter $($pins.hollowsHunter.version))"
        if ($d.HollowsHunter -and $have.hollowsHunterSha256 -eq $pins.hollowsHunter.sha256) {
            Write-Host 'HollowsHunter is already at the pinned version; nothing to download.'
        } else {
            $exe = Join-Path $tmp $pins.hollowsHunter.asset
            $url = 'https://github.com/{0}/releases/download/{1}/{2}' -f $pins.hollowsHunter.repo, $pins.hollowsHunter.version, $pins.hollowsHunter.asset
            Save-GuardianDownload -Uri $url -OutFile $exe -Label 'In-memory scanner' -ExpectedBytes ([long]$pins.hollowsHunter.approxBytes)
            $got = (Get-FileHash -Path $exe -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($got -ne $pins.hollowsHunter.sha256) { throw "HollowsHunter download does not match the pinned SHA-256 (expected $($pins.hollowsHunter.sha256), got $got). Nothing was installed." }
            Write-GuardianProgress -Type file -Value 'Checked the download against its pinned hash'
            $dest = Join-Path $base 'hollows_hunter'
            New-Item -ItemType Directory -Force -Path $dest | Out-Null
            Copy-Item -Path $exe -Destination (Join-Path $dest $pins.hollowsHunter.asset) -Force
            $have.hollowsHunterSha256 = $pins.hollowsHunter.sha256
        }

        # --- LOLDrivers (data list, refreshed weekly) ----------------------------------------------------
        Start-GuardianPhase -Name 'Vulnerable-driver list (LOLDrivers)'
        $fresh = $false
        if ($d.LolDrivers -and $have.lolDriversFetched) {
            try { $fresh = ((Get-Date) - [datetime]::Parse($have.lolDriversFetched, [Globalization.CultureInfo]::InvariantCulture)).TotalDays -lt 7 } catch { $fresh = $false }
        }
        if ($fresh) {
            Write-Host 'The vulnerable-driver list was refreshed within the last 7 days.'
        } else {
            $list = Join-Path $tmp 'drivers.json'
            Save-GuardianDownload -Uri $pins.lolDrivers.url -OutFile $list -Label 'Vulnerable-driver list'
            $size = (Get-Item $list).Length
            if ($size -gt [long]$pins.lolDrivers.maxBytes) { throw "The driver list is larger than expected ($size bytes); it was not installed." }
            $map = ConvertFrom-LolDriversList -Text (Get-Content -Path $list -Raw)
            if ($map.Count -lt [int]$pins.lolDrivers.minEntries) { throw "The driver list has only $($map.Count) entries (expected more); it was not installed." }
            $dest = Join-Path $base 'loldrivers'
            New-Item -ItemType Directory -Force -Path $dest | Out-Null
            Copy-Item -Path $list -Destination (Join-Path $dest 'drivers.json') -Force
            Set-Content -Path (Join-Path $dest 'SOURCE.txt') -Encoding ASCII -Value @(
                'LOLDrivers (https://www.loldrivers.io), Apache-2.0. Used only to compare driver file hashes.')
            $have.lolDriversFetched = (Get-Date).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        }
        Set-Content -Path $d.StatePath -Encoding UTF8 -Value ([pscustomobject]$have | ConvertTo-Json)
        Set-Content -Path (Join-Path $base 'ATTRIBUTION.txt') -Encoding ASCII -Value @(
            'Hayabusa (AGPL-3.0) and its rules (Detection Rule License 1.1): https://github.com/Yamato-Security/hayabusa',
            'HollowsHunter / PE-sieve (BSD-2-Clause): https://github.com/hasherezade/hollows_hunter',
            'LOLDrivers (Apache-2.0): https://www.loldrivers.io',
            'These are run as separate programs and are not modified or bundled into pc-guardian.')
    }
    finally { Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
