function ConvertFrom-LolDriversList {
    <#
    .SYNOPSIS
        Reads the LOLDrivers list into a lookup of SHA-256 -> name and category.
    .DESCRIPTION
        The file is untrusted data. It is read as text with fixed patterns (never executed, never evaluated), so a
        malformed or hostile file can at worst produce no matches. Windows PowerShell 5.1 cannot parse the whole
        file as JSON (it has keys that differ only in letter case), so entries are split on their "Id" field.
        Returns a hashtable keyed by lower-case SHA-256.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $map = @{}
    # Each entry starts with its own "Id": "<guid>" line.
    $chunks = [regex]::Split($Text, '"Id":\s*"(?=[0-9a-fA-F]{8}-)')
    foreach ($c in ($chunks | Select-Object -Skip 1)) {
        $category = 'unknown'
        if ($c -match '"Category":\s*"(?<c>[^"]{1,40})"') { $category = $Matches.c.ToLowerInvariant() }
        $name = ''
        if ($c -match '"Tags":\s*\[\s*"(?<n>[^"]{1,80})"') { $name = $Matches.n }
        elseif ($c -match '"Filename":\s*"(?<n>[^"]{1,80})"') { $name = $Matches.n }
        foreach ($m in [regex]::Matches($c, '"SHA256":\s*"(?<h>[0-9a-fA-F]{64})"')) {
            $h = $m.Groups['h'].Value.ToLowerInvariant()
            if (-not $map.ContainsKey($h)) { $map[$h] = [pscustomobject]@{ Name = $name; Category = $category } }
        }
    }
    $map
}

function Invoke-DriverCheck {
    <#
    .SYNOPSIS
        Compares the driver files installed on this PC with the public LOLDrivers list (read-only).
    .DESCRIPTION
        Attackers load a legitimate, signed but vulnerable driver to switch off security tools. Each installed
        driver file is hashed (SHA-256) and looked up in the list. Nothing is sent anywhere.
    .PARAMETER ListPath
        Path to the downloaded drivers.json (defaults to the detector folder).
    .PARAMETER DriverFile
        Hash these files instead of the installed drivers (used by tests).
    #>
    [CmdletBinding()]
    param(
        [string]$ListPath,
        [string[]]$DriverFile
    )

    if (-not $ListPath) { $d = Find-GuardianDetector; $ListPath = $d.LolDrivers }
    if (-not $ListPath -or -not (Test-Path $ListPath)) {
        return New-Finding -Category 'Scanner' -Key 'Driver:NoList' -Detail 'The vulnerable-driver list is not downloaded; driver check skipped.'
    }
    $map = ConvertFrom-LolDriversList -Text (Get-Content -Path $ListPath -Raw)
    if ($map.Count -lt 1) {
        return New-Finding -Category 'Scanner' -Key 'Driver:BadList' -Detail 'The vulnerable-driver list could not be read; driver check skipped.'
    }

    if (-not $DriverFile) {
        $DriverFile = @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue | ForEach-Object {
            $p = "$($_.PathName)" -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:SystemRoot
            $p = $p.Trim('"')
            if ($p -match '^(?<f>.+?\.sys)\b') { $Matches.f }
        } | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Sort-Object -Unique)
    }

    $seen = @{}
    foreach ($file in $DriverFile) {
        Write-GuardianProgress -Type file -Value $file
        $hash = $null
        try { $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() } catch { continue }
        if ($map.ContainsKey($hash)) {
            $hit = $map[$hash]
            $leaf = Split-Path $file -Leaf
            $kind = if ($hit.Category -like '*malicious*') { 'Malicious' } else { 'Vulnerable' }
            $key = "Driver:${kind}:$leaf"
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $f = New-Finding -Category 'Driver' -Key $key -Detail ("{0} driver on the LOLDrivers list (listed as: {1}) at {2}" -f $kind.ToLowerInvariant(), $hit.Name, $file)
            Write-GuardianFound -Finding $f
            $f
        }
    }
}
