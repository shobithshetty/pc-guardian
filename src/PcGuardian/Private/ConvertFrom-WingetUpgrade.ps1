function ConvertFrom-WingetUpgrade {
    <#
    .SYNOPSIS
        Parses the table printed by `winget upgrade` into objects (Name, Id, Version, Available).
    .DESCRIPTION
        Column positions come from the header line, because names can contain spaces.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Lines)

    $clean = @($Lines | ForEach-Object { ($_ -replace '[\x00-\x08\x0B-\x1F]', '').TrimEnd() })
    $headerIdx = -1
    for ($i = 0; $i -lt $clean.Count; $i++) {
        if ($clean[$i] -match '^Name\s+Id\s+Version\s+Available') { $headerIdx = $i; break }
    }
    if ($headerIdx -lt 0) { return }

    $h = $clean[$headerIdx]
    $iId = $h.IndexOf('Id'); $iVer = $h.IndexOf('Version'); $iAvail = $h.IndexOf('Available')
    $iSrc = $h.IndexOf('Source'); if ($iSrc -lt 0) { $iSrc = $h.Length + 100 }

    foreach ($line in $clean[($headerIdx + 2)..($clean.Count - 1)]) {
        if (-not $line -or $line -match '^\d+ upgrades? available' -or $line.Length -le $iAvail) { continue }
        $take = { param($from, $to) $line.Substring($from, [Math]::Min($to, $line.Length) - $from).Trim() }
        [pscustomobject]@{
            Name      = & $take 0 $iId
            Id        = & $take $iId $iVer
            Version   = & $take $iVer $iAvail
            Available = & $take $iAvail $iSrc
        }
    }
}
