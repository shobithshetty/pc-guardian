function Add-GuardianIgnoredFile {
    <#
    .SYNOPSIS
        Stops reporting one file that a scanner flagged, as long as its contents stay exactly the same.
    .DESCRIPTION
        Malware detections cannot be marked safe by name, because a threat could then hide behind a name you
        trusted. This is the narrow alternative for false alarms: it records the file's path AND its SHA-256
        fingerprint. If the file changes in any way (or is replaced), it is reported again.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$DataPath = (Get-GuardianDataPath)
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'That file no longer exists, so there is nothing to ignore.' }
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    New-Item -ItemType Directory -Force -Path $DataPath | Out-Null
    $items = @(Get-GuardianIgnoredFile -DataPath $DataPath | Where-Object { $_.Path -ne $Path })
    $items += [pscustomobject]@{ Path = $Path; Sha256 = $hash; Added = (Get-Date -Format 's') }
    ConvertTo-Json -InputObject @($items) -Depth 3 | Set-Content -Path (Join-Path $DataPath 'ignored-files.json') -Encoding UTF8
}
