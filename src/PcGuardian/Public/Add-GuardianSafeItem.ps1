function Add-GuardianSafeItem {
    <#
    .SYNOPSIS
        Marks one or more findings as safe by key, so later runs stop reporting them.
    .DESCRIPTION
        Malware detections cannot be marked safe: they are reported on every run. Only changes to
        your PC (new startup items, tasks, ports, accounts), hiding places and update notices can be silenced.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)][string[]]$Key,
        [string]$DataPath = (Get-GuardianDataPath)
    )
    process {
        foreach ($k in $Key) {
            if ($k -like 'Malware:*') { throw 'Malware detections cannot be marked safe.' }
        }
        New-Item -ItemType Directory -Force -Path $DataPath | Out-Null
        $items = @(Get-GuardianSafeItem -DataPath $DataPath)
        $known = @($items | ForEach-Object { $_.Key })
        $added = 0
        foreach ($k in $Key) {
            if ($k -notin $known) {
                $items += [pscustomobject]@{ Key = $k; Added = (Get-Date -Format 's') }
                $known += $k
                $added++
            }
        }
        if ($added -gt 0) {
            ConvertTo-Json -InputObject @($items) -Depth 3 | Set-Content -Path (Join-Path $DataPath 'safe.json') -Encoding UTF8
        }
    }
}
