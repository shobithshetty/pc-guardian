function Add-GuardianSafeItem {
    <#
    .SYNOPSIS
        Marks a finding as safe by its key, so later runs stop reporting it.
    .DESCRIPTION
        Malware detections cannot be marked safe: they are reported on every run. Only changes to
        your PC (new startup items, tasks, ports, accounts) and update notices can be silenced.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)][string]$Key,
        [string]$DataPath = (Join-Path $env:LOCALAPPDATA 'PcGuardian')
    )
    process {
        if ($Key -like 'Malware:*') { throw 'Malware detections cannot be marked safe.' }
        New-Item -ItemType Directory -Force -Path $DataPath | Out-Null
        $items = @(Get-GuardianSafeItem -DataPath $DataPath)
        if ($items | Where-Object { $_.Key -eq $Key }) { return }
        $items += [pscustomobject]@{ Key = $Key; Added = (Get-Date -Format 's') }
        ConvertTo-Json -InputObject @($items) -Depth 3 | Set-Content -Path (Join-Path $DataPath 'safe.json') -Encoding UTF8
    }
}
