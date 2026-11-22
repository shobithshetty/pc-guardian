function Remove-GuardianSafeItem {
    <#
    .SYNOPSIS
        Takes a finding off the safe list so it is reported again.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Key,
        [string]$DataPath = (Get-GuardianDataPath)
    )
    $items = @(Get-GuardianSafeItem -DataPath $DataPath | Where-Object { $_.Key -ne $Key })
    ConvertTo-Json -InputObject @($items) -Depth 3 | Set-Content -Path (Join-Path $DataPath 'safe.json') -Encoding UTF8
}
