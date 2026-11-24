function Remove-GuardianIgnoredFile {
    <#
    .SYNOPSIS
        Starts reporting an ignored file again.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$DataPath = (Get-GuardianDataPath)
    )
    $items = @(Get-GuardianIgnoredFile -DataPath $DataPath | Where-Object { $_.Path -ne $Path })
    ConvertTo-Json -InputObject @($items) -Depth 3 | Set-Content -Path (Join-Path $DataPath 'ignored-files.json') -Encoding UTF8
}
