function Get-GuardianSafeItem {
    <#
    .SYNOPSIS
        Lists the findings you marked as safe. They stop being reported as new.
    #>
    [CmdletBinding()]
    param([string]$DataPath = (Get-GuardianDataPath))

    $file = Join-Path $DataPath 'safe.json'
    if (-not (Test-Path $file)) { return @() }
    # ForEach-Object flattens the array that Windows PowerShell 5.1 would otherwise return as one object.
    @(Get-Content -Path $file -Raw | ConvertFrom-Json | ForEach-Object { $_ })
}
