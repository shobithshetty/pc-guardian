function Get-GuardianIgnoredFile {
    <#
    .SYNOPSIS
        Lists the files you chose to ignore (path and the fingerprint they had when you ignored them).
    #>
    [CmdletBinding()]
    param([string]$DataPath = (Get-GuardianDataPath))

    $file = Join-Path $DataPath 'ignored-files.json'
    if (-not (Test-Path $file)) { return @() }
    # ForEach-Object flattens the array that Windows PowerShell 5.1 would otherwise return as one object.
    @(Get-Content -Path $file -Raw | ConvertFrom-Json | ForEach-Object { $_ })
}
