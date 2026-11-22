function Add-GuardianDevFolder {
    <#
    .SYNOPSIS
        Adds a code folder (for example on another drive) to search for stray secrets and package lock files.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$DataPath = (Get-GuardianDataPath)
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "That folder does not exist: $Path" }
    $full = (Resolve-Path -LiteralPath $Path).ProviderPath.TrimEnd('\')
    New-Item -ItemType Directory -Force -Path $DataPath | Out-Null
    $current = Get-GuardianSetting -DataPath $DataPath
    $folders = @($current.devFolders)
    if ($folders -contains $full) { return }
    $out = [ordered]@{ virusTotal = [bool]$current.virusTotal; osv = [bool]$current.osv; devFolders = @($folders + $full) }
    $out | ConvertTo-Json | Set-Content -Path (Join-Path $DataPath 'settings.json') -Encoding UTF8
}
