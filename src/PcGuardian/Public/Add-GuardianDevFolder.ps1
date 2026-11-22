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
    $current = Get-GuardianSetting -DataPath $DataPath
    if (@($current.devFolders) -contains $full) { return }
    $current.devFolders = @(@($current.devFolders) + $full)
    Save-GuardianSettings -Settings $current -DataPath $DataPath
}
