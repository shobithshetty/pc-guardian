function Remove-GuardianDevFolder {
    <#
    .SYNOPSIS
        Removes a folder from the list of code folders to search.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$DataPath = (Get-GuardianDataPath)
    )
    $current = Get-GuardianSetting -DataPath $DataPath
    $current.devFolders = @($current.devFolders | Where-Object { $_ -ne $Path.TrimEnd('\') })
    Save-GuardianSettings -Settings $current -DataPath $DataPath
}
