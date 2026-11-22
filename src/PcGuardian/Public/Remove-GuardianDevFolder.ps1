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
    $folders = @($current.devFolders | Where-Object { $_ -ne $Path.TrimEnd('\') })
    $out = [ordered]@{ virusTotal = [bool]$current.virusTotal; osv = [bool]$current.osv; devFolders = @($folders) }
    $out | ConvertTo-Json | Set-Content -Path (Join-Path $DataPath 'settings.json') -Encoding UTF8
}
