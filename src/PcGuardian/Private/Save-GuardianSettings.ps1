function Save-GuardianSettings {
    <#
    .SYNOPSIS
        Writes settings.json from a settings object. The one place that knows which settings exist.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Settings,
        [Parameter(Mandatory)][string]$DataPath
    )
    New-Item -ItemType Directory -Force -Path $DataPath | Out-Null
    $out = [ordered]@{}
    foreach ($name in 'virusTotal', 'osv', 'knownExploited', 'updateCheck') { $out[$name] = [bool]$Settings.$name }
    $out['devFolders'] = @($Settings.devFolders | Where-Object { $_ })
    $out | ConvertTo-Json | Set-Content -Path (Join-Path $DataPath 'settings.json') -Encoding UTF8
}
