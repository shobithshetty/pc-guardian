function Set-GuardianSetting {
    <#
    .SYNOPSIS
        Saves one pc-guardian setting. Only known settings are accepted.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('virusTotal', 'osv')][string]$Name,
        [Parameter(Mandatory)][bool]$Value,
        [string]$DataPath = (Get-GuardianDataPath)
    )

    New-Item -ItemType Directory -Force -Path $DataPath | Out-Null
    $current = Get-GuardianSetting -DataPath $DataPath
    $out = [ordered]@{ virusTotal = [bool]$current.virusTotal; osv = [bool]$current.osv; devFolders = @($current.devFolders) }
    $out[$Name] = $Value
    $out | ConvertTo-Json | Set-Content -Path (Join-Path $DataPath 'settings.json') -Encoding UTF8
}
