function Set-GuardianSetting {
    <#
    .SYNOPSIS
        Saves one on/off pc-guardian setting. Only known settings are accepted.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('virusTotal', 'osv', 'knownExploited', 'updateCheck')][string]$Name,
        [Parameter(Mandatory)][bool]$Value,
        [string]$DataPath = (Get-GuardianDataPath)
    )

    $current = Get-GuardianSetting -DataPath $DataPath
    $current.$Name = $Value
    Save-GuardianSettings -Settings $current -DataPath $DataPath
}
