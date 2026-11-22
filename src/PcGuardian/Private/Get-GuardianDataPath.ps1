function Get-GuardianDataPath {
    <#
    .SYNOPSIS
        The folder where pc-guardian keeps its data (baseline, safe list, settings, scanner files).
    .DESCRIPTION
        If the PCGUARDIAN_DATA environment variable is set (the installer sets it when you choose another
        folder or drive), that folder is used. Otherwise it is %LOCALAPPDATA%\PcGuardian.
    #>
    [CmdletBinding()]
    param()
    if ($env:PCGUARDIAN_DATA) { return $env:PCGUARDIAN_DATA }
    Join-Path $env:LOCALAPPDATA 'PcGuardian'
}
