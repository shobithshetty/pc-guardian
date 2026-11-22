function Set-GuardianVirusTotalKey {
    <#
    .SYNOPSIS
        Stores your VirusTotal API key encrypted for your Windows account only (or removes it).
    .DESCRIPTION
        Without -Key the key is typed at a hidden prompt. It is saved with Windows DPAPI
        (ConvertFrom-SecureString), so it is unreadable by other users or other PCs. pc-guardian never logs it.
        Get a free key at virustotal.com (profile -> API key). Free keys are for personal, non-commercial use.
    .PARAMETER Key
        The key as a SecureString (the app passes it this way). Omit it to be prompted.
    .PARAMETER Remove
        Delete the stored key.
    #>
    [CmdletBinding()]
    param(
        [securestring]$Key,
        [switch]$Remove,
        [string]$DataPath = (Join-Path $env:LOCALAPPDATA 'PcGuardian')
    )

    $file = Join-Path $DataPath 'vt.key'
    if ($Remove) {
        if (Test-Path $file) { Remove-Item -Path $file -Force }
        Write-Output 'Key removed.'
        return
    }
    $secure = if ($Key) { $Key } else { Read-Host -Prompt 'Paste your VirusTotal API key' -AsSecureString }
    if ($secure.Length -eq 0) { throw 'No key entered.' }
    New-Item -ItemType Directory -Force -Path $DataPath | Out-Null
    $secure | ConvertFrom-SecureString | Set-Content -Path $file -Encoding ASCII
    Write-Output "Key saved (encrypted) to $file."
}
