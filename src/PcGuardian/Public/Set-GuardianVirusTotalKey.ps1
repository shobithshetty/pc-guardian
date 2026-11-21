function Set-GuardianVirusTotalKey {
    <#
    .SYNOPSIS
        Prompts for your VirusTotal API key and stores it encrypted for your Windows account only.
    .DESCRIPTION
        The key is typed at a hidden prompt and saved with Windows DPAPI (ConvertFrom-SecureString), so it is
        unreadable by other users or other PCs. pc-guardian never logs it. Get a free key at virustotal.com
        (profile -> API key). Remove it with: Remove-Item "$env:LOCALAPPDATA\PcGuardian\vt.key"
    #>
    [CmdletBinding()]
    param([string]$DataPath = (Join-Path $env:LOCALAPPDATA 'PcGuardian'))

    $secure = Read-Host -Prompt 'Paste your VirusTotal API key' -AsSecureString
    if ($secure.Length -eq 0) { throw 'No key entered.' }
    New-Item -ItemType Directory -Force -Path $DataPath | Out-Null
    $secure | ConvertFrom-SecureString | Set-Content -Path (Join-Path $DataPath 'vt.key') -Encoding ASCII
    Write-Output "Key saved (encrypted) to $(Join-Path $DataPath 'vt.key')."
}
