function Get-VirusTotalKey {
    <#
    .SYNOPSIS
        Returns the VirusTotal API key, or $null. Order: PCGUARDIAN_VT_KEY env var, then the DPAPI-protected
        key file written by Set-GuardianVirusTotalKey (readable only by this Windows user on this PC).
    #>
    [CmdletBinding()]
    param([string]$DataPath = (Join-Path $env:LOCALAPPDATA 'PcGuardian'))

    if ($env:PCGUARDIAN_VT_KEY) { return $env:PCGUARDIAN_VT_KEY }
    $file = Join-Path $DataPath 'vt.key'
    if (-not (Test-Path $file)) { return $null }
    try {
        $secure = Get-Content -Path $file -Raw | ConvertTo-SecureString
        [System.Net.NetworkCredential]::new('', $secure).Password
    } catch {
        $null
    }
}
