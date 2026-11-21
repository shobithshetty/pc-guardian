function Get-FindingSeverity {
    <#
    .SYNOPSIS
        Decides whether a NEW finding deserves an alert or is just informational.
    .OUTPUTS
        'Alert' or 'Info'
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Finding)

    # Rules (edit to taste):
    #   1. Any new administrator account            -> Alert
    #   2. Defender protection findings             -> Alert (real-time/tamper off, or stale scan/signatures)
    #   3. New Startup/Task entry running from user-writable paths (AppData, Temp, Downloads, Public) -> Alert
    #   4. New Startup/Task entry using script hosts with encoded/hidden flags -> Alert
    #   5. Everything else (new ports, normal startup entries, new users) -> Info
    $detail = "$($Finding.Detail)"

    if ($Finding.Key -like 'Admin:*') { return 'Alert' }
    if ($Finding.Category -eq 'Malware') { return 'Alert' }
    if ($Finding.Key -like 'Exposure:Config:*') { return 'Alert' }
    if ($Finding.Key -like 'Exposure:Update:*') { return 'Info' }

    if ($Finding.Category -eq 'Defender') {
        if ($detail -match 'RealTimeProtectionEnabled=False|IsTamperProtected=False') { return 'Alert' }
        return 'Info'
    }

    if ($Finding.Category -in 'Startup', 'Task') {
        if ($detail -match '\\AppData\\|\\Temp\\|\\Downloads\\|\\Users\\Public\\') { return 'Alert' }
        if ($detail -match '(?i)(powershell|pwsh|wscript|cscript|mshta|rundll32).*(-enc|-encodedcommand|-w(indowstyle)?\s+hidden|http)') { return 'Alert' }
    }

    return 'Info'
}
