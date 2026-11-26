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

    # Hiding places: a new Defender exclusion or WMI consumer, a new user-installed root certificate, a hosts entry
    # that redirects traffic elsewhere, or a risky browser extension, are all worth attention.
    if ($Finding.Key -like 'Defender:Exclusion:*' -or $Finding.Key -like 'WMI:*') { return 'Alert' }
    if ($Finding.Category -eq 'Certificate') {
        if ($detail -match 'user-installed') { return 'Alert' }
        return 'Info'
    }
    if ($Finding.Category -eq 'Hosts') {
        if ($detail -match 'points to (127\.0\.0\.1|0\.0\.0\.0|::1)$') { return 'Info' }
        return 'Alert'
    }
    if ($Finding.Category -in 'Extension', 'ExtensionRisk') {
        if ($detail -match 'risky permissions') { return 'Alert' }
        return 'Info'
    }
    # Traces of pasted-command attacks: only the clearly suspicious ones are alerts.
    if ($Finding.Category -eq 'ClickFix') {
        if ($detail -match 'suspicious:') { return 'Alert' }
        return 'Info'
    }
    # Plain-text secrets are what supply-chain worms and infostealers steal; an unprotected SSH key is a lesser risk.
    if ($Finding.Category -eq 'Credential') {
        if ($Finding.Key -like 'Credential:SshKey:*') { return 'Info' }
        return 'Alert'
    }
    # Recently exploited vulnerabilities in something you have installed: an alert when the newest is under two weeks old.
    if ($Finding.Category -eq 'KnownExploited') {
        if ($detail -match 'newest (0|1[0-4]|[1-9]) days? ago') { return 'Alert' }
        return 'Info'
    }
    # Extra detectors: injected code in a running program and event-log detections are alerts. A driver on the
    # LOLDrivers list is an alert when listed as malicious; a merely vulnerable one is informational.
    if ($Finding.Category -in 'Memory', 'EventLog') { return 'Alert' }
    if ($Finding.Category -eq 'Driver') {
        if ($Finding.Key -like 'Driver:Malicious:*') { return 'Alert' }
        return 'Info'
    }
    # A connected phone: a known spy app or open wireless debugging is an alert; the rest is for the person to judge.
    if ($Finding.Category -eq 'Phone') {
        if ($Finding.Key -like 'Phone:Stalkerware:*' -or $Finding.Key -eq 'Phone:WirelessDebugging') { return 'Alert' }
        return 'Info'
    }
    # A known-malicious package is an alert; ordinary advisories are informational.
    if ($Finding.Category -eq 'Package') {
        if ($Finding.Key -like 'Package:Malicious:*') { return 'Alert' }
        return 'Info'
    }

    if ($Finding.Category -in 'Startup', 'Task', 'Service') {
        if ($detail -match '\\AppData\\|\\Temp\\|\\Downloads\\|\\Users\\Public\\') { return 'Alert' }
        if ($detail -match '(?i)(powershell|pwsh|wscript|cscript|mshta|rundll32).*(-enc|-encodedcommand|-w(indowstyle)?\s+hidden|http)') { return 'Alert' }
    }

    return 'Info'
}
