function Get-DefenderAudit {
    [CmdletBinding()]
    param()
    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
    } catch {
        return New-Finding -Category 'Defender' -Key 'Defender:Unavailable' -Detail "Could not read Defender status: $($_.Exception.Message)"
    }
    New-Finding -Category 'Defender' -Key 'Defender:RealTime' -Detail "RealTimeProtectionEnabled=$($s.RealTimeProtectionEnabled)"
    New-Finding -Category 'Defender' -Key 'Defender:Tamper'   -Detail "IsTamperProtected=$($s.IsTamperProtected)"
    New-Finding -Category 'Defender' -Key 'Defender:Signatures' -Detail "Updated=$($s.AntivirusSignatureLastUpdated)"
    New-Finding -Category 'Defender' -Key 'Defender:FullScan' -Detail "LastFullScan=$($s.FullScanEndTime)"
}
