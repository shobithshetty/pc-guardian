function Get-ExposureAudit {
    <#
    .SYNOPSIS
        Offline, read-only checks for risky Windows configuration. Emits a finding ONLY for a bad state.
    .DESCRIPTION
        Exposure findings are reported on every run and are never baselined, so a weakness that existed
        on day one cannot silently become "normal".
        Keys start with 'Exposure:Config:' (alert) or 'Exposure:Update:' (informational).
    #>
    [CmdletBinding()]
    param()

    function Get-RegValue($Path, $Name) {
        try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
    }

    # SMBv1 is the protocol behind WannaCry-style worms. Absent value = OS default (off on current Windows).
    if ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1') -eq 1) {
        New-Finding -Category 'Exposure' -Key 'Exposure:Config:SMB1' -Detail 'SMBv1 is enabled (legacy protocol exploited by worms).'
    }

    if ((Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA') -eq 0) {
        New-Finding -Category 'Exposure' -Key 'Exposure:Config:UAC' -Detail 'User Account Control is disabled.'
    }

    if ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') -eq 0) {
        New-Finding -Category 'Exposure' -Key 'Exposure:Config:RDP' -Detail 'Remote Desktop accepts incoming connections.'
    }

    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if ((Get-RegValue $winlogon 'AutoAdminLogon') -eq '1' -and $null -ne (Get-RegValue $winlogon 'DefaultPassword')) {
        New-Finding -Category 'Exposure' -Key 'Exposure:Config:AutoLogon' -Detail 'Automatic sign-in is on with a password stored in the registry.'
    }

    Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { -not $_.Enabled } | ForEach-Object {
        New-Finding -Category 'Exposure' -Key "Exposure:Config:Firewall:$($_.Name)" -Detail "Windows Firewall is off for the $($_.Name) profile."
    }

    $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
    if ($guest -and $guest.Enabled) {
        New-Finding -Category 'Exposure' -Key 'Exposure:Config:Guest' -Detail 'The Guest account is enabled.'
    }

    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if (-not $mp.RealTimeProtectionEnabled) {
            New-Finding -Category 'Exposure' -Key 'Exposure:Config:DefenderRealTime' -Detail 'Defender real-time protection is off.'
        }
        $age = ((Get-Date) - $mp.AntivirusSignatureLastUpdated).TotalDays
        if ($age -gt 7) {
            New-Finding -Category 'Exposure' -Key 'Exposure:Config:DefenderSignatures' -Detail ("Defender signatures are {0:N0} days old." -f $age)
        }
    } catch {
        New-Finding -Category 'Exposure' -Key 'Exposure:Config:DefenderUnreadable' -Detail 'Could not read Defender status.'
    }

    # No installed Windows update in 60 days usually means updating is broken or switched off.
    $latest = Get-HotFix -ErrorAction SilentlyContinue | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($latest) {
        $days = ((Get-Date) - $latest.InstalledOn).TotalDays
        if ($days -gt 60) {
            New-Finding -Category 'Exposure' -Key 'Exposure:Config:WindowsUpdate' -Detail ("Last Windows update was installed {0:N0} days ago." -f $days)
        }
    }
}
