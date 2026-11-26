function Invoke-GuardianPhoneCheck {
    <#
    .SYNOPSIS
        Checks one connected, authorized Android phone or tablet for stalkerware and risky settings (read-only).
    .DESCRIPTION
        Only the device named by -Serial is touched. It reads settings and app names through a fixed read-only allowlist
        (no messages, photos or files, nothing changed) and compares app names with the public stalkerware lists.
        Findings you marked safe are hidden. A clean result is never proof that a phone is safe.
    .PARAMETER Serial
        The device serial from Get-GuardianPhoneStatus. There is deliberately no "all devices" mode.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Serial,
        [string]$DataPath = (Get-GuardianDataPath)
    )

    $t = Find-GuardianPhoneTools -DataPath $DataPath
    if (-not ($t.Adb -and $t.IocPath -and $t.WatchwarePath)) { throw 'The phone-check tools are not downloaded yet. Run Install-GuardianPhoneTools first.' }

    Enter-PrivateAdb
    try {
        $dev = @(Get-AndroidDeviceSettled -Adb $t.Adb) | Where-Object { $_.Serial -eq $Serial } | Select-Object -First 1
        if (-not $dev) { throw 'That device is not connected any more.' }
        if ($dev.State -ne 'device') {
            throw "The device is '$($dev.State)'. Unlock it, turn on USB debugging, and tap Allow on the 'Allow USB debugging?' prompt, then try again."
        }
        $map = ConvertFrom-StalkerwareList -Text (Get-Content -Path $t.IocPath -Raw)
        $watch = ConvertFrom-StalkerwareList -Text (Get-Content -Path $t.WatchwarePath -Raw) -DefaultType watchware
        foreach ($k in $watch.Keys) { if (-not $map.ContainsKey($k)) { $map[$k] = $watch[$k] } }
        $r = Invoke-AndroidCheck -Adb $t.Adb -Serial $Serial -Indicators $map
    }
    finally { Exit-PrivateAdb -Adb $t.Adb }

    $safe = @(Get-GuardianSafeItem -DataPath $DataPath | ForEach-Object { $_.Key })
    $items = foreach ($f in $r.Findings) {
        # Stalkerware is never hidden by the safe list, in line with the rule for malware on the PC.
        if ($f.Key -like 'Phone:Stalkerware:*' -or $f.Key -notin $safe) {
            [pscustomobject]@{ Kind = 'Phone'; Severity = (Get-FindingSeverity -Finding $f); Category = $f.Category; Key = $f.Key; Detail = $f.Detail }
        }
    }
    [pscustomobject]@{
        Generated  = (Get-Date -Format 's')
        Device     = $r.Device
        Packages   = $r.Packages
        ThirdParty = $r.ThirdParty
        Checked    = $r.Checked
        Items      = [object[]]@($items)
    }
}
