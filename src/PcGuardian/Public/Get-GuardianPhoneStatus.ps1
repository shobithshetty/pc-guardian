function Get-GuardianPhoneStatus {
    <#
    .SYNOPSIS
        Reports whether the phone-check tools are downloaded and which Android devices are connected.
    .DESCRIPTION
        Read-only. It only lists devices (serial, state, model); it reads nothing from them. It uses pc-guardian's own
        adb server port and stops that server afterwards. A device in the "unauthorized" state has not approved this PC:
        the person must unlock it and tap Allow on the phone.
    #>
    [CmdletBinding()]
    param([string]$DataPath = (Get-GuardianDataPath))

    $t = Find-GuardianPhoneTools -DataPath $DataPath
    $ready = [bool]($t.Adb -and $t.IocPath -and $t.WatchwarePath)
    $devices = @()
    if ($t.Adb) {
        Enter-PrivateAdb
        try { $devices = @(Get-AndroidDeviceSettled -Adb $t.Adb) }
        finally { Exit-PrivateAdb -Adb $t.Adb }
    }
    [pscustomobject]@{ ToolsReady = $ready; Devices = $devices }
}
