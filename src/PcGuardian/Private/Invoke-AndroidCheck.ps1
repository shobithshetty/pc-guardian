function ConvertFrom-StalkerwareList {
    <#
    .SYNOPSIS
        Reads the public stalkerware indicator lists (ioc.yaml, watchware.yaml) into a lookup of package name -> app.
    .DESCRIPTION
        The lists are untrusted data. They are read line by line with fixed patterns, never evaluated, and only
        package names (reverse-domain identifiers) are kept. Returns a hashtable keyed by lower-case package name.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [string]$DefaultType = 'stalkerware')

    $map = @{}
    $name = ''; $type = $DefaultType; $inPackages = $false
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^- name:\s*(?<n>.+?)\s*$') { $name = $Matches.n.Trim('"', "'"); $type = $DefaultType; $inPackages = $false; continue }
        if ($line -match '^  type:\s*(?<t>\w+)') { $type = $Matches.t; continue }
        if ($line -match '^  packages:\s*$') { $inPackages = $true; continue }
        if ($line -match '^  [A-Za-z_]+:') { $inPackages = $false; continue }
        if ($inPackages -and $line -match '^  - (?<p>[A-Za-z][\w]*(\.[\w]+)+)\s*$') {
            $pkg = $Matches.p.ToLowerInvariant()
            if (-not $map.ContainsKey($pkg)) { $map[$pkg] = [pscustomobject]@{ Name = $name; Type = $type } }
        }
    }
    $map
}

function Get-AndroidDevice {
    <#
    .SYNOPSIS
        Lists devices that adb can see (read-only). Needs only the adb program.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Adb)

    $lines = & $Adb devices -l 2>&1
    foreach ($l in $lines) {
        if ("$l" -match '^(?<s>\S+)\s+(?<st>device|unauthorized|offline|recovery|sideload)\b(?<rest>.*)$') {
            # Copy the groups first: the next -match would overwrite $Matches.
            $serial = $Matches.s; $state = $Matches.st; $rest = $Matches.rest
            $model = if ($rest -match 'model:(?<m>\S+)') { $Matches.m } else { '' }
            [pscustomobject]@{
                Serial    = $serial
                State     = $state
                Model     = $model
                Transport = $(if ($serial -like 'adb-*' -or $serial -match ':\d+$') { 'wireless' } else { 'usb' })
            }
        }
    }
}

function Get-AndroidDeviceSettled {
    <#
    .SYNOPSIS
        Like Get-AndroidDevice, but waits for a freshly started adb server to finish finding devices.
    .DESCRIPTION
        Right after adb starts, the first listing can be missing a device or show it "offline" for a moment.
        If nothing is listed, or something is offline, it waits two seconds and lists again (up to twice).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Adb, [int]$WaitMilliseconds = 2000)
    $devices = @(Get-AndroidDevice -Adb $Adb)
    for ($i = 0; $i -lt 2 -and (($devices.Count -eq 0) -or @($devices | Where-Object State -eq 'offline').Count -gt 0); $i++) {
        Start-Sleep -Milliseconds $WaitMilliseconds
        $devices = @(Get-AndroidDevice -Adb $Adb)
    }
    $devices
}

function Test-AndroidReadOnlyCommand {
    <#
    .SYNOPSIS
        True only for the small set of read-only adb shell commands pc-guardian is allowed to send to a phone.
    .DESCRIPTION
        This is a safety fence: whatever else the code does, it cannot ask the phone for messages, photos or files,
        and cannot change anything. Each allowed command reads a setting or lists package names.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Command)
    $allowed = @(
        '^getprop$',
        '^pm list packages( -3| -i -3| -s)?$',
        '^dumpsys device_policy$',
        '^settings get secure (enabled_accessibility_services|enabled_notification_listeners)$',
        '^settings get global (adb_enabled|adb_wifi_enabled|development_settings_enabled)$'
    )
    foreach ($a in $allowed) { if ($Command -match $a) { return $true } }
    $false
}

function Invoke-AndroidCheck {
    <#
    .SYNOPSIS
        Checks one authorized Android phone or tablet for stalkerware and risky settings (read-only).
    .DESCRIPTION
        Reads only settings and app package names through the read-only allowlist: the Android version and security
        patch date, installed app names, apps with device-administrator, accessibility or notification-listener
        powers, apps installed from outside the usual stores, and whether USB or wireless debugging is on.
        App names are compared with the public stalkerware indicator lists. Nothing is uploaded; no message, photo or
        file is read.
    .PARAMETER Runner
        Replaces the real adb call (used by tests). Receives the shell command text and returns its output lines.
    #>
    [CmdletBinding()]
    param(
        [string]$Adb,
        [Parameter(Mandatory)][string]$Serial,
        [hashtable]$Indicators = @{},
        [scriptblock]$Runner,
        [datetime]$Today = (Get-Date)
    )

    $send = {
        param([string]$cmd)
        if (-not (Test-AndroidReadOnlyCommand -Command $cmd)) { throw "Refused: '$cmd' is not an allowed read-only phone command." }
        if ($Runner) { return @(& $Runner $cmd) }
        @(& $Adb -s $Serial shell $cmd 2>&1)
    }

    $props = @{}
    foreach ($l in (& $send 'getprop')) {
        if ("$l" -match '^\[(?<k>[^\]]+)\]: \[(?<v>.*)\]$') { $props[$Matches.k] = $Matches.v }
    }
    $model   = "$($props['ro.product.manufacturer']) $($props['ro.product.model'])".Trim()
    $android = $props['ro.build.version.release']
    $patch   = $props['ro.build.version.security_patch']
    $device  = [pscustomobject]@{ Serial = $Serial; Model = $model; Android = $android; SecurityPatch = $patch }
    $findings = New-Object System.Collections.Generic.List[object]
    $add = { param($key, $detail) $findings.Add((New-Finding -Category 'Phone' -Key $key -Detail $detail)) }

    # Reverse-domain names of the makers' own system components. They keep the "powers" lists short and are never
    # used to skip the stalkerware check, which looks at every installed package.
    $common = '^(android|com\.(google|android|samsung|sec|qualcomm|qti|knox|osp|microsoft|facebook)|org\.codeaurora|com\.sec)\.'
    # Recognised app stores, including F-Droid (the open-source store) and the Aurora client for Google Play.
    $storeInstallers = '^(com\.android\.vending|com\.sec\.android\.app\.samsungapps|com\.amazon\.venezia|com\.huawei\.appmarket|com\.xiaomi\.mipicks|com\.heytap\.market|com\.oppo\.market|org\.fdroid\.fdroid|org\.fdroid\.basic|com\.aurora\.store)$'

    # 1. Every installed package against the stalkerware lists.
    $all = @((& $send 'pm list packages') | ForEach-Object { if ("$_" -match '^package:(?<p>\S+)') { $Matches.p } })
    foreach ($p in $all) {
        $hit = $Indicators[$p.ToLowerInvariant()]
        if ($hit) {
            $kind = if ($hit.Type -eq 'stalkerware') { 'Stalkerware' } else { 'Watchware' }
            & $add "Phone:${kind}:$p" ("{0} ({1}) is installed on {2}: package {3}. {4}" -f $hit.Name, $hit.Type, $model, $p,
                $(if ($kind -eq 'Stalkerware') { 'This kind of app secretly reports the phone owner''s location, messages and more.' } else { 'A monitoring app that may be legitimate (parental control, company device management) if you installed it.' }))
        }
    }

    # 2. Apps from outside the usual stores.
    $third = @((& $send 'pm list packages -i -3') | ForEach-Object {
        if ("$_" -match '^package:(?<p>\S+)\s+installer=(?<i>\S+)') { [pscustomobject]@{ Package = $Matches.p; Installer = $Matches.i } }
    })
    foreach ($t in $third) {
        if ($t.Installer -notmatch $storeInstallers -and $t.Package -notmatch $common) {
            & $add "Phone:Sideloaded:$($t.Package)" "Installed from outside the app stores (installer: $($t.Installer)). Fine if you installed it yourself from a file; worth a look if not."
        }
    }

    # 3. Apps with powers that stalkerware relies on.
    $adminSection = $false
    foreach ($l in (& $send 'dumpsys device_policy')) {
        $s = "$l"
        if ($s -match 'Enabled Device Admins') { $adminSection = $true; continue }
        if ($adminSection) {
            if ($s -match '^\s+(?<p>[A-Za-z][\w]*(\.[\w]+)+)/(?<c>\S+?):\s*$') {
                if ($Matches.p -notmatch $common) { & $add "Phone:DeviceAdmin:$($Matches.p)" 'Has device-administrator rights: it can lock the phone, block uninstalling, and set rules. Normal for work or parental-control apps you set up; suspicious if you did not.' }
            }
            elseif ($s -match '^\S') { $adminSection = $false }
        }
    }
    foreach ($pair in @(@('enabled_accessibility_services', 'Accessibility', 'Is an accessibility service: it can read the screen and what is typed. Normal for screen readers and password managers; a common stalkerware trick otherwise.'),
                        @('enabled_notification_listeners', 'NotificationListener', 'Can read every notification, including message previews and one-time codes. Normal for smartwatch and some assistant apps; suspicious if you do not know it.'))) {
        $raw = ((& $send "settings get secure $($pair[0])") -join '').Trim()
        if ($raw -and $raw -ne 'null') {
            foreach ($comp in ($raw -split ':')) {
                if ($comp -match '^(?<p>[A-Za-z][\w]*(\.[\w]+)+)/') {
                    if ($Matches.p -notmatch $common) { & $add "Phone:$($pair[1]):$($Matches.p)" $pair[2] }
                }
            }
        }
    }

    # 4. Software age and debugging switches.
    if ($patch -match '^\d{4}-\d{2}-\d{2}$') {
        $age = ($Today - [datetime]::ParseExact($patch, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)).TotalDays
        if ($age -gt 365) { & $add 'Phone:SecurityPatch' ("The last Android security update is dated $patch ({0:N0} months ago). Old phones miss fixes for flaws that spyware uses." -f ($age / 30.4)) }
    }
    $wifiDebug = ((& $send 'settings get global adb_wifi_enabled') -join '').Trim()
    if ($wifiDebug -eq '1') { & $add 'Phone:WirelessDebugging' 'Wireless debugging is on: a computer on the same Wi-Fi that was paired once can control this phone. Turn it off in Developer options when you are not using it.' }

    [pscustomobject]@{
        Device     = $device
        Packages   = $all.Count
        ThirdParty = $third.Count
        Findings   = [object[]]$findings.ToArray()
        Checked    = @('installed apps against stalkerware lists', 'apps installed outside the stores', 'device-administrator apps', 'accessibility services', 'notification listeners', 'Android security-patch age', 'wireless debugging')
    }
}
