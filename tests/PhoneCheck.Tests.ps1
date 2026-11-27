BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\src\PcGuardian\PcGuardian.psd1') -Force
}

Describe 'phone tools download' {
    It 'pins adb to an exact version, hashes and signer' {
        $p = Get-Content (Join-Path $PSScriptRoot '..\src\PcGuardian\data\pins.json') -Raw | ConvertFrom-Json
        $p.adb.sha256 | Should -Match '^[0-9a-f]{64}$'
        $p.adb.sha1   | Should -Match '^[0-9a-f]{40}$'
        $p.adb.url    | Should -Match '^https://dl\.google\.com/android/repository/platform-tools_r[\d.]+-win\.zip$'
        $p.adb.signer | Should -Be 'Google LLC'
        $p.phoneLists.stalkerwareUrl | Should -Match '^https://raw\.githubusercontent\.com/AssoEchap/stalkerware-indicators/'
    }
    It 'refuses to download anything until the Android SDK License is accepted' {
        $d = Join-Path ([IO.Path]::GetTempPath()) ('pcg-phone-' + [guid]::NewGuid())
        { Install-GuardianPhoneTools -DataPath $d } | Should -Throw '*Android SDK License*'
        Test-Path $d | Should -BeFalse
    }
    It 'reports not ready and no devices when nothing is downloaded' {
        $d = Join-Path ([IO.Path]::GetTempPath()) ('pcg-phone-' + [guid]::NewGuid())
        $s = Get-GuardianPhoneStatus -DataPath $d
        $s.ToolsReady | Should -BeFalse
        @($s.Devices).Count | Should -Be 0
    }
    It 'says so when another program is running its own adb and no phone is visible' {
        $d = Join-Path ([IO.Path]::GetTempPath()) ('pcg-phone-' + [guid]::NewGuid())
        Mock -ModuleName PcGuardian Get-Process { [pscustomobject]@{ Name = 'adb'; Id = 1 } }
        (Get-GuardianPhoneStatus -DataPath $d).OtherAdbRunning | Should -BeTrue
        Mock -ModuleName PcGuardian Get-Process { }
        (Get-GuardianPhoneStatus -DataPath $d).OtherAdbRunning | Should -BeFalse
    }
    It 'refuses to check a phone before the tools exist' {
        $d = Join-Path ([IO.Path]::GetTempPath()) ('pcg-phone-' + [guid]::NewGuid())
        { Invoke-GuardianPhoneCheck -Serial 'X' -DataPath $d } | Should -Throw '*not downloaded*'
    }
}

Describe 'ConvertFrom-StalkerwareList' {
    BeforeAll {
        $script:yaml = @'
- name: SpyOne
  names:
  - SpyOne
  type: stalkerware
  packages:
  - com.spy.one
  - com.spy.one.helper
  certificates:
  - AABBCC
  websites:
  - spyone.example
- name: Other
  type: stalkerware
  packages:
  - org.other.app
  websites:
  - com.not.a.package.example
'@
    }
    It 'keeps only package names, with the app name and type' {
        $m = InModuleScope PcGuardian -Parameters @{ t = $script:yaml } { param($t) ConvertFrom-StalkerwareList -Text $t }
        $m.Count | Should -Be 3
        $m['com.spy.one'].Name | Should -Be 'SpyOne'
        $m['org.other.app'].Type | Should -Be 'stalkerware'
    }
    It 'ignores list items under other keys such as websites' {
        $m = InModuleScope PcGuardian -Parameters @{ t = $script:yaml } { param($t) ConvertFrom-StalkerwareList -Text $t }
        $m.ContainsKey('com.not.a.package.example') | Should -BeFalse
    }
    It 'returns nothing for garbage and never throws' {
        (InModuleScope PcGuardian { (ConvertFrom-StalkerwareList -Text 'not yaml <<< ###').Count }) | Should -Be 0
    }
}

Describe 'the read-only command fence' {
    It 'allows the reading commands the check uses' {
        InModuleScope PcGuardian {
            'getprop', 'pm list packages', 'pm list packages -i -3', 'dumpsys device_policy',
            'settings get secure enabled_accessibility_services', 'settings get global adb_wifi_enabled' |
                ForEach-Object { Test-AndroidReadOnlyCommand -Command $_ }
        } | Should -Not -Contain $false
    }
    It 'refuses everything that reads personal data or changes the phone' {
        $bad = 'cat /sdcard/DCIM/photo.jpg', 'content query --uri content://sms', 'pm uninstall com.x', 'rm -rf /sdcard', 'am start x',
               'settings put global adb_enabled 0', 'pm list packages; cat /sdcard/x', 'screencap /sdcard/a.png', 'run-as com.x ls'
        $r = InModuleScope PcGuardian -Parameters @{ bad = $bad } { param($bad) $bad | ForEach-Object { Test-AndroidReadOnlyCommand -Command $_ } }
        $r | Should -Not -Contain $true
    }
}

Describe 'Invoke-AndroidCheck' {
    BeforeAll {
        $script:runner = {
            param($cmd)
            switch -Regex ($cmd) {
                '^getprop$' { '[ro.product.manufacturer]: [samsung]'; '[ro.product.model]: [SM-T505]'; '[ro.build.version.release]: [12]'; '[ro.build.version.security_patch]: [2024-06-01]' }
                '^pm list packages$' { 'package:com.android.settings'; 'package:com.spy.one'; 'package:org.fdroid.fdroid'; 'package:com.parent.watch' }
                '^pm list packages -i -3$' {
                    'package:com.spy.one  installer=null'
                    'package:org.fdroid.fdroid  installer=com.android.vending'
                    'package:com.apk.only  installer=null'
                    'package:com.google.something  installer=null'
                }
                '^dumpsys device_policy$' { 'Policy for user 0:'; '  Enabled Device Admins (user 0, provisioningState: 0):'; '    com.spy.one/com.spy.one.Admin:'; '      uid=10123'; '    com.samsung.android.knox/.Admin:'; 'Other section:' }
                'enabled_accessibility_services' { 'com.spy.one/com.spy.one.Access:com.google.android.marvin.talkback/.TalkBackService' }
                'enabled_notification_listeners' { 'null' }
                'adb_wifi_enabled' { '1' }
                default { '' }
            }
        }
        $script:ind = @{
            'com.spy.one'     = [pscustomobject]@{ Name = 'SpyOne'; Type = 'stalkerware' }
            'com.parent.watch' = [pscustomobject]@{ Name = 'ParentWatch'; Type = 'watchware' }
        }
    }
    It 'finds stalkerware, watchware, admin rights, accessibility, sideloading, old patch and wireless debugging' {
        $r = InModuleScope PcGuardian -Parameters @{ run = $script:runner; ind = $script:ind } { param($run, $ind)
            Invoke-AndroidCheck -Serial 'X' -Indicators $ind -Runner $run -Today ([datetime]'2026-11-25')
        }
        $keys = @($r.Findings | ForEach-Object { $_.Key })
        $keys | Should -Contain 'Phone:Stalkerware:com.spy.one'
        $keys | Should -Contain 'Phone:Watchware:com.parent.watch'
        $keys | Should -Contain 'Phone:DeviceAdmin:com.spy.one'
        $keys | Should -Contain 'Phone:Accessibility:com.spy.one'
        $keys | Should -Contain 'Phone:Sideloaded:com.apk.only'
        $keys | Should -Contain 'Phone:SecurityPatch'
        $keys | Should -Contain 'Phone:WirelessDebugging'
    }
    It 'stays quiet about the maker''s own components, recognised stores and talkback' {
        $r = InModuleScope PcGuardian -Parameters @{ run = $script:runner; ind = $script:ind } { param($run, $ind)
            Invoke-AndroidCheck -Serial 'X' -Indicators $ind -Runner $run -Today ([datetime]'2026-11-25')
        }
        $keys = @($r.Findings | ForEach-Object { $_.Key })
        $keys | Should -Not -Contain 'Phone:DeviceAdmin:com.samsung.android.knox'
        $keys | Should -Not -Contain 'Phone:Accessibility:com.google.android.marvin.talkback'
        $keys | Should -Not -Contain 'Phone:Sideloaded:org.fdroid.fdroid'
        $keys | Should -Not -Contain 'Phone:Sideloaded:com.google.something'
    }
    It 'reports the device details' {
        $r = InModuleScope PcGuardian -Parameters @{ run = $script:runner; ind = $script:ind } { param($run, $ind)
            Invoke-AndroidCheck -Serial 'X' -Indicators $ind -Runner $run -Today ([datetime]'2026-11-25')
        }
        $r.Device.Model | Should -Be 'samsung SM-T505'
        $r.Device.Android | Should -Be '12'
        $r.Packages | Should -Be 4
    }
    It 'alerts on stalkerware and wireless debugging, and only informs on the rest' {
        InModuleScope PcGuardian {
            Get-FindingSeverity -Finding (New-Finding -Category 'Phone' -Key 'Phone:Stalkerware:com.x' -Detail 'd')
        } | Should -Be 'Alert'
        InModuleScope PcGuardian {
            Get-FindingSeverity -Finding (New-Finding -Category 'Phone' -Key 'Phone:WirelessDebugging' -Detail 'd')
        } | Should -Be 'Alert'
        InModuleScope PcGuardian {
            Get-FindingSeverity -Finding (New-Finding -Category 'Phone' -Key 'Phone:Sideloaded:com.x' -Detail 'd')
        } | Should -Be 'Info'
    }
}
