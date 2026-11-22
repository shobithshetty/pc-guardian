BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\src\PcGuardian\PcGuardian.psd1') -Force
    function script:NewDir { Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid()) }
}

Describe 'Settings' {
    It 'defaults VirusTotal to off with no key' {
        $s = Get-GuardianSetting -DataPath (NewDir)
        $s.virusTotal | Should -BeFalse
        $s.virusTotalKeySet | Should -BeFalse
    }
    It 'saves and reads a setting' {
        $d = NewDir
        Set-GuardianSetting -Name virusTotal -Value $true -DataPath $d
        (Get-GuardianSetting -DataPath $d).virusTotal | Should -BeTrue
        Set-GuardianSetting -Name virusTotal -Value $false -DataPath $d
        (Get-GuardianSetting -DataPath $d).virusTotal | Should -BeFalse
    }
    It 'saves the osv setting without losing the others' {
        $d = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid())
        Set-GuardianSetting -Name virusTotal -Value $true -DataPath $d
        Set-GuardianSetting -Name osv -Value $true -DataPath $d
        $s = Get-GuardianSetting -DataPath $d
        $s.virusTotal | Should -BeTrue
        $s.osv | Should -BeTrue
    }
    It 'adds and removes code folders and keeps the other settings' {
        $d = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid())
        $code = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid()); New-Item -ItemType Directory -Path $code | Out-Null
        Set-GuardianSetting -Name osv -Value $true -DataPath $d
        Add-GuardianDevFolder -Path $code -DataPath $d
        Add-GuardianDevFolder -Path $code -DataPath $d      # duplicate is ignored
        $s = Get-GuardianSetting -DataPath $d
        @($s.devFolders).Count | Should -Be 1
        $s.osv | Should -BeTrue
        Remove-GuardianDevFolder -Path $code -DataPath $d
        @((Get-GuardianSetting -DataPath $d).devFolders).Count | Should -Be 0
    }
    It 'refuses a folder that does not exist' {
        { Add-GuardianDevFolder -Path 'Z:\no\such\folder' -DataPath (Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid())) } | Should -Throw '*does not exist*'
    }
    It 'rejects unknown settings' {
        { Set-GuardianSetting -Name 'nothing' -Value $true -DataPath (NewDir) } | Should -Throw
    }
    It 'ignores a broken settings file' {
        $d = NewDir; New-Item -ItemType Directory -Path $d | Out-Null
        Set-Content -Path (Join-Path $d 'settings.json') -Value '{ not json'
        (Get-GuardianSetting -DataPath $d).virusTotal | Should -BeFalse
    }
}

Describe 'VirusTotal key' {
    It 'stores a key encrypted, reports it set, and removes it' {
        $d = NewDir
        $secure = ConvertTo-SecureString 'abc123-test-key' -AsPlainText -Force
        Set-GuardianVirusTotalKey -Key $secure -DataPath $d | Out-Null
        (Get-GuardianSetting -DataPath $d).virusTotalKeySet | Should -BeTrue
        (Get-Content (Join-Path $d 'vt.key') -Raw) | Should -Not -Match 'abc123-test-key'
        Set-GuardianVirusTotalKey -Remove -DataPath $d | Out-Null
        (Get-GuardianSetting -DataPath $d).virusTotalKeySet | Should -BeFalse
    }
}

Describe 'Get-GuardianDailyScan' {
    It 'returns Exists, Enabled and At' {
        $r = Get-GuardianDailyScan
        $r.PSObject.Properties.Name | Should -Contain 'Exists'
        $r.PSObject.Properties.Name | Should -Contain 'Enabled'
        $r.PSObject.Properties.Name | Should -Contain 'At'
    }
}
