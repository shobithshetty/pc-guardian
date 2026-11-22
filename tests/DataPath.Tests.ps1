BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\src\PcGuardian\PcGuardian.psd1') -Force
}

Describe 'Get-GuardianDataPath' {
    BeforeEach { $script:old = $env:PCGUARDIAN_DATA }
    AfterEach  { $env:PCGUARDIAN_DATA = $script:old }

    It 'defaults to the standard Windows location' {
        $env:PCGUARDIAN_DATA = $null
        (InModuleScope PcGuardian { Get-GuardianDataPath }) | Should -Be (Join-Path $env:LOCALAPPDATA 'PcGuardian')
    }
    It 'uses PCGUARDIAN_DATA when it is set' {
        $env:PCGUARDIAN_DATA = 'F:\somewhere\pc-guardian-data'
        (InModuleScope PcGuardian { Get-GuardianDataPath }) | Should -Be 'F:\somewhere\pc-guardian-data'
    }
    It 'lets every setting command follow the override' {
        $d = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid())
        $env:PCGUARDIAN_DATA = $d
        Set-GuardianSetting -Name virusTotal -Value $true
        Test-Path (Join-Path $d 'settings.json') | Should -BeTrue
        (Get-GuardianSetting).virusTotal | Should -BeTrue
        Add-GuardianSafeItem -Key 'Task:\Demo'
        @(Get-GuardianSafeItem).Key | Should -Be @('Task:\Demo')
    }
}
