BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\src\PcGuardian\PcGuardian.psd1') -Force
}

Describe 'ConvertFrom-WingetUpgrade' {
    It 'parses names with spaces using header column positions' {
        InModuleScope PcGuardian {
            $lines = @(
                'Name                    Id              Version  Available Source',
                '-----------------------------------------------------------------',
                'Google Chrome           Google.Chrome   130.0.1  131.0.2   winget',
                'Visual Studio Code      Microsoft.VSCode 1.94.0  1.95.1    winget',
                '2 upgrades available.'
            )
            $apps = @(ConvertFrom-WingetUpgrade -Lines $lines)
            $apps.Count | Should -Be 2
            $apps[0].Name | Should -Be 'Google Chrome'
            $apps[0].Id | Should -Be 'Google.Chrome'
            $apps[0].Available | Should -Be '131.0.2'
        }
    }
    It 'returns nothing when there is no table' {
        InModuleScope PcGuardian {
            @(ConvertFrom-WingetUpgrade -Lines @('No installed package found matching input criteria.')).Count | Should -Be 0
        }
    }
}
