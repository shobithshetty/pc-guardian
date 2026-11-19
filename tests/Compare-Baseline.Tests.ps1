BeforeAll {
    $module = Join-Path $PSScriptRoot '..\src\PcGuardian\PcGuardian.psd1'
    Import-Module $module -Force
}

Describe 'Compare-Baseline' {
    BeforeAll {
        function F($c, $k, $d = '') { [pscustomobject]@{ Category = $c; Key = $k; Detail = $d } }
    }

    It 'reports a new finding' {
        InModuleScope PcGuardian {
            $base = @([pscustomobject]@{ Category = 'Port'; Key = 'Port:135:svchost'; Detail = '' })
            $cur  = @($base[0], [pscustomobject]@{ Category = 'Port'; Key = 'Port:8001:python'; Detail = '' })
            $diff = Compare-Baseline -Baseline $base -Current $cur
            $diff.New.Count | Should -Be 1
            $diff.New[0].Key | Should -Be 'Port:8001:python'
            $diff.Removed.Count | Should -Be 0
        }
    }

    It 'reports a removed finding' {
        InModuleScope PcGuardian {
            $base = @([pscustomobject]@{ Category = 'Task'; Key = 'Task:\Foo'; Detail = '' })
            $diff = Compare-Baseline -Baseline $base -Current @()
            $diff.Removed.Count | Should -Be 1
            $diff.New.Count | Should -Be 0
        }
    }

    It 'ignores Detail-only changes' {
        InModuleScope PcGuardian {
            $base = @([pscustomobject]@{ Category = 'Defender'; Key = 'Defender:Signatures'; Detail = 'old' })
            $cur  = @([pscustomobject]@{ Category = 'Defender'; Key = 'Defender:Signatures'; Detail = 'new' })
            $diff = Compare-Baseline -Baseline $base -Current $cur
            $diff.New.Count | Should -Be 0
            $diff.Removed.Count | Should -Be 0
        }
    }
}
