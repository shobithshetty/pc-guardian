BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\src\PcGuardian\PcGuardian.psd1') -Force
}

Describe 'ConvertFrom-VirusTotalFile' {
    It 'reads malicious and suspicious counts' {
        InModuleScope PcGuardian {
            $resp = [pscustomobject]@{ data = [pscustomobject]@{ attributes = [pscustomobject]@{
                last_analysis_stats = [pscustomobject]@{ malicious = 12; suspicious = 2; harmless = 0; undetected = 50 } } } }
            $v = ConvertFrom-VirusTotalFile -Response $resp
            $v.Known | Should -BeTrue
            $v.Malicious | Should -Be 12
            $v.Suspicious | Should -Be 2
        }
    }
    It 'treats a missing response (404) as unknown' {
        InModuleScope PcGuardian {
            (ConvertFrom-VirusTotalFile -Response $null).Known | Should -BeFalse
        }
    }
}

Describe 'Invoke-VirusTotalCheck' {
    It 'skips with an Info finding when no key is configured' {
        InModuleScope PcGuardian {
            $tmp = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid())
            $old = $env:PCGUARDIAN_VT_KEY; $env:PCGUARDIAN_VT_KEY = $null
            try {
                $f = Invoke-VirusTotalCheck -Path $tmp -DataPath $tmp
                $f.Key | Should -Be 'VirusTotal:NoKey'
            } finally { $env:PCGUARDIAN_VT_KEY = $old }
        }
    }
}
