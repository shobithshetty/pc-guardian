BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\src\PcGuardian\PcGuardian.psd1') -Force
    $script:pinsPath = Join-Path $PSScriptRoot '..\src\PcGuardian\data\pins.json'
}

Describe 'pins.json' {
    It 'pins every download to an exact version and hash' {
        $p = Get-Content $script:pinsPath -Raw | ConvertFrom-Json
        $p.yara.version      | Should -Match '^v\d+\.\d+\.\d+$'
        $p.yara.sha256       | Should -Match '^[0-9a-f]{64}$'
        $p.rules.commit      | Should -Match '^[0-9a-f]{40}$'
        $p.rules.contentSha256 | Should -Match '^[0-9a-f]{64}$'
    }
}

Describe 'Get-RuleSetHash' {
    BeforeAll {
        $script:d = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid())
        New-Item -ItemType Directory -Path $script:d | Out-Null
        Set-Content -Path (Join-Path $script:d 'a.yar') -Value 'rule a { condition: true }'
        Set-Content -Path (Join-Path $script:d 'b.yar') -Value 'rule b { condition: true }'
    }
    It 'is stable for the same contents' {
        InModuleScope PcGuardian -Parameters @{ d = $script:d } { param($d) (Get-RuleSetHash -Path $d) -eq (Get-RuleSetHash -Path $d) } | Should -BeTrue
    }
    It 'changes when one rule file changes' {
        $before = InModuleScope PcGuardian -Parameters @{ d = $script:d } { param($d) Get-RuleSetHash -Path $d }
        Add-Content -Path (Join-Path $script:d 'b.yar') -Value '// tampered'
        $after = InModuleScope PcGuardian -Parameters @{ d = $script:d } { param($d) Get-RuleSetHash -Path $d }
        $after | Should -Not -Be $before
    }
}
