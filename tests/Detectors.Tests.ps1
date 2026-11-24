BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\src\PcGuardian\PcGuardian.psd1') -Force
    $script:pinsPath = Join-Path $PSScriptRoot '..\src\PcGuardian\data\pins.json'
}

Describe 'extra detector pins' {
    It 'pins the programs to an exact version and hash' {
        $p = Get-Content $script:pinsPath -Raw | ConvertFrom-Json
        foreach ($n in 'hayabusa', 'hollowsHunter') {
            $p.$n.version | Should -Match '^v\d+\.\d+\.\d+(\.\d+)?$'
            $p.$n.sha256  | Should -Match '^[0-9a-f]{64}$'
            $p.$n.repo    | Should -Match '^[\w.-]+/[\w.-]+$'
        }
    }
    It 'downloads only over https' {
        $p = Get-Content $script:pinsPath -Raw | ConvertFrom-Json
        $p.lolDrivers.url | Should -Match '^https://'
    }
}

Describe 'ConvertFrom-LolDriversList' {
    BeforeAll {
        # Mirrors the real list: keys that differ only by case ("init"/"INIT") must not matter, because it is read as text.
        $script:sample = @'
[
 {"Id": "11111111-2222-3333-4444-555555555555", "Category": "malicious", "Tags": ["evil.sys"],
  "KnownVulnerableSamples": [ {"SHA256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "init": 1, "INIT": 2,
   "Authentihash": {"SHA256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}} ]},
 {"Id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "Category": "vulnerable driver", "Tags": ["old.sys"],
  "KnownVulnerableSamples": [ {"SHA256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"} ]}
]
'@
    }
    It 'maps lower-cased hashes to name and category' {
        $r = InModuleScope PcGuardian -Parameters @{ t = $script:sample } { param($t)
            $m = ConvertFrom-LolDriversList -Text $t
            [pscustomobject]@{ Count = $m.Count; Evil = $m[('a' * 64)].Category; Name = $m[('a' * 64)].Name; Old = $m[('b' * 64)].Category } }
        $r.Evil | Should -Be 'malicious'
        $r.Name | Should -Be 'evil.sys'
        $r.Old  | Should -Be 'vulnerable driver'
    }
    It 'returns nothing for garbage and never throws' {
        $c = InModuleScope PcGuardian { (ConvertFrom-LolDriversList -Text 'not json at all <<<').Count }
        $c | Should -Be 0
    }
}

Describe 'Invoke-DriverCheck' {
    BeforeAll {
        $script:dir = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid())
        New-Item -ItemType Directory -Path $script:dir | Out-Null
        $script:bad = Join-Path $script:dir 'evil.sys'
        $script:ok  = Join-Path $script:dir 'fine.sys'
        Set-Content -Path $script:bad -Value 'bad driver bytes'
        Set-Content -Path $script:ok  -Value 'harmless bytes'
        $h = (Get-FileHash $script:bad -Algorithm SHA256).Hash
        $script:list = Join-Path $script:dir 'drivers.json'
        Set-Content -Path $script:list -Value ('[{"Id": "11111111-2222-3333-4444-555555555555", "Category": "malicious", "Tags": ["evil.sys"], "KnownVulnerableSamples": [{"SHA256": "' + $h + '"}]}]')
    }
    It 'flags a driver whose hash is on the list and leaves others alone' {
        $r = @(InModuleScope PcGuardian -Parameters @{ l = $script:list; f = @($script:bad, $script:ok) } { param($l, $f) Invoke-DriverCheck -ListPath $l -DriverFile $f })
        $r.Count | Should -Be 1
        $r[0].Key | Should -Be 'Driver:Malicious:evil.sys'
    }
    It 'says so when the list is missing instead of failing' {
        $r = InModuleScope PcGuardian { Invoke-DriverCheck -ListPath 'Z:\nope\drivers.json' -DriverFile @() }
        $r.Key | Should -Be 'Driver:NoList'
    }
}

Describe 'ConvertFrom-HollowsHunterReport' {
    It 'is quiet when nothing is suspicious' {
        $j = '{ "scanned_count" : 126, "failed_count" : 164, "suspicious_count" : 0 }'
        @(InModuleScope PcGuardian -Parameters @{ j = $j } { param($j) ConvertFrom-HollowsHunterReport -Json $j }).Count | Should -Be 0
    }
    It 'reports a generic finding when the count is non-zero but no names are given' {
        $j = '{ "scanned_count" : 5, "suspicious_count" : 2 }'
        $r = @(InModuleScope PcGuardian -Parameters @{ j = $j } { param($j) ConvertFrom-HollowsHunterReport -Json $j })
        $r.Count | Should -Be 1
        $r[0].Key | Should -Be 'Memory:Suspicious'
    }
    It 'names processes when the report lists them' {
        $j = 'banner text { "suspicious_count" : 1, "suspicious" : [ { "pid" : 4242, "name" : "C:\\Users\\x\\evil.exe" } ] }'
        $r = @(InModuleScope PcGuardian -Parameters @{ j = $j } { param($j) ConvertFrom-HollowsHunterReport -Json $j })
        $r.Count | Should -Be 1
        $r[0].Key | Should -Be 'Memory:evil.exe'
    }
    It 'ignores output that is not a report' {
        @(InModuleScope PcGuardian { ConvertFrom-HollowsHunterReport -Json 'error: access denied' }).Count | Should -Be 0
    }
}

Describe 'ConvertFrom-HayabusaTimeline' {
    It 'groups many events into one finding per rule' {
        $lines = @(
            '{"Timestamp":"2026-11-01 10:00:00.000 +00:00","RuleTitle":"Suspicious Service Path","Level":"high"}',
            '{"Timestamp":"2026-11-03 10:00:00.000 +00:00","RuleTitle":"Suspicious Service Path","Level":"high"}',
            '{"Timestamp":"2026-11-02 09:00:00.000 +00:00","RuleTitle":"Other Rule","Level":"critical"}',
            'not json', '')
        $r = @(InModuleScope PcGuardian -Parameters @{ l = $lines } { param($l) ConvertFrom-HayabusaTimeline -Line $l })
        $r.Count | Should -Be 2
        ($r | Where-Object Key -eq 'EventLog:Suspicious Service Path').Detail | Should -Match '^2 event'
        ($r | Where-Object Key -eq 'EventLog:Suspicious Service Path').Detail | Should -Match '2026-11-03'
    }
    It 'returns nothing for an empty timeline' {
        @(InModuleScope PcGuardian { ConvertFrom-HayabusaTimeline -Line @() }).Count | Should -Be 0
    }
}

Describe 'trusted certificate check' {
    It 'reads the stores without the Cert: drive and finds the same roots as it' {
        $r = InModuleScope PcGuardian {
            $viaApi = @(Get-CertificateStoreItem -Location LocalMachine -Name Root).Count
            $viaDrive = @(Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue).Count
            [pscustomobject]@{ Api = $viaApi; Drive = $viaDrive; Findings = @(Get-RootCertificateAudit | Where-Object Category -eq 'Certificate').Count }
        }
        $r.Api | Should -BeGreaterThan 0
        $r.Api | Should -Be $r.Drive
        $r.Findings | Should -BeGreaterThan 0
    }
    It 'says so when a store cannot be read' {
        @(InModuleScope PcGuardian { Get-CertificateStoreItem -Location LocalMachine -Name 'NoSuchStoreName123' }).Count | Should -Be 0
    }
}

Describe 'severity of the extra detectors' {
    It 'alerts on memory injection and event-log detections' {
        InModuleScope PcGuardian { Get-FindingSeverity -Finding (New-Finding -Category 'Memory' -Key 'Memory:x.exe' -Detail 'd') } | Should -Be 'Alert'
        InModuleScope PcGuardian { Get-FindingSeverity -Finding (New-Finding -Category 'EventLog' -Key 'EventLog:r' -Detail 'd') } | Should -Be 'Alert'
    }
    It 'alerts on a malicious driver and only informs on a vulnerable one' {
        InModuleScope PcGuardian { Get-FindingSeverity -Finding (New-Finding -Category 'Driver' -Key 'Driver:Malicious:a.sys' -Detail 'd') } | Should -Be 'Alert'
        InModuleScope PcGuardian { Get-FindingSeverity -Finding (New-Finding -Category 'Driver' -Key 'Driver:Vulnerable:a.sys' -Detail 'd') } | Should -Be 'Info'
    }
}
