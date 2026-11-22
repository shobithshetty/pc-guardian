BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\src\PcGuardian\PcGuardian.psd1') -Force
}

Describe 'Test-YaraRuleUsesExternals' {
    BeforeAll {
        $script:dir = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid())
        New-Item -ItemType Directory -Path $script:dir | Out-Null
        function script:Check($text) {
            $f = Join-Path $script:dir ([guid]::NewGuid().ToString() + '.yar')
            Set-Content -Path $f -Value $text
            InModuleScope PcGuardian -Parameters @{ f = $f } { param($f) Test-YaraRuleUsesExternals -Path $f }
        }
    }
    It 'flags filename matches'   { Check 'rule a { condition: filename matches /x/i }' | Should -BeTrue }
    It 'flags extension equality' { Check 'rule a { condition: extension == ".dll" and filesize < 1KB }' | Should -BeTrue }
    It 'flags filepath contains'  { Check 'rule a { condition: filepath contains "temp" }' | Should -BeTrue }
    It 'ignores words in comments' { Check "// owner == bob`nrule a { condition: true }" | Should -BeFalse }
    It 'ignores words in strings'  { Check 'rule a { strings: $s = "filename matches" condition: $s }' | Should -BeFalse }
    It 'ignores ordinary rules'    { Check 'rule a { strings: $s = "evil" condition: $s }' | Should -BeFalse }
}
