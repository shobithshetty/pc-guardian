BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\src\PcGuardian\PcGuardian.psd1') -Force
    $script:data = Join-Path ([IO.Path]::GetTempPath()) ('pcg-ign-' + [guid]::NewGuid())
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ('pcg-files-' + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $script:data, $script:work | Out-Null
    $script:file = Join-Path $script:work 'sample.bin'
    Set-Content -Path $script:file -Value 'some harmless sample bytes'
}

Describe 'ignoring a flagged file' {
    It 'hides the finding while the file is unchanged' {
        Add-GuardianIgnoredFile -Path $script:file -DataPath $script:data
        $f = [pscustomobject]@{ Category = 'Malware'; Key = "Malware:$($script:file)"; Detail = 'x' }
        $r = @(InModuleScope PcGuardian -Parameters @{ f = $f; d = $script:data } { param($f, $d) Remove-SuppressedMalware -Finding @($f) -DataPath $d })
        $r.Count | Should -Be 0
    }
    It 'reports the finding again once the file changes' {
        Add-Content -Path $script:file -Value '// changed'
        $f = [pscustomobject]@{ Category = 'Malware'; Key = "Malware:YARA:$($script:file)"; Detail = 'x' }
        $r = @(InModuleScope PcGuardian -Parameters @{ f = $f; d = $script:data } { param($f, $d) Remove-SuppressedMalware -Finding @($f) -DataPath $d })
        $r.Count | Should -Be 1
    }
    It 'does not touch findings that are not file detections' {
        $f = [pscustomobject]@{ Category = 'Memory'; Key = 'Memory:x.exe'; Detail = 'x' }
        @(InModuleScope PcGuardian -Parameters @{ f = $f; d = $script:data } { param($f, $d) Remove-SuppressedMalware -Finding @($f) -DataPath $d }).Count | Should -Be 1
    }
    It 'refuses a file that does not exist' {
        { Add-GuardianIgnoredFile -Path (Join-Path $script:work 'nope.bin') -DataPath $script:data } | Should -Throw
    }
    It 'lists and removes ignored files' {
        Add-GuardianIgnoredFile -Path $script:file -DataPath $script:data
        @(Get-GuardianIgnoredFile -DataPath $script:data).Count | Should -Be 1
        Remove-GuardianIgnoredFile -Path $script:file -DataPath $script:data
        @(Get-GuardianIgnoredFile -DataPath $script:data).Count | Should -Be 0
    }
}

Describe 'detection-rule files are not findings' {
    It 'drops detections on .yar, .yara and .yarc files wherever they are' {
        $fs = foreach ($n in 'a.yar', 'b.YARA', 'c.yarc') { [pscustomobject]@{ Category = 'Malware'; Key = "Malware:YARA:C:\Users\x\Temp\$n"; Detail = 'x' } }
        $keep = [pscustomobject]@{ Category = 'Malware'; Key = 'Malware:C:\Users\x\Temp\evil.exe'; Detail = 'x' }
        $r = @(InModuleScope PcGuardian -Parameters @{ f = @($fs) + $keep; d = $script:data } { param($f, $d) Remove-SuppressedMalware -Finding $f -DataPath $d })
        $r.Count | Should -Be 1
        $r[0].Key | Should -Match 'evil\.exe$'
    }
}

Describe 'pc-guardian does not report its own folders' {
    It 'drops a detection inside the data folder but keeps one elsewhere' {
        $own   = [pscustomobject]@{ Category = 'Malware'; Key = "Malware:YARA:$($script:data)\yara\rules\thor-webshells.yar"; Detail = 'x' }
        $other = [pscustomobject]@{ Category = 'Malware'; Key = "Malware:$($script:work)\other.exe"; Detail = 'x' }
        $r = @(InModuleScope PcGuardian -Parameters @{ a = $own; b = $other; d = $script:data } { param($a, $b, $d) Remove-SuppressedMalware -Finding @($a, $b) -DataPath $d })
        $r.Count | Should -Be 1
        $r[0].Key | Should -Match 'other\.exe$'
    }
}
