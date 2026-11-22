BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\src\PcGuardian\PcGuardian.psd1') -Force
    function script:NewDir { $d = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid()); New-Item -ItemType Directory -Path $d | Out-Null; $d }
}

Describe 'Safe list' {
    It 'starts empty' {
        @(Get-GuardianSafeItem -DataPath (NewDir)).Count | Should -Be 0
    }
    It 'stores one item as a list, not a bare object' {
        $d = NewDir
        Add-GuardianSafeItem -Key 'Task:\Example' -DataPath $d
        $items = @(Get-GuardianSafeItem -DataPath $d)
        $items.Count | Should -Be 1
        $items[0].Key | Should -Be 'Task:\Example'
    }
    It 'ignores duplicates' {
        $d = NewDir
        Add-GuardianSafeItem -Key 'a' -DataPath $d
        Add-GuardianSafeItem -Key 'a' -DataPath $d
        @(Get-GuardianSafeItem -DataPath $d).Count | Should -Be 1
    }
    It 'removes an item' {
        $d = NewDir
        Add-GuardianSafeItem -Key 'a' -DataPath $d
        Add-GuardianSafeItem -Key 'b' -DataPath $d
        Remove-GuardianSafeItem -Key 'a' -DataPath $d
        @(Get-GuardianSafeItem -DataPath $d).Key | Should -Be @('b')
    }
    It 'marks several keys safe in one call and skips duplicates' {
        $d = NewDir
        Add-GuardianSafeItem -Key 'a' -DataPath $d
        Add-GuardianSafeItem -Key @('a', 'b', 'c') -DataPath $d
        (@(Get-GuardianSafeItem -DataPath $d).Key | Sort-Object) | Should -Be @('a', 'b', 'c')
    }
    It 'refuses the whole batch if one key is malware' {
        $d = NewDir
        { Add-GuardianSafeItem -Key @('ok', 'Malware:YARA:C:\x.exe') -DataPath $d } | Should -Throw '*cannot be marked safe*'
        @(Get-GuardianSafeItem -DataPath $d).Count | Should -Be 0
    }
    It 'refuses to mark malware as safe' {
        { Add-GuardianSafeItem -Key 'Malware:YARA:C:\x.exe' -DataPath (NewDir) } | Should -Throw '*cannot be marked safe*'
    }
}

Describe 'Invoke-GuardianRun -AsObject' {
    It 'returns structured results and hides items on the safe list' {
        $d = NewDir
        $first = Invoke-GuardianRun -DataPath $d -AsObject
        $first.FirstRun | Should -BeTrue
        $first.BaselineCount | Should -BeGreaterThan 0

        # Pretend one baseline entry is gone so the next run sees it as new, then mark it safe.
        $b = @(Get-Content (Join-Path $d 'baseline.json') -Raw | ConvertFrom-Json | ForEach-Object { $_ })
        $gone = $b[0]
        ConvertTo-Json -InputObject @($b | Select-Object -Skip 1) -Depth 4 | Set-Content (Join-Path $d 'baseline.json')

        $second = Invoke-GuardianRun -DataPath $d -AsObject
        $second.FirstRun | Should -BeFalse
        @($second.Items | Where-Object { $_.Kind -eq 'New' -and $_.Key -eq $gone.Key }).Count | Should -Be 1

        Add-GuardianSafeItem -Key $gone.Key -DataPath $d
        $third = Invoke-GuardianRun -DataPath $d -AsObject
        @($third.Items | Where-Object { $_.Kind -eq 'New' -and $_.Key -eq $gone.Key }).Count | Should -Be 0
    }
}
