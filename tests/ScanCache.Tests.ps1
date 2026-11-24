BeforeDiscovery {
    # -Skip is decided before BeforeAll runs, so the ClamAV check has to live here. CI has no ClamAV: these skip there.
    Import-Module (Join-Path $PSScriptRoot '..\src\PcGuardian\PcGuardian.psd1') -Force
    $script:clamReady = InModuleScope PcGuardian {
        $c = Find-ClamAv
        [bool]($c -and (Get-ChildItem -Path (Join-Path $c.Database '*') -Include '*.cvd', '*.cld' -ErrorAction SilentlyContinue))
    }
}

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\src\PcGuardian\PcGuardian.psd1') -Force
    $script:dir = Join-Path ([IO.Path]::GetTempPath()) ('pcg-cache-' + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $script:dir | Out-Null
    1..5 | ForEach-Object { Set-Content (Join-Path $script:dir "f$_.txt") "file $_" }
    $script:cache = Join-Path ([IO.Path]::GetTempPath()) ('pcg-cache-' + [guid]::NewGuid() + '.json')
}

Describe 'clean-file memory in the ClamAV scan' {
    It 'remembers clean files, skips them next time, and rescans a file that changed' -Skip:(-not $script:clamReady) {
        $r = InModuleScope PcGuardian -Parameters @{ d = $script:dir; c = $script:cache } { param($d, $c)
            $null = @(Invoke-ClamAvScan -Path $d -CachePath $c)
            $first = @(Get-Content $c -Raw | ConvertFrom-Json | ForEach-Object { $_ }).Count
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $null = @(Invoke-ClamAvScan -Path $d -CachePath $c)
            $secondSeconds = $sw.Elapsed.TotalSeconds
            Add-Content (Join-Path $d 'f3.txt') 'changed'
            $sw.Restart()
            $null = @(Invoke-ClamAvScan -Path $d -CachePath $c)
            [pscustomobject]@{ First = $first; SecondSeconds = $secondSeconds; ThirdSeconds = $sw.Elapsed.TotalSeconds }
        }
        $r.First | Should -Be 5
        # Nothing changed: no signature load at all. A changed file: the signatures load again.
        $r.SecondSeconds | Should -BeLessThan 5
        $r.ThirdSeconds | Should -BeGreaterThan 5
    }
    It 'never trusts a file for longer than the allowed days' -Skip:(-not $script:clamReady) {
        $r = InModuleScope PcGuardian -Parameters @{ d = $script:dir; c = $script:cache } { param($d, $c)
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $null = @(Invoke-ClamAvScan -Path $d -CachePath $c -CacheDays 0)
            $sw.Elapsed.TotalSeconds
        }
        $r | Should -BeGreaterThan 5
    }
}

Describe 'Invoke-GuardianRun -ScanPath' {
    It 'scans only the given folder and skips the system-wide detectors' -Skip:(-not $script:clamReady) {
        $data = Join-Path ([IO.Path]::GetTempPath()) ('pcg-data-' + [guid]::NewGuid())
        # The PCG| progress lines go to the host stream; 6>&1 captures them as text.
        $out = @(Invoke-GuardianRun -DataPath $data -ScanPath @($script:dir) -AsObject -Progress 6>&1)
        $phases = @($out | Where-Object { "$_" -like 'PCG|phase|*' })
        ($phases | Where-Object { $_ -match 'injected code|event logs|vulnerable-driver' }).Count | Should -Be 0
        ($phases | Where-Object { $_ -match 'ClamAV' }).Count | Should -Be 1
    }
}
