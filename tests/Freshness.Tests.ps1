BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\src\PcGuardian\PcGuardian.psd1') -Force
    function script:NewDir { Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid()) }
    function script:Entry($vendor, $product, $daysAgo, $cve = 'CVE-2026-0001') {
        [pscustomobject]@{ cveID = $cve; vendorProject = $vendor; product = $product; dateAdded = (Get-Date).AddDays(-$daysAgo).ToString('yyyy-MM-dd') }
    }
}

Describe 'Known-exploited matching' {
    It 'matches by name and vendor, including Chromium-based browsers, and skips Windows itself' {
        InModuleScope PcGuardian {
            $chrome = [pscustomobject]@{ Name = 'Google Chrome'; Publisher = 'Google LLC'; Version = '1' }
            $zip    = [pscustomobject]@{ Name = '7-Zip 26.02 (x64 edition)'; Publisher = 'Igor Pavlov'; Version = '26.02' }
            $other  = [pscustomobject]@{ Name = 'Notepad++'; Publisher = 'Don Ho'; Version = '1' }
            Test-KevSoftwareMatch -Software $chrome -Entry ([pscustomobject]@{ vendorProject = 'Google'; product = 'Chromium V8' }) | Should -BeTrue
            Test-KevSoftwareMatch -Software $zip    -Entry ([pscustomobject]@{ vendorProject = '7-Zip'; product = '7-Zip' }) | Should -BeTrue
            Test-KevSoftwareMatch -Software $other  -Entry ([pscustomobject]@{ vendorProject = 'Google'; product = 'Chromium V8' }) | Should -BeFalse
            Test-KevSoftwareMatch -Software $chrome -Entry ([pscustomobject]@{ vendorProject = 'Microsoft'; product = 'Windows Win32k' }) | Should -BeFalse
            Test-KevSoftwareMatch -Software $other  -Entry ([pscustomobject]@{ vendorProject = 'Acme'; product = 'Widget Server' }) | Should -BeFalse
            # The program must be the product, not merely mention it in its name
            $office  = [pscustomobject]@{ Name = 'Microsoft Office Professional Plus 2019 - en-us'; Publisher = 'Microsoft Corporation'; Version = '1' }
            $vsTools = [pscustomobject]@{ Name = 'Microsoft Visual Studio 2010 Tools for Office Runtime (x64)'; Publisher = 'Microsoft Corporation'; Version = '1' }
            Test-KevSoftwareMatch -Software $office  -Entry ([pscustomobject]@{ vendorProject = 'Microsoft'; product = 'Office' }) | Should -BeTrue
            Test-KevSoftwareMatch -Software $vsTools -Entry ([pscustomobject]@{ vendorProject = 'Microsoft'; product = 'Office' }) | Should -BeFalse
            $php = [pscustomobject]@{ Name = 'PHP 8.3'; Publisher = 'The PHP Group'; Version = '8.3' }
            Test-KevSoftwareMatch -Software $php -Entry ([pscustomobject]@{ vendorProject = 'PHP Group'; product = 'PHP' }) | Should -BeTrue
        }
    }
}

Describe 'Get-KnownExploitedAudit' {
    It 'reports only recent entries for installed software, with the date in the key and a day-based alert level' {
        $catalog = @(
            (Entry 'Google' 'Chromium V8' 3 'CVE-2026-1111'),
            (Entry 'Google' 'Chromium Mojo' 90 'CVE-2025-2222'),     # too old: ignored
            (Entry 'Microsoft' 'Windows Win32k' 2),                  # operating system: ignored
            (Entry '7-Zip' '7-Zip' 30 'CVE-2026-3333'))
        $software = @(
            [pscustomobject]@{ Name = 'Google Chrome'; Publisher = 'Google LLC'; Version = '1' },
            [pscustomobject]@{ Name = '7-Zip 26.02 (x64 edition)'; Publisher = 'Igor Pavlov'; Version = '26.02' },
            [pscustomobject]@{ Name = 'Notepad++'; Publisher = 'Don Ho'; Version = '1' })
        $r = @(InModuleScope PcGuardian -Parameters @{ c = $catalog; s = $software } { param($c, $s) Get-KnownExploitedAudit -Catalog $c -Software $s -DataPath 'unused' })
        $r.Count | Should -Be 2
        $chrome = $r | Where-Object Key -like 'KnownExploited:Google Chrome:*'
        $chrome.Key | Should -Match ':\d{4}-\d{2}-\d{2}$'
        $chrome.Detail | Should -Match 'CVE-2026-1111'
        $chrome.Detail | Should -Not -Match 'CVE-2025-2222'
        (InModuleScope PcGuardian -Parameters @{ f = $chrome } { param($f) Get-FindingSeverity -Finding $f }) | Should -Be 'Alert'
        $zip = $r | Where-Object Key -like 'KnownExploited:7-Zip*'
        (InModuleScope PcGuardian -Parameters @{ f = $zip } { param($f) Get-FindingSeverity -Finding $f }) | Should -Be 'Info'
    }
    It 'says so when the list cannot be downloaded and nothing is cached' {
        $d = NewDir
        $r = InModuleScope PcGuardian -Parameters @{ d = $d } { param($d)
            Mock Invoke-WebRequest { throw 'offline' }
            Get-KnownExploitedAudit -DataPath $d -Software @([pscustomobject]@{ Name = 'x'; Publisher = ''; Version = '' }) }
        $r.Key | Should -Be 'KnownExploited:Unavailable'
    }
    It 'uses a fresh cached copy without touching the network' {
        $d = NewDir; New-Item -ItemType Directory -Path $d | Out-Null
        Set-Content (Join-Path $d 'kev.json') -Value '{"vulnerabilities":[{"cveID":"CVE-1","vendorProject":"A","product":"B","dateAdded":"2026-01-01"}]}'
        $r = @(InModuleScope PcGuardian -Parameters @{ d = $d } { param($d)
            Mock Invoke-WebRequest { throw 'must not be called' }
            Get-KevCatalog -DataPath $d })
        $r.Count | Should -Be 1
        $r[0].cveID | Should -Be 'CVE-1'
    }
}

Describe 'Get-GuardianUpdateInfo' {
    It 'reports a newer release, caches the answer, and works offline afterwards' {
        $d = NewDir
        $first = InModuleScope PcGuardian -Parameters @{ d = $d } { param($d)
            Mock Invoke-RestMethod { [pscustomobject]@{ tag_name = 'v0.2.0'; html_url = 'https://github.com/o/r/releases/tag/v0.2.0' } }
            Get-GuardianUpdateInfo -Repository 'o/r' -CurrentVersion '0.1.0' -DataPath $d }
        $first.Available | Should -BeTrue
        $first.Latest | Should -Be '0.2.0'
        $second = InModuleScope PcGuardian -Parameters @{ d = $d } { param($d)
            Mock Invoke-RestMethod { throw 'must not be called' }
            Get-GuardianUpdateInfo -Repository 'o/r' -CurrentVersion '0.2.0' -DataPath $d }
        $second.Available | Should -BeFalse
    }
    It 'never offers a link that is not on github.com' {
        $d = NewDir
        $r = InModuleScope PcGuardian -Parameters @{ d = $d } { param($d)
            Mock Invoke-RestMethod { [pscustomobject]@{ tag_name = 'v9.0.0'; html_url = 'https://evil.example/download' } }
            Get-GuardianUpdateInfo -Repository 'o/r' -CurrentVersion '0.1.0' -DataPath $d }
        $r.Available | Should -BeTrue
        $r.Url | Should -BeNullOrEmpty
    }
    It 'rejects a repository name with odd characters and treats a failed lookup as no update' {
        { Get-GuardianUpdateInfo -Repository 'a/b; calc' -CurrentVersion '0.1.0' } | Should -Throw '*owner/name*'
        $r = InModuleScope PcGuardian -Parameters @{ d = (NewDir) } { param($d)
            Mock Invoke-RestMethod { throw '404 not found' }
            Get-GuardianUpdateInfo -Repository 'o/r' -CurrentVersion '0.1.0' -DataPath $d }
        $r.Available | Should -BeFalse
    }
}

Describe 'New settings' {
    It 'saves knownExploited and updateCheck without losing the other settings' {
        $d = NewDir
        Set-GuardianSetting -Name osv -Value $true -DataPath $d
        Set-GuardianSetting -Name knownExploited -Value $true -DataPath $d
        Set-GuardianSetting -Name updateCheck -Value $true -DataPath $d
        $s = Get-GuardianSetting -DataPath $d
        $s.osv | Should -BeTrue
        $s.knownExploited | Should -BeTrue
        $s.updateCheck | Should -BeTrue
        $s.virusTotal | Should -BeFalse
    }
}
