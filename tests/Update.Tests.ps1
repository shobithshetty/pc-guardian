BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\src\PcGuardian\PcGuardian.psd1') -Force
    $script:base = 'https://github.com/o/r/releases/download/v0.2.0/'
    $script:setupUrl = $script:base + 'pc-guardian-setup-0.2.0.exe'
    $script:sumsUrl = $script:base + 'SHA256SUMS.txt'
    # A stand-in for Invoke-WebRequest: writes the given checksum list, or a pretend installer, to -OutFile.
    function FakeRelease([string]$Sums) {
        [scriptblock]::Create(@"
if (`$Uri -like '*SHA256SUMS.txt') { Set-Content -LiteralPath `$OutFile -Value @'
$Sums
'@ } else { [IO.File]::WriteAllBytes(`$OutFile, [Text.Encoding]::ASCII.GetBytes('pretend installer bytes')) }
"@)
    }
    function NewDir { $d = Join-Path ([IO.Path]::GetTempPath()) ('pcg-upd-' + [guid]::NewGuid()); New-Item -ItemType Directory -Path $d | Out-Null; $d }
}

Describe 'Get-GuardianUpdateInfo release files' {
    It 'offers the installer and checksum files only when they are downloads of this repository' {
        $d = NewDir
        $r = InModuleScope PcGuardian -Parameters @{ d = $d } { param($d)
            Mock Invoke-RestMethod { [pscustomobject]@{ tag_name = 'v0.2.0'; html_url = 'https://github.com/o/r/releases/tag/v0.2.0'; assets = @(
                [pscustomobject]@{ name = 'pc-guardian-setup-0.2.0.exe'; browser_download_url = 'https://github.com/o/r/releases/download/v0.2.0/pc-guardian-setup-0.2.0.exe' },
                [pscustomobject]@{ name = 'SHA256SUMS.txt'; browser_download_url = 'https://evil.example/SHA256SUMS.txt' }) } }
            Get-GuardianUpdateInfo -Repository 'o/r' -CurrentVersion '0.1.0' -DataPath $d }
        $r.InstallerUrl | Should -Be 'https://github.com/o/r/releases/download/v0.2.0/pc-guardian-setup-0.2.0.exe'
        $r.ChecksumsUrl | Should -BeNullOrEmpty
    }
    It 'still works for a release with no assets' {
        $d = NewDir
        $r = InModuleScope PcGuardian -Parameters @{ d = $d } { param($d)
            Mock Invoke-RestMethod { [pscustomobject]@{ tag_name = 'v0.2.0'; html_url = 'https://github.com/o/r/releases/tag/v0.2.0' } }
            Get-GuardianUpdateInfo -Repository 'o/r' -CurrentVersion '0.1.0' -DataPath $d }
        $r.Available | Should -BeTrue
        $r.InstallerUrl | Should -BeNullOrEmpty
    }
}

Describe 'Save-GuardianUpdate' {
    BeforeEach {
        $script:bytes = [Text.Encoding]::ASCII.GetBytes('pretend installer bytes')
        $script:good = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($script:bytes)) -replace '-', '').ToLower()
    }
    It 'keeps the installer when its SHA-256 matches the release list' {
        $d = NewDir
        Mock -ModuleName PcGuardian Invoke-WebRequest (FakeRelease ("$($script:good)  pc-guardian-setup-0.2.0.exe" + [Environment]::NewLine + ('b' * 64) + '  other.zip'))
        $r = Save-GuardianUpdate -InstallerUrl $script:setupUrl -ChecksumsUrl $script:sumsUrl -Repository 'o/r' -OutDir $d
        $r.Sha256 | Should -Be $script:good
        Test-Path $r.Path | Should -BeTrue
        $r.Signature | Should -Not -Be 'Valid'   # a fake file is not signed; the app says so
    }
    It 'deletes the download and throws when the checksum does not match' {
        $d = NewDir
        Mock -ModuleName PcGuardian Invoke-WebRequest (FakeRelease (('a' * 64) + '  pc-guardian-setup-0.2.0.exe'))
        { Save-GuardianUpdate -InstallerUrl $script:setupUrl -ChecksumsUrl $script:sumsUrl -Repository 'o/r' -OutDir $d } | Should -Throw '*does not match*'
        Test-Path (Join-Path $d 'pc-guardian-setup-0.2.0.exe') | Should -BeFalse
    }
    It 'deletes the download when the release list does not name the installer' {
        $d = NewDir
        Mock -ModuleName PcGuardian Invoke-WebRequest (FakeRelease (('a' * 64) + '  something-else.exe'))
        { Save-GuardianUpdate -InstallerUrl $script:setupUrl -ChecksumsUrl $script:sumsUrl -Repository 'o/r' -OutDir $d } | Should -Throw '*does not list*'
        Test-Path (Join-Path $d 'pc-guardian-setup-0.2.0.exe') | Should -BeFalse
    }
    It 'refuses addresses outside this repository releases without downloading anything' {
        $d = NewDir
        Mock -ModuleName PcGuardian Invoke-WebRequest { throw 'must not be called' }
        { Save-GuardianUpdate -InstallerUrl 'https://evil.example/pc-guardian-setup-0.2.0.exe' -ChecksumsUrl $script:sumsUrl -Repository 'o/r' -OutDir $d } | Should -Throw '*only release files*'
        { Save-GuardianUpdate -InstallerUrl 'https://github.com/other/repo/releases/download/v1/pc-guardian-setup-0.2.0.exe' -ChecksumsUrl $script:sumsUrl -Repository 'o/r' -OutDir $d } | Should -Throw '*only release files*'
        { Save-GuardianUpdate -InstallerUrl 'http://github.com/o/r/releases/download/v0.2.0/pc-guardian-setup-0.2.0.exe' -ChecksumsUrl $script:sumsUrl -Repository 'o/r' -OutDir $d } | Should -Throw '*only release files*'
    }
    It 'refuses an unexpected installer file name' {
        $d = NewDir
        Mock -ModuleName PcGuardian Invoke-WebRequest { throw 'must not be called' }
        { Save-GuardianUpdate -InstallerUrl ($script:base + 'payload.exe') -ChecksumsUrl $script:sumsUrl -Repository 'o/r' -OutDir $d } | Should -Throw '*Unexpected installer file name*'
    }
}
