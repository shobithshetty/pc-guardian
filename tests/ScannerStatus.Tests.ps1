BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\src\PcGuardian\PcGuardian.psd1') -Force
}

Describe 'Get-GuardianScannerStatus' {
    It 'reports not ready when no virus database exists in the data folder' {
        $d = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid())
        $s = Get-GuardianScannerStatus -DataPath $d
        $s.DatabaseReady | Should -BeFalse
        $s.Ready | Should -BeFalse
        $s.DatabaseAgeDays | Should -BeNullOrEmpty
    }
    It 'reads the age of the newest database file' {
        $d = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid())
        $db = Join-Path $d 'clamav-db'; New-Item -ItemType Directory -Path $db | Out-Null
        $f = New-Item -ItemType File -Path (Join-Path $db 'daily.cvd')
        $f.LastWriteTime = (Get-Date).AddDays(-5)
        (Get-GuardianScannerStatus -DataPath $d).DatabaseAgeDays | Should -Be 5
    }
}
