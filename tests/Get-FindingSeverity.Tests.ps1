BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\src\PcGuardian\PcGuardian.psd1') -Force
}

Describe 'Get-FindingSeverity' {
    It 'alerts on a new admin account' {
        InModuleScope PcGuardian {
            $f = [pscustomobject]@{ Category = 'Account'; Key = 'Admin:PC\evil'; Detail = 'User in Administrators' }
            Get-FindingSeverity -Finding $f | Should -Be 'Alert'
        }
    }
    It 'alerts on any malware detection' {
        InModuleScope PcGuardian {
            $f = [pscustomobject]@{ Category = 'Malware'; Key = 'Malware:C:\x.exe'; Detail = 'ClamAV detected Win.Test' }
            Get-FindingSeverity -Finding $f | Should -Be 'Alert'
        }
    }
    It 'alerts on startup entries in AppData' {
        InModuleScope PcGuardian {
            $f = [pscustomobject]@{ Category = 'Startup'; Key = 'Startup:HKCU:x'; Detail = 'C:\Users\a\AppData\Roaming\x.exe' }
            Get-FindingSeverity -Finding $f | Should -Be 'Alert'
        }
    }
    It 'alerts on hidden encoded PowerShell tasks' {
        InModuleScope PcGuardian {
            $f = [pscustomobject]@{ Category = 'Task'; Key = 'Task:\x'; Detail = 'powershell.exe -w hidden -enc AAAA' }
            Get-FindingSeverity -Finding $f | Should -Be 'Alert'
        }
    }
    It 'keeps ordinary new ports informational' {
        InModuleScope PcGuardian {
            $f = [pscustomobject]@{ Category = 'Port'; Key = 'Port:8001:python'; Detail = 'Listening on 0.0.0.0 (python)' }
            Get-FindingSeverity -Finding $f | Should -Be 'Info'
        }
    }
    It 'keeps Program Files startup entries informational' {
        InModuleScope PcGuardian {
            $f = [pscustomobject]@{ Category = 'Startup'; Key = 'Startup:HKLM:n'; Detail = '"C:\Program Files\NordVPN\NordVPN.exe" --auto-start' }
            Get-FindingSeverity -Finding $f | Should -Be 'Info'
        }
    }
}
