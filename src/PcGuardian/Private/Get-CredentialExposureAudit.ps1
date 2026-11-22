function Get-DevFolderRoot {
    <#
    .SYNOPSIS
        Folders searched for stray secrets: common code folders in your profile plus PCGUARDIAN_DEV_ROOTS (semicolon list).
    #>
    [CmdletBinding()]
    param()
    $roots = @()
    foreach ($n in 'Documents', 'source', 'Projects', 'dev', 'repos', 'code', 'Desktop') {
        $p = Join-Path $env:USERPROFILE $n
        if (Test-Path -LiteralPath $p) { $roots += $p }
    }
    # Folders added in Settings (for example a code folder on another drive)
    $roots += @((Get-GuardianSetting).devFolders | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    if ($env:PCGUARDIAN_DEV_ROOTS) {
        $roots += @($env:PCGUARDIAN_DEV_ROOTS -split ';' | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    }
    $roots | Select-Object -Unique
}

function Test-SshKeyUnprotected {
    <#
    .SYNOPSIS
        $true when a private key file has no passphrase. Reads the file only; never prints it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $text = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
    if (-not $text) { return $false }
    if ($text -match 'BEGIN OPENSSH PRIVATE KEY') {
        try {
            $body = ($text -split "`n" | Where-Object { $_ -and $_ -notmatch '-----' }) -join ''
            $bytes = [Convert]::FromBase64String(($body -replace '\s', ''))
            # "openssh-key-v1" + NUL (15 bytes), then a big-endian length and the cipher name ("none" = no passphrase).
            $len = ([int]$bytes[15] -shl 24) -bor ([int]$bytes[16] -shl 16) -bor ([int]$bytes[17] -shl 8) -bor [int]$bytes[18]
            $cipher = [System.Text.Encoding]::ASCII.GetString($bytes, 19, $len)
            return ($cipher -eq 'none')
        } catch { return $false }
    }
    if ($text -match 'BEGIN (RSA|EC|DSA) PRIVATE KEY') { return ($text -notmatch 'ENCRYPTED') }
    if ($text -match 'BEGIN PRIVATE KEY') { return $true }
    $false
}

function Get-CredentialExposureAudit {
    <#
    .SYNOPSIS
        Finds secrets stored in plain text where supply-chain worms and infostealers look for them.
    .DESCRIPTION
        Read-only and offline. Checks well-known credential files in your profile, private keys without a
        passphrase, and .env files in your code folders. A secret's value is never shown or stored: findings
        only say which kind of secret is in which file.
    .PARAMETER HomePath
        Your profile folder (tests override it).
    .PARAMETER Roots
        Code folders to search (default: Get-DevFolderRoot).
    #>
    [CmdletBinding()]
    param(
        [string]$HomePath = $env:USERPROFILE,
        [string[]]$Roots,
        [int]$MaxDepth = 4,
        [int]$MaxFileBytes = 262144
    )

    $patterns = [ordered]@{
        'GitHub token'        = 'gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}'
        'AWS access key'      = '\b(AKIA|ASIA)[0-9A-Z]{16}\b'
        'npm token'           = '\bnpm_[A-Za-z0-9]{36}\b'
        'Slack token'         = '\bxox[baprs]-[A-Za-z0-9-]{10,}'
        'Anthropic API key'   = '\bsk-ant-[A-Za-z0-9_-]{20,}'
        'OpenAI API key'      = '\bsk-(proj-)?[A-Za-z0-9_-]{32,}'
        'Private key'         = '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
    }

    function Test-FileForSecret([string]$File) {
        $info = Get-Item -LiteralPath $File -ErrorAction SilentlyContinue
        if (-not $info -or $info.Length -gt $MaxFileBytes -or $info.Length -eq 0) { return }
        $text = Get-Content -LiteralPath $File -Raw -ErrorAction SilentlyContinue
        if (-not $text) { return }
        foreach ($kind in $patterns.Keys) {
            if ($text -match $patterns[$kind]) {
                $slug = $kind -replace '\s', ''
                New-Finding -Category 'Credential' -Key "Credential:${slug}:$File" -Detail "$kind stored in plain text in this file (value not shown)"
            }
        }
    }

    # 1. Well-known credential files in the profile
    $known = @(
        @{ Rel = '.npmrc';                 Test = '_authToken\s*=\s*(?!\$\{)\S{10,}';       Kind = 'npm login token' },
        @{ Rel = '.pypirc';                Test = 'password\s*[:=]\s*\S+';                   Kind = 'PyPI password or token' },
        @{ Rel = '.git-credentials';       Test = '://[^/\s:]+:[^@\s]+@';                    Kind = 'Git username and password or token' },
        @{ Rel = '.aws\credentials';       Test = 'aws_secret_access_key\s*=\s*\S+';         Kind = 'AWS secret key' },
        @{ Rel = '.docker\config.json';    Test = '"auth"\s*:\s*"[^"]{10,}"';                Kind = 'Docker registry login' },
        @{ Rel = '.config\gh\hosts.yml';   Test = 'oauth_token:\s*\S+';                      Kind = 'GitHub CLI login token' }
    )
    foreach ($k in $known) {
        $file = Join-Path $HomePath $k.Rel
        if (Test-Path -LiteralPath $file) {
            $text = Get-Content -LiteralPath $file -Raw -ErrorAction SilentlyContinue
            if ($text -and $text -match $k.Test) {
                New-Finding -Category 'Credential' -Key "Credential:KnownFile:$file" -Detail "$($k.Kind) stored in plain text (value not shown)"
            }
        }
    }

    # 2. SSH private keys without a passphrase
    $sshDir = Join-Path $HomePath '.ssh'
    if (Test-Path -LiteralPath $sshDir) {
        Get-ChildItem -LiteralPath $sshDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^id_' -and $_.Extension -ne '.pub' } |
            ForEach-Object {
                if (Test-SshKeyUnprotected -Path $_.FullName) {
                    New-Finding -Category 'Credential' -Key "Credential:SshKey:$($_.FullName)" -Detail 'SSH private key without a passphrase: anyone who copies the file can use it'
                }
            }
    }

    # 3. .env files in code folders (pruning folders that hold other people's code or build output)
    if (-not $Roots) { $Roots = @(Get-DevFolderRoot) }
    $skip = 'node_modules', '.git', 'venv', '.venv', '__pycache__', 'bin', 'obj', 'dist', 'build', 'AppData', '.next', 'target'
    foreach ($root in $Roots) {
        $queue = New-Object System.Collections.Generic.Queue[object]
        $queue.Enqueue(@{ Path = $root; Depth = 0 })
        while ($queue.Count -gt 0) {
            $cur = $queue.Dequeue()
            foreach ($entry in (Get-ChildItem -LiteralPath $cur.Path -Force -ErrorAction SilentlyContinue)) {
                if ($entry.PSIsContainer) {
                    if ($cur.Depth -lt $MaxDepth -and $entry.Name -notin $skip -and -not ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                        $queue.Enqueue(@{ Path = $entry.FullName; Depth = $cur.Depth + 1 })
                    }
                }
                elseif ($entry.Name -match '^\.env(\..+)?$' -and $entry.Name -notmatch '(example|sample|template)$') {
                    Test-FileForSecret -File $entry.FullName
                }
            }
        }
    }
}
