function Get-CommandRisk {
    <#
    .SYNOPSIS
        Rates a command line typed or pasted by a person: 'Strong', 'Weak' or $null.
    .DESCRIPTION
        ClickFix pages trick people into pasting a command into the Run box or PowerShell. Strong signs are
        encoded or hidden commands and living-off-the-land downloaders. Weak signs are plain download-and-run
        one-liners, which many legitimate installers also use, so they are only worth a look.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)

    if (-not $Text) { return $null }
    if ($Text -match '(?i)\bmshta\b|-enc(odedcommand)?\s|frombase64string|\bdownloadstring\b|certutil.+-urlcache|bitsadmin.+/transfer|regsvr32.+/i:https?|rundll32.+https?://|-w(indowstyle)?\s+hidden.+(iex|invoke-expression|http)') {
        return 'Strong'
    }
    if ($Text -match '(?i)(irm|iwr|invoke-restmethod|invoke-webrequest|curl|wget)\b.*[|;]\s*(iex|invoke-expression)\b|^\s*https?://') {
        return 'Weak'
    }
    $null
}

function Format-CommandForDisplay {
    <#
    .SYNOPSIS
        Shortens a command line for display and hides anything that looks like a secret.
    #>
    [CmdletBinding()]
    param([string]$Text, [int]$MaxLength = 140)
    $t = ($Text -replace '\s+', ' ').Trim()
    # "Bearer abc" and "Basic abc" first, so a header like "Authorization: Bearer abc" loses the real secret too.
    $t = $t -replace '(?i)\b(bearer|basic)\s+\S+', '$1 <hidden>'
    $t = $t -replace '(?i)\b(token|secret|password|passwd|apikey|api[_-]?key|authorization)\b(\S*)(\s*[:=]\s*|\s+)(?!<hidden>)\S+', '$1$2 <hidden>'
    $t = $t -replace '[A-Za-z0-9+/=]{40,}', '<long value hidden>'
    if ($t.Length -gt $MaxLength) { $t = $t.Substring(0, $MaxLength) + '...' }
    $t
}

function Get-ShortHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text)
    $sha = [System.Security.Cryptography.SHA1]::Create()
    try { (-join ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') })).Substring(0, 10) }
    finally { $sha.Dispose() }
}

function Get-ClickFixTraceAudit {
    <#
    .SYNOPSIS
        Looks for traces of pasted-command attacks (ClickFix): the Run box history and PowerShell history.
    .DESCRIPTION
        Read-only and offline. This finds evidence after the fact; it cannot stop a paste. Findings are reported
        on every full scan and can be marked safe if they are commands you ran on purpose.
    #>
    [CmdletBinding()]
    param(
        [string]$HistoryPath = (Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'),
        [string]$RunMruKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU',
        [int]$MaxFindings = 20
    )

    $count = 0
    $seen = @{}

    # 1. Windows Run box (Win+R) history
    if (Test-Path $RunMruKey) {
        $item = Get-ItemProperty -Path $RunMruKey -ErrorAction SilentlyContinue
        foreach ($p in $item.PSObject.Properties) {
            if ($p.Name -in 'MRUList', 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') { continue }
            $cmd = "$($p.Value)" -replace '\\1$', ''
            $risk = Get-CommandRisk -Text $cmd
            if ($risk -and $count -lt $MaxFindings) {
                $key = "ClickFix:RunBox:$(Get-ShortHash $cmd)"
                if ($seen[$key]) { continue }
                $seen[$key] = $true; $count++
                $why = if ($risk -eq 'Strong') { 'suspicious: encoded, hidden or downloader command' } else { 'download-and-run command' }
                New-Finding -Category 'ClickFix' -Key $key -Detail "Run box history: $(Format-CommandForDisplay $cmd) ($why)"
            }
        }
    }

    # 2. PowerShell command history (last 3000 lines)
    if (Test-Path -LiteralPath $HistoryPath) {
        foreach ($line in (Get-Content -LiteralPath $HistoryPath -Tail 3000 -ErrorAction SilentlyContinue)) {
            $risk = Get-CommandRisk -Text $line
            if ($risk -and $count -lt $MaxFindings) {
                $key = "ClickFix:PowerShellHistory:$(Get-ShortHash $line)"
                if ($seen[$key]) { continue }
                $seen[$key] = $true; $count++
                $why = if ($risk -eq 'Strong') { 'suspicious: encoded, hidden or downloader command' } else { 'download-and-run command' }
                New-Finding -Category 'ClickFix' -Key $key -Detail "PowerShell history: $(Format-CommandForDisplay $line) ($why)"
            }
        }
    }
}
