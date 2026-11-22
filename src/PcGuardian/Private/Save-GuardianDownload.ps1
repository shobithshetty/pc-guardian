function Save-GuardianDownload {
    <#
    .SYNOPSIS
        Downloads a file and reports real percent progress (PCG|percent lines) when the size is known.
    .DESCRIPTION
        Uses a streaming HTTP download so progress can be reported, which Invoke-WebRequest cannot do.
        Verification of the file (hash check) is the caller's job and happens after this returns.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$OutFile,
        [string]$Label = 'Downloading',
        # Used only when the server does not announce the size (GitHub source archives): the percent is then an estimate.
        [long]$ExpectedBytes = 0
    )

    Add-Type -AssemblyName System.Net.Http
    $client = New-Object System.Net.Http.HttpClient
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('pc-guardian')
    $client.Timeout = [TimeSpan]::FromMinutes(20)
    try {
        $response = $client.GetAsync($Uri, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        $response.EnsureSuccessStatusCode() | Out-Null
        $total = $response.Content.Headers.ContentLength   # $null when the server does not say
        $estimated = $false
        if (-not $total -and $ExpectedBytes -gt 0) { $total = $ExpectedBytes; $estimated = $true }
        $in = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $out = [System.IO.File]::Create($OutFile)
        try {
            $buffer = New-Object byte[] 81920
            $done = 0L; $lastPercent = -1; $lastMb = -1
            while (($n = $in.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $out.Write($buffer, 0, $n)
                $done += $n
                if ($total) {
                    $percent = [int][math]::Floor($done * 100 / $total)
                    if ($estimated) { $percent = [math]::Min(99, $percent) }   # an estimate must not claim 100% early
                    if ($percent -ne $lastPercent) {
                        $lastPercent = $percent
                        Write-GuardianProgress -Type percent -Value $percent
                        Write-GuardianProgress -Type file -Value ('{0}: {1:n1} of {2:n1} MB' -f $Label, ($done / 1MB), ($total / 1MB))
                    }
                } else {
                    $mb = [int][math]::Floor($done / 1MB)
                    if ($mb -ne $lastMb) {
                        $lastMb = $mb
                        Write-GuardianProgress -Type file -Value ('{0}: {1} MB so far' -f $Label, $mb)
                    }
                }
            }
        }
        finally { $out.Dispose(); $in.Dispose() }
        if ($total) { Write-GuardianProgress -Type percent -Value 100 }
    }
    finally { $client.Dispose() }
}
