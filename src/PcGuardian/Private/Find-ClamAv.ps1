function Find-ClamAv {
    <#
    .SYNOPSIS
        Locates clamscan.exe and freshclam.exe. Returns $null if ClamAV is not installed.
    #>
    [CmdletBinding()]
    param()
    $dirs = @(
        (Join-Path $env:ProgramFiles 'ClamAV'),
        (Join-Path ${env:ProgramFiles(x86)} 'ClamAV')
    ) | Where-Object { $_ -and (Test-Path $_) }

    # Definitions live in pc-guardian's own data folder so updating them never needs admin rights.
    $userDb = Join-Path (Get-GuardianDataPath) 'clamav-db'

    foreach ($d in $dirs) {
        $scan = Join-Path $d 'clamscan.exe'
        if (Test-Path $scan) {
            $db = if (Test-Path $userDb) { $userDb } else { Join-Path $d 'database' }
            return [pscustomobject]@{ Dir = $d; ClamScan = $scan; FreshClam = (Join-Path $d 'freshclam.exe'); Database = $db }
        }
    }
    $cmd = Get-Command clamscan.exe -ErrorAction SilentlyContinue
    if ($cmd) {
        $d = Split-Path $cmd.Source -Parent
        $db = if (Test-Path $userDb) { $userDb } else { Join-Path $d 'database' }
        return [pscustomobject]@{ Dir = $d; ClamScan = $cmd.Source; FreshClam = (Join-Path $d 'freshclam.exe'); Database = $db }
    }
    return $null
}
