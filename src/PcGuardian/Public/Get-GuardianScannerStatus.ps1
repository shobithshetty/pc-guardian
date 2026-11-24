function Get-GuardianScannerStatus {
    <#
    .SYNOPSIS
        Reports whether the scanners and their data are in place, and how old the virus database is.
    .DESCRIPTION
        Read-only and offline. The app uses it to decide whether to offer a one-time download before the
        first scan and whether the database should be refreshed.
    #>
    [CmdletBinding()]
    param([string]$DataPath = (Get-GuardianDataPath))

    $clam = Find-ClamAv
    $yara = Find-Yara
    $dbFiles = @(Get-ChildItem -Path (Join-Path (Join-Path $DataPath 'clamav-db') '*') -Include '*.cvd', '*.cld' -File -ErrorAction SilentlyContinue)
    $age = $null
    if ($dbFiles.Count -gt 0) {
        $newest = ($dbFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
        $age = [int][math]::Floor(((Get-Date) - $newest).TotalDays)
    }
    $yaraReady = [bool]($yara -and (Test-Path $yara.Rules))
    $det = Find-GuardianDetector -DataPath $DataPath
    $detReady = [bool]($det.Hayabusa -and $det.HollowsHunter -and $det.LolDrivers)
    [pscustomobject]@{
        ClamAvInstalled = [bool]$clam
        DatabaseReady   = ($dbFiles.Count -gt 0)
        DatabaseAgeDays = $age
        YaraReady       = $yaraReady
        DetectorsReady  = $detReady
        Ready           = ([bool]$clam -and ($dbFiles.Count -gt 0) -and $yaraReady -and $detReady)
    }
}
