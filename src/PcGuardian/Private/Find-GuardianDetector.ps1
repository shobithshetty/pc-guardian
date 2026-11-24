function Find-GuardianDetector {
    <#
    .SYNOPSIS
        Locates the detector programs and data downloaded by Install-GuardianDetectors. A missing one is $null.
    #>
    [CmdletBinding()]
    param([string]$DataPath = (Get-GuardianDataPath))

    $pins = Get-Content -Path (Join-Path $script:ModuleRoot 'data\pins.json') -Raw | ConvertFrom-Json
    $base = Join-Path $DataPath 'detectors'
    $hayabusaDir = Join-Path $base 'hayabusa'
    $hayabusaExe = Join-Path $hayabusaDir $pins.hayabusa.exe
    $hh          = Join-Path $base ('hollows_hunter\' + $pins.hollowsHunter.asset)
    $lol         = Join-Path $base 'loldrivers\drivers.json'
    [pscustomobject]@{
        Hayabusa      = $(if (Test-Path $hayabusaExe) { $hayabusaExe } else { $null })
        HayabusaDir   = $hayabusaDir
        HollowsHunter = $(if (Test-Path $hh) { $hh } else { $null })
        LolDrivers    = $(if (Test-Path $lol) { $lol } else { $null })
        StatePath     = (Join-Path $base 'installed.json')
        Base          = $base
    }
}
