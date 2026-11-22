function Get-GuardianSetting {
    <#
    .SYNOPSIS
        Returns pc-guardian's settings, with defaults for anything not saved yet.
    .DESCRIPTION
        Settings live in settings.json in the data folder. Current settings:
          virusTotal       look up hashes of new unsigned programs on VirusTotal during full scans (default off)
        virusTotalKeySet is read-only and tells whether a key has been stored.
    #>
    [CmdletBinding()]
    param([string]$DataPath = (Get-GuardianDataPath))

    $settings = [pscustomobject]@{ virusTotal = $false }
    $file = Join-Path $DataPath 'settings.json'
    if (Test-Path $file) {
        try {
            $saved = Get-Content -Path $file -Raw | ConvertFrom-Json
            foreach ($p in $saved.PSObject.Properties) {
                if ($settings.PSObject.Properties[$p.Name]) { $settings.($p.Name) = $p.Value }
            }
        } catch { Write-Verbose "settings.json could not be read; using defaults. $($_.Exception.Message)" }
    }
    $settings | Add-Member -NotePropertyName virusTotalKeySet -NotePropertyValue (Test-Path (Join-Path $DataPath 'vt.key')) -PassThru
}
