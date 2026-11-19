function Get-StartupAudit {
    [CmdletBinding()]
    param()
    $runKeys = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
               'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
    foreach ($key in $runKeys) {
        $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            New-Finding -Category 'Startup' -Key "Startup:$($key.Substring(0,4)):$($p.Name)" -Detail "$($p.Value)"
        }
    }
    $folders = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
               "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    foreach ($f in $folders) {
        Get-ChildItem -Path $f -File -ErrorAction SilentlyContinue | ForEach-Object {
            New-Finding -Category 'Startup' -Key "StartupFolder:$($_.Name)" -Detail $_.FullName
        }
    }
}
