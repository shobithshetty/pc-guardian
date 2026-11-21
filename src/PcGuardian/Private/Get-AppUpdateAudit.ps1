function Get-AppUpdateAudit {
    <#
    .SYNOPSIS
        Lists installed apps that have a newer version in winget. Needs network access to winget sources.
    .DESCRIPTION
        Outdated software is the most common exploit path. This only reads; it never upgrades anything.
    #>
    [CmdletBinding()]
    param()

    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        return New-Finding -Category 'Exposure' -Key 'Exposure:Update:WingetMissing' -Detail 'winget not found; app update check skipped.'
    }
    $raw = & winget.exe upgrade --accept-source-agreements --disable-interactivity 2>&1 | ForEach-Object { "$_" }
    foreach ($app in @(ConvertFrom-WingetUpgrade -Lines $raw)) {
        New-Finding -Category 'Exposure' -Key "Exposure:Update:$($app.Id)" -Detail "$($app.Name) $($app.Version) -> $($app.Available)"
    }
}
