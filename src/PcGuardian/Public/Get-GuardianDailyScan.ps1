function Get-GuardianDailyScan {
    <#
    .SYNOPSIS
        Reports whether the daily scan task exists, whether it is enabled, and the time it runs (HH:mm).
    #>
    [CmdletBinding()]
    param()

    $task = Get-ScheduledTask -TaskName 'pc-guardian' -ErrorAction SilentlyContinue
    if (-not $task) { return [pscustomobject]@{ Exists = $false; Enabled = $false; At = $null } }
    $trigger = $task.Triggers | Select-Object -First 1
    $at = $null
    if ($trigger -and $trigger.StartBoundary) { $at = ([datetime]$trigger.StartBoundary).ToString('HH:mm') }
    [pscustomobject]@{ Exists = $true; Enabled = ($task.State -ne 'Disabled'); At = $at }
}
