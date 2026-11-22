function Get-TaskAudit {
    [CmdletBinding()]
    param()
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        # Skip Microsoft's tasks, disabled tasks, and pc-guardian's own daily scan (it would flag itself).
        Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' -and
                       -not ($_.TaskPath -eq '\' -and $_.TaskName -eq 'pc-guardian') } |
        ForEach-Object {
            $action = ($_.Actions | Select-Object -First 1)
            $detail = ''
            if ($action -and $action.PSObject.Properties['Execute']) {
                $detail = "$($action.Execute) $($action.Arguments)".Trim()
            }
            New-Finding -Category 'Task' -Key "Task:$($_.TaskPath)$($_.TaskName)" -Detail $detail
        }
}
