function Get-TaskAudit {
    [CmdletBinding()]
    param()
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' } |
        ForEach-Object {
            $action = ($_.Actions | Select-Object -First 1)
            $detail = ''
            if ($action -and $action.PSObject.Properties['Execute']) {
                $detail = "$($action.Execute) $($action.Arguments)".Trim()
            }
            New-Finding -Category 'Task' -Key "Task:$($_.TaskPath)$($_.TaskName)" -Detail $detail
        }
}
