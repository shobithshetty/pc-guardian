<#
.SYNOPSIS
    Removes the daily 'pc-guardian' scheduled task that earlier versions could create.
.DESCRIPTION
    pc-guardian no longer schedules anything: it runs only when someone opens it. This script exists so a task left
    by an older version can be cleaned up (the uninstaller runs it, and Settings offers it). It does nothing when
    there is no such task. Removing a scheduled task needs an elevated PowerShell.
#>
[CmdletBinding(SupportsShouldProcess)]
param()

$taskName = 'pc-guardian'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this script from an elevated (Administrator) PowerShell.' }

if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
    Write-Output "No '$taskName' scheduled task found."
    return
}
if ($PSCmdlet.ShouldProcess($taskName, 'Remove scheduled task')) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Output "Removed '$taskName'."
}
