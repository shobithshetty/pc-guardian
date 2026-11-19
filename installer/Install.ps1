<#
.SYNOPSIS
    Registers a daily scheduled task that runs the pc-guardian audit.
.DESCRIPTION
    Read-only audit only. Requires an elevated PowerShell once, to register the task.
    Remove later with:  Unregister-ScheduledTask -TaskName 'pc-guardian' -Confirm:$false
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$At = '09:00'
)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this script from an elevated (Administrator) PowerShell.' }

$module = Join-Path (Split-Path $PSScriptRoot -Parent) 'src\PcGuardian\PcGuardian.psd1'
if (-not (Test-Path $module)) { throw "Module not found at $module" }

$command = "Import-Module '$module' -Force; Invoke-GuardianRun | Out-Null"
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"$command`""
$trigger = New-ScheduledTaskTrigger -Daily -At $At

if ($PSCmdlet.ShouldProcess('pc-guardian', 'Register scheduled task')) {
    Register-ScheduledTask -TaskName 'pc-guardian' -Action $action -Trigger $trigger -Description 'pc-guardian read-only security audit' -Force | Out-Null
    Write-Output "Registered 'pc-guardian' daily at $At."
}
