<#
.SYNOPSIS
    Registers (or removes) the daily scheduled task that runs the pc-guardian scan.
.DESCRIPTION
    Read-only scan only. Requires an elevated PowerShell once, to register the task. The Windows installer
    calls this for you. By hand:
        .\Install.ps1                 register, daily at 02:00
        .\Install.ps1 -At 21:30       register at another time
        .\Install.ps1 -Remove         remove the task
.PARAMETER ModulePath
    Path to PcGuardian.psd1. Defaults to the repository's src folder (development) or ..\module\PcGuardian
    next to this script (installed).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$At = '02:00',
    [string]$ModulePath,
    [switch]$Remove
)

$taskName = 'pc-guardian'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this script from an elevated (Administrator) PowerShell.' }

if ($Remove) {
    if ($PSCmdlet.ShouldProcess($taskName, 'Remove scheduled task')) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Output "Removed '$taskName'."
    }
    return
}

if (-not $ModulePath) {
    $installed = Join-Path (Split-Path $PSScriptRoot -Parent) 'module\PcGuardian\PcGuardian.psd1'
    $dev       = Join-Path (Split-Path $PSScriptRoot -Parent) 'src\PcGuardian\PcGuardian.psd1'
    $ModulePath = if (Test-Path $installed) { $installed } else { $dev }
}
if (-not (Test-Path $ModulePath)) { throw "Module not found at $ModulePath" }
if ($ModulePath -match "'") { throw 'The module path must not contain a single quote.' }

# Refresh the virus database first (incremental, signature-checked by ClamAV's own tool), then scan.
$command  = "Import-Module '$ModulePath' -Force; try { Install-GuardianScanner -ClamAv | Out-Null } catch { }; Invoke-GuardianRun -Scan -NoDonateNote | Out-Null"
$action   = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"$command`""
$trigger  = New-ScheduledTaskTrigger -Daily -At $At
# Run a missed scan when the PC is next on, even on battery, and never run longer than two hours.
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2)

if ($PSCmdlet.ShouldProcess($taskName, 'Register scheduled task')) {
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings `
        -Description 'pc-guardian read-only security scan' -Force | Out-Null
    Write-Output "Registered '$taskName' daily at $At."
}
