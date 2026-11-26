function Find-GuardianPhoneTools {
    <#
    .SYNOPSIS
        Locates the Android tools and stalkerware lists downloaded for the phone check. A missing one is $null.
    #>
    [CmdletBinding()]
    param([string]$DataPath = (Get-GuardianDataPath))

    $pins = Get-Content -Path (Join-Path $script:ModuleRoot 'data\pins.json') -Raw | ConvertFrom-Json
    $base = Join-Path $DataPath 'phone'
    $adb  = Join-Path $base ('adb\' + $pins.adb.exe)
    $ioc  = Join-Path $base 'ioc.yaml'
    $wat  = Join-Path $base 'watchware.yaml'
    [pscustomobject]@{
        Adb           = $(if (Test-Path $adb) { $adb } else { $null })
        AdbDir        = (Join-Path $base 'adb')
        IocPath       = $(if (Test-Path $ioc) { $ioc } else { $null })
        WatchwarePath = $(if (Test-Path $wat) { $wat } else { $null })
        StatePath     = (Join-Path $base 'installed.json')
        Base          = $base
    }
}

function Enter-PrivateAdb {
    <#
    .SYNOPSIS
        Points adb at pc-guardian's own server port, so it never touches an adb session the person uses elsewhere.
    #>
    [CmdletBinding()]
    param()
    $script:PreviousAdbPort = $env:ANDROID_ADB_SERVER_PORT
    $env:ANDROID_ADB_SERVER_PORT = '5038'
}

function Exit-PrivateAdb {
    <#
    .SYNOPSIS
        Stops pc-guardian's adb server and restores the environment.
    #>
    [CmdletBinding()]
    param([string]$Adb)
    if ($Adb) { try { & $Adb kill-server 2>&1 | Out-Null } catch { } }
    if ($null -eq $script:PreviousAdbPort) { Remove-Item Env:\ANDROID_ADB_SERVER_PORT -ErrorAction SilentlyContinue }
    else { $env:ANDROID_ADB_SERVER_PORT = $script:PreviousAdbPort }
}
