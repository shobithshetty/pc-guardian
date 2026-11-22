function Get-DefenderExclusionAudit {
    <#
    .SYNOPSIS
        Lists Microsoft Defender exclusions. Malware often adds one so Defender stops looking at it.
    .DESCRIPTION
        Defender hides the list from non-administrators ("N/A: Administrators only"); those values are skipped,
        so run pc-guardian as administrator (the daily task does) to see them.
    #>
    [CmdletBinding()]
    param()
    $pref = Get-MpPreference -ErrorAction SilentlyContinue
    if (-not $pref) { return }
    foreach ($kind in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension') {
        foreach ($value in @($pref.$kind)) {
            if ($value -and "$value" -notlike 'N/A*') {
                $what = switch ($kind) { 'ExclusionPath' { 'files in this folder or path' } 'ExclusionProcess' { 'files opened by this program' } default { 'files of this type' } }
                New-Finding -Category 'Persistence' -Key "Defender:Exclusion:${kind}:$value" `
                    -Detail "Microsoft Defender will not scan $what. Developer tools such as Android Studio add these on purpose; malware also adds them to hide, so keep only the ones you recognize."
            }
        }
    }
}

function Get-WmiPersistenceAudit {
    <#
    .SYNOPSIS
        Lists WMI event consumers that run a command or script. A classic fileless persistence spot.
    #>
    [CmdletBinding()]
    param()
    foreach ($class in 'CommandLineEventConsumer', 'ActiveScriptEventConsumer') {
        Get-CimInstance -Namespace 'root\subscription' -ClassName $class -ErrorAction SilentlyContinue | ForEach-Object {
            $what = if ($_.PSObject.Properties['CommandLineTemplate'] -and $_.CommandLineTemplate) { ("$($_.CommandLineTemplate)" -replace '\s+', ' ') }
                    elseif ($_.PSObject.Properties['ScriptText'] -and $_.ScriptText) {
                        $flat = "$($_.ScriptText)" -replace '\s+', ' '
                        "Runs a script in the background: $($flat.Substring(0, [Math]::Min(110, $flat.Length)))..."
                    }
                    else { '' }
            New-Finding -Category 'Persistence' -Key "WMI:${class}:$($_.Name)" -Detail $what
        }
    }
}

function Get-ServiceAudit {
    <#
    .SYNOPSIS
        Lists automatic services that do not live under the Windows folder.
    #>
    [CmdletBinding()]
    param()
    Get-CimInstance -ClassName Win32_Service -Filter "StartMode='Auto'" -ErrorAction SilentlyContinue |
        Where-Object { $_.PathName -and $_.PathName -notmatch '^"?[A-Za-z]:\\Windows\\' } |
        ForEach-Object { New-Finding -Category 'Service' -Key "Service:$($_.Name)" -Detail "$($_.PathName)" }
}

function Get-RootCertificateAudit {
    <#
    .SYNOPSIS
        Lists trusted root certificates. A newly added root can let someone read your encrypted traffic.
    #>
    [CmdletBinding()]
    param()
    # Windows copies system roots into each user's store over time, so a user-store certificate is only
    # remarkable when the system stores do not have it too ("user-installed": added by you or a program you ran).
    $system = @{}
    foreach ($s in 'Root', 'AuthRoot') {
        Get-ChildItem -Path "Cert:\LocalMachine\$s" -ErrorAction SilentlyContinue | ForEach-Object { $system[$_.Thumbprint] = $true }
    }
    foreach ($store in 'LocalMachine', 'CurrentUser') {
        Get-ChildItem -Path "Cert:\$store\Root" -ErrorAction SilentlyContinue | ForEach-Object {
            $detail = "$($_.Subject) (expires $($_.NotAfter.ToString('yyyy-MM-dd')))"
            if ($store -eq 'CurrentUser' -and -not $system[$_.Thumbprint]) { $detail += '; user-installed, not in the system certificate stores' }
            New-Finding -Category 'Certificate' -Key "Cert:Root:${store}:$($_.Thumbprint)" -Detail $detail
        }
    }
}

function Get-HostsFileAudit {
    <#
    .SYNOPSIS
        Lists hosts-file entries other than localhost. Redirecting a bank or login site is a known attack.
    #>
    [CmdletBinding()]
    param([string]$Path = (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'))
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue | ForEach-Object {
        $line = ($_ -replace '#.*$', '').Trim()
        if ($line -match '^(?<ip>\S+)\s+(?<hosts>.+)$') {
            $ip = $Matches.ip
            foreach ($h in ($Matches.hosts -split '\s+')) {
                if ($h -and $h -ne 'localhost') {
                    New-Finding -Category 'Hosts' -Key "Hosts:$h" -Detail "points to $ip"
                }
            }
        }
    }
}

function Get-BrowserExtensionAudit {
    <#
    .SYNOPSIS
        Lists Chrome, Edge and Brave extensions, and marks the ones that can read every site plus sensitive data.
    .DESCRIPTION
        Read-only: reads each extension's manifest.json. "Risky" means access to all websites combined with
        cookies, web requests, native messaging or the debugger, the combination infostealing extensions use.
    #>
    [CmdletBinding()]
    param([hashtable]$Roots)

    if (-not $Roots) {
        $Roots = @{
            Chrome = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data'
            Edge   = Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data'
            Brave  = Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data'
        }
    }
    $allSites  = '<all_urls>', '*://*/*', 'http://*/*', 'https://*/*'
    $sensitive = 'cookies', 'webRequest', 'webRequestBlocking', 'nativeMessaging', 'debugger'

    foreach ($browser in $Roots.Keys) {
        if (-not (Test-Path -LiteralPath $Roots[$browser])) { continue }
        $profiles = Get-ChildItem -LiteralPath $Roots[$browser] -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }
        foreach ($prof in $profiles) {
            $extDir = Join-Path $prof.FullName 'Extensions'
            foreach ($ext in (Get-ChildItem -LiteralPath $extDir -Directory -ErrorAction SilentlyContinue)) {
                $verDir = Get-ChildItem -LiteralPath $ext.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
                if (-not $verDir) { continue }
                $manifestPath = Join-Path $verDir.FullName 'manifest.json'
                if (-not (Test-Path -LiteralPath $manifestPath)) { continue }
                try { $m = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json } catch { continue }

                $name = "$($m.name)"
                if ($name -match '^__MSG_(?<k>.+)__$') {
                    $locale = if ($m.PSObject.Properties['default_locale']) { $m.default_locale } else { 'en' }
                    $msgFile = Join-Path $verDir.FullName "_locales\$locale\messages.json"
                    if (Test-Path -LiteralPath $msgFile) {
                        try {
                            $msgs = Get-Content -LiteralPath $msgFile -Raw | ConvertFrom-Json
                            $hit = $msgs.PSObject.Properties | Where-Object { $_.Name -ieq $Matches.k } | Select-Object -First 1
                            if ($hit -and $hit.Value.message) { $name = $hit.Value.message }
                        } catch { Write-Verbose "Could not read $msgFile" }
                    }
                }

                $perms = @()
                foreach ($field in 'permissions', 'host_permissions', 'optional_permissions') {
                    if ($m.PSObject.Properties[$field]) { $perms += @($m.$field | Where-Object { $_ -is [string] }) }
                }
                $hasAll  = [bool]($perms | Where-Object { $_ -in $allSites })
                $hasSens = @($perms | Where-Object { $_ -in $sensitive })
                $risky = $hasAll -and $hasSens.Count -gt 0

                $detail = "$name $($m.version) ($($prof.Name))"
                if ($risky) { $detail += "; risky permissions: all websites + $($hasSens -join ', ')" }
                # Risky extensions use their own category: they are reported on every scan, not baselined.
                New-Finding -Category $(if ($risky) { 'ExtensionRisk' } else { 'Extension' }) -Key "Extension:${browser}:$($ext.Name)" -Detail $detail
            }
        }
    }
}

function Get-PersistenceAudit {
    <#
    .SYNOPSIS
        Collects the "hiding places" audits. Part of the baseline: only NEW entries are reported later.
    #>
    [CmdletBinding()]
    param()
    Write-GuardianProgress -Type file -Value 'Defender exclusions'
    Get-DefenderExclusionAudit
    Write-GuardianProgress -Type file -Value 'Background services'
    Get-ServiceAudit
    Write-GuardianProgress -Type file -Value 'WMI subscriptions'
    Get-WmiPersistenceAudit
    Write-GuardianProgress -Type file -Value 'Trusted root certificates'
    Get-RootCertificateAudit
    Write-GuardianProgress -Type file -Value 'Hosts file'
    Get-HostsFileAudit
    Write-GuardianProgress -Type file -Value 'Browser extensions'
    Get-BrowserExtensionAudit
}
