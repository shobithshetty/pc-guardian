function Install-GuardianPhoneTools {
    <#
    .SYNOPSIS
        Downloads the tools for the Android phone check: Google's adb and the public stalkerware lists.
    .DESCRIPTION
        Runs only when you ask. adb is Google software under the Android SDK License, so it is never downloaded until
        -AcceptAndroidSdkLicense is passed (the app shows the terms and asks first). Safety checks, in order:
          1. the download must match the SHA-256 pinned in data\pins.json (and Google's published SHA-1);
          2. adb.exe must carry a valid Authenticode signature from Google LLC;
          3. the stalkerware lists are data: size-capped, shape-checked, never run, refreshed weekly.
        Nothing is installed system-wide; files go under <data folder>\phone.
    .PARAMETER AcceptAndroidSdkLicense
        Confirms the person read and accepted https://developer.android.com/studio/terms.
    #>
    [CmdletBinding()]
    param(
        [switch]$AcceptAndroidSdkLicense,
        [switch]$Progress,
        [string]$DataPath = (Get-GuardianDataPath)
    )

    $pins = Get-Content -Path (Join-Path $script:ModuleRoot 'data\pins.json') -Raw | ConvertFrom-Json
    if (-not $AcceptAndroidSdkLicense) {
        throw "Google's adb is licensed under the Android SDK License ($($pins.adb.licenseUrl)). Read it, then run again with -AcceptAndroidSdkLicense."
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $script:ProgressEnabled = [bool]$Progress
    $script:PhaseIndex = 0
    $script:PhaseTotal = 2
    $t = Find-GuardianPhoneTools -DataPath $DataPath
    New-Item -ItemType Directory -Force -Path $t.Base | Out-Null
    $state = @{ adbSha256 = ''; listsFetched = '' }
    if (Test-Path $t.StatePath) {
        $s = Get-Content -Path $t.StatePath -Raw | ConvertFrom-Json
        foreach ($k in @($state.Keys)) { if ($s.PSObject.Properties[$k]) { $state[$k] = "$($s.$k)" } }
    }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('pcg-phone-' + [guid]::NewGuid())
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    try {
        # --- adb ------------------------------------------------------------------------------------------
        Start-GuardianPhase -Name "Android tools from Google (adb $($pins.adb.version))"
        if ($t.Adb -and $state.adbSha256 -eq $pins.adb.sha256) {
            Write-Host 'adb is already at the pinned version; nothing to download.'
        } else {
            $zip = Join-Path $tmp 'platform-tools.zip'
            Save-GuardianDownload -Uri $pins.adb.url -OutFile $zip -Label 'Android tools' -ExpectedBytes ([long]$pins.adb.approxBytes)
            $sha256 = (Get-FileHash -Path $zip -Algorithm SHA256).Hash.ToLowerInvariant()
            $sha1   = (Get-FileHash -Path $zip -Algorithm SHA1).Hash.ToLowerInvariant()
            if ($sha256 -ne $pins.adb.sha256) { throw "The adb download does not match the pinned SHA-256 (expected $($pins.adb.sha256), got $sha256). Nothing was installed." }
            if ($sha1 -ne $pins.adb.sha1) { throw "The adb download does not match Google's published SHA-1. Nothing was installed." }
            Write-GuardianProgress -Type file -Value 'Checked the download against its pinned hashes'
            $x = Join-Path $tmp 'x'
            Expand-Archive -Path $zip -DestinationPath $x -Force
            $exe = Join-Path $x $pins.adb.exe
            if (-not (Test-Path $exe)) { throw 'The adb download does not contain adb.exe. Nothing was installed.' }
            $sig = Get-AuthenticodeSignature -LiteralPath $exe
            if ($sig.Status -ne 'Valid' -or "$($sig.SignerCertificate.Subject)" -notmatch ('CN=' + [regex]::Escape($pins.adb.signer))) {
                throw "adb.exe is not validly signed by $($pins.adb.signer) (status: $($sig.Status)). Nothing was installed."
            }
            Write-GuardianProgress -Type file -Value "adb.exe is signed by $($pins.adb.signer)"
            if (Test-Path $t.AdbDir) { Remove-Item -Path $t.AdbDir -Recurse -Force }
            New-Item -ItemType Directory -Force -Path $t.AdbDir | Out-Null
            Copy-Item -Path (Join-Path $x '*') -Destination $t.AdbDir -Recurse -Force
            $state.adbSha256 = $pins.adb.sha256
        }

        # --- stalkerware lists (data) ---------------------------------------------------------------------
        Start-GuardianPhase -Name 'Stalkerware indicator lists'
        $fresh = $false
        if ($t.IocPath -and $t.WatchwarePath -and $state.listsFetched) {
            try { $fresh = ((Get-Date) - [datetime]::Parse($state.listsFetched, [Globalization.CultureInfo]::InvariantCulture)).TotalDays -lt 7 } catch { $fresh = $false }
        }
        if ($fresh) {
            Write-Host 'The stalkerware lists were refreshed within the last 7 days.'
        } else {
            $got = @{}
            foreach ($n in @(@('ioc.yaml', $pins.phoneLists.stalkerwareUrl), @('watchware.yaml', $pins.phoneLists.watchwareUrl))) {
                $f = Join-Path $tmp $n[0]
                Save-GuardianDownload -Uri $n[1] -OutFile $f -Label $n[0]
                if ((Get-Item $f).Length -gt [long]$pins.phoneLists.maxBytes) { throw "$($n[0]) is larger than expected; it was not installed." }
                $got[$n[0]] = $f
            }
            $map = ConvertFrom-StalkerwareList -Text (Get-Content -Path $got['ioc.yaml'] -Raw)
            if ($map.Count -lt [int]$pins.phoneLists.minPackages) { throw "The stalkerware list has only $($map.Count) package names (expected more); it was not installed." }
            Copy-Item -Path $got['ioc.yaml'] -Destination (Join-Path $t.Base 'ioc.yaml') -Force
            Copy-Item -Path $got['watchware.yaml'] -Destination (Join-Path $t.Base 'watchware.yaml') -Force
            Set-Content -Path (Join-Path $t.Base 'SOURCE.txt') -Encoding ASCII -Value @(
                "Stalkerware indicators: https://github.com/$($pins.phoneLists.repo) (no licence stated; fetched to this PC, not redistributed).",
                "adb: Google platform-tools $($pins.adb.version), Android SDK License: $($pins.adb.licenseUrl)")
            $state.listsFetched = (Get-Date).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        }
        Set-Content -Path $t.StatePath -Encoding UTF8 -Value ([pscustomobject]$state | ConvertTo-Json)
    }
    finally { Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
