function Install-GuardianScanner {
    <#
    .SYNOPSIS
        Downloads the ClamAV virus database and the YARA program + public rules used by -Scan.
    .DESCRIPTION
        Network use happens only when you run this command. Files go under -DataPath (per user, no admin needed).
        - ClamAV program: only with -InstallClamAv, installed from the official winget package (Cisco.ClamAV).
          Windows may ask for permission, because ClamAV installs for all users.
        - ClamAV database: runs freshclam against an own config so the database lands in <DataPath>\clamav-db.
          freshclam verifies the signatures on the database files itself.
        - YARA: downloads the exact YARA release listed in data\pins.json and refuses it unless its SHA-256 matches.
        - Rules: downloads Neo23x0/signature-base at the exact commit pinned in data\pins.json and refuses it
          unless the content hash matches. Rule files that depend on Loki-style externals are dropped and the
          rest compiled into rules.yarc.
        Nothing is fetched from a moving target such as a branch name or "latest". To move to newer versions,
        a maintainer reviews the change and updates data\pins.json.
    .PARAMETER ClamAv
        Only update ClamAV definitions. With neither -ClamAv nor -Yara, both are done.
    .PARAMETER Yara
        Only install/update YARA and its rules.
    .PARAMETER InstallClamAv
        Also install the ClamAV program with winget if it is missing.
    .PARAMETER Progress
        Print PCG| progress lines for the app.
    #>
    [CmdletBinding()]
    param(
        [switch]$ClamAv,
        [switch]$Yara,
        [switch]$InstallClamAv,
        [switch]$Progress,
        [string]$DataPath = (Get-GuardianDataPath)
    )

    if (-not ($ClamAv -or $Yara)) { $ClamAv = $true; $Yara = $true }
    # Windows PowerShell 5.1 does not enable TLS 1.2 by default; GitHub requires it.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    New-Item -ItemType Directory -Force -Path $DataPath | Out-Null

    $needClamInstall = $InstallClamAv -and -not (Find-ClamAv)

    # YARA is skipped when the pinned program and rules are already installed (recorded in installed.json).
    $pins = Get-Content -Path (Join-Path $script:ModuleRoot 'data\pins.json') -Raw | ConvertFrom-Json
    $yaraBase  = Join-Path $DataPath 'yara'
    $yaraState = Join-Path $yaraBase 'installed.json'
    $yaraCurrent = $false
    if ($Yara -and (Test-Path $yaraState) -and (Test-Path (Join-Path $yaraBase 'bin\yara64.exe')) -and (Test-Path (Join-Path $yaraBase 'rules.yarc'))) {
        $have = Get-Content -Path $yaraState -Raw | ConvertFrom-Json
        $yaraCurrent = ($have.yaraSha256 -eq $pins.yara.sha256) -and ($have.rulesContentSha256 -eq $pins.rules.contentSha256)
    }

    $script:ProgressEnabled = [bool]$Progress
    $script:PhaseIndex = 0
    $yaraPhases = if (-not $Yara) { 0 } elseif ($yaraCurrent) { 1 } else { 3 }
    $script:PhaseTotal = [int][bool]$needClamInstall + [int][bool]$ClamAv + $yaraPhases

    if ($needClamInstall) {
        Start-GuardianPhase -Name 'Installing ClamAV (Windows may ask for permission)'
        winget install --id Cisco.ClamAV --exact --silent --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -ne 0) { Write-Warning "winget exited with code $LASTEXITCODE; ClamAV may not be installed." }
    }

    if ($ClamAv) {
        Start-GuardianPhase -Name 'Updating the virus database'
        $c = Find-ClamAv
        if (-not $c) {
            Write-Warning 'ClamAV is not installed. Run: winget install Cisco.ClamAV   (then run this command again)'
        } else {
            $db   = Join-Path $DataPath 'clamav-db'
            $conf = Join-Path $DataPath 'freshclam.conf'
            New-Item -ItemType Directory -Force -Path $db | Out-Null
            Set-Content -Path $conf -Encoding ASCII -Value @("DatabaseDirectory $db", 'DatabaseMirror database.clamav.net')
            Write-GuardianProgress -Type file -Value 'Downloading virus signatures (about 100 MB the first time)'
            # freshclam prints "... 12.30MiB/84.95MiB" while it downloads; turn that into a percent for the bar.
            $unit = @{ K = 1KB; M = 1MB; G = 1GB }
            & $c.FreshClam "--config-file=$conf" 2>&1 | ForEach-Object {
                $line = "$_"
                Write-Host $line
                if ($line -match '(?<done>[\d.]+)(?<du>[KMG])iB/(?<tot>[\d.]+)(?<tu>[KMG])iB') {
                    $d = [double]$Matches.done * $unit[$Matches.du]
                    $t = [double]$Matches.tot * $unit[$Matches.tu]
                    if ($t -gt 0) { Write-GuardianProgress -Type percent -Value ([int][math]::Min(100, [math]::Floor($d * 100 / $t))) }
                }
            }
            if ($LASTEXITCODE -ne 0) { Write-Warning "freshclam exited with code $LASTEXITCODE" }
        }
    }

    if ($Yara -and $yaraCurrent) {
        Start-GuardianPhase -Name 'YARA program and rules are already up to date'
        Write-Host 'YARA is already at the pinned versions; nothing to download.'
    }
    elseif ($Yara) {
        $base  = $yaraBase
        $bin   = Join-Path $base 'bin'
        $rules = Join-Path $base 'rules'
        $tmp   = Join-Path ([IO.Path]::GetTempPath()) ('pcg-' + [guid]::NewGuid())
        New-Item -ItemType Directory -Force -Path $bin, $rules, $tmp | Out-Null
        try {
            Start-GuardianPhase -Name "Downloading the YARA program ($($pins.yara.version))"
            $zip = Join-Path $tmp $pins.yara.asset
            $url = 'https://github.com/VirusTotal/yara/releases/download/{0}/{1}' -f $pins.yara.version, $pins.yara.asset
            Save-GuardianDownload -Uri $url -OutFile $zip -Label 'YARA program'
            $got = (Get-FileHash -Path $zip -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($got -ne $pins.yara.sha256) { throw "YARA download does not match the pinned SHA-256 (expected $($pins.yara.sha256), got $got). Nothing was installed." }
            Write-GuardianProgress -Type file -Value 'Checked the download against its pinned hash'
            $x = Join-Path $tmp 'yara-x'
            Expand-Archive -Path $zip -DestinationPath $x -Force
            Get-ChildItem -Path $x -Recurse -Include 'yara64.exe', 'yarac64.exe' | Copy-Item -Destination $bin -Force

            Start-GuardianPhase -Name 'Downloading the public YARA rules'
            Write-GuardianProgress -Type file -Value "Neo23x0/signature-base at commit $($pins.rules.commit.Substring(0,8))"
            $rzip = Join-Path $tmp 'rules.zip'
            Save-GuardianDownload -Uri ('https://github.com/{0}/archive/{1}.zip' -f $pins.rules.repo, $pins.rules.commit) -OutFile $rzip -Label 'Detection rules' -ExpectedBytes ([long]$pins.rules.approxBytes)
            $rx = Join-Path $tmp 'rules-x'
            Expand-Archive -Path $rzip -DestinationPath $rx -Force
            $srcDir = Get-ChildItem -Path $rx -Recurse -Directory | Where-Object { $_.FullName -like '*\yara' } | Select-Object -First 1
            if (-not $srcDir) { throw 'The rules download has no yara folder.' }
            $gotRules = Get-RuleSetHash -Path $srcDir.FullName
            if ($gotRules -ne $pins.rules.contentSha256) { throw "Rules do not match the pinned content hash (expected $($pins.rules.contentSha256), got $gotRules). Nothing was installed." }
            Write-GuardianProgress -Type file -Value 'Checked the rules against their pinned hash'

            Start-GuardianPhase -Name 'Preparing the rules'
            Get-ChildItem -Path $rules -Filter '*.yar' -ErrorAction SilentlyContinue | Remove-Item -Force
            Get-ChildItem -Path $srcDir.FullName -Filter '*.yar' | Copy-Item -Destination $rules -Force

            $keep = @(Get-ChildItem -Path $rules -Filter '*.yar' | Where-Object { -not (Test-YaraRuleUsesExternals -Path $_.FullName) })
            $skipped = @(Get-ChildItem -Path $rules -Filter '*.yar').Count - $keep.Count
            $index = Join-Path $base 'index.yar'
            $keep | ForEach-Object { 'include "{0}"' -f ($_.FullName -replace '\\', '/') } | Set-Content -Path $index -Encoding ASCII
            Set-Content -Path (Join-Path $base 'RULES-ATTRIBUTION.txt') -Encoding ASCII -Value @(
                'Rules: Neo23x0/signature-base, Detection Rule License 1.1 (https://github.com/Neo23x0/signature-base).',
                "Pinned commit: $($pins.rules.commit)",
                'Rule authors are shown in scan findings. Rules are third-party and can false-positive.')

            Write-GuardianProgress -Type file -Value 'Compiling the rules'
            & (Join-Path $bin 'yarac64.exe') -w $index (Join-Path $base 'rules.yarc')
            if ($LASTEXITCODE -ne 0) { throw "yarac64 could not compile the rules (exit $LASTEXITCODE)." }
            # Remember what is installed so the next run can skip the download.
            [pscustomobject]@{ yaraSha256 = $pins.yara.sha256; rulesContentSha256 = $pins.rules.contentSha256; rulesCommit = $pins.rules.commit } |
                ConvertTo-Json | Set-Content -Path $yaraState -Encoding UTF8
            Write-Host ("YARA ready: {0} rule files compiled, {1} skipped (they need filename/path context)." -f $keep.Count, $skipped)
        }
        finally {
            Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
