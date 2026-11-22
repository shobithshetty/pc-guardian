<#
.SYNOPSIS
    Reports whether the pinned third-party downloads have newer versions, with ready-to-review values.
.DESCRIPTION
    Read-only. It never edits pins.json or any workflow: pins change only through a reviewed pull request
    (see docs/SUPPLY-CHAIN.md). It checks:
      - YARA (data/pins.json) against the latest VirusTotal/yara release
      - the signature-base rules commit against the branch head (how many commits ahead, and what they say)
      - Inno Setup (release.yml) against the latest jrsoftware/issrc release
    With -ComputeHashes it also downloads the newest rules and computes the content hash you would pin.
    GitHub Actions versions are handled by Dependabot (.github/dependabot.yml).
.PARAMETER OutFile
    Also write the report (markdown) to this file.
.PARAMETER AsObject
    Return an object instead of text.
#>
[CmdletBinding()]
param(
    [switch]$ComputeHashes,
    [string]$OutFile,
    [switch]$AsObject,
    [string]$Token = $env:GITHUB_TOKEN,
    # Repository root to read pins from (defaults to this script's repository). Used to test against old pins.
    [string]$Root
)

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$repoRoot = Split-Path $PSScriptRoot -Parent
$root = if ($Root) { $Root } else { $repoRoot }
$pins = Get-Content -Path (Join-Path $root 'src\PcGuardian\data\pins.json') -Raw | ConvertFrom-Json
$headers = @{ 'User-Agent' = 'pc-guardian-pin-watch'; Accept = 'application/vnd.github+json' }
if ($Token) { $headers['Authorization'] = "Bearer $Token" }
function Get-Gh($path) { Invoke-RestMethod -Uri "https://api.github.com/$path" -Headers $headers -TimeoutSec 60 }

$lines = New-Object System.Collections.Generic.List[string]
$updates = New-Object System.Collections.Generic.List[object]
$errors = New-Object System.Collections.Generic.List[string]

# --- YARA ---------------------------------------------------------------------------------------
try {
    $rel = Get-Gh 'repos/VirusTotal/yara/releases/latest'
    if ($rel.tag_name -ne $pins.yara.version) {
        $asset = @($rel.assets | Where-Object { $_.name -like '*win64.zip' })[0]
        $digest = if ($asset -and $asset.PSObject.Properties['digest']) { "$($asset.digest)" } else { 'not published' }
        $updates.Add([pscustomobject]@{ Name = 'YARA'; Current = $pins.yara.version; Latest = $rel.tag_name })
        $lines.Add("### YARA: $($pins.yara.version) -> $($rel.tag_name)")
        $lines.Add("- Release notes: $($rel.html_url)")
        if ($asset) { $lines.Add("- New asset: ``$($asset.name)``, GitHub digest: ``$digest``") }
        $lines.Add('- Check: the changelog for rule-syntax changes, then update `yara` in `src/PcGuardian/data/pins.json` (version, asset, sha256) and run the tests.')
    } else { $lines.Add("- YARA is current ($($pins.yara.version)).") }
} catch { $errors.Add("YARA check failed: $($_.Exception.Message)") }

# --- signature-base rules ----------------------------------------------------------------------
try {
    $repoInfo = Get-Gh "repos/$($pins.rules.repo)"
    $cmp = Get-Gh "repos/$($pins.rules.repo)/compare/$($pins.rules.commit)...$($repoInfo.default_branch)"
    if ($cmp.ahead_by -gt 0) {
        $head = $cmp.commits[-1].sha
        $updates.Add([pscustomobject]@{ Name = 'Rules'; Current = $pins.rules.commit.Substring(0, 8); Latest = $head.Substring(0, 8) })
        $lines.Add("### Rules (signature-base): $($cmp.ahead_by) new commit(s) since the pinned $($pins.rules.commit.Substring(0, 8))")
        $lines.Add("- Diff to review: $($cmp.html_url)")
        $lines.Add("- Newest commit: ``$head``")
        foreach ($c in ($cmp.commits | Select-Object -Last 8)) { $lines.Add("  - $((($c.commit.message -split "`n")[0]))") }
        if ($ComputeHashes) {
            $tmp = Join-Path ([IO.Path]::GetTempPath()) ('pinwatch-' + [guid]::NewGuid())
            New-Item -ItemType Directory -Force -Path $tmp | Out-Null
            try {
                $zip = Join-Path $tmp 'rules.zip'
                Invoke-WebRequest -Uri "https://github.com/$($pins.rules.repo)/archive/$head.zip" -OutFile $zip -UseBasicParsing -TimeoutSec 120
                Expand-Archive -Path $zip -DestinationPath (Join-Path $tmp 'x') -Force
                $dir = Get-ChildItem -Path (Join-Path $tmp 'x') -Recurse -Directory | Where-Object { $_.FullName -like '*\yara' } | Select-Object -First 1
                Import-Module (Join-Path $repoRoot 'src\PcGuardian\PcGuardian.psd1') -Force
                $hash = & (Get-Module PcGuardian) { param($p) Get-RuleSetHash -Path $p } $dir.FullName
                $size = (Get-Item $zip).Length
                $lines.Add("- Values to pin: commit ``$head``, contentSha256 ``$hash``, approxBytes ``$size``")
            } finally { Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue }
        }
        $lines.Add('- Check: read the diff (new or changed rules), measure false positives on a clean machine, then update `rules` in `src/PcGuardian/data/pins.json`.')
    } else { $lines.Add("- Rules are current (commit $($pins.rules.commit.Substring(0, 8)) is the branch head).") }
} catch { $errors.Add("Rules check failed: $($_.Exception.Message)") }

# --- Inno Setup --------------------------------------------------------------------------------
try {
    $workflow = Get-Content -Path (Join-Path $root '.github\workflows\release.yml') -Raw
    if ($workflow -match 'innosetup-(?<v>[\d.]+)-x64\.exe') {
        $current = $Matches.v
        $rel = Get-Gh 'repos/jrsoftware/issrc/releases/latest'
        $latest = ($rel.tag_name -replace '^is-', '') -replace '_', '.'
        if ($latest -ne $current) {
            $asset = @($rel.assets | Where-Object { $_.name -like 'innosetup-*-x64.exe' })[0]
            $digest = if ($asset -and $asset.PSObject.Properties['digest']) { "$($asset.digest)" } else { 'not published' }
            $updates.Add([pscustomobject]@{ Name = 'Inno Setup'; Current = $current; Latest = $latest })
            $lines.Add("### Inno Setup: $current -> $latest")
            $lines.Add("- Release: $($rel.html_url)")
            if ($asset) { $lines.Add("- New asset: ``$($asset.name)``, digest: ``$digest``") }
            $lines.Add('- Check: update `INNO_URL` and `INNO_SHA256` in `.github/workflows/release.yml`, rebuild the installer, and test it.')
        } else { $lines.Add("- Inno Setup is current ($current).") }
    }
} catch { $errors.Add("Inno Setup check failed: $($_.Exception.Message)") }

$summary = if ($updates.Count -gt 0) { "$($updates.Count) pinned dependenc$(if ($updates.Count -eq 1) { 'y has' } else { 'ies have' }) a newer version." } else { 'All pinned downloads are current.' }
$report = New-Object System.Collections.Generic.List[string]
$report.Add("## Pin watch report ($(Get-Date -Format 'yyyy-MM-dd'))")
$report.Add('')
$report.Add($summary)
$report.Add('')
foreach ($l in $lines) { $report.Add($l) }
if ($errors.Count -gt 0) { $report.Add(''); $report.Add('### Could not check'); foreach ($e in $errors) { $report.Add("- $e") } }
$report.Add('')
$report.Add('_This report only reads. Pins change only through a reviewed pull request; see docs/SUPPLY-CHAIN.md._')
$text = $report -join "`n"
if ($OutFile) { Set-Content -Path $OutFile -Value $text -Encoding UTF8 }

if ($AsObject) { [pscustomobject]@{ HasUpdates = ($updates.Count -gt 0); Updates = $updates.ToArray(); Errors = $errors.ToArray(); Report = $text } }
else { $text }
