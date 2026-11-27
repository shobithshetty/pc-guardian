function Save-GuardianUpdate {
    <#
    .SYNOPSIS
        Downloads a new pc-guardian installer from this project's GitHub release and checks it. Installs nothing.
    .DESCRIPTION
        The app calls this when the person presses "Update now". It refuses any address that is not a release download
        of the given repository, downloads the installer and the release's SHA256SUMS.txt into a temporary folder,
        and keeps the installer only if its SHA-256 matches the listed one. A mismatch, an oversized file or a
        wrong file name deletes the download and throws. It also reports the installer's Authenticode signature
        (releases are unsigned until code signing is approved; the app shows that). The caller decides whether to run
        the installer.
    .PARAMETER InstallerUrl
        https://github.com/<owner>/<name>/releases/download/<tag>/pc-guardian-setup-<version>.exe
    .PARAMETER ChecksumsUrl
        https://github.com/<owner>/<name>/releases/download/<tag>/SHA256SUMS.txt
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InstallerUrl,
        [Parameter(Mandatory)][string]$ChecksumsUrl,
        [Parameter(Mandatory)][string]$Repository,
        [string]$OutDir = (Join-Path ([IO.Path]::GetTempPath()) 'pc-guardian-update'),
        [int64]$MaxBytes = 200MB
    )

    if ($Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { throw 'Repository must look like owner/name.' }
    $prefix = "https://github.com/$Repository/releases/download/"
    foreach ($u in $InstallerUrl, $ChecksumsUrl) {
        if (-not $u.StartsWith($prefix, [StringComparison]::Ordinal) -or $u -match '[\s"''<>`]' -or ($u.Substring($prefix.Length) -split '/').Count -ne 2) {
            throw "Refusing to download from $u : only release files of $Repository are allowed."
        }
    }
    $name = [IO.Path]::GetFileName(([uri]$InstallerUrl).LocalPath)
    if ($name -notmatch '^pc-guardian-setup-[\d.]+\.exe$') { throw "Unexpected installer file name: $name" }
    if ([IO.Path]::GetFileName(([uri]$ChecksumsUrl).LocalPath) -ne 'SHA256SUMS.txt') { throw 'The checksum file must be SHA256SUMS.txt.' }

    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    Get-ChildItem -Path $OutDir -Filter 'pc-guardian-setup-*.exe' -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    $file = Join-Path $OutDir $name
    $sumsFile = Join-Path $OutDir 'SHA256SUMS.txt'

    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    try {
        Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $sumsFile -UseBasicParsing -TimeoutSec 60 -Headers @{ 'User-Agent' = 'pc-guardian' }
        Invoke-WebRequest -Uri $InstallerUrl -OutFile $file -UseBasicParsing -TimeoutSec 600 -Headers @{ 'User-Agent' = 'pc-guardian' }
    }
    catch {
        Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
        throw "Could not download the update: $($_.Exception.Message)"
    }

    $bytes = (Get-Item -LiteralPath $file).Length
    if ($bytes -gt $MaxBytes -or $bytes -le 0) {
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        throw "The downloaded installer has an unexpected size ($bytes bytes); it was deleted."
    }

    # SHA256SUMS.txt lines look like: <64 hex>  <file name>
    $expected = $null
    foreach ($line in @(Get-Content -LiteralPath $sumsFile)) {
        if ("$line" -match '^(?<h>[0-9a-fA-F]{64})\s+\*?(?<n>\S+)\s*$' -and $Matches.n -eq $name) { $expected = $Matches.h.ToLowerInvariant(); break }
    }
    if (-not $expected) {
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        throw "SHA256SUMS.txt does not list $name; the download was deleted."
    }
    $actual = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        throw "The installer's checksum does not match the release ($actual, expected $expected). It was deleted and nothing was installed."
    }

    $sig = Get-AuthenticodeSignature -LiteralPath $file -ErrorAction SilentlyContinue
    $signer = ''
    if ($sig -and $sig.SignerCertificate) { $signer = "$($sig.SignerCertificate.Subject)" }
    [pscustomobject]@{
        Path      = $file
        Name      = $name
        Sha256    = $actual
        Bytes     = $bytes
        Signature = if ($sig) { "$($sig.Status)" } else { 'Unknown' }
        Signer    = $signer
    }
}
