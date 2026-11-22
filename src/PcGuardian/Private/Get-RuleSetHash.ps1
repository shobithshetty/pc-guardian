function Get-RuleSetHash {
    <#
    .SYNOPSIS
        One SHA-256 that identifies the exact contents of a folder of .yar files.
    .DESCRIPTION
        Hashes each file, lists "name:hash" lines sorted by lower-case name, then hashes that list.
        It depends only on file names and contents, not on how a zip was compressed, so the value
        stays the same however GitHub packs the archive.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    [string[]]$lines = @(Get-ChildItem -Path $Path -Filter '*.yar' -File |
        ForEach-Object { '{0}:{1}' -f $_.Name.ToLowerInvariant(), (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() })
    [Array]::Sort($lines, [StringComparer]::Ordinal)
    $bytes = [Text.Encoding]::UTF8.GetBytes(($lines -join "`n"))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
}
