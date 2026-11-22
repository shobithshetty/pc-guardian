<#
.SYNOPSIS
    Draws the pc-guardian shield and writes it as a multi-size Windows icon (.ico).
.DESCRIPTION
    Run from the repository root:  .\tools\New-AppIcon.ps1
    To use your own logo instead, replace app\PcGuardian.App\Assets\pc-guardian.ico and rebuild.
#>
[CmdletBinding()]
param(
    [string]$OutFile = (Join-Path $PSScriptRoot '..\app\PcGuardian.App\Assets\pc-guardian.ico'),
    [string]$PreviewPng
)

Add-Type -AssemblyName System.Drawing

function New-ShieldPng {
    param([int]$Size)
    $k = $Size / 24.0
    $bmp = New-Object System.Drawing.Bitmap $Size, $Size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::Transparent)

    function Pt($x, $y) { New-Object System.Drawing.PointF ([single]($x * $k)), ([single]($y * $k)) }
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddLine((Pt 12 2), (Pt 20.5 5.2))
    $path.AddLine((Pt 20.5 5.2), (Pt 20.5 11))
    $path.AddBezier((Pt 20.5 11), (Pt 20.5 16.2), (Pt 16.9 20.4), (Pt 12 22))
    $path.AddBezier((Pt 12 22), (Pt 7.1 20.4), (Pt 3.5 16.2), (Pt 3.5 11))
    $path.AddLine((Pt 3.5 11), (Pt 3.5 5.2))
    $path.CloseFigure()

    $fill = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 22, 138, 62))
    $g.FillPath($fill, $path)

    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::White), ([single](2.3 * $k))
    $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
    $g.DrawLines($pen, [System.Drawing.PointF[]]@((Pt 8 12), (Pt 11 15), (Pt 16.5 9)))

    $g.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    , $ms.ToArray()
}

$sizes = 16, 24, 32, 48, 64, 128, 256
$images = foreach ($s in $sizes) { , (New-ShieldPng -Size $s) }

if ($PreviewPng) { [System.IO.File]::WriteAllBytes($PreviewPng, (New-ShieldPng -Size 256)) }

$dir = Split-Path $OutFile -Parent
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$stream = [System.IO.File]::Create($OutFile)
$w = New-Object System.IO.BinaryWriter $stream
$w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$sizes.Count)   # ICONDIR
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i]; $bytes = $images[$i]
    $w.Write([byte]$(if ($s -ge 256) { 0 } else { $s }))   # width (0 means 256)
    $w.Write([byte]$(if ($s -ge 256) { 0 } else { $s }))   # height
    $w.Write([byte]0); $w.Write([byte]0)                    # palette, reserved
    $w.Write([uint16]1); $w.Write([uint16]32)               # planes, bits per pixel
    $w.Write([uint32]$bytes.Length); $w.Write([uint32]$offset)
    $offset += $bytes.Length
}
foreach ($bytes in $images) { $w.Write($bytes) }
$w.Dispose(); $stream.Dispose()
"Wrote $OutFile ($($sizes.Count) sizes, $([math]::Round((Get-Item $OutFile).Length / 1KB, 1)) KB)"
