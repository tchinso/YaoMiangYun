# Run: powershell -NoProfile -ExecutionPolicy Bypass -STA -File scripts/New-AppIcon.ps1
$ErrorActionPreference = 'Stop'
if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    throw 'WPF rendering requires STA. Run this script with powershell -NoProfile -ExecutionPolicy Bypass -STA -File scripts/New-AppIcon.ps1.'
}
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

$root = Split-Path -Parent $PSScriptRoot
$windowPath = Join-Path $root 'src/YaoVpn.App/MainWindow.xaml'
$iconPath = Join-Path $root 'src/YaoVpn.App/Assets/AppIcon.ico'
[xml]$window = Get-Content -LiteralPath $windowPath -Raw -Encoding UTF8
$namespaces = New-Object System.Xml.XmlNamespaceManager($window.NameTable)
$namespaces.AddNamespace('x', 'http://schemas.microsoft.com/winfx/2006/xaml')
$logoNode = $window.SelectSingleNode('//*[@x:Name="AppLogo"]', $namespaces)
if (!$logoNode) { throw 'The in-app AppLogo element was not found.' }

# Render the actual in-app vector, so colors, corners and shield stay identical.
$reader = New-Object System.Xml.XmlNodeReader($logoNode)
try { $logo = [Windows.Markup.XamlReader]::Load($reader) }
finally { $reader.Close() }
$logo.Margin = [Windows.Thickness]::new(0)
$logoSize = [Windows.Size]::new($logo.Width, $logo.Height)
$logo.Measure($logoSize)
$logo.Arrange([Windows.Rect]::new($logoSize))
$logo.UpdateLayout()

$sizes = @(16, 20, 24, 32, 40, 48, 64, 128, 256)
$frames = @(
    foreach ($size in $sizes) {
        $visual = [Windows.Media.DrawingVisual]::new()
        $drawing = $visual.RenderOpen()
        $drawing.DrawRectangle([Windows.Media.VisualBrush]::new($logo), $null, [Windows.Rect]::new(0, 0, $size, $size))
        $drawing.Close()
        $bitmap = [Windows.Media.Imaging.RenderTargetBitmap]::new($size, $size, 96, 96, [Windows.Media.PixelFormats]::Pbgra32)
        $bitmap.Render($visual)
        $encoder = [Windows.Media.Imaging.PngBitmapEncoder]::new()
        $encoder.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
        $stream = [IO.MemoryStream]::new()
        try {
            $encoder.Save($stream)
            [pscustomobject]@{ Size = $size; Bytes = $stream.ToArray() }
        }
        finally { $stream.Dispose() }
    }
)

# ICO directory entries point to full-color PNG frames with transparent corners.
[IO.Directory]::CreateDirectory((Split-Path -Parent $iconPath)) | Out-Null
$writer = [IO.BinaryWriter]::new([IO.File]::Create($iconPath))
try {
    $writer.Write([uint16]0)
    $writer.Write([uint16]1)
    $writer.Write([uint16]$frames.Count)
    $offset = 6 + 16 * $frames.Count
    foreach ($frame in $frames) {
        $dimension = if ($frame.Size -eq 256) { 0 } else { $frame.Size }
        $writer.Write([byte]$dimension)
        $writer.Write([byte]$dimension)
        $writer.Write([byte]0)
        $writer.Write([byte]0)
        $writer.Write([uint16]1)
        $writer.Write([uint16]32)
        $writer.Write([uint32]$frame.Bytes.Length)
        $writer.Write([uint32]$offset)
        $offset += $frame.Bytes.Length
    }
    foreach ($frame in $frames) { $writer.Write([byte[]]$frame.Bytes) }
}
finally { $writer.Dispose() }
Write-Output "Created $iconPath ($($sizes -join ', ') px)"
