# Génère src\deR4Tizer.ico : un rat « dératisé » (sur le dos, pattes en l'air, œil en croix) en dégradé cyan→bleu,
# sur un carré arrondi sombre. Clin d'œil aux RAT (Remote Access Trojans). Dessiné à chaque taille pour rester net en 16 px.
param([string]$Sortie = (Join-Path $PSScriptRoot 'src\deR4Tizer.ico'), [string]$Apercu)
Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'Stop'

function Couleur([string]$hex, [int]$alpha = 255) {
    $c = [Drawing.ColorTranslator]::FromHtml($hex); [Drawing.Color]::FromArgb($alpha, $c)
}

function Dessiner([int]$s) {
    $bmp = New-Object Drawing.Bitmap $s, $s, ([Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'; $g.PixelOffsetMode = 'HighQuality'; $g.Clear([Drawing.Color]::Transparent)

    # Fond : carré arrondi sombre
    $r = [Math]::Max(2, $s * 0.22)
    $fond = New-Object Drawing.Drawing2D.GraphicsPath
    $fond.AddArc(0, 0, $r, $r, 180, 90); $fond.AddArc($s - $r - 1, 0, $r, $r, 270, 90)
    $fond.AddArc($s - $r - 1, $s - $r - 1, $r, $r, 0, 90); $fond.AddArc(0, $s - $r - 1, $r, $r, 90, 90); $fond.CloseFigure()
    $degrade = New-Object Drawing.Drawing2D.LinearGradientBrush ([Drawing.Point]::new(0, 0)), ([Drawing.Point]::new($s, $s)), (Couleur '#141C2E'), (Couleur '#06090F')
    $g.FillPath($degrade, $fond)
    if ($s -ge 32) { $g.DrawPath((New-Object Drawing.Pen (Couleur '#1E2A3D'), ([Math]::Max(1, $s / 64))), $fond) }

    # Tête de rat stylisée (géométrique), de face, deux yeux en croix. Boîte de 24 unités, mise à l'échelle ($f).
    $f = $s / 24.0
    $ratBrush = New-Object Drawing.Drawing2D.LinearGradientBrush ([Drawing.Point]::new(0, 0)), ([Drawing.Point]::new($s, $s)), (Couleur '#2DD4BF'), (Couleur '#38BDF8')
    function Poly($pairs) {
        $p = New-Object Drawing.Drawing2D.GraphicsPath
        $pf = for ($i = 0; $i -lt $pairs.Count; $i += 2) { [Drawing.PointF]::new($pairs[$i] * $f, $pairs[$i + 1] * $f) }
        $p.AddPolygon([Drawing.PointF[]]$pf); $p
    }

    # Oreilles (triangles) + intérieur
    $g.FillPath($ratBrush, (Poly @(4, 7.5, 10, 7.5, 4.5, 1.5)))
    $g.FillPath($ratBrush, (Poly @(20, 7.5, 14, 7.5, 19.5, 1.5)))
    $ei = New-Object Drawing.SolidBrush (Couleur '#042B27' 128)
    $g.FillPath($ei, (Poly @(5.5, 6.7, 8.6, 6.7, 5.9, 3.2)))
    $g.FillPath($ei, (Poly @(18.5, 6.7, 15.4, 6.7, 18.1, 3.2)))

    # Visage (triangle)
    $g.FillPath($ratBrush, (Poly @(3.5, 7, 20.5, 7, 12, 20.5)))

    # Moustaches (rectangles fins)
    if ($s -ge 24) {
        $pw = New-Object Drawing.Pen (Couleur '#2DD4BF' 170), ([Math]::Max(0.6, 0.55 * $f)); $pw.StartCap = 'Round'; $pw.EndCap = 'Round'
        $g.DrawLine($pw, 10.3 * $f, 16.6 * $f, 6.6 * $f, 16.0 * $f); $g.DrawLine($pw, 10.3 * $f, 17.4 * $f, 7.0 * $f, 17.8 * $f)
        $g.DrawLine($pw, 13.7 * $f, 16.6 * $f, 17.4 * $f, 16.0 * $f); $g.DrawLine($pw, 13.7 * $f, 17.4 * $f, 17.0 * $f, 17.8 * $f)
    }

    # Nez (losange)
    $g.FillPath((New-Object Drawing.SolidBrush (Couleur '#042B27')), (Poly @(12, 15.8, 13, 16.9, 12, 18, 11, 16.9)))

    # Yeux en croix
    $penEye = New-Object Drawing.Pen (Couleur '#042B27'), ([Math]::Max(1.0, 1.35 * $f)); $penEye.StartCap = 'Round'; $penEye.EndCap = 'Round'
    $g.DrawLine($penEye, 7.4 * $f, 9.8 * $f, 9.7 * $f, 11.9 * $f); $g.DrawLine($penEye, 9.7 * $f, 9.8 * $f, 7.4 * $f, 11.9 * $f)
    $g.DrawLine($penEye, 14.3 * $f, 9.8 * $f, 16.6 * $f, 11.9 * $f); $g.DrawLine($penEye, 16.6 * $f, 9.8 * $f, 14.3 * $f, 11.9 * $f)
    $g.Dispose()
    $bmp
}

# Fichier ICO avec des images PNG (accepté par Windows depuis Vista)
$tailles = 256, 128, 64, 48, 32, 24, 20, 16
$images = foreach ($t in $tailles) {
    $b = Dessiner $t; $ms = New-Object IO.MemoryStream; $b.Save($ms, [Drawing.Imaging.ImageFormat]::Png)
    if ($Apercu -and $t -eq 256) { $b.Save($Apercu, [Drawing.Imaging.ImageFormat]::Png) }
    $b.Dispose(); , $ms.ToArray()
}
$f = New-Object IO.MemoryStream; $w = New-Object IO.BinaryWriter $f
$w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$tailles.Count)
$position = 6 + 16 * $tailles.Count
for ($i = 0; $i -lt $tailles.Count; $i++) {
    $t = $tailles[$i]; $octet = if ($t -ge 256) { 0 } else { $t }
    $w.Write([byte]$octet); $w.Write([byte]$octet); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([uint16]1); $w.Write([uint16]32); $w.Write([uint32]$images[$i].Length); $w.Write([uint32]$position)
    $position += $images[$i].Length
}
foreach ($img in $images) { $w.Write($img) }
[IO.File]::WriteAllBytes($Sortie, $f.ToArray())
"Icône écrite : $Sortie ($([int]($f.Length / 1KB)) Ko)"
