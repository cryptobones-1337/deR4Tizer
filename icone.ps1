# Génère src\deR4Tizer.ico : bouclier néon cyan avec décalage magenta (aberration chromatique) et viseur,
# dessiné séparément pour chaque taille afin de rester net en 16 px.
param([string]$Sortie = (Join-Path $PSScriptRoot 'src\deR4Tizer.ico'), [string]$Apercu)
Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'Stop'

function Couleur([string]$hex, [int]$alpha = 255) {
    $c = [Drawing.ColorTranslator]::FromHtml($hex); [Drawing.Color]::FromArgb($alpha, $c)
}

function Bouclier([float]$s, [float]$dx, [float]$dy) {
    # Bouclier : haut plat, flancs droits puis pointe en bas
    $m = $s * 0.20; $l = $s - 2 * $m
    $p = New-Object Drawing.Drawing2D.GraphicsPath
    [Drawing.PointF[]]$pts = @(
        [Drawing.PointF]::new($m + $dx, $m + $l * 0.10 + $dy),
        [Drawing.PointF]::new($s / 2 + $dx, $m + $dy),
        [Drawing.PointF]::new($s - $m + $dx, $m + $l * 0.10 + $dy),
        [Drawing.PointF]::new($s - $m + $dx, $m + $l * 0.52 + $dy),
        [Drawing.PointF]::new($s / 2 + $dx, $s - $m * 0.75 + $dy),
        [Drawing.PointF]::new($m + $dx, $m + $l * 0.52 + $dy))
    $p.AddPolygon($pts)
    $p
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

    $epaisseur = [Math]::Max(1.4, $s / 14)
    $decalage = [Math]::Max(1, $s / 36)
    if ($s -ge 32) {
        # Halo cyan puis copie magenta décalée (effet « glitch »)
        $g.DrawPath((New-Object Drawing.Pen (Couleur '#00E5FF' 45), ($epaisseur * 3.2)), (Bouclier $s 0 0))
        $g.DrawPath((New-Object Drawing.Pen (Couleur '#FF2BD6' 200), $epaisseur), (Bouclier $s $decalage $decalage))
    }
    $g.DrawPath((New-Object Drawing.Pen (Couleur '#00E5FF'), $epaisseur), (Bouclier $s 0 0))

    # Viseur au centre du bouclier
    $cx = $s / 2; $cy = $s * 0.47
    if ($s -ge 24) {
        $rv = $s * 0.13
        $fin = New-Object Drawing.Pen (Couleur '#00E5FF' 230), ([Math]::Max(1, $s / 40))
        $g.DrawEllipse($fin, $cx - $rv, $cy - $rv, 2 * $rv, 2 * $rv)
        $g.DrawLine($fin, $cx - $rv * 1.7, $cy, $cx - $rv * 0.55, $cy); $g.DrawLine($fin, $cx + $rv * 0.55, $cy, $cx + $rv * 1.7, $cy)
        $g.DrawLine($fin, $cx, $cy - $rv * 1.7, $cx, $cy - $rv * 0.55); $g.DrawLine($fin, $cx, $cy + $rv * 0.55, $cx, $cy + $rv * 1.7)
    }
    $rp = [Math]::Max(1.6, $s * 0.055)
    $g.FillEllipse((New-Object Drawing.SolidBrush (Couleur '#FF2BD6')), $cx - $rp, $cy - $rp, 2 * $rp, 2 * $rp)
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
