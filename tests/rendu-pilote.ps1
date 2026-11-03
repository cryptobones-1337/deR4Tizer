# Rendu hors écran de la coquille du pilote WPF (U1, docs/roadmap/interface.md) : compile l'interface, construit la
# coquille sans l'afficher ni la montrer à l'écran (aucune capture d'écran, aucun service, aucune donnée), puis la rend
# en PNG par RenderTargetBitmap à 100, 125 et 150 %, en français et en anglais. Les pages WinForms hébergées ne sont pas
# rendues ainsi (fenêtres Win32) : leur zone reste vide, les captures réelles en VM les montrent (tests\vm\captures.ps1).
# Contrôle aussi les décisions pures du pilote : contrastes des jetons, navigation complète.
# Usage (Windows PowerShell 5.1) : powershell -File tests\rendu-pilote.ps1 [-Depot <racine>] [-Sortie <dossier des PNG>]
param([string]$Depot = (Split-Path $PSScriptRoot), [string]$Sortie = '')
$ErrorActionPreference = 'Stop'
$src = Join-Path $Depot 'src'
$travail = Join-Path $env:TEMP ("d4t-pilote-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $travail | Out-Null
if (-not $Sortie) { $Sortie = Join-Path $travail 'rendus' }
New-Item -ItemType Directory -Force -Path $Sortie | Out-Null
$ko = 0
function Cas([string]$Nom, [bool]$Ok, [string]$Detail = '') {
    if ($Ok) { "RÉUSSI  $Nom" } else { "ÉCHOUÉ  $Nom $Detail"; $script:ko++ }
}
try {
    $out = Join-Path $travail 'interface.exe'
    $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $wpf = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\WPF'
    & $csc /nologo /platform:anycpu /codepage:65001 /target:winexe /r:System.dll /r:System.Core.dll /r:System.Web.Extensions.dll /r:System.ServiceProcess.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll "/r:$wpf\PresentationFramework.dll" "/r:$wpf\PresentationCore.dll" "/r:$wpf\WindowsBase.dll" "/r:$wpf\WindowsFormsIntegration.dll" /r:System.Xaml.dll "/out:$out" "$src\Commun.cs" "$src\Langue.cs" "$src\Theme.cs" "$src\Gui.cs" "$src\Reglages.cs" "$src\Siem.cs" "$src\Incidents.cs" "$src\Reponses.cs" "$src\Trafic.cs" "$src\Reseau.cs" "$src\Fluent.cs" "/resource:$src\carte-pays.txt,carte-pays.txt"
    if ($LASTEXITCODE) { throw 'compilation' }
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms
    $asm = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($out))
    $t = { param($n) $asm.GetType("DeR4Tizer.$n") }
    $jetons = & $t 'Jetons'; $nav = & $t 'NavigationFluent'; $langue = & $t 'L'; $coquille = & $t 'Coquille'

    # Contrastes de la direction visuelle (WCAG : 4,5:1 pour le texte)
    $c = { param($a, $b) $jetons.GetMethod('Contraste').Invoke($null, @($jetons.GetField($a).GetValue($null), $jetons.GetField($b).GetValue($null))) }
    foreach ($paire in @('Texte', 'Fond'), @('Texte', 'Carte'), @('Texte', 'Surface'), @('TexteSecondaire', 'Fond'), @('TexteSecondaire', 'Carte'), @('TexteSurAccent', 'Accent'), @('Danger', 'Fond'), @('Attention', 'Fond'), @('Succes', 'Fond')) {
        $k = & $c $paire[0] $paire[1]
        Cas "contraste $($paire[0]) sur $($paire[1]) : $([math]::Round($k, 2)):1" ($k -ge 4.5)
    }

    # Navigation : Vue d'ensemble en tête, les 19 pages d'aujourd'hui une seule fois, Réponses, Santé, Réglages en bas
    $groupes = $nav.GetMethod('Groupes').Invoke($null, @())
    $cles = @($groupes | ForEach-Object { $_.Entrees } | ForEach-Object { $_.Cle })
    $attendues = "Vue d'ensemble", 'Connexions', 'Trafic', 'Alertes', 'Incidents', 'Événements', 'Détection', 'Réseau local', 'Chaînes', 'Vie privée',
        'Pare-feu', 'Démarrage auto', 'Baseline', 'Extensions', 'Blocages', 'Quarantaine', 'Réponses en cours', 'Menaces', 'Santé', 'Réglages'
    Cas 'navigation : 20 entrées, chacune une fois' ($cles.Count -eq 20 -and @($cles | Sort-Object -Unique).Count -eq 20) ($cles -join ', ')
    Cas 'navigation : toutes les pages d''aujourd''hui présentes' (@($attendues | Where-Object { $cles -notcontains $_ }).Count -eq 0)
    Cas 'navigation : Vue d''ensemble en tête' ($cles[0] -eq "Vue d'ensemble")
    Cas 'navigation : Réponses en cours, Santé, Réglages toujours visibles en bas' ((@($groupes[-1].Entrees | ForEach-Object { $_.Cle }) -join '|') -eq 'Réponses en cours|Santé|Réglages')
    Cas 'navigation : groupes titrés et traduits' ((@($groupes | ForEach-Object { $_.Titre } | Where-Object { $_ }) -join '|') -eq 'Surveillance|Protection|Système et confidentialité')
    $langue.GetField('En').SetValue($null, $true)
    $titresEn = @('Surveillance', 'Protection', 'Système et confidentialité', "Vue d'ensemble") | ForEach-Object { $langue.GetMethod('T').Invoke($null, @([string]$_)) }
    $langue.GetField('En').SetValue($null, $false)
    Cas 'navigation : traductions anglaises' (($titresEn -join '|') -eq 'Monitoring|Protection|System and privacy|Overview') ($titresEn -join '|')

    # L'assistant élevé ne charge pas WPF : Main ne nomme aucun type WPF, le pilote est dans une méthode jamais intégrée
    $g = [IO.File]::ReadAllText("$src\Gui.cs") -replace "`r`n", "`n"
    $main = $g.Substring($g.IndexOf('static int Main(string[] args)'))
    $main = $main.Substring(0, $main.IndexOf("`n        }`n"))
    $nommes = @([regex]::Matches($main, 'System\.Windows\.(Application|Window|Controls|Media)|Coquille|Jetons') | ForEach-Object Value)
    Cas 'assistant élevé : Main ne nomme aucun type WPF' ($nommes.Count -eq 0 -and $main.Contains('if (args.Contains("--fluent")) return LancerPilote();')) "types nommés : $($nommes -join ', ') ; appel du pilote : $($main.Contains('return LancerPilote();'))"
    $programme = $asm.GetType('DeR4Tizer.Programme')
    $lp = $programme.GetMethod('LancerPilote', [Reflection.BindingFlags]'Static,NonPublic')
    Cas 'assistant élevé : pilote dans une méthode jamais intégrée (NoInlining)' ($lp -ne $null -and ($lp.MethodImplementationFlags -band [Reflection.MethodImplAttributes]::NoInlining))
    # Rendu hors écran : coquille construite sans Show(), contenu mesuré, arrangé et rendu
    $sansPage = [Func[string, Windows.Forms.Control]] { param($cle) $null }
    foreach ($code in 'fr', 'en') {
        $langue.GetField('En').SetValue($null, $code -eq 'en')
        foreach ($page in "Vue d'ensemble", 'Connexions') {
            $fen = [Activator]::CreateInstance($coquille, [Reflection.BindingFlags]'Instance,Public,NonPublic', $null, @(, $sansPage), $null)
            $coquille.GetMethod('Ouvrir', [Reflection.BindingFlags]'Instance,NonPublic').Invoke($fen, @($page))
            $ouvertes = $coquille.GetMethod('Ouvertes', [Reflection.BindingFlags]'Instance,NonPublic').Invoke($fen, @())
            Cas "navigation $code : une seule entrée ouverte après « $page »" ($ouvertes -eq 1) "$ouvertes" 
            $contenu = $fen.Content; $fen.Content = $null
            $cadre = New-Object Windows.Controls.Border -Property @{ Background = $fen.Background; Child = $contenu }
            [Windows.Documents.TextElement]::SetFontFamily($cadre, $fen.FontFamily); [Windows.Documents.TextElement]::SetFontSize($cadre, $fen.FontSize)
            [Windows.Documents.TextElement]::SetForeground($cadre, $fen.Foreground)
            foreach ($echelle in 100, 125, 150) {
                $taille = New-Object Windows.Size 1200, 780
                $cadre.Measure($taille); $cadre.Arrange((New-Object Windows.Rect $taille)); $cadre.UpdateLayout()
                $f = $echelle / 100.0
                $bmp = New-Object Windows.Media.Imaging.RenderTargetBitmap ([int](1200 * $f)), ([int](780 * $f)), (96 * $f), (96 * $f), ([Windows.Media.PixelFormats]::Pbgra32)
                $bmp.Render($cadre)
                $enc = New-Object Windows.Media.Imaging.PngBitmapEncoder
                $enc.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bmp))
                $nom = (($page.Normalize([Text.NormalizationForm]::FormD) -replace '\p{Mn}', '') -replace '[^A-Za-z0-9]+', '-').Trim('-').ToLowerInvariant()
                $fichier = Join-Path $Sortie "pilote-$code-$nom-$echelle.png"
                $flux = [IO.File]::Create($fichier); try { $enc.Save($flux) } finally { $flux.Dispose() }
                Cas "rendu $code $page $echelle %" ((Get-Item $fichier).Length -gt 5000) $fichier
            }
            $fen.Close()
        }
    }
    $langue.GetField('En').SetValue($null, $false)
    "Rendus : $Sortie"
} finally {
    if ($Sortie -notlike "$travail*") { Remove-Item $travail -Recurse -Force -ErrorAction SilentlyContinue }
}
if ($ko) { "$ko échec(s)"; exit 1 } else { 'Tous les cas réussis.' }
