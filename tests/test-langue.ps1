# Constat T-17, étape 1 : une seule décision de la langue (L.Choisir, appelée par Programme.ChoisirLangue) pour l'interface
# WPF, l'interface classique, l'assistant élevé et les notifications locales. Compile l'interface, vérifie les décisions
# pures, puis lance un processus par culture (en-US, fr-FR), sans config.json ni réglage de l'utilisateur, qui construit
# chaque surface hors écran et en rend le texte : page Réglages WPF et classique, fenêtre de confirmation de l'assistant
# élevé (langue passée par --langue, culture du compte élevé ignorée), notification locale. Aucune capture d'écran, aucun
# service, aucune écriture dans le profil de l'utilisateur. -Rendus : PNG des surfaces (rendu hors écran).
# Usage (Windows PowerShell 5.1) : powershell -File tests\test-langue.ps1 [-Depot <racine du dépôt>] [-Rendus <dossier des PNG>]
param([string]$Depot = (Split-Path $PSScriptRoot), [string]$Rendus = '')
$ErrorActionPreference = 'Stop'
$src = Join-Path $Depot 'src'
$travail = Join-Path $env:TEMP ("d4t-langue-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $travail | Out-Null
$ko = 0
function Cas([string]$Nom, [bool]$Ok, [string]$Detail = '') {
    if ($Ok) { "RÉUSSI  $Nom" } else { "ÉCHOUÉ  $Nom $Detail"; $script:ko++ }
}
try {
    $out = Join-Path $travail 'interface.exe'
    $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $wpf = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\WPF'
    & $csc /nologo /platform:anycpu /codepage:65001 /target:winexe /r:System.dll /r:System.Core.dll /r:System.Web.Extensions.dll /r:System.ServiceProcess.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll "/r:$wpf\PresentationFramework.dll" "/r:$wpf\PresentationCore.dll" "/r:$wpf\WindowsBase.dll" /r:System.Xaml.dll "/out:$out" "$src\Commun.cs" "$src\Langue.cs" "$src\Theme.cs" "$src\Gui.cs" "$src\Reglages.cs" "$src\Siem.cs" "$src\Incidents.cs" "$src\Reponses.cs" "$src\Trafic.cs" "$src\Reseau.cs" "$src\Fluent.cs" "/resource:$src\carte-pays.txt,carte-pays.txt" "/resource:$src\deR4Tizer.ico,deR4Tizer.ico" | Out-Null
    if ($LASTEXITCODE) { throw 'compilation' }
    $asm = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($out))
    $t = { param($n) $asm.GetType("DeR4Tizer.$n") }
    $langue = & $t 'L'
    $fr = [Globalization.CultureInfo]::GetCultureInfo('fr-FR'); $us = [Globalization.CultureInfo]::GetCultureInfo('en-US')
    $frCa = [Globalization.CultureInfo]::GetCultureInfo('fr-CA'); $de = [Globalization.CultureInfo]::GetCultureInfo('de-DE')

    # ---------------------------------------------------------------- décision pure : L.Choisir
    $choisir = $langue.GetMethod('Choisir')
    $ch = { param($argument, $utilisateur, $config, $culture) $p = [object[]]@($argument, $utilisateur, $config, $culture, $null); $en = $choisir.Invoke($null, $p); "$(if ($en) { 'en' } else { 'fr' })/$($p[4])" }
    Cas 'sans réglage ni config.json : culture en-US → anglais, réglage « auto »' ((& $ch $null $null $null $us) -eq 'en/auto') (& $ch $null $null $null $us)
    Cas 'sans réglage ni config.json : culture fr-FR → français' ((& $ch $null $null $null $fr) -eq 'fr/auto') (& $ch $null $null $null $fr)
    Cas 'sans réglage : toute culture française (fr-CA) → français, toute autre (de-DE) → anglais' ((& $ch $null $null $null $frCa) -eq 'fr/auto' -and (& $ch $null $null $null $de) -eq 'en/auto')
    # Défaut d'avant T-17 : « fr » que le service écrit par défaut dans config.json imposait le français à un Windows anglais
    Cas 'config.json « fr » (valeur par défaut du service) ne dit pas un choix : culture en-US → anglais' ((& $ch $null $null 'fr' $us) -eq 'en/auto') (& $ch $null $null 'fr' $us)
    Cas 'config.json « en » (choix d''une version précédente) gardé sans réglage de l''utilisateur' ((& $ch $null $null 'en' $fr) -eq 'en/en') (& $ch $null $null 'en' $fr)
    Cas 'réglage de l''utilisateur prioritaire sur config.json et la culture (fr, en, auto)' ((& $ch $null 'fr' 'en' $us) -eq 'fr/fr' -and (& $ch $null 'en' $null $fr) -eq 'en/en' -and (& $ch $null 'auto' 'en' $fr) -eq 'fr/auto')
    Cas 'réglage hors liste ignoré (« EN », « de », vide)' ((& $ch $null 'EN' $null $fr) -eq 'fr/auto' -and (& $ch $null 'de' $null $us) -eq 'en/auto' -and (& $ch $null '' $null $fr) -eq 'fr/auto')
    Cas 'langue passée à l''assistant élevé prioritaire sur la culture du compte élevé' ((& $ch 'en' $null $null $fr).StartsWith('en/') -and (& $ch 'fr' $null 'en' $us).StartsWith('fr/'))
    Cas 'langue passée hors liste ignorée (« EN », « fr-FR », « x »)' ((& $ch 'EN' $null $null $fr).StartsWith('fr/') -and (& $ch 'fr-FR' $null $null $us).StartsWith('en/') -and (& $ch 'x' $null $null $us).StartsWith('en/'))

    # ---------------------------------------------------------------- fichier du réglage par utilisateur
    $chemin = [string](Join-Path $travail 'profil\deR4Tizer\langue.txt')
    $ecrire = $langue.GetMethod('EcrireReglage'); $lire = $langue.GetMethod('LireReglage')
    Cas 'réglage absent : null' ($null -eq $lire.Invoke($null, @($chemin)))
    Cas 'réglage jamais écrit en administrateur (dossier contrôlé par le compte non élevé, S151-01)' (-not $ecrire.Invoke($null, @($chemin, 'en', $true)) -and -not (Test-Path $chemin))
    Cas 'valeur hors liste jamais écrite' (-not $ecrire.Invoke($null, @($chemin, 'de', $false)) -and -not (Test-Path $chemin))
    $okE = $ecrire.Invoke($null, @($chemin, 'en', $false))
    Cas 'réglage écrit sans élévation et relu' ($okE -and $lire.Invoke($null, @($chemin)) -eq 'en')
    [IO.File]::WriteAllText($chemin, "en`r`n"); $l1 = $lire.Invoke($null, @($chemin))
    [IO.File]::WriteAllText($chemin, 'english'); $l2 = $lire.Invoke($null, @($chemin))
    [IO.File]::WriteAllText($chemin, ('a' * 100)); $l3 = $lire.Invoke($null, @($chemin))
    Cas 'réglage relu : espaces tolérés, autre valeur ou fichier trop long → null' ($l1 -eq 'en' -and $null -eq $l2 -and $null -eq $l3) "$l1|$l2|$l3"
    # Audit de #298, A298-1 : 64 octets au plus, lus sur un seul handle ; point de reparse et dossier refusés
    [IO.File]::WriteAllText($chemin, 'fr' + (' ' * 62)); $l4 = $lire.Invoke($null, @($chemin))
    [IO.File]::WriteAllText($chemin, 'fr' + (' ' * 63)); $l5 = $lire.Invoke($null, @($chemin))
    Cas 'réglage de 64 octets lu, de 65 octets refusé' ($l4 -eq 'fr' -and $null -eq $l5) "$l4|$l5"
    $profilTest = Split-Path $chemin
    $cibleJ = Join-Path $travail 'cible-jonction'; New-Item -ItemType Directory -Path $cibleJ | Out-Null
    Remove-Item $chemin -Force
    cmd.exe /c mklink /J "$chemin" "$cibleJ" | Out-Null
    $estReparse = (Test-Path $chemin) -and (([IO.File]::GetAttributes($chemin) -band [IO.FileAttributes]::ReparsePoint) -ne 0)
    $l6 = $lire.Invoke($null, @($chemin))
    cmd.exe /c rmdir "$chemin" | Out-Null
    Cas 'réglage : point de reparse (jonction nommée langue.txt) refusé sans être suivi' ($estReparse -and $null -eq $l6) "$estReparse|$l6"
    New-Item -ItemType Directory -Path $chemin | Out-Null; $l7 = $lire.Invoke($null, @($chemin)); Remove-Item $chemin -Force
    # Lien symbolique de fichier vers un fichier qui porte « en » : jamais suivi (création possible en mode développeur ou
    # en administrateur ; sinon cas non exécuté, dit)
    $cibleL = Join-Path $travail 'cible-lien.txt'; [IO.File]::WriteAllText($cibleL, 'en')
    # mklink : Windows PowerShell 5.1 (New-Item) n'emploie pas le droit du mode développeur
    cmd.exe /c mklink "$chemin" "$cibleL" 2>&1 | Out-Null
    $lienOk = (Test-Path $chemin) -and (([IO.File]::GetAttributes($chemin) -band [IO.FileAttributes]::ReparsePoint) -ne 0)
    if ($lienOk) { $l8 = $lire.Invoke($null, @($chemin)); Remove-Item $chemin -Force; Cas 'réglage : lien symbolique vers un fichier « en » jamais suivi' ($null -eq $l8) "$l8" }
    else { 'NON EXÉCUTÉ  réglage : lien symbolique de fichier (création refusée : ni mode développeur ni administrateur)' }
    Cas 'réglage : dossier nommé langue.txt refusé' ($null -eq $l7)
    $lSrc = [IO.File]::ReadAllText((Join-Path $src 'Langue.cs')); $lSrc = $lSrc.Substring($lSrc.IndexOf('public static string LireReglage('), 1500)
    Cas 'réglage : ouvert une fois sans suivre de point de reparse, jamais relu par chemin' ($lSrc.Contains('0x00200000') -and $lSrc.Contains('GetFileInformationByHandle(h, out info)') -and $lSrc.Contains('(info.Attributs & 0x410) != 0') -and $lSrc.Contains('new byte[65]') -and -not $lSrc.Contains('ReadAllText') -and -not $lSrc.Contains('FileInfo('))
    # Sous jeton administrateur (interface élevée), langue.txt n'est pas lu : --langue, sinon config.json et culture
    [IO.File]::WriteAllText($chemin, 'fr')
    $prog = & $t 'Programme'; $cl = $prog.GetMethod('ChoisirLangue', [Reflection.BindingFlags]'Static,NonPublic')
    $aucun = [string[]]::new(0)
    $cl.Invoke($null, [object[]]@($aucun, $null, $chemin, $us, $true)); $adm = "$($langue.GetField('En').GetValue($null))/$($langue.GetField('Reglage').GetValue($null))"
    $cl.Invoke($null, [object[]]@($aucun, $null, $chemin, $us, $false)); $std = "$($langue.GetField('En').GetValue($null))/$($langue.GetField('Reglage').GetValue($null))"
    $langue.GetField('En').SetValue($null, $false); $langue.GetField('Reglage').SetValue($null, 'auto')
    Cas 'interface élevée : langue.txt jamais lu (culture en-US → anglais) ; sans élévation, « fr » lu' ($adm -eq 'True/auto' -and $std -eq 'False/fr') "$adm|$std"
    # Audit de #298, A298-2 : --dossier n'est jamais une option de l'assistant élevé
    $dd = $prog.GetMethod('DossierDemande', [Reflection.BindingFlags]'Static,NonPublic')
    # Lecteurs du labo : C fixe, Z « réseau » (non fixe) ; jamais le vrai type des lecteurs du poste
    $fixe = [Func[char, bool]] { param($l) $l -eq [char]'C' }
    $dos = { param([string[]]$a, [bool]$adm = $false) $dd.Invoke($null, [object[]]@($a, $adm, $fixe)) }
    Cas 'assistant élevé : « --dossier » parmi ses arguments ignoré ; interface : --dossier appliqué' ($null -eq (& $dos @('--commande-fichier', '--dossier', '--langue', 'en')) -and $null -eq (& $dos @('--commande-fichier', 'x.json', '--langue', '--dossier')) -and $null -eq (& $dos @('--commande-fichier', '--dossier')) -and (& $dos @('--dossier', 'C:\essai')) -eq 'C:\essai' -and (& $dos @('--cache', '--dossier', 'C:\essai')) -eq 'C:\essai' -and $null -eq (& $dos @('--dossier')))
    # Audit de #298, A298-3 : sous jeton administrateur, --dossier jamais appliqué (dossier de données normal), même local
    Cas 'interface élevée : --dossier jamais appliqué, même sur un disque local fixe (A298-3)' ($null -eq (& $dos @('--dossier', 'C:\essai') $true) -and $null -eq (& $dos @('--cache', '--dossier', 'C:\essai') $true) -and $null -eq (& $dos @('--dossier', '\\hote\partage') $true) -and (& $dos @('--dossier', 'C:\essai') $false) -eq 'C:\essai')
    # A298-3 : critère de A-1-1 / A-5-2 (Canal.CheminLocalFixeTexte), jugé sur le texte avant tout accès disque
    $refuses = @('\\hote\partage', '\\hote@SSL\DavWWWRoot\d', '\\?\UNC\hote\p', '\\.\pipe\x', '\\?\C:\essai', 'Z:\essai', 'C:essai', 'C:/essai', 'C:\a\..\b', 'C:\a:flux', '//hote/partage', 'essai', '')
    $acceptes = @(foreach ($r in $refuses) { if ($null -ne (& $dos @('--dossier', $r))) { $r } })
    Cas 'interface : --dossier hors disque local fixe refusé (UNC, WebDAV, \\?\, lecteur non fixe, relatif, « .. », flux) (A298-3)' ($acceptes.Count -eq 0) ($acceptes -join ' | ')
    $gSrc = [IO.File]::ReadAllText((Join-Path $src 'Gui.cs'))
    $dSrc = $gSrc.Substring($gSrc.IndexOf('internal static string DossierDemande('), 700)
    Cas 'DossierDemande : réutilise Canal.CheminLocalFixeTexte, aucune copie du critère (A298-3)' ($dSrc.Contains('Canal.CheminLocalFixeTexte(') -and -not $dSrc.Contains('DriveType') -and -not $dSrc.Contains('StartsWith("\\\\'))
    Cas 'Main : Commun.Dossier posé par DossierDemande seulement, avec le jeton et le type de lecteur réels' ($gSrc.Contains('string dossierDemande = DossierDemande(args, Canal.EstAdmin(), Canal.LecteurFixe);') -and $gSrc.Contains('if (dossierDemande != null) Commun.Dossier = dossierDemande;') -and -not $gSrc.Contains('Commun.Dossier = args['))
    # --dossier refusé : instance ordinaire (mutex commun), jamais une seconde interface parallèle sur le dossier normal
    Cas 'Main : mutex et écoute décidés par le dossier appliqué, plus par la seule présence de « --dossier » (A298-3)' (-not $gSrc.Substring($gSrc.IndexOf('static int Main(string[] args)')).Contains('Array.IndexOf(args, "--dossier")') -and -not ($gSrc -match 'if \(i < 0\) Ecouter') -and -not $gSrc.Contains('Array.IndexOf(Environment.GetCommandLineArgs(), "--dossier")') -and $gSrc.Contains('new Mutex(true, dossierDeTest ? "deR4Tizer.Interface." + Guid.NewGuid() : "deR4Tizer.Interface", out premier)'))

    # ---------------------------------------------------------------- ce que la page Réglages dit
    $langue.GetField('En').SetValue($null, $true)
    $libAuto = [string]$langue.GetMethod('Libelle').Invoke($null, @('auto', $us))
    $etat = $langue.GetMethod('EtatReglage')
    $e1 = [string]$etat.Invoke($null, @('auto', $null, $false, $us)); $e2 = [string]$etat.Invoke($null, @('auto', 'fr', $false, $us)); $e3 = [string]$etat.Invoke($null, @('auto', 'auto', $true, $us))
    $langue.GetField('En').SetValue($null, $false)
    $libAutoFr = [string]$langue.GetMethod('Libelle').Invoke($null, @('auto', $fr))
    Cas 'libellé « automatique » : dit la langue qu''il donne sur ce poste' ($libAuto -eq 'Automatic (Windows: English)' -and $libAutoFr -eq 'Automatique (Windows : Français)') "$libAuto|$libAutoFr"
    Cas 'page Réglages : langue affichée toujours dite ; choix en attente dit à part avec le moment où il s''applique ; refus en administrateur dit' ($e1 -eq 'Displayed language: English.' -and $e2.StartsWith('Displayed language: English. Choice saved: Français, applied the next time the interface starts') -and $e3.Contains('only be changed from the interface run without administrator rights') -and -not $e3.Contains('Choice saved')) "$e1|$e2|$e3"

    # ---------------------------------------------------------------- pare-feu : résultat du contrôle, jamais « not found »
    $vpf = & $t 'VueParefeuFluent'; $ceT = & $t 'ConstatExposition'
    $constat = [Activator]::CreateInstance($ceT); $constat.Piste = 'parefeu'; $constat.Etat = 'pas_constate'; $constat.Texte = 'pare-feu de Windows actif'
    $langue.GetField('En').SetValue($null, $true)
    $etEn = [string]$vpf.GetMethod('Etat').Invoke($null, @($constat)); $nomEn = [string]$vpf.GetMethod('NomPiste').Invoke($null, @('parefeu'))
    $langue.GetField('En').SetValue($null, $false)
    $etFr = [string]$vpf.GetMethod('Etat').Invoke($null, @($constat))
    Cas 'Pare-feu : pare-feu actif (« pas_constate ») dit « no issue found » / « rien relevé », jamais « not found »' ($nomEn -eq 'Windows Firewall' -and $etEn -eq 'no issue found' -and $etFr -eq 'rien relevé') "$nomEn : $etEn | $etFr"

    # ---------------------------------------------------------------- sources : une seule décision, langue passée à l'assistant
    $tous = (Get-ChildItem (Join-Path $src '*.cs') | ForEach-Object { [IO.File]::ReadAllText($_.FullName) }) -join "`n"
    $g = [IO.File]::ReadAllText((Join-Path $src 'Gui.cs')); $fl = [IO.File]::ReadAllText((Join-Path $src 'Fluent.cs')); $rg = [IO.File]::ReadAllText((Join-Path $src 'Reglages.cs'))
    Cas 'une seule affectation de L.En dans l''interface (Programme.ChoisirLangue)' (([regex]::Matches($tous, '\bL\.En\s*=[^=]')).Count -eq 1 -and $g.Contains('L.En = L.Choisir(')) "$(([regex]::Matches($tous, '\bL\.En\s*=[^=]')).Count)"
    Cas 'culture de Windows lue par L.CultureAnglaise seulement' (([regex]::Matches($tous, 'TwoLetterISOLanguageName')).Count -eq 1)
    Cas 'Main : langue choisie avant l''assistant élevé et avant toute fenêtre, réglage jamais lu sous jeton administrateur' ($g.IndexOf('ChoisirLangue(args, cfg, L.CheminReglage(), System.Globalization.CultureInfo.CurrentUICulture, Canal.EstAdmin());') -ge 0 -and $g.IndexOf('ChoisirLangue(args, cfg,') -lt $g.IndexOf('Commande c;'))
    Cas 'assistant élevé lancé avec la langue de l''interface (--langue)' ($g.Contains('"--commande-fichier \"" + fichier + "\" --langue " + (L.En ? "en" : "fr")'))
    Cas 'pages Réglages : bouton actif = réglage en vigueur, jamais la langue de config.json ; la langue ne part plus avec les réglages' (-not ($fl -match '[xc]\.Langue\b') -and -not ($rg -match 'config\.Langue|anglais \? "en"') -and $fl.Contains('langue.Definir(L.Reglage, ActionsReglages.LangueEnregistree());') -and $rg.Contains('return Canal.EstAdmin() ? null : L.LireReglage(L.CheminReglage());') -and ([regex]::Matches($tous, 'L\.LireReglage\(')).Count -eq 2 -and $rg.Contains('cbLangue.SelectedIndex = Math.Max(0, Array.IndexOf(L.Reglages, L.Reglage));'))

    # Niveaux d'incident, d'événement et de détection (codes « Critique », « Alerte », « Info ») : traduits comme ceux des alertes
    $inc = [IO.File]::ReadAllText((Join-Path $src 'Incidents.cs')); $siem = [IO.File]::ReadAllText((Join-Path $src 'Siem.cs')); $res = [IO.File]::ReadAllText((Join-Path $src 'Reseau.cs'))
    $bruts = @(foreach ($m in [regex]::Matches($fl + $inc + $siem + $res + $g, '(Canal\.Visible\(|\bv\(|new\[\] \{ [a-z]\.Heure, |a\.Heure, )[a-z]\.Niveau\b')) { $m.Value })
    Cas 'niveaux affichés par L.T (incidents, mini-SIEM, IDS, liste classique des alertes), jamais bruts' ($bruts.Count -eq 0 -and $fl.Contains('Canal.Visible(L.T(x.Niveau))') -and ([regex]::Matches($inc, 'L\.T\([ia]\.Niveau\)')).Count -eq 3 -and ([regex]::Matches($siem, 'L\.T\([ie]\.Niveau\)')).Count -eq 3 -and $res.Contains('L.T(d.Niveau)') -and $g.Contains('L.T(a.Niveau).ToUpperInvariant()')) ($bruts -join ' | ')
    $langue.GetField('En').SetValue($null, $true)
    $niv = @('Critique', 'Alerte', 'Info') | ForEach-Object { [string]$langue.GetMethod('T').Invoke($null, @([string]$_)) }
    $langue.GetField('En').SetValue($null, $false)
    Cas 'niveaux au dictionnaire : Critical, Alert, Info' (($niv -join '|') -eq 'Critical|Alert|Info') ($niv -join '|')

    # Prérelecture de #298, D3 : langue de config.json renvoyée normalisée (« en » gardé, le reste « fr »)
    $ar = & $t 'ActionsReglages'; $cfgT = & $t 'Config'
    $norm = foreach ($v in 'en', 'fr', $null, '', 'EN', 'de') { $c0 = [Activator]::CreateInstance($cfgT); $c0.Langue = $v; $r0 = $ar.GetMethod('Composer').Invoke($null, [object[]]@($c0, $null, $null)); [string]$r0.Langue }
    Cas 'Composer : langue « en » gardée, null, vide, « EN » ou autre ramené à « fr » (refusé sinon par le service)' (($norm -join '|') -eq 'en|fr|fr|fr|fr|fr') ($norm -join '|')
    # D2 : confirmation de « reglages » : la langue de config.json dite gardée, sans effet sur l'affichage
    $canalT = & $t 'Canal'; $cmdR = [Activator]::CreateInstance((& $t 'Commande')); $cmdR.Action = 'reglages'; $cmdR.Valeur = '{"Langue":"fr","Syslog":{"Actif":false,"Hote":"","Port":514,"Protocole":"UDP","Format":"JSON","NiveauMin":"Alerte"},"Api":{"Actif":false,"Port":8642,"Reseau":false,"Adresses":""}}'
    $langue.GetField('En').SetValue($null, $true); $dEn = [string]$canalT.GetMethod('Decrire').Invoke($null, @($cmdR))
    $langue.GetField('En').SetValue($null, $false); $dFr = [string]$canalT.GetMethod('Decrire').Invoke($null, @($cmdR))
    Cas 'confirmation des réglages : langue de config.json dite gardée, sans effet sur la langue affichée' ($dEn.Contains('language kept in config.json (no effect on the displayed language): fr') -and $dFr.Contains('langue gardée dans config.json (sans effet sur la langue affichée) : fr')) "$dEn | $dFr"
    # D4 : liste classique enregistrée à la validation seulement
    Cas 'interface classique : choix de langue écrit à la validation (liste refermée, sortie, Entrée), jamais à chaque changement de sélection' (-not $rg.Contains('cbLangue.SelectedIndexChanged += (s, e) => ChoisirLangue();') -and $rg.Contains('cbLangue.SelectedIndexChanged += (s, e) => { if (!langueEnCours) langueModifiee = true; };') -and $rg.Contains('cbLangue.DropDownClosed +=') -and $rg.Contains('cbLangue.Leave += (s, e) => ChoisirLangue();') -and $rg.Contains('if (langueEnCours || !langueModifiee || cbLangue.SelectedIndex < 0) return;'))

    # ---------------------------------------------------------------- un processus par culture : chaque surface
    $sonde = Join-Path $travail 'sonde-langue.ps1'
    $donnees = Join-Path $travail 'donnees'; New-Item -ItemType Directory -Path $donnees | Out-Null
    [IO.File]::WriteAllText($sonde, @'
param([string]$Exe, [string]$Culture, [string]$Arguments = '', [string]$Dossier, [string]$Rendus = '', [string]$Nom = '')
$ErrorActionPreference = 'Stop'
# « aucun » : valeur vide (un argument vide ne passe pas la ligne de commande de powershell.exe)
if ($Arguments -eq 'aucun') { $Arguments = '' }; if ($Rendus -eq 'aucun') { $Rendus = '' }
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms, System.Drawing
[Threading.Thread]::CurrentThread.CurrentUICulture = [Globalization.CultureInfo]::GetCultureInfo($Culture)
$asm = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($Exe))
$t = { param($n) $asm.GetType("DeR4Tizer.$n") }
$sp = [Reflection.BindingFlags]'Static,NonPublic,Public'; $ip = [Reflection.BindingFlags]'Instance,NonPublic,Public'
$commun = & $t 'Commun'; $langue = & $t 'L'
$commun.GetField('Dossier').SetValue($null, $Dossier)
if (Test-Path (Join-Path $Dossier 'config.json')) { throw 'config.json présent' }
$arg = [string[]]::new(0); if ($Arguments) { $arg = [string[]]($Arguments.Split('|')) }
# Réglage de l'utilisateur absent (fichier inexistant du dossier de test) ; config.json absent : null
(& $t 'Programme').GetMethod('ChoisirLangue', $sp).Invoke($null, [object[]]@($arg, $null, ([string](Join-Path $Dossier 'langue-absente.txt')), [Globalization.CultureInfo]::CurrentUICulture, $false))
$en = [bool]$langue.GetField('En').GetValue($null)
"EN=$en"; "REGLAGE=$($langue.GetField('Reglage').GetValue($null))"
function Png($fichier) { if ($Rendus) { Join-Path $Rendus "$Nom-$fichier.png" } }
if ($Rendus) {
Add-Type -ReferencedAssemblies System.Windows.Forms, System.Drawing -TypeDefinition @"
using System; using System.Drawing; using System.Runtime.InteropServices; using System.Windows.Forms;
public static class RenduLangueT17
{
    [StructLayout(LayoutKind.Sequential)] struct Rect { public int G, H, D, B; }
    [StructLayout(LayoutKind.Sequential)] struct Plage { public int Min, Max; }
    [StructLayout(LayoutKind.Sequential)] struct Format { public IntPtr Dc, DcCible; public Rect Zone, Page; public Plage Car; }
    [DllImport("user32.dll")] static extern IntPtr SendMessage(IntPtr h, int m, IntPtr w, ref Format f);
    [DllImport("user32.dll")] static extern IntPtr SendMessage(IntPtr h, int m, IntPtr w, IntPtr l);
    static Point Position(Control c, Form f) { var p = Point.Empty; for (var x = c; x != null && x != f; x = x.Parent) p.Offset(x.Location); return p; }
    static void Dessiner(Control c, Bitmap bmp, int x, int y)
    {
        var r = new Rectangle(x + c.Left, y + c.Top, c.Width, c.Height);
        if (r.Width <= 0 || r.Height <= 0 || r.Right > bmp.Width || r.Bottom > bmp.Height) return;
        c.DrawToBitmap(bmp, r);
        // Liste déroulante jamais montrée : DrawToBitmap la laisse vide ; son texte réel (élément choisi) est écrit dessus
        if (c is ComboBox) using (var g = Graphics.FromImage(bmp)) TextRenderer.DrawText(g, c.Text, c.Font, new Rectangle(r.X + 4, r.Y + 3, r.Width - 24, r.Height - 4), c.ForeColor, TextFormatFlags.Left);
        foreach (Control e in c.Controls) Dessiner(e, bmp, x + c.Left, y + c.Top);
    }
    // Contrôle WinForms jamais montré : chaque contrôle visible dessiné à sa place, puis ses enfants
    public static Bitmap RendreControle(Control c, int largeur, int hauteur)
    {
        var grand = new Bitmap(1600, 8000);
        using (var g = Graphics.FromImage(grand)) g.Clear(c.BackColor);
        foreach (Control e in c.Controls) if (e.Visible) Dessiner(e, grand, 0, 0);
        var bmp = grand.Clone(new Rectangle(0, 0, largeur, hauteur), grand.PixelFormat);
        grand.Dispose();
        return bmp;
    }
    // Barre de titre simulée (titre réel de la fenêtre) ; zone de texte par EM_FORMATRANGE, comme tests\test-confirmations.ps1
    public static Bitmap Rendre(Form f)
    {
        const int barre = 32;
        var cs = f.ClientSize;
        var bmp = new Bitmap(cs.Width + 2, cs.Height + barre + 1);
        using (var g = Graphics.FromImage(bmp))
        {
g.Clear(f.BackColor);
using (var b = new SolidBrush(Color.FromArgb(0x14, 0x15, 0x18))) g.FillRectangle(b, 0, 0, bmp.Width, barre);
using (var p = new Font("Segoe UI", 9f)) TextRenderer.DrawText(g, f.Text, p, new Point(12, 8), Color.FromArgb(0xE6, 0xE8, 0xEB));
        }
        foreach (Control c in f.Controls) Dessiner(c, bmp, 1, barre);
        var zone = (RichTextBox)f.Controls.Find("Texte", true)[0];
        var o = Position(zone, f);
        using (var g = Graphics.FromImage(bmp))
        {
IntPtr dc = g.GetHdc();
try
{
    int x = o.X + 1, y = o.Y + barre, w = zone.ClientSize.Width, h = zone.ClientSize.Height;
    var fr = new Format { Dc = dc, DcCible = dc, Car = new Plage { Min = 0, Max = -1 } };
    fr.Zone = new Rect { G = x * 15, H = y * 15, D = (x + w) * 15, B = (y + h) * 15 };
    fr.Page = new Rect { G = 0, H = 0, D = bmp.Width * 15, B = bmp.Height * 15 };
    SendMessage(zone.Handle, 0x0439, (IntPtr)1, ref fr);
    SendMessage(zone.Handle, 0x0439, IntPtr.Zero, IntPtr.Zero);
}
finally { g.ReleaseHdc(dc); }
        }
        return bmp;
    }
}
"@
}
if ($arg.Count -gt 0) {
    # Assistant élevé : fenêtre de confirmation construite comme dans Main, jamais montrée
    $canal = & $t 'Canal'; $c = [Activator]::CreateInstance((& $t 'Commande')); $c.Action = 'bloquer'; $c.Cible = ''; $c.NomDns = 'tracker.example.net'
    $titre = [string]$canal.GetMethod('TitreConfirmation').Invoke($null, @($c, $en)); $texte = [string]$canal.GetMethod('Decrire').Invoke($null, @($c))
    "ASSISTANT_TITRE=$titre"; "ASSISTANT_TEXTE=$(($texte -split "`n")[0])"
    $f = $canal.GetMethod('FenetreConfirmation').Invoke($null, [object[]]@($titre, $texte, $en, $false))
    try {
        "ASSISTANT_FENETRE=$($f.Text)|$(($f.Controls.Find('Continuer', $true)[0]).Text)|$(($f.Controls.Find('Annuler', $true) | Select-Object -First 1).Text)"
        if ($Rendus) {
            $img = [RenduLangueT17]::Rendre($f); $img.Save((Png 'assistant'), [Drawing.Imaging.ImageFormat]::Png); $img.Dispose()
        }
    } finally { $f.Dispose() }
    return
}
# Interface WPF : coquille construite sans Show(), page Réglages ouverte
$coq = & $t 'Coquille'; $pr = & $t 'PageReglagesFluent'
$fen = [Activator]::CreateInstance($coq, $ip, $null, [object[]]@(), $null)
$coq.GetMethod('Ouvrir', $ip).Invoke($fen, @('Réglages'))
$page = $coq.GetField('zone', $ip).GetValue($fen).Content
$choix = $pr.GetField('langue', $ip).GetValue($page)
$actif = @($choix.Children | Where-Object { [string]$_.Tag -eq $choix.Valeur })[0]
"WPF_ACTIF=$($choix.Valeur)|$($actif.Content)"; "WPF_ETAT=$($pr.GetField('langueEtat', $ip).GetValue($page).Text)"
"WPF_NAVIGATION=$($langue.GetMethod('T').Invoke($null, @('Surveillance')))"
if ($Rendus) {
    $contenu = $fen.Content; $fen.Content = $null
    $cadre = New-Object Windows.Controls.Border -Property @{ Background = $fen.Background; Child = $contenu }
    [Windows.Documents.TextElement]::SetFontFamily($cadre, $fen.FontFamily); [Windows.Documents.TextElement]::SetFontSize($cadre, $fen.FontSize)
    [Windows.Documents.TextElement]::SetForeground($cadre, $fen.Foreground)
    $taille = New-Object Windows.Size 1200, 560
    $cadre.Measure($taille); $cadre.Arrange((New-Object Windows.Rect $taille)); $cadre.UpdateLayout()
    $bmp = New-Object Windows.Media.Imaging.RenderTargetBitmap 1200, 560, 96, 96, ([Windows.Media.PixelFormats]::Pbgra32)
    $bmp.Render($cadre)
    $enc = New-Object Windows.Media.Imaging.PngBitmapEncoder; $enc.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bmp))
    $flux = [IO.File]::Create((Png 'wpf-reglages')); try { $enc.Save($flux) } finally { $flux.Dispose() }
}
$fen.Close()
# Interface classique : page Réglages WinForms
$pcT = & $t 'PageReglages'
$pc = [Activator]::CreateInstance($pcT, $ip, $null, [object[]]@(), $null)
"CLASSIQUE_ACTIF=$($pcT.GetField('cbLangue', $ip).GetValue($pc).SelectedItem)"; "CLASSIQUE_ETAT=$($pcT.GetField('lblLangue', $ip).GetValue($pc).Text)"
if ($Rendus) {
    $pc.Visible = $true; $pc.Size = New-Object Drawing.Size 1000, 700; $pc.CreateControl(); $pc.PerformLayout(); $pc.Controls[0].PerformLayout()
    $bmp = [RenduLangueT17]::RendreControle($pc, 1000, 260)
    $bmp.Save((Png 'classique-reglages'), [Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
}
# Notifications locales : deux alertes critiques, et bulle de l'icône près de l'horloge
$alT = & $t 'Alerte'; $l = [Activator]::CreateInstance([Collections.Generic.List`1].MakeGenericType($alT))
foreach ($i in 1, 2) { $a = [Activator]::CreateInstance($alT); $a.Niveau = 'Critique'; $a.Processus = 'x.exe'; $a.Destination = 'd'; $a.Raisons = 'r'; $l.Add($a) }
$fenT = & $t 'Fenetre'
$n = $fenT.GetMethod('TexteNotification', $sp).Invoke($null, [object[]]@(,$l))
"NOTIF=$($n[0])|$($n[1])"; "ICONE=$($fenT.GetMethod('TexteIcone', $sp).Invoke($null, @([int]2)))"
'@, (New-Object Text.UTF8Encoding $true))
    if ($Rendus) { New-Item -ItemType Directory -Force -Path $Rendus | Out-Null }
    $lancer = { param($culture, $arguments, $nom)
        $r = @{}; $ErrorActionPreference = 'Continue'
        $sortie = & powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File $sonde -Exe $out -Culture $culture -Arguments $(if ($arguments) { $arguments } else { 'aucun' }) -Dossier $donnees -Rendus $(if ($Rendus) { $Rendus } else { 'aucun' }) -Nom $nom 2>&1
        foreach ($ligne in $sortie) { $s = [string]$ligne; $k = $s.IndexOf('='); if ($k -gt 0) { $r[$s.Substring(0, $k)] = $s.Substring($k + 1) } else { $r['AUTRE'] += "$s " } }
        $r
    }
    $u = & $lancer 'en-US' '' 'apres-en'
    Cas 'en-US, sans config.json : interface en anglais, réglage « auto »' ($u.EN -eq 'True' -and $u.REGLAGE -eq 'auto') "$($u.EN) $($u.REGLAGE) $($u.AUTRE)"
    Cas 'en-US : WPF, bouton actif « Automatic (Windows: English) » (la langue affichée), langue affichée dite, navigation en anglais' ($u.WPF_ACTIF -eq 'auto|Automatic (Windows: English)' -and $u.WPF_ETAT -eq 'Displayed language: English.' -and $u.WPF_NAVIGATION -eq 'Monitoring') "$($u.WPF_ACTIF) | $($u.WPF_ETAT) | $($u.WPF_NAVIGATION)"
    Cas 'en-US : interface classique, élément choisi et langue affichée en anglais' ($u.CLASSIQUE_ACTIF -eq 'Automatic (Windows: English)' -and $u.CLASSIQUE_ETAT -eq 'Displayed language: English.') "$($u.CLASSIQUE_ACTIF) | $($u.CLASSIQUE_ETAT)"
    Cas 'en-US : notification locale et bulle de l''icône en anglais' ($u.NOTIF -eq 'Critical: deR4Tizer|2 new alerts' -and $u.ICONE -eq 'deR4Tizer: 2 unread alert(s)') "$($u.NOTIF) | $($u.ICONE) $($u.AUTRE)"
    $f = & $lancer 'fr-FR' '' 'apres-fr'
    Cas 'fr-FR, sans config.json : interface en français, réglage « auto »' ($f.EN -eq 'False' -and $f.REGLAGE -eq 'auto') "$($f.EN) $($f.REGLAGE) $($f.AUTRE)"
    Cas 'fr-FR : WPF, bouton actif « Automatique (Windows : Français) », langue affichée dite, navigation en français' ($f.WPF_ACTIF -eq 'auto|Automatique (Windows : Français)' -and $f.WPF_ETAT -eq 'Langue affichée : français.' -and $f.WPF_NAVIGATION -eq 'Surveillance') "$($f.WPF_ACTIF) | $($f.WPF_ETAT)"
    Cas 'fr-FR : interface classique en français' ($f.CLASSIQUE_ACTIF -eq 'Automatique (Windows : Français)' -and $f.CLASSIQUE_ETAT -eq 'Langue affichée : français.') "$($f.CLASSIQUE_ACTIF) | $($f.CLASSIQUE_ETAT)"
    Cas 'fr-FR : notification locale et bulle en français' ($f.NOTIF -eq 'Critique : deR4Tizer|2 nouvelles alertes' -and $f.ICONE -eq 'deR4Tizer : 2 alerte(s) non lue(s)') "$($f.NOTIF) | $($f.ICONE) $($f.AUTRE)"
    # Assistant élevé : compte élevé en fr-FR, interface qui le lance en anglais (et l'inverse)
    $canal = & $t 'Canal'; $c = [Activator]::CreateInstance((& $t 'Commande')); $c.Action = 'bloquer'; $c.Cible = ''; $c.NomDns = 'tracker.example.net'
    $titreEn = [string]$canal.GetMethod('TitreConfirmation').Invoke($null, @($c, $true)); $titreFr = [string]$canal.GetMethod('TitreConfirmation').Invoke($null, @($c, $false))
    $ae = & $lancer 'fr-FR' '--commande-fichier|x.json|--langue|en' 'apres-assistant-en'
    Cas 'assistant élevé, compte en fr-FR, interface en anglais : fenêtre en anglais (titre, texte, boutons)' ($ae.EN -eq 'True' -and $ae.ASSISTANT_TITRE -eq $titreEn -and $titreEn -ne $titreFr -and $ae.ASSISTANT_TEXTE.StartsWith('Block') -and $ae.ASSISTANT_FENETRE -match '\|Continue' -and $ae.ASSISTANT_FENETRE -match '\|Cancel$') "$($ae.ASSISTANT_TITRE) | $($ae.ASSISTANT_TEXTE) | $($ae.ASSISTANT_FENETRE) $($ae.AUTRE)"
    $af = & $lancer 'en-US' '--commande-fichier|x.json|--langue|fr' 'apres-assistant-fr'
    Cas 'assistant élevé, compte en en-US, interface en français : fenêtre en français' ($af.EN -eq 'False' -and $af.ASSISTANT_TITRE -eq $titreFr -and $af.ASSISTANT_TEXTE.StartsWith('Bloquer') -and $af.ASSISTANT_FENETRE -match '\|Annuler$') "$($af.ASSISTANT_TITRE) | $($af.ASSISTANT_TEXTE) | $($af.ASSISTANT_FENETRE) $($af.AUTRE)"
    $al = & $lancer 'fr-FR' '--commande-fichier|x.json' 'apres-assistant-sans-argument'
    Cas 'assistant élevé lancé sans --langue (version précédente) : culture du compte, comme avant' ($al.EN -eq 'False' -and $al.ASSISTANT_TITRE -eq $titreFr) "$($al.EN) $($al.ASSISTANT_TITRE) $($al.AUTRE)"
    if ($Rendus) { "Rendus : $Rendus" }
} finally {
    Remove-Item $travail -Recurse -Force -ErrorAction SilentlyContinue
}
if ($ko) { "$ko échec(s)"; exit 1 } else { 'Tous les cas réussis.' }
