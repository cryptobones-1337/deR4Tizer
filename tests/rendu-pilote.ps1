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

    # Vue d'ensemble (U2) : textes de l'en-tête remis en casse de phrase, sigles et noms gardés ; phrase de tête
    $vue = & $t 'VueEnsembleFluent'; $pointT = & $t 'PointEtat'
    $phrase = { param($x) $vue.GetMethod('Phrase').Invoke($null, @([string]$x)) }
    foreach ($c in @(
            @('SERVICE EN LIGNE', 'Service en ligne'), @('DEFENDER OK', 'Defender OK'), @('CAM / MIC OFF', 'CAM / MIC OFF'),
            @('NOMS DES SITES INCONNUS (JOURNAL DNS INACTIF)', 'Noms des sites inconnus (journal DNS inactif)'),
            @('PC EXPOSÉ À INTERNET', 'PC exposé à Internet'), @('◉ PANIQUE : COUPER INTERNET', 'Panique : couper Internet'),
            @('PROCESSUS : WMI', 'Processus : WMI'), @('Listes de menaces : 1 234 IP', 'Listes de menaces : 1 234 IP'),
            @('WEBCAM : chrome.exe', 'WEBCAM : chrome.exe'), @('', ''))) {
        $r = & $phrase $c[0]
        Cas "Vue d'ensemble : « $($c[0]) » devient « $($c[1]) »" ($r -ceq $c[1]) "obtenu « $r »"
    }
    # Textes venus du service neutralisés avant affichage (relecture de #134, D1) : inversion du sens d'écriture, largeur
    # nulle, retour à la ligne, contrôle
    $affichable = { param($x) $vue.GetMethod('Affichable').Invoke($null, @([string]$x)) }
    $piege = "WEBCAM : evil" + [char]0x202E + "gpj.exe" + [char]0x200B + "`r`nDEFENDER OK" + [char]7
    $neutre = & $affichable $piege
    Cas "Vue d'ensemble : texte du service neutralisé (U+202E, largeur nulle, retours à la ligne, contrôle)" (-not ($neutre -match "[‮​\r\n\u0007]") -and $neutre.StartsWith('WEBCAM : evil')) "obtenu « $neutre »"
    $lignes2 = $vue.GetMethod('Lignes').Invoke($null, @([string]("○ a" + [char]0x202E + "b`r`n○ c`nd")))
    Cas "Vue d'ensemble : texte de plusieurs lignes neutralisé ligne par ligne, retours à la ligne gardés" ($lignes2 -eq "○ a?b`n○ c`nd") "obtenu « $lignes2 »"
    $statutSrc = [IO.File]::ReadAllText("$src\Gui.cs")
    Cas "Vue d'ensemble : faits, ligne d'état et bouton passent par Visible côté source" ($statutSrc.Contains('Texte = VueEnsembleFluent.Affichable(p.Texte)') -and $statutSrc.Contains('public string Statut() { return Canal.Visible(statut.Text); }') -and $statutSrc.Contains('return VueEnsembleFluent.Affichable(btnPanique.Text)') -and $statutSrc.Contains('foreach (var p in pastilles) p.Texte = Canal.Visible(p.Texte);'))
    $points = { param([int[]]$g) $l = [Activator]::CreateInstance([Collections.Generic.List``1].MakeGenericType($pointT)); foreach ($x in $g) { $p = [Activator]::CreateInstance($pointT); $pointT.GetField('Gravite').SetValue($p, $x); $pointT.GetField('Texte').SetValue($p, 't'); $l.Add($p) }; , $l }
    $resume = { param($l) $args2 = [object[]]@($l, 0); $s = $vue.GetMethod('Resume').Invoke($null, $args2); "$s|$($args2[1])" }
    Cas "Vue d'ensemble : rien de publié, état inconnu en orange (jamais « en ordre »)" ((& $resume (& $points @())) -eq "État inconnu : rien n'est publié par le service pour l'instant.|1") (& $resume (& $points @()))
    Cas "Vue d'ensemble : un rouge l'emporte" ((& $resume (& $points @(0, 1, 2, 2))) -eq '2 points à traiter|2') (& $resume (& $points @(0, 1, 2, 2)))
    Cas "Vue d'ensemble : orange seul, « rien d'avéré »" ((& $resume (& $points @(0, 1))) -eq "Rien d'avéré, 1 point à surveiller|1") (& $resume (& $points @(0, 1)))
    Cas "Vue d'ensemble : tout en ordre, sans promesse" ((& $resume (& $points @(0, 0))) -eq 'Aucun problème relevé|0') (& $resume (& $points @(0, 0)))
    # Compteurs colorés de la navigation : ajoutés « à surveiller » (jamais « à traiter »), compteurs neutres ignorés
    $badges = [Activator]::CreateInstance([Collections.Generic.Dictionary``2].MakeGenericType([string], $pointT))
    foreach ($b in @(@('Baseline', '12%', 2), @('Démarrage auto', '2', 1), @('Alertes', '1', 0))) {
        $p = [Activator]::CreateInstance($pointT); $pointT.GetField('Texte').SetValue($p, $b[1]); $pointT.GetField('Gravite').SetValue($p, [int]$b[2]); $badges.Add($b[0], $p)
    }
    $avec = $vue.GetMethod('AvecCompteurs').Invoke($null, @((& $points @(0)), $badges))
    $lu = @($avec | ForEach-Object { "$($pointT.GetField('Texte').GetValue($_))=$($pointT.GetField('Gravite').GetValue($_))" }) -join '|'
    Cas "Vue d'ensemble : compteurs colorés de la navigation à surveiller, jamais à traiter" ($lu -eq 't=0|Baseline : 12%=1|Démarrage auto : 2=1') $lu
    Cas "Vue d'ensemble : avec un compteur rouge, la tête n'est plus « aucun problème »" ((& $resume $avec) -eq "Rien d'avéré, 2 points à surveiller|1") (& $resume $avec)
    $langue.GetField('En').SetValue($null, $true)
    $deux = $vue.GetProperty('DeuxPoints').GetValue($null)
    $langue.GetField('En').SetValue($null, $false)
    Cas "Vue d'ensemble : deux-points sans espace avant en anglais, avec en français" ($deux -eq ': ' -and $vue.GetProperty('DeuxPoints').GetValue($null) -eq ' : ')

    # Page Alertes (U2b) : actions offertes selon l'alerte, ordre et plafond de la liste, détail neutralisé
    $alertes = & $t 'VueAlertesFluent'; $alerteT = & $t 'Alerte'
    $nouvelle = { param([hashtable]$h) $a = [Activator]::CreateInstance($alerteT); foreach ($k in $h.Keys) { $alerteT.GetProperty($k).SetValue($a, $h[$k]) }; $a }
    $actions = { param($a) @($alertes.GetMethod('Actions').Invoke($null, @($a))) -join ',' }
    $complete = & $nouvelle @{ Id = '1'; Heure = '2026-11-09 10:00:00'; Niveau = 'Alerte'; Processus = 'x.exe'; Chemin = 'C:\x.exe'; Pid = [Nullable[int]]1234; Ip = '1.2.3.4' }
    Cas 'Alertes : toutes les actions pour une alerte complète, dans l''ordre' ((& $actions $complete) -eq 'bloquer,exception,isolerProgramme,suspendre,tuerChaine,quarantaine,emplacement') (& $actions $complete)
    $critique = & $nouvelle @{ Id = '2'; Heure = '2026-11-09 10:00:01'; Niveau = 'Critique'; Processus = 'y.exe'; Chemin = 'C:\y.exe'; Pid = [Nullable[int]]4 }
    Cas 'Alertes : critique sans exception, PID système (4) sans suspendre ni tuer, sans destination sans blocage' ((& $actions $critique) -eq 'isolerProgramme,quarantaine,emplacement') (& $actions $critique)
    $nue = & $nouvelle @{ Id = '3'; Heure = '2026-11-09 10:00:02'; Niveau = 'Info'; Processus = 'z' }
    Cas 'Alertes : sans chemin ni PID ni destination, seule l''exception' ((& $actions $nue) -eq 'exception') (& $actions $nue)
    $liste = [Activator]::CreateInstance([Collections.Generic.List``1].MakeGenericType($alerteT)); foreach ($a in $complete, $critique, $nue) { $liste.Add($a) }
    $ids = { param($n) @($alertes.GetMethod('Filtrer').Invoke($null, @($liste, $n)) | ForEach-Object { $_.Id }) -join ',' }
    Cas 'Alertes : plus récentes d''abord, filtre par niveau' ((& $ids $null) -eq '3,2,1' -and (& $ids 'Critique') -eq '2' -and (& $ids 'Alerte') -eq '1') "$(& $ids $null) / $(& $ids 'Critique')"
    for ($i = 0; $i -lt 520; $i++) { $liste.Add((& $nouvelle @{ Id = "n$i"; Heure = '2026-11-09 11:00:00'; Niveau = 'Info' })) }
    $plafond = @($alertes.GetMethod('Filtrer').Invoke($null, @($liste, $null)))
    Cas 'Alertes : au plus 500 affichées, les plus récentes' ($plafond.Count -eq 500 -and $plafond[0].Id -eq 'n519') "$($plafond.Count) ; première $($plafond[0].Id)"
    Cas 'Alertes : non lue après la dernière lecture seulement' ($alertes.GetMethod('NonLue').Invoke($null, @($complete, '2026-11-09 09:59:59')) -and -not $alertes.GetMethod('NonLue').Invoke($null, @($complete, '2026-11-09 10:00:00')))
    $piegee = & $nouvelle @{ Id = '4'; Heure = 'h'; Niveau = 'Alerte'; Processus = 'p'; Raisons = 'ok' + [char]0x202E + "exe.txt`r`nfaux"; Chemin = 'C:\a' + [char]0x200B + 'b.exe'; Conseil = '' }
    $lignes = @($alertes.GetMethod('Detail').Invoke($null, @($piegee)))
    $textes = ($lignes | ForEach-Object { $_.Texte }) -join '|'
    Cas 'Alertes : détail neutralisé (U+202E, largeur nulle, retours à la ligne), lignes vides omises, chemin en chasse fixe' (-not ($textes -match "[\u202E\u200B\r\n]") -and -not ($lignes | Where-Object { $_.Titre -eq 'Que faire' }) -and ($lignes | Where-Object { $_.Titre -eq 'Chemin' }).Chasse) $textes
    $fluentSrc = [IO.File]::ReadAllText("$src\Fluent.cs")
    Cas 'Alertes : niveau affiché par Visible (audit de #136, S136-01)' (-not $fluentSrc.Contains('Text = L.T(a.Niveau') -and ([regex]::Matches($fluentSrc, 'Canal\.Visible\(L\.T\(a\.Niveau')).Count -eq 2)

    # PID d'une alerte ancienne (relecture de #136, remarque 5) : refus si le processus est lancé après l'alerte, heures dites sinon
    $pidA = & $t 'PidAlerte'
    $apres = { param($h, [DateTime]$d) [bool]$pidA.GetMethod('Posterieur').Invoke($null, @($h, [Nullable[DateTime]]$d)) }
    $base = [DateTime]::ParseExact('2026-11-09 10:00:00', 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
    Cas 'PID d''alerte : lancé 5 s après l''alerte, refusé' (& $apres '2026-11-09 10:00:00' $base.AddSeconds(5))
    Cas 'PID d''alerte : lancé dans la seconde de l''alerte ou avant, accepté' (-not (& $apres '2026-11-09 10:00:00' $base.AddSeconds(2)) -and -not (& $apres '2026-11-09 10:00:00' $base.AddHours(-3)))
    Cas 'PID d''alerte : heure illisible ou lancement inconnu, rien de refusé (la confirmation élevée tranche)' (-not (& $apres 'h' $base.AddDays(1)) -and -not [bool]$pidA.GetMethod('Posterieur').Invoke($null, @('2026-11-09 10:00:00', $null)))
    Cas 'PID d''alerte : heure de création absente ou nulle, lancement inconnu' ($null -eq $pidA.GetMethod('Lancement').Invoke($null, @($null)) -and $null -eq $pidA.GetMethod('Lancement').Invoke($null, @([Nullable[long]]0)))
    $ligneP = [string]$pidA.GetMethod('Ligne').Invoke($null, @(('2026-11-09 10:00:00' + [char]0x202E), $null))
    Cas 'PID d''alerte : les deux heures dites, heure de l''alerte neutralisée, lancement « illisible »' ($ligneP.Contains('Alerte levée le 2026-11-09 10:00:00') -and -not ($ligneP -match "\u202E") -and $ligneP.EndsWith('lancé le illisible')) $ligneP
    $agir = $g0 = [IO.File]::ReadAllText("$src\Gui.cs") -replace "`r`n", "`n"
    $agir = $agir.Substring($agir.IndexOf('void AgirSur(object tag, string action)')); $agir = $agir.Substring(0, $agir.IndexOf("`n        }`n"))
    Cas 'PID d''alerte : AgirSur vérifie avant la question, et nom affiché neutralisé' ($agir.IndexOf('PidAlerte.Posterieur(a.Heure, lancement)') -gt 0 -and $agir.IndexOf('PidAlerte.Posterieur') -lt $agir.IndexOf('MessageBox.Show(libelles[action]') -and $agir.Contains('string vu = Canal.Visible(nom);') -and $agir.Contains('Raison = "action manuelle sur " + nom'))

    # Incidents (U2c) : transitions offertes, gravité, sections du panneau sans perte ni texte brut
    $vi = & $t 'VueIncidentsFluent'; $incT = & $t 'IncidentSuivi'
    $inc = { param([hashtable]$h) $x = [Activator]::CreateInstance($incT); foreach ($k in $h.Keys) { $incT.GetProperty($k).SetValue($x, $h[$k]) }; $x }
    $regles = { param([string[]]$r) $l = New-Object 'Collections.Generic.List[string]'; foreach ($x in $r) { $l.Add($x) }; , $l }
    $actI = { param($etat) @($vi.GetMethod('Actions').Invoke($null, @((& $inc @{ Id = 'i'; Etat = $etat })))) -join ',' }
    Cas 'Incidents : transitions offertes comme la page d''aujourd''hui' ((& $actI 'Ouvert') -eq 'PrisEnCharge,Clos' -and (& $actI 'PrisEnCharge') -eq 'Clos' -and (& $actI 'Clos') -eq 'Ouvert') "$(& $actI 'Ouvert') / $(& $actI 'PrisEnCharge') / $(& $actI 'Clos')"
    $grav = { param($x) [int]$vi.GetMethod('Gravite').Invoke($null, @($x)) }
    $risque = & $inc @{ Id = 'a'; Etat = 'Ouvert'; Niveau = 'Critique'; Regles = (& $regles 'LEU-001') }
    $sante = & $inc @{ Id = 'b'; Etat = 'Ouvert'; Niveau = 'Critique'; Regles = (& $regles 'SAN-001') }
    $clos = & $inc @{ Id = 'c'; Etat = 'Clos'; Niveau = 'Critique'; Regles = (& $regles 'LEU-001') }
    Cas 'Incidents : rouge pour un risque confirmé seulement, constat de santé à surveiller, clos estompé' ((& $grav $risque) -eq 2 -and (& $grav $sante) -eq 1 -and (& $grav $clos) -eq 0)
    $piege = & $inc @{ Id = 'p'; Etat = 'Ouvert'; Niveau = 'Alerte'; Entite = 'programme:c:\x' + [char]0x202E + 'exe.txt'; Ouverture = '2026-11-09 10:00:00'; Regles = (& $regles 'RES-002'); NombreAlertes = 0 }
    $detailI = [string]((& $t 'VueIncidents').GetMethod('Detail').Invoke($null, @($piege, $null)))
    $sections = @($vi.GetMethod('Sections').Invoke($null, @($detailI)))
    $avant = @(($detailI -replace "`r", '').Split("`n") | Where-Object { $_ -ne '' -and -not $_.StartsWith('-- ') }).Count
    $apresL = @($sections | ForEach-Object { $_.Texte.Split("`n") } | Where-Object { $_ -ne '' }).Count
    Cas 'Incidents : panneau en sections (résumé, Alertes, Chronologie, Transitions), aucune ligne perdue, texte neutralisé' ((@($sections | ForEach-Object { $_.Titre }) -join '|') -eq '|Alertes|Chronologie|Transitions' -and $avant -eq $apresL -and -not ((@($sections | ForEach-Object { $_.Texte }) -join '') -match "\u202E")) "$((@($sections | ForEach-Object { $_.Titre }) -join '|')) ; $avant / $apresL"

    # Réponses en cours (U2c) : détail de la ligne, récupération toujours écrite, cible en chasse fixe
    $lrT = & $t 'LigneReponse'; $lr = [Activator]::CreateInstance($lrT)
    foreach ($kv in @{ Quoi = 'q'; Cible = 'c:\a.exe (PID 9)'; Declencheur = 'LEU-001'; Depuis = '2026-11-09 10:00'; Echeance = '2026-11-09 14:00'; Etat = 'en cours'; Recuperation = 'r'; Bouton = 'Reprendre' }.GetEnumerator()) { $lrT.GetField($kv.Key).SetValue($lr, $kv.Value) }
    $dr = @((& $t 'VueReponsesFluent').GetMethod('Detail').Invoke($null, @($lr)))
    Cas 'Réponses : détail complet, récupération dite, cible en chasse fixe' ((@($dr | ForEach-Object { $_.Titre }) -join '|') -eq 'Cible|Déclencheur|Depuis|Relance|État|Récupération' -and ($dr | Where-Object { $_.Titre -eq 'Cible' }).Chasse) ((@($dr | ForEach-Object { $_.Titre }) -join '|'))
    Cas 'Réponses : sorte inconnue neutralisée (relecture de #137, constat 5)' (-not ([string]((& $t 'VueReponses').GetMethod('Libelle').Invoke($null, @(('Autre' + [char]0x202E + 'x')))) -match "\u202E"))

    # Détection (U3a) : noms TLS, chemins HTTP, noms DNS et messages des règles neutralisés ; gravité ; chasse fixe
    $vd = & $t 'VueDetectionFluent'; $idsT = & $t 'EtatIds'; $dpiT = & $t 'EtatDpi'; $detT = & $t 'DetectionIds'; $sesT = & $t 'SessionDpi'
    $nouv = { param($type, [hashtable]$h) $x = [Activator]::CreateInstance($type); foreach ($k in $h.Keys) { $type.GetProperty($k).SetValue($x, $h[$k]) }; $x }
    $listeDe = { param($type, $elements) $l = [Activator]::CreateInstance([Collections.Generic.List``1].MakeGenericType($type)); foreach ($e in $elements) { $l.Add($e) }; , $l }
    $piegeR = 'evil' + [char]0x202E + 'moc.exe' + "`r`nfaux"
    $ids = & $nouv $idsT @{ Detections = (& $listeDe $detT @((& $nouv $detT @{ Heure = '2026-11-10 10:00:00'; Sid = [long]2000001; Message = $piegeR; Niveau = 'Critique'; Source = '10.0.0.2:5000'; Destination = '1.2.3.4:443'; Bloque = $true }))) }
    $dpi = & $nouv $dpiT @{ Tls = (& $listeDe $sesT @((& $nouv $sesT @{ Heure = 'h'; Programme = 'p.exe'; Ip = '1.2.3.4'; Port = 443; Nom = $piegeR; Ja3 = 'abc'; Remarque = 'JA3 malveillant' }))); Dns = (& $listeDe $sesT @((& $nouv $sesT @{ Heure = 'h'; Programme = 'p.exe'; Ip = '9.9.9.9'; Nom = $piegeR }))) }
    $tout = foreach ($v in 0..4) { foreach ($x in @($vd.GetMethod('Lignes').Invoke($null, @($ids, $dpi, $v)))) { $x.Titre; $x.Etiquette; $x.Sous; foreach ($d in $x.Detail) { $d.Texte } } }
    Cas 'Détection : textes du réseau et des règles neutralisés dans les cinq vues (U+202E, retours à la ligne)' (-not ((@($tout) -join '|') -match "[\u202E\r\n]") -and @($tout).Count -gt 10) "$(@($tout).Count) textes"
    $ids0 = @($vd.GetMethod('Lignes').Invoke($null, @($ids, $dpi, 0)))[0]; $tls0 = @($vd.GetMethod('Lignes').Invoke($null, @($ids, $dpi, 1)))[0]
    Cas 'Détection : critique en rouge et bloqué dit, session TLS signalée en rouge, destination en chasse fixe' ($ids0.Gravite -eq 2 -and $ids0.Etiquette.Contains('bloqué') -and $tls0.Gravite -eq 2 -and ($ids0.Detail | Where-Object { $_.Titre -eq 'Destination' }).Chasse)
    Cas 'Détection : fichiers absents, aucune ligne et aucune exception' (@($vd.GetMethod('Lignes').Invoke($null, @($null, $null, 0))).Count -eq 0)
    $reseauSrc = [IO.File]::ReadAllText("$src\Reseau.cs")
    Cas 'Détection : page d''aujourd''hui neutralisée aussi, IPS et dossier des règles par les mêmes méthodes' ($reseauSrc.Contains('valeurs = valeurs.Select(v => Canal.Visible(v ?? "")).ToArray();') -and $reseauSrc.Contains('VueDetection.ChangerIps(chkIps.Checked);') -and $fluentSrc.Contains('VueDetection.ChangerIps(!ipsActif)') -and ([regex]::Matches($reseauSrc, 'Action = "config", Cible = "Ips"')).Count -eq 1)
    # Préalables de #138 : état de l'IPS inconnu si config.json est illisible ; « Copier » rend la valeur d'origine
    $infoInconnu = [string]((& $t 'VueDetection').GetMethod('Info').Invoke($null, @($null, $null, $null)))
    Cas 'Détection : config.json illisible, IPS dit « inconnu », jamais « inactif » (audit de #138, S138-01)' ($infoInconnu.Contains('IPS inconnu') -and -not $infoInconnu.Contains('inactif')) $infoInconnu
    Cas 'Détection : sans état lu, ni case active (aujourd''hui) ni bouton IPS (coquille)' ($reseauSrc.Contains('chkIps.Enabled = configLue != null;') -and $fluentSrc.Contains('bIps.Visibility = lu && ips.HasValue ? Visibility.Visible : Visibility.Collapsed;'))
    $siemSrc = [IO.File]::ReadAllText("$src\Siem.cs")
    Cas 'Copier : valeur d''origine (Détection, Réseau, Événements), affichage neutralisé (relecture de #138, constat 5)' ($reseauSrc.Contains('item.SubItems[k].Tag = Canal.Echappe(brutes[k]);') -and $reseauSrc.Contains('x.Tag as string ?? x.Text') -and $siemSrc.Contains('item.SubItems[k].Tag = Canal.Echappe(valeurs[k]);') -and $siemSrc.Contains('s.Tag as string ?? s.Text'))
    # Valeur copiée : exacte et lisible, mais sans retour à la ligne ni caractère invisible qui s'exécuterait au collage (audit de #139, S139-01)
    $canalT = $asm.GetType('DeR4Tizer.Canal'); $ech = $canalT.GetMethod('Echappe', [Reflection.BindingFlags]'Static,NonPublic')
    $copie = [string]$ech.Invoke($null, @(("x.exe`r`nStart-Process calc`t" + [char]0x202E + [char]0x2028 + [char]7 + 'é C:\a')))
    Cas 'Copier : retours à la ligne, tabulation, U+202E, U+2028 et contrôles échappés ; accents et chemins gardés' ($copie -ceq 'x.exe\r\nStart-Process calc\t\u202E\u2028\u0007é C:\a' -and -not ($copie -match "[\r\n\t\u202E\u2028\u0007]")) $copie

    # Événements (U3b) : textes des événements et des incidents de corrélation neutralisés, page d'aujourd'hui aussi
    $ve = & $t 'VueEvenementsFluent'; $evT = & $t 'Evenement'; $icT = & $t 'Incident'
    $ev = & $nouv $evT @{ Heure = '2026-11-10 10:00:00'; Source = 'securite'; Type = '4625'; Niveau = 'Alerte'; Utilisateur = 'adm' + [char]0x202E; Processus = 'x.exe'; Pid = [Nullable[int]]42; Ip = '1.2.3.4'; Port = 445; Message = $piegeR; Mitre = 'T1110' }
    $lev = $ve.GetMethod('Ligne', [type[]]@($evT)).Invoke($null, @($ev))
    $txt = (@($lev.Titre, $lev.Etiquette, $lev.Sous) + @($lev.Detail | ForEach-Object { $_.Texte })) -join '|'
    Cas 'Événements : événement neutralisé (message, utilisateur), alerte à surveiller, IP en chasse fixe' (-not ($txt -match "[\u202E\r\n]") -and $lev.Gravite -eq 1 -and ($lev.Detail | Where-Object { $_.Titre -eq 'IP' }).Chasse -and $txt.Contains('x.exe (PID 42)')) $txt
    $evs = New-Object 'Collections.Generic.List[string]'; $evs.Add('ligne 1' + [char]0x202E); $evs.Add("ligne`r`n2")
    $ic = & $nouv $icT @{ Heure = '2026-11-10 10:00:00'; Regle = 'COR-001'; Titre = 'Force brute' + [char]0x200B; Niveau = 'Critique'; Resume = 'r'; Evenements = $evs }
    $lic = $ve.GetMethod('Ligne', [type[]]@($icT)).Invoke($null, @($ic))
    $txtI = (@($lic.Titre, $lic.Etiquette, $lic.Sous) + @($lic.Detail | ForEach-Object { $_.Texte })) -join '|'
    $evDetail = ($lic.Detail | Where-Object { $_.Titre -eq 'Événements' }).Texte
    Cas 'Événements : incident de corrélation neutralisé, critique en rouge, une ligne par événement lié' (-not ($txtI -match "[\u202E\u200B\r]") -and $lic.Gravite -eq 2 -and @($evDetail.Split("`n")).Count -eq 2) $txtI
    Cas 'Événements : avant la première recherche, « Recherche… », jamais « aucun événement »' (([string]$ve.GetMethod('Resume').Invoke($null, @($null, $null, $null))) -eq 'Recherche…')
    $tr = (& $t 'RechercheSiem').GetMethod('Tranche')
    $deb = [DateTime]'2026-11-10 00:00:00'; $fin = $deb.AddHours(24)
    $a = @($deb, $fin, 48, 0, [DateTime]::MinValue, [DateTime]::MinValue); $tr.Invoke($null, $a) | Out-Null
    $b = @($deb, $fin, 48, 47, [DateTime]::MinValue, [DateTime]::MinValue); $tr.Invoke($null, $b) | Out-Null
    $segm = { param($i, $a, $c, $m) @((& $t 'ChronologieFluent').GetMethod('Segments', [Reflection.BindingFlags]'Static,NonPublic').Invoke($null, @([int]$i, [int]$a, [int]$c, [int]$m, [double]66))) }
    $s1 = & $segm 5000 0 3 5003
    Cas 'Événements : 3 critiques parmi 5000 infos, segment critique de 2 px au moins (relecture de #139, constat 6b)' ($s1[2] -ge 2 -and $s1[1] -eq 0 -and $s1[0] -gt 0) ($s1 -join ' / ')
    $s2 = & $segm 0 0 0 10
    Cas 'Événements : tranche vide, aucun segment' (($s2 | Measure-Object -Sum).Sum -eq 0)
    Cas 'Événements : chronologie avec maximum et heures écrits (constat 6a)' ($fluentSrc.Contains('L.T("max {0} par tranche, hauteur en racine carrée")') -and $fluentSrc.Contains('g.DrawText(milieu,'))
    Cas 'Événements : chronologie en 48 tranches, de début à fin' ($a[4] -eq $deb -and $b[5] -eq $fin -and ($a[5] - $a[4]).TotalMinutes -eq 30)
    Cas 'Événements : page d''aujourd''hui neutralisée (cellules, info-bulle, détail), même recherche que la coquille' ($siemSrc.Contains('new ListViewItem(valeurs.Select(v => Canal.Visible(v ?? "")).ToArray())') -and $siemSrc.Contains('item.ToolTipText = Canal.Visible(e.Message ?? "");') -and $siemSrc.Contains('"\n" + v(e.Message);') -and $siemSrc.Contains('RechercheSiem.ChercherSur(texte, source, niveauMin') -and $fluentSrc.Contains('RechercheSiem.ChercherSur(texte, src, niv'))
    # Connexions (U4a) : actions selon la ligne, tri par gravité puis score, détail et copie neutralisés ou échappés
    $vc = & $t 'VueConnexionsFluent'; $fluxT = & $t 'FluxInfo'
    $fx = { param([hashtable]$h) & $nouv $fluxT $h }
    $complet = & $fx @{ Cle = 'a'; Score = 2; Processus = 'x' + [char]0x202E + 'exe'; Pid = 42; Chemin = 'C:\x.exe'; Ip = '1.2.3.4'; NomDns = 'evil.test'; Port = 443; Raisons = 'nouveau'; Signataire = 'S'; PremiereVue = '2026-11-10 09:00:00'; LigneCommande = "x.exe`r`n-c calc"; Origine = 'Internet' }
    $actionsC = { param($f) (@($vc.GetMethod('Actions').Invoke($null, @($f))) -join ',') }
    Cas 'Connexions : toutes les actions pour une ligne complète, dans l''ordre du menu d''aujourd''hui' ((& $actionsC $complet) -eq 'bloquer,bloquerIp,isolerProgramme,suspendre,reprendre,tuer,quarantaine,emplacement,copier') (& $actionsC $complet)
    $systeme = & $fx @{ Cle = 'b'; Score = 0; Processus = 'System'; Pid = 4; Ip = '5.6.7.8'; Port = 80; Raisons = '' }
    Cas 'Connexions : PID système (4) sans suspendre ni tuer, sans chemin ni isoler ni quarantaine, sans nom un seul blocage' ((& $actionsC $systeme) -eq 'bloquer,copier') (& $actionsC $systeme)
    $menace = & $fx @{ Cle = 'c'; Score = 1; Processus = 'm'; Pid = 50; Ip = '9.9.9.9'; Port = 80; Raisons = 'MENACE liste' }
    $alerteF = & $fx @{ Cle = 'd'; Score = 5; Processus = 'n'; Pid = 51; Ip = '8.8.8.8'; Port = 80; Raisons = 'x' }
    $calme = & $fx @{ Cle = 'e'; Score = 0; Processus = 'a'; Pid = 52; Ip = '7.7.7.7'; Port = 80; Raisons = 'BLOQUÉ' }
    $lf = New-Object "Collections.Generic.List[$($fluxT.FullName)]"; foreach ($x in $calme, $complet, $menace, $alerteF) { $lf.Add($x) }
    $cles = { param($n) (@($vc.GetMethod('Filtrer').Invoke($null, [object[]]@($lf.PSObject.BaseObject, [int]$n)) | ForEach-Object { $_.Cle }) -join ',') }
    Cas 'Connexions : menace d''abord, puis score ; filtres suspectes et menaces' ((& $cles 0) -eq 'c,d,a,e' -and (& $cles 1) -eq 'c,d,a' -and (& $cles 2) -eq 'c') "$(& $cles 0) / $(& $cles 1) / $(& $cles 2)"
    Cas 'Connexions : gravité (menace 2, score de 3 au moins 1), ligne bloquée estompée' ($vc.GetMethod('Gravite').Invoke($null, @($menace)) -eq 2 -and $vc.GetMethod('Gravite').Invoke($null, @($alerteF)) -eq 1 -and $vc.GetMethod('Gravite').Invoke($null, @($complet)) -eq 0 -and $vc.GetMethod('Bloquee').Invoke($null, @($calme)))
    $dc = @($vc.GetMethod('Detail').Invoke($null, @($complet)))
    $txtC = (@($dc | ForEach-Object { $_.Texte }) + @($vc.GetMethod('Sous').Invoke($null, @($complet)), $vc.GetMethod('Destination').Invoke($null, @($complet)))) -join '|'
    Cas 'Connexions : détail neutralisé (U+202E, retours à la ligne), chemin et ligne de commande en chasse fixe' (-not ($txtC -match "[\u202E\r\n]") -and ($dc | Where-Object { $_.Titre -eq 'Chemin' }).Chasse -and ($dc | Where-Object { $_.Titre -eq 'Ligne de commande' }).Chasse) $txtC
    $copieC = [string]$vc.GetMethod('Copie').Invoke($null, @($complet))
    Cas 'Connexions : copie des colonnes d''aujourd''hui, valeur d''origine échappée (S139-01)' ($copieC -ceq ("2`tx\u202Eexe`t`t42`tevil.test (1.2.3.4)`t443`tS`t2026-11-10 09:00:00`tnouveau")) $copieC
    $res = { param($l, $lu, $ill, $p) [string]$vc.GetMethod('Resume').Invoke($null, [object[]]@($l.PSObject.BaseObject, [bool]$lu, [bool]$ill, '2026-11-10 10:00:00', $p)) }
    $vide = New-Object "Collections.Generic.List[$($fluxT.FullName)]"
    Cas 'Connexions : avant lecture « Lecture en cours… », illisible sans liste « rien n''est conclu », jamais « 0 connexion »' ((& $res $vide $false $false $null) -eq 'Lecture en cours…' -and (& $res $vide $true $true $null).Contains('rien n''est conclu') -and -not (& $res $vide $true $true $null).Contains('0 connexion'))
    $r2 = & $res $lf $true $true 'Connexions indisponible (x) : connexions réseau non vues'
    Cas 'Connexions : illisible après une lecture, dernier affichage gardé et dit ; collecte en panne dite' ($r2.Contains('dernier affichage gardé') -and $r2.Contains('4 connexion(s)') -and $r2.Contains('Liste incomplète')) $r2
    $etatT = & $t 'Etat'; $collT = & $t 'EtatCollecte'
    $lc = New-Object "Collections.Generic.List[$($collT.FullName)]"; $lc.Add((& $nouv $collT @{ Id = 'Connexions'; Etat = 'Indisponible'; Raison = 'r' + [char]0x202E }))
    $etatP = & $nouv $etatT @{ Collectes = $lc }
    $panne = [string](& $t 'VueReseauFluent').GetMethod('Panne').Invoke($null, @($etatP, 'Connexions'))
    Cas 'Connexions : collecte en panne trouvée et neutralisée, aucune pour une autre collecte' ($panne.Contains('Connexions') -and -not ($panne -match "\u202E") -and $null -eq (& $t 'VueReseauFluent').GetMethod('Panne').Invoke($null, @($etatP, 'Processus'))) $panne

    # Chaînes (U4a) : chaînes au score positif, plus lourdes d'abord ; seuil 12 ; arbre, détail et copie
    $vch = & $t 'VueChainesFluent'; $chT = & $t 'Chaine'; $noT = & $t 'NoeudChaine'
    $nds = New-Object "Collections.Generic.List[$($noT.FullName)]"
    $nds.Add((& $nouv $noT @{ Profondeur = 0; Pid = 100; Nom = 'explorer.exe'; Score = 0; Chemin = 'C:\Windows\explorer.exe' }))
    $nds.Add((& $nouv $noT @{ Profondeur = 1; Pid = 101; Nom = 'cmd' + [char]0x202E + '.exe'; Score = 8; Raisons = 'r'; Chemin = 'C:\cmd.exe'; LigneCommande = "cmd /c`r`nwhoami" }))
    $nds.Add((& $nouv $noT @{ Profondeur = 2; Pid = 4; Nom = 'System'; Score = 6 }))
    $forte = & $nouv $chT @{ Racine = 'r1'; Score = 14; Resume = 'chaîne' + [char]0x200B; Depuis = '10:00'; Noeuds = $nds }
    $faible = & $nouv $chT @{ Racine = 'r2'; Score = 3; Resume = 'b'; Depuis = '09:00' }
    $nulle = & $nouv $chT @{ Racine = 'r3'; Score = 0; Resume = 'c'; Depuis = '08:00' }
    $lch = New-Object "Collections.Generic.List[$($chT.FullName)]"; foreach ($x in $faible, $nulle, $forte) { $lch.Add($x) }
    $susL = $vch.GetMethod('Suspectes').Invoke($null, [object[]](, $lch.PSObject.BaseObject)); $sus = @($susL)
    Cas 'Chaînes : score nul écarté (comme aujourd''hui), plus lourdes d''abord' ((@($sus | ForEach-Object { $_.Racine }) -join ',') -eq 'r1,r2') (@($sus | ForEach-Object { $_.Racine }) -join ',')
    Cas 'Chaînes : au-delà de 12 critique, nœud qui compte en rouge, nœud à 0 neutre' ($vch.GetMethod('Gravite').Invoke($null, @($forte)) -eq 2 -and $vch.GetMethod('Gravite').Invoke($null, @($faible)) -eq 1 -and $vch.GetMethod('GraviteNoeud').Invoke($null, @($forte, $nds[1])) -eq 2 -and $vch.GetMethod('GraviteNoeud').Invoke($null, @($forte, $nds[0])) -eq 0)
    $actionsN = { param($n) (@($vch.GetMethod('Actions').Invoke($null, @($n))) -join ',') }
    Cas 'Chaînes : actions du menu d''aujourd''hui, PID système sans tuer ni suspendre' ((& $actionsN $nds[1]) -eq 'tuerChaine,suspendre,quarantaine,isolerProgramme,emplacement,copier' -and (& $actionsN $nds[2]) -eq 'copier') "$(& $actionsN $nds[1]) / $(& $actionsN $nds[2])"
    $txtN = (@($vch.GetMethod('Detail').Invoke($null, @($nds[1])) | ForEach-Object { $_.Texte }) + @([string]$vch.GetMethod('Resume').Invoke($null, [object[]]@($susL, $true, $false, '2026-11-10 10:00:00', $null)), [string]$vch.GetMethod('Sous').Invoke($null, @($forte)))) -join '|'
    Cas 'Chaînes : détail et résumé neutralisés' (-not ($txtN -match "[\u202E\u200B\r\n]") -and $txtN.Contains('2 chaîne(s) suspecte(s), dont 1 au-delà')) $txtN
    $copieN = [string]$vch.GetMethod('Copie').Invoke($null, @($nds[1]))
    Cas 'Chaînes : copie sans retrait, valeur d''origine échappée' ($copieN -ceq ("cmd\u202E.exe`t101`t8`tr`tcmd /c\r\nwhoami")) $copieN
    $vchVide = New-Object "Collections.Generic.List[$($chT.FullName)]"
    Cas 'Chaînes : avant lecture « Lecture en cours… », lue et vide « aucune chaîne suspecte »' (([string]$vch.GetMethod('Resume').Invoke($null, [object[]]@($vchVide.PSObject.BaseObject, $false, $false, $null, $null))) -eq 'Lecture en cours…' -and ([string]$vch.GetMethod('Resume').Invoke($null, [object[]]@($vchVide.PSObject.BaseObject, $true, $false, $null, $null))).StartsWith('Aucune chaîne suspecte'))
    $guiSrc = [IO.File]::ReadAllText("$src\Gui.cs")
    Cas 'Connexions : aucun compteur de filtre avant la première lecture (« 0 » ferait croire à une liste vide)' ($fluentSrc.Contains('(lu ? "  " + VueConnexionsFluent.Filtrer(flux, n).Count : "")'))
    Cas 'Connexions et Chaînes : seules les réponses que la question d''AgirSur sait dire partent de la coquille' ($guiSrc.Contains('var permises = new[] { "tuer", "tuerChaine", "suspendre", "reprendre", "quarantaine", "isolerProgramme" };') -and $guiSrc.Contains('permises.Contains(action)) AgirSur(element, action);'))
    Cas 'Connexions et Chaînes d''aujourd''hui : cellules et info-bulles neutralisées, copie échappée' ($guiSrc.Contains('var item = new ListViewItem(brutes.Select(v => Canal.Visible(v ?? "")).ToArray())') -and $guiSrc.Contains('retrait + Canal.Visible(n.Nom)') -and ([regex]::Matches($guiSrc, 'item\.SubItems\[k\]\.Tag = Canal\.Echappe\(brutes\[k\]\);')).Count -eq 2 -and $guiSrc.Contains('s.Tag as string ?? Canal.Echappe(s.Text)'))
    # Trafic (U4b) : échelle logarithmique, résumé honnête, lignes triées et neutralisées, bulle de la carte neutralisée
    $vt = & $t 'VueTraficFluent'; $etT = & $t 'EtatTrafic'; $apT = & $t 'TraficApplication'; $paT = & $t 'TraficPays'; $deT = & $t 'TraficDestination'
    $int = { param($v, $m) [double]$vt.GetMethod('Intensite').Invoke($null, [object[]]@([long]$v, [long]$m)) }
    Cas 'Trafic : échelle logarithmique, 0 sans échange, 1 au maximum, 1 Ko visible à côté de 1 Go' ((& $int 0 100) -eq 0 -and [math]::Abs((& $int 1GB 1GB) - 1) -lt 1e-9 -and (& $int 1KB 1GB) -gt 0.3) "$(& $int 1KB 1GB)"
    $resT = { param($e, $lu, $ill) [string]$vt.GetMethod('Resume').Invoke($null, [object[]]@($e, [bool]$lu, [bool]$ill)) }
    Cas 'Trafic : avant lecture « Lecture en cours… », sans fichier « rien n''est conclu », jamais 0 o rassurant' ((& $resT $null $false $false) -eq 'Lecture en cours…' -and (& $resT $null $true $false).Contains('rien n''est conclu') -and -not (& $resT $null $true $false).Contains(' 0 o'))
    $la = New-Object "Collections.Generic.List[$($apT.FullName)]"
    $la.Add((& $nouv $apT @{ Nom = 'petit'; Entrant = [long]10; Sortant = [long]5; Destinations = 1 }))
    $la.Add((& $nouv $apT @{ Nom = 'gros' + [char]0x202E + 'exe'; Entrant = [long]5000; Sortant = [long]100; Destinations = 3 }))
    $progs = New-Object 'Collections.Generic.List[string]'; $progs.Add('a' + [char]0x200B + "`r`nb")
    $lp = New-Object "Collections.Generic.List[$($paT.FullName)]"; $lp.Add((& $nouv $paT @{ Code = 'FR'; Entrant = [long]100; Sortant = [long]0; Destinations = 2; Programmes = $progs; Active = $true }))
    $ld = New-Object "Collections.Generic.List[$($deT.FullName)]"; $ld.Add((& $nouv $deT @{ Ip = '1.2.3.4'; Nom = 'evil' + [char]0x202E + '.test'; Pays = 'FR'; Programme = "x`r`ny"; Port = 443; Entrant = [long]1; Sortant = [long]1; Active = $false }))
    $etatTr = & $nouv $etT @{ Interface = 'eth' + [char]0x202E; Depuis = '2026-11-10 00:00:00'; MisAJour = '2026-11-10 10:00:00'; Applications = $la; Pays = $lp; Destinations = $ld; DebitEntrant = [long]2048; Paquets = [long]10 }
    $lig = { param($v) @($vt.GetMethod('Lignes').Invoke($null, [object[]]@($etatTr, [int]$v))) }
    $l0 = & $lig 0; $l1 = & $lig 1; $l2 = & $lig 2
    $txtT = (@($l0 + $l1 + $l2 | ForEach-Object { $_.Titre; $_.Sous; $_.Detail | ForEach-Object { $_.Texte } }) + @((& $resT $etatTr $true $false), [string]$vt.GetMethod('Bulle').Invoke($null, [object[]]@('FR', $lp[0])))) -join '|'
    Cas 'Trafic : programmes, pays, destinations, résumé et bulle neutralisés (U+202E, largeur nulle, retours à la ligne)' (-not ($txtT -match "[\u202E\u200B\r]") -and -not (($l1[0].Sous + $l2[0].Sous) -match "\n")) $txtT
    Cas 'Trafic : plus gros volume d''abord, échange récent dit, IP en chasse fixe' ($l0[0].Titre.StartsWith('gros') -and $l1[0].Sous.Contains('en ce moment') -and -not $l2[0].Sous.Contains('en ce moment') -and ($l2[0].Detail | Where-Object { $_.Titre -eq 'Adresse IP' }).Chasse) "$($l0[0].Titre) ; $($l1[0].Sous)"
    $r3 = & $resT $etatTr $true $true
    Cas 'Trafic : illisible après une lecture, dernier affichage gardé et dit' ($r3.StartsWith('trafic.json illisible : dernier affichage gardé') -and $r3.Contains('2 Ko/s')) $r3
    $traficSrc = [IO.File]::ReadAllText("$src\Trafic.cs")
    Cas 'Trafic : courbe sans maximum avant deux mesures (« pas encore de mesure »)' ($fluentSrc.Contains('points.Count < 2 ? (en ? "no measurement yet" : "pas encore de mesure")'))
    Cas 'Trafic d''aujourd''hui : programmes, destinations, interface et bulle neutralisés' ($traficSrc.Contains('Canal.Visible(a.Nom)') -and $traficSrc.Contains('Canal.Visible(t.Interface)') -and ([regex]::Matches($traficSrc, '\.Select\(Canal\.Visible\)')).Count -eq 2 -and $traficSrc.Contains('Canal.Visible(x.Programme)') -and $traficSrc.Contains('Canal.Visible((t.Depuis ?? "").Length >= 16') -and $traficSrc.Contains('Select(p => new[] { VueTraficFluent.NomPays(p.Code),'))
    $carteSrc = $fluentSrc.Substring($fluentSrc.IndexOf('class CarteFluent'), $fluentSrc.IndexOf('class CourbeFluent') - $fluentSrc.IndexOf('class CarteFluent'))
    Cas 'Trafic : carte sans animation continue ni chargement réseau, contours de l''exécutable' (-not $carteSrc.Contains('DispatcherTimer') -and -not $carteSrc.Contains('http') -and $carteSrc.Contains('PaysCarte.Tous'))
    # Blocages, Quarantaine, Menaces (U5a) : résumés honnêtes, textes neutralisés, mêmes commandes, S139-02
    $vb = & $t 'VueBlocagesFluent'; $blT = & $t 'Blocage'
    $lb = New-Object "Collections.Generic.List[$($blT.FullName)]"
    $lb.Add((& $nouv $blT @{ Type = 'hosts'; Cible = 'evil' + [char]0x202E + '.test'; Raison = "flux de x`r`ny"; Date = '2026-11-10' }))
    $lb.Add((& $nouv $blT @{ Type = 'parefeu'; Cible = '1.2.3.4'; Raison = ''; Date = '2026-11-10' }))
    $lb.Add((& $nouv $blT @{ Type = 'programme'; Cible = 'C:\x.exe'; Raison = 'r'; Date = '2026-11-10' }))
    $lbVide = New-Object "Collections.Generic.List[$($blT.FullName)]"
    $resB = { param($l, $lu, $ill) [string]$vb.GetMethod('Resume').Invoke($null, [object[]]@($l.PSObject.BaseObject, [bool]$lu, [bool]$ill)) }
    Cas 'Blocages : avant lecture « Lecture en cours… », absent « Aucun blocage », illisible sans liste « rien n''est conclu »' ((& $resB $lbVide $false $false) -eq 'Lecture en cours…' -and (& $resB $lbVide $true $false) -eq 'Aucun blocage.' -and (& $resB $lbVide $true $true).Contains('rien n''est conclu'))
    $rb = & $resB $lb $true $true
    Cas 'Blocages : décompte par type, illisible après lecture dit' ($rb.Contains('3 blocage(s) : 1 nom(s)') -and $rb.Contains('1 IP bloquée(s)') -and $rb.Contains('1 programme(s) isolé(s)') -and $rb.StartsWith('blocages.json illisible : dernier affichage gardé')) $rb
    $txtB = @($vb.GetMethod('Detail').Invoke($null, @($lb[0])) | ForEach-Object { $_.Texte }) -join '|'
    Cas 'Blocages : détail neutralisé, type en clair' (-not ($txtB -match "[\u202E\r\n]") -and $txtB.StartsWith('fichier hosts')) $txtB
    $vq = & $t 'VueQuarantaineFluent'; $qT = & $t 'ElementQuarantaine'
    $lq = New-Object "Collections.Generic.List[$($qT.FullName)]"
    $lq.Add((& $nouv $qT @{ Id = 'q1'; CheminOrigine = 'C:\Users\x\facture' + [char]0x202E + 'fdp.exe'; Date = '2026-11-09'; Raison = 'r'; Taille = [long]4096 }))
    $lq.Add((& $nouv $qT @{ Id = 'q2'; CheminOrigine = 'C:\b.exe'; Date = '2026-11-10'; Raison = ''; Taille = [long]1024 }))
    $tri = @($vq.GetMethod('Trier').Invoke($null, [object[]](, $lq.PSObject.BaseObject)))
    $nomQ = [string]$vq.GetMethod('Nom').Invoke($null, @($lq[0]))
    Cas 'Quarantaine : plus récents d''abord, nom du fichier neutralisé' ((@($tri | ForEach-Object { $_.Id }) -join ',') -eq 'q2,q1' -and -not ($nomQ -match "\u202E") -and $nomQ.StartsWith('facture')) "$((@($tri | ForEach-Object { $_.Id }) -join ',')) ; $nomQ"
    $dq = @($vq.GetMethod('Detail').Invoke($null, @($lq[0])))
    Cas 'Quarantaine : emplacement d''origine neutralisé et en chasse fixe, taille en Ko' (-not ((@($dq | ForEach-Object { $_.Texte }) -join '|') -match "\u202E") -and $dq[0].Chasse -and $dq[3].Texte -eq '4 Ko')
    $lqVide = New-Object "Collections.Generic.List[$($qT.FullName)]"
    Cas 'Quarantaine : vide après lecture « Aucun fichier en quarantaine », illisible sans liste rien de conclu' (([string]$vq.GetMethod('Resume').Invoke($null, [object[]]@($lqVide.PSObject.BaseObject, $true, $false))) -eq 'Aucun fichier en quarantaine.' -and ([string]$vq.GetMethod('Resume').Invoke($null, [object[]]@($lqVide.PSObject.BaseObject, $true, $true))).Contains('rien n''est conclu'))
    $vm = & $t 'VueMenacesFluent'; $smT = & $t 'SourceMenace'; $imT = & $t 'InfosMenaces'
    $ls = New-Object "Collections.Generic.List[$($smT.FullName)]"
    $ls.Add((& $nouv $smT @{ Nom = 'Feodo'; Type = 'IP'; Confiance = 'haute'; Entrees = 10; Statut = 'ok' }))
    $ls.Add((& $nouv $smT @{ Nom = 'X'; Type = 'IP'; Confiance = 'réputation'; Entrees = 0; Statut = "échec : HTTP 500`r`n" + [char]0x202E }))
    $ls.Add((& $nouv $smT @{ Nom = 'Y'; Type = 'Domaines'; Confiance = 'réputation'; Entrees = 0; Statut = 'désactivée (licence)' }))
    $im = & $nouv $imT @{ TotalIp = 10; TotalReseaux = 2; TotalDomaines = 3; MisAJour = '2026-11-10 06:00'; Sources = $ls }
    $rm = [string]$vm.GetMethod('Resume').Invoke($null, [object[]]@($im, $true, $false))
    Cas 'Menaces : liste en échec signalée, désactivée par choix non comptée' ($rm.Contains('1 liste(s) en échec') -and $vm.GetMethod('Gravite').Invoke($null, @($ls[2])) -eq 0 -and $vm.GetMethod('Gravite').Invoke($null, @($ls[1])) -eq 1) $rm
    Cas 'Menaces : étiquette courte (ok, désactivée, en échec), statut entier dans le détail ; réglage : état d''abord' (([string]$vm.GetMethod('Etiquette').Invoke($null, @($ls[2]))) -eq 'désactivée' -and ([string]$vm.GetMethod('Etiquette').Invoke($null, @($ls[1]))) -eq 'en échec' -and ([string]$vm.GetMethod('TexteReglage').Invoke($null, @('ListesRestreintes', $false))).StartsWith('Désactivé  ·  ') -and $fluentSrc.Contains('Text = VueMenacesFluent.TexteReglage(nom, actif), TextWrapping = TextWrapping.Wrap'))
    Cas 'Menaces : statut neutralisé dans le détail' (-not ((@($vm.GetMethod('Detail').Invoke($null, @($ls[1])) | ForEach-Object { $_.Texte }) -join '|') -match "[\u202E\r\n]"))
    Cas 'Menaces : avant lecture « Lecture en cours… », sans fichier « pas encore chargées », illisible rien de conclu' (([string]$vm.GetMethod('Resume').Invoke($null, [object[]]@($null, $false, $false))) -eq 'Lecture en cours…' -and ([string]$vm.GetMethod('Resume').Invoke($null, [object[]]@($null, $true, $false))) -eq 'Listes pas encore chargées.' -and ([string]$vm.GetMethod('Resume').Invoke($null, [object[]]@($null, $true, $true))).Contains('rien n''est conclu'))
    $guiSrc2 = [IO.File]::ReadAllText("$src\Gui.cs")
    Cas 'Menaces : config.json illisible, cases grisées et aucun réglage envoyé, dans les deux interfaces (audit de #139, S139-02)' ($guiSrc2.Contains('chkBlocageAuto.Enabled = chkRancongiciel.Enabled = chkListesRestreintes.Enabled = !illisible;') -and $guiSrc2.Contains('if (majCase || configIllisible) return;') -and $fluentSrc.Contains('if (lu && config != null && !configIllisible)') -and -not $guiSrc2.Contains('Commun.Lire<Config>("config.json") ?? new Config()'))
    Cas 'Protection : mêmes commandes dans les deux interfaces, seuls les trois réglages connus, chemin neutralisé dans la question' ($guiSrc2.Contains('if (Array.IndexOf(Reglages, reglage) < 0) return;') -and ([regex]::Matches($guiSrc2, 'Canal\.Visible\(q\.CheminOrigine\)')).Count -eq 3 -and $guiSrc2.Contains('ActionsProtection.Restaurer(lvQuarantaine.SelectedItems[0].Tag as ElementQuarantaine, false)') -and $fluentSrc.Contains('ActionsProtection.Restaurer(choix, true)') -and $fluentSrc.Contains('ActionsProtection.Debloquer(choix)'))
    Cas 'Blocages, Quarantaine et Menaces d''aujourd''hui : cellules neutralisées' ($guiSrc2.Contains('Canal.Visible(b.Cible), Canal.Visible(b.Raison)') -and $guiSrc2.Contains('Canal.Visible(q.CheminOrigine), Canal.Visible(q.Raison)') -and $guiSrc2.Contains('Canal.Visible(s.Statut) });'))
    Cas 'Protection : accès refusé pris pour illisible, jamais pour absent (audit de #142, S142-01)' ($guiSrc2.Contains('return !Directory.EnumerateFiles(Commun.Dossier, nom).Any();') -and $guiSrc2.Contains('catch { return false; }') -and $guiSrc2.Contains('if (Absent("config.json")) return new Config();') -and $fluentSrc.Contains('absent = ActionsProtection.Absent(nom);'))
    Cas 'Trafic : légende de la carte coupée proprement quand elle est étroite (captures de #141)' ($fluentSrc.Contains('legende.MaxLineCount = 1; legende.Trimming = TextTrimming.CharacterEllipsis;'))
    # Baseline et Pare-feu (U5b) : résumés honnêtes, gravités d'aujourd'hui, textes neutralisés, mêmes opérations
    $vbl = & $t 'VueBaselineFluent'; $ebT = & $t 'EtatBaseline'; $erT = & $t 'EtatRegle'
    $lr = New-Object "Collections.Generic.List[$($erT.FullName)]"
    $lr.Add((& $nouv $erT @{ Id = 'a'; Profil = 'recommandé'; Categorie = 'Réseau'; Titre = 'SMBv1'; Etat = 'non conforme'; Actuel = 'activé' + [char]0x202E; Attendu = 'désactivé'; Pourquoi = 'p'; Appliquee = $false }))
    $lr.Add((& $nouv $erT @{ Id = 'b'; Profil = 'renforcé'; Categorie = 'Comptes'; Titre = 'x'; Etat = 'non conforme'; Actuel = '1'; Attendu = '0'; Appliquee = $false }))
    $lr.Add((& $nouv $erT @{ Id = 'c'; Profil = 'recommandé'; Categorie = 'Audit'; Titre = 'y'; Etat = 'conforme'; Actuel = '1'; Attendu = '1'; Appliquee = $true }))
    $sc = New-Object 'Collections.Generic.Dictionary[string,int]'; $sc['recommandé'] = 50; $sc['journalisation'] = 100; $sc['renforcé'] = 0
    $eb = & $nouv $ebT @{ Regles = $lr; Scores = $sc; Message = "ok`r`n" + [char]0x202E }
    $rbl = [string]$vbl.GetMethod('Resume').Invoke($null, [object[]]@($eb, $true, $false))
    Cas 'Baseline : scores des trois profils, dernière opération neutralisée' ($rbl.StartsWith('Recommandé : 50 % conforme · journalisation 100 % · renforcé 0 %') -and -not ($rbl.Substring($rbl.IndexOf('Dernière')) -match "[\u202E\r]")) $rbl
    Cas 'Baseline : avant lecture « Lecture en cours… », pas encore évaluée dit, illisible rien de conclu' (([string]$vbl.GetMethod('Resume').Invoke($null, [object[]]@($null, $false, $false))) -eq 'Lecture en cours…' -and ([string]$vbl.GetMethod('Resume').Invoke($null, [object[]]@($null, $true, $false))).Contains('pas encore évalué') -and ([string]$vbl.GetMethod('Resume').Invoke($null, [object[]]@($null, $true, $true))).Contains('rien n''est conclu'))
    $rec = @($vbl.GetMethod('Regles').Invoke($null, [object[]]@($eb, 'recommandé')))
    Cas 'Baseline : règles du profil triées par catégorie ; non conforme du recommandé à surveiller, renforcé jamais' ((@($rec | ForEach-Object { $_.Id }) -join ',') -eq 'c,a' -and $vbl.GetMethod('Gravite').Invoke($null, @($lr[0])) -eq 1 -and $vbl.GetMethod('Gravite').Invoke($null, @($lr[1])) -eq 0) (@($rec | ForEach-Object { $_.Id }) -join ',')
    $dbl = @($vbl.GetMethod('Detail').Invoke($null, @($lr[0])))
    Cas 'Baseline : valeur actuelle neutralisée et en chasse fixe' (-not ((@($dbl | ForEach-Object { $_.Texte }) -join '|') -match "\u202E") -and ($dbl | Where-Object { $_.Titre -eq 'Actuel' }).Chasse)
    $vpf = & $t 'VueParefeuFluent'; $evrT = & $t 'EvenementRegle'; $exT = & $t 'Exposition'; $enT = & $t 'EntreeExposee'
    $piegeRegle = & $nouv $evrT @{ Heure = '10:00'; Operation = 'ajoutée'; Regle = 'Autoriser' + [char]0x202E + "`r`nmoi"; Sens = 'entrant'; Action = 'autoriser'; Ports = '445'; ProgrammeCible = 'C:\x' + [char]0x200B + '.exe'; Auteur = 'C:\Windows\evil.exe' }
    $toutes = & $nouv $evrT @{ Heure = '10:01'; Operation = 'toutes supprimées'; Regle = '*'; Sens = 'entrant'; Action = '' }
    $lpf = $vpf.GetMethod('Ligne', [type[]]@($evrT)).Invoke($null, @($piegeRegle))
    $txtPf = (@($lpf.Titre, $lpf.Sous) + @($lpf.Detail | ForEach-Object { $_.Texte })) -join '|'
    Cas 'Pare-feu : nom de règle, programme visé et auteur neutralisés ; entrée autorisée à surveiller, toutes supprimées critique' (-not ($txtPf -match "[\u202E\u200B\r\n]") -and $lpf.Gravite -eq 1 -and $vpf.GetMethod('Gravite', [type[]]@($evrT)).Invoke($null, @($toutes)) -eq 2) $txtPf
    $entree = & $nouv $enT @{ Source = '203.0.113.5'; PortLocal = 3389; Protocole = 'TCP'; Action = 'ACCEPTÉ'; Nombre = 4; Programme = 'svc' + [char]0x202E; Premiere = 'a'; Derniere = 'b' }
    $lent = $vpf.GetMethod('Ligne', [type[]]@($enT)).Invoke($null, @($entree))
    Cas 'Pare-feu : paquet entrant accepté critique, programme neutralisé' ($lent.Gravite -eq 2 -and -not ((@($lent.Sous) + @($lent.Detail | ForEach-Object { $_.Texte })) -join '|' -match "\u202E"))
    $rs = New-Object 'Collections.Generic.List[string]'; $rs.Add('port 3389 ouvert' + [char]0x202E)
    $expo = & $nouv $exT @{ Exposee = $true; Raisons = $rs; JournalPaquets = $false }
    $rpf = [string]$vpf.GetMethod('Resume').Invoke($null, [object[]]@($expo, $true, $false, 3))
    Cas 'Pare-feu : exposition dite et neutralisée, journal des paquets inactif dit, avant lecture rien de conclu' ($rpf.StartsWith('PC EXPOSÉ À INTERNET : port 3389 ouvert') -and -not ($rpf -match "\u202E") -and $rpf.Contains('Journal des paquets du pare-feu inactif') -and ([string]$vpf.GetMethod('Resume').Invoke($null, [object[]]@($null, $false, $false, 0))) -eq 'Lecture en cours…' -and ([string]$vpf.GetMethod('Resume').Invoke($null, [object[]]@($null, $true, $true, 0))).Contains('rien n''est conclu')) $rpf
    $guiSrc3 = [IO.File]::ReadAllText("$src\Gui.cs")
    # U5c-0 (constat C1 du dossier U5c) : rien de non vérifié n'est affiché comme « rien »
    $baseOk = 'journal des paquets du pare-feu : actif ; redirections de la box (UPnP) : 2 redirection(s) sur la box, dont 0 vers ce PC'
    $baseNon = 'journal des paquets du pare-feu : actif ; redirections de la box (UPnP) : pas encore vérifiées'
    $cst = { param($j, $b) [string]$vpf.GetMethod('Constat').Invoke($null, @((& $nouv $exT @{ Exposee = $false; JournalPaquets = [bool]$j; Base = $b }))) }
    $cOk = & $cst $true $baseOk; $cUpnp = & $cst $true $baseNon; $cJournal = & $cst $false $baseOk
    Cas 'Pare-feu : UPnP non vérifié, jamais « aucune redirection » ; contrôles incomplets dits (C1)' (-not $cUpnp.Contains('aucune redirection') -and $cUpnp.StartsWith('Rien relevé, contrôles incomplets') -and $cUpnp.Contains('redirections UPnP de la box (non vérifiées)')) $cUpnp
    Cas 'Pare-feu : journal inactif, jamais « aucun paquet » (C1)' (-not $cJournal.Contains('aucun paquet') -and $cJournal.Contains('journal des paquets du pare-feu inactif')) $cJournal
    Cas 'Pare-feu : tout vérifié, « rien relevé par les contrôles disponibles », jamais « aucune exposition » ni « protégé »' ($cOk.StartsWith('Rien relevé par les contrôles disponibles') -and -not (($cOk + $cUpnp + $cJournal) -match 'Aucune exposition|protégé|non exposé')) $cOk
    $rBase = [string]$vpf.GetMethod('Resume').Invoke($null, [object[]]@((& $nouv $exT @{ Exposee = $false; JournalPaquets = $true; Base = $baseNon + [char]0x202E }), $true, $false, 0))
    Cas 'Pare-feu : ce sur quoi repose le verdict (Base) affiché et neutralisé' ($rBase.Contains('Repose sur : journal des paquets') -and -not ($rBase -match "\u202E")) $rBase
    Cas 'Baseline : mêmes questions et même commande dans les deux interfaces, trois opérations seulement' ($guiSrc3.Contains('if (operation != "appliquer" && operation != "annuler" && operation != "evaluer") return false;') -and $guiSrc3.Contains('if (ActionsProtection.Baseline(operation, cible, question)) detailBaseline.Text') -and $fluentSrc.Contains('ActionsProtection.Baseline("appliquer", "renforcé", ActionsProtection.QuestionRenforce)') -and ([regex]::Matches($guiSrc3, 'Action = "baseline"')).Count -eq 1)
    Cas 'Baseline et Pare-feu d''aujourd''hui : cellules neutralisées' ($guiSrc3.Contains('Canal.Visible(r.Actuel), Canal.Visible(r.Attendu)') -and $guiSrc3.Contains('"Règle " + Canal.Visible(r.Operation) + " : " + Canal.Visible(r.Regle)') -and $guiSrc3.Contains('Canal.Visible(e.Programme)') -and $guiSrc3.Contains('(exp.Raisons ?? new List<string>()).Select(Canal.Visible)'))
    # Démarrage auto, Extensions, Vie privée (U6a) : filtres d'aujourd'hui, résumés honnêtes, textes neutralisés
    $vdm = & $t 'VueDemarrageFluent'; $edT = & $t 'EntreeDemarrage'
    $lde = New-Object "Collections.Generic.List[$($edT.FullName)]"
    $lde.Add((& $nouv $edT @{ Cle = 'a'; Categorie = 'Run'; Nom = 'zz'; Commande = 'c'; Cible = 'C:\a.exe'; Signataire = 'Microsoft Windows'; Remarque = ''; Depuis = 'x' }))
    $lde.Add((& $nouv $edT @{ Cle = 'b'; Categorie = 'Run'; Nom = 'piège' + [char]0x202E; Commande = "cmd /c`r`ncalc"; Cible = 'C:\b.exe'; Signataire = ''; Remarque = 'nouvelle'; Depuis = 'x' }))
    $lde.Add((& $nouv $edT @{ Cle = 'c'; Categorie = 'Tâche'; Nom = 'aa'; Commande = 'c'; Cible = 'C:\c.exe'; Signataire = 'Windows (catalogue)'; Remarque = 'modifiée'; Depuis = 'x' }))
    $flt = { param($m) (@($vdm.GetMethod('Filtrer').Invoke($null, [object[]]@($lde.PSObject.BaseObject, [bool]$m)) | ForEach-Object { $_.Cle }) -join ',') }
    Cas 'Démarrage : Microsoft masqué sauf remarque (filtre d''aujourd''hui), remarques d''abord' ((& $flt $true) -eq 'b,c' -and (& $flt $false) -eq 'b,c,a') "$(& $flt $true) / $(& $flt $false)"
    $txtD = (@($vdm.GetMethod('Detail').Invoke($null, @($lde[1])) | ForEach-Object { $_.Texte }) + @([string]$vdm.GetMethod('Signataire').Invoke($null, @($lde[1])))) -join '|'
    Cas 'Démarrage : nom et commande neutralisés, commande en chasse fixe, non signé dit' (-not ($txtD -match "[\u202E\r\n]") -and $txtD.Contains('non signé') -and (@($vdm.GetMethod('Detail').Invoke($null, @($lde[1])))[1]).Chasse) $txtD
    $copieD = [string]$vdm.GetMethod('Copie').Invoke($null, @($lde[1]))
    Cas 'Démarrage : copie des colonnes d''aujourd''hui, valeur d''origine échappée' ($copieD -ceq ("Run`tpiège\u202E`tcmd /c\r\ncalc`tNON SIGNÉ`tnouvelle`tx")) $copieD
    Cas 'Démarrage : avant lecture « Lecture en cours… », illisible sans liste rien de conclu, décompte des remarques' (([string]$vdm.GetMethod('Resume').Invoke($null, [object[]]@($lde.PSObject.BaseObject, 2, $false, $false))) -eq 'Lecture en cours…' -and ([string]$vdm.GetMethod('Resume').Invoke($null, [object[]]@($lde.PSObject.BaseObject, 2, $true, $false))).Contains('3 entrée(s) de démarrage, dont 2 nouvelle(s)'))
    $vex = & $t 'VueExtensionsFluent'; $xT = & $t 'Extension'
    $lx = New-Object "Collections.Generic.List[$($xT.FullName)]"
    $lx.Add((& $nouv $xT @{ Navigateur = 'Edge'; Id = 'i1'; Nom = 'ok'; Version = '1'; Permissions = 'storage'; Dangereuse = $false; Depuis = 'x' }))
    $lx.Add((& $nouv $xT @{ Navigateur = 'Chrome'; Id = 'i2'; Nom = 'espion' + [char]0x200B; Version = "2`r`n"; Permissions = '<all_urls>, cookies'; Dangereuse = $true; Depuis = 'x' }))
    $trx = @($vex.GetMethod('Trier').Invoke($null, [object[]](, $lx.PSObject.BaseObject)))
    $txtX = (@($vex.GetMethod('Detail').Invoke($null, @($lx[1])) | ForEach-Object { $_.Texte })) -join '|'
    Cas 'Extensions : permissions sensibles d''abord, détail neutralisé, décompte dit' ($trx[0].Id -eq 'i2' -and -not ($txtX -match "[\u200B\r\n]") -and ([string]$vex.GetMethod('Resume').Invoke($null, [object[]]@($lx.PSObject.BaseObject, $true, $false))).Contains('2 extension(s), dont 1 avec des permissions sensibles')) $txtX
    $vv = & $t 'VueVieFluent'; $upT = & $t 'UsagePeripherique'; $odT = & $t 'OutilDistant'; $ecT = & $t 'Ecoute'
    $lu2 = New-Object "Collections.Generic.List[$($upT.FullName)]"
    $lu2.Add((& $nouv $upT @{ Peripherique = 'Caméra'; Programme = 'Zoom'; Chemin = 'C:\z.exe'; DernierDebut = '2026-11-10 09:00'; DerniereFin = '2026-11-10 09:30'; EnCours = $false }))
    $lu2.Add((& $nouv $upT @{ Peripherique = 'Caméra'; Programme = 'zoom'; Chemin = 'C:\z.exe'; DernierDebut = '2026-11-10 10:00'; DerniereFin = ''; EnCours = $true }))
    $lu2.Add((& $nouv $upT @{ Peripherique = 'Micro'; Programme = 'esp' + [char]0x202E; Chemin = 'C:\e.exe'; DernierDebut = '2026-11-09'; DerniereFin = '2026-11-09'; EnCours = $false }))
    $lo = New-Object "Collections.Generic.List[$($odT.FullName)]"; $lo.Add((& $nouv $odT @{ Nom = 'AnyDesk'; Pid = 77; Chemin = 'C:\ad.exe'; Signataire = 's'; Depuis = '10:00' }))
    $le = New-Object "Collections.Generic.List[$($ecT.FullName)]"; $le.Add((& $nouv $ecT @{ Programme = 'srv' + [char]0x202E; Chemin = 'C:\s.exe'; Pid = 9; Adresse = '0.0.0.0'; Port = 8080; Signataire = '-'; Depuis = '09:00' }))
    $etV = & $nouv (& $t 'Etat') @{ Peripheriques = $lu2; OutilsDistants = $lo; Ecoutes = $le; BureauADistance = $true; MisAJour = '2026-11-10 10:05' }
    $us = @($vv.GetMethod('Usages').Invoke($null, @($etV)))
    Cas 'Vie privée : une ligne par programme et périphérique, l''usage en cours d''abord (comme aujourd''hui)' ($us.Count -eq 2 -and $us[0].EnCours) "$($us.Count)"
    $l0v = @($vv.GetMethod('Lignes').Invoke($null, [object[]]@($etV, 0))); $l1v = @($vv.GetMethod('Lignes').Invoke($null, [object[]]@($etV, 1))); $l2v = @($vv.GetMethod('Lignes').Invoke($null, [object[]]@($etV, 2)))
    $txtV = (@($l0v + $l1v + $l2v | ForEach-Object { $_.Titre; $_.Sous; $_.Detail | ForEach-Object { $_.Texte } })) -join '|'
    Cas 'Vie privée : caméra en cours et RDP et outil distant critiques, port non signé à surveiller, textes neutralisés' ($l0v[0].Gravite -eq 2 -and $l1v[0].Gravite -eq 2 -and $l1v[1].Gravite -eq 2 -and $l2v[0].Gravite -eq 1 -and -not ($txtV -match "\u202E") -and $l2v[0].Chemin -eq 'C:\s.exe') $txtV
    $rv = [string]$vv.GetMethod('Resume').Invoke($null, [object[]]@($etV, $true, $false, $null))
    Cas 'Vie privée : résumé en chiffres, avant lecture rien de conclu' ($rv.StartsWith('Caméra ou micro utilisés en ce moment : 1. Bureau à distance : ACTIVÉ. Outils de prise en main en cours : 1. Ports ouverts en attente de connexions entrantes : 1.') -and ([string]$vv.GetMethod('Resume').Invoke($null, [object[]]@($null, $false, $false, $null))) -eq 'Lecture en cours…') $rv
    $guiSrc4 = [IO.File]::ReadAllText("$src\Gui.cs")
    Cas 'Démarrage : seule la quarantaine part de la coquille pour une entrée de démarrage' ($guiSrc4.Contains('else if (element is EntreeDemarrage && action == "quarantaine") AgirSur(element, action);'))
    Cas 'Démarrage, Vie privée et Extensions d''aujourd''hui : cellules et info-bulles neutralisées' ($guiSrc4.Contains('Canal.Visible(e.Nom), Canal.Visible(e.Commande)') -and $guiSrc4.Contains('ToolTipText = Canal.Visible(e.Cible)') -and $guiSrc4.Contains('Canal.Visible(u.Programme), Canal.Visible(u.Chemin)') -and $guiSrc4.Contains('Canal.Visible(o.Nom) + "  ● EN COURS"') -and $guiSrc4.Contains('Canal.Visible(e.Programme), Canal.Visible(e.Adresse)') -and $guiSrc4.Contains('Canal.Visible(e.Navigateur), Canal.Visible(e.Nom), Canal.Visible(e.Version), Canal.Visible(e.Permissions)'))
    $reponsesSrc = [IO.File]::ReadAllText("$src\Reponses.cs"); $incidentsSrc = [IO.File]::ReadAllText("$src\Incidents.cs")
    Cas 'Incidents et Réponses : la coquille et la page d''aujourd''hui passent par les mêmes actions' ($fluentSrc.Contains('ActionsIncidents.Passer(i, vers, motif, note)') -and $fluentSrc.Contains('ActionsReponses.Recuperer(x)') -and $incidentsSrc.Contains('ActionsIncidents.Passer(Choisi(), vers, motif, note)') -and $reponsesSrc.Contains('ActionsReponses.Recuperer(Choisie())') -and ([regex]::Matches($fluentSrc + $incidentsSrc + $reponsesSrc, 'Canal\.Executer\(')).Count -eq 2)
    # Chaînes du code seulement (les commentaires peuvent citer la règle)
    $chainesProtege = @([regex]::Matches($fluentSrc, '"[^"\r\n]*(prot[eé]g[eé]|protected)[^"\r\n]*"') | ForEach-Object Value)
    Cas "Vue d'ensemble : jamais « protégé » dans les textes du pilote" ($chainesProtege.Count -eq 0) ($chainesProtege -join ' ; ')

    # L'assistant élevé ne charge pas WPF : Main ne nomme aucun type WPF, le pilote est dans une méthode jamais intégrée
    $g = [IO.File]::ReadAllText("$src\Gui.cs") -replace "`r`n", "`n"
    $main = $g.Substring($g.IndexOf('static int Main(string[] args)'))
    $main = $main.Substring(0, $main.IndexOf("`n        }`n"))
    $nommes = @([regex]::Matches($main, 'System\.Windows\.(Application|Window|Controls|Media)|Coquille|Jetons') | ForEach-Object Value)
    Cas 'assistant élevé : Main ne nomme aucun type WPF' ($nommes.Count -eq 0 -and $main.Contains('if (args.Contains("--fluent")) return LancerPilote();')) "types nommés : $($nommes -join ', ') ; appel du pilote : $($main.Contains('return LancerPilote();'))"
    $programme = $asm.GetType('DeR4Tizer.Programme')
    $lp = $programme.GetMethod('LancerPilote', [Reflection.BindingFlags]'Static,NonPublic')
    Cas 'assistant élevé : pilote dans une méthode jamais intégrée (NoInlining)' ($lp -ne $null -and ($lp.MethodImplementationFlags -band [Reflection.MethodImplAttributes]::NoInlining))
    # Rendu logiciel demandé avant la création de l'application (VM de test : le rendu matériel laissait la fenêtre blanche)
    $pilote = $g.Substring($g.IndexOf('static int LancerPilote()'))
    $pilote = $pilote.Substring(0, $pilote.IndexOf("`n        }`n"))
    $iRendu = $pilote.IndexOf('RenderOptions.ProcessRenderMode = System.Windows.Interop.RenderMode.SoftwareOnly')
    Cas 'pilote : rendu logiciel demandé avant l''application WPF' ($iRendu -ge 0 -and $iRendu -lt $pilote.IndexOf('new System.Windows.Application'))
    Cas 'pilote : « Quitter » de la zone de notification ferme aussi la coquille' ($pilote.Contains('ancienne.FormClosed += (s, e) => { coquille.Quitter(); app.Shutdown(); };') -and $pilote.IndexOf('FormClosed') -lt $pilote.IndexOf('app.Run(') -and $pilote.Contains('ShutdownMode.OnExplicitShutdown'))
    # Pages d'aujourd'hui : palette de la coquille avec --fluent, palette néon sans (processus séparés : la palette est fixée
    # au chargement, d'après la ligne de commande du processus)
    $sonde = Join-Path $travail 'sonde-theme.ps1'
    Set-Content $sonde -Encoding UTF8 -Value @'
param([string]$Exe)
$a = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($Exe))
$t = $a.GetType('DeR4Tizer.Theme')
$f = { param($n) $t.GetField($n, [Reflection.BindingFlags]'Static,Public').GetValue($null) }
$fond = & $f 'Fond'; $cyan = & $f 'Cyan'; $mag = & $f 'Magenta'
$casse = $t.GetMethod('Casse').Invoke($null, @('Alertes'))
$titre = $t.GetMethod('TitreDePage').Invoke($null, [object[]]@('Alertes', [Windows.Forms.Padding]::Empty))
# Visibilité demandée (état interne) : Visible rend faux pour tout contrôle sans parent affiché
$visible = [Windows.Forms.Control].GetMethod('GetState', [Reflection.BindingFlags]'NonPublic,Instance').Invoke($titre, @(2))
"$(& $f 'Fluent')|{0:X2}{1:X2}{2:X2}|{3:X2}{4:X2}{5:X2}|{6:X2}{7:X2}{8:X2}|$casse|$visible|$((& $f 'TitrePage').Name)" -f $fond.R, $fond.G, $fond.B, $cyan.R, $cyan.G, $cyan.B, $mag.R, $mag.G, $mag.B
'@
    Add-Type -AssemblyName System.Windows.Forms
    $avec = (powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.Windows.Forms; & '$sonde' -Exe '$out'" --fluent | Select-Object -Last 1)
    $sans = (powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.Windows.Forms; & '$sonde' -Exe '$out'" | Select-Object -Last 1)
    Cas 'pages d''aujourd''hui avec --fluent : palette neutre, un seul accent, pas de capitales, titre « // » caché, Segoe UI' ($avec -eq 'True|141518|3BA7F0|3BA7F0|Alertes|False|Segoe UI Semibold') $avec
    Cas 'pages d''aujourd''hui sans --fluent : palette néon inchangée' ($sans -like 'False|0A0E14|00E5FF|FF2BD6|ALERTES|True|*') $sans
    # Rendu hors écran : coquille construite sans Show(), contenu mesuré, arrangé et rendu
    $sansPage = [Func[string, Windows.Forms.Control]] { param($cle) $null }
    foreach ($code in 'fr', 'en') {
        $langue.GetField('En').SetValue($null, $code -eq 'en')
        foreach ($page in "Vue d'ensemble", 'Connexions', 'Incidents', 'Réponses en cours', 'Santé', 'Détection', 'Événements', 'Chaînes', 'Trafic', 'Blocages', 'Quarantaine', 'Menaces', 'Baseline', 'Pare-feu', 'Démarrage auto', 'Extensions', 'Vie privée') {
            $fen = [Activator]::CreateInstance($coquille, [Reflection.BindingFlags]'Instance,Public,NonPublic', $null, @(, $sansPage), $null)
            $coquille.GetMethod('Ouvrir', [Reflection.BindingFlags]'Instance,NonPublic').Invoke($fen, @($page))
            $natif = @{ 'Incidents' = 'PageIncidentsFluent'; 'Réponses en cours' = 'PageReponsesFluent'; 'Santé' = 'PageSanteFluent'; 'Détection' = 'PageDetectionFluent'; 'Événements' = 'PageEvenementsFluent'; 'Connexions' = 'PageConnexionsFluent'; 'Chaînes' = 'PageChainesFluent'; 'Trafic' = 'PageTraficFluent'; 'Blocages' = 'PageBlocagesFluent'; 'Quarantaine' = 'PageQuarantaineFluent'; 'Menaces' = 'PageMenacesFluent'; 'Baseline' = 'PageBaselineFluent'; 'Pare-feu' = 'PageParefeuFluent'; 'Démarrage auto' = 'PageDemarrageFluent'; 'Extensions' = 'PageExtensionsFluent'; 'Vie privée' = 'PageVieFluent' }[$page]
            if ($natif) {
                $zoneC = $coquille.GetField('zone', [Reflection.BindingFlags]'Instance,NonPublic').GetValue($fen).Content
                Cas "$page $code : page native WPF (U2c)" ($zoneC.GetType().Name -eq $natif) $zoneC.GetType().Name
            }
            $ouvertes = $coquille.GetMethod('Ouvertes', [Reflection.BindingFlags]'Instance,NonPublic').Invoke($fen, @())
            Cas "navigation $code : une seule entrée ouverte après « $page »" ($ouvertes -eq 1) "$ouvertes"
            $zt = [Windows.SystemParameters]::WorkArea
            Cas "fenêtre $code : tient dans la zone de travail ($([int]$fen.Width) x $([int]$fen.Height) pour $([int]$zt.Width) x $([int]$zt.Height))" ($fen.Width -le $zt.Width -and $fen.Height -le $zt.Height -and $fen.Width -ge $fen.MinWidth)
            $kNav = $coquille.GetMethod('ContrasteNavigation', [Reflection.BindingFlags]'Instance,NonPublic').Invoke($fen, @())
            Cas "navigation $code : couleur réellement donnée aux libellés, $([math]::Round($kNav, 2)):1 sur le panneau (4,5 au moins)" ($kNav -ge 4.5)
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
