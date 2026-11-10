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
    Cas 'Détection : page d''aujourd''hui neutralisée aussi, IPS et dossier des règles par les mêmes méthodes' ($reseauSrc.Contains('valeurs = valeurs.Select(v => Canal.Visible(v ?? "")).ToArray();') -and $reseauSrc.Contains('VueDetection.ChangerIps(chkIps.Checked);') -and $fluentSrc.Contains('VueDetection.ChangerIps(!ips)') -and ([regex]::Matches($reseauSrc, 'Action = "config", Cible = "Ips"')).Count -eq 1)
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
        foreach ($page in "Vue d'ensemble", 'Connexions', 'Incidents', 'Réponses en cours', 'Santé', 'Détection') {
            $fen = [Activator]::CreateInstance($coquille, [Reflection.BindingFlags]'Instance,Public,NonPublic', $null, @(, $sansPage), $null)
            $coquille.GetMethod('Ouvrir', [Reflection.BindingFlags]'Instance,NonPublic').Invoke($fen, @($page))
            $natif = @{ 'Incidents' = 'PageIncidentsFluent'; 'Réponses en cours' = 'PageReponsesFluent'; 'Santé' = 'PageSanteFluent'; 'Détection' = 'PageDetectionFluent' }[$page]
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
