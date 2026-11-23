# Compile l'interface et vérifie que chaque confirmation de Canal.Decrire (assistant élevé) neutralise un texte piégé
# venu de la commande ou des fichiers lus pour la décrire (inversion du sens d'écriture, retour à la ligne injecté),
# en français et en anglais, branches « élément trouvé » comprises (quarantaine.json et alertes.json piégés dans un
# dossier de données de test). Code de sortie 1 si un cas n'est pas neutralisé. Constat T-16 : présentation de la fenêtre
# (titre d'une table fixe, liste, bandeau, hauteur bornée, compte à rebours) ; -Rendus : rendus hors écran des cas des maquettes.
# Usage (Windows PowerShell 5.1) : powershell -File tests\test-confirmations.ps1 [-Depot <racine du dépôt>] [-Rendus <dossier des PNG>]
param([string]$Depot = (Split-Path $PSScriptRoot), [string]$Rendus = '')
$ErrorActionPreference = 'Stop'
$src = Join-Path $Depot 'src'
$travail = Join-Path $env:TEMP ("d4t-confirmations-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $travail | Out-Null
try {
    $out = Join-Path $travail 'interface.exe'
    $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $wpf = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\WPF'
    & $csc /nologo /platform:anycpu /codepage:65001 /target:winexe /r:System.dll /r:System.Core.dll /r:System.Web.Extensions.dll /r:System.ServiceProcess.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll "/r:$wpf\PresentationFramework.dll" "/r:$wpf\PresentationCore.dll" "/r:$wpf\WindowsBase.dll" /r:System.Xaml.dll "/out:$out" "$src\Commun.cs" "$src\Langue.cs" "$src\Theme.cs" "$src\Gui.cs" "$src\Reglages.cs" "$src\Siem.cs" "$src\Incidents.cs" "$src\Reponses.cs" "$src\Trafic.cs" "$src\Reseau.cs" "$src\Fluent.cs" "/resource:$src\carte-pays.txt,carte-pays.txt" "/resource:$src\deR4Tizer.ico,deR4Tizer.ico" | Out-Null
    if ($LASTEXITCODE) { throw 'compilation' }
    # Chargé depuis ses octets : l'exe n'est pas verrouillé et le dossier de travail s'efface à la fin
    $asm = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($out))
    $canal = $asm.GetType('DeR4Tizer.Canal'); $cmdT = $asm.GetType('DeR4Tizer.Commande')
    $commun = $asm.GetType('DeR4Tizer.Commun'); $langue = $asm.GetType('DeR4Tizer.L')

    $piege = "C:\x\" + [char]0x202E + "txt.exe" + "`r`nLIGNE-INJECTEE"
    # Dossier de données de test : un élément de quarantaine et une alerte dont chaque texte est piégé
    $donnees = Join-Path $travail 'donnees'; New-Item -ItemType Directory -Path $donnees | Out-Null
    Add-Type -AssemblyName System.Web.Extensions
    $js = New-Object Web.Script.Serialization.JavaScriptSerializer
    [IO.File]::WriteAllText((Join-Path $donnees 'quarantaine.json'), $js.Serialize(@(@{ Id = 'q1'; CheminOrigine = $piege; Raison = $piege; Date = ''; Taille = 0 })))
    [IO.File]::WriteAllText((Join-Path $donnees 'alertes.json'), $js.Serialize(@(@{ Id = 'a1'; Processus = $piege; Destination = $piege; Raisons = $piege })))
    $commun.GetField('Dossier').SetValue($null, $donnees)

    # Action, et champs posés en plus de Cible = Ip = Valeur = texte piégé
    $cas = @(
        @{ A = 'bloquer' }, @{ A = 'bloquer'; NomDns = $piege; Nom = 'bloquer (nom DNS)' }, @{ A = 'bloquerIp' }, @{ A = 'debloquer' },
        @{ A = 'config' }, @{ A = 'tuer' }, @{ A = 'tuerChaine' }, @{ A = 'suspendre' }, @{ A = 'reprendre' }, @{ A = 'quarantaine' },
        @{ A = 'restaurer' }, @{ A = 'restaurer'; Cible = 'q1'; Nom = 'restaurer (élément trouvé)' },
        @{ A = 'restaurerRepli' }, @{ A = 'restaurerRepli'; Cible = 'q1'; Nom = 'restaurerRepli (élément trouvé)' },
        @{ A = 'isolerProgramme' }, @{ A = 'baseline' },
        @{ A = 'exception' }, @{ A = 'exception'; Cible = 'a1'; Nom = 'exception (alerte trouvée)' },
        @{ A = 'majConfig'; Valeur = '{"Auto":false,"Url":"https://exemple.invalid/' + [char]0x202E + 'x\r\nLIGNE-INJECTEE"}' },
        @{ A = 'autoriserLecteur' }, @{ A = "inconnue" + [char]0x202E + "`nLIGNE-INJECTEE"; Nom = 'action inconnue' }
    )
    $ko = 0; $n = 0
    foreach ($en in $false, $true) {
        $langue.GetField('En').SetValue($null, $en)
        foreach ($k in $cas) {
            $n++
            $nom = "$(if ($k.Nom) { $k.Nom } else { $k.A }) [$(if ($en) { 'en' } else { 'fr' })]"
            $c = [Activator]::CreateInstance($cmdT)
            $c.Action = $k.A; $c.Cible = $piege; $c.Ip = $piege; $c.Valeur = $piege; $c.Chemin = $piege; $c.Creation = [long]133000000000000000
            if ($k.ContainsKey('Cible')) { $c.Cible = $k.Cible }
            if ($k.ContainsKey('NomDns')) { $c.NomDns = $k.NomDns }
            if ($k.ContainsKey('Valeur')) { $c.Valeur = $k.Valeur }
            try { $t = $canal.GetMethod('Decrire').Invoke($null, @($c)) } catch { "$nom : EXCEPTION $($_.Exception.InnerException.Message)"; $ko++; continue }
            # Branche « élément trouvé » : le texte piégé du fichier doit apparaître (neutralisé), sinon le cas ne prouve rien
            if ($k.ContainsKey('Cible') -and $t -notmatch 'txt\.exe') { "$nom : élément non trouvé, cas sans valeur"; $ko++; continue }
            $mauvais = @($t.ToCharArray() | Where-Object { $_ -eq [char]0x202E -or $_ -eq "`r" }).Count -gt 0 -or $t -match "`nLIGNE-INJECTEE"
            if ($mauvais) { $ko++; "$nom : NON NEUTRALISÉ" } else { "$nom : ok" }
        }
    }
    "bilan : $ko cas non neutralisé(s) sur $n"

    # Fenêtre de confirmation (S60-06/07) : texte entier, renvoi à la ligne, défilement, « Annuler » par défaut ; fin de
    # l'hôte à part ; adresse de mise à jour vide présentée comme l'adresse par défaut (S68b-02). Construite, jamais affichée
    Add-Type -AssemblyName System.Windows.Forms
    $langue.GetField('En').SetValue($null, $false)
    $kof = 0
    function Verifier-Fenetre([string]$nom, [scriptblock]$controle) {
        $r = try { & $controle } catch { "exception : $($_.Exception.Message)" }
        if ($r -eq $true) { "$nom : ok" } else { $script:kof++; "$nom : ÉCHEC ($r)" }
    }
    # Hôte d'un seul tenant d'environ 250 caractères (labels de 60, sous la limite DNS de 63)
    $long = 'https://' + ((('a' * 60) + '.') * 4) + 'attaquant.test/sujet'
    $c = [Activator]::CreateInstance($cmdT); $c.Action = 'notifications'
    $c.Valeur = '{"Config":{"Ntfy":true},"NtfyUrl":"' + $long + '"}'
    $texte = $canal.GetMethod('Decrire').Invoke($null, @($c))
    # Phase 6, PR 6.3 : l'identité vient de la lecture de l'instance administrateur, jamais de la commande reçue
    # Une heure de création portée par la commande n'est jamais crue : différente de celle lue, refus (PID réutilisé,
    # relecture de #120, D1) ; absente, l'heure lue la remplace
    $c = [Activator]::CreateInstance($cmdT); $c.Action = 'tuer'; $c.Cible = "$PID"; $c.Chemin = 'C:\faux.exe'; $c.Creation = [long]1
    $refusHeure = try { $canal.GetMethod('PreparerIdentite').Invoke($null, @($c)); $false } catch { $true }
    Verifier-Fenetre 'identité : heure fournie différente de celle lue, refus' { $refusHeure }
    $c = [Activator]::CreateInstance($cmdT); $c.Action = 'tuer'; $c.Cible = "$PID"; $c.Chemin = 'C:\faux.exe'
    $canal.GetMethod('PreparerIdentite').Invoke($null, @($c)) | Out-Null
    $lu = (Get-Process -Id $PID).Path
    Verifier-Fenetre 'identité : chemin et heure lus, valeurs de la commande remplacées' { $c.Chemin -eq $lu -and $c.Creation -gt 1 }
    $texteI = $canal.GetMethod('Decrire').Invoke($null, @($c))
    Verifier-Fenetre 'identité : la confirmation montre le PID, le nom, le chemin, la signature et l''heure' { $texteI.Contains("$PID") -and $texteI.Contains($lu) -and $texteI.Contains((Split-Path $lu -Leaf)) -and $texteI -match 'Signature' -and $texteI -match '\d{4}-\d\d-\d\d \d\d:\d\d:\d\d' }
    $c = [Activator]::CreateInstance($cmdT); $c.Action = 'tuer'; $c.Cible = '4000000000'
    $refus = try { $canal.GetMethod('PreparerIdentite').Invoke($null, @($c)); $false } catch { $true }
    Verifier-Fenetre 'identité : PID invalide, exception, rien à envoyer' { $refus }
    $c = [Activator]::CreateInstance($cmdT); $c.Action = 'debloquer'; $c.Cible = 'x'; $c.Chemin = 'C:\faux.exe'
    $canal.GetMethod('PreparerIdentite').Invoke($null, @($c)) | Out-Null
    Verifier-Fenetre 'identité : autre action, aucun champ posé' { -not $c.Chemin -and -not $c.Creation }
    $c = [Activator]::CreateInstance($cmdT); $c.Action = 'tuer'; $c.Cible = '1234'
    Verifier-Fenetre 'identité : non lue, la confirmation le dit' { $canal.GetMethod('Decrire').Invoke($null, @($c)) -match 'non lue|not read' }
    Verifier-Fenetre 'notifications : fin de l''hôte à part' { if ($texte -match "`n\s+l'hôte se termine par : attaquant\.test(`n|$)") { $true } else { $texte } }
    $f = $canal.GetMethod('FenetreConfirmation').Invoke($null, @('Modifier la remontée des alertes', $texte, $false, $false))
    try {
        $zone = $f.Controls.Find('Texte', $true)[0]; $annuler = $f.Controls.Find('Annuler', $true)[0]; $continuer = $f.Controls.Find('Continuer', $true)[0]
        # Constat T-16 : la zone montre les lignes de Decrire en liste (contrôle ligne à ligne plus bas)
        Verifier-Fenetre 'fenêtre : texte entier, sans troncature' { $zone.Text -eq $canal.GetMethod('TexteZoneConfirmation').Invoke($null, @(, $canal.GetMethod('LignesConfirmation').Invoke($null, @($texte)))) -and $zone.Text.Contains(((('a' * 60) + '.') * 4) + 'attaquant.test') }
        Verifier-Fenetre 'fenêtre : renvoi à la ligne et défilement, lecture seule' { $zone.Multiline -and $zone.WordWrap -and $zone.ReadOnly -and $zone.ScrollBars -eq 'Vertical' }
        Verifier-Fenetre 'fenêtre : « Annuler » par défaut (Entrée, Échap)' { $f.AcceptButton -eq $annuler -and $f.CancelButton -eq $annuler -and $f.ActiveControl -eq $annuler -and $annuler.DialogResult -eq 'Cancel' }
        Verifier-Fenetre 'fenêtre : « Continuer » seul renvoie Oui' { $continuer.DialogResult -eq 'Yes' }
        Verifier-Fenetre 'fenêtre : « Continuer » désarmé à l''ouverture (armé 1 s après l''affichage)' { -not $continuer.Enabled }
    } finally { $f.Dispose() }
    # Armement (fenêtre montrée hors de l'écran, jamais à l'emplacement visible) : inactif à l'affichage, actif 1 s après
    # l'activation, désarmé quand la fenêtre perd le premier plan, réarmé 1 s après le retour (S69-02, S69-03).
    # Déterministe (relecture de #134, R1) : avant, le test confiait le premier plan au vrai Windows (Show, Activate), qui ne
    # l'accorde pas à un processus qui ne l'a pas (échecs au hasard, environ 1 sur 20) et attendait des durées fixes trop
    # justes. Les événements d'activation sont levés directement (OnActivated, OnDeactivate, ceux qu'écoute la fenêtre) ;
    # l'armement est attendu jusqu'à 5 s, et jamais accepté avant 0,9 s (le minuteur ne part pas en avance).
    $f = $canal.GetMethod('FenetreConfirmation').Invoke($null, @('x', 'essai', $false, $false))
    try {
        $f.StartPosition = 'Manual'; $f.Location = New-Object Drawing.Point(-4000, -4000); $f.ShowInTaskbar = $false
        $k = $f.Controls.Find('Continuer', $true)[0]
        $drapeaux = [Reflection.BindingFlags]'NonPublic,Instance'
        $activer = { [Windows.Forms.Form].GetMethod('OnActivated', $drapeaux).Invoke($f, @([EventArgs]::Empty)) }
        $desactiver = { [Windows.Forms.Form].GetMethod('OnDeactivate', $drapeaux).Invoke($f, @([EventArgs]::Empty)) }
        function Attendre([int]$ms) { $fin = [DateTime]::UtcNow.AddMilliseconds($ms); while ([DateTime]::UtcNow -lt $fin) { [Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 20 } }
        # Délai jusqu'à l'armement en ms, ou -1 s'il n'arrive pas avant $max
        function Attendre-Arme([int]$max) {
            $chrono = [Diagnostics.Stopwatch]::StartNew()
            while (-not $k.Enabled -and $chrono.ElapsedMilliseconds -lt $max) { [Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 10 }
            if ($k.Enabled) { [int]$chrono.ElapsedMilliseconds } else { -1 }
        }
        # Fenêtre jamais montrée : Windows ne lui envoie aucune activation réelle, qui arrêtait le minuteur au hasard
        # (vu 3 fois sur 25 avec Show) ; le minuteur et les événements fonctionnent sans affichage
        $a0 = $k.Enabled
        & $activer; $a1 = $k.Enabled; $t1 = Attendre-Arme 5000
        & $desactiver; $a2 = $k.Enabled; Attendre 1300; $a3 = $k.Enabled
        & $activer; $a4 = $k.Enabled; $t5 = Attendre-Arme 5000
        # Nouvelle activation alors qu'il est armé (fenêtre reprise au premier plan sans perte vue) : désarmé de nouveau
        & $activer; $a6 = $k.Enabled; $t7 = Attendre-Arme 5000
        Verifier-Fenetre 'armement : inactif à l''affichage, actif après 1 s' { if (-not $a0 -and -not $a1 -and $t1 -ge 900) { $true } else { "départ : $a0 ; à l'activation : $a1 ; armé après $t1 ms" } }
        Verifier-Fenetre 'armement : désarmé hors du premier plan, réarmé 1 s après le retour' { if (-not $a2 -and -not $a3 -and -not $a4 -and $t5 -ge 900) { $true } else { "perte : $a2/$a3 ; retour : $a4, armé après $t5 ms" } }
        Verifier-Fenetre 'armement : toute activation désarme, même armé, puis réarme après 1 s' { if (-not $a6 -and $t7 -ge 900) { $true } else { "à l'activation : $a6 ; armé après $t7 ms" } }
    } finally { $f.Dispose() }
    $c = [Activator]::CreateInstance($cmdT); $c.Action = 'majConfig'; $c.Valeur = '{"Auto":false,"Url":""}'
    $t = $canal.GetMethod('Decrire').Invoke($null, @($c))
    Verifier-Fenetre 'majConfig : adresse vide = adresse par défaut, affichée' { $t -match 'adresse par défaut https://github\.com/' }
    $c.Valeur = '{"Auto":true,"Url":"https://attaquant.test/m.json"}'
    $t = $canal.GetMethod('Decrire').Invoke($null, @($c))
    Verifier-Fenetre 'majConfig : autre adresse signalée' { $t -match 'ADRESSE MODIFIÉE https://attaquant\.test/m\.json' -and $t -match "l'hôte se termine par : attaquant\.test" }
    # Signes combinants (S69-04) : remplacés, ils ne s'empilent plus sur les lignes voisines
    $c = [Activator]::CreateInstance($cmdT); $c.Action = 'quarantaine'; $c.Cible = 'C:\x\a' + ([string][char]0x0489 * 50) + ([string][char]0x0301 * 50)
    $t = $canal.GetMethod('Decrire').Invoke($null, @($c))
    Verifier-Fenetre 'signes combinants neutralisés' { -not ($t.ToCharArray() | Where-Object { [Globalization.CharUnicodeInfo]::GetUnicodeCategory($_) -in 'NonSpacingMark', 'EnclosingMark' }) }
    # Audit du 2026-11-23, A-1-5 : parcours par point de code ; étiquette U+E0041, sélecteur U+E0100 et moitié isolée
    $c = [Activator]::CreateInstance($cmdT); $c.Action = 'quarantaine'
    $c.Cible = 'C:\x\a' + [char]::ConvertFromUtf32(0xE0041) + [char]::ConvertFromUtf32(0xE0100) + [string][char]0xD800 + 'b' + [char]::ConvertFromUtf32(0x1F600)
    $t = $canal.GetMethod('Decrire').Invoke($null, @($c))
    Verifier-Fenetre 'A-1-5 : caractères hors du plan de base neutralisés par point de code, moitié isolée comprise' { if ($t.EndsWith('C:\x\a???b' + [char]::ConvertFromUtf32(0x1F600))) { $true } else { ($t.ToCharArray() | ForEach-Object { '{0:X4}' -f [int]$_ }) -join ' ' } }

    # Audit du 2026-11-23, A-1-2 : commande qui affaiblit, phrase en tête et « Continuer » armé après 2 s
    $affaiblit = $canal.GetMethod('Affaiblit')
    $liste = @(@('apprentissage', 'recommencer'), @('config', 'false'), @('toutDebloquer', ''), @('baseline', 'annuler'), @('filtrage', 'off'), @('restaurer', ''), @('restaurerRepli', ''),
        # S277-02
        @('exception', ''), @('debloquer', ''), @('reprendre', ''), @('panique', 'off'), @('filtrageAutoriser', ''), @('filtrageRetirer', ''),
        @('filtrageCategories', 'publicite'), @('reglages', '{}'), @('autoriserLecteur', 'S-1-5-21-1-2-3-1001'))
    $autres = @(@('apprentissage', 'terminer'), @('config', 'true'), @('baseline', 'appliquer'), @('filtrage', 'on'), @('bloquer', ''), @('tuer', ''), @('majMenaces', ''), @('panique', 'on'), @('quarantaine', ''), @('bloquerIp', ''))
    foreach ($en in $false, $true) {
        $langue.GetField('En').SetValue($null, $en)
        $phrase = $canal.GetMethod('AvertissementAffaiblit').Invoke($null, @($en))
        foreach ($p in $liste) {
            $c = [Activator]::CreateInstance($cmdT); $c.Action = $p[0]; $c.Valeur = $p[1]; $c.Cible = 'x'
            $nom = "A-1-2 : $($p[0]) $($p[1]) [$(if ($en) { 'en' } else { 'fr' })]"
            $f = $canal.GetMethod('FenetreConfirmation').Invoke($null, @($canal.GetMethod('TitreConfirmation').Invoke($null, @($c, $en)), $canal.GetMethod('Decrire').Invoke($null, @($c)), $en, $affaiblit.Invoke($null, @($c))))
            try {
                $k = $f.Controls.Find('Continuer', $true)[0]
                # Constat T-16 : la phrase est dans le bandeau rouge en tête, son « ⚠ » dessiné à côté
                $tete = @($f.Controls.Find('Avertissement', $true) | ForEach-Object { $_.Text })
                Verifier-Fenetre "$nom : phrase en tête, « Continuer » désactivé à l'ouverture" { if ($phrase[0] -eq [char]0x26A0 -and $tete.Count -eq 1 -and $tete[0] -eq $phrase.Substring(2) -and -not $k.Enabled) { $true } else { "tête : $tete ; actif : $($k.Enabled)" } }
            } finally { $f.Dispose() }
        }
        foreach ($p in $autres) {
            $c = [Activator]::CreateInstance($cmdT); $c.Action = $p[0]; $c.Valeur = $p[1]
            Verifier-Fenetre "A-1-2 : $($p[0]) $($p[1]) n'affaiblit pas, pas de phrase" { -not $affaiblit.Invoke($null, @($c)) }
        }
    }
    $langue.GetField('En').SetValue($null, $false)
    Verifier-Fenetre 'A-1-2 : phrase française attendue' { $canal.GetMethod('AvertissementAffaiblit').Invoke($null, @($false)).Contains("Cette demande ne vient peut-être pas de vous : si vous n'avez rien demandé dans deR4Tizer, annulez") }
    $f = $canal.GetMethod('FenetreConfirmation').Invoke($null, @('x', 'essai', $false, $true))
    try {
        $k = $f.Controls.Find('Continuer', $true)[0]
        [Windows.Forms.Form].GetMethod('OnActivated', [Reflection.BindingFlags]'NonPublic,Instance').Invoke($f, @([EventArgs]::Empty))
        $chrono = [Diagnostics.Stopwatch]::StartNew()
        while (-not $k.Enabled -and $chrono.ElapsedMilliseconds -lt 6000) { [Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 10 }
        $t2 = if ($k.Enabled) { [int]$chrono.ElapsedMilliseconds } else { -1 }
        Verifier-Fenetre 'A-1-2 : armé après 2 s, jamais avant 1,9 s' { if ($t2 -ge 1900) { $true } else { "armé après $t2 ms" } }
    } finally { $f.Dispose() }
    $principal = [IO.File]::ReadAllText((Join-Path $src 'Gui.cs'))
    Verifier-Fenetre 'A-1-2 : l''assistant élevé passe Affaiblit à la fenêtre' { $principal.Contains('Canal.FenetreConfirmation(Canal.TitreConfirmation(c, L.En), texte, L.En, Canal.Affaiblit(c))') }

    # Audit du 2026-11-23, A-1-1 : fichier de commande jugé sur la chaîne seule, avant tout accès disque. Décision pure :
    # dossier attendu fixé, lecteur C: seul fixe (Z: joue le lecteur mappé)
    $accepte = $canal.GetMethod('CheminDeCommandeAccepte')
    $hex = 'commande-' + ('0123456789abcdef' * 2) + '.json'
    $attendu = 'C:\Users\essai\AppData\Local\deR4Tizer'
    $fixe = [Func[char, bool]] { param($l) $l -eq [char]'C' }
    $juger = { param($chemin, $dossiers = @($attendu)) $accepte.Invoke($null, @($chemin, [string[]]$dossiers, $fixe)) }
    Verifier-Fenetre 'A-1-1 : chemin attendu accepté' { & $juger "$attendu\$hex" }
    Verifier-Fenetre 'A-1-1 : casse du dossier ignorée' { & $juger ("$attendu\$hex".ToUpperInvariant().Replace('.JSON', '.json').Replace('COMMANDE-', 'commande-').Replace(('0123456789ABCDEF' * 2), ('0123456789abcdef' * 2))) }
    foreach ($refuse in @("\\hote\partage\deR4Tizer\$hex", "\\hote@80\DavWWWRoot\deR4Tizer\$hex", "\\hote@SSL\deR4Tizer\$hex", "\\?\UNC\hote\p\deR4Tizer\$hex",
                          "\\?\$attendu\$hex", "\\.\$attendu\$hex", "Z:\Users\essai\AppData\Local\deR4Tizer\$hex", "C:\Users\autre\AppData\Local\deR4Tizer\$hex",
                          "$attendu\..\deR4Tizer\$hex", "$attendu\.\$hex", "$attendu\$hex`:flux", "C:/Users/essai/AppData/Local/deR4Tizer/$hex",
                          "$attendu\commande-XYZ.json", "$attendu\autre\$hex", "C:$hex", '')) {
        Verifier-Fenetre "A-1-1 : refusé sans accès : $refuse" { -not (& $juger $refuse) }
    }
    Verifier-Fenetre 'A-1-1 : lecteur mappé refusé même s''il est le dossier attendu' { -not (& $juger "Z:\d\deR4Tizer\$hex" @('Z:\d\deR4Tizer')) }
    Verifier-Fenetre 'A-1-1 : dossier attendu réseau ignoré' { -not (& $juger "\\h\p\deR4Tizer\$hex" @('\\h\p\deR4Tizer')) }
    # Chemin réseau réel (TEST-NET-1, injoignable) : refus immédiat, sans tentative de connexion (qui durerait des secondes)
    $chrono = [Diagnostics.Stopwatch]::StartNew()
    $r = $canal.GetMethod('FichierDeCommande').Invoke($null, @("\\192.0.2.1\p\deR4Tizer\$hex"))
    Verifier-Fenetre 'A-1-1 : FichierDeCommande refuse un UNC sans y accéder' { if (-not $r -and $chrono.ElapsedMilliseconds -lt 1000) { $true } else { "$r, $($chrono.ElapsedMilliseconds) ms" } }
    $r = $canal.GetMethod('FichierDeCommande').Invoke($null, @("\\192.0.2.1@80\DavWWWRoot\deR4Tizer\$hex"))
    Verifier-Fenetre 'A-1-1 : FichierDeCommande refuse un chemin WebDAV' { -not $r }
    # Cas positif : vrai fichier de commande dans le %LOCALAPPDATA%\deR4Tizer de ce compte, comme l'écrit Executer
    $dossierCmd = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'deR4Tizer'
    New-Item -ItemType Directory -Force -Path $dossierCmd | Out-Null
    $vrai = [string](Join-Path $dossierCmd ('commande-' + [guid]::NewGuid().ToString('N') + '.json'))
    [IO.File]::WriteAllText($vrai, '{}')
    try {
        Verifier-Fenetre 'A-1-1 : vrai fichier de commande du compte accepté' { $canal.GetMethod('FichierDeCommande').Invoke($null, @($vrai)) }
    } finally { Remove-Item -LiteralPath $vrai -Force -ErrorAction SilentlyContinue }
    # Même nom de fichier dans %TEMP%\deR4Tizer (dossier qu'employait le scénario de CI quarantaine.ps1 jusqu'à #280) :
    # refusé ; le scénario écrit désormais là où l'interface écrit
    $dossierTemp = Join-Path $env:TEMP 'deR4Tizer'
    New-Item -ItemType Directory -Force -Path $dossierTemp | Out-Null
    $faux = [string](Join-Path $dossierTemp ('commande-' + [guid]::NewGuid().ToString('N') + '.json'))
    [IO.File]::WriteAllText($faux, '{}')
    try {
        Verifier-Fenetre 'A-1-1 : fichier de commande dans %TEMP%\deR4Tizer refusé' { -not $canal.GetMethod('FichierDeCommande').Invoke($null, @($faux)) }
    } finally { Remove-Item -LiteralPath $faux -Force -ErrorAction SilentlyContinue }
    $scenario = [IO.File]::ReadAllText((Join-Path $Depot 'tests\integration\quarantaine.ps1'))
    Verifier-Fenetre 'A-1-1 : le scénario de CI de la confirmation élevée écrit dans %LOCALAPPDATA%\deR4Tizer, comme l''interface' { $scenario.Contains("`$dossierCmd = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'deR4Tizer'") -and -not $scenario.Contains("Join-Path `$env:TEMP 'deR4Tizer'") }
    Verifier-Fenetre 'A-5-2 : emplacement d''un programme : chemin réseau refusé avant File.Exists' { $principal.Contains('if (Canal.CheminLocalFixe(chemin) && File.Exists(chemin))') -and -not $canal.GetMethod('CheminLocalFixe').Invoke($null, @('\\hote\p\x.exe')) }

    # Audit du 2026-11-23, A-5-3 : aucun programme lancé par son nom nu depuis l'interface
    $nus = foreach ($fichier in Get-ChildItem (Join-Path $src '*.cs')) {
        $texteSrc = [IO.File]::ReadAllText($fichier.FullName)
        foreach ($m in [regex]::Matches($texteSrc, '(?:Process\.Start|new ProcessStartInfo)\(\s*"([^"]*)"')) { if (-not $m.Groups[1].Value.Contains('\')) { "$($fichier.Name) : $($m.Groups[1].Value)" } }
    }
    Verifier-Fenetre 'A-5-3 : aucun Process.Start ni ProcessStartInfo par nom nu dans src\*.cs' { if (-not $nus) { $true } else { $nus -join ' ; ' } }

    # Constat T-16 : présentation de la fenêtre (maquettes validées par le mainteneur) sans rien changer à ce qui est affiché
    # ni envoyé. Fenêtres construites, jamais affichées ; état d'armement par les événements, comme plus haut
    $theme = $asm.GetType('DeR4Tizer.Theme')
    $titreDe = $canal.GetMethod('TitreConfirmation')
    $fenetre = { param($titre, $texte, $en, $affaiblit) $canal.GetMethod('FenetreConfirmation').Invoke($null, @([string]$titre, [string]$texte, [bool]$en, [bool]$affaiblit)) }
    $drapeaux = [Reflection.BindingFlags]'NonPublic,Instance'
    $activerF = { param($fx) [Windows.Forms.Form].GetMethod('OnActivated', $drapeaux).Invoke($fx, @([EventArgs]::Empty)) }
    $desactiverF = { param($fx) [Windows.Forms.Form].GetMethod('OnDeactivate', $drapeaux).Invoke($fx, @([EventArgs]::Empty)) }
    # Titres : table fixe ; aucune valeur de la commande n'y paraît, pour chaque action de Decrire (lue dans la source) et une
    # action inconnue, avec toutes les valeurs qui choisissent une variante
    $sourceDecrire = $principal.Substring($principal.IndexOf('public static string Decrire(Commande c)'))
    $sourceDecrire = $sourceDecrire.Substring(0, $sourceDecrire.IndexOf('public static string DecrireIncident('))
    $actions = @([regex]::Matches($sourceDecrire, 'case "(\w+)":') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    $marque = 'MARQUE' + [char]0x202E + "`nT16"
    foreach ($en in $false, $true) {
        $langue.GetField('En').SetValue($null, $en)
        $inconnu = if ($en) { 'Unknown command' } else { 'Commande inconnue' }
        $mauvais = @()
        foreach ($a in $actions + @("inconnue$marque")) {
            foreach ($v in @($marque, 'true', 'on', 'off', 'annuler', 'appliquer', 'terminer', 'recommencer', 'quad9')) {
                $c = [Activator]::CreateInstance($cmdT); $c.Action = $a; $c.Valeur = $v
                $c.Cible = $marque; $c.Ip = $marque; $c.NomDns = $marque; $c.Chemin = $marque; $c.Type = $marque; $c.Raison = $marque
                $t = [string]$titreDe.Invoke($null, @($c, $en))
                if (-not $t -or $t.Contains('MARQUE') -or $t.Contains('T16') -or ($actions -contains $a) -eq ($t -eq $inconnu)) { $mauvais += "$a/$v : $t" }
            }
        }
        Verifier-Fenetre "T-16 : titres d'une table fixe, sans texte de la commande, pour les $($actions.Count) actions de Decrire et une inconnue [$(if ($en) { 'en' } else { 'fr' })]" { if (-not $mauvais -and $actions.Count -ge 33) { $true } else { "$($actions.Count) actions ; " + ($mauvais -join ' ; ') } }
    }
    $langue.GetField('En').SetValue($null, $false)
    $c = [Activator]::CreateInstance($cmdT); $c.Action = 'bloquer'; $c.NomDns = 'pistage.example.net'
    $f = & $fenetre ($titreDe.Invoke($null, @($c, $false))) ($canal.GetMethod('Decrire').Invoke($null, @($c))) $false $false
    try { Verifier-Fenetre 'T-16 : titre de la table affiché en tête (« Bloquer un domaine »)' { $f.Controls.Find('Titre', $true)[0].Text -eq 'Bloquer un domaine' } } finally { $f.Dispose() }
    $f = & $fenetre ('T' + [char]0x202E + 'x') 'essai' $false $false
    try { Verifier-Fenetre 'T-16 : titre passé par Visible (A-1-5)' { $f.Controls.Find('Titre', $true)[0].Text -eq 'T?x' } } finally { $f.Dispose() }

    # Zone sombre en lecture seule, texte brut ; conséquences en liste, rien retiré ; Visible partout ; jamais lue comme du RTF
    $lignesDe = $canal.GetMethod('LignesConfirmation'); $composer = $canal.GetMethod('TexteZoneConfirmation')
    $dest = (1..24 | ForEach-Object { 'dest{0:00}@example.org' -f $_ }) -join ','
    $c = [Activator]::CreateInstance($cmdT); $c.Action = 'notifications'
    $c.Valeur = '{"Config":{"Ntfy":true,"Smtp":true,"SmtpServeur":"smtp.example.org","SmtpPort":465,"SmtpSecurite":"SSL","SmtpUtilisateur":"alertes@example.org","Expediteur":"alertes@example.org","Destinataires":"' + $dest + '","NiveauMin":"Critique","MaxParHeure":10},"NtfyUrl":"https://ntfy.example.org/alertes-4f9c"}'
    $texteN = [string]$canal.GetMethod('Decrire').Invoke($null, @($c))
    $f = & $fenetre 'Modifier la remontée des alertes' $texteN $false $false
    try {
        $zone = $f.Controls.Find('Texte', $true)[0]
        Verifier-Fenetre 'T-16 : zone sombre en lecture seule, sans lien, hors de la tabulation' { $zone -is [Windows.Forms.RichTextBox] -and $zone.ReadOnly -and -not $zone.DetectUrls -and -not $zone.TabStop -and $zone.BackColor -eq $theme.GetField('Fond').GetValue($null) -and $zone.ContextMenuStrip.Items.Count -eq 2 }
        Verifier-Fenetre 'T-16 : la zone montre la composition des lignes, texte brut' { $zone.Text -eq $composer.Invoke($null, @(, $lignesDe.Invoke($null, @($texteN)))) }
        $vues = $zone.Text.Split("`n"); $source = $texteN.Split("`n")
        $ecarts = @(for ($i = 0; $i -lt [Math]::Max($vues.Count, $source.Count); $i++) {
            $s = if ($i -lt $source.Count) { $source[$i].TrimStart(' ') } else { '<absente>' }; if ($s.StartsWith([string][char]0x2022 + ' ')) { $s = $s.Substring(2) }
            $v = if ($i -lt $vues.Count) { $vues[$i] } else { '<absente>' }; if ($v -match "^[•◦]`t") { $v = $v.Substring(2) }
            if ($s -ne $v) { "ligne $i : « $s » / « $v »" } })
        Verifier-Fenetre "T-16 : liste : chacune des $($source.Count) lignes de Decrire, dans l'ordre, sans rien retirer" { if (-not $ecarts -and $source.Count -ge 28) { $true } else { $ecarts -join ' ; ' } }
        Verifier-Fenetre 'T-16 : liste : « • » au premier niveau, « ◦ » au second, fin de l''hôte sans puce' { $vues[1].StartsWith([string][char]0x2022 + "`t") -and @($vues | Where-Object { $_.StartsWith([string][char]0x25E6 + "`tdest") }).Count -eq 24 -and @($vues | Where-Object { $_ -eq "l'hôte se termine par : example.org" }).Count -eq 1 }
    } finally { $f.Dispose() }
    $f = & $fenetre 'x' ('a' + [char]0x202E + 'b' + "`n  " + [char]0x2022 + ' c' + [char]0x200B + 'd' + "`n      e" + [char]0x0301) $false $false
    try { Verifier-Fenetre 'T-16 : Visible sur chaque ligne de la zone (A-1-5)' { $t = $f.Controls.Find('Texte', $true)[0].Text; if ($t -eq ('a?b' + "`n" + [char]0x2022 + "`tc?d`n" + 'e?')) { $true } else { ($t.ToCharArray() | ForEach-Object { '{0:X4}' -f [int]$_ }) -join ' ' } } } finally { $f.Dispose() }
    $c = [Activator]::CreateInstance($cmdT); $c.Action = '{\rtf1\ansi PIEGE}'; $c.Cible = 'x'
    $texteR = [string]$canal.GetMethod('Decrire').Invoke($null, @($c))
    $f = & $fenetre ($titreDe.Invoke($null, @($c, $false))) $texteR $false $false
    try { Verifier-Fenetre 'T-16 : texte d''allure RTF montré tel quel, jamais interprété' { $f.Controls.Find('Texte', $true)[0].Text -eq '{\rtf1\ansi PIEGE} x' -and $f.Controls.Find('Titre', $true)[0].Text -eq 'Commande inconnue' } } finally { $f.Dispose() }

    # Largeur 600, hauteur ajustée au contenu jusqu'à 70 % de l'écran, défilement au-delà (rappel au pied)
    $hz = $canal.GetMethod('HauteurZoneConfirmation')
    Verifier-Fenetre 'T-16 : hauteur de la zone : tout le contenu quand la fenêtre tient' { $hz.Invoke($null, @(200, 300, 1000)) -eq 200 }
    Verifier-Fenetre 'T-16 : hauteur de la zone : au-delà, fenêtre bornée à 70 % de l''écran' { $hz.Invoke($null, @(2000, 300, 1000)) -eq 400 }
    Verifier-Fenetre 'T-16 : hauteur de la zone : jamais moins de 80 px' { $hz.Invoke($null, @(2000, 300, 400)) -eq 80 -and $hz.Invoke($null, @(50, 300, 400)) -eq 50 }
    $ecran = [Windows.Forms.Screen]::FromPoint([Windows.Forms.Control]::MousePosition).WorkingArea.Height
    $f = & $fenetre 'Bloquer un domaine' 'Bloquer pistage.example.net' $false $false
    try {
        $cadre = $f.Controls.Find('Cadre', $true)[0]
        Verifier-Fenetre 'T-16 : texte court : largeur 600, hauteur au contenu, sans rappel de défilement' { if ($f.ClientSize.Width -eq 600 -and $f.Height -lt 300 -and $cadre.Height -lt 80 -and $f.Controls.Find('Defiler', $true).Count -eq 0) { $true } else { "client $($f.ClientSize), cadre $($cadre.Height)" } }
    } finally { $f.Dispose() }
    $long = ((1..1200 | ForEach-Object { 'mot' }) -join ' ')
    $f = & $fenetre 'Commande inconnue' $long $false $false
    try {
        $zone = $f.Controls.Find('Texte', $true)[0]
        $deborde = $zone.GetPositionFromCharIndex($zone.TextLength - 1).Y -gt $zone.ClientSize.Height
        Verifier-Fenetre 'T-16 : texte long : fenêtre bornée à 70 % de l''écran, défilement et rappel au pied' { if (-not $deborde) { "cas sans valeur : écran de $ecran px, le texte tient" } elseif ($f.ClientSize.Width -eq 600 -and $f.Height -le [int]($ecran * 0.7) -and $f.Height -ge [int]($ecran * 0.7) - 30 -and $f.Controls.Find('Defiler', $true).Count -eq 1) { $true } else { "fenêtre $($f.Height) px pour un écran de $ecran px" } }
        Verifier-Fenetre 'T-16 : texte long : jamais tronqué' { $zone.Text -eq $long }
    } finally { $f.Dispose() }

    # Icône du produit en tête ; barre de titre sombre demandée à la création de la poignée, échec ignoré
    $f = & $fenetre 'x' 'essai' $false $false
    try {
        $icone = $f.Controls.Find('Icone', $true)
        Verifier-Fenetre 'T-16 : icône du produit en tête (48 px)' { $icone.Count -eq 1 -and $icone[0].Image.Width -eq 48 -and $icone[0].Width -eq 48 }
        $accepte = try { [bool]$theme.GetMethod('BarreTitreSombre').Invoke($null, @($f.Handle)); 'sans exception' } catch { "exception $($_.Exception.InnerException.Message)" }
        Verifier-Fenetre 'T-16 : barre de titre sombre demandée à la création de la poignée, échec ignoré' { $principal.Contains('f.HandleCreated += (s, e) => Theme.BarreTitreSombre(f.Handle);') -and -not $theme.GetMethod('BarreTitreSombre').Invoke($null, @([IntPtr]::Zero)) -and $accepte -eq 'sans exception' }
    } finally { $f.Dispose() }

    # Bandeau rouge et phrase (A-1-2) pour une commande qui affaiblit, au-dessus de l'en-tête ; aucun sinon
    foreach ($en in $false, $true) {
        $phraseB = ([string]$canal.GetMethod('AvertissementAffaiblit').Invoke($null, @($en))).Substring(2)
        $f = & $fenetre 'x' 'essai' $en $true
        try {
            $b = $f.Controls.Find('Bandeau', $true); $m = $f.Controls.Find('Avertissement', $true)
            Verifier-Fenetre "T-16 : commande qui affaiblit : bandeau rouge en tête, phrase sans « ⚠ » [$(if ($en) { 'en' } else { 'fr' })]" { $b.Count -eq 1 -and $b[0].Top -eq 0 -and $b[0].BackColor -eq $theme.GetField('FondCritique').GetValue($null) -and $m.Count -eq 1 -and $m[0].Text -eq $phraseB -and $f.Controls.Find('Titre', $true)[0].Top -gt $b[0].Bottom }
        } finally { $f.Dispose() }
        $f = & $fenetre 'x' 'essai' $en $false
        try { Verifier-Fenetre "T-16 : commande ordinaire : pas de bandeau [$(if ($en) { 'en' } else { 'fr' })]" { $f.Controls.Find('Bandeau', $true).Count -eq 0 -and $f.Controls.Find('Avertissement', $true).Count -eq 0 } } finally { $f.Dispose() }
    }

    # Compte à rebours sur « Continuer » : 1 s (2 s pour une commande qui affaiblit), délais inchangés ; langue de l'interface
    $tc = $canal.GetMethod('TexteContinuer')
    Verifier-Fenetre 'T-16 : libellé du compte à rebours' { $tc.Invoke($null, @($false, 1)) -eq 'Continuer (1)' -and $tc.Invoke($null, @($false, 0)) -eq 'Continuer' -and $tc.Invoke($null, @($true, 2)) -eq 'Continue (2)' -and $tc.Invoke($null, @($true, 0)) -eq 'Continue' }
    foreach ($cas in @(@{ En = $false; Aff = $false; D = 1 }, @{ En = $true; Aff = $true; D = 2 })) {
        $nomC = "T-16 : compte à rebours de $($cas.D) s [$(if ($cas.En) { 'en' } else { 'fr' })]"
        $base = if ($cas.En) { 'Continue' } else { 'Continuer' }
        $f = & $fenetre 'x' 'essai' $cas.En $cas.Aff
        try {
            $k = $f.Controls.Find('Continuer', $true)[0]; $a = $f.Controls.Find('Annuler', $true)[0]
            $vus = New-Object Collections.Generic.List[string]; $t0 = $k.Text
            & $activerF $f
            $chrono = [Diagnostics.Stopwatch]::StartNew()
            while (-not $k.Enabled -and $chrono.ElapsedMilliseconds -lt 6000) { if (-not $vus.Contains($k.Text)) { $vus.Add($k.Text) }; [Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 10 }
            $tArme = $chrono.ElapsedMilliseconds; $tFin = $k.Text
            $attendus = @($cas.D..1 | ForEach-Object { "$base ($_)" })
            Verifier-Fenetre "$nomC : secondes restantes sur le bouton, puis « $base » armé" { if ($t0 -eq "$base ($($cas.D))" -and (($vus -join '|') -eq ($attendus -join '|')) -and $tFin -eq $base -and $k.Enabled -and $tArme -ge ($cas.D * 1000 - 100)) { $true } else { "départ « $t0 », vus « $($vus -join '|') », fin « $tFin » après $tArme ms" } }
            Verifier-Fenetre "$nomC : « Annuler » reste le bouton par défaut une fois armé" { $f.AcceptButton -eq $a -and $f.CancelButton -eq $a -and $a.DialogResult -eq 'Cancel' -and $a.GetType().GetField('Accent').GetValue($a) -and -not $k.GetType().GetField('Accent').GetValue($k) -and $a.TabIndex -lt $k.TabIndex }
            & $desactiverF $f
            Verifier-Fenetre "$nomC : hors du premier plan, désarmé et compte remis à $($cas.D)" { -not $k.Enabled -and $k.Text -eq "$base ($($cas.D))" }
            $sousTitre = $f.Controls.Find('SousTitre', $true)[0].Text
            Verifier-Fenetre "$nomC : textes dans la langue de l'interface" { if ($cas.En) { $a.Text -eq 'Cancel' -and $sousTitre -eq 'deR4Tizer (administrator) is about to:' -and $f.Text -eq 'deR4Tizer (administrator)' } else { $a.Text -eq 'Annuler' -and $sousTitre -eq 'deR4Tizer (administrateur) va :' -and $f.Text -eq 'deR4Tizer (administrateur)' } }
        } finally { $f.Dispose() }
    }
    $langue.GetField('En').SetValue($null, $false)

    # Rendus hors écran des six cas des maquettes T-16, en français et en anglais (-Rendus <dossier>) : fenêtre construite,
    # jamais affichée, chaque contrôle dessiné par DrawToBitmap ; la zone de texte (RichTextBox, que DrawToBitmap laisse vide)
    # par EM_FORMATRANGE, comme l'imprimerait le contrôle. La barre de titre est celle de Windows (DWM) : simulée ici avec
    # le titre et l'icône réels de la fenêtre ; la barre de défilement n'est pas dessinée. Aucune capture d'écran
    if ($Rendus) {
        New-Item -ItemType Directory -Force -Path $Rendus | Out-Null
        Add-Type -ReferencedAssemblies System.Windows.Forms, System.Drawing -TypeDefinition @'
using System; using System.Drawing; using System.Runtime.InteropServices; using System.Windows.Forms;
public static class RenduConfirmationT16
{
    [StructLayout(LayoutKind.Sequential)] struct Rect { public int G, H, D, B; }
    [StructLayout(LayoutKind.Sequential)] struct Plage { public int Min, Max; }
    [StructLayout(LayoutKind.Sequential)] struct Format { public IntPtr Dc, DcCible; public Rect Zone, Page; public Plage Car; }
    [DllImport("user32.dll")] static extern IntPtr SendMessage(IntPtr h, int m, IntPtr w, ref Format f);
    [DllImport("user32.dll")] static extern IntPtr SendMessage(IntPtr h, int m, IntPtr w, IntPtr l);
    static Point Position(Control c, Form f) { var p = Point.Empty; for (var x = c; x != null && x != f; x = x.Parent) p.Offset(x.Location); return p; }
    // Chaque contrôle dessiné à sa place, puis ses enfants (poignées créées au passage : la fenêtre n'est jamais montrée)
    static void Dessiner(Control c, Bitmap bmp, int x, int y)
    {
        c.DrawToBitmap(bmp, new Rectangle(x + c.Left, y + c.Top, c.Width, c.Height));
        foreach (Control e in c.Controls) Dessiner(e, bmp, x + c.Left, y + c.Top);
    }
    public static Bitmap Rendre(Form f, Image icone)
    {
        const int barre = 32;
        var cs = f.ClientSize;
        var bmp = new Bitmap(cs.Width + 2, cs.Height + barre + 1);
        using (var g = Graphics.FromImage(bmp))
        {
            g.Clear(f.BackColor);
            using (var b = new SolidBrush(Color.FromArgb(0x14, 0x15, 0x18))) g.FillRectangle(b, 0, 0, bmp.Width, barre);
            g.DrawImage(icone, new Rectangle(11, 8, 16, 16));
            using (var p = new Font("Segoe UI", 9f)) TextRenderer.DrawText(g, f.Text, p, new Point(36, 8), Color.FromArgb(0xE6, 0xE8, 0xEB));
            using (var p = new Pen(Color.FromArgb(0x9A, 0xA3, 0xAF), 1.2f)) { int x = bmp.Width - 26; g.DrawLine(p, x, 11, x + 9, 20); g.DrawLine(p, x + 9, 11, x, 20); }
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
            using (var p = new Pen(Color.FromArgb(0x2E, 0x32, 0x38))) g.DrawRectangle(p, 0, 0, bmp.Width - 1, bmp.Height - 1);
        }
        return bmp;
    }
}
'@
        $dossierEtat = $commun.GetField('Dossier').GetValue($null)
        Remove-Item (Join-Path $dossierEtat 'filtrage-etat.json') -ErrorAction SilentlyContinue
        $nouvelle = { param($a, $v, $dns) $x = [Activator]::CreateInstance($cmdT); $x.Action = $a; $x.Valeur = $v; $x.NomDns = $dns; $x }
        $destR = (1..24 | ForEach-Object { 'recipient{0:00}@example.org' -f $_ }) -join ','
        $notif = & $nouvelle 'notifications' ('{"Config":{"Ntfy":true,"Smtp":true,"SmtpServeur":"smtp.example.org","SmtpPort":465,"SmtpSecurite":"SSL","SmtpUtilisateur":"alerts@example.org","Expediteur":"alerts@example.org","Destinataires":"' + $destR + '","NiveauMin":"Critique","MaxParHeure":10},"NtfyUrl":"https://ntfy.example.org/alerts-desk-4f9c"}') $null
        $casR = @(
            @{ N = 't16-a-commande-ordinaire'; C = (& $nouvelle 'bloquer' '' 'tracker.example.net'); Arme = $true },
            @{ N = 't16-a2-commande-ordinaire-desarmee'; C = (& $nouvelle 'bloquer' '' 'tracker.example.net'); Arme = $false },
            @{ N = 't16-a3-commande-ordinaire-liste'; C = (& $nouvelle 'filtrage' 'on' $null); Arme = $true },
            @{ N = 't16-b-commande-qui-affaiblit'; C = (& $nouvelle 'toutDebloquer' '' $null); Arme = $false },
            @{ N = 't16-b2-desactiver-filtrage'; C = (& $nouvelle 'filtrage' 'off' $null); Arme = $false },
            @{ N = 't16-c-texte-long-defilement'; C = $notif; Arme = $true },
            @{ N = 't16-d-texte-au-plafond-defilement'; Texte = ('Unknown command x' + ((1..39 | ForEach-Object { "`n  " + [char]0x2022 + " line $_ of a confirmation at the 40-line cap" }) -join '')); Arme = $true }
        )
        foreach ($en in $false, $true) {
            $langue.GetField('En').SetValue($null, $en)
            foreach ($r in $casR) {
                if ($r.C) { $texteC = [string]$canal.GetMethod('Decrire').Invoke($null, @($r.C)); $titreC = $titreDe.Invoke($null, @($r.C, $en)); $aff = [bool]$affaiblit.Invoke($null, @($r.C)) }
                else { $texteC = $r.Texte; $titreC = if ($en) { 'Unknown command' } else { 'Commande inconnue' }; $aff = $false }
                $f = & $fenetre $titreC $texteC $en $aff
                try {
                    if ($r.Arme) {
                        $k = $f.Controls.Find('Continuer', $true)[0]; & $activerF $f
                        $chrono = [Diagnostics.Stopwatch]::StartNew()
                        while (-not $k.Enabled -and $chrono.ElapsedMilliseconds -lt 5000) { [Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 10 }
                    }
                    $chemin = Join-Path $Rendus ("$($r.N)-$(if ($en) { 'en' } else { 'fr' }).png")
                    $img = [RenduConfirmationT16]::Rendre($f, $theme.GetMethod('ImageApplication').Invoke($null, @(16))); $img.Save($chemin, [Drawing.Imaging.ImageFormat]::Png); $img.Dispose()
                    "rendu : $chemin ($($f.ClientSize.Width) x $($f.ClientSize.Height), défilement : $($f.Controls.Find('Defiler', $true).Count -eq 1))"
                } finally { $f.Dispose() }
            }
        }
        $langue.GetField('En').SetValue($null, $false)
    }
    "bilan fenêtre : $kof échec(s)"
    if ($ko -or $kof) { exit 1 }
} finally {
    Remove-Item $travail -Recurse -Force -ErrorAction SilentlyContinue
}
