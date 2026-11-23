# Compile l'interface et vérifie que chaque confirmation de Canal.Decrire (assistant élevé) neutralise un texte piégé
# venu de la commande ou des fichiers lus pour la décrire (inversion du sens d'écriture, retour à la ligne injecté),
# en français et en anglais, branches « élément trouvé » comprises (quarantaine.json et alertes.json piégés dans un
# dossier de données de test). Code de sortie 1 si un cas n'est pas neutralisé.
# Usage (Windows PowerShell 5.1) : powershell -File tests\test-confirmations.ps1 [-Depot <racine du dépôt>]
param([string]$Depot = (Split-Path $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$src = Join-Path $Depot 'src'
$travail = Join-Path $env:TEMP ("d4t-confirmations-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $travail | Out-Null
try {
    $out = Join-Path $travail 'interface.exe'
    $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $wpf = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\WPF'
    & $csc /nologo /platform:anycpu /codepage:65001 /target:winexe /r:System.dll /r:System.Core.dll /r:System.Web.Extensions.dll /r:System.ServiceProcess.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll "/r:$wpf\PresentationFramework.dll" "/r:$wpf\PresentationCore.dll" "/r:$wpf\WindowsBase.dll" /r:System.Xaml.dll "/out:$out" "$src\Commun.cs" "$src\Langue.cs" "$src\Theme.cs" "$src\Gui.cs" "$src\Reglages.cs" "$src\Siem.cs" "$src\Incidents.cs" "$src\Reponses.cs" "$src\Trafic.cs" "$src\Reseau.cs" "$src\Fluent.cs" "/resource:$src\carte-pays.txt,carte-pays.txt" | Out-Null
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
    $f = $canal.GetMethod('FenetreConfirmation').Invoke($null, @($texte, $false, $false))
    try {
        $zone = $f.Controls.Find('Texte', $true)[0]; $annuler = $f.Controls.Find('Annuler', $true)[0]; $continuer = $f.Controls.Find('Continuer', $true)[0]
        Verifier-Fenetre 'fenêtre : texte entier, sans troncature' { $zone.Text.Replace("`r`n", "`n").EndsWith($texte) -and $zone.Text.Contains(((('a' * 60) + '.') * 4) + 'attaquant.test') }
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
    $f = $canal.GetMethod('FenetreConfirmation').Invoke($null, @('essai', $false, $false))
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
            $f = $canal.GetMethod('FenetreConfirmation').Invoke($null, @($canal.GetMethod('Decrire').Invoke($null, @($c)), $en, $affaiblit.Invoke($null, @($c))))
            try {
                $zone = $f.Controls.Find('Texte', $true)[0]; $k = $f.Controls.Find('Continuer', $true)[0]
                $tete = $zone.Text.Replace("`r`n", "`n").Split("`n") | Where-Object { $_ } | Select-Object -Skip 1 -First 1
                Verifier-Fenetre "$nom : phrase en tête, « Continuer » désactivé à l'ouverture" { if ($tete -eq $phrase -and -not $k.Enabled) { $true } else { "tête : $tete ; actif : $($k.Enabled)" } }
            } finally { $f.Dispose() }
        }
        foreach ($p in $autres) {
            $c = [Activator]::CreateInstance($cmdT); $c.Action = $p[0]; $c.Valeur = $p[1]
            Verifier-Fenetre "A-1-2 : $($p[0]) $($p[1]) n'affaiblit pas, pas de phrase" { -not $affaiblit.Invoke($null, @($c)) }
        }
    }
    $langue.GetField('En').SetValue($null, $false)
    Verifier-Fenetre 'A-1-2 : phrase française attendue' { $canal.GetMethod('AvertissementAffaiblit').Invoke($null, @($false)).Contains("Cette demande ne vient peut-être pas de vous : si vous n'avez rien demandé dans deR4Tizer, annulez") }
    $f = $canal.GetMethod('FenetreConfirmation').Invoke($null, @('essai', $false, $true))
    try {
        $k = $f.Controls.Find('Continuer', $true)[0]
        [Windows.Forms.Form].GetMethod('OnActivated', [Reflection.BindingFlags]'NonPublic,Instance').Invoke($f, @([EventArgs]::Empty))
        $chrono = [Diagnostics.Stopwatch]::StartNew()
        while (-not $k.Enabled -and $chrono.ElapsedMilliseconds -lt 6000) { [Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 10 }
        $t2 = if ($k.Enabled) { [int]$chrono.ElapsedMilliseconds } else { -1 }
        Verifier-Fenetre 'A-1-2 : armé après 2 s, jamais avant 1,9 s' { if ($t2 -ge 1900) { $true } else { "armé après $t2 ms" } }
    } finally { $f.Dispose() }
    $principal = [IO.File]::ReadAllText((Join-Path $src 'Gui.cs'))
    Verifier-Fenetre 'A-1-2 : l''assistant élevé passe Affaiblit à la fenêtre' { $principal.Contains('Canal.FenetreConfirmation(texte, L.En, Canal.Affaiblit(c))') }

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
    "bilan fenêtre : $kof échec(s)"
    if ($ko -or $kof) { exit 1 }
} finally {
    Remove-Item $travail -Recurse -Force -ErrorAction SilentlyContinue
}
