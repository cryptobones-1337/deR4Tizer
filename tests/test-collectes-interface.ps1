# Compile l'interface et vérifie les textes de l'état des collectes (classe Couverture, phase 3.4) : « Aucune alerte. »
# seul seulement si chaque détection a sa collecte ; collectes en panne (indisponibles ou jamais lues) comptées, les
# désactivées par choix non ; caméra et micro « OFF » seulement si leur collecte est lue ; textes anglais ; puis
# contrôle du source de Gui.cs (branchements : la fenêtre n'est pas lancée). Code de sortie 1 si un cas échoue.
# Usage (Windows PowerShell 5.1) : powershell -File tests\test-collectes-interface.ps1 [-Depot <racine du dépôt>]
param([string]$Depot = (Split-Path $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$src = Join-Path $Depot 'src'
$travail = Join-Path $env:TEMP ("d4t-collectes-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $travail | Out-Null
$ko = 0
function Cas([string]$Nom, [bool]$Ok, [string]$Detail = '') {
    if ($Ok) { "RÉUSSI  $Nom" } else { "ÉCHOUÉ  $Nom $Detail"; $script:ko++ }
}
try {
    $out = Join-Path $travail 'interface.exe'
    $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $csc /nologo /platform:anycpu /codepage:65001 /target:winexe /r:System.dll /r:System.Core.dll /r:System.Web.Extensions.dll /r:System.ServiceProcess.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll "/out:$out" "$src\Commun.cs" "$src\Langue.cs" "$src\Theme.cs" "$src\Gui.cs" "$src\Reglages.cs" "$src\Siem.cs" "$src\Trafic.cs" "$src\Reseau.cs" "/resource:$src\carte-pays.txt,carte-pays.txt" | Out-Null
    if ($LASTEXITCODE) { throw 'compilation' }
    $asm = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($out))
    $couv = $asm.GetType('DeR4Tizer.Couverture'); $langue = $asm.GetType('DeR4Tizer.L')
    $etatT = $asm.GetType('DeR4Tizer.Etat'); $colT = $asm.GetType('DeR4Tizer.EtatCollecte'); $causeT = $asm.GetType('DeR4Tizer.CauseSansCollecte')
    $appel = { param($m, $e) $couv.GetMethod($m).Invoke($null, @(, $e)) }
    $alarme = { param($e) [bool]$couv.GetMethod('Alarme').Invoke($null, @(, $e)) }
    $liste = { param($t) $l = [Activator]::CreateInstance([Collections.Generic.List`1].MakeGenericType($t)); , $l }
    function Collecte([string]$Id, [string]$Etat, [string]$Raison = '') { $c = [Activator]::CreateInstance($colT); $c.Id = $Id; $c.Etat = $Etat; $c.Raison = $Raison; $c }
    function Etat($Collectes, [string[]]$Sans = @(), $Causes = $null) {
        $e = [Activator]::CreateInstance($etatT)
        if ($null -ne $Collectes) { $l = & $liste $colT; foreach ($c in $Collectes) { $l.Add($c) }; $e.Collectes = $l }
        $s = New-Object 'Collections.Generic.List[string]'; foreach ($r in $Sans) { $s.Add($r) }; $e.ReglesSansCollecte = $s
        if ($Causes) {
            $lc = & $liste $causeT
            foreach ($k in $Causes.Keys) { $c = [Activator]::CreateInstance($causeT); $c.Regle = $k; $v = New-Object 'Collections.Generic.List[string]'; foreach ($x in $Causes[$k]) { $v.Add($x) }; $c.Collectes = $v; $lc.Add($c) }
            $e.CausesSansCollecte = $lc
        }
        $e
    }
    $langue.GetField('En').SetValue($null, $false)

    # « Aucune alerte » : seul seulement si chaque détection a sa collecte
    $t = & $appel 'AucuneAlerte' $null
    Cas 'état illisible : jamais « Aucune alerte. » seul' ($t -ne 'Aucune alerte.' -and $t -match 'illisible') $t
    $t = & $appel 'AucuneAlerte' (Etat $null)
    Cas 'service plus ancien (pas de Collectes) : dit' ($t -match 'non publié') $t
    $t = & $appel 'AucuneAlerte' (Etat @((Collecte 'Connexions' 'Active')))
    Cas 'toutes les détections couvertes : « Aucune alerte. »' ($t -eq 'Aucune alerte.') $t
    $t = & $appel 'AucuneAlerte' (Etat @((Collecte 'JournalDns' 'Indisponible')) @('DNS-001', 'COR-R1') @{ 'DNS-001' = @('JournalDns', 'Sysmon'); 'COR-R1' = @('JournalSecurite') })
    Cas 'détections muettes : nombre, conséquence en clair, sources manquantes' ($t -match '^Aucune alerte, mais 2 détections' -and $t -match 'DNS-001 : domaines contactés non vus \(manque JournalDns ou Sysmon\)' -and $t -match 'COR-R1 : ouvertures de session et accès aux fichiers non vus \(manque JournalSecurite\)') $t
    $eAlarme = Etat @((Collecte 'JournalDns' 'Indisponible')) @('DNS-001') @{ 'DNS-001' = @('JournalDns', 'Sysmon') }
    Cas 'détections muettes par panne : message en jaune' (& $alarme $eAlarme)
    # Réglage voulu (listes de domaines coupées par défaut) : dit, mais en neutre, et pas compté comme une panne
    $e = Etat @((Collecte 'ListesDomaines' 'Desactivee' 'aucune liste activée'), (Collecte 'Connexions' 'Active')) @('DNS-001') @{ 'DNS-001' = @('ListesDomaines') }
    $t = & $appel 'AucuneAlerte' $e
    Cas 'réglage voulu : « Aucune alerte. » puis la détection coupée, nommée en clair' ($t -eq 'Aucune alerte. Désactivé par réglage : DNS-001 : domaines malveillants connus non reconnus (manque ListesDomaines).') $t
    Cas 'réglage voulu : pas d''alarme (neutre)' (-not (& $alarme $e))
    Cas 'réglage voulu : pas compté dans les détections en panne' ($couv.GetMethod('ReglesEnPanne').Invoke($null, @(, $e)).Count -eq 0)
    # Panne et réglage mêlés : la panne d'abord, le réglage ensuite
    $e = Etat @((Collecte 'ListesDomaines' 'Desactivee'), (Collecte 'Leurres' 'Indisponible')) @('DNS-001', 'LEU-001') @{ 'DNS-001' = @('ListesDomaines'); 'LEU-001' = @('Leurres') }
    $t = & $appel 'AucuneAlerte' $e
    Cas 'panne et réglage mêlés' ($t -match '^Aucune alerte, mais 1 détection ne peut pas se déclencher : LEU-001 : ' -and $t -match 'Désactivé par réglage : DNS-001 : ') $t
    # Échec fermé : une source citée mais absente de Collectes, ou une règle sans cause, compte comme une panne
    $e = Etat @((Collecte 'ListesDomaines' 'Desactivee')) @('DNS-001') @{ 'DNS-001' = @('ListesDomaines', 'Introuvable') }
    Cas 'source citée introuvable : panne, pas réglage' ($couv.GetMethod('ReglesEnPanne').Invoke($null, @(, $e)).Count -eq 1)
    $t = & $appel 'AucuneAlerte' (Etat @((Collecte 'Leurres' 'Indisponible')) @('LEU-001') @{ 'LEU-001' = @('Leurres') })
    Cas 'une détection muette : singulier' ($t -match '^Aucune alerte, mais 1 détection ne peut pas') $t
    # Bandeau de la page Alertes : panne (▲) puis désactivée (○), chacune expliquée ; vide si tout est lu
    $t = & $appel 'Detail' (Etat @((Collecte 'Leurres' 'Indisponible' 'aucun leurre posé'), (Collecte 'Sysmon' 'Desactivee' 'Sysmon absent'), (Collecte 'Connexions' 'Active')))
    Cas 'bandeau : panne puis désactivée, état, raison, conséquence' ($t -eq ("▲ Leurres indisponible (aucun leurre posé) : chiffrement par un rançongiciel non repéré par les leurres`n○ Sysmon désactivée (Sysmon absent) : créations de programmes non vues")) $t
    Cas 'bandeau : rien quand tout est lu' ((& $appel 'Detail' (Etat @((Collecte 'Connexions' 'Active')))) -eq '')
    # Defender au démarrage du PC : pas encore lu, pas « illisible »
    Cas 'Defender pas encore lu' ([bool](& $appel 'DefenderPasEncoreLu' (Etat @((Collecte 'EtatDefender' 'Inconnue')))))
    Cas 'Defender indisponible : pas « lecture en cours »' (-not [bool](& $appel 'DefenderPasEncoreLu' (Etat @((Collecte 'EtatDefender' 'Indisponible')))))
    $t = & $appel 'AucuneAlerte' (Etat @() @('PER-001'))
    Cas 'règle muette sans cause publiée : la règle est dite quand même' ($t -match 'PER-001') $t
    Cas 'règle muette sans cause publiée : panne (échec fermé), pas réglage' ($t -match '^Aucune alerte, mais 1 détection' -and (& $alarme (Etat @() @('PER-001')))) $t

    # Pastille : collectes en panne (indisponibles ou jamais lues), pas les désactivées par choix
    $e = Etat @((Collecte 'JournalDns' 'Indisponible' 'journal illisible'), (Collecte 'Leurres' 'Inconnue'), (Collecte 'Sysmon' 'Desactivee'), (Collecte 'WmiProcessus' 'Partielle'))
    $t = & $appel 'Pastille' $e
    Cas 'pastille : indisponible et inconnue comptées, désactivée et partielle non' ($t -eq '2 COLLECTES INDISPONIBLES') $t
    $t = & $appel 'Pastille' (Etat @((Collecte 'Sysmon' 'Desactivee')))
    Cas 'pastille : aucune collecte en panne, rien' ($t -eq '') $t
    $t = & $appel 'Pastille' (Etat @((Collecte 'Leurres' 'Indisponible')))
    Cas 'pastille : singulier' ($t -eq '1 COLLECTE INDISPONIBLE') $t
    $t = $couv.GetMethod('Decrire').Invoke($null, @((Collecte 'JournalDns' 'Indisponible' 'journal illisible')))
    Cas 'collecte décrite : état, raison, conséquence' ($t -eq 'JournalDns indisponible (journal illisible) : domaines contactés non vus') $t

    # Caméra et micro : « OFF » seulement si leur collecte est lue
    Cas 'cam/mic : collecte indisponible, pas « OFF »' (-not (& $appel 'CamMicLue' (Etat @((Collecte 'Peripheriques' 'Indisponible')))))
    Cas 'cam/mic : collecte absente de la liste, pas « OFF »' (-not (& $appel 'CamMicLue' (Etat @((Collecte 'Connexions' 'Active')))))
    Cas 'cam/mic : collecte lue, « OFF » permis' (& $appel 'CamMicLue' (Etat @((Collecte 'Peripheriques' 'Active'))))
    Cas 'cam/mic : service plus ancien, comportement d''avant' (& $appel 'CamMicLue' (Etat $null))

    # Anglais
    $langue.GetField('En').SetValue($null, $true)
    $t = & $appel 'AucuneAlerte' (Etat @((Collecte 'Connexions' 'Active')))
    Cas 'anglais : « No alerts. »' ($t -eq 'No alerts.') $t
    $t = & $appel 'AucuneAlerte' (Etat @() @('DNS-001') @{ 'DNS-001' = @('JournalDns', 'Sysmon') })
    Cas 'anglais : détections muettes' ($t -match '^No alerts, but 1 detection cannot trigger: DNS-001 : contacted domains not seen \(missing JournalDns or Sysmon\)') $t
    Cas 'anglais : pastille' ((& $appel 'Pastille' (Etat @((Collecte 'Leurres' 'Indisponible')))) -eq '1 COLLECTION UNAVAILABLE')
    $langue.GetField('En').SetValue($null, $false)

    # Branchements dans Gui.cs (contrôle du source : la fenêtre n'est pas lancée par ce script)
    $g = [IO.File]::ReadAllText("$src\Gui.cs") -replace "`r`n", "`n"
    Cas 'Defender illisible : pastille « ÉTAT ILLISIBLE »' ($g.Contains("else`n                    // État illisible : ni « OK » ni « désactivé », c'est dit (phase 3.4)`n                    pastilles.Add(new Entete.Pastille { Texte = L.T(""DEFENDER : ÉTAT ILLISIBLE""), Couleur = Theme.Jaune });"))
    Cas 'cam/mic : « OFF » conditionné à la collecte lue' ($g.Contains(': Couverture.CamMicLue(etat)'))
    Cas 'pastille des collectes en panne, en jaune' ($g.Contains('if (enPanne != "") pastilles.Add(new Entete.Pastille { Texte = enPanne, Couleur = Theme.Jaune });'))
    Cas 'liste des alertes vide : message de Couverture' ($g.Contains("if (alertes.Count == 0)`n            {") -and $g.Contains('string message = Couverture.AucuneAlerte(dernierEtat);'))
    Cas 'message suivi quand seul l''état change' ($g.Contains("else if (couverture != couvertureVue)"))
    Cas 'détail d''une alerte : règle et collecte présumée' ($g.Contains('L.T("RÈGLE") + " : " + a.Regle'))
    # Ligne courte (la colonne la coupe), message entier dans le panneau de détail ; bandeau mis à la hauteur de son texte
    $t = & $appel 'LigneVide' (Etat @((Collecte 'Leurres' 'Indisponible')) @('LEU-001') @{ 'LEU-001' = @('Leurres') })
    Cas 'ligne vide courte, en panne' ($t -eq 'Aucune alerte, 1 détection muette ↓') $t
    Cas 'ligne vide sans panne : « Aucune alerte. »' ((& $appel 'LigneVide' (Etat @((Collecte 'ListesDomaines' 'Desactivee')) @('DNS-001') @{ 'DNS-001' = @('ListesDomaines') })) -eq 'Aucune alerte.')
    Cas 'message entier dans le panneau de détail' ($g.Contains('Couverture.LigneVide(dernierEtat)') -and $g.Contains("lvAlertes.Items.Add(vide);`n                detailAlerte.Text = message;"))
    Cas 'bandeau : hauteur mesurée sur le texte' ($g.Contains('TextRenderer.MeasureText(t, bandeauCollectes.Font, new Size(largeur, 0), TextFormatFlags.WordBreak)'))
    # Relecture de #80, D1 : la ligne « Aucune alerte… » n'a pas d'alerte derrière ; aucune action ne la convertit de force
    Cas 'aucune conversion forcée d''une ligne en alerte' (-not $g.Contains('(Alerte)lvAlertes.SelectedItems[0].Tag'))
    Cas 'exception et blocage : ligne sans alerte ignorée' ($g.Contains("var a = lvAlertes.SelectedItems[0].Tag as Alerte;`n            if (a == null) return;") -and $g.Contains('if (a == null || (string.IsNullOrEmpty(a.Ip) && string.IsNullOrEmpty(a.NomDns))) return;'))
    Cas 'bandeau des collectes dans la page Alertes' ($g.Contains('lvAlertes.Parent.Controls.Add(bandeauCollectes);') -and $g.Contains('var detail = Couverture.Detail(etat);'))
    Cas 'barre d''état : seulement les détections en panne' ($g.Contains('int muettes = Couverture.ReglesEnPanne(etat).Count;'))
    Cas 'couleur du message : jaune seulement sur panne' ($g.Contains('vide.ForeColor = Couverture.Alarme(dernierEtat) ? Theme.Jaune : Theme.TexteDim;'))
    Cas 'Defender : « lecture en cours » au démarrage' ($g.Contains('else if (Couverture.DefenderPasEncoreLu(etat))'))

    # Relecture de #80, D1, exécuté : la fenêtre est construite sans être affichée (dossier de données de test, aucun
    # service), la liste des alertes vide reçoit sa ligne « Aucune alerte… », elle est sélectionnée, puis les deux
    # actions du menu qui plantaient sont appelées
    $donnees = Join-Path $travail 'donnees'; New-Item -ItemType Directory -Path $donnees | Out-Null
    $asm.GetType('DeR4Tizer.Commun').GetField('Dossier').SetValue($null, $donnees)
    $fenT = $asm.GetType('DeR4Tizer.Fenetre')
    $prive = [Reflection.BindingFlags]'Instance,NonPublic,Public'
    $fen = $fenT.GetConstructor($prive, $null, @([bool]), $null).Invoke(@($true))
    try {
        $fen.CreateControl()
        $alerteT = $asm.GetType('DeR4Tizer.Alerte')
        $vide = & $liste $alerteT
        $fenT.GetMethod('RemplirAlertes', $prive).Invoke($fen, @(, $vide)) | Out-Null
        $lv = $fenT.GetField('lvAlertes', $prive).GetValue($fen)
        Cas 'liste vide : une seule ligne, sans alerte derrière' ($lv.Items.Count -eq 1 -and $null -eq $lv.Items[0].Tag) "$($lv.Items.Count) ligne(s)"
        # Sans poignée, la sélection n'est pas retenue et les actions sortent aussitôt : on la crée, et on vérifie
        [void]$lv.Handle
        $lv.Items[0].Selected = $true
        Cas 'ligne « Aucune alerte… » réellement sélectionnée (sinon le cas suivant ne prouverait rien)' ($lv.SelectedItems.Count -eq 1) "$($lv.SelectedItems.Count) sélectionnée(s)"
        foreach ($action in 'ExceptionAlerte', 'BloquerAlerte', 'DetaillerAlerte') {
            $erreur = $null
            try { $fenT.GetMethod($action, $prive).Invoke($fen, @()) | Out-Null } catch { $erreur = $_.Exception.InnerException }
            Cas "ligne « Aucune alerte… » sélectionnée : $action sans plantage" ($null -eq $erreur) "$erreur"
        }
    } finally {
        $fen.Dispose()
    }
} finally {
    Remove-Item -Recurse -Force $travail -ErrorAction SilentlyContinue
}
"$ko échec(s)"
if ($ko) { exit 1 }
