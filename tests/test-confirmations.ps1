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
    & $csc /nologo /platform:anycpu /codepage:65001 /target:winexe /r:System.dll /r:System.Core.dll /r:System.Web.Extensions.dll /r:System.ServiceProcess.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll "/out:$out" "$src\Commun.cs" "$src\Langue.cs" "$src\Theme.cs" "$src\Gui.cs" "$src\Reglages.cs" "$src\Siem.cs" "$src\Incidents.cs" "$src\Trafic.cs" "$src\Reseau.cs" "/resource:$src\carte-pays.txt,carte-pays.txt" | Out-Null
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
            $c.Action = $k.A; $c.Cible = $piege; $c.Ip = $piege; $c.Valeur = $piege
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
    Verifier-Fenetre 'notifications : fin de l''hôte à part' { if ($texte -match "`n\s+l'hôte se termine par : attaquant\.test(`n|$)") { $true } else { $texte } }
    $f = $canal.GetMethod('FenetreConfirmation').Invoke($null, @($texte, $false))
    try {
        $zone = $f.Controls.Find('Texte', $true)[0]; $annuler = $f.Controls.Find('Annuler', $true)[0]; $continuer = $f.Controls.Find('Continuer', $true)[0]
        Verifier-Fenetre 'fenêtre : texte entier, sans troncature' { $zone.Text.Replace("`r`n", "`n").EndsWith($texte) -and $zone.Text.Contains(((('a' * 60) + '.') * 4) + 'attaquant.test') }
        Verifier-Fenetre 'fenêtre : renvoi à la ligne et défilement, lecture seule' { $zone.Multiline -and $zone.WordWrap -and $zone.ReadOnly -and $zone.ScrollBars -eq 'Vertical' }
        Verifier-Fenetre 'fenêtre : « Annuler » par défaut (Entrée, Échap)' { $f.AcceptButton -eq $annuler -and $f.CancelButton -eq $annuler -and $f.ActiveControl -eq $annuler -and $annuler.DialogResult -eq 'Cancel' }
        Verifier-Fenetre 'fenêtre : « Continuer » seul renvoie Oui' { $continuer.DialogResult -eq 'Yes' }
        Verifier-Fenetre 'fenêtre : « Continuer » désarmé à l''ouverture (armé 1 s après l''affichage)' { -not $continuer.Enabled }
    } finally { $f.Dispose() }
    # Armement réel (fenêtre montrée hors de l'écran, jamais à l'emplacement visible) : inactif à l'affichage, actif après
    # 1 s, désarmé quand une autre fenêtre prend le premier plan, réarmé 1 s après le retour (S69-02, S69-03)
    $f = $canal.GetMethod('FenetreConfirmation').Invoke($null, @('essai', $false))
    $autre = New-Object Windows.Forms.Form
    try {
        $f.StartPosition = 'Manual'; $f.Location = New-Object Drawing.Point(-4000, -4000); $f.ShowInTaskbar = $false
        $autre.StartPosition = 'Manual'; $autre.Location = New-Object Drawing.Point(-4000, -3000); $autre.ShowInTaskbar = $false
        $k = $f.Controls.Find('Continuer', $true)[0]
        function Attendre([int]$ms) { $fin = [DateTime]::UtcNow.AddMilliseconds($ms); while ([DateTime]::UtcNow -lt $fin) { [Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 20 } }
        $f.Show(); Attendre 150; $a0 = $k.Enabled; Attendre 1400; $a1 = $k.Enabled
        $autre.Show(); $autre.Activate(); Attendre 300; $a2 = $k.Enabled; Attendre 1300; $a3 = $k.Enabled
        $f.Activate(); Attendre 200; $a4 = $k.Enabled; Attendre 1400; $a5 = $k.Enabled
        Verifier-Fenetre 'armement : inactif à l''affichage, actif après 1 s' { if (-not $a0 -and $a1) { $true } else { "0,15 s : $a0 ; 1,55 s : $a1" } }
        Verifier-Fenetre 'armement : désarmé hors du premier plan, réarmé 1 s après le retour' { if (-not $a2 -and -not $a3 -and -not $a4 -and $a5) { $true } else { "perte : $a2/$a3 ; retour : $a4/$a5" } }
    } finally { $autre.Dispose(); $f.Dispose() }
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
    "bilan fenêtre : $kof échec(s)"
    if ($ko -or $kof) { exit 1 }
} finally {
    Remove-Item $travail -Recurse -Force -ErrorAction SilentlyContinue
}
