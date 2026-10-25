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
    & $csc /nologo /platform:anycpu /codepage:65001 /target:winexe /r:System.dll /r:System.Core.dll /r:System.Web.Extensions.dll /r:System.ServiceProcess.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll "/out:$out" "$src\Commun.cs" "$src\Langue.cs" "$src\Theme.cs" "$src\Gui.cs" "$src\Reglages.cs" "$src\Siem.cs" "$src\Trafic.cs" "$src\Reseau.cs" "/resource:$src\carte-pays.txt,carte-pays.txt" | Out-Null
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
    if ($ko) { exit 1 }
} finally {
    Remove-Item $travail -Recurse -Force -ErrorAction SilentlyContinue
}
