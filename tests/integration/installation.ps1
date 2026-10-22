# Lot 3a : installation, service, droits du dossier de données, compte standard, dossier précréé par un compte
# standard (fichiers à DACL vide, fichier tenu ouvert pendant le démarrage, redémarrage), mise à niveau depuis
# une version plus ancienne, désinstallations. Runner jetable seulement (voir commun.ps1).
param(
    [Parameter(Mandatory)] [string]$Msi,
    [Parameter(Mandatory)] [string]$MsiAncien,
    [Parameter(Mandatory)] [string]$Version,
    [string]$Journaux = (Join-Path $env:RUNNER_TEMP 'journaux-msi')
)
. (Join-Path $PSScriptRoot 'commun.ps1')
New-Item -ItemType Directory -Force -Path $Journaux | Out-Null
$PortPiege = 18999

# ---------------------------------------------------------------- préparation : compte standard
$compte = $null
Verifier 'Compte local standard créé' {
    $script:compte = Nouveau-CompteStandard
    $g = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID.Value -eq $script:compte.Sid })
    if ($g.Count) { return 'le compte est administrateur' }
    $true
}
$compte = $script:compte

# ---------------------------------------------------------------- dossier précréé par le compte standard
$tenu = $null
if ($compte) {
    Verifier 'Dossier de données précréé par le compte standard (pièges posés)' {
        if (Test-Path $script:Donnees) { return "le dossier existe déjà avant le test" }
        $config = '{"Api":{"Actif":true,"Port":' + $PortPiege + ',"Reseau":false,"Adresses":""}}'
        $lecteurs = '[{"Sid":"' + $compte.Sid + '","Nom":"pirate"}]'
        $s = En-TantQue $compte @"
New-Item -ItemType Directory -Path '$script:Donnees' -ErrorAction Stop | Out-Null
Set-Content -LiteralPath '$script:Donnees\config.json' -Value '$config' -Encoding Ascii
Set-Content -LiteralPath '$script:Donnees\lecteurs.json' -Value '$lecteurs' -Encoding Ascii
Set-Content -LiteralPath '$script:Donnees\apprentissage.json' -Value '{"Actif":false}' -Encoding Ascii
# DACL vide (propriétaire = ce compte) : propriétaire et contenu illisibles pour les autres
icacls '$script:Donnees\apprentissage.json' /inheritance:r | Out-Null
'PROPRIETAIRE=' + (Get-Acl '$script:Donnees').Owner
"@
        $d = Droits $script:Donnees
        if ($d.Proprietaire -ne $compte.Sid) { return "dossier non créé par le compte standard ($s)" }
        $true
    }
    # Fichier tenu ouvert (partage en lecture seule) par un processus du compte standard pendant l'installation
    # et le premier démarrage
    $tenu = En-TantQue $compte "`$h = [IO.File]::Open('$script:Donnees\lecteurs.json', 'Open', 'Read', 'Read'); Start-Sleep 600" -SansAttendre
    Start-Sleep 5
    if ($tenu.HasExited) { Noter 'Fichier tenu ouvert par le compte standard' 'ÉCHOUÉ' 'le processus qui tient le fichier s''est arrêté' }
} else {
    NonExecute 'Dossier de données précréé par le compte standard' 'compte standard indisponible'
}

# ---------------------------------------------------------------- installation et service
$debut = Get-Date
Verifier 'Installation du MSI' {
    $c = Installer $Msi (Join-Path $Journaux 'installation.log')
    if ($c -ne 0) { return "msiexec a rendu $c" }
    $true
}
Verifier 'Service : compte SYSTEM, démarrage automatique, en marche' {
    $s = Get-CimInstance Win32_Service -Filter "Name='deR4Tizer'"
    if (-not $s) { return 'service absent' }
    if ($s.StartName -ne 'LocalSystem') { return "compte $($s.StartName)" }
    if ($s.StartMode -ne 'Auto') { return "démarrage $($s.StartMode)" }
    if ($s.State -ne 'Running') { return "état $($s.State)" }
    $true
}
Verifier 'Service : redémarrage en cas d''échec' {
    $q = sc.exe qfailure deR4Tizer | Out-String
    if (@([regex]::Matches($q, 'RESTART')).Count -lt 1) { return "actions : $q" }
    $true
}
Verifier 'Canal : le service répond en administrateur, avec sa version' {
    $j = Attendre-Canal
    if (-not $j) { return 'aucune réponse' }
    if ($j.Message -ne "deR4Tizer $Version") { return "réponse : $($j.Message)" }
    $true
}
$etat1 = Attendre-Etat $debut
Verifier 'Dossier de données : propriétaire Administrateurs, héritage coupé' {
    $d = Droits $script:Donnees
    if ($d.Proprietaire -ne 'S-1-5-32-544') { return "propriétaire $($d.Proprietaire)" }
    if (-not $d.Protege) { return 'droits hérités de ProgramData' }
    $true
}
Verifier 'Dossier de données : aucune écriture pour Utilisateurs, Utilisateurs authentifiés, Tout le monde' {
    $d = Droits $script:Donnees
    $e = @($d.Entrees | Where-Object { $_.Autorise -and $_.Sid -in 'S-1-5-32-545', 'S-1-5-11', 'S-1-1-0' -and (Ecriture $_.Droits) })
    if ($e.Count) { return ($e | ForEach-Object { "$($_.Sid) : $($_.Droits)" }) -join ', ' }
    $true
}
NonExecute 'Dossier de données : lecture accordée au compte connecté à la console' 'aucune session de console sur un runner hébergé (VM nécessaire)'

if ($compte) {
    Verifier 'Dossier précréé : le compte standard n''a plus aucun droit' {
        $d = Droits $script:Donnees
        $e = @($d.Entrees | Where-Object { $_.Sid -eq $compte.Sid })
        if ($d.Proprietaire -eq $compte.Sid) { return 'toujours propriétaire' }
        if ($e.Count) { return ($e | ForEach-Object { "$($_.Droits)" }) -join ', ' }
        $true
    }
    Verifier 'Compte standard : canal refusé, aucune écriture dans le dossier de données' {
        $s = Essais-Standard $compte
        $mauvais = @('TUBE=REPONSE', 'FICHIER=ECRIT', 'DOSSIER=CREE', 'MAJ=ECRIT' | Where-Object { $s -match [regex]::Escape($_) })
        if ($mauvais.Count -or $s -notmatch 'TUBE=REFUSE') { return "résultats : $($s -replace "`r?`n", ' ')" }
        $true
    }
    Verifier 'Pièges, premier démarrage : configuration piégée jamais chargée (API du piège absente)' {
        if (Get-NetTCPConnection -LocalPort $PortPiege -State Listen -ErrorAction SilentlyContinue) { return "port $PortPiege en écoute" }
        $true
    }
    Verifier 'Pièges, premier démarrage : comptes autorisés piégés jamais chargés' {
        if (@((Droits $script:Donnees).Entrees | Where-Object { $_.Sid -eq $compte.Sid }).Count) { return 'le SID du piège a reçu des droits' }
        $true
    }
    Verifier 'Pièges, premier démarrage : fichier tenu ouvert → intact et échec fermé' {
        if ($tenu.HasExited) { return 'le processus qui tient le fichier s''est arrêté avant le test' }
        $e = Attendre-Etat $debut
        if (-not (Test-Path (Join-Path $script:Donnees 'lecteurs.json'))) { return 'lecteurs.json déplacé alors qu''il était tenu ouvert' }
        if (-not $e -or [string]::IsNullOrEmpty($e.ProtectionDonnees)) { return 'protection déclarée vérifiée alors qu''un élément n''a pas pu être écarté' }
        $true
    }
    # Le processus du compte standard se termine, puis redémarrage du service
    if ($tenu -and -not $tenu.HasExited) { Stop-Process -Id $tenu.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep 2
    $debut2 = Get-Date
    Restart-Service deR4Tizer -Force
    Verifier 'Pièges, second démarrage : fichier écarté, protection vérifiée' {
        if (-not (Attendre-Canal)) { return 'le service ne répond plus' }
        $e = Attendre-Etat $debut2
        if (Test-Path (Join-Path $script:Donnees 'lecteurs.json')) { return 'lecteurs.json toujours à la racine' }
        if (-not $e) { return 'état non publié' }
        if (-not [string]::IsNullOrEmpty($e.ProtectionDonnees)) { return "protection en échec : $($e.ProtectionDonnees)" }
        $true
    }
    Verifier 'Pièges, second démarrage : rien de piégé chargé (port, comptes autorisés, apprentissage)' {
        if (Get-NetTCPConnection -LocalPort $PortPiege -State Listen -ErrorAction SilentlyContinue) { return "port $PortPiege en écoute" }
        if (@((Droits $script:Donnees).Entrees | Where-Object { $_.Sid -eq $compte.Sid }).Count) { return 'le SID du piège a reçu des droits' }
        if (Test-Path (Join-Path $script:Donnees 'apprentissage.json')) {
            $d = Droits (Join-Path $script:Donnees 'apprentissage.json')
            if ($d.Proprietaire -eq $compte.Sid) { return 'apprentissage.json à DACL vide resté à la racine' }
        }
        $true
    }
} else {
    NonExecute 'Compte standard et pièges' 'compte standard indisponible'
}

# ---------------------------------------------------------------- désinstallation complète
Verifier 'Désinstallation sans GARDER_DONNEES : service, programme, données et règles de pare-feu retirés' {
    $c = Desinstaller (Join-Path $Journaux 'desinstallation-1.log')
    if ($c -ne 0) { return "msiexec a rendu $c" }
    $reste = @()
    if (Get-Service deR4Tizer -ErrorAction SilentlyContinue) { $reste += 'service' }
    if (Test-Path $script:Programme) { $reste += 'Program Files\deR4Tizer' }
    if (Test-Path $script:Donnees) { $reste += 'données' }
    if (@(Get-NetFirewallRule -Group 'deR4Tizer' -ErrorAction SilentlyContinue).Count) { $reste += 'règles de pare-feu' }
    if (@(Produits).Count) { $reste += 'entrée « Applications »' }
    if ($reste.Count) { return 'reste : ' + ($reste -join ', ') }
    $true
}

# ---------------------------------------------------------------- mise à niveau depuis une version plus ancienne
Verifier 'Version plus ancienne installée (MSI construit depuis un commit figé)' {
    $c = Installer $MsiAncien (Join-Path $Journaux 'installation-ancienne.log')
    if ($c -ne 0) { return "msiexec a rendu $c" }
    $p = @(Produits)
    if ($p.Count -ne 1 -or -not $p[0].DisplayVersion) { return "entrées : $($p.Count)" }
    if ((Get-Service deR4Tizer).Status -ne 'Running') { return 'service arrêté' }
    $script:VersionAncienne = $p[0].DisplayVersion
    $true
}
Start-Sleep 10
$journalAvant = if (Test-Path (Join-Path $script:Donnees 'journal.txt')) { Get-Content (Join-Path $script:Donnees 'journal.txt') -TotalCount 1 -Encoding UTF8 } else { $null }
Verifier 'Mise à niveau vers la version courante' {
    $c = Installer $Msi (Join-Path $Journaux 'mise-a-niveau.log')
    if ($c -ne 0) { return "msiexec a rendu $c" }
    $p = @(Produits)
    if ($p.Count -ne 1) { return "$($p.Count) entrées « Applications »" }
    if (-not $p[0].DisplayVersion.StartsWith($Version)) { return "version $($p[0].DisplayVersion) (avant : $script:VersionAncienne)" }
    $j = Attendre-Canal
    if (-not $j -or $j.Message -ne "deR4Tizer $Version") { return 'le service mis à niveau ne répond pas' }
    $true
}
Verifier 'Mise à niveau : données conservées, droits du dossier imposés' {
    if (-not $journalAvant) { return 'aucun journal écrit par la version précédente' }
    $premiere = Get-Content (Join-Path $script:Donnees 'journal.txt') -TotalCount 1 -Encoding UTF8
    if ($premiere -ne $journalAvant) { return 'journal remplacé' }
    $d = Droits $script:Donnees
    if ($d.Proprietaire -ne 'S-1-5-32-544' -or -not $d.Protege) { return "propriétaire $($d.Proprietaire), protégé $($d.Protege)" }
    $true
}

# ---------------------------------------------------------------- désinstallation en gardant les données
Verifier 'Désinstallation avec GARDER_DONNEES=1 : données gardées, le reste retiré' {
    $c = Desinstaller (Join-Path $Journaux 'desinstallation-2.log') @('GARDER_DONNEES=1')
    if ($c -ne 0) { return "msiexec a rendu $c" }
    if (-not (Test-Path (Join-Path $script:Donnees 'journal.txt'))) { return 'données supprimées' }
    $reste = @()
    if (Get-Service deR4Tizer -ErrorAction SilentlyContinue) { $reste += 'service' }
    if (Test-Path $script:Programme) { $reste += 'Program Files\deR4Tizer' }
    if (@(Get-NetFirewallRule -Group 'deR4Tizer' -ErrorAction SilentlyContinue).Count) { $reste += 'règles de pare-feu' }
    if ($reste.Count) { return 'reste : ' + ($reste -join ', ') }
    $true
}

Bilan 'Lot 3a : installation, droits, compte standard, dossier précréé, mise à niveau'
