# Lot 3a : installation, service, droits du dossier de données, compte standard, dossier précréé par un compte
# standard (fichiers à DACL vide, fichier tenu ouvert pendant le démarrage, redémarrage), mise à niveau depuis
# une version plus ancienne pendant laquelle un compte standard a posé un piège, désinstallations. Runner jetable
# seulement (voir commun.ps1).
#
# Chaque « jamais chargé » a son témoin positif : une configuration légitime (propriétaire Administrateurs) ouvre
# un port témoin quand elle est chargée, des comptes autorisés légitimes donnent une entrée de lecture. Un port
# fermé ou une entrée absente ne prouvent donc quelque chose que si le témoin s'est ouvert ailleurs.
param(
    [Parameter(Mandatory)] [string]$Msi,
    [Parameter(Mandatory)] [string]$MsiAncien,
    [Parameter(Mandatory)] [string]$Version,
    [string]$Journaux = (Join-Path $env:RUNNER_TEMP 'journaux-msi')
)
. (Join-Path $PSScriptRoot 'commun.ps1')
New-Item -ItemType Directory -Force -Path $Journaux | Out-Null

# Configuration légitime : API sur le port témoin, ouverte au réseau pour une adresse de documentation
# (192.0.2.10) afin que le service crée ses règles de pare-feu (désinstallation vérifiée sur des règles réelles)
$PortTemoin = 18998
$ConfigLegitime = '{"Api":{"Actif":true,"Port":' + $PortTemoin + ',"Reseau":true,"Adresses":"192.0.2.10"}}'
# Configuration piégée posée par le compte standard pendant que la 4.1.0 tourne
$PortPiege = 18997
$ConfigPiegee = '{"Api":{"Actif":true,"Port":' + $PortPiege + ',"Reseau":false,"Adresses":""}}'
# TrustedInstaller : droit hérité de Program Files sur tout sous-dossier (le service ne l'a pas choisi)
$Toleres = @{ $script:Programme = @($script:SidTrustedInstaller) }
$Racines = @($script:Donnees, $script:Programme)

function Reglesparefeu { @(Get-NetFirewallRule -Group 'deR4Tizer' -ErrorAction SilentlyContinue).Count }

# Le fichier n'est pas à la racine, ou il y est mais appartient à SYSTEM ou aux administrateurs (réécrit par le
# service) et ne contient pas le motif du piège ; et il a bien été mis de côté dans « ecartes »
function Piege-Ecarte([string]$Nom, [string]$Motif) {
    if (-not (Ecarte $Nom).Count) { return "$Nom absent de ecartes" }
    $f = Join-Path $script:Donnees $Nom
    if (Test-Path $f) {
        $d = Droits $f
        if ($d.Proprietaire -notin $script:SidsConfiance) { return "$Nom toujours à la racine (propriétaire $($d.Proprietaire))" }
        if ((Get-Content $f -Raw -Encoding UTF8) -match [regex]::Escape($Motif)) { return "$Nom à la racine contient le piège" }
    }
    $true
}

# ---------------------------------------------------------------- préparation : comptes
$compte = $null; $lecteur = $null
Verifier 'Compte local standard créé (auteur des pièges)' {
    $script:compte = Nouveau-CompteStandard
    if (@(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID.Value -eq $script:compte.Sid }).Count) { return 'le compte est administrateur' }
    $true
}
Verifier 'Second compte local standard créé (témoin des comptes autorisés)' {
    $script:lecteur = Nouveau-CompteStandard 'd4t_lecteur'
    $true
}

# ---------------------------------------------------------------- dossier précréé par le compte standard
$tenu = $null
$fLecteurs = Join-Path $script:Donnees 'lecteurs.json'
if ($compte) {
    Verifier 'Dossier de données précréé par le compte standard (pièges posés), configuration légitime de l''administrateur' {
        if (Test-Path $script:Donnees) { return "le dossier existe déjà avant le test" }
        $lecteurs = '[{"Sid":"' + $compte.Sid + '","Nom":"pirate"}]'
        $s = En-TantQue $compte @"
New-Item -ItemType Directory -Path '$script:Donnees' -ErrorAction Stop | Out-Null
Set-Content -LiteralPath '$fLecteurs' -Value '$lecteurs' -Encoding Ascii
Set-Content -LiteralPath '$script:Donnees\apprentissage.json' -Value '{"Actif":false}' -Encoding Ascii
# DACL vide (propriétaire = ce compte) : propriétaire et contenu illisibles pour les autres
icacls '$script:Donnees\apprentissage.json' /inheritance:r | Out-Null
'POSE'
"@
        if ((Droits $script:Donnees).Proprietaire -ne $compte.Sid) { return "dossier non créé par le compte standard ($s)" }
        if ((Droits $fLecteurs).Proprietaire -ne $compte.Sid) { return 'lecteurs.json piégé absent' }
        # Témoin positif : configuration légitime, propriétaire Administrateurs, dans le même dossier
        Poser-EnAdministrateur 'config.json' $ConfigLegitime
        $true
    }
    # Fichier tenu ouvert (partage en lecture seule) par un processus du compte standard pendant l'installation
    # et le premier démarrage ; le processus écrit un marqueur une fois le fichier ouvert
    $marqueur = Join-Path $script:Commun 'tenu.txt'
    $tenu = En-TantQue $compte "`$h = [IO.File]::Open('$fLecteurs', 'Open', 'Read', 'Read'); if (`$h) { [IO.File]::WriteAllText('$marqueur', 'ouvert'); Start-Sleep 600 }" -SansAttendre
    Verifier 'Fichier piège tenu ouvert par le compte standard (marqueur écrit après l''ouverture)' {
        $fin = (Get-Date).AddSeconds(30)
        while ((Get-Date) -lt $fin -and -not (Test-Path $marqueur)) { Start-Sleep 1 }
        if (-not (Test-Path $marqueur)) { return "marqueur absent (processus arrêté : $($tenu.HasExited))" }
        if ($tenu.HasExited) { return 'le processus qui tient le fichier s''est arrêté' }
        $true
    }
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

if ($compte) {
    # ------------------------------------------------------------ premier démarrage : échec fermé
    Verifier 'Premier démarrage : échec fermé déclaré, fichier tenu ouvert intact' {
        if ($tenu.HasExited) { return 'le processus qui tient le fichier s''est arrêté avant le test' }
        if (-not $etat1) { return 'état non publié' }
        if ([string]::IsNullOrEmpty($etat1.ProtectionDonnees)) { return 'protection déclarée vérifiée alors qu''un élément n''a pas pu être écarté' }
        if ((Droits $fLecteurs).Proprietaire -ne $compte.Sid) { return 'lecteurs.json modifié alors qu''il était tenu ouvert' }
        $true
    }
    Verifier 'Premier démarrage : configuration légitime non chargée en échec fermé (port témoin fermé)' {
        if (Port-Ouvert $PortTemoin) { return "port $PortTemoin en écoute : configuration chargée malgré l'échec fermé" }
        $true
    }
    Verifier 'Premier démarrage : comptes autorisés piégés jamais chargés' {
        if (@((Droits $script:Donnees).Entrees | Where-Object { $_.Sid -eq $compte.Sid }).Count) { return 'le SID du piège a reçu des droits' }
        $true
    }
    Verifier 'Premier démarrage : apprentissage.json à DACL vide écarté (contrôlé par l''emplacement seulement)' {
        if (-not (Ecarte 'apprentissage.json').Count) { return "absent de ecartes ; journal : $(Journal 'protection des donn')" }
        $true
    }
    Verifier 'Premier démarrage : droits de chaque élément (données, Program Files), hors fichier tenu ouvert' {
        Controle-Droits $Racines @('lecteurs.json') $Toleres
    }
    Verifier 'Premier démarrage : le compte standard n''a plus aucun droit sur le dossier' {
        $d = Droits $script:Donnees
        if ($d.Proprietaire -eq $compte.Sid) { return 'toujours propriétaire' }
        $e = @($d.Entrees | Where-Object { $_.Sid -eq $compte.Sid })
        if ($e.Count) { return ($e | ForEach-Object { "$($_.Droits)" }) -join ', ' }
        $true
    }
    Verifier 'Premier démarrage : compte standard refusé (canal, création et écriture partout, hors fichier tenu ouvert)' {
        Essais-Standard $compte @($fLecteurs)
    }

    # ------------------------------------------------------------ second démarrage, fichier relâché
    Verifier 'Processus du piège arrêté (fichier relâché)' {
        if (-not $tenu.HasExited) { Stop-Process -Id $tenu.Id -Force }
        if (-not $tenu.WaitForExit(15000)) { return 'le processus ne s''arrête pas' }
        $true
    }
    # Dans Verifier : un redémarrage raté est un ÉCHOUÉ du tableau, pas un arrêt du script sans bilan
    $debut2 = Get-Date
    Verifier 'Second démarrage : le service redémarre et répond' { $script:debut2 = Redemarrer-Service; $true }
    $etat2 = Attendre-Etat $debut2
    Verifier 'Second démarrage : protection vérifiée' {
        if (-not $etat2) { return 'état non publié' }
        if (-not [string]::IsNullOrEmpty($etat2.ProtectionDonnees)) { return "protection en échec : $($etat2.ProtectionDonnees)" }
        $true
    }
    # Comptes autorisés piégés écartés et aucun autre : le service accorde la lecture au compte de la console
    $console = (Get-CimInstance Win32_ComputerSystem).UserName
    $consoleSid = $null
    if ($console) { try { $consoleSid = (New-Object Security.Principal.NTAccount($console)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { } }
    if ($consoleSid -like 'S-1-5-21-*') {
        # Runner hébergé : runneradmin, un administrateur ; le cas d'un utilisateur standard demande une VM
        $genre = if (@(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID.Value -eq $consoleSid }).Count) { "session d'administrateur" } else { "session d'utilisateur standard" }
        Verifier "Second démarrage : lecture accordée au compte connecté à la console ($genre, $console), sans écriture" {
            $fin = (Get-Date).AddSeconds(60)
            do {
                $a = @((Droits $script:Donnees).Entrees | Where-Object { $_.Sid -eq $consoleSid -and $_.Autorise })
                if ($a.Count) { break }
                Start-Sleep 2
            } while ((Get-Date) -lt $fin)
            if (-not $a.Count) { return "aucune entrée pour $console ; journal : $(Journal 'protection des donn')" }
            if (@($a | Where-Object { Ecriture $_.Droits }).Count) { return "droit d'écriture : $($a.Droits -join ', ')" }
            $true
        }
    } else {
        NonExecute 'Dossier de données : lecture accordée au compte connecté à la console' "aucun compte utilisateur à la console ($console)"
    }
    Verifier 'Second démarrage : configuration légitime chargée (port témoin ouvert)' {
        if (-not (Attendre-Port $PortTemoin)) { return "port $PortTemoin fermé ; journal : $(Journal 'API|protection des donn')" }
        $true
    }
    Verifier 'Second démarrage : comptes autorisés piégés écartés et jamais chargés' {
        $r = Piege-Ecarte 'lecteurs.json' $compte.Sid
        if ($r -ne $true) { return "$r ; journal : $(Journal 'protection des donn')" }
        if (@((Droits $script:Donnees).Entrees | Where-Object { $_.Sid -eq $compte.Sid }).Count) { return 'le SID du piège a reçu des droits' }
        $true
    }
    # Dossier « maj » du dossier de données : créé par une recherche de mise à jour (manifeste public du dépôt,
    # installation automatique désactivée par défaut), pour que les essais du compte standard le couvrent
    Verifier 'Dossier maj créé par une recherche de mise à jour' {
        $j = Commande '{"Action":"majVerifier"}' | ConvertFrom-Json
        if (-not $j.Ok) { return "réponse : $($j.Message)" }
        $fin = (Get-Date).AddSeconds(60)
        while ((Get-Date) -lt $fin -and -not (Test-Path (Join-Path $script:Donnees 'maj'))) { Start-Sleep 2 }
        if (-not (Test-Path (Join-Path $script:Donnees 'maj'))) { return 'dossier maj absent' }
        $true
    }
    Verifier 'Second démarrage : droits de chaque élément (données, Program Files)' {
        Controle-Droits $Racines @() $Toleres
    }
    Verifier 'Second démarrage : compte standard refusé (canal, création et écriture partout, maj compris)' {
        Essais-Standard $compte
    }

    # ------------------------------------------------------------ comptes autorisés légitimes
    if ($lecteur) {
        Verifier 'Comptes autorisés légitimes : le second compte reçoit la lecture, sans écriture' {
            Poser-EnAdministrateur 'lecteurs.json' ('[{"Sid":"' + $lecteur.Sid + '","Nom":"d4t_lecteur"}]')
            $d3 = Redemarrer-Service
            $e = Attendre-Etat $d3
            if (-not $e -or -not [string]::IsNullOrEmpty($e.ProtectionDonnees)) { return "protection : $($e.ProtectionDonnees)" }
            $a = @((Droits $script:Donnees).Entrees | Where-Object { $_.Sid -eq $lecteur.Sid -and $_.Autorise })
            if (-not $a.Count) { return "aucune entrée pour le second compte ; journal : $(Journal 'protection des donn')" }
            if (@($a | Where-Object { Ecriture $_.Droits }).Count) { return "droit d'écriture accordé : $($a.Droits -join ', ')" }
            if (@((Droits $script:Donnees).Entrees | Where-Object { $_.Sid -eq $compte.Sid }).Count) { return 'le SID du piège a reçu des droits' }
            $s = En-TantQue $lecteur "try { [void][IO.File]::ReadAllText('$script:Donnees\etat.json'); 'LECTURE=OK' } catch { 'LECTURE=' + `$_.Exception.GetType().Name }"
            if ($s -notmatch 'LECTURE=OK') { return "lecture refusée au second compte : $s" }
            $true
        }
        Verifier 'Comptes autorisés légitimes : second compte refusé (canal, création et écriture partout)' {
            Essais-Standard $lecteur
        }
    } else {
        NonExecute 'Comptes autorisés légitimes' 'second compte indisponible'
    }

    # ------------------------------------------------------------ réparation par un compte standard
    # Condition de lancement AdminUser (installeur\deR4Tizer.wxs) : une réparation arrêterait puis relancerait le
    # service ; refusée à un compte standard. Preuve : code de retour d'échec et même processus du service.
    # Témoin d'abord : la même réparation par l'administrateur réussit et relance le service (autre PID) ; sans
    # lui, « même PID » ne prouverait rien.
    Verifier 'Réparation (msiexec /fa) par l''administrateur (témoin) : acceptée (code 0), service relancé (autre PID)' {
        $code = (Produits | Select-Object -First 1).PSChildName
        if (-not $code) { return 'code produit introuvable' }
        $avant = (Get-CimInstance Win32_Service -Filter "Name='deR4Tizer'").ProcessId
        $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList '/fa', $code, '/qn', '/norestart', '/l*v', "`"$(Join-Path $Journaux 'reparation-administrateur.log')`""
        if ($p.ExitCode -ne 0) { return "msiexec a rendu $($p.ExitCode)" }
        if (-not (Attendre-Canal)) { return 'le service ne répond plus après la réparation' }
        $apres = (Get-CimInstance Win32_Service -Filter "Name='deR4Tizer'").ProcessId
        if ($apres -eq $avant) { return "service non relancé (PID $avant inchangé) : le témoin ne distingue rien" }
        $true
    }
    Verifier 'Réparation (msiexec /fa) par le compte standard : refusée, service jamais relancé (même PID)' {
        $code = (Produits | Select-Object -First 1).PSChildName
        if (-not $code) { return 'code produit introuvable' }
        $avant = (Get-CimInstance Win32_Service -Filter "Name='deR4Tizer'").ProcessId
        $journal = Join-Path $script:Commun 'reparation-standard.log'
        $s = En-TantQue $compte @"
`$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList '/fa', '$code', '/qn', '/l*v', '"$journal"'
'CODE=' + `$p.ExitCode
"@ -Secondes 300
        if (Test-Path $journal) { Copy-Item $journal (Join-Path $Journaux 'reparation-standard.log') }
        $apres = (Get-CimInstance Win32_Service -Filter "Name='deR4Tizer'").ProcessId
        if ($s -notmatch 'CODE=(\d+)') { return "msiexec sans code de retour : $($s -replace "`r?`n", ' ')" }
        if ([int]$Matches[1] -eq 0) { return 'réparation acceptée (code 0)' }
        if ($apres -ne $avant) { return "service relancé (PID $avant → $apres)" }
        if (-not (Attendre-Canal 30)) { return 'le service ne répond plus' }
        $true
    }
} else {
    NonExecute 'Compte standard et pièges' 'compte standard indisponible'
}

# ---------------------------------------------------------------- état des collectes (phase 3.3)
# Témoin retenu : toutes les collectes sont notées (aucune « Inconnue ») ; celles que la VM fournit sont lues
# (Sysmon absent : désactivée, WMI partielle ; listes de domaines désactivées par le réglage par défaut) et leurs règles
# ne sont pas « sans collecte ». Témoin écarté : une liste LOLDrivers vide (posée par l'administrateur, propriétaire
# contrôlé) rend LOLDrivers « Indisponible » et PIL-001 sans collecte. Le journal DNS coupé après le
# démarrage (D4) et un témoin écarté « Indisponible » (journal du pare-feu coupé) viennent avec la PR 3.3c, plus bas ;
# aucun témoin n'exerce les branches « Indisponible » des leurres, de la capture ou de la persistance : les provoquer en
# VM toucherait au fonctionnement du poste de test.
Verifier 'État des collectes : toutes notées, collectes de la VM actives' {
    # Defender, extensions, LOLDrivers (téléchargement : 300 s au plus) puis baseline sont lus par le fil « contrôles »
    # au démarrage : attendus en 7 min au plus
    $fin = (Get-Date).AddSeconds(420)
    do {
        $e = Etat
        $c = @{}
        if ($e -and $e.Collectes) { foreach ($x in $e.Collectes) { $c[$x.Id] = $x } }
        if ($c.Count -and -not @($c.Values | Where-Object { $_.Etat -eq 'Inconnue' }).Count) { break }
        Start-Sleep 3
    } while ((Get-Date) -lt $fin)
    if (-not $c.Count) { return 'etat.json sans Collectes' }
    $vu = ($c.Values | ForEach-Object { "$($_.Id)=$($_.Etat)" }) -join ' '
    $inconnues = @($c.Values | Where-Object { $_.Etat -eq 'Inconnue' } | ForEach-Object { $_.Id })
    if ($inconnues.Count) { return "collecte(s) jamais notée(s) : $($inconnues -join ', ') ; $vu" }
    foreach ($id in 'Connexions', 'Processus', 'JournalDefender', 'EtatDefender', 'JournalSecurite', 'JournalSysteme', 'JournalParefeu', 'JournalDns', 'Sessions',
                    'Persistance', 'Leurres', 'Extensions', 'Peripheriques', 'CaptureTrafic') {
        if (-not $c[$id]) { return "collecte $id absente ; $vu" }
        if ($c[$id].Etat -ne 'Active') { return "collecte $id : $($c[$id].Etat) ($($c[$id].Raison)) ; $vu" }
    }
    $sysmon = [bool](Get-Service Sysmon, Sysmon64 -ErrorAction SilentlyContinue)
    if ($sysmon) {
        if ($c['Sysmon'].Etat -ne 'Active') { return "Sysmon présent mais collecte $($c['Sysmon'].Etat) ; $vu" }
    } else {
        if ($c['Sysmon'].Etat -ne 'Desactivee') { return "Sysmon absent mais collecte $($c['Sysmon'].Etat) ; $vu" }
        if ($c['WmiProcessus'].Etat -ne 'Partielle') { return "WMI des processus : $($c['WmiProcessus'].Etat) ; $vu" }
    }
    if ($c['Baseline'].Etat -notin 'Active', 'Partielle') { return "baseline : $($c['Baseline'].Etat) ($($c['Baseline'].Raison)) ; $vu" }
    if ($c['ListesDomaines'].Etat -ne 'Desactivee') { return "listes de domaines : $($c['ListesDomaines'].Etat) (attendues désactivées par défaut) ; $vu" }
    $sans = @($e.ReglesSansCollecte)
    foreach ($r in 'DEF-001', 'DEF-010', 'RES-002', 'RES-003', 'SYS-002', 'COR-R1', 'PER-001', 'CHA-001', 'LEU-001', 'EXT-001', 'VIE-001', 'EXP-IDS-001') {
        if ($sans -contains $r) { return "règle $r publiée sans collecte ; sans collecte : $($sans -join ', ')" }
    }
    # Cause publiée (PR 3.3d) : DNS-001, sans collecte par défaut, manque des listes de domaines (coupées par défaut)
    $cause = @($e.CausesSansCollecte | Where-Object { $_.Regle -eq 'DNS-001' }) | Select-Object -First 1
    if ($sans -contains 'DNS-001' -and (-not $cause -or @($cause.Collectes) -notcontains 'ListesDomaines')) { return "cause de DNS-001 absente ou fausse : $(if ($cause) { @($cause.Collectes) -join ', ' } else { 'aucune' })" }
    $deg = @($e.ReglesDegradees)
    if (-not $sysmon -and $deg -notcontains 'PRC-002') { return "PRC-002 (WMI seul) non dégradée : $($deg -join ', ')" }
    Write-Host "  collectes : $vu"
    Write-Host "  sans collecte : $($sans -join ', ')"
    $true
}

Verifier 'État des collectes : liste LOLDrivers vide publiée indisponible, PIL-001 sans collecte' {
    # Récente : le service ne la retélécharge pas ; lue au premier tour du fil « contrôles »
    New-Item -ItemType Directory -Force (Join-Path $script:Donnees 'menaces') | Out-Null
    Poser-EnAdministrateur 'menaces\loldrivers.json' '[]'
    $d = Redemarrer-Service
    $fin = (Get-Date).AddSeconds(180)
    do {
        $e = Attendre-Etat $d 60
        $l = if ($e) { @($e.Collectes | Where-Object { $_.Id -eq 'Loldrivers' }) | Select-Object -First 1 }
        if ($l -and $l.Etat -ne 'Inconnue') { break }
        Start-Sleep 3
    } while ((Get-Date) -lt $fin)
    if (-not $l) { return 'collecte Loldrivers absente' }
    if ($l.Etat -ne 'Indisponible') { return "LOLDrivers : $($l.Etat) ($($l.Raison))" }
    if (@($e.ReglesSansCollecte) -notcontains 'PIL-001') { return "PIL-001 absente des règles sans collecte : $(@($e.ReglesSansCollecte) -join ', ')" }
    Write-Host "  LOLDrivers : $($l.Etat) ($($l.Raison))"
    # Liste vide retirée : les contrôles suivants retrouvent une liste téléchargée au prochain démarrage
    Remove-Item (Join-Path $script:Donnees 'menaces\loldrivers.json') -Force -ErrorAction SilentlyContinue
    $true
}

# Phase 3.3c, décision D4 : le journal DNS-Client coupé après le démarrage est réactivé par le service (il le lit à
# chaque tour de 2 s), avec une ligne dans journal.txt
Verifier 'Journal DNS coupé après le démarrage : réactivé par le service, ligne de journal (D4)' {
    $dns = 'Microsoft-Windows-DNS-Client/Operational'
    # Au premier tour après un démarrage, le service applique le profil « journalisation » s'il le voit non conforme, ce qui
    # réactiverait aussi ce journal, sans la ligne attendue ici (échecs du 2026-10-31 : cause probable, d'après le code, non
    # mesurée). Attente de la fin de ce tour : baseline.json écrit depuis le démarrage du service
    $demarrage = (Get-Process -Id (Get-CimInstance Win32_Service -Filter "Name='deR4Tizer'").ProcessId).StartTime
    $baseline = Join-Path $script:Donnees 'baseline.json'
    $fin = (Get-Date).AddSeconds(180)
    while (((-not (Test-Path $baseline)) -or (Get-Item $baseline).LastWriteTime -lt $demarrage) -and (Get-Date) -lt $fin) { Start-Sleep 2 }
    wevtutil sl $dns /e:false
    # La coupure doit être constatée : sinon « réactivé » ne prouverait rien. La relecture peut tomber après la réactivation
    # (tour de 2 s) : la ligne de journal le dira plus bas
    $coupe = [bool]((wevtutil gl $dns) -match 'enabled:\s*false')
    $fin = (Get-Date).AddSeconds(60)
    do {
        Start-Sleep 2
        $actif = [bool]((wevtutil gl $dns) -match 'enabled:\s*true')
    } while (-not $actif -and (Get-Date) -lt $fin)
    if (-not $actif) {
        wevtutil sl $dns /e:true
        return "journal DNS non réactivé en 60 s ; journal : $(Journal 'DNS-Client')"
    }
    # Le service écrit la ligne juste après wevtutil : 15 s pour l'écrire (échec du 2026-10-31 : lue une seule fois, vide)
    $fin = (Get-Date).AddSeconds(15)
    do {
        $l = Journal 'DNS-Client/Operational désactivé'
        if ($l -match 'réactivé') { break }
        Start-Sleep 1
    } while ((Get-Date) -lt $fin)
    if ($l -notmatch 'réactivé') { Copy-Item (Join-Path $script:Donnees 'journal.txt') (Join-Path $Journaux 'journal-apres-d4.txt') -Force -ErrorAction SilentlyContinue; return "réactivé sans ligne de journal en 15 s : « $l » ; coupure constatée : $coupe ; baseline : $(Journal 'baseline' 3) ; journal : $(Journal 'DNS' 4)" }
    # Trace du contrôle, réussi ou non (cause des échecs du 2026-10-31 : probable, non mesurée)
    Write-Host "  coupure constatée : $coupe ; baseline : $(Journal 'baseline' 3)"
    Copy-Item (Join-Path $script:Donnees 'journal.txt') (Join-Path $Journaux 'journal-apres-d4.txt') -Force -ErrorAction SilentlyContinue
    $true
}

# Phase 3.3c, témoin écarté d'une branche « Indisponible » (relecture de la PR 3.3b, D7) : le journal du pare-feu coupé
# n'est pas réactivé (D4 ne vise que le DNS) ; la collecte passe « Indisponible » et SYS-002 sans collecte, puis
# redevient « Active » une fois le journal rallumé par le script
Verifier 'Journal du pare-feu coupé : collecte indisponible, SYS-002 sans collecte, puis de nouveau active' {
    $pf = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
    $etat = {
        param($Attendu)
        $fin = (Get-Date).AddSeconds(90)
        do {
            Start-Sleep 3
            $e = Etat
            $j = if ($e) { @($e.Collectes | Where-Object { $_.Id -eq 'JournalParefeu' }) | Select-Object -First 1 }
        } while ((-not $j -or $j.Etat -ne $Attendu) -and (Get-Date) -lt $fin)
        @{ E = $e; J = $j }
    }
    wevtutil sl $pf /e:false
    try {
        $r = & $etat 'Indisponible'; $e = $r.E; $j = $r.J
        if (-not $j -or $j.Etat -ne 'Indisponible') { return "journal du pare-feu coupé, collecte : $($j.Etat) ($($j.Raison))" }
        if (@($e.ReglesSansCollecte) -notcontains 'SYS-002') { return "SYS-002 absente des règles sans collecte : $(@($e.ReglesSansCollecte) -join ', ')" }
        Write-Host "  pare-feu coupé : $($j.Etat) ($($j.Raison))"
    } finally {
        wevtutil sl $pf /e:true
    }
    $r = & $etat 'Active'; $j = $r.J
    if (-not $j -or $j.Etat -ne 'Active') { return "journal du pare-feu rallumé, collecte : $($j.Etat) ($($j.Raison))" }
    $true
}

# ---------------------------------------------------------------- phase 4, PR 4.4a : santé des collectes
# Le fil « sante » (toutes les 30 s) écrit chaque changement d'état d'une collecte dans le SIEM (Source « sante ») : le
# journal du pare-feu est coupé jusqu'à l'événement « Indisponible », puis rallumé jusqu'à l'événement « Active ». Aucun
# constat SAN-* avant 30 min (la coupure dure moins), et Defender pleinement actif ne lève pas SAN-003
Verifier 'Santé : coupure du journal du pare-feu historisée dans le SIEM, aucun constat SAN' {
    $pf = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
    $siem = Join-Path $script:Donnees 'siem'
    # Seulement les événements de ce contrôle : la coupure précédente a pu en écrire
    $debut = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $sante = {
        param($Vers)
        $fin = (Get-Date).AddSeconds(120)
        do {
            Start-Sleep 3
            $l = @(Get-ChildItem $siem -Filter 'evenements-*.ndjson' -ErrorAction SilentlyContinue | ForEach-Object { Get-Content $_.FullName -Encoding UTF8 } |
                Where-Object { $_ -match '"Source":"sante"' -and $_ -match '"Destination":"JournalParefeu"' -and $_ -match '"HeureUtc":"([^"]*)"' -and $Matches[1] -ge $debut } |
                ForEach-Object { $_ | ConvertFrom-Json } |
                Where-Object { $_.Message -match "→ $Vers" })
        } while (-not $l.Count -and (Get-Date) -lt $fin)
        $l | Select-Object -Last 1
    }
    wevtutil sl $pf /e:false
    try {
        $coupe = & $sante 'Indisponible'
        if (-not $coupe) { return 'aucun événement « sante » JournalParefeu → Indisponible en 120 s' }
        if ($coupe.Type -ne 'collecte' -or $coupe.Niveau -ne 'Alerte') { return "événement inattendu : $($coupe.Type) / $($coupe.Niveau) / $($coupe.Message)" }
        Write-Host "  SIEM : $($coupe.Message)"
    } finally {
        wevtutil sl $pf /e:true
    }
    $retour = & $sante 'Active'
    if (-not $retour) { return 'aucun événement « sante » JournalParefeu → Active en 120 s après le rallumage' }
    Write-Host "  SIEM : $($retour.Message)"
    $alertes = Join-Path $script:Donnees 'alertes.json'
    $san = @(if (Test-Path $alertes) { (Get-Content $alertes -Raw -Encoding UTF8 | ConvertFrom-Json) | Where-Object { "$($_.Regle)" -like 'SAN-*' } })
    if ($san.Count) { return "constat(s) SAN inattendu(s) : $(($san | ForEach-Object { "$($_.Regle) $($_.Destination)" }) -join ', ')" }
    $true
}

# ---------------------------------------------------------------- phase 4, PR 4.4b : santé de la remontée
# Remontée non configurée en VM : notifications.json publie les champs de la 4.4b sans échec ni attente, et aucun
# constat SAN-004 n'est levé. Le chemin d'échec (file de reprise, SAN-004 après une heure) est couvert par les tests
# unitaires seulement
Verifier 'Remontée non configurée : notifications.json sans échec ni attente, aucun SAN-004' {
    $f = Join-Path $script:Donnees 'notifications.json'
    if (-not (Test-Path $f)) { return 'notifications.json absent' }
    $brut = Get-Content $f -Raw -Encoding UTF8
    foreach ($champ in 'EchecDepuis', 'EnAttente', 'Abandonnees', 'DernierBattement') {
        if ($brut -notmatch "`"$champ`"") { return "champ $champ absent de notifications.json" }
    }
    $n = $brut | ConvertFrom-Json
    if ("$($n.EchecDepuis)" -ne '' -or $n.EnAttente -ne 0) { return "échec ou attente sans remontée : EchecDepuis « $($n.EchecDepuis) », EnAttente $($n.EnAttente)" }
    $alertes = Join-Path $script:Donnees 'alertes.json'
    $san = @(if (Test-Path $alertes) { (Get-Content $alertes -Raw -Encoding UTF8 | ConvertFrom-Json) | Where-Object { "$($_.Regle)" -eq 'SAN-004' } })
    if ($san.Count) { return "SAN-004 levé sans remontée configurée" }
    $true
}

# ---------------------------------------------------------------- phase 4, PR 4.5b : relance de l'interface
# Tâche posée par le MSI (D4-1, option C) : lancée par Windows sous l'identité de l'utilisateur, jamais par le service
$tacheRelance = 'deR4Tizer Relance interface'
Verifier 'Relance : tâche posée, groupe Utilisateurs, sans élévation, chemin installé' {
    $x = schtasks /Query /TN $tacheRelance /XML 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { return "tâche absente : $x" }
    $t = [xml]$x
    $p = $t.Task.Principals.Principal
    if ($p.GroupId -ne 'S-1-5-32-545') { return "principal : groupe « $($p.GroupId) », compte « $($p.UserId) »" }
    # Windows omet LeastPrivilege, valeur par défaut, à la relecture
    if ($p.RunLevel -eq 'HighestAvailable') { return "niveau : $($p.RunLevel)" }
    $attendu = Join-Path $script:Programme 'deR4Tizer.exe'
    if ($t.Task.Actions.Exec.Command -ne $attendu) { return "commande : $($t.Task.Actions.Exec.Command), attendu $attendu" }
    if ($t.Task.Actions.Exec.Arguments -ne '--cache --relance') { return "arguments : $($t.Task.Actions.Exec.Arguments)" }
    $true
}
Verifier 'Relance : tâche non modifiable par un compte standard' {
    $f = Join-Path $env:SystemRoot "System32\Tasks\$tacheRelance"
    $ecriture = 'Write|Modify|FullControl|Delete|ChangePermissions|TakeOwnership'
    $mauvais = @((Get-Acl -LiteralPath $f).Access | Where-Object { $_.AccessControlType -eq 'Allow' -and "$($_.FileSystemRights)" -match $ecriture -and
        $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin 'S-1-5-18', 'S-1-5-32-544' })
    if ($mauvais.Count) { return "droits d'écriture : $(($mauvais | ForEach-Object { "$($_.IdentityReference) $($_.FileSystemRights)" }) -join ', ')" }
    foreach ($essai in "/Change /TN '$tacheRelance' /DISABLE", "/Delete /F /TN '$tacheRelance'", "/Run /TN '$tacheRelance'") {
        $s = En-TantQue $script:compte "schtasks $essai 2>&1 | Out-Null; `$LASTEXITCODE"
        if ("$s".Trim() -eq '0') { return "le compte standard a pu faire : schtasks $essai" }
    }
    $etat = [xml](schtasks /Query /TN $tacheRelance /XML | Out-String)
    if ($etat.Task.Settings.Enabled -eq 'false') { return 'tâche désactivée par le compte standard' }
    $true
}
function Interfaces-EnSession {
    $chemin = Join-Path $script:Programme 'deR4Tizer.exe'
    @(Get-CimInstance Win32_Process -Filter "Name='deR4Tizer.exe'" | Where-Object { $_.ExecutablePath -eq $chemin -and $_.SessionId -gt 0 })
}
function Attendre-Interface([int]$Secondes = 360) {
    $fin = (Get-Date).AddSeconds($Secondes)
    do {
        $i = @(Interfaces-EnSession)
        if ($i.Count) { return $i }
        Start-Sleep 5
    } while ((Get-Date) -lt $fin)
    @()
}
if ((Get-CimInstance Win32_ComputerSystem).UserName) {
    Verifier 'Relance : interface lancée dans la session ouverte (5 min au plus), sans invite' {
        $i = @(Attendre-Interface)
        if (-not $i.Count) { return "aucune interface en session après 6 min ; tâche : $(schtasks /Query /TN $tacheRelance /FO LIST /V 2>&1 | Select-String 'Last Result|Dernier résultat' | Out-String)" }
        $proprietaire = (Invoke-CimMethod -InputObject $i[0] -MethodName GetOwner).User
        Write-Host "  interface : pid $($i[0].ProcessId), session $($i[0].SessionId), compte $proprietaire"
        if ($proprietaire -eq 'SYSTEM') { return 'interface lancée en SYSTEM' }
        $true
    }
    Verifier 'Relance : interface arrêtée, relancée dans les 5 min, aucune seconde instance' {
        $avant = @(Interfaces-EnSession)
        foreach ($p in $avant) { Stop-Process -Id $p.ProcessId -Force }
        Start-Sleep 2
        $i = @(Attendre-Interface)
        if (-not $i.Count) { return 'interface non relancée après 6 min' }
        if ($i.ProcessId -contains $avant[0].ProcessId) { return 'même processus : arrêt sans effet' }
        # S101-09 : une instance tourne, un compte standard ne l'arrête pas par la tâche
        $fin = En-TantQue $script:compte "schtasks /End /TN '$tacheRelance' 2>&1 | Out-Null; `$LASTEXITCODE"
        Start-Sleep 3
        if (-not @(Interfaces-EnSession).Count) { return "interface arrêtée par schtasks /End d'un compte standard (code $fin)" }
        # Le tour suivant de la tâche sort aussitôt (mutex) : toujours une seule interface par session
        Start-Sleep 310
        $doublons = @(Interfaces-EnSession | Group-Object SessionId | Where-Object Count -gt 1)
        if ($doublons.Count) { return "plusieurs interfaces dans une session : $(($doublons | ForEach-Object { "$($_.Name) : $($_.Count)" }) -join ', ')" }
        $true
    }
} else {
    NonExecute 'Relance : interface lancée dans la session ouverte (5 min au plus), sans invite' 'aucun compte connecté à la console'
    NonExecute 'Relance : interface arrêtée, relancée dans les 5 min, aucune seconde instance' 'aucun compte connecté à la console'
}
Verifier 'Relance : la tâche ne lève aucune alerte de persistance' {
    $a = Join-Path $script:Donnees 'alertes.json'
    $l = @(if (Test-Path $a) { (Get-Content $a -Raw -Encoding UTF8 | ConvertFrom-Json) | Where-Object { "$($_.Regle)" -like 'PER-*' -and "$($_.Destination) $($_.Raisons)" -match 'Relance interface' } })
    if ($l.Count) { return "$($l.Count) alerte(s) : $($l[0].Regle) $($l[0].Raisons)" }
    $true
}

# ---------------------------------------------------------------- arrêt du service (relecture de #61)
# Hors du bloc du compte standard, qu'elles n'utilisent pas (relecture de #63)
# Le fil « persistance » relève les démarrages automatiques dès le démarrage (pilotes compris, 9,4 s mesurées en
# VM) ; l'arrêt attend la fin d'un relevé en cours 8 s au plus. Arrêt demandé dès que le canal répond : attendu
# arrêté en 10 s au plus (délai annoncé à Windows). Que le relevé soit encore en cours n'est pas observable ici.
function Arreter-Chrono {
    $t = [Diagnostics.Stopwatch]::StartNew()
    sc.exe stop deR4Tizer | Out-Null
    while ((Get-Service deR4Tizer).Status -ne 'Stopped' -and $t.Elapsed.TotalSeconds -lt 60) { Start-Sleep -Milliseconds 200 }
    if ((Get-Service deR4Tizer).Status -ne 'Stopped') { return $null }
    $t.Elapsed.TotalSeconds
}
Verifier 'Arrêt juste après un démarrage (relevé des démarrages automatiques) : service arrêté en 10 s au plus' {
    Restart-Service deR4Tizer -Force
    if (-not (Attendre-Canal)) { return 'le service ne répond plus après le redémarrage' }
    $s = Arreter-Chrono
    # Service encore en cours d'arrêt : Start-Service lèverait et masquerait la vraie raison (relecture de #63)
    if ($null -eq $s) { return 'service toujours en marche 60 s après la demande d''arrêt' }
    Start-Service deR4Tizer
    if (-not (Attendre-Canal)) { return 'le service ne répond plus après la relance' }
    if ($s -gt 10) { return ('arrêté en {0:N1} s' -f $s) }
    $true
}
# Alerte de persistance produite puis arrêt aussitôt : elle doit figurer dans alertes.json. Valeur Run témoin
# (notepad, jamais lancée : la session n'est pas rouverte), retirée dans tous les cas. Bout en bout seulement :
# l'alerte peut avoir été reprise par le cycle (toutes les 3 s) avant l'arrêt ; la course elle-même est couverte
# par le test unitaire phase1_persistance_videe_a_l_arret
$cleRun = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; $nomTemoin = 'd4t-temoin-persistance'
Verifier 'Alerte de persistance produite juste avant un arrêt : enregistrée dans alertes.json' {
    try {
        # Hors apprentissage d'abord : un service sans demarrage.json (sans compte standard, il vient d'être installé)
        # apprend en silence à son premier relevé. demarrage.json écrit, puis redémarrage : le nouveau processus
        # trouve la référence et le marqueur, et alerte dès son premier relevé (persistance.rs, Persistance::nouvelle)
        $demarrage = Join-Path $script:Donnees 'demarrage.json'
        $fin = (Get-Date).AddSeconds(120)
        while ((Get-Date) -lt $fin -and -not (Test-Path $demarrage)) { Start-Sleep 1 }
        if (-not (Test-Path $demarrage)) { return 'demarrage.json jamais écrit en 120 s' }
        [void](Redemarrer-Service)
        New-ItemProperty -Path $cleRun -Name $nomTemoin -Value '"C:\Windows\System32\notepad.exe" /d4t-temoin' -PropertyType String -Force | Out-Null
        $demarrage = Join-Path $script:Donnees 'demarrage.json'
        $fin = (Get-Date).AddSeconds(150)
        while ((Get-Date) -lt $fin -and -not ((Test-Path $demarrage) -and (Get-Content $demarrage -Raw -Encoding UTF8) -match $nomTemoin)) { Start-Sleep -Milliseconds 500 }
        if ((Get-Date) -ge $fin) { return "valeur témoin jamais relevée en 150 s ; journal : $(Journal 'persistance|démarrage')" }
        if ($null -eq (Arreter-Chrono)) { return 'service toujours en marche 60 s après la demande d''arrêt' }
        $a = Join-Path $script:Donnees 'alertes.json'
        if (-not ((Test-Path $a) -and (Get-Content $a -Raw -Encoding UTF8) -match $nomTemoin)) { return "aucune alerte pour $nomTemoin dans alertes.json" }
        # Modèle d'événement (phase 3.1) : la nouvelle alerte porte le modèle 1
        $temoin = @((Get-Content $a -Raw -Encoding UTF8 | ConvertFrom-Json) | Where-Object { "$($_.Destination) $($_.Raisons)" -match $nomTemoin })
        if (-not $temoin.Count -or $temoin[-1].Modele -ne 1) { return "alerte témoin sans le modèle 1 (Modele = $(if ($temoin.Count) { $temoin[-1].Modele } else { 'absente' }))" }
        $true
    } finally {
        Remove-ItemProperty -Path $cleRun -Name $nomTemoin -ErrorAction SilentlyContinue
        if ((Get-Service deR4Tizer).Status -eq 'Stopped') { Start-Service deR4Tizer; [void](Attendre-Canal) }
    }
}

# ---------------------------------------------------------------- phase 4, PR 4.2 : suivi des incidents
# Témoin retenu : apprentissage terminé (sinon les alertes non critiques sont baissées en Info), puis une clé Run vers un
# programme absent de C:\Users\Public (remarque « dossier suspect ») : PER-001 au niveau Alerte ouvre un incident. Transitions par la
# commande « incident » en administrateur, avec l'auteur lu sur le jeton ; une transition interdite est refusée.
Verifier 'Incidents : alerte témoin suivie, transitions historisées avec leur auteur, transition interdite refusée' {
    $cleRun = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    $nom = 'd4t-incident-temoin'
    $cible = 'C:\Users\Public\d4t-incident-temoin.exe'
    try {
        $r = Commande '{"Action":"apprentissage","Valeur":"terminer"}' 30000 | ConvertFrom-Json
        if (-not $r.Ok) { return "fin de l'apprentissage refusée : $($r.Message)" }
        New-ItemProperty -Path $cleRun -Name $nom -Value "`"$cible`" /d4t" -PropertyType String -Force | Out-Null
        $suivi = Join-Path $script:Donnees 'suivi-incidents.json'
        $fin = (Get-Date).AddSeconds(180)
        $incident = $null
        while ((Get-Date) -lt $fin -and -not $incident) {
            if (Test-Path $suivi) {
                $incident = @((Get-Content $suivi -Raw -Encoding UTF8 | ConvertFrom-Json) | Where-Object { $_.Entite -like '*d4t-incident-temoin.exe' }) | Select-Object -Last 1
            }
            if (-not $incident) { Start-Sleep 2 }
        }
        if (-not $incident) { return "aucun incident pour $cible en 180 s ; journal : $(Journal 'persistance|incident')" }
        if ($incident.Etat -ne 'Ouvert' -or $incident.Regles -notcontains 'PER-001') { return "incident inattendu : $($incident.Etat) / $($incident.Regles -join ',')" }
        $id = $incident.Id
        $a = Commande (@{ Action = 'incident'; Cible = $id; Valeur = 'PrisEnCharge'; Raison = 'témoin 4.2' } | ConvertTo-Json -Compress) 30000 | ConvertFrom-Json
        if (-not $a.Ok) { return "prise en charge refusée : $($a.Message)" }
        $b = Commande (@{ Action = 'incident'; Cible = $id; Valeur = 'Clos'; Type = 'Resolu' } | ConvertTo-Json -Compress) 30000 | ConvertFrom-Json
        if (-not $b.Ok) { return "clôture refusée : $($b.Message)" }
        $c = Commande (@{ Action = 'incident'; Cible = $id; Valeur = 'PrisEnCharge' } | ConvertTo-Json -Compress) 30000 | ConvertFrom-Json
        if ($c.Ok) { return 'transition Clos vers PrisEnCharge acceptée' }
        $i = @((Get-Content $suivi -Raw -Encoding UTF8 | ConvertFrom-Json) | Where-Object { $_.Id -eq $id }) | Select-Object -First 1
        if ($i.Etat -ne 'Clos' -or $i.MotifCloture -ne 'Resolu') { return "état final inattendu : $($i.Etat) / $($i.MotifCloture)" }
        if (@($i.Transitions).Count -ne 2) { return "$(@($i.Transitions).Count) transition(s) au lieu de 2" }
        if (@($i.Transitions | Where-Object { $_.Auteur -notmatch '^S-1-5-' }).Count) { return "auteur absent ou mal formé : $(@($i.Transitions).Auteur -join ', ')" }
        if ($i.Transitions[0].Note -ne 'témoin 4.2') { return "note perdue : « $($i.Transitions[0].Note) »" }
        $true
    } finally {
        Remove-ItemProperty -Path $cleRun -Name $nom -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------- phase 4, PR 4.3 : chronologie
# La chronologie de l'incident témoin (contrôle précédent) est calculée hors du verrou, au plus une fois par minute, et
# écrite dans chronologies\<id>.json : l'alerte jointe puis les deux transitions, dans l'ordre
Verifier 'Chronologie de l''incident témoin : alerte et transitions, dans l''ordre' {
    $suivi = Join-Path $script:Donnees 'suivi-incidents.json'
    if (-not (Test-Path $suivi)) { return 'suivi-incidents.json absent' }
    $incident = @((Get-Content $suivi -Raw -Encoding UTF8 | ConvertFrom-Json) | Where-Object { $_.Entite -like '*d4t-incident-temoin.exe' }) | Select-Object -Last 1
    if (-not $incident) { return 'incident témoin absent (contrôle précédent)' }
    $f = Join-Path $script:Donnees "chronologies\$($incident.Id).json"
    $fin = (Get-Date).AddSeconds(150)
    $c = $null
    while ((Get-Date) -lt $fin) {
        if (Test-Path $f) {
            $c = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json
            if (@($c.Elements | Where-Object { $_.Source -eq 'transition' }).Count -ge 2) { break }
        }
        Start-Sleep 5
    }
    if (-not $c) { return "chronologie jamais écrite en 150 s ($f)" }
    $sources = @($c.Elements | ForEach-Object { $_.Source })
    $premiere = [array]::IndexOf($sources, 'alerte')
    $transitions = @(0..($sources.Count - 1) | Where-Object { $sources[$_] -eq 'transition' })
    if ($premiere -lt 0) { return "aucune alerte dans la chronologie : $($sources -join ', ')" }
    if ($transitions.Count -lt 2) { return "$($transitions.Count) transition(s) dans la chronologie : $($sources -join ', ')" }
    if ($transitions[0] -lt $premiere) { return "ordre : une transition avant l'alerte ($($sources -join ', '))" }
    $true
}

# ---------------------------------------------------------------- phase 4, PR 4.1 : actions de réponse dans le SIEM
# Blocage manuel d'une adresse de documentation (RFC 5737 : aucune connexion n'est ouverte vers elle), puis sa levée :
# deux événements « reponse » dans le SIEM, avec l'heure UTC et le numéro d'ordre (ordre total, D4-4)
Verifier 'SIEM : blocage manuel et levée journalisés (Source « reponse », HeureUtc, Seq)' {
    $ip = '203.0.113.77'
    $b = Commande (@{ Action = 'bloquerIp'; Ip = $ip; Raison = 'témoin 4.1' } | ConvertTo-Json -Compress) 30000 | ConvertFrom-Json
    if (-not $b.Ok) { return "blocage refusé : $($b.Message)" }
    $d = Commande (@{ Action = 'debloquer'; Type = 'parefeu'; Cible = $ip } | ConvertTo-Json -Compress) 30000 | ConvertFrom-Json
    if (-not $d.Ok) { return "levée refusée : $($d.Message)" }
    $siem = Join-Path $script:Donnees 'siem'
    $fin = (Get-Date).AddSeconds(90)
    $vus = @()
    while ((Get-Date) -lt $fin) {
        $vus = @(Get-ChildItem $siem -Filter 'evenements-*.ndjson' -ErrorAction SilentlyContinue | ForEach-Object { Get-Content $_.FullName -Encoding UTF8 } |
            Where-Object { $_ -match '"Source":"reponse"' -and $_ -match [regex]::Escape($ip) } | ForEach-Object {
                # HeureUtc lue sur la ligne brute : PowerShell 7 convertirait la chaîne en date
                $o = $_ | ConvertFrom-Json
                $o | Add-Member -NotePropertyName HeureBrute -NotePropertyValue $(if ($_ -match '"HeureUtc":"([^"]*)"') { $Matches[1] } else { '' }) -PassThru
            })
        if (@($vus | Where-Object { $_.Type -eq 'debloquer' }).Count) { break }
        Start-Sleep 2
    }
    $bloc = @($vus | Where-Object { $_.Type -eq 'bloquerIp' }) | Select-Object -Last 1
    $levee = @($vus | Where-Object { $_.Type -eq 'debloquer' }) | Select-Object -Last 1
    if (-not $bloc) { return "aucun événement « reponse » bloquerIp pour $ip en 90 s ($($vus.Count) vus)" }
    if (-not $levee) { return "aucun événement « reponse » debloquer pour $ip en 90 s" }
    if ($bloc.Niveau -ne 'Info' -or $bloc.Message -notmatch 'commande d''administrateur') { return "événement de blocage inattendu : $($bloc.Niveau) / $($bloc.Message)" }
    if ($bloc.HeureBrute -notmatch '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$' -or -not ($bloc.Seq -gt 0)) { return "horodatage absent : HeureUtc « $($bloc.HeureBrute) », Seq « $($bloc.Seq) »" }
    if (-not ($levee.Seq -gt $bloc.Seq)) { return "ordre : Seq de la levée ($($levee.Seq)) pas après celui du blocage ($($bloc.Seq))" }
    $true
}

# ---------------------------------------------------------------- désinstallation complète
$regles1 = Reglesparefeu
Verifier 'Désinstallation sans GARDER_DONNEES : service, programme et données retirés' {
    $c = Desinstaller (Join-Path $Journaux 'desinstallation-1.log')
    if ($c -ne 0) { return "msiexec a rendu $c" }
    $reste = @()
    if (Get-Service deR4Tizer -ErrorAction SilentlyContinue) { $reste += 'service' }
    if (Test-Path $script:Programme) { $reste += 'Program Files\deR4Tizer' }
    if (Test-Path $script:Donnees) { $reste += 'données' }
    if (@(Produits).Count) { $reste += 'entrée « Applications »' }
    if ((Schtasks-Code /Query /TN $tacheRelance) -eq 0) { $reste += 'tâche de relance' }
    if ($reste.Count) { return 'reste : ' + ($reste -join ', ') + ' ; ' + (Restes-Donnees) }
    $true
}
if ($regles1) {
    Verifier "Désinstallation sans GARDER_DONNEES : règles de pare-feu retirées ($regles1 avant)" {
        $n = Reglesparefeu; if ($n) { return "$n règle(s) restante(s)" }; $true
    }
} else {
    NonExecute 'Désinstallation sans GARDER_DONNEES : règles de pare-feu retirées' 'aucune règle du groupe deR4Tizer avant la désinstallation (rien à prouver)'
}

# ---------------------------------------------------------------- phase 4, PR 4.5b : tâche de relance, cas de pose
# Audit de #101, S101-01 : le nom est public, un compte standard a pu créer la tâche avant l'installation
$s = En-TantQue $script:compte "schtasks /Create /TN '$tacheRelance' /TR 'cmd.exe /c exit 0' /SC ONCE /ST 23:59 /F 2>&1 | Out-Null; `$LASTEXITCODE"
if ("$s".Trim() -ne '0') {
    # Sans précréation, le contrôle ne prouverait rien (S101-12)
    NonExecute 'Relance : tâche précréée par un compte standard, remplacée à l''installation, plus modifiable par lui' "Windows a refusé la précréation ($s)"
} else {
Verifier 'Relance : tâche précréée par un compte standard, remplacée à l''installation, plus modifiable par lui' {
    $f = Join-Path $env:SystemRoot "System32\Tasks\$tacheRelance"
    $c = Installer $Msi (Join-Path $Journaux 'installation-tache-precreee.log')
    if ($c -ne 0) { return "msiexec a rendu $c" }
    try {
        $x = schtasks /Query /TN $tacheRelance /XML 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { return "tâche absente après l'installation : $x" }
        $t = [xml]$x
        if ($t.Task.Actions.Exec.Command -ne (Join-Path $script:Programme 'deR4Tizer.exe')) { return "commande conservée : $($t.Task.Actions.Exec.Command)" }
        $mauvais = @((Get-Acl -LiteralPath $f).Access | Where-Object { $_.AccessControlType -eq 'Allow' -and "$($_.FileSystemRights)" -match 'Write|Modify|FullControl|Delete|ChangePermissions|TakeOwnership' -and
            $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin 'S-1-5-18', 'S-1-5-32-544' })
        if ($mauvais.Count) { return "droits d'écriture : $(($mauvais | ForEach-Object { "$($_.IdentityReference) $($_.FileSystemRights)" }) -join ', ')" }
        foreach ($essai in "/Change /TN '$tacheRelance' /DISABLE", "/Delete /F /TN '$tacheRelance'", "/Create /TN '$tacheRelance' /TR 'cmd.exe /c exit 0' /SC ONCE /ST 23:59 /F") {
            $r = En-TantQue $script:compte "schtasks $essai 2>&1 | Out-Null; `$LASTEXITCODE"
            if ("$r".Trim() -eq '0') { return "le compte standard a pu faire : schtasks $essai" }
        }
        $x2 = [xml](schtasks /Query /TN $tacheRelance /XML | Out-String)
        if ($x2.Task.Actions.Exec.Command -ne (Join-Path $script:Programme 'deR4Tizer.exe') -or $x2.Task.Settings.Enabled -eq 'false') { return 'tâche modifiée par le compte standard' }
        $true
    } finally {
        Desinstaller (Join-Path $Journaux 'desinstallation-tache-precreee.log') | Out-Null
    }
}
}
# Audit de #101, S101-16 : System32\Tasks accepte la création par les comptes authentifiés. Un fichier précréé sous ce nom,
# sans tâche enregistrée : l'installation aboutit et aucune tâche ne porte une autre commande que l'interface
$f = Join-Path $env:SystemRoot "System32\Tasks\$tacheRelance"
$s = En-TantQue $script:compte "try { Set-Content -LiteralPath '$f' -Value 'x' -ErrorAction Stop; 'cree' } catch { `$_.Exception.Message }"
if ("$s".Trim() -ne 'cree') {
    NonExecute 'Relance : fichier précréé par un compte standard dans le dossier des tâches : installation aboutie, aucune tâche étrangère' "Windows a refusé la précréation ($s)"
} else {
Verifier 'Relance : fichier précréé par un compte standard dans le dossier des tâches : installation aboutie, aucune tâche étrangère' {
    $c = Installer $Msi (Join-Path $Journaux 'installation-fichier-precree.log')
    if ($c -ne 0) { return "msiexec a rendu $c" }
    try {
        $x = schtasks /Query /TN $tacheRelance /XML 2>&1 | Out-String
        $pose = $LASTEXITCODE -eq 0
        if ($pose -and ([xml]$x).Task.Actions.Exec.Command -ne (Join-Path $script:Programme 'deR4Tizer.exe')) { return "tâche étrangère : $x" }
        Write-Host "  tâche posée : $pose ; journal : $(Journal 'relance' 3)"
        $true
    } finally {
        Desinstaller (Join-Path $Journaux 'desinstallation-fichier-precree.log') | Out-Null
        Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
    }
}
}
# S101-08 : création sans /F sur une tâche existante, entrée fermée : elle doit échouer vite, sans changer la tâche
Verifier 'Relance : création sur une tâche existante, sans réponse possible : échec en moins de 60 s, tâche intacte' {
    $temoin = 'd4t-temoin-creation'
    Schtasks-Code /Create /TN $temoin /TR 'cmd.exe /c exit 0' /SC ONCE /ST 23:59 /F | Out-Null
    try {
        # Une définition différente : un écrasement se verrait à la relecture (audit de #101, S101-21)
        $f = Join-Path $env:TEMP 'd4t-temoin-creation.xml'
        $avant = schtasks /Query /TN $temoin /XML | Out-String
        ($avant -replace 'exit 0', 'exit 7') | Set-Content $f -Encoding Unicode
        $vide = Join-Path $env:TEMP 'd4t-vide.txt'
        Set-Content $vide '' -NoNewline
        $p = Start-Process schtasks.exe -ArgumentList "/Create /TN $temoin /XML `"$f`"" -RedirectStandardInput $vide -WindowStyle Hidden -PassThru
        # Sans cette lecture, ExitCode reste vide une fois le processus fini
        $null = $p.Handle
        if (-not $p.WaitForExit(60000)) { Stop-Process -Id $p.Id -Force; return 'schtasks sans réponse après 60 s (blocage possible de l''installation)' }
        Write-Host "  code de retour sans /F sur une tâche existante : $($p.ExitCode)"
        if ($p.ExitCode -eq 0) { return 'création acceptée sur une tâche existante, sans /F' }
        if ((schtasks /Query /TN $temoin /XML | Out-String) -notmatch 'exit 0') { return 'tâche existante modifiée' }
        $true
    } finally {
        Schtasks-Code /Delete /F /TN $temoin | Out-Null
    }
}
# D4-1 : retour arrière vers une version sans relance. Le paquet de référence (4.1.0) refuse de descendre (code 1603,
# WIX_DOWNGRADE_DETECTED), ce qui n'est pas le chemin réel de maj.rs : aucun essai possible ici tant qu'il n'y a pas de paquet
# sans relance qui accepte le retour arrière (audit de #101, S101-20)
NonExecute 'Retour arrière vers une version sans relance (D4-1)' 'le paquet de référence 4.1.0 refuse de descendre ; il faudrait un paquet sans relance qui accepte le retour arrière'
# Relecture de #101, D1 : le refus du lancement survit à une mise à niveau, qui ne repasse pas LANCEMENT_SESSION
$cleRun = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
Installer $MsiAncien (Join-Path $Journaux 'installation-ancienne-sans-lancement.log') @('LANCEMENT_SESSION=0') | Out-Null
if ($null -ne (Get-ItemProperty $cleRun -Name deR4Tizer -ErrorAction SilentlyContinue)) {
    NonExecute 'LANCEMENT_SESSION=0 : mise à niveau sans la propriété, ni clé Run ni tâche' 'la version ancienne a posé la clé Run malgré LANCEMENT_SESSION=0'
    Desinstaller (Join-Path $Journaux 'desinstallation-ancienne-sans-lancement.log') | Out-Null
} else {
    Verifier 'LANCEMENT_SESSION=0 : mise à niveau sans la propriété, ni clé Run ni tâche' {
        $c = Installer $Msi (Join-Path $Journaux 'mise-a-niveau-sans-lancement.log')
        if ($c -ne 0) { return "msiexec a rendu $c" }
        try {
            if ($null -ne (Get-ItemProperty $cleRun -Name deR4Tizer -ErrorAction SilentlyContinue)) { return 'clé Run posée par la mise à niveau' }
            if ((Schtasks-Code /Query /TN $tacheRelance) -eq 0) { return 'tâche posée par la mise à niveau' }
            $true
        } finally {
            Desinstaller (Join-Path $Journaux 'desinstallation-sans-lancement.log') | Out-Null
        }
    }
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
# Chemin d'attaque des postes déjà installés : un fichier d'un autre propriétaire présent dans le dossier au
# moment de la mise à niveau. La 4.1.0 (commit 758ff1e) retire déjà aux Utilisateurs le droit de créer dans le
# dossier au démarrage de son service : le compte standard essaie d'abord pour de vrai ; s'il est refusé (attendu),
# l'état hérité d'une version plus ancienne (ou d'un dossier précréé avant la 4.1.0) est simulé par
# l'administrateur : configuration piégée dont le propriétaire est le compte standard, qui y a le contrôle total.
$piegePose = $false
if ($compte) {
    $fConfig = Join-Path $script:Donnees 'config.json'
    $essai = En-TantQue $compte @"
try { `$h = [IO.File]::Open('$script:Donnees\piege-4.1.0.json', 'CreateNew', 'Write'); `$h.Dispose(); 'CREATION=ECRIT' }
catch { `$x = `$_.Exception; while (`$x.InnerException) { `$x = `$x.InnerException }; 'CREATION=' + `$x.GetType().Name }
"@
    # La 4.1.0 ne pose ses droits qu'une fois un compte connecté à la console (protection::demarrer de 758ff1e) :
    # sans personne à la console (Windows Sandbox), son dossier reste ouvert, défaut de cette version corrigé depuis.
    # Ce n'est alors pas un échec de la version testée ; le piège réel posé rend la mise à niveau plus exigeante.
    $consoleAncienne = (Get-CimInstance Win32_ComputerSystem).UserName
    if ($essai -match 'CREATION=ECRIT' -and -not $consoleAncienne) {
        NonExecute 'Version 4.1.0 en marche : création refusée au compte standard' 'aucun compte à la console : la 4.1.0 ne pose alors pas ses droits (défaut connu de cette version) ; piège réel posé par le compte standard'
        [IO.File]::WriteAllText($fConfig, $ConfigPiegee)
        icacls $fConfig /setowner $compte.Nom /Q | Out-Null
        $piegePose = (Droits $fConfig).Proprietaire -eq $compte.Sid
    } elseif ($essai -match 'CREATION=ECRIT') {
        Noter 'Version 4.1.0 en marche : création refusée au compte standard' 'ÉCHOUÉ' "le compte standard crée des fichiers dans le dossier de la 4.1.0 alors que $consoleAncienne est à la console (piège réel posé)"
        [IO.File]::WriteAllText($fConfig, $ConfigPiegee)
        icacls $fConfig /setowner $compte.Nom /Q | Out-Null
        $piegePose = (Droits $fConfig).Proprietaire -eq $compte.Sid
    } else {
        Verifier 'Version 4.1.0 en marche : création refusée au compte standard' {
            if ($essai -notmatch 'CREATION=UnauthorizedAccessException') { return "résultat : $($essai -replace "`r?`n", ' ')" }
            $true
        }
        Verifier 'État hérité simulé : configuration piégée dont le propriétaire est le compte standard' {
            [IO.File]::WriteAllText($fConfig, $ConfigPiegee, (New-Object Text.ASCIIEncoding))
            icacls $fConfig /setowner $compte.Nom /Q | Out-Null
            icacls $fConfig /grant "$($compte.Nom):F" /Q | Out-Null
            $o = (Droits $fConfig).Proprietaire
            if ($o -ne $compte.Sid) { return "propriétaire $o" }
            $script:piegePose = $true
            $true
        }
    }
}
$journalAvant = if (Test-Path (Join-Path $script:Donnees 'journal.txt')) { Get-Content (Join-Path $script:Donnees 'journal.txt') -TotalCount 1 -Encoding UTF8 } else { $null }
$debut4 = Get-Date
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
$etat4 = Attendre-Etat $debut4
Verifier 'Mise à niveau : protection vérifiée' {
    if (-not $etat4) { return 'état non publié' }
    if (-not [string]::IsNullOrEmpty($etat4.ProtectionDonnees)) { return "protection en échec : $($etat4.ProtectionDonnees)" }
    $true
}
if ($piegePose) {
    Verifier 'Mise à niveau : configuration piégée écartée et jamais chargée (port du piège fermé)' {
        $r = Piege-Ecarte 'config.json' ([string]$PortPiege)
        if ($r -ne $true) { return "$r ; journal : $(Journal 'protection des donn')" }
        if (Port-Ouvert $PortPiege) { return "port $PortPiege en écoute" }
        $true
    }
} else {
    NonExecute 'Mise à niveau : configuration piégée écartée et jamais chargée' 'piège non posé pendant la 4.1.0 (voir plus haut)'
}
Verifier 'Mise à niveau : données conservées, droits du dossier imposés' {
    if (-not $journalAvant) { return 'aucun journal écrit par la version précédente' }
    $premiere = Get-Content (Join-Path $script:Donnees 'journal.txt') -TotalCount 1 -Encoding UTF8
    if ($premiere -ne $journalAvant) { return 'journal remplacé' }
    $d = Droits $script:Donnees
    if ($d.Proprietaire -ne 'S-1-5-32-544' -or -not $d.Protege) { return "propriétaire $($d.Proprietaire), protégé $($d.Protege)" }
    $true
}
Verifier 'Mise à niveau : droits de chaque élément (données, Program Files)' {
    Controle-Droits $Racines @() $Toleres
}
if ($compte) {
    Verifier 'Mise à niveau : compte standard refusé (canal, création et écriture partout)' { Essais-Standard $compte }
}
# Témoin positif après la mise à niveau : une configuration légitime est chargée (et crée les règles de pare-feu)
Verifier 'Mise à niveau : configuration légitime chargée après redémarrage (port témoin ouvert)' {
    Poser-EnAdministrateur 'config.json' $ConfigLegitime
    [void](Redemarrer-Service)
    if (-not (Attendre-Port $PortTemoin)) { return "port $PortTemoin fermé ; journal : $(Journal 'API|protection des donn')" }
    $true
}

# ---------------------------------------------------------------- désinstallation en gardant les données
$regles2 = Reglesparefeu
Verifier 'Désinstallation avec GARDER_DONNEES=1 : données gardées, le reste retiré' {
    $c = Desinstaller (Join-Path $Journaux 'desinstallation-2.log') @('GARDER_DONNEES=1')
    if ($c -ne 0) { return "msiexec a rendu $c" }
    if (-not (Test-Path (Join-Path $script:Donnees 'journal.txt'))) { return 'données supprimées' }
    $reste = @()
    if (Get-Service deR4Tizer -ErrorAction SilentlyContinue) { $reste += 'service' }
    if (Test-Path $script:Programme) { $reste += 'Program Files\deR4Tizer' }
    if ($reste.Count) { return 'reste : ' + ($reste -join ', ') + ' ; ' + (Restes-Donnees) }
    $true
}
if ($regles2) {
    Verifier "Désinstallation avec GARDER_DONNEES=1 : règles de pare-feu retirées ($regles2 avant)" {
        $n = Reglesparefeu; if ($n) { return "$n règle(s) restante(s)" }; $true
    }
} else {
    NonExecute 'Désinstallation avec GARDER_DONNEES=1 : règles de pare-feu retirées' 'aucune règle du groupe deR4Tizer avant la désinstallation (rien à prouver)'
}
# Le dossier gardé est le point de départ de la prochaine installation
Verifier 'Désinstallation avec GARDER_DONNEES=1 : droits de chaque élément du dossier gardé' {
    Controle-Droits @($script:Donnees) @() @{}
}

Bilan 'Lot 3a : installation, droits, compte standard, dossier précréé, mise à niveau'
