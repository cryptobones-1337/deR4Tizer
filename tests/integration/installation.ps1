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
# Témoin retenu : les collectes branchées sont lues dans la VM (Sysmon absent : désactivée, WMI partielle ; listes de
# domaines désactivées par le réglage par défaut) et leurs règles ne sont pas « sans collecte ». Témoins écartés : la
# capture (gelée) n'est pas encore notée, elle reste « Inconnue » et EXP-IDS-001 est publiée sans collecte ; puis une
# liste LOLDrivers vide (posée par l'administrateur, propriétaire contrôlé) rend LOLDrivers « Indisponible » et
# PIL-001 sans collecte. Écart au dossier : le journal DNS coupé après le démarrage (D4) vient avec la PR 3.3b.
Verifier 'État des collectes : collectes branchées actives, inconnue publiée sans collecte' {
    # L'état de Defender est lu par le fil « contrôles » au démarrage : attendu en 3 min au plus
    $fin = (Get-Date).AddSeconds(180)
    do {
        $e = Etat
        $c = @{}
        if ($e -and $e.Collectes) { foreach ($x in $e.Collectes) { $c[$x.Id] = $x } }
        if ($c.Count -and $c['EtatDefender'] -and $c['EtatDefender'].Etat -ne 'Inconnue') { break }
        Start-Sleep 3
    } while ((Get-Date) -lt $fin)
    if (-not $c.Count) { return 'etat.json sans Collectes' }
    $vu = ($c.Values | ForEach-Object { "$($_.Id)=$($_.Etat)" }) -join ' '
    foreach ($id in 'Connexions', 'JournalDefender', 'EtatDefender', 'JournalSecurite', 'JournalSysteme', 'JournalParefeu', 'JournalDns') {
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
    if ($c['Capture'].Etat -ne 'Inconnue') { return "capture : $($c['Capture'].Etat) (attendue inconnue, non notée) ; $vu" }
    if ($c['ListesDomaines'].Etat -ne 'Desactivee') { return "listes de domaines : $($c['ListesDomaines'].Etat) (attendues désactivées par défaut) ; $vu" }
    $sans = @($e.ReglesSansCollecte)
    foreach ($r in 'DEF-001', 'DEF-010', 'RES-003', 'SYS-002', 'COR-R1') {
        if ($sans -contains $r) { return "règle $r publiée sans collecte ; sans collecte : $($sans -join ', ')" }
    }
    if ($sans -notcontains 'EXP-IDS-001') { return "EXP-IDS-001 (capture inconnue) absente des règles sans collecte : $($sans -join ', ')" }
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
