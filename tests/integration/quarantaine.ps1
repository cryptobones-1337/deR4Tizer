# Lot 3b : quarantaine avec le service réel. Mise en quarantaine, redémarrage, restauration à l'identique (marque
# Internet comprise) ; lot 1 ter : jonction posée avant une restauration, jonction dans le chemin d'une mise en
# quarantaine, lien dans le chemin d'origine à la reprise du démarrage (avec témoin positif sans lien),
# restauration sans session du propriétaire (refusée, repli dans le dossier du service), restauration avec
# session (création sous l'identité de l'utilisateur) ; dossier mis de côté dans « ecartes » où son auteur pose
# une jonction : le canari survit au redémarrage, à la protection et à la désinstallation complète.
# Runner jetable seulement (voir commun.ps1).
#
# Chaque « rien d'écrit, rien de supprimé hors du chemin » est prouvé par un canari : dossier de l'administrateur
# dont l'empreinte (contenu, taille, propriétaire de chaque élément) est relevée avant et après.
param(
    [Parameter(Mandatory)] [string]$Msi,
    [string]$Journaux = (Join-Path $env:RUNNER_TEMP 'journaux-msi')
)
. (Join-Path $PSScriptRoot 'commun.ps1')
New-Item -ItemType Directory -Force -Path $Journaux | Out-Null
$Origine = 'C:\d4t-origine'
$Canaris = 'C:\d4t-canari'
$Toleres = @{ $script:Programme = @($script:SidTrustedInstaller) }
$Zone = "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://exemple.invalid/essai.bin"

# Fichier d'essai : contenu aléatoire et marque Internet ; renvoie son empreinte
function Nouveau-Fichier([string]$Chemin, [byte[]]$Contenu = (Octets-Aleatoires 200000)) {
    New-Item -ItemType Directory -Force -Path (Split-Path $Chemin) | Out-Null
    [IO.File]::WriteAllBytes($Chemin, $Contenu)
    Set-Content -LiteralPath $Chemin -Stream Zone.Identifier -Value $Zone
    Sha256 $Chemin
}

# Met en quarantaine par le canal et vérifie l'entrée « terminee » ; renvoie l'entrée ou une chaîne d'erreur
function Quarantaine-Verifiee([string]$Chemin, [string]$Empreinte) {
    $r = Commande-Cible 'quarantaine' $Chemin
    if (-not $r.Ok) { return "refusée : $($r.Message)" }
    if (Test-Path -LiteralPath $Chemin) { return 'original toujours présent' }
    $e = Entree-Quarantaine $Chemin
    if (-not $e) { return 'aucune entrée dans quarantaine.json' }
    if ($e.Etat -ne 'terminee') { return "état $($e.Etat)" }
    if ($e.Sha256 -ne $Empreinte) { return "empreinte enregistrée $($e.Sha256), attendue $Empreinte" }
    $e
}

function Copie([object]$Entree) { Join-Path $script:Donnees "quarantaine\$($Entree.Fichier)" }

# Réécrit l'état d'entrées du manifeste, service arrêté (transaction interrompue simulée), puis redémarre
function Simuler-Etats([hashtable]$Etats, [hashtable]$Restaures = @{}) {
    Stop-Service deR4Tizer -Force
    $l = @(Liste-Quarantaine)
    foreach ($e in $l) {
        if ($Etats.ContainsKey($e.Id)) { $e.Etat = $Etats[$e.Id] }
        if ($Restaures.ContainsKey($e.Id)) { $e.CheminRestaure = $Restaures[$e.Id] }
    }
    $f = Join-Path $script:Donnees 'quarantaine.json'
    [IO.File]::WriteAllText($f, (ConvertTo-Json -InputObject $l -Depth 5 -Compress), (New-Object Text.UTF8Encoding($false)))
    $d = Get-Date
    Start-Service deR4Tizer
    if (-not (Attendre-Canal)) { throw 'le service ne répond plus après la reprise' }
    $d
}

# ---------------------------------------------------------------- préparation
$compte = $null
Verifier 'Compte local standard créé' {
    $script:compte = Nouveau-CompteStandard
    $true
}
# Session interactive ouverte sur le runner (restauration avec session) : compte de la console, s'il y en a un
$sessionNom = (Get-CimInstance Win32_ComputerSystem).UserName
$sessionSid = $null
if ($sessionNom) { try { $sessionSid = (New-Object Security.Principal.NTAccount($sessionNom)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { } }
# Sur un runner hébergé, la session est celle d'un administrateur (runneradmin) : les scénarios avec session
# prouvent le mécanisme (création sous le jeton de l'utilisateur), pas le cas d'un utilisateur standard (VM)
$sessionGenre = if ($sessionSid -and @(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID.Value -eq $sessionSid }).Count) { "session d'administrateur" } else { "session d'utilisateur standard" }
New-Item -ItemType Directory -Force -Path $Origine, $Canaris | Out-Null

# Dossier de données précréé par le compte standard, avec un sous-dossier qui sera mis de côté dans « ecartes »
# en gardant son propriétaire
if ($compte) {
    Verifier 'Dossier de données précréé par le compte standard (sous-dossier à mettre de côté)' {
        if (Test-Path $script:Donnees) { return 'le dossier existe déjà avant le test' }
        $s = En-TantQue $compte @"
New-Item -ItemType Directory -Path '$script:Donnees\piege-dossier' -Force -ErrorAction Stop | Out-Null
Set-Content -LiteralPath '$script:Donnees\piege-dossier\x.txt' -Value 'piege' -Encoding Ascii
'POSE'
"@
        if ((Droits "$script:Donnees\piege-dossier").Proprietaire -ne $compte.Sid) { return "sous-dossier non créé par le compte standard ($s)" }
        $true
    }
}

# ---------------------------------------------------------------- installation
$debut = Get-Date
Verifier 'Installation du MSI, service en marche, protection vérifiée' {
    $c = Installer $Msi (Join-Path $Journaux 'installation-3b.log')
    if ($c -ne 0) { return "msiexec a rendu $c" }
    if (-not (Attendre-Canal)) { return 'le service ne répond pas' }
    $e = Attendre-Etat $debut
    if (-not $e) { return 'état non publié' }
    if (-not [string]::IsNullOrEmpty($e.ProtectionDonnees)) { return "protection en échec : $($e.ProtectionDonnees)" }
    $true
}

# ---------------------------------------------------------------- dossier mis de côté : jonction de son auteur
$canariEcartes = Join-Path $Canaris 'ecartes'
$empreinteEcartes = Nouveau-Canari $canariEcartes
$dossierEcarte = @(Ecarte 'piege-dossier') | Select-Object -First 1
if ($compte -and $dossierEcarte) {
    Verifier 'Dossier mis de côté : il garde son propriétaire (le compte standard)' {
        $o = (Droits $dossierEcarte.FullName).Proprietaire
        if ($o -ne $compte.Sid) { return "propriétaire $o" }
        $true
    }
    $lien = Join-Path $dossierEcarte.FullName 'lien'
    if (Nouvelle-Jonction $lien $canariEcartes $compte) {
        Noter 'Dossier mis de côté : jonction vers un canari posée' 'RÉUSSI' 'posée par le compte standard lui-même (chemin complet, droit de traverser)'
    } elseif (Nouvelle-Jonction $lien $canariEcartes) {
        Noter 'Dossier mis de côté : jonction vers un canari posée' 'RÉUSSI' 'refusée au compte standard ; posée par l''administrateur pour l''essai'
    } else {
        Noter 'Dossier mis de côté : jonction vers un canari posée' 'ÉCHOUÉ' 'jonction impossible à créer'
    }
    $d = Get-Date
    Verifier 'Dossier mis de côté : redémarrage et protection, canari intact' {
        [void](Redemarrer-Service)
        $e = Attendre-Etat $d
        if (-not $e -or -not [string]::IsNullOrEmpty($e.ProtectionDonnees)) { return "protection : $($e.ProtectionDonnees)" }
        if ((Empreinte-Dossier $canariEcartes) -ne $empreinteEcartes) { return 'canari modifié' }
        $true
    }
} elseif ($compte) {
    Noter 'Dossier mis de côté : sous-dossier du compte standard écarté' 'ÉCHOUÉ' "piege-dossier absent de ecartes ; journal : $(Journal 'protection des donn')"
} else {
    NonExecute 'Dossier mis de côté : jonction vers un canari' 'compte standard indisponible'
}

# ---------------------------------------------------------------- quarantaine, redémarrage, restauration
# Emplacement d'origine dont le propriétaire est le compte standard, qui n'a pas de session : restauration à
# l'origine refusée (jamais d'écriture en SYSTEM), repli dans le dossier du service
$dB = Join-Path $Origine 'standard'
$fB = Join-Path $dB 'essai-quarantaine.bin'
$hB = Nouveau-Fichier $fB
$eB = $null
if ($compte) {
    icacls $dB /setowner $compte.Nom /Q | Out-Null
    icacls $dB /grant "$($compte.Nom):(OI)(CI)F" /Q | Out-Null
}
Verifier 'Quarantaine : original retiré, copie encodée, entrée terminée avec la marque Internet' {
    $e = Quarantaine-Verifiee $fB $hB
    if ($e -is [string]) { return $e }
    $c = Copie $e
    if (-not (Test-Path $c)) { return 'copie absente' }
    $o = [IO.File]::ReadAllBytes($c)
    if ([Text.Encoding]::ASCII.GetString($o, 0, 4) -ne 'D4TQ') { return 'copie sans en-tête D4TQ' }
    if ((Sha256 $c) -eq $hB) { return 'copie en clair' }
    if ($e.ZoneIdentifier -notmatch 'ZoneId=3') { return "marque Internet non relevée : $($e.ZoneIdentifier)" }
    $d = Droits $c
    if ($d.Proprietaire -ne 'S-1-5-18' -or @($d.Entrees | Where-Object { $_.Sid -notin $script:SidsConfiance }).Count) { return "droits de la copie : $($d.Proprietaire)" }
    $script:eB = $e
    $true
}
Verifier 'Quarantaine : après redémarrage du service, entrée et copie conservées' {
    if (-not $eB) { return 'pas d''entrée à suivre' }
    [void](Redemarrer-Service)
    $e = Entree-Quarantaine $fB
    if (-not $e -or $e.Etat -ne 'terminee' -or $e.Id -ne $eB.Id) { return "entrée : $($e.Etat)" }
    if (-not (Test-Path (Copie $e))) { return 'copie disparue' }
    if (Test-Path $fB) { return 'original réapparu' }
    $true
}
if ($compte) {
    Verifier 'Restauration sans session du propriétaire : refusée (repli proposé), rien écrit à l''origine' {
        $r = Commande-Cible 'restaurer' $eB.Id
        if ($r.Ok) { return "acceptée : $($r.Message)" }
        if ($r.Message -notmatch '^REPLI') { return "refus inattendu : $($r.Message)" }
        if (Test-Path $fB) { return 'fichier écrit à l''emplacement d''origine' }
        if (-not (Entree-Quarantaine $fB)) { return 'entrée retirée' }
        $true
    }
    $fRepli = Join-Path $script:Donnees "restaurations\$($eB.Id)\essai-quarantaine.bin"
    Verifier 'Restauration de repli : fichier identique (marque Internet comprise) dans le dossier du service' {
        $r = Commande-Cible 'restaurerRepli' $eB.Id
        if (-not $r.Ok) { return "refusée : $($r.Message)" }
        if (-not (Test-Path $fRepli)) { return "absent : $fRepli" }
        if ((Sha256 $fRepli) -ne $hB) { return 'contenu différent' }
        $z = Get-Content -LiteralPath $fRepli -Stream Zone.Identifier -Raw -ErrorAction SilentlyContinue
        if ($z -notmatch 'ZoneId=3') { return "marque Internet : $z" }
        if (Entree-Quarantaine $fB) { return 'entrée toujours dans quarantaine.json' }
        if (Test-Path (Copie $eB)) { return 'copie toujours présente' }
        if (Test-Path $fB) { return 'fichier écrit à l''emplacement d''origine' }
        $true
    }
    Verifier 'Restauration de repli : dossier à SYSTEM, protégé, lecture seule pour le propriétaire de l''origine' {
        $dossier = Split-Path $fRepli
        $d = Droits $dossier
        if ($d.Proprietaire -ne 'S-1-5-18' -or -not $d.Protege) { return "propriétaire $($d.Proprietaire), protégé $($d.Protege)" }
        $ecr = @($d.Entrees | Where-Object { $_.Autorise -and $_.Sid -notin $script:SidsConfiance -and (Ecriture $_.Droits) })
        if ($ecr.Count) { return "écriture pour $($ecr.Sid -join ', ')" }
        if (-not @($d.Entrees | Where-Object { $_.Sid -eq $compte.Sid -and $_.Autorise }).Count) { return 'aucune lecture pour le propriétaire' }
        $s = En-TantQue $compte @"
try { 'EMPREINTE=' + (Get-FileHash -LiteralPath '$fRepli' -Algorithm SHA256).Hash } catch { 'EMPREINTE=ERREUR' }
try { `$h = [IO.File]::Open('$fRepli', 'Open', 'Write'); `$h.Dispose(); 'ECRITURE=OUVERT' } catch { `$x = `$_.Exception; while (`$x.InnerException) { `$x = `$x.InnerException }; 'ECRITURE=' + `$x.GetType().Name }
"@
        if ($s -notmatch "EMPREINTE=$hB") { return "lecture par le propriétaire : $($s -replace "`r?`n", ' ')" }
        if ($s -notmatch 'ECRITURE=UnauthorizedAccessException') { return "écriture par le propriétaire : $($s -replace "`r?`n", ' ')" }
        $true
    }
}

# ---------------------------------------------------------------- restauration avec session
# Le dossier d'origine n'accorde plus rien qu'à l'utilisateur de la session : une création en SYSTEM y serait
# refusée, la restauration réussie prouve la création sous son identité
if ($sessionSid) {
    $dC = Join-Path $Origine 'session'
    $fC = Join-Path $dC 'essai-session.bin'
    $hC = Nouveau-Fichier $fC
    Verifier "Restauration avec session ($sessionGenre, $sessionNom) : fichier recréé sous son identité, identique" {
        $e = Quarantaine-Verifiee $fC $hC
        if ($e -is [string]) { return $e }
        # Propriétaire l'utilisateur ; lui seul peut créer dans le dossier. SYSTEM : lecture des droits et
        # synchronisation sur le dossier (lecture du propriétaire par le service), contrôle total seulement sur les
        # fichiers créés dedans (héritage seul : restitution et marque Internet par le handle)
        icacls $dC /setowner $sessionNom /Q | Out-Null
        $acl = Get-Acl -LiteralPath $dC
        $acl.SetSecurityDescriptorSddlForm("D:P(A;OICI;FA;;;$sessionSid)(A;;0x120000;;;SY)(A;OIIO;FA;;;SY)", 'Access')
        Set-Acl -LiteralPath $dC -AclObject $acl
        $d = Droits $dC
        if ($d.Proprietaire -ne $sessionSid) { return "propriétaire du dossier d'origine : $($d.Proprietaire)" }
        $autres = @($d.Entrees | Where-Object { $_.Sid -ne $sessionSid -and ($_.Sid -ne 'S-1-5-18' -or (-not $_.HeritageSeul -and (Ecriture $_.Droits))) })
        if ($autres.Count) { return "droits du dossier d'origine : $(($autres | ForEach-Object { "$($_.Sid) $($_.Droits)" }) -join ', ')" }
        $r = Commande-Cible 'restaurer' $e.Id
        if (-not $r.Ok) { return "refusée : $($r.Message)" }
        if (-not (Test-Path $fC)) { return 'fichier absent' }
        if ((Sha256 $fC) -ne $hC) { return 'contenu différent' }
        $z = Get-Content -LiteralPath $fC -Stream Zone.Identifier -Raw -ErrorAction SilentlyContinue
        if ($z -notmatch 'ZoneId=3') { return "marque Internet : $z" }
        $o = (Droits $fC).Proprietaire
        if ($o -notin $sessionSid, 'S-1-5-32-544') { return "propriétaire du fichier restauré : $o" }
        if (Entree-Quarantaine $fC) { return 'entrée toujours dans quarantaine.json' }
        $true
    }
} else {
    NonExecute 'Restauration avec session : fichier recréé sous l''identité de l''utilisateur' 'aucune session interactive sur le runner (VM nécessaire)'
}

# ---------------------------------------------------------------- lot 1 ter : jonctions
# Jonction posée après la quarantaine, à la place d'un dossier du chemin d'origine, vers un canari
$dD = Join-Path $Origine 'jonction-restauration'
$fD = Join-Path $dD 'sous\f.bin'
$hD = Nouveau-Fichier $fD
$canariD = Join-Path $Canaris 'restauration'
$empreinteD = Nouveau-Canari $canariD
# Le propriétaire de l'emplacement est lu en remontant le chemin sans suivre de lien : la jonction le rend
# illisible, d'où un refus (REPLI) avant toute écriture, avec ou sans session. Témoin, seule la jonction
# différant entre les deux essais : avec une session, même dossier au même propriétaire (l'utilisateur de la
# session) sans jonction, restauration RÉUSSIE, puis nouvelle quarantaine, jonction, restauration refusée ; sans
# session, même dossier sans jonction refusé pour une autre raison (emplacement des administrateurs). Le refus
# des liens à la création (creer_sans_lien) ne joue que si la jonction arrive entre ce contrôle et la création :
# course non reproductible ici.
Verifier 'Jonction posée avant une restauration : refusée avant toute écriture (REPLI, propriétaire illisible), canari intact' {
    $e = Quarantaine-Verifiee $fD $hD
    if ($e -is [string]) { return "préparation : $e" }
    if ($sessionSid) {
        icacls $dD /setowner $sessionNom /Q | Out-Null
        $t = Commande-Cible 'restaurer' $e.Id
        if (-not $t.Ok) { return "témoin sans jonction ($sessionGenre) : restauration refusée : $($t.Message)" }
        if (-not (Test-Path $fD) -or (Sha256 $fD) -ne $hD) { return 'témoin sans jonction : fichier non restauré à l''identique' }
        $e = Quarantaine-Verifiee $fD $hD
        if ($e -is [string]) { return "seconde quarantaine : $e" }
    } else {
        $t = Commande-Cible 'restaurer' $e.Id
        if ($t.Ok -or $t.Message -notmatch '^REPLI : emplacement appartenant au système ou aux administrateurs') { return "témoin sans jonction : $($t.Message)" }
    }
    Remove-Item -LiteralPath (Join-Path $dD 'sous') -Force -Recurse
    if (-not (Nouvelle-Jonction (Join-Path $dD 'sous') $canariD)) { return 'jonction non créée' }
    $r = Commande-Cible 'restaurer' $e.Id
    if ($r.Ok) { return "acceptée : $($r.Message)" }
    if ($r.Message -notmatch '^REPLI : propriétaire de l''emplacement illisible') { return "refus inattendu : $($r.Message)" }
    if ((Empreinte-Dossier $canariD) -ne $empreinteD) { return 'canari modifié' }
    if (-not (Entree-Quarantaine $fD) -or -not (Test-Path (Copie $e))) { return 'entrée ou copie perdue' }
    $true
}
NonExecute 'Jonction posée entre le contrôle du propriétaire et la création : refus par creer_sans_lien' 'course non reproductible de façon déterministe'

# Jonction dans le chemin au moment de la mise en quarantaine, vers un canari qui contient un fichier du même nom
# (forme déterministe de la jonction posée pendant l'opération : le handle ouvert aboutit hors du chemin demandé)
$dE = Join-Path $Origine 'jonction-quarantaine'
$canariE = Join-Path $Canaris 'quarantaine'
$empreinteE = Nouveau-Canari $canariE 'f.bin' (Octets-Aleatoires 50000)
New-Item -ItemType Directory -Force -Path $dE | Out-Null
Verifier 'Jonction dans le chemin d''une mise en quarantaine : refusée, rien lu ni supprimé hors du chemin' {
    if (-not (Nouvelle-Jonction (Join-Path $dE 'sous') $canariE)) { return 'jonction non créée' }
    $f = Join-Path $dE 'sous\f.bin'
    $r = Commande-Cible 'quarantaine' $f
    if ($r.Ok) { return "acceptée : $($r.Message)" }
    # Refus pour la bonne raison : chemin final hors du chemin demandé (natif::ErreurOuverture::Detourne)
    if ($r.Message -notmatch 'le chemin mène ailleurs .* ; quarantaine refusée') { return "refus inattendu : $($r.Message)" }
    if ((Empreinte-Dossier $canariE) -ne $empreinteE) { return 'canari modifié (appât supprimé ?)' }
    if (Entree-Quarantaine $f) { return 'entrée créée' }
    $true
}

# Reprise au démarrage. Témoin positif : transaction interrompue (« en_cours ») avec l'original réel intact, sans
# lien : copie et entrée retirées. Puis le même état, et « restauree », quand l'original est remplacé par une
# jonction vers un fichier IDENTIQUE : un lien compte comme « différent », la copie est gardée, le canari intact.
$contenu = Octets-Aleatoires 120000
$fT = Join-Path $Origine 'reprise-temoin\f.bin'
$hT = Nouveau-Fichier $fT $contenu
$fL1 = Join-Path $Origine 'reprise-lien1\sous\f.bin'
$fL2 = Join-Path $Origine 'reprise-lien2\sous\f.bin'
[void](Nouveau-Fichier $fL1 $contenu); [void](Nouveau-Fichier $fL2 $contenu)
$canariL1 = Join-Path $Canaris 'reprise1'; $canariL2 = Join-Path $Canaris 'reprise2'
$empreinteL1 = Nouveau-Canari $canariL1 'f.bin' $contenu
$empreinteL2 = Nouveau-Canari $canariL2 'f.bin' $contenu
$eT = $null; $eL1 = $null; $eL2 = $null
Verifier 'Reprise au démarrage : préparation (trois quarantaines, liens à la place de deux origines)' {
    $script:eT = Quarantaine-Verifiee $fT $hT; if ($script:eT -is [string]) { return "témoin : $($script:eT)" }
    $script:eL1 = Quarantaine-Verifiee $fL1 $hT; if ($script:eL1 -is [string]) { return "lien 1 : $($script:eL1)" }
    $script:eL2 = Quarantaine-Verifiee $fL2 $hT; if ($script:eL2 -is [string]) { return "lien 2 : $($script:eL2)" }
    # Témoin : l'original réel revient (transaction interrompue avant la suppression)
    [IO.File]::WriteAllBytes($fT, $contenu)
    foreach ($p in @(@($fL1, $canariL1), @($fL2, $canariL2))) {
        $sous = Split-Path $p[0]
        Remove-Item -LiteralPath $sous -Force -Recurse
        if (-not (Nouvelle-Jonction $sous $p[1])) { return "jonction non créée : $sous" }
    }
    $true
}
if (@($eT, $eL1, $eL2 | Where-Object { $_ -and $_ -isnot [string] }).Count -eq 3) {
    Verifier 'Reprise au démarrage : redémarrage avec trois transactions interrompues simulées' {
        [void](Simuler-Etats @{ $eT.Id = 'en_cours'; $eL1.Id = 'en_cours'; $eL2.Id = 'restauree' } @{ $eL2.Id = $fL2 })
        $true
    }
    Verifier 'Reprise au démarrage, témoin sans lien : original identique, copie et entrée retirées, original intact' {
        if (Entree-Quarantaine $fT) { return "entrée gardée ; journal : $(Journal 'quarantaine')" }
        if (Test-Path (Copie $eT)) { return 'copie gardée' }
        if (-not (Test-Path $fT) -or (Sha256 $fT) -ne $hT) { return 'original touché' }
        $true
    }
    Verifier 'Reprise au démarrage, lien dans le chemin d''origine (en_cours, restauree) : copies gardées, canaris intacts' {
        foreach ($c in @(@($fL1, $eL1, $canariL1, $empreinteL1), @($fL2, $eL2, $canariL2, $empreinteL2))) {
            $e = Entree-Quarantaine $c[0]
            if (-not $e) { return "$($c[0]) : entrée retirée ; journal : $(Journal 'quarantaine')" }
            if ($e.Etat -ne 'terminee') { return "$($c[0]) : état $($e.Etat)" }
            if (-not (Test-Path (Copie $c[1]))) { return "$($c[0]) : copie supprimée" }
            if ((Empreinte-Dossier $c[2]) -ne $c[3]) { return "$($c[2]) : canari modifié" }
        }
        $true
    }
} else {
    NonExecute 'Reprise au démarrage : transactions interrompues' 'préparation échouée (voir plus haut)'
}

# ---------------------------------------------------------------- droits après les scénarios
Verifier 'Droits de chaque élément après les scénarios (données, Program Files)' {
    Controle-Droits @($script:Donnees, $script:Programme) @() $Toleres
}

# ---------------------------------------------------------------- désinstallation complète
Verifier 'Désinstallation sans GARDER_DONNEES : données retirées, canaris intacts (jonction de ecartes comprise)' {
    $c = Desinstaller (Join-Path $Journaux 'desinstallation-3b.log')
    if ($c -ne 0) { return "msiexec a rendu $c" }
    if (Test-Path $script:Donnees) { return "données restantes : $(@(Get-ChildItem $script:Donnees -Recurse -Force).Count) élément(s)" }
    $mod = @()
    if ((Empreinte-Dossier $canariEcartes) -ne $empreinteEcartes) { $mod += 'ecartes' }
    if ((Empreinte-Dossier $canariD) -ne $empreinteD) { $mod += 'restauration' }
    if ((Empreinte-Dossier $canariE) -ne $empreinteE) { $mod += 'quarantaine' }
    if ($mod.Count) { return 'canaris modifiés : ' + ($mod -join ', ') }
    $true
}

Bilan 'Lot 3b : quarantaine, restauration, jonctions, dossier mis de côté'
