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

# ---------------------------------------------------------------- leurres anti-rançongiciel (revue de sécurité)
# Les leurres vivent dans les dossiers de l'utilisateur. Rejeu de l'attaque : le compte standard remplace son dossier
# Documents par une jonction vers un canari qui contient un fichier au nom public des anciens leurres
# (« !000-deR4Tizer-leurre.docx », retiré à chaque pose). Par chemin, SYSTEM supprimerait ce fichier hors du profil ;
# par handle vérifié, rien n'est touché. Témoin : dans le profil qui a une session, les leurres sont posés (cachés,
# système, audités).
$profilStd = if ($compte) { "C:\Users\$($compte.Nom)" } else { '' }
if ($compte -and (Test-Path "$profilStd\NTUSER.DAT")) {
    $canariLeurres = Join-Path $Canaris 'leurres'
    $empreinteLeurres = Nouveau-Canari $canariLeurres '!000-deR4Tizer-leurre.docx' (Octets-Aleatoires 4000)
    Verifier 'Leurres : jonction dans le profil du compte standard vers un canari, redémarrage, canari intact' {
        $s = En-TantQue $compte @"
Remove-Item -LiteralPath '$profilStd\Documents' -Recurse -Force -ErrorAction SilentlyContinue
cmd.exe /c mklink /J "$profilStd\Documents" "$canariLeurres"
"@
        $i = Get-Item -LiteralPath "$profilStd\Documents" -Force -ErrorAction SilentlyContinue
        if (-not $i -or -not ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return "jonction non posée : $($s -replace "`r?`n", ' ')" }
        [void](Redemarrer-Service)
        Start-Sleep 5
        if ((Empreinte-Dossier $canariLeurres) -ne $empreinteLeurres) { return 'canari modifié : un leurre a été retiré ou posé à travers la jonction' }
        $true
    }
} else {
    NonExecute 'Leurres : jonction dans le profil du compte standard' 'profil du compte standard absent'
}
if ($sessionSid) {
    Verifier "Leurres : posés dans le profil de la session ($sessionGenre), cachés, système, audités" {
        $f = Join-Path $script:Donnees 'secrets\leurres.json'
        if (-not (Test-Path $f)) { return 'liste des leurres absente' }
        $liste = @((Get-Content $f -Raw -Encoding UTF8).TrimStart([char]0xFEFF) | ConvertFrom-Json)
        $profilSession = (Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sessionSid }).LocalPath
        $miens = @(@($liste) | ForEach-Object { $_ } | Where-Object { $_.chemin -like "$profilSession\*" })
        if (-not $miens.Count) { return "aucun leurre dans $profilSession" }
        foreach ($l in $miens) {
            $i = Get-Item -LiteralPath $l.chemin -Force -ErrorAction SilentlyContinue
            if (-not $i) { return "absent : $($l.chemin)" }
            if (($i.Attributes -band 6) -ne 6) { return "ni caché ni système : $($l.chemin)" }
            $audit = @((Get-Acl -LiteralPath $l.chemin -Audit).Audit)
            if (-not @($audit | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-1-0' }).Count) { return "audit absent : $($l.chemin)" }
        }
        $true
    }
} else {
    NonExecute 'Leurres : posés dans le profil de la session' 'aucune session interactive sur le runner'
}

# ---------------------------------------------------------------- audit des données sensibles (revue du relecteur)
# Toutes les heures, en SYSTEM, le service pose l'audit de lecture dans les dossiers de navigateur des profils. Rejeu :
# le compte standard remplace son dossier « Chrome\User Data » par une jonction vers un canari. Par chemin (ancien
# Get-Acl / Set-Acl), SYSTEM réécrivait les descripteurs complets du canari ; par handle vérifié, rien n'y est
# écrit : chaque descripteur (DACL et SACL) du canari est relu à l'identique. Témoin : un vrai dossier « Edge\User
# Data » du même profil reçoit l'audit (dossier : entrée héritée par ses fichiers ; fichier présent : entrée posée),
# et une règle d'audit posée avant par l'« organisation » (échecs de suppression des Administrateurs) y est gardée :
# la SACL est complétée, jamais remplacée. L'étiquette d'intégrité vit dans la même liste (SACL) : un fichier
# « Low » du dossier (comme ceux qu'écrit un navigateur en mode protégé) garde son étiquette et reçoit l'audit ; une
# étiquette perdue empêcherait le navigateur d'y écrire.
function Descripteurs([string]$Racine) {
    $l = foreach ($e in @(Get-Item -LiteralPath $Racine -Force) + @(Get-ChildItem -LiteralPath $Racine -Recurse -Force)) {
        "$($e.FullName.Substring($Racine.Length))|$((Get-Acl -LiteralPath $e.FullName -Audit).Sddl)"
    }
    ($l | Sort-Object) -join "`n"
}
# Étiquette d'intégrité en SDDL (« S:(ML;;NW;;;LW) »), lue par SID : la sortie d'icacls dépend de la langue et
# Get-Acl ne rend pas l'étiquette
Add-Type -Namespace D4T -Name Etiquette -MemberDefinition @'
[DllImport("advapi32.dll", CharSet = CharSet.Unicode)] public static extern uint GetNamedSecurityInfoW(string n, int t, uint i, IntPtr o, IntPtr g, IntPtr d, IntPtr s, out IntPtr sd);
[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr sd, uint r, uint i, out IntPtr s, IntPtr l);
[DllImport("kernel32.dll")] public static extern IntPtr LocalFree(IntPtr p);
public static string Sddl(string n) {
    IntPtr sd; uint e = GetNamedSecurityInfoW(n, 1, 0x10, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out sd);
    if (e != 0) return "erreur " + e;
    IntPtr s; string r = ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, 0x10, out s, IntPtr.Zero) ? Marshal.PtrToStringUni(s) : "conversion impossible";
    if (s != IntPtr.Zero) LocalFree(s); LocalFree(sd); return r;
}
'@
function Etiquette([string]$Chemin) { [D4T.Etiquette]::Sddl($Chemin) }
function Audit-Tous([string]$Chemin) {
    @((Get-Acl -LiteralPath $Chemin -Audit).Audit | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-1-0' })
}
if ($compte -and (Test-Path "$profilStd\NTUSER.DAT")) {
    $canariAudit = Join-Path $Canaris 'audit'
    [void](Nouveau-Canari $canariAudit 'Login Data' (Octets-Aleatoires 2000))
    $descripteursAvant = Descripteurs $canariAudit
    $chrome = "$profilStd\AppData\Local\Google\Chrome"
    $edge = "$profilStd\AppData\Local\Microsoft\Edge\User Data"
    $s = En-TantQue $compte @"
New-Item -ItemType Directory -Force -Path '$chrome', '$edge' | Out-Null
Remove-Item -LiteralPath '$chrome\User Data' -Recurse -Force -ErrorAction SilentlyContinue
cmd.exe /c mklink /J "$chrome\User Data" "$canariAudit"
Set-Content -LiteralPath '$edge\Local State' -Value '{}'
Set-Content -LiteralPath '$edge\temoin-integrite-basse.dat' -Value 'Low'
"@
    $i = Get-Item -LiteralPath "$chrome\User Data" -Force -ErrorAction SilentlyContinue
    if (-not $i -or -not ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) -or -not (Test-Path -LiteralPath "$edge\Local State")) {
        Noter 'Audit des données sensibles : jonction et dossier témoin posés par le compte standard' 'ÉCHOUÉ' "mise en place : $($s -replace "`r?`n", ' ')"
    } else {
        # Règle tierce sur le dossier témoin, posée par l'administrateur avant le passage du service
        $a = Get-Acl -LiteralPath $edge -Audit
        $a.AddAuditRule((New-Object Security.AccessControl.FileSystemAuditRule((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'), 'Delete', 'None', 'None', 'Failure')))
        Set-Acl -LiteralPath $edge -AclObject $a
        # Témoin à étiquette d'intégrité basse
        $fichierLow = "$edge\temoin-integrite-basse.dat"
        icacls $fichierLow /setintegritylevel low | Out-Null
        $etiquetteAvant = Etiquette $fichierLow
        # Pose faite au démarrage du service, puis toutes les heures
        $debutAudit = Redemarrer-Service
        $fin = (Get-Date).AddSeconds(90)
        while ((Get-Date) -lt $fin -and -not (@(Get-Content (Join-Path $script:Donnees 'journal.txt') -Encoding UTF8 -Tail 400 |
            Where-Object { $_ -match 'audit de lecture posé sur' -and [datetime]::ParseExact($_.Substring(0, 19), 'yyyy-MM-dd HH:mm:ss', $null) -ge $debutAudit.AddSeconds(-1) }).Count)) { Start-Sleep 3 }
        Verifier 'Audit des données sensibles : jonction du compte standard vers un canari, descripteurs du canari inchangés' {
            $j = Journal 'audit de lecture posé sur|audit des données sensibles'
            if ($j -notmatch 'audit de lecture posé sur') { return "pose jamais faite après le redémarrage ; journal : $j" }
            $apres = Descripteurs $canariAudit
            if ($apres -ne $descripteursAvant) { return "descripteurs du canari modifiés à travers la jonction" }
            $true
        }
        Verifier 'Audit des données sensibles : fichier à étiquette d''intégrité basse, étiquette gardée et audit posé' {
            if ($etiquetteAvant -notmatch '\(ML;[^)]*;LW\)') { return "témoin non marqué Low avant le passage : $etiquetteAvant" }
            $e = Etiquette $fichierLow
            if ($e -notmatch '\(ML;[^)]*;LW\)') { return "étiquette d'intégrité perdue ou changée : avant $etiquetteAvant, après $e" }
            if (-not @(Audit-Tous $fichierLow).Count) { return "audit absent sur le fichier Low (écriture refusée ?) ; journal : $(Journal 'audit')" }
            $true
        }
        Verifier 'Audit des données sensibles : témoin, audit posé dans le vrai dossier du profil (dossier et fichier présent), règle tierce gardée' {
            $d = @(Audit-Tous $edge)
            if (-not $d.Count) { return "aucun audit sur $edge ; journal : $(Journal 'audit')" }
            if (-not ($d[0].PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { return "audit du dossier non limité à ses fichiers ($($d[0].PropagationFlags))" }
            if (-not @(Audit-Tous "$edge\Local State").Count) {
                return "aucun audit sur le fichier présent ; SACL du fichier : $((Get-Acl -LiteralPath "$edge\Local State" -Audit).Sddl) ; du dossier : $((Get-Acl -LiteralPath $edge -Audit).Sddl) ; journal : $(Journal 'audit')"
            }
            $tierce = @((Get-Acl -LiteralPath $edge -Audit).Audit | Where-Object {
                $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-544' -and $_.AuditFlags -eq 'Failure' })
            if (-not $tierce.Count) { return "règle d'audit tierce effacée (SACL remplacée au lieu d'être complétée)" }
            $true
        }
    }
} else {
    NonExecute 'Audit des données sensibles : jonction du compte standard vers un canari' 'profil du compte standard absent'
}

# Audit d'un leurre déjà présent, sans session : le service ne crée pas de leurre dans un profil sans session, mais
# audite ceux qui y sont déjà. Le compte standard crée lui-même, dans son profil, un fichier au nom d'un leurre (nom
# lu dans secrets\, hors du dossier Documents remplacé plus haut par une jonction) ; après redémarrage, l'audit
# d'écriture doit y être posé. Avant le correctif, l'écriture de la SACL échouait (« Access is denied »), constaté
# sur un poste réel.
if ($compte -and (Test-Path "$profilStd\NTUSER.DAT")) {
    # Tableau de paires [dossier, nom] ; boucle explicite : Windows PowerShell 5.1 rend le tableau en un seul objet
    $brut = Get-Content (Join-Path $script:Donnees 'secrets\leurres-noms.json') -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
    $noms = @(if ($brut) { foreach ($x in ($brut.TrimStart([char]0xFEFF) | ConvertFrom-Json)) { , $x } })
    $choisi = @($noms | Where-Object { $_[0] -ne 'Documents' }) | Select-Object -First 1
    if (-not $choisi) {
        Noter 'Leurres : leurre déjà présent dans un profil sans session, audit posé' 'ÉCHOUÉ' "noms des leurres illisibles ou vides ($($noms.Count))"
    } else {
        $leurreStd = Join-Path (Join-Path $profilStd $choisi[0]) $choisi[1]
        $s = En-TantQue $compte @"
New-Item -ItemType Directory -Force -Path '$(Split-Path $leurreStd)' | Out-Null
Set-Content -LiteralPath '$leurreStd' -Value 'leurre pose par le compte standard'
"@
        Verifier 'Leurres : leurre déjà présent dans un profil sans session, audit d''écriture posé (redémarrage)' {
            if (-not (Test-Path -LiteralPath $leurreStd)) { return "fichier non créé par le compte standard : $($s -replace "`r?`n", ' ')" }
            [void](Redemarrer-Service)
            $fin = (Get-Date).AddSeconds(60)
            while ((Get-Date) -lt $fin -and -not @(Audit-Tous $leurreStd).Count) { Start-Sleep 3 }
            if (-not @(Audit-Tous $leurreStd).Count) { return "audit absent ; SACL : $((Get-Acl -LiteralPath $leurreStd -Audit).Sddl) ; journal : $(Journal 'leurres')" }
            $true
        }
    }
} else {
    NonExecute 'Leurres : leurre déjà présent dans un profil sans session, audit posé' 'profil du compte standard absent'
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
        # Toute l'arborescence : le service lit le propriétaire du plus proche dossier existant (ici « sous »)
        icacls $dD /setowner $sessionNom /T /Q | Out-Null
        if ((Droits (Join-Path $dD 'sous')).Proprietaire -ne $sessionSid) { return 'propriétaire de « sous » non posé' }
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
