# Lot 3d : exécution avec Microsoft Defender actif, dans la VM de test (jamais sur un poste réel). Defender relevé
# avant et après (NON EXÉCUTÉ s'il n'est pas pleinement actif, jamais RÉUSSI) ; MSI comparé à l'empreinte attendue ;
# installation, quarantaine d'un fichier bénin, redémarrage du service, restauration à l'identique, désinstallation ;
# aucune détection Defender pendant tout le passage (Get-MpThreatDetection, journal Microsoft-Windows-Windows
# Defender/Operational, événements 1116 et 1117).
#
# Lancé dans la VM par tests\vm\lancer.ps1 -Scenario lot3d (exécuteur tests\bac-a-sable\executer.ps1).
param(
    [Parameter(Mandatory)] [string]$Msi,
    # Empreinte SHA-256 attendue du MSI (celle de la preuve citée) ; vide : comparaison NON EXÉCUTÉ
    [string]$Sha256Attendu = '',
    [string]$Journaux = (Join-Path $env:RUNNER_TEMP 'journaux-msi')
)
. (Join-Path $PSScriptRoot '..\integration\commun.ps1')
New-Item -ItemType Directory -Force -Path $Journaux | Out-Null
$debut = Get-Date
$Origine = 'C:\d4t-lot3d'

# Defender pleinement actif : service, antivirus, temps réel, protection cloud, protection contre les falsifications
function Etat-Defender {
    $s = Get-MpComputerStatus
    $p = Get-MpPreference
    [pscustomobject]@{
        Service = $s.AMServiceEnabled; Antivirus = $s.AntivirusEnabled; TempsReel = $s.RealTimeProtectionEnabled
        Mode = $s.AMRunningMode; Falsification = $s.IsTamperProtected; Cloud = [int]$p.MAPSReporting
        Exclusions = @($p.ExclusionPath) + @($p.ExclusionProcess) + @($p.ExclusionExtension) | Where-Object { $_ }
        Signatures = $s.AntivirusSignatureVersion; Plateforme = $s.AMProductVersion
    }
}
function Actif($e) { $e.Service -and $e.Antivirus -and $e.TempsReel -and $e.Mode -eq 'Normal' -and $e.Falsification -and $e.Cloud -gt 0 -and -not @($e.Exclusions).Count }
function Decrire($e) { "service $($e.Service), antivirus $($e.Antivirus), temps réel $($e.TempsReel), mode $($e.Mode), falsification $($e.Falsification), cloud $($e.Cloud), exclusions $(@($e.Exclusions).Count), plateforme $($e.Plateforme), signatures $($e.Signatures)" }

# Détections depuis le début du passage : menaces et événements 1116 (détection) et 1117 (action)
function Detections {
    $m = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -ge $debut })
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116, 1117; StartTime = $debut } -ErrorAction SilentlyContinue)
    [pscustomobject]@{ Menaces = $m; Evenements = $ev; Nombre = $m.Count + $ev.Count }
}

$avant = Etat-Defender
$actif = Actif $avant
if ($actif) { Noter 'Defender pleinement actif avant le passage' 'RÉUSSI' (Decrire $avant) }
else { NonExecute 'Defender pleinement actif avant le passage' (Decrire $avant) }

if (-not $actif) {
    foreach ($s in 'Empreinte du MSI', 'Installation avec Defender actif', 'Quarantaine d''un fichier bénin', 'Redémarrage du service',
                   'Restauration à l''identique', 'Désinstallation', 'Aucune détection Defender pendant le passage') {
        NonExecute $s 'Defender n''est pas pleinement actif : passage sans valeur de preuve'
    }
    Bilan 'Lot 3d : exécution avec Microsoft Defender actif'
    exit 0
}

$empreinteMsi = Sha256 $Msi
if ($Sha256Attendu) {
    Verifier 'Empreinte du MSI' { if ($empreinteMsi -eq $Sha256Attendu.ToUpper()) { $true } else { "SHA-256 $empreinteMsi, attendu $Sha256Attendu" } }
} else {
    NonExecute 'Empreinte du MSI' "aucune empreinte attendue fournie (SHA-256 relevé : $empreinteMsi)"
}

$installe = $false
Verifier 'Installation avec Defender actif' {
    $c = Installer $Msi (Join-Path $Journaux 'installation-3d.log')
    if ($c -ne 0) { return "msiexec a rendu $c" }
    if (-not (Attendre-Canal)) { return "le service ne répond pas ; journal : $(Journal 'erreur')" }
    $script:installe = $true
    $true
}

$fichier = Join-Path $Origine 'releve-benin.txt'
$entree = $null
$empreinte = $null
if ($installe) {
    Verifier 'Quarantaine d''un fichier bénin' {
        New-Item -ItemType Directory -Force -Path $Origine | Out-Null
        [IO.File]::WriteAllText($fichier, "Fichier de test bénin du lot 3d, $(Get-Date -Format o)`r`n" + ('ligne de texte ordinaire' * 200), (New-Object Text.UTF8Encoding($false)))
        $script:empreinte = Sha256 $fichier
        $r = Commande-Cible 'quarantaine' $fichier
        if (-not $r.Ok) { return "refusée : $($r.Message)" }
        if (Test-Path -LiteralPath $fichier) { return 'original toujours présent' }
        $script:entree = Entree-Quarantaine $fichier
        if (-not $script:entree) { return 'aucune entrée dans quarantaine.json' }
        if ($script:entree.Etat -ne 'terminee') { return "état $($script:entree.Etat)" }
        $true
    }
    Verifier 'Redémarrage du service' {
        Redemarrer-Service
        if (-not (Attendre-Canal)) { return 'le service ne répond plus' }
        $e = Entree-Quarantaine $fichier
        if (-not $e -or $e.Etat -ne 'terminee') { return "entrée de quarantaine après redémarrage : $($e.Etat)" }
        $true
    }
    if ($entree) {
        Verifier 'Restauration à l''identique' {
            $r = Commande-Cible 'restaurer' $entree.Id
            # Fichier créé par l'administrateur (propriétaire Administrateurs, sans session à lui) : la restauration
            # peut se faire à l'origine ou dans le dossier de repli du service ; les deux sont acceptés ici
            $e = @(Liste-Quarantaine | Where-Object Id -eq $entree.Id) | Select-Object -Last 1
            $chemin = if (Test-Path -LiteralPath $fichier) { $fichier } elseif ($e -and $e.CheminRestaure) { $e.CheminRestaure } else { $null }
            if (-not $r.Ok -and -not $chemin) {
                $r = Commande-Cible 'restaurerRepli' $entree.Id
                $e = @(Liste-Quarantaine | Where-Object Id -eq $entree.Id) | Select-Object -Last 1
                $chemin = if ($e -and $e.CheminRestaure) { $e.CheminRestaure } else { $null }
            }
            if (-not $chemin -or -not (Test-Path -LiteralPath $chemin)) { return "fichier restauré introuvable : $($r.Message)" }
            if ((Sha256 $chemin) -ne $empreinte) { return "contenu différent ($chemin)" }
            $true
        }
    } else {
        NonExecute 'Restauration à l''identique' 'quarantaine échouée (voir plus haut)'
    }
    Verifier 'Désinstallation' {
        $c = Desinstaller (Join-Path $Journaux 'desinstallation-3d.log')
        if ($c -ne 0) { return "msiexec a rendu $c" }
        if (Get-Service deR4Tizer -ErrorAction SilentlyContinue) { return 'service encore présent' }
        $true
    }
} else {
    foreach ($s in 'Quarantaine d''un fichier bénin', 'Redémarrage du service', 'Restauration à l''identique', 'Désinstallation') {
        NonExecute $s 'installation échouée (voir plus haut)'
    }
}

Verifier 'Aucune détection Defender pendant le passage' {
    $d = Detections
    if ($d.Nombre) {
        return "détections : " + ((@($d.Menaces | ForEach-Object { "$($_.ThreatID) $($_.Resources -join ',')" }) +
                                   @($d.Evenements | ForEach-Object { "événement $($_.Id) $($_.TimeCreated.ToString('HH:mm:ss'))" })) -join ' ; ')
    }
    $true
}
$apres = Etat-Defender
if (Actif $apres) { Noter 'Defender pleinement actif après le passage' 'RÉUSSI' (Decrire $apres) }
else { Noter 'Defender pleinement actif après le passage' 'ÉCHOUÉ' (Decrire $apres) }

Bilan 'Lot 3d : exécution avec Microsoft Defender actif'
