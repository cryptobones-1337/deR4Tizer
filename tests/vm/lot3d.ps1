# Lot 3d : exécution avec Microsoft Defender actif, dans la VM de test (jamais sur un poste réel). Defender relevé
# avant et après (NON EXÉCUTÉ s'il n'est pas pleinement actif, jamais RÉUSSI) ; MSI comparé à l'empreinte attendue ;
# installation, quarantaine d'un fichier bénin, redémarrage du service, restauration à l'identique, désinstallation ;
# aucune détection Defender pendant tout le passage (Get-MpThreatDetection, journal Microsoft-Windows-Windows
# Defender/Operational, événements 1116 et 1117).
#
# Lancé dans la VM par tests\vm\lancer.ps1 -Scenario lot3d (exécuteur tests\bac-a-sable\executer.ps1).
param(
    [Parameter(Mandatory)] [string]$Msi,
    # Empreinte SHA-256 du MSI calculée sur l'hôte (tests\vm\lancer.ps1) : prouve que le fichier installé dans la VM est
    # celui de l'hôte (intégrité de la copie) ; vide : comparaison NON EXÉCUTÉ
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
        Comportement = $s.BehaviorMonitorEnabled; Acces = $s.OnAccessProtectionEnabled; Telechargements = $s.IoavProtectionEnabled
        AgeSignatures = [int]$s.AntivirusSignatureAge
        Mode = $s.AMRunningMode; Falsification = $s.IsTamperProtected; Cloud = [int]$p.MAPSReporting
        Exclusions = @($p.ExclusionPath) + @($p.ExclusionProcess) + @($p.ExclusionExtension) | Where-Object { $_ }
        Signatures = $s.AntivirusSignatureVersion; Plateforme = $s.AMProductVersion
    }
}
# Signatures de plus de 7 jours : un « aucune détection » ne vaudrait rien (instantané ancien)
function Actif($e) { $e.Service -and $e.Antivirus -and $e.TempsReel -and $e.Comportement -and $e.Acces -and $e.Telechargements -and $e.Mode -eq 'Normal' -and $e.Falsification -and $e.Cloud -gt 0 -and $e.AgeSignatures -le 7 -and -not @($e.Exclusions).Count }
function Decrire($e) { "service $($e.Service), antivirus $($e.Antivirus), temps réel $($e.TempsReel), comportement $($e.Comportement), accès $($e.Acces), téléchargements $($e.Telechargements), mode $($e.Mode), falsification $($e.Falsification), cloud $($e.Cloud), exclusions $(@($e.Exclusions).Count), plateforme $($e.Plateforme), signatures $($e.Signatures) ($($e.AgeSignatures) j)" }

# Détections depuis le début du passage : menaces et événements 1116 (détection) et 1117 (action)
function Detections {
    $m = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -ge $debut })
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116, 1117; StartTime = $debut } -ErrorAction SilentlyContinue)
    [pscustomobject]@{ Menaces = $m; Evenements = $ev; Nombre = $m.Count + $ev.Count }
}

function Reglages-Defender {
    $p = Get-MpPreference
    $r = [ordered]@{}
    foreach ($n in ($p.PSObject.Properties.Name | Where-Object { $_ -notmatch '^(PSComputerName|PSShowComputerName|RunspaceId|Cim.*)$' } | Sort-Object)) {
        $r[$n] = (@($p.$n) | ForEach-Object { "$_" }) -join '|'
    }
    $r
}
# Stratégies de Defender (registre) : Get-MpPreference ne rend pas toujours la valeur posée par stratégie
function Strategies-Defender {
    $r = [ordered]@{}
    foreach ($racine in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection') {
        if (-not (Test-Path -LiteralPath $racine)) { continue }
        # Clé illisible (droits de Defender) : notée comme telle, pas d'arrêt du scénario ; qu'elle change d'état compte
        $illisibles = @()
        $cles = @(Get-Item -LiteralPath $racine) + @(Get-ChildItem -LiteralPath $racine -Recurse -ErrorAction SilentlyContinue -ErrorVariable +illisibles)
        foreach ($i in $illisibles) { $r["(illisible) $($i.TargetObject)"] = 'illisible' }
        foreach ($k in $cles) {
            $r["$($k.Name)\"] = ''
            foreach ($n in $k.GetValueNames() | Sort-Object) { $r["$($k.Name)\$n"] = (@($k.GetValue($n, $null, 'DoNotExpandEnvironmentNames')) | ForEach-Object { "$_" }) -join '|' }
        }
    }
    $r
}
function Differences($a, $b) {
    @((@($a.Keys) + @($b.Keys)) | Sort-Object -Unique | Where-Object { -not $a.Contains($_) -or -not $b.Contains($_) -or $a[$_] -ne $b[$_] } |
        ForEach-Object { "$_ : « $(if ($a.Contains($_)) { $a[$_] } else { '(absent)' }) » → « $(if ($b.Contains($_)) { $b[$_] } else { '(absent)' }) »" })
}
$reglagesAvant = Reglages-Defender
$strategiesAvant = Strategies-Defender
$avant = Etat-Defender
$actif = Actif $avant
if ($actif) { Noter 'Defender pleinement actif avant le passage' 'RÉUSSI' (Decrire $avant) }
else { NonExecute 'Defender pleinement actif avant le passage' (Decrire $avant) }

if (-not $actif) {
    foreach ($s in 'Empreinte du MSI', 'Installation avec Defender actif', 'Quarantaine d''un fichier bénin', 'Redémarrage du service',
                   'Restauration à l''identique', 'Désinstallation', 'Aucune détection Defender pendant le passage',
                   'Réglages de Defender inchangés pendant le passage', 'Stratégies de Defender inchangées pendant le passage',
                   'Aucun interrupteur de protection modifié pendant le passage (5007)') {
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
            # Fichier créé par l'administrateur (propriétaire Administrateurs, sans session à lui) : la restauration se
            # fait à l'origine, ou dans le dossier de repli du service (restaurations\<id>\<nom>) ; les deux sont
            # acceptés ici, avec une empreinte identique
            $repli = Join-Path $script:Donnees "restaurations\$($entree.Id)\$(Split-Path $fichier -Leaf)"
            $r = Commande-Cible 'restaurer' $entree.Id
            if (-not $r.Ok -and -not (Test-Path -LiteralPath $fichier)) { $r = Commande-Cible 'restaurerRepli' $entree.Id }
            $chemin = if (Test-Path -LiteralPath $fichier) { $fichier } elseif (Test-Path -LiteralPath $repli) { $repli } else { $null }
            if (-not $chemin) { return "fichier restauré introuvable (origine ni repli) : $($r.Message)" }
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

# Analyse dans le cloud éventuellement tardive : une minute d'attente avant la relecture des détections
Start-Sleep 60
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
# Réglages de Defender inchangés pendant le passage : deR4Tizer ne doit jamais y toucher. Trois contrôles en échec
# fermé : tous les réglages de Get-MpPreference avant/après ; les stratégies du registre avant/après ; et, pour un
# changement défait avant la fin (exclusion ajoutée puis retirée, temps réel coupé puis rétabli), les événements 5007
# dont la clé est un interrupteur de protection (liste fermée ; aucune des valeurs internes que Defender réécrit
# lui-même : relevé sur un poste réel, 701 événements en deux ans, 20 retenus, tous des changements de configuration).
# Limites, non couvertes : fournisseurs AMSI, atténuations de processus (Get-ProcessMitigation), démarrage de WinDefend.
Verifier 'Réglages de Defender inchangés pendant le passage' {
    $diff = Differences $reglagesAvant (Reglages-Defender)
    if ($diff.Count) { return "$($diff.Count) réglage(s) modifié(s) (Get-MpPreference) : " + (($diff | Select-Object -First 5) -join ' ; ') }
    $true
}
Verifier 'Stratégies de Defender inchangées pendant le passage' {
    $diff = Differences $strategiesAvant (Strategies-Defender)
    if ($diff.Count) { return "$($diff.Count) valeur(s) de stratégie modifiée(s) : " + (($diff | Select-Object -First 5) -join ' ; ') }
    $true
}
$evenements5007 = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 5007; StartTime = $debut } -ErrorAction SilentlyContinue)
Verifier 'Aucun interrupteur de protection modifié pendant le passage (5007)' {
    # Nouvelle valeur lue dans les données de l'événement (« New Value »), non traduites ; sous Microsoft\Windows
    # Defender comme sous Policies\Microsoft\Windows Defender
    $interrupteurs = '\Windows Defender\(Exclusions\|Real-Time Protection\|Windows Defender Exploit Guard\|Features\TamperProtection\b)' +
        '|\SpyNet\(SpyNetReporting|SubmitSamplesConsent)\b|\(DisableAntiSpyware|DisableAntiVirus|PUAProtection|DisableRealtimeMonitoring)\b'
    $m = @($evenements5007 | ForEach-Object {
            $x = [xml]$_.ToXml()
            "$(@($x.Event.EventData.Data | Where-Object { $_.Name -eq 'New Value' } | ForEach-Object { $_.'#text' }) | Select-Object -First 1)"
        } | Where-Object { $_ -match $interrupteurs })
    if ($m.Count) { return "$($m.Count) changement(s) : " + (($m | Select-Object -First 4) -join ' ; ') }
    $true
}
Noter 'Événements 5007 pendant le passage' 'INFORMATION' "$($evenements5007.Count) événement(s) ; Defender en écrit lui-même sur ses valeurs internes"

Bilan 'Lot 3d : exécution avec Microsoft Defender actif'
