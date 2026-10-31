# Mesure du cycle de surveillance (phase 1 de CLAUDE.md, condition préalable au découpage de Moniteur), dans la VM de
# test (jamais sur un poste réel). Installe le service, le laisse tourner avec une activité légère et réaliste
# (programmes lancés, fichiers écrits, connexions locales) le temps d'au moins deux écritures de mesures.json (toutes
# les 10 minutes environ), copie le fichier dans la sortie du scénario, puis désinstalle. Ne décide rien : les chiffres
# servent à justifier, ou non, une PR de découpage.
#
# Lancé dans la VM par tests\vm\lancer.ps1 -Scenario mesure (exécuteur tests\bac-a-sable\executer.ps1).
param(
    [Parameter(Mandatory)] [string]$Msi,
    [Parameter(Mandatory)] [string]$Sortie,
    [int]$Minutes = 22,
    [string]$Journaux = (Join-Path $env:RUNNER_TEMP 'journaux-msi')
)
. (Join-Path $PSScriptRoot '..\integration\commun.ps1')
New-Item -ItemType Directory -Force -Path $Journaux | Out-Null
$fichier = Join-Path $script:Donnees 'mesures.json'

$installe = $false
Verifier 'Installation' {
    $c = Installer $Msi (Join-Path $Journaux 'installation-mesure.log')
    if ($c -ne 0) { return "msiexec a rendu $c" }
    if (-not (Attendre-Canal)) { return "le service ne répond pas ; journal : $(Journal 'erreur')" }
    $script:installe = $true
    $true
}

if ($installe) {
    # Activité légère pendant la mesure : un programme lancé et un fichier écrit toutes les 10 s, une connexion locale
    # toutes les 30 s (pas d'Internet dans le réseau de test) ; rien qui déclenche une réponse automatique
    $travail = Join-Path $env:RUNNER_TEMP 'mesure-activite'
    New-Item -ItemType Directory -Force -Path $travail | Out-Null
    $ecoute = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $n = 0
    # Dans un Verifier (exception notée ÉCHOUÉ, le tableau reste complet) et un finally (écouteur arrêté, dossier
    # effacé quoi qu'il arrive) : relecture de #59, D2
    # Heure du début de l'activité (horloge de la VM, celle du service) : les alertes comptées comme faux positifs sont
    # celles produites après, pas celles de l'installation et du premier relevé
    # PR 4.5b : tâche de relance retirée et interface arrêtée, pour le contrôle de SAN-010 en fin de mesure
    Schtasks-Code /Delete /F /TN 'deR4Tizer Relance interface' | Out-Null
    Get-Process deR4Tizer -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    $debutActivite = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Verifier 'Activité pendant la mesure' {
        try {
            $ecoute.Start()
            $port = $ecoute.LocalEndpoint.Port
            $fin = (Get-Date).AddMinutes($Minutes)
            while ((Get-Date) -lt $fin) {
                $script:n++
                Start-Process -FilePath "$env:WINDIR\System32\cmd.exe" -ArgumentList '/c', 'exit 0' -WindowStyle Hidden -Wait
                Set-Content -LiteralPath (Join-Path $travail "f$($script:n % 20).txt") -Value "activite $($script:n)" -Encoding Ascii
                if ($script:n % 3 -eq 0) {
                    try { $c = [Net.Sockets.TcpClient]::new('127.0.0.1', $port); $s = $ecoute.AcceptTcpClient(); $s.Close(); $c.Close() } catch { }
                }
                Start-Sleep 10
            }
        } finally {
            $ecoute.Stop()
            Remove-Item $travail -Recurse -Force -ErrorAction SilentlyContinue
        }
        $true
    }
    Noter 'Tours d''activité' 'INFORMATION' "$Minutes min, $n tours (programme lancé et fichier écrit à chaque tour, connexion locale un tour sur trois)"

    # Interface absente d'une session active : SAN-010 après le délai de grâce (5 min) et 15 min d'absence, non adouci par
    # l'apprentissage. La mesure dure 22 min
    Verifier 'SAN-010 : tâche de relance retirée, interface absente : constat levé, niveau Critique' {
        if (-not (Get-CimInstance Win32_ComputerSystem).UserName) { return 'aucun compte connecté à la console : contrôle sans objet' }
        $a = Join-Path $script:Donnees 'alertes.json'
        $l = @(if (Test-Path $a) { (Get-Content $a -Raw -Encoding UTF8 | ConvertFrom-Json) | Where-Object { "$($_.Regle)" -eq 'SAN-010' } })
        if (-not $l.Count) { return "aucun SAN-010 après $Minutes min ; collecte Sessions : $(@((Etat).Collectes | Where-Object Id -eq 'Sessions') | ConvertTo-Json -Compress)" }
        if ($l[0].Niveau -ne 'Critique') { return "niveau : $($l[0].Niveau)" }
        Write-Host "  $($l[0].Regle) $($l[0].Destination) : $($l[0].Raisons)"
        $true
    }
    Verifier 'mesures.json écrit par le service (deux écritures au moins, service toujours actif)' {
        if (-not (Attendre-Canal 30)) { return 'le service ne répond plus après la mesure' }
        if (-not (Test-Path -LiteralPath $fichier)) { return "absent après $Minutes min ($fichier)" }
        $m = Get-Content -LiteralPath $fichier -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not $m.cumul) { return 'cumul absent' }
        # Au moins deux écritures : la fenêtre en cours commence après le début du cumul ; étapes mesurées présentes
        # (relecture de #59, D3)
        if (-not $m.fenetre -or [string]$m.fenetre.depuis -le [string]$m.cumul.depuis) { return "une seule écriture (cumul depuis $($m.cumul.depuis), fenêtre depuis $($m.fenetre.depuis))" }
        if (-not $m.cumul.etapes -or -not @($m.cumul.etapes.PSObject.Properties).Count) { return 'aucune étape mesurée' }
        Copy-Item -LiteralPath $fichier -Destination (Join-Path $Sortie 'mesure-mesures.json') -Force
        $true
    }

    # Faux positifs (phase 3, PR par domaine) : alertes produites par l'activité synthétique, comptées par règle et par
    # niveau ; limite écrite dans les fiches : une activité de VM ne représente pas un poste réel
    try {
        $fa = Join-Path $script:Donnees 'alertes.json'
        # Windows PowerShell 5.1 : ConvertFrom-Json rend un tableau JSON comme un seul objet ; @() sur la variable, pas
        # sur l'appel, le déplie (relecture de #81, D1 ; même forme qu'installation.ps1)
        $alertes = @()
        if (Test-Path -LiteralPath $fa) { $lu = Get-Content -LiteralPath $fa -Raw -Encoding UTF8 | ConvertFrom-Json; $alertes = @($lu) }
        $toutes = $alertes.Count
        $alertes = @($alertes | Where-Object { [string]$_.Heure -ge $debutActivite })
        $parHeure = 60.0 / [Math]::Max(1, $Minutes)
        $groupes = @($alertes | Group-Object { if ($_.Regle) { "$($_.Regle) $($_.Niveau)" } else { "(sans règle) $($_.Niveau)" } } | Sort-Object Count -Descending)
        $lignes = @($groupes | ForEach-Object { "$($_.Name) : $($_.Count) ({0:N1}/h)" -f ($_.Count * $parHeure) })
        $entete = "$($alertes.Count) alerte(s) pendant les $Minutes min d'activité (depuis $debutActivite ; $toutes depuis l'installation) ; service en apprentissage (alertes non critiques notées Info)"
        Set-Content -LiteralPath (Join-Path $Sortie 'mesure-alertes-par-regle.txt') -Value (@($entete) + $lignes) -Encoding UTF8
        # Les alertes elles-mêmes, pour expliquer le bruit (chemins de la VM de test seulement, rien d'un poste réel)
        if (Test-Path -LiteralPath $fa) { Copy-Item -LiteralPath $fa -Destination (Join-Path $Sortie 'mesure-alertes.json') -Force }
        Noter 'Alertes par règle pendant la mesure (faux positifs)' 'INFORMATION' $(if ($lignes.Count) { "$entete : " + ($lignes -join ' ; ') } else { $entete })
    } catch {
        Noter 'Alertes par règle pendant la mesure (faux positifs)' 'NON EXÉCUTÉ' "alertes.json illisible : $($_.Exception.Message)"
    }

    Verifier 'Désinstallation' {
        $c = Desinstaller (Join-Path $Journaux 'desinstallation-mesure.log')
        if ($c -ne 0) { return "msiexec a rendu $c" }
        $true
    }
} else {
    foreach ($s in 'Activité pendant la mesure', 'mesures.json écrit par le service', 'Désinstallation') { NonExecute $s 'installation en échec' }
}

Bilan 'Mesure du cycle de surveillance'
