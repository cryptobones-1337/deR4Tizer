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
    $ecoute.Start()
    $port = $ecoute.LocalEndpoint.Port
    $fin = (Get-Date).AddMinutes($Minutes)
    $n = 0
    while ((Get-Date) -lt $fin) {
        $n++
        Start-Process -FilePath "$env:WINDIR\System32\cmd.exe" -ArgumentList '/c', 'exit 0' -WindowStyle Hidden -Wait
        Set-Content -LiteralPath (Join-Path $travail "f$($n % 20).txt") -Value "activité $n" -Encoding Ascii
        if ($n % 3 -eq 0) {
            try { $c = [Net.Sockets.TcpClient]::new('127.0.0.1', $port); $s = $ecoute.AcceptTcpClient(); $s.Close(); $c.Close() } catch { }
        }
        Start-Sleep 10
    }
    $ecoute.Stop()
    Remove-Item $travail -Recurse -Force -ErrorAction SilentlyContinue
    Noter 'Activité pendant la mesure' 'INFORMATION' "$Minutes min, $n tours (programme lancé et fichier écrit à chaque tour, connexion locale un tour sur trois)"

    Verifier 'mesures.json écrit par le service' {
        if (-not (Test-Path -LiteralPath $fichier)) { return "absent après $Minutes min ($fichier)" }
        $m = Get-Content -LiteralPath $fichier -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not $m.cumul) { return 'cumul absent' }
        Copy-Item -LiteralPath $fichier -Destination (Join-Path $Sortie 'mesure-mesures.json') -Force
        $true
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
