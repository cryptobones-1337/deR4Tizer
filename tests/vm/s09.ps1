# Lot 4 de la couverture ATT&CK : S-09 (persistance par clé Run et par tâche planifiée, T1547.001 et T1053.005) rejoué
# dix fois dans une même session, avec les témoins N-06 (valeur Run vers un programme signé) et N-02 (tâche vers un
# programme signé), dans la VM de test (jamais sur un poste réel). Liste v1.7, protocole de répétition (3.4) : apprentissage
# terminé avant le premier essai, cibles distinctes (noms par essai), niveau vérifié (Alerte attendue ; Info « apprentissage »
# ou « appris » notée C), nettoyage prouvé par le relevé suivant des démarrages automatiques avant l'essai d'après, règle
# D-3 (la persistance de la tâche d'exécution du banc est un artefact, jamais comptée). Latence : alerte (HeureUtc) moins
# l'heure de pose de l'entrée ; le relevé tourne toutes les minutes. Commande bénigne : écriture d'un fichier témoin hors
# des dossiers protégés. EMULATION : aucune charge réelle.
#
# Lancé dans la VM par tests\vm\lancer.ps1 -Scenario s09 (exécuteur tests\bac-a-sable\executer.ps1).
param(
    [Parameter(Mandatory)] [string]$Msi,
    [Parameter(Mandatory)] [string]$Sortie,
    [int]$Essais = 10,
    [int]$Temoins = 3,
    [string]$Journaux = (Join-Path $env:RUNNER_TEMP 'journaux-msi')
)
. (Join-Path $PSScriptRoot '..\integration\commun.ps1')
New-Item -ItemType Directory -Force -Path $Journaux | Out-Null
$modele = (Get-CimInstance Win32_ComputerSystem).Model
if ($modele -notmatch 'Virtual Machine|VMware|VirtualBox|KVM') { throw "Script réservé à la VM de test (modèle : $modele)." }
$fichierAlertes = Join-Path $script:Donnees 'alertes.json'
$fichierDemarrage = Join-Path $script:Donnees 'demarrage.json'
$temoinDossier = Join-Path $env:RUNNER_TEMP 's09-temoins'
New-Item -ItemType Directory -Force -Path $temoinDossier | Out-Null
$cleRun = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$signe = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'

function Alertes {
    if (-not (Test-Path $fichierAlertes)) { return @() }
    # Sous Windows PowerShell 5.1, ConvertFrom-Json rend un tableau JSON comme un seul objet : déroulé ici
    try { @(Get-Content $fichierAlertes -Raw -Encoding UTF8 | ConvertFrom-Json | ForEach-Object { $_ }) } catch { @() }
}

function Demarrage { if (Test-Path $fichierDemarrage) { Get-Content $fichierDemarrage -Raw -Encoding UTF8 } else { '' } }

# Attend une alerte PER-* dont la destination ou les raisons citent ce nom ; rend l'alerte et la latence, ou $null
function Attendre-Persistance([string]$Nom, [datetime]$Depart, [int]$Secondes = 180, [string]$Regle = 'PER-001') {
    $fin = $Depart.AddSeconds($Secondes)
    while ((Get-Date) -lt $fin) {
        $a = Alertes | Where-Object { "$($_.Regle)" -like $Regle -and ("$($_.Destination) $($_.Raisons)" -match [regex]::Escape($Nom)) } | Select-Object -First 1
        if ($a) {
            $heure = try { [datetime]::Parse($a.HeureUtc).ToUniversalTime() } catch { (Get-Date).ToUniversalTime() }
            return @{ Alerte = $a; Latence = [math]::Round(($heure - $Depart.ToUniversalTime()).TotalSeconds, 1) }
        }
        Start-Sleep 2
    }
    $null
}

# Nettoyage prouvé : le relevé suivant ne contient plus le nom (relevé toutes les minutes)
function Attendre-Nettoyage([string]$Nom, [int]$Secondes = 150) {
    $fin = (Get-Date).AddSeconds($Secondes)
    $avant = (Get-Item $fichierDemarrage -ErrorAction SilentlyContinue).LastWriteTime
    while ((Get-Date) -lt $fin) {
        $f = Get-Item $fichierDemarrage -ErrorAction SilentlyContinue
        if ($f -and $f.LastWriteTime -gt $avant -and (Demarrage) -notmatch [regex]::Escape($Nom)) { return $true }
        Start-Sleep 3
    }
    $false
}

# Preuve que l'activité a eu lieu : le nom figure dans un relevé des démarrages automatiques (3.2 bis : sinon D)
function Attendre-Vu([string]$Nom, [int]$Secondes = 150) {
    $fin = (Get-Date).AddSeconds($Secondes)
    while ((Get-Date) -lt $fin) {
        if ((Demarrage) -match [regex]::Escape($Nom)) { return $true }
        Start-Sleep 3
    }
    $false
}

# Critère D-2 : collecte des démarrages automatiques active avant l'essai (sinon l'essai est invalide, jamais un FN)
function Persistance-Active([int]$Secondes = 120) {
    $fin = (Get-Date).AddSeconds($Secondes)
    do {
        $e = Etat
        $c = if ($e -and $e.Collectes) { $e.Collectes | Where-Object { $_.Id -eq 'Persistance' } | Select-Object -First 1 }
        if ($c -and $c.Etat -eq 'Active') { return $true }
        Start-Sleep 5
    } while ((Get-Date) -lt $fin)
    $false
}

# Arrêt de série (3.4, points 6 et 13) : posé par un nettoyage non constaté, une alerte notée C ou une collecte inactive ;
# testé avant chaque essai, la raison est écrite dans le CSV
$script:arret = ''

function Commande-Temoin([int]$n, [string]$quoi) {
    $f = Join-Path $temoinDossier "$quoi-$n.txt"
    "powershell.exe -NoProfile -WindowStyle Hidden -Command `"Set-Content -LiteralPath '$f' -Value ok`""
}

# Note un essai : VP (règle et niveau attendus), C (bonne règle au niveau Info d'apprentissage ou de comportement appris),
# FN (rien dans le délai)
function Noter-Essai($r, [string]$Attendu) {
    if (-not $r) { return 'FN' }
    if ($r.Alerte.Niveau -eq $Attendu) { return 'VP' }
    if ("$($r.Alerte.Raisons)" -match 'apprentissage|appris') { return 'C' }
    return "autre ($($r.Alerte.Niveau))"
}

$lignes = New-Object System.Collections.Generic.List[string]
$lignes.Add('serie;essai;nom;regle;niveau;latence_s;note')

$installe = $false
Verifier 'Installation' {
    $c = Installer $Msi (Join-Path $Journaux 'installation-s09.log')
    if ($c -ne 0) { return "msiexec a rendu $c" }
    if (-not (Attendre-Canal)) { return "le service ne répond pas ; journal : $(Journal 'erreur')" }
    $script:installe = $true
    $true
}

$pret = $false
if ($installe) {
    Verifier 'Préparation : apprentissage terminé (3.4, point 5), premier relevé des démarrages automatiques passé' {
        $r = Commande (@{ Action = 'apprentissage'; Valeur = 'terminer' } | ConvertTo-Json -Compress) 10000 | ConvertFrom-Json
        if (-not $r.Ok) { return "apprentissage non terminé : $($r.Message)" }
        $fin = (Get-Date).AddSeconds(180)
        while (-not (Test-Path $fichierDemarrage) -and (Get-Date) -lt $fin) { Start-Sleep 3 }
        if (-not (Test-Path $fichierDemarrage)) { return 'demarrage.json absent après 180 s' }
        # Un relevé complet de plus, pour que la référence existe avant le premier essai
        $t = (Get-Item $fichierDemarrage).LastWriteTime
        $fin = (Get-Date).AddSeconds(150)
        while ((Get-Item $fichierDemarrage).LastWriteTime -le $t -and (Get-Date) -lt $fin) { Start-Sleep 3 }
        Write-Host "  $($r.Message)"
        $script:pret = $true
        $true
    }
}

$score = @{ run = @{ VP = 0; total = 0 }; tache = @{ VP = 0; total = 0 } }
if ($pret) {
    for ($i = 1; $i -le $Essais; $i++) {
        $n = $i
        if ($script:arret) { NonExecute "S-09, essai $n" "série arrêtée : $($script:arret)"; $script:lignes.Add("S-09;$n;;;;;arrêt : $($script:arret)"); continue }
        if (-not (Persistance-Active)) { $script:arret = 'collecte Persistance inactive (D-2)'; $script:lignes.Add("S-09;$n;;;;;D : $($script:arret)"); NonExecute "S-09, essai $n" $script:arret; continue }
        # (a) valeur Run vers un interpréteur qui écrit un témoin
        Verifier "S-09 (a), essai $n : valeur Run vers un interpréteur, PER-001 Alerte" {
            $nom = "d4t-s09-run-$n"
            $depart = Get-Date
            New-ItemProperty -Path $cleRun -Name $nom -Value (Commande-Temoin $n 'run') -PropertyType String -Force | Out-Null
            $r = Attendre-Persistance $nom $depart
            $note = Noter-Essai $r 'Alerte'
            $script:lignes.Add("S-09a;$n;$nom;$($r.Alerte.Regle);$($r.Alerte.Niveau);$($r.Latence);$note")
            $script:score.run.total++
            if ($note -eq 'VP') { $script:score.run.VP++ }
            Remove-ItemProperty -Path $cleRun -Name $nom -ErrorAction SilentlyContinue
            if ($note -eq 'C') { $script:arret = "alerte notée C sur $nom (apprentissage ou comportement appris)" }
            if (-not (Attendre-Nettoyage $nom)) { $script:arret = "nettoyage non constaté au relevé suivant ($nom)"; return "$($script:arret) : série arrêtée" }
            if ($note -ne 'VP') { return "$note pour $nom" }
            Write-Host "  $nom : $($r.Alerte.Regle) $($r.Alerte.Niveau) après $($r.Latence) s"
            $true
        }
        if ($script:arret) { continue }
        # (b) tâche planifiée équivalente
        Verifier "S-09 (b), essai $n : tâche planifiée vers un interpréteur, PER-001 Alerte" {
            $nom = "d4t-s09-tache-$n"
            $f = Join-Path $temoinDossier "tache-$n.txt"
            $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -Command `"Set-Content -LiteralPath '$f' -Value ok`""
            $declencheur = New-ScheduledTaskTrigger -Once -At (Get-Date).AddDays(30)
            $depart = Get-Date
            Register-ScheduledTask -TaskName $nom -Action $action -Trigger $declencheur -Force | Out-Null
            $r = Attendre-Persistance $nom $depart
            $note = Noter-Essai $r 'Alerte'
            $script:lignes.Add("S-09b;$n;$nom;$($r.Alerte.Regle);$($r.Alerte.Niveau);$($r.Latence);$note")
            $script:score.tache.total++
            if ($note -eq 'VP') { $script:score.tache.VP++ }
            Unregister-ScheduledTask -TaskName $nom -Confirm:$false -ErrorAction SilentlyContinue
            if ($note -eq 'C') { $script:arret = "alerte notée C sur $nom (apprentissage ou comportement appris)" }
            if (-not (Attendre-Nettoyage $nom)) { $script:arret = "nettoyage non constaté au relevé suivant ($nom)"; return "$($script:arret) : série arrêtée" }
            if ($note -ne 'VP') { return "$note pour $nom" }
            Write-Host "  $nom : $($r.Alerte.Regle) $($r.Alerte.Niveau) après $($r.Latence) s"
            $true
        }
    }
    Verifier "S-09 (a) : $Essais essais, détections Alerte" { if ($score.run.VP -eq $Essais) { $true } else { "$($score.run.VP) VP sur $($score.run.total)" } }
    Verifier "S-09 (b) : $Essais essais, détections Alerte" { if ($score.tache.VP -eq $Essais) { $true } else { "$($score.tache.VP) VP sur $($score.tache.total)" } }

    for ($i = 1; $i -le $Temoins; $i++) {
        $n = $i
        if ($script:arret) { NonExecute "Témoins, essai $n" "série arrêtée : $($script:arret)"; continue }
        Verifier "N-06, essai $n : valeur Run vers un programme signé, PER-001 Info au plus" {
            $nom = "d4t-n06-run-$n"
            $depart = Get-Date
            New-ItemProperty -Path $cleRun -Name $nom -Value "`"$signe`"" -PropertyType String -Force | Out-Null
            $vu = Attendre-Vu $nom
            # Fenêtre de la fiche (180 s depuis la pose), relue après la preuve d'activité : une alerte déjà enregistrée est vue
            $r = Attendre-Persistance $nom $depart 180 '*'
            $note = if ($r -and $r.Alerte.Niveau -ne 'Info') { 'FP' } elseif ($vu -or $r) { 'conforme' } else { 'D (entrée jamais relevée)' }
            $script:lignes.Add("N-06;$n;$nom;$($r.Alerte.Regle);$($r.Alerte.Niveau);$($r.Latence);$note")
            Remove-ItemProperty -Path $cleRun -Name $nom -ErrorAction SilentlyContinue
            if (-not (Attendre-Nettoyage $nom)) { $script:arret = "nettoyage du témoin non constaté ($nom)" }
            if ($note -ne 'conforme') { return "$note : $($r.Alerte.Regle) $($r.Alerte.Niveau)" }
            $true
        }
        if ($script:arret) { NonExecute "N-02, essai $n" "série arrêtée : $($script:arret)"; continue }
        Verifier "N-02, essai $n : tâche vers un programme signé, PER-001 Info au plus" {
            $nom = "d4t-n02-tache-$n"
            $action = New-ScheduledTaskAction -Execute $signe
            $declencheur = New-ScheduledTaskTrigger -Once -At (Get-Date).AddDays(30)
            $depart = Get-Date
            Register-ScheduledTask -TaskName $nom -Action $action -Trigger $declencheur -Force | Out-Null
            $vu = Attendre-Vu $nom
            # Fenêtre de la fiche (180 s depuis la pose), relue après la preuve d'activité : une alerte déjà enregistrée est vue
            $r = Attendre-Persistance $nom $depart 180 '*'
            $note = if ($r -and $r.Alerte.Niveau -ne 'Info') { 'FP' } elseif ($vu -or $r) { 'conforme' } else { 'D (entrée jamais relevée)' }
            $script:lignes.Add("N-02;$n;$nom;$($r.Alerte.Regle);$($r.Alerte.Niveau);$($r.Latence);$note")
            Unregister-ScheduledTask -TaskName $nom -Confirm:$false -ErrorAction SilentlyContinue
            if (-not (Attendre-Nettoyage $nom)) { $script:arret = "nettoyage du témoin non constaté ($nom)" }
            if ($note -ne 'conforme') { return "$note : $($r.Alerte.Regle) $($r.Alerte.Niveau)" }
            $true
        }
    }
}

# D-3 : alertes de persistance sur la tâche d'exécution du banc, gardées dans les preuves, jamais comptées
$artefacts = @(Alertes | Where-Object { "$($_.Regle)" -like 'PER-*' -and "$($_.Destination) $($_.Raisons)" -match 'd4t-executeur' })
$lignes.Add("D-3;;d4t-executeur;$(@($artefacts).Count) alerte(s);;;artefact du banc, exclu")
if ($script:arret) { $lignes.Add("arrêt;;;;;;$($script:arret)") }
$lignes | Set-Content (Join-Path $Sortie 's09-essais.csv') -Encoding UTF8
Copy-Item $fichierAlertes (Join-Path $Sortie 's09-alertes.json') -ErrorAction SilentlyContinue
Copy-Item (Join-Path $script:Donnees 'etat.json') (Join-Path $Sortie 's09-etat.json') -ErrorAction SilentlyContinue
"commit=$(Get-Content (Join-Path (Split-Path $Msi) 'version.txt') -ErrorAction SilentlyContinue) ; windows=$([Environment]::OSVersion.Version) ; build=$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild).$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR) ; sysmon=$(if (Get-Service Sysmon, Sysmon64 -ErrorAction SilentlyContinue) { 'présent' } else { 'absent' }) ; atomic=absent ; liste=v1.7" | Set-Content (Join-Path $Sortie 's09-versions.txt') -Encoding UTF8

if ($installe) {
    Verifier 'Désinstallation' {
        $c = Desinstaller (Join-Path $Journaux 'desinstallation-s09.log')
        if ($c -ne 0) { return "msiexec a rendu $c" }
        $true
    }
}
Bilan 'S-09 et témoins N-06, N-02 (couverture ATT&CK, lot 4, liste v1.7)'
