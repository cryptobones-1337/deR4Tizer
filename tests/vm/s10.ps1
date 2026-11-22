# Rejeu de S-10 (PowerShell encodé, T1059.001 et T1027, charge bénigne) sans Sysmon, en configuration A (profil
# « journalisation » appliqué à l'installation), dans la VM de test (jamais sur un poste réel). Couverture ATT&CK, lot 1 :
# chaque essai lance un PowerShell encodé qui attend quelques millisecondes puis se termine ; PRC-002 doit se lever pour
# chacun, sous son PID, d'après l'événement 4688. Témoin négatif : un PowerShell ordinaire, sans alerte. La latence notée
# va du lancement à l'alerte lue dans alertes.json (écriture du fichier comprise). SIMULATION : aucune charge réelle.
#
# Chaque essai lance une copie de powershell.exe posée dans son propre dossier : le service ne répète pas pendant 24 h
# une alerte de même niveau, même programme (chemin), même parent et même début de raison (moniteur.rs, cle_alerte),
# si bien que dix lancements du même powershell.exe ne laissent qu'une alerte. La détection, elle, ne lit que le nom
# du programme et la ligne de commande : une copie est détectée comme l'original. Le premier passage (2026-11-22) a
# montré les deux pièges : alertes.json lu comme un seul objet sous Windows PowerShell 5.1, et alertes regroupées.
#
# Lancé dans la VM par tests\vm\lancer.ps1 -Scenario s10 (exécuteur tests\bac-a-sable\executer.ps1).
param(
    [Parameter(Mandatory)] [string]$Msi,
    [Parameter(Mandatory)] [string]$Sortie,
    [int]$Essais = 10,
    [string]$Journaux = (Join-Path $env:RUNNER_TEMP 'journaux-msi')
)
. (Join-Path $PSScriptRoot '..\integration\commun.ps1')
New-Item -ItemType Directory -Force -Path $Journaux | Out-Null
$modele = (Get-CimInstance Win32_ComputerSystem).Model
if ($modele -notmatch 'Virtual Machine|VMware|VirtualBox|KVM') { throw "Script réservé à la VM de test (modèle : $modele)." }
$fichierAlertes = Join-Path $script:Donnees 'alertes.json'

function Alertes {
    if (-not (Test-Path $fichierAlertes)) { return @() }
    # Sous Windows PowerShell 5.1, ConvertFrom-Json rend un tableau JSON comme un seul objet : déroulé ici
    try { @(Get-Content $fichierAlertes -Raw -Encoding UTF8 | ConvertFrom-Json | ForEach-Object { $_ }) } catch { @() }
}

function Collectes {
    $c = @{}
    $e = Etat
    if ($e -and $e.Collectes) { foreach ($x in $e.Collectes) { $c[$x.Id] = $x } }
    $c, $e
}

# Attend une alerte de processus pour ce PID ; rend l'alerte et la latence en secondes, ou $null
function Attendre-Alerte([int]$ProcessId, [datetime]$Depart, [int]$Secondes = 60) {
    $fin = $Depart.AddSeconds($Secondes)
    while ((Get-Date) -lt $fin) {
        $a = Alertes | Where-Object { $_.Pid -eq $ProcessId -and "$($_.Regle)" -like 'PRC-*' } | Select-Object -First 1
        if ($a) { return @{ Alerte = $a; Latence = [math]::Round(((Get-Date) - $Depart).TotalSeconds, 1) } }
        Start-Sleep -Milliseconds 500
    }
    $null
}

$installe = $false
Verifier 'Installation' {
    $c = Installer $Msi (Join-Path $Journaux 'installation-s10.log')
    if ($c -ne 0) { return "msiexec a rendu $c" }
    if (-not (Attendre-Canal)) { return "le service ne répond pas ; journal : $(Journal 'erreur')" }
    $script:installe = $true
    $true
}

$pret = $false
if ($installe) {
    Verifier 'Configuration A : Sysmon absent, audit des créations de processus actif, source « Audit 4688 »' {
        if (Get-Service Sysmon, Sysmon64 -ErrorAction SilentlyContinue) { return 'Sysmon présent : ce n''est pas la configuration A' }
        # L'état de l'audit est relu toutes les 5 min : le profil appliqué après le démarrage du service est vu au relevé suivant
        $fin = (Get-Date).AddMinutes(8)
        do {
            $c, $e = Collectes
            $a = $c['AuditProcessus']
            if ($a -and $a.Etat -eq 'Active' -and $e.SourceProcessus -eq 'Audit 4688') {
                Write-Host "  audit : $($a.Etat) ; source : $($e.SourceProcessus) ; WMI : $($c['WmiProcessus'].Etat)"
                $script:pret = $true
                return $true
            }
            Start-Sleep 10
        } while ((Get-Date) -lt $fin)
        "audit des créations de processus : $($a.Etat) ($($a.Raison)) ; source : $($e.SourceProcessus)"
    }
}

$lignes = New-Object System.Collections.Generic.List[string]
$lignes.Add('essai;pid;regle;niveau;latence_s')
if ($pret) {
    $detectes = 0
    for ($i = 1; $i -le $Essais; $i++) {
        $n = $i
        Verifier "S-10, essai $n : PowerShell encodé bref, PRC-002" {
            # Charge distincte à chaque essai (une alerte identique pourrait être regroupée avec la précédente)
            $commande = "Start-Sleep -Milliseconds $(40 + $n)"
            $code = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($commande))
            $dossier = Join-Path $env:RUNNER_TEMP "s10\essai-$n"
            New-Item -ItemType Directory -Force -Path $dossier | Out-Null
            $copie = Join-Path $dossier 'powershell.exe'
            Copy-Item (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') $copie -Force
            $depart = Get-Date
            $p = Start-Process $copie -ArgumentList "-NoProfile -NonInteractive -EncodedCommand $code" -PassThru -WindowStyle Hidden
            $p.WaitForExit()
            $duree = [math]::Round(((Get-Date) - $depart).TotalSeconds, 2)
            $r = Attendre-Alerte $p.Id $depart
            if (-not $r) { $script:lignes.Add("$n;$($p.Id);aucune;;"); return "aucune alerte PRC pour le PID $($p.Id) en 60 s (processus terminé en $duree s)" }
            $script:lignes.Add("$n;$($p.Id);$($r.Alerte.Regle);$($r.Alerte.Niveau);$($r.Latence)")
            if ($r.Alerte.Regle -ne 'PRC-002') { return "alerte $($r.Alerte.Regle) au lieu de PRC-002" }
            $script:detectes++
            Write-Host "  PID $($p.Id) terminé en $duree s ; PRC-002 ($($r.Alerte.Niveau)) lue après $($r.Latence) s"
            $true
        }
        Start-Sleep 3
    }
    Verifier "S-10 : $Essais essais, $Essais détections" { if ($detectes -eq $Essais) { $true } else { "$detectes détection(s) sur $Essais" } }

    Verifier 'Témoin négatif : PowerShell ordinaire, aucune alerte' {
        $depart = Get-Date
        $p = Start-Process powershell.exe -ArgumentList '-NoProfile -NonInteractive -Command "Get-Date | Out-Null"' -PassThru -WindowStyle Hidden
        $p.WaitForExit()
        $r = Attendre-Alerte $p.Id $depart 45
        $script:lignes.Add("temoin;$($p.Id);$(if ($r) { $r.Alerte.Regle } else { 'aucune' });;")
        if ($r) { return "alerte $($r.Alerte.Regle) pour le témoin (PID $($p.Id))" }
        $true
    }
}
$lignes | Set-Content (Join-Path $Sortie 's10-essais.csv') -Encoding UTF8
Copy-Item $fichierAlertes (Join-Path $Sortie 's10-alertes.json') -ErrorAction SilentlyContinue
Copy-Item (Join-Path $script:Donnees 'etat.json') (Join-Path $Sortie 's10-etat.json') -ErrorAction SilentlyContinue

if ($installe) {
    Verifier 'Désinstallation' {
        $c = Desinstaller (Join-Path $Journaux 'desinstallation-s10.log')
        if ($c -ne 0) { return "msiexec a rendu $c" }
        $true
    }
}
Bilan 'S-10 sans Sysmon (couverture ATT&CK, lot 1)'
