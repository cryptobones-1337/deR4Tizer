# Contrôle de la baseline règle par règle (relecture de la baseline du 2026-11-20, T3), dans la VM de test (jamais sur
# un poste réel). Pour chaque règle publiée dans baseline.json : relevé témoin (valeurs des clés de registre touchées par
# la baseline, stratégie d'audit, journaux concernés), application seule par le canal, état effectif attendu
# « conforme » (Defender actif dans l'instantané), annulation, puis relevé identique au témoin. Un message « Échec »,
# un refus ou un état illisible fait échouer la règle. Un cas final vérifie qu'une sauvegarde illisible fait refuser
# l'application sans rien modifier. Environ une minute par règle : lancer avec -Minutes 150.
#
# Lancé dans la VM par tests\vm\lancer.ps1 -Scenario baseline (exécuteur tests\bac-a-sable\executer.ps1).
param(
    [Parameter(Mandatory)] [string]$Msi,
    [Parameter(Mandatory)] [string]$Sortie,
    [string]$Journaux = (Join-Path $env:RUNNER_TEMP 'journaux-msi')
)
. (Join-Path $PSScriptRoot '..\integration\commun.ps1')
New-Item -ItemType Directory -Force -Path $Journaux | Out-Null
$fichier = Join-Path $script:Donnees 'baseline.json'
$sauvegarde = Join-Path $script:Donnees 'baseline-sauvegarde.json'
# VM seulement : le script applique et annule toute la baseline, et réécrit la sauvegarde du retour arrière (audit de
# #219, S219-04)
$modele = (Get-CimInstance Win32_ComputerSystem).Model
if ($modele -notmatch 'Virtual Machine|VMware|VirtualBox|KVM') { throw "Script réservé à la VM de test (modèle : $modele)." }

# Clés posées par les règles (service-rs\src\baseline.rs), relevées en entier ; journaux activés ou dimensionnés
$cles = @(
    'SOFTWARE\Microsoft\Windows Script Host\Settings'
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    'SOFTWARE\Policies\Microsoft\Windows Defender'
    'SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'
    'SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
    'SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
    'SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
    'SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
    'SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access'
    'SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
    'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
    'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
    'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
    'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
    'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
    'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
    'SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'
    'SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    'SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
    'SOFTWARE\Policies\Microsoft\Windows\Installer'
    'SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
    'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'
    'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    'SOFTWARE\Policies\Microsoft\Windows\System'
    'SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
    'SYSTEM\CurrentControlSet\Control\Lsa'
    'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
)
$canaux = 'Security', 'Microsoft-Windows-DNS-Client/Operational', 'Microsoft-Windows-TaskScheduler/Operational'

function Releve {
    $l = New-Object System.Collections.Generic.List[string]
    foreach ($c in $cles) {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($c)
        # Clé vide et clé absente sont équivalentes : seules les valeurs comptent (passage T3 du 2026-11-20)
        if (-not $k -or $k.ValueCount -eq 0) { $l.Add("$c : (absente ou vide)"); if ($k) { $k.Close() }; continue }
        foreach ($n in ($k.GetValueNames() | Sort-Object)) { $l.Add("$c|$n=$(@($k.GetValue($n)) -join ',')") }
        $k.Close()
    }
    foreach ($ligne in (auditpol.exe /get /category:* /r | ConvertFrom-Csv)) { $l.Add("audit|$($ligne.'Subcategory GUID')=$($ligne.'Inclusion Setting')") }
    foreach ($c in $canaux) {
        $g = (wevtutil.exe gl $c) -join "`n"
        $act = if ($g -match '(?m)^enabled:\s*(\S+)') { $Matches[1] } else { '?' }
        $max = if ($g -match '(?m)maxSize:\s*(\d+)') { $Matches[1] } else { '?' }
        $l.Add("journal|$c=enabled:$act maxSize:$max")
    }
    , $l
}
function Ecarts($a, $b) {
    $d = @(Compare-Object -ReferenceObject @($a) -DifferenceObject @($b) | ForEach-Object { "$(if ($_.SideIndicator -eq '<=') { 'avant' } else { 'après' }) $($_.InputObject)" })
    $d
}
function Lire-Baseline { if (Test-Path $fichier) { Get-Content $fichier -Raw -Encoding UTF8 | ConvertFrom-Json } }
# Commande baseline, refaite tant que le service répond « occupé » (application automatique au démarrage) ; rend
# baseline.json réécrit après la commande, ou une chaîne d'erreur
function Operation([string]$Op, [string]$Cible) {
    $fin = (Get-Date).AddSeconds(240)
    while ((Get-Date) -lt $fin) {
        $d = Get-Date
        $r = Commande (@{ Action = 'baseline'; Valeur = $Op; Cible = $Cible } | ConvertTo-Json -Compress) 30000 | ConvertFrom-Json
        if (-not $r.Ok) {
            if ("$($r.Message)" -match 'cours|occup') { Start-Sleep 5; continue }
            return "$Op refusé : $($r.Message)"
        }
        $limite = (Get-Date).AddSeconds(180)
        while ((Get-Date) -lt $limite) {
            if ((Test-Path $fichier) -and (Get-Item $fichier).LastWriteTime -gt $d) { Start-Sleep 1; return (Lire-Baseline) }
            Start-Sleep 2
        }
        return "baseline.json non réécrit après $Op"
    }
    "$Op : service occupé pendant 4 min"
}

$installe = $false
Verifier 'Installation' {
    $c = Installer $Msi (Join-Path $Journaux 'installation-baseline.log')
    if ($c -ne 0) { return "msiexec a rendu $c" }
    if (-not (Attendre-Canal)) { return "le service ne répond pas ; journal : $(Journal 'erreur')" }
    $script:installe = $true
    $true
}

if ($installe) {
    $regles = @()
    Verifier 'Point de départ : aucune règle appliquée (application automatique annulée)' {
        $fin = (Get-Date).AddSeconds(180)
        while (-not (Test-Path $fichier) -and (Get-Date) -lt $fin) { Start-Sleep 3 }
        $b = Lire-Baseline
        if (-not $b) { return 'baseline.json absent' }
        $appliquees = @($b.Regles | Where-Object Appliquee | ForEach-Object Id)
        if ($appliquees.Count) {
            $b = Operation 'annuler' ($appliquees -join ',')
            if ($b -is [string]) { return $b }
            if ($b.Message -like 'Échec*') { return "annulation de départ : $($b.Message)" }
        }
        $script:regles = @($b.Regles | ForEach-Object Id)
        if (@($b.Regles | Where-Object Appliquee).Count) { return 'des règles restent appliquées' }
        Write-Host "  $($script:regles.Count) règle(s) à contrôler"
        $true
    }
    foreach ($id in $regles) {
        Verifier "Règle $id : appliquée, conforme, annulée, état d'origine rendu" {
            $temoin = Releve
            $b = Operation 'appliquer' $id
            if ($b -is [string]) { return $b }
            $etat = $b.Regles | Where-Object { $_.Id -eq $id }
            $constat = "message « $($b.Message) », état « $($etat.Etat) », actuel « $($etat.Actuel) », attendu « $($etat.Attendu) »"
            $echec = if ($b.Message -like 'Échec*' -or $b.Message -like '*impossible*') { "application : $constat" }
                     elseif (-not $etat.Appliquee) { "non marquée appliquée : $constat" }
                     elseif ($etat.Etat -ne 'conforme') { "état après application : $constat" }
            $posee = Ecarts $temoin (Releve)
            $b = Operation 'annuler' $id
            if ($b -is [string]) { return "$b (application : $constat)" }
            if ($b.Message -like 'Échec*' -or $b.Message -like '*non remise*') { return "annulation : $($b.Message)" }
            if (($b.Regles | Where-Object { $_.Id -eq $id }).Appliquee) { return 'encore marquée appliquée après annulation' }
            $reste = Ecarts $temoin (Releve)
            if ($reste.Count) { return "état d'origine non rendu : $($reste -join ' ; ')" }
            if ($echec) { return $echec }
            if (-not $posee.Count) { Write-Host "  $id : aucune valeur modifiée (déjà en place dans l'instantané)" }
            $true
        }
    }
    Verifier 'Sauvegarde illisible : application refusée, rien n''est modifié (B1)' {
        $temoin = Releve
        $copie = "$sauvegarde.essai"
        if (Test-Path $sauvegarde) { Copy-Item $sauvegarde $copie -Force }
        [IO.File]::WriteAllText($sauvegarde, '{ pas du json')
        try {
            $b = Operation 'appliquer' 'reseau.llmnr'
            $refus = ($b -is [string]) -or ("$($b.Message)" -match 'illisible')
            if (-not $refus) { return "application non refusée : $($b.Message)" }
            $reste = Ecarts $temoin (Releve)
            if ($reste.Count) { return "modifié malgré le refus : $($reste -join ' ; ')" }
        } finally {
            Remove-Item $sauvegarde -Force -ErrorAction SilentlyContinue
            if (Test-Path $copie) { Move-Item $copie $sauvegarde -Force }
        }
        $true
    }
    Verifier 'Désinstallation' {
        $c = Desinstaller (Join-Path $Journaux 'desinstallation-baseline.log')
        if ($c -ne 0) { return "msiexec a rendu $c" }
        $true
    }
} else {
    NonExecute 'Contrôle règle par règle' 'installation en échec'
}

Bilan 'Baseline : contrôle règle par règle'
