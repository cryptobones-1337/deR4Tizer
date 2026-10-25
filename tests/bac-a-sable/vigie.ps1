# Vigie d'un passage complet (passage-complet.ps1 lancé en arrière-plan, sa sortie dans -Journal) : une vérification
# par minute, une ligne par événement (scénario terminé, blocage, fin), rien sinon.
# Usage : .\tests\bac-a-sable\vigie.ps1 -Journal <sortie du passage> [-Cible vm|bac-a-sable] [-Depuis <heure du lancement>]
# Bac à sable : bloqué si aucun Windows Sandbox ouvert ni résultat pendant 6 min (le lanceur en tolère 5 à
# l'ouverture), ou aucune écriture pendant 30 min.
# VM : bloqué si la VM n'est plus en marche deux relevés de suite (la remise à l'instantané l'arrête un instant), ou
# si aucun fichier de travail du scénario (C:\sortie, C:\d4t-temp, dans la VM) n'a été écrit pendant 30 min.
param([Parameter(Mandatory)] [string]$Journal, [string]$Racine = 'C:\d4t-bac-a-sable',
      [ValidateSet('bac-a-sable', 'vm')] [string]$Cible = 'bac-a-sable', [string]$Vm = 'deR4Tizer-test-26H2', [datetime]$Depuis = (Get-Date))
# Mesures en UTC : un passage peut franchir le changement d'heure (heure locale répétée ou sautée)
$debut = $Depuis.ToUniversalTime()
$signales = @{}
$absent = 0
$ecritVm = $null; $vuVm = [datetime]::UtcNow; $arretVm = 0; $scenarioVm = ''
$journalVu = [datetime]::UtcNow; $tailleJournal = -1
# Marqueurs de fin déjà présents au lancement de la vigie (journal de plusieurs passages enchaînés) : seule une fin
# NOUVELLE termine la vigie
$motifFin = 'modifications du worktree après passage|exited with code|préparation en échec|préparation -Maj en échec'
$finsDejaVues = if (Test-Path $Journal) { @((Get-Content $Journal -ErrorAction SilentlyContinue) | Select-String $motifFin).Count } else { 0 }
while ($true) {
    Start-Sleep 60
    $j = if (Test-Path $Journal) { Get-Content $Journal -Raw -ErrorAction SilentlyContinue } else { '' }
    if (@(($j -split "`n") | Select-String $motifFin).Count -gt $finsDejaVues) {
        "FIN du passage ($(Get-Date -Format HH:mm)) : " + (($j -split "`n" | Select-String '^==|ÉCHOUÉ \||échec|exited') -join ' / ')
        exit 0
    }
    # Lanceur en échec pour un scénario : événement, le passage continue avec les suivants
    foreach ($m in ($j -split "`n" | Select-String '^== (\S+) : lanceur en échec')) {
        if (-not $signales["echec-$($m.Line)"]) { $signales["echec-$($m.Line)"] = $true; "LANCEUR EN ÉCHEC ($(Get-Date -Format HH:mm)) : $($m.Line.Trim())" }
    }
    if ($j.Length -ne $tailleJournal) { $tailleJournal = $j.Length; $journalVu = [datetime]::UtcNow }
    $prefixe = if ($Cible -eq 'vm') { 'sortie-vm-' } else { 'sortie-' }
    $d = Get-ChildItem $Racine -Directory -Filter "$prefixe*" | Where-Object CreationTimeUtc -gt $debut | Sort-Object CreationTimeUtc | Select-Object -Last 1
    if (-not $d) {
        if (([datetime]::UtcNow - $journalVu).TotalMinutes -gt 20) { "BLOQUÉ ($(Get-Date -Format HH:mm)) : aucun scénario lancé et journal immobile depuis 20 min (préparation ?)"; $journalVu = [datetime]::UtcNow }
        continue
    }
    $code = Get-ChildItem $d.FullName -Filter '*-code.txt' -ErrorAction SilentlyContinue
    if ($code) {
        if (-not $signales[$d.Name]) { $signales[$d.Name] = $true; "Scénario terminé ($(Get-Date -Format HH:mm)) : $($d.Name), code $((Get-Content $code.FullName -Raw).Trim())" }
        $absent = 0; continue
    }
    if ($Cible -eq 'bac-a-sable') {
        $ouvert = @(Get-Process WindowsSandboxRemoteSession -ErrorAction SilentlyContinue).Count
        $absent = if ($ouvert) { 0 } else { $absent + 1 }
        if ($absent -eq 6) { "BLOQUÉ ($(Get-Date -Format HH:mm)) : $($d.Name) sans Windows Sandbox ouvert ni résultat depuis 6 min" }
        $dernier = Get-ChildItem $d.FullName -Recurse -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc | Select-Object -Last 1
        $ref = if ($dernier) { $dernier.LastWriteTimeUtc } else { $d.CreationTimeUtc }
        if (([datetime]::UtcNow - $ref).TotalMinutes -gt 30 -and -not $signales["lent-$($d.Name)"]) { $signales["lent-$($d.Name)"] = $true; "BLOQUÉ ? ($(Get-Date -Format HH:mm)) : $($d.Name), aucune écriture depuis 30 min" }
    } else {
        $etat = (Get-VM $Vm).State
        $arretVm = if ($etat -eq 'Running') { 0 } else { $arretVm + 1 }
        if ($arretVm -eq 2) { "BLOQUÉ ($(Get-Date -Format HH:mm)) : VM $Vm $etat pendant $($d.Name)" }
        if ($arretVm) { continue }
        $c = Import-Clixml (Join-Path $env:USERPROFILE '.d4t-vm-credential.xml')
        # Progression : dernière écriture d'un fichier de travail du scénario dans la VM
        $t = try { Invoke-Command -VMName $Vm -Credential $c -ErrorAction Stop {
            Get-ChildItem C:\sortie, C:\d4t-temp -Recurse -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1 -ExpandProperty LastWriteTime
        } } catch { $null }
        if ($d.Name -ne $scenarioVm) { $scenarioVm = $d.Name; $ecritVm = $null; $vuVm = [datetime]::UtcNow }
        if ($t -and $t -ne $ecritVm) { $ecritVm = $t; $vuVm = [datetime]::UtcNow }
        elseif (([datetime]::UtcNow - $vuVm).TotalMinutes -gt 30) { "BLOQUÉ ? ($(Get-Date -Format HH:mm)) : $($d.Name), aucun fichier de travail écrit depuis 30 min dans la VM"; $vuVm = [datetime]::UtcNow }
    }
}
