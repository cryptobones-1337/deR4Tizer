# Lance un scénario d'intégration dans Windows Sandbox et attend son résultat. Le bac à sable reçoit le dossier
# d'entrée en LECTURE SEULE (MSI, scripts) et un dossier de sortie (tableau, journaux) ; il s'éteint seul à la fin et
# tout ce qu'il contenait est effacé. Prérequis : fonctionnalité « Windows Sandbox » activée (Windows Pro), et
# preparer.ps1 exécuté. Un seul bac à sable à la fois : un scénario par lancement (chacun part d'un Windows vierge).
#
# Usage : .\tests\bac-a-sable\lancer.ps1 -Scenario installation|quarantaine|maj [-Racine C:\d4t-bac-a-sable]
# Le scénario maj demande preparer.ps1 -Maj ; ses clés et binaires de test sont effacés à la fin, quel que soit le
# résultat.
param(
    [Parameter(Mandatory)] [ValidateSet('installation', 'quarantaine', 'maj')] [string]$Scenario,
    [string]$Racine = 'C:\d4t-bac-a-sable',
    [int]$Minutes = 60
)
$ErrorActionPreference = 'Stop'
$exe = Join-Path $env:SystemRoot 'System32\WindowsSandbox.exe'
if (-not (Test-Path $exe)) { throw 'Windows Sandbox n''est pas activé (Fonctionnalités facultatives de Windows, puis redémarrage).' }
$entree = Join-Path $Racine 'entree'
$sortie = Join-Path $Racine "sortie-$Scenario-$(Get-Date -Format yyyyMMdd-HHmmss)"
if (-not (Test-Path (Join-Path $entree 'deR4Tizer.msi'))) { throw 'Dossier d''entrée incomplet : lancer d''abord preparer.ps1.' }
if ($Scenario -eq 'maj' -and -not (Test-Path (Join-Path $entree 'maj\versions.txt'))) { throw 'Scénario maj : lancer d''abord preparer.ps1 -Maj.' }
New-Item -ItemType Directory -Force -Path $sortie | Out-Null
$wsb = Join-Path $Racine "$Scenario.wsb"
@"
<Configuration>
  <Networking>Enable</Networking>
  <vGPU>Disable</vGPU>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <PrinterRedirection>Disable</PrinterRedirection>
  <MemoryInMB>4096</MemoryInMB>
  <MappedFolders>
    <MappedFolder><HostFolder>$entree</HostFolder><SandboxFolder>C:\entree</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>$sortie</HostFolder><SandboxFolder>C:\sortie</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\entree\executer.ps1 -Scenario $Scenario</Command>
  </LogonCommand>
</Configuration>
"@ | Set-Content -LiteralPath $wsb -Encoding UTF8
Write-Host "Bac à sable lancé ($Scenario), résultats dans $sortie"
Start-Process $exe -ArgumentList "`"$wsb`""
$fin = (Get-Date).AddMinutes($Minutes)
$fichierCode = Join-Path $sortie "$Scenario-code.txt"
try {
    # Blocage détecté au lieu d'attendre la fin du délai : bac à sable jamais ouvert (une instance précédente encore
    # en cours de fermeture, par exemple) ou fermé sans écrire de résultat
    $ouvert = $false; $absent = 0; $debut = Get-Date
    while ((Get-Date) -lt $fin -and -not (Test-Path $fichierCode)) {
        Start-Sleep 15
        if (Get-Process WindowsSandboxRemoteSession -ErrorAction SilentlyContinue) { $ouvert = $true; $absent = 0; continue }
        $absent++
        if (-not $ouvert -and ((Get-Date) - $debut).TotalMinutes -gt 5) { throw "Windows Sandbox ne s'est pas ouvert en 5 minutes (une autre instance tourne-t-elle encore ?)." }
        if ($ouvert -and $absent -ge 4 -and -not (Test-Path $fichierCode)) { throw "Windows Sandbox fermé sans résultat (voir $sortie)." }
    }
} finally {
    if ($Scenario -eq 'maj') {
        # Clés privées de test et binaires où la clé de test est épinglée : effacés du poste
        while (Get-Process WindowsSandboxRemoteSession -ErrorAction SilentlyContinue) { Start-Sleep 5 }
        Remove-Item -LiteralPath (Join-Path $entree 'maj') -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Join-Path $Racine 'tmp') -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Clés et binaires de test effacés ($(Join-Path $entree 'maj'))"
    }
}
if (-not (Test-Path $fichierCode)) { throw "Pas de résultat après $Minutes minutes (voir $sortie)." }
$code = (Get-Content $fichierCode -Raw).Trim()
$tableau = Join-Path $sortie "$Scenario-tableau.md"
if (Test-Path $tableau) { Get-Content $tableau -Encoding UTF8 }
$detections = Join-Path $sortie "$Scenario-defender-detections.txt"
Write-Host "Code de sortie : $code ; détections Defender : $(if ((Test-Path $detections) -and (Get-Content $detections -Raw).Trim()) { 'OUI, voir ' + $detections } else { 'aucune' })"
