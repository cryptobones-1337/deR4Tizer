# Passage complet (preuve locale de CLAUDE.md, section 4) depuis le worktree d'intégration : tests unitaires, MSI, puis
# 3a, 3b et 3c dans la VM de test (tests\vm\lancer.ps1, par défaut) ou dans Windows Sandbox (-Cible bac-a-sable).
# Résumé de chaque tableau ; clés et binaires de test du 3c effacés quoi qu'il arrive. À surveiller avec vigie.ps1.
# Usage : .\tests\bac-a-sable\passage-complet.ps1 -Depot <worktree d'intégration> [-Cible vm|bac-a-sable]
param([string]$Depot = 'C:\d4t-integration', [string]$Racine = 'C:\d4t-bac-a-sable', [string[]]$Scenarios = @('installation', 'quarantaine', 'maj'),
      [ValidateSet('vm', 'bac-a-sable')] [string]$Cible = 'vm')
$lanceur = if ($Cible -eq 'vm') { '.\tests\vm\lancer.ps1' } else { '.\tests\bac-a-sable\lancer.ps1' }
$prefixe = if ($Cible -eq 'vm') { 'sortie-vm' } else { 'sortie' }
$ErrorActionPreference = 'Continue'
Set-Location $Depot
"commit : $(git rev-parse --short HEAD) ; modifications : $(@(git status --porcelain).Count)"

# Windows Sandbox n'accepte qu'une instance : attendre la fermeture complète de la précédente (elle peut traîner
# quand le poste est chargé, et lancer.ps1 rend la main dès le tableau écrit)
function Attendre-Fermeture {
    $fin = (Get-Date).AddMinutes(10)
    while ((Get-Process WindowsSandbox* -ErrorAction SilentlyContinue) -and (Get-Date) -lt $fin) { Start-Sleep 5 }
    if (Get-Process WindowsSandbox* -ErrorAction SilentlyContinue) { 'Windows Sandbox encore ouvert après 10 min : arrêt'; exit 1 }
    Start-Sleep 10
}

function Resume([string]$Scenario) {
    $s = Get-ChildItem $Racine -Directory -Filter "$prefixe-$Scenario-*" | Sort-Object LastWriteTime | Select-Object -Last 1
    $t = Get-ChildItem $s.FullName -Filter '*-tableau.md' -ErrorAction SilentlyContinue
    if (-not $t) { "== $Scenario : pas de tableau ($($s.Name))"; return }
    $c = Get-Content $t.FullName -Encoding UTF8
    "== $Scenario ($($s.Name)) : RÉUSSI=$(@($c | Select-String '\| RÉUSSI \|').Count) ÉCHOUÉ=$(@($c | Select-String '\| ÉCHOUÉ \|').Count) NON EXÉCUTÉ=$(@($c | Select-String '\| NON EXÉCUTÉ \|').Count)"
    $c | Select-String '\| ÉCHOUÉ \||\| NON EXÉCUTÉ \|' | ForEach-Object { $_.Line }
}

Remove-Item (Join-Path $Racine 'entree\maj'), (Join-Path $Racine 'tmp') -Recurse -Force -ErrorAction SilentlyContinue
& .\tests\bac-a-sable\preparer.ps1 *> "$env:TEMP\d4t-prep.log"
if (-not $?) { 'préparation en échec'; Get-Content "$env:TEMP\d4t-prep.log" -Tail 25; exit 1 }
"tests unitaires : $((Get-Content "$env:TEMP\d4t-prep.log" | Select-String 'test result' | Select-Object -Last 1).Line.Trim())"
$os = Get-CimInstance Win32_OperatingSystem
$ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
"commit testé : $(git rev-parse HEAD)"
"arbre testé : $(git rev-parse 'HEAD^{tree}')"
"MSI (3a, 3b) : SHA-256 $((Get-FileHash (Join-Path $Racine 'entree\deR4Tizer.msi') -Algorithm SHA256).Hash)"
"Cible : $Cible ; Windows de l'hôte : $($os.Caption) $($os.Version).$ubr"
foreach ($s in @('installation', 'quarantaine') | Where-Object { $Scenarios -contains $_ }) {
    Attendre-Fermeture
    & $lanceur -Scenario $s *> "$env:TEMP\d4t-$s.log"
    Resume $s
    if ($Cible -eq 'vm') { $v = Get-ChildItem $Racine -Directory -Filter "$prefixe-$s-*" | Sort-Object LastWriteTime | Select-Object -Last 1 | Get-ChildItem -Filter '*-vm.txt'; if ($v) { Get-Content $v.FullName } }
}
if ($Scenarios -contains 'maj') { try {
    Attendre-Fermeture
    & .\tests\bac-a-sable\preparer.ps1 -Maj *> "$env:TEMP\d4t-prep-maj.log"
    if (-not $? -or -not (Test-Path (Join-Path $Racine 'entree\maj\versions.txt'))) { 'préparation -Maj en échec'; Get-Content "$env:TEMP\d4t-prep-maj.log" -Tail 25 }
    else {
        "MSI (3c, reconstruit après les paquets de test) : SHA-256 $((Get-FileHash (Join-Path $Racine 'entree\deR4Tizer.msi') -Algorithm SHA256).Hash)"
        & $lanceur -Scenario maj *> "$env:TEMP\d4t-maj.log"
        Resume 'maj'
        if ($Cible -eq 'vm') { $v = Get-ChildItem $Racine -Directory -Filter "$prefixe-maj-*" | Sort-Object LastWriteTime | Select-Object -Last 1 | Get-ChildItem -Filter '*-vm.txt'; if ($v) { Get-Content $v.FullName } }
    }
} finally {
    Remove-Item (Join-Path $Racine 'entree\maj'), (Join-Path $Racine 'tmp') -Recurse -Force -ErrorAction SilentlyContinue
    "entree\maj restant : $(Test-Path (Join-Path $Racine 'entree\maj'))"
    "modifications du worktree après passage : $(@(git status --porcelain).Count)"
} }
