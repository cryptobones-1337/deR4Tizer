# Passage complet (preuve locale de CLAUDE.md, section 4) depuis le worktree d'intégration : tests unitaires, MSI, puis
# 3a, 3b et 3c dans la VM de test (tests\vm\lancer.ps1, par défaut) ou dans Windows Sandbox (-Cible bac-a-sable).
# Résumé de chaque tableau ; clés et binaires de test du 3c effacés quoi qu'il arrive. À surveiller avec vigie.ps1.
# Usage : .\tests\bac-a-sable\passage-complet.ps1 -Depot <worktree d'intégration> [-Cible vm|bac-a-sable]
param([string]$Depot = 'C:\d4t-integration', [string]$Racine = 'C:\d4t-bac-a-sable', [string[]]$Scenarios = @('installation', 'quarantaine', 'maj'),
      [ValidateSet('vm', 'bac-a-sable')] [string]$Cible = 'vm',
      # VM seulement : compte standard connecté à la console pendant les scénarios (lot 3d, session standard)
      [switch]$SessionStandard)
$options = if ($Cible -eq 'vm' -and $SessionStandard) { @{ SessionStandard = $true } } else { @{} }
$lanceur = if ($Cible -eq 'vm') { '.\tests\vm\lancer.ps1' } else { '.\tests\bac-a-sable\lancer.ps1' }
$prefixe = if ($Cible -eq 'vm') { 'sortie-vm' } else { 'sortie' }
$ErrorActionPreference = 'Continue'
Set-Location $Depot -ErrorAction Stop
# En UTC : un passage peut franchir le changement d'heure (constaté le 25/10/2026 : à 03:00 CEST, retour à 02:00 CET,
# les dossiers créés après le changement paraissaient antérieurs au début du passage)
$debutPassage = (Get-Date).ToUniversalTime()
# Dossier de sortie d'un scénario créé par CE passage : nom exact (« -standard » seulement avec -SessionStandard, pour ne
# jamais prendre le dossier d'un passage administrateur pour celui d'un passage en session standard), heure UTC
function Dossier-Du-Passage([string]$Scenario) {
    $motif = '^' + [regex]::Escape("$prefixe-$Scenario") + $(if ($SessionStandard) { '-standard' } else { '' }) + '-\d{8}-\d{6}$'
    Get-ChildItem $Racine -Directory | Where-Object { $_.Name -match $motif -and $_.CreationTimeUtc -ge $debutPassage } |
        Sort-Object CreationTimeUtc | Select-Object -Last 1
}
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
    # Seulement un dossier créé par CE passage : jamais le tableau d'un passage antérieur
    $s = Dossier-Du-Passage $Scenario
    if (-not $s) { "== $Scenario : AUCUN RÉSULTAT de ce passage (le lanceur a échoué avant le scénario)"; return }
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
foreach ($s in @('installation', 'quarantaine', 'lot3d') | Where-Object { $Scenarios -contains $_ }) {
    Attendre-Fermeture
    & $lanceur -Scenario $s @options *> "$env:TEMP\d4t-$s.log"
    if (-not $?) { "== $s : lanceur en échec :"; Get-Content "$env:TEMP\d4t-$s.log" -Tail 6 }
    Resume $s
    if ($Cible -eq 'vm') { $v = Dossier-Du-Passage $s | Get-ChildItem -Filter '*-vm.txt'; if ($v) { Get-Content $v.FullName } }
}
if ($Scenarios -contains 'maj') { try {
    Attendre-Fermeture
    & .\tests\bac-a-sable\preparer.ps1 -Maj *> "$env:TEMP\d4t-prep-maj.log"
    if (-not $? -or -not (Test-Path (Join-Path $Racine 'entree\maj\versions.txt'))) { 'préparation -Maj en échec'; Get-Content "$env:TEMP\d4t-prep-maj.log" -Tail 25 }
    else {
        "MSI (3c, reconstruit après les paquets de test) : SHA-256 $((Get-FileHash (Join-Path $Racine 'entree\deR4Tizer.msi') -Algorithm SHA256).Hash)"
        & $lanceur -Scenario maj @options *> "$env:TEMP\d4t-maj.log"
        if (-not $?) { "== maj : lanceur en échec :"; Get-Content "$env:TEMP\d4t-maj.log" -Tail 6 }
        Resume 'maj'
        if ($Cible -eq 'vm') { $v = Dossier-Du-Passage 'maj' | Get-ChildItem -Filter '*-vm.txt'; if ($v) { Get-Content $v.FullName } }
    }
} finally {
    Remove-Item (Join-Path $Racine 'entree\maj'), (Join-Path $Racine 'tmp') -Recurse -Force -ErrorAction SilentlyContinue
    "entree\maj restant : $(Test-Path (Join-Path $Racine 'entree\maj'))"
    "modifications du worktree après passage : $(@(git status --porcelain).Count)"
} }
