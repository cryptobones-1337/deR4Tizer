# Passage complet (preuve locale de CLAUDE.md, section 4) depuis le worktree d'intégration : tests unitaires, MSI, puis
# 3a, 3b et 3c dans la VM de test (tests\vm\lancer.ps1, par défaut) ou dans Windows Sandbox (-Cible bac-a-sable).
# Résumé de chaque tableau ; clés et binaires de test du 3c effacés quoi qu'il arrive. À surveiller avec vigie.ps1.
# Échec fermé (audit du 2026-11-14, F1) : un worktree modifié est refusé avant toute compilation (l'arbre annoncé dans
# la preuve est celui de HEAD, le MSI est construit depuis le worktree : ils doivent être identiques) ; tout ÉCHOUÉ,
# résultat absent, lanceur ou préparation en échec, ou worktree modifié par le passage donne « PASSAGE EN ÉCHEC » et le
# code de sortie 1 ; sinon « PASSAGE RÉUSSI » et 0.
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
$modifications = @(git status --porcelain).Count
"commit : $(git rev-parse --short HEAD) ; modifications : $modifications"
if ($modifications -ne 0) {
    "worktree modifié ($modifications) : passage refusé, l'arbre testé ne serait pas celui de HEAD (commiter d'abord)"
    git status --porcelain | Select-Object -First 10
    'PASSAGE EN ÉCHEC'
    exit 1
}
$script:echec = $false

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
    if (-not $s) { $script:echec = $true; "== $Scenario : AUCUN RÉSULTAT de ce passage (le lanceur a échoué avant le scénario)"; return }
    $t = Get-ChildItem $s.FullName -Filter '*-tableau.md' -ErrorAction SilentlyContinue
    if (-not $t) { $script:echec = $true; "== $Scenario : pas de tableau ($($s.Name))"; return }
    $c = Get-Content $t.FullName -Encoding UTF8
    if (@($c | Select-String '\| ÉCHOUÉ \|').Count -gt 0 -or @($c | Select-String '\| RÉUSSI \|').Count -eq 0) { $script:echec = $true }
    "== $Scenario ($($s.Name)) : RÉUSSI=$(@($c | Select-String '\| RÉUSSI \|').Count) ÉCHOUÉ=$(@($c | Select-String '\| ÉCHOUÉ \|').Count) NON EXÉCUTÉ=$(@($c | Select-String '\| NON EXÉCUTÉ \|').Count)"
    $c | Select-String '\| ÉCHOUÉ \||\| NON EXÉCUTÉ \|' | ForEach-Object { $_.Line }
}

Remove-Item (Join-Path $Racine 'entree\maj'), (Join-Path $Racine 'tmp') -Recurse -Force -ErrorAction SilentlyContinue
& .\tests\bac-a-sable\preparer.ps1 *> "$env:TEMP\d4t-prep.log"
if (-not $?) { 'préparation en échec'; Get-Content "$env:TEMP\d4t-prep.log" -Tail 25; 'PASSAGE EN ÉCHEC'; exit 1 }
"tests unitaires : $((Get-Content "$env:TEMP\d4t-prep.log" | Select-String 'test result' | Select-Object -Last 1).Line.Trim())"
$os = Get-CimInstance Win32_OperatingSystem
$ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
"commit testé : $(git rev-parse HEAD)"
"arbre testé : $(git rev-parse 'HEAD^{tree}')"
"MSI (3a, 3b) : SHA-256 $((Get-FileHash (Join-Path $Racine 'entree\deR4Tizer.msi') -Algorithm SHA256).Hash)"
"Cible : $Cible ; Windows de l'hôte : $($os.Caption) $($os.Version).$ubr"
# « mesure » (mesure du cycle, environ 25 min) seulement si demandé : ne fait pas partie de la preuve de CLAUDE.md
foreach ($s in @('installation', 'quarantaine', 'lot3d', 'mesure') | Where-Object { $Scenarios -contains $_ }) {
    Attendre-Fermeture
    # Exception du lanceur (VM injoignable, console vide…) : notée, et les scénarios suivants tournent quand même
    # (avant : elle arrêtait tout le passage)
    try { & $lanceur -Scenario $s @options *> "$env:TEMP\d4t-$s.log"; $ok = $? } catch { $ok = $false; "== $s : exception du lanceur : $($_.Exception.Message)" }
    if (-not $ok) { $script:echec = $true; "== $s : lanceur en échec :"; Get-Content "$env:TEMP\d4t-$s.log" -Tail 6 }
    Resume $s
    if ($Cible -eq 'vm') { $v = Dossier-Du-Passage $s | Get-ChildItem -Filter '*-vm.txt'; if ($v) { Get-Content $v.FullName } }
}
if ($Scenarios -contains 'maj') { try {
    Attendre-Fermeture
    & .\tests\bac-a-sable\preparer.ps1 -Maj *> "$env:TEMP\d4t-prep-maj.log"
    if (-not $? -or -not (Test-Path (Join-Path $Racine 'entree\maj\versions.txt'))) { $script:echec = $true; 'préparation -Maj en échec'; Get-Content "$env:TEMP\d4t-prep-maj.log" -Tail 25 }
    else {
        "MSI (3c, reconstruit après les paquets de test) : SHA-256 $((Get-FileHash (Join-Path $Racine 'entree\deR4Tizer.msi') -Algorithm SHA256).Hash)"
        try { & $lanceur -Scenario maj @options *> "$env:TEMP\d4t-maj.log"; $ok = $? } catch { $ok = $false; "== maj : exception du lanceur : $($_.Exception.Message)" }
        if (-not $ok) { $script:echec = $true; "== maj : lanceur en échec :"; Get-Content "$env:TEMP\d4t-maj.log" -Tail 6 }
        Resume 'maj'
        if ($Cible -eq 'vm') { $v = Dossier-Du-Passage 'maj' | Get-ChildItem -Filter '*-vm.txt'; if ($v) { Get-Content $v.FullName } }
    }
} finally {
    Remove-Item (Join-Path $Racine 'entree\maj'), (Join-Path $Racine 'tmp') -Recurse -Force -ErrorAction SilentlyContinue
    "entree\maj restant : $(Test-Path (Join-Path $Racine 'entree\maj'))"
} }
$apres = @(git status --porcelain).Count
"modifications du worktree après passage : $apres"
if ($apres -ne 0) { $script:echec = $true }
# Scénarios demandés sans résultat (aucun appel à Resume) : déjà couverts par « AUCUN RÉSULTAT » ; verdict final
if ($script:echec) { 'PASSAGE EN ÉCHEC'; exit 1 }
'PASSAGE RÉUSSI'
exit 0
