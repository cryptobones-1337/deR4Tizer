# Dossier de compilation du service, commun à toutes les copies du dépôt (worktrees), chargé par compiler-rs.ps1 et
# tests\bac-a-sable\preparer.ps1 (point-source). Cargo juge un fichier à jour par sa date : des sources plus anciennes
# que la dernière compilation faite depuis une autre copie ne seraient pas recompilées, et le binaire de l'autre copie
# serait livré (passage de mesure du 2026-10-26 : binaire de main testé sous la tête d'une PR). Quand la copie change,
# notre paquet est donc nettoyé avant de compiler ; les dépendances restent en cache.
# Prérequis : $chaine et PATH (cargo) déjà posés par l'appelant.
$env:CARGO_TARGET_DIR = Join-Path $env:USERPROFILE '.der4tizer-build-msvc'
New-Item -ItemType Directory -Force -Path $env:CARGO_TARGET_DIR | Out-Null
$marqueCopie = Join-Path $env:CARGO_TARGET_DIR 'copie-du-depot.txt'
$cetteCopie = (Resolve-Path $PSScriptRoot).Path
if ((Get-Content -LiteralPath $marqueCopie -ErrorAction SilentlyContinue | Select-Object -First 1) -ne $cetteCopie) {
    Push-Location (Join-Path $cetteCopie 'service-rs')
    try {
        cargo "+$chaine" clean -p der4tizer-svc --release
        if ($LASTEXITCODE) { throw 'nettoyage du paquet (copie du dépôt changée)' }
        cargo "+$chaine" clean -p der4tizer-svc
        if ($LASTEXITCODE) { throw 'nettoyage du paquet (copie du dépôt changée)' }
    } finally { Pop-Location }
    Set-Content -LiteralPath $marqueCopie -Value $cetteCopie -Encoding UTF8
}
