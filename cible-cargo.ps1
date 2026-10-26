# Dossier de compilation du service, chargé par compiler-rs.ps1 et tests\bac-a-sable\preparer.ps1 (point-source).
# Un dossier par copie du dépôt (worktree), nommé par une empreinte courte de son chemin (limite de 260 caractères des
# chemins Windows). Avec un dossier commun, Cargo, qui juge un fichier à jour par sa date, ne recompilait pas des sources
# plus anciennes que la dernière compilation d'une autre copie, et livrait le binaire de l'autre copie (passage de mesure
# du 2026-10-26 : binaire de main testé sous la tête d'une PR). Un dossier par copie règle aussi le cas de deux
# compilations lancées en même temps depuis deux copies (relecture de #84, D1).
# Les dossiers des copies qui n'existent plus (worktrees retirés) sont effacés.
$racineCompilation = Join-Path $env:USERPROFILE '.der4tizer-build-msvc'
$cetteCopie = (Resolve-Path $PSScriptRoot).Path
$sha = [Security.Cryptography.SHA256]::Create()
$empreinteCopie = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($cetteCopie.ToLowerInvariant()))[0..3] | ForEach-Object { $_.ToString('x2') })
$sha.Dispose()
$env:CARGO_TARGET_DIR = Join-Path $racineCompilation $empreinteCopie
New-Item -ItemType Directory -Force -Path $env:CARGO_TARGET_DIR | Out-Null
Set-Content -LiteralPath (Join-Path $env:CARGO_TARGET_DIR 'copie-du-depot.txt') -Value $cetteCopie -Encoding UTF8
Get-ChildItem -LiteralPath $racineCompilation -Directory | Where-Object { $_.Name -match '^[0-9a-f]{8}$' -and $_.Name -ne $empreinteCopie } | ForEach-Object {
    # Sans marque (dossier en cours de création par une autre compilation) : laissé
    $copie = Get-Content -LiteralPath (Join-Path $_.FullName 'copie-du-depot.txt') -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($copie -and -not (Test-Path -LiteralPath $copie)) { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
}
