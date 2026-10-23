# Prépare, sur le poste, de quoi exécuter les scénarios d'intégration dans Windows Sandbox (Windows jetable, effacé à
# la fermeture), en remplacement de la CI GitHub tant qu'elle est indisponible. Rien n'est installé sur le poste :
# ce script compile et copie seulement. Le MSI n'est installé que dans le bac à sable (lancer.ps1).
#
#   1. service compilé avec la chaîne MSVC (la même que la CI, compiler-rs.ps1), interface, paquet MSI ;
#   2. version plus ancienne (4.1.0) construite depuis le commit figé 4da823a, comme dans la CI (en cache) ;
#   3. scripts d'intégration et script d'exécution copiés dans le dossier d'entrée, monté en lecture seule.
#
# Usage : .\tests\bac-a-sable\preparer.ps1 [-Racine C:\d4t-bac-a-sable]
param([string]$Racine = 'C:\d4t-bac-a-sable')
$ErrorActionPreference = 'Stop'
$depot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$entree = Join-Path $Racine 'entree'
$cache = Join-Path $Racine 'cache'
$chaine = 'stable-x86_64-pc-windows-msvc'
$env:PATH = "$(Join-Path $env:USERPROFILE '.cargo\bin');$env:PATH"
if (-not $env:WIX) { $env:WIX = Join-Path $env:USERPROFILE '.der4tizer-outils\wix314' }
if (-not (Test-Path (Join-Path $env:WIX 'candle.exe'))) { throw "WiX 3.14 introuvable ($env:WIX)." }

function Etape([string]$t) { Write-Host "== $t" }

# Dossier d'entrée vidé (jamais le cache)
New-Item -ItemType Directory -Force -Path $Racine, $cache | Out-Null
Remove-Item -LiteralPath $entree -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $entree, (Join-Path $entree 'integration') | Out-Null

Etape 'Tests unitaires (MSVC)'
$env:CARGO_TARGET_DIR = Join-Path $env:USERPROFILE '.der4tizer-build-msvc'
Push-Location (Join-Path $depot 'service-rs')
try { cargo "+$chaine" test --release; if ($LASTEXITCODE) { throw 'tests unitaires en échec' } } finally { Pop-Location }

Etape 'Service (MSVC), interface, paquet MSI'
& (Join-Path $depot 'compiler-rs.ps1')
& (Join-Path $depot 'compiler.ps1') -InterfaceSeulement
& (Join-Path $depot 'construire-msi.ps1')
Copy-Item (Join-Path $depot 'bin\deR4Tizer.msi') (Join-Path $entree 'deR4Tizer.msi') -Force
$version = (Select-String -Path (Join-Path $depot 'service-rs\src\commun.rs') -Pattern 'pub const VERSION: &str = "([^"]+)"').Matches[0].Groups[1].Value
Set-Content -LiteralPath (Join-Path $entree 'version.txt') -Value $version -Encoding Ascii
# Commit exact construit, pour le rapport
Set-Content -LiteralPath (Join-Path $entree 'commit.txt') -Value ((git -C $depot rev-parse HEAD) + $(if (git -C $depot status --porcelain) { ' (modifications non commitées)' } else { '' })) -Encoding Ascii

Etape 'Version plus ancienne 4.1.0 (commit 4da823a, en cache)'
$ancien = Join-Path $cache 'deR4Tizer-ancien.msi'
if (-not (Test-Path $ancien)) {
    $arbre = Join-Path $cache 'ancien'
    if (-not (Test-Path $arbre)) { git -C $depot worktree add --detach $arbre 4da823ac699e198106c9c6cbdbdd58286992dbf1; if ($LASTEXITCODE) { throw 'worktree 4da823a' } }
    $env:CARGO_TARGET_DIR = Join-Path $env:USERPROFILE '.der4tizer-build-msvc-ancien'
    Push-Location (Join-Path $arbre 'service-rs')
    try { cargo "+$chaine" build --release; if ($LASTEXITCODE) { throw 'compilation de la version ancienne' } } finally { Pop-Location }
    Push-Location $arbre
    try {
        & .\compiler.ps1 -InterfaceSeulement
        New-Item -ItemType Directory -Force -Path bin | Out-Null
        Copy-Item (Join-Path $env:CARGO_TARGET_DIR 'release\der4tizer-svc.exe') bin\deR4TizerSvc.exe -Force
        & .\construire-msi.ps1 -Version 4.1.0
        Copy-Item bin\deR4Tizer.msi $ancien -Force
    } finally { Pop-Location }
}
Copy-Item $ancien (Join-Path $entree 'deR4Tizer-ancien.msi') -Force

Etape 'Scripts'
Copy-Item (Join-Path $depot 'tests\integration\*.ps1') (Join-Path $entree 'integration') -Force
Copy-Item (Join-Path $PSScriptRoot 'executer.ps1') $entree -Force
Write-Host "Prêt : $entree (version $version). Lancer : .\tests\bac-a-sable\lancer.ps1 -Scenario installation|quarantaine"
