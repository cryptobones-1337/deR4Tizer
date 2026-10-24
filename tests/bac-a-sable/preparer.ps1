# Prépare, sur le poste, de quoi exécuter les scénarios d'intégration dans Windows Sandbox (Windows jetable, effacé à
# la fermeture), en remplacement de la CI GitHub tant qu'elle est indisponible. Rien n'est installé sur le poste :
# ce script compile et copie seulement. Le MSI n'est installé que dans le bac à sable (lancer.ps1).
#
#   1. service compilé avec la chaîne MSVC (la même que la CI, compiler-rs.ps1), interface, paquet MSI ;
#   2. version plus ancienne (4.1.0) construite depuis le commit figé 4da823a, comme dans la CI (en cache) ;
#   3. scripts d'intégration et script d'exécution copiés dans le dossier d'entrée, monté en lecture seule.
#
#   4. avec -Maj (scénario 3c) : PKI de test (openssl de Git), versions courante et suivante compilées avec la clé
#      de test épinglée (variable définie dans ce seul processus de compilation), paquets signés, Python embarquable
#      (cache, empreinte vérifiée à la main : MD5 publié par python.org). Clés et binaires de test dans entree\maj,
#      effacés par lancer.ps1 à la fin du scénario ; jamais commités ni téléversés.
#
# Usage : .\tests\bac-a-sable\preparer.ps1 [-Maj] [-Racine C:\d4t-bac-a-sable]
param([string]$Racine = 'C:\d4t-bac-a-sable', [switch]$Maj)
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
# CRT liée statiquement comme la version courante (service-rs/.cargo/config.toml, absent de 4da823a) : sans cela le
# service 4.1.0 dépend de VCRUNTIME140.dll, absent du bac à sable, et son installation échoue (erreur 1920)
$ancien = Join-Path $cache 'deR4Tizer-ancien-crt-statique.msi'
if (-not (Test-Path $ancien)) {
    $arbre = Join-Path $cache 'ancien'
    if (-not (Test-Path $arbre)) { git -C $depot worktree add --detach $arbre 4da823ac699e198106c9c6cbdbdd58286992dbf1; if ($LASTEXITCODE) { throw 'worktree 4da823a' } }
    $env:CARGO_TARGET_DIR = Join-Path $env:USERPROFILE '.der4tizer-build-msvc-ancien'
    Push-Location (Join-Path $arbre 'service-rs')
    $env:RUSTFLAGS = '-C target-feature=+crt-static'
    try { cargo "+$chaine" build --release; if ($LASTEXITCODE) { throw 'compilation de la version ancienne' } } finally { Pop-Location; Remove-Item Env:\RUSTFLAGS }
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

if ($Maj) {
    Etape 'Scénario 3c : PKI de test, versions avec la clé de test épinglée, paquets signés'
    $m = Join-Path $entree 'maj'
    $ex = Join-Path $m 'executables'
    $courante = $version
    $p = $courante.Split('.'); $d = [int]$p[-1]
    $nouvelle = ((@($p[0..($p.Count - 2)]) + ($d + 1)) -join '.')
    $precedente = ((@($p[0..($p.Count - 2)]) + ($d - 1)) -join '.')
    New-Item -ItemType Directory -Force -Path "$ex\$courante", "$ex\$nouvelle", (Join-Path $m 'ci-bin') | Out-Null
    # Exécutable officiel (sans clé de test) : sert à vérifier que la clé de test n'y figure pas
    Copy-Item (Join-Path $depot 'bin\deR4TizerSvc.exe') (Join-Path $m 'ci-bin\deR4TizerSvc.exe') -Force
    # openssl de Git : mingw64\bin ou usr\bin selon l'installation
    $openssl = @('mingw64\bin', 'usr\bin') | ForEach-Object { Join-Path $env:ProgramFiles "Git\$_\openssl.exe" } | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $openssl) { throw 'openssl de Git introuvable' }
    & (Join-Path $depot 'tests\integration\maj-pki.ps1') -Dossier (Join-Path $m 'pki') -OpenSsl $openssl
    $cle = (Get-Content (Join-Path $m 'pki\cle-epinglee.txt') -Raw).Trim()
    $fichier = Join-Path $depot 'service-rs\src\commun.rs'
    $original = [IO.File]::ReadAllText($fichier)
    $env:CARGO_TARGET_DIR = Join-Path $env:USERPROFILE '.der4tizer-build-msvc-test'
    $env:DER4TIZER_CLES_SIGNATURE = $cle
    try {
        Push-Location (Join-Path $depot 'service-rs')
        try {
            cargo "+$chaine" build --release; if ($LASTEXITCODE) { throw 'compilation (version courante, clé de test)' }
            Copy-Item (Join-Path $env:CARGO_TARGET_DIR 'release\der4tizer-svc.exe') "$ex\$courante\deR4TizerSvc.exe" -Force
            $t = $original.Replace("pub const VERSION: &str = `"$courante`"", "pub const VERSION: &str = `"$nouvelle`"")
            if ($t -eq $original) { throw 'numéro de version introuvable' }
            [IO.File]::WriteAllText($fichier, $t)
            cargo "+$chaine" build --release; if ($LASTEXITCODE) { throw 'compilation (version suivante, clé de test)' }
            Copy-Item (Join-Path $env:CARGO_TARGET_DIR 'release\der4tizer-svc.exe') "$ex\$nouvelle\deR4TizerSvc.exe" -Force
        } finally { Pop-Location }
    } finally {
        [IO.File]::WriteAllText($fichier, $original)
        Remove-Item Env:\DER4TIZER_CLES_SIGNATURE
    }
    Copy-Item (Join-Path $depot 'bin\deR4Tizer.exe') "$ex\$courante\deR4Tizer.exe" -Force
    $env:RUNNER_TEMP = Join-Path $Racine 'tmp'
    New-Item -ItemType Directory -Force -Path $env:RUNNER_TEMP | Out-Null
    & (Join-Path $depot 'tests\integration\maj-paquets.ps1') -Pki (Join-Path $m 'pki') -Executables $ex -Sortie (Join-Path $m 'paquets') -Courante $courante -Nouvelle $nouvelle -Precedente $precedente
    # Paquets construits : le MSI officiel de bin\ a été remplacé par maj-paquets.ps1, on le reconstruit
    & (Join-Path $depot 'compiler-rs.ps1')
    & (Join-Path $depot 'compiler.ps1') -InterfaceSeulement
    & (Join-Path $depot 'construire-msi.ps1')
    Copy-Item (Join-Path $depot 'bin\deR4Tizer.msi') (Join-Path $entree 'deR4Tizer.msi') -Force
    Set-Content -LiteralPath (Join-Path $m 'versions.txt') -Value "$courante $nouvelle $precedente" -Encoding Ascii
    $python = Join-Path $cache 'python-3.12.10'
    if (-not (Test-Path (Join-Path $python 'python.exe'))) { throw "Python embarquable absent du cache ($python)" }
    Copy-Item $python (Join-Path $entree 'python') -Recurse -Force
}

Etape 'Scripts'
Copy-Item (Join-Path $depot 'tests\integration\*.ps1') (Join-Path $entree 'integration') -Force
Copy-Item (Join-Path $depot 'tests\integration\*.py') (Join-Path $entree 'integration') -Force -ErrorAction SilentlyContinue
Copy-Item (Join-Path $PSScriptRoot 'executer.ps1') $entree -Force
Write-Host "Prêt : $entree (version $version). Lancer : .\tests\bac-a-sable\lancer.ps1 -Scenario installation|quarantaine"
