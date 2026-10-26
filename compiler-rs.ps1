# Compile le service Rust (deR4TizerSvc.exe) avec la chaîne MSVC de rustup, la même que la CI (versions
# distribuées), puis le copie dans bin\. Prérequis : Visual Studio Build Tools 2022, charge de travail
# « Développement Desktop en C++ » (éditeur de liens et SDK Windows), et
#   rustup toolchain install stable-x86_64-pc-windows-msvc
# Les fichiers intermédiaires vont dans un dossier court (%USERPROFILE%\.der4tizer-build-msvc) pour éviter
# la limite de 260 caractères des chemins Windows.
# Les tests sur un poste se font avec l'artefact compilé par la CI, pas avec cette compilation locale.
param([switch]$Debug)
$ErrorActionPreference = 'Stop'
$chaine = 'stable-x86_64-pc-windows-msvc'
$env:PATH = "$(Join-Path $env:USERPROFILE '.cargo\bin');$env:PATH"
# Dossier de compilation propre à cette copie du dépôt (cible-cargo.ps1)
. (Join-Path $PSScriptRoot 'cible-cargo.ps1')

Push-Location (Join-Path $PSScriptRoot 'service-rs')
try {
    if ($Debug) { cargo "+$chaine" build } else { cargo "+$chaine" build --release }
    if ($LASTEXITCODE) { throw 'Échec de la compilation du service Rust.' }
} finally { Pop-Location }

$profil = if ($Debug) { 'debug' } else { 'release' }
$sortie = Join-Path $PSScriptRoot 'bin'
New-Item -ItemType Directory -Force -Path $sortie | Out-Null
Copy-Item (Join-Path $env:CARGO_TARGET_DIR "$profil\der4tizer-svc.exe") (Join-Path $sortie 'deR4TizerSvc.exe') -Force
