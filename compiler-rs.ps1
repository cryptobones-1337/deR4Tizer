# Compile le service Rust (deR4TizerSvc.exe) avec la chaîne GNU de rustup, puis le copie dans bin\.
# Les fichiers intermédiaires vont dans un dossier court (%USERPROFILE%\.der4tizer-build) pour éviter
# la limite de 260 caractères des chemins Windows.
param([switch]$Debug)
$ErrorActionPreference = 'Stop'
$cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
$outils = Get-ChildItem (Join-Path $env:USERPROFILE '.rustup\toolchains') -Directory -Filter 'stable-*-gnu' |
    ForEach-Object { Join-Path $_.FullName 'lib\rustlib\x86_64-pc-windows-gnu\bin\self-contained' } | Select-Object -First 1
$env:PATH = "$cargoBin;$outils;$env:PATH"
$env:CARGO_TARGET_DIR = Join-Path $env:USERPROFILE '.der4tizer-build'

Push-Location (Join-Path $PSScriptRoot 'service-rs')
try {
    if ($Debug) { cargo build } else { cargo build --release }
    if ($LASTEXITCODE) { throw 'Échec de la compilation du service Rust.' }
} finally { Pop-Location }

$profil = if ($Debug) { 'debug' } else { 'release' }
$sortie = Join-Path $PSScriptRoot 'bin'
New-Item -ItemType Directory -Force -Path $sortie | Out-Null
Copy-Item (Join-Path $env:CARGO_TARGET_DIR "$profil\der4tizer-svc.exe") (Join-Path $sortie 'deR4TizerSvc.exe') -Force
