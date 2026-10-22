#Requires -RunAsAdministrator
# Désinstalle deR4Tizer : retire tous ses blocages (hosts, pare-feu, programmes isolés, mode panique),
# les fichiers leurres, le journal DNS s'il l'avait activé, le service, les fichiers et les raccourcis.
#   -GarderDonnees   conserve C:\ProgramData\deR4Tizer (alertes, journal, quarantaine)
#   -GarderBaseline  conserve les réglages de sécurité appliqués par la GPO locale (sinon : valeurs d'origine restaurées)
param([switch]$GarderDonnees, [switch]$GarderBaseline)
$ErrorActionPreference = 'Stop'
$dest    = Join-Path $env:ProgramFiles 'deR4Tizer'
$donnees = Join-Path $env:ProgramData 'deR4Tizer'
$menu    = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'

Get-Process deR4Tizer -ErrorAction SilentlyContinue | Stop-Process -Force
if (Get-Service deR4Tizer -ErrorAction SilentlyContinue) {
    Stop-Service deR4Tizer -Force
    (Get-Service deR4Tizer).WaitForStatus('Stopped', '00:00:20')
}

$svc = Join-Path $dest 'deR4TizerSvc.exe'
if (Test-Path $svc) {
    & $svc --nettoyer
    if (-not $GarderBaseline) { & $svc --annuler-baseline }
}

if (Get-Service deR4Tizer -ErrorAction SilentlyContinue) { sc.exe delete deR4Tizer | Out-Null }
Remove-Item (Join-Path $menu 'deR4Tizer.lnk'), (Join-Path $menu 'Startup\deR4Tizer.lnk') -ErrorAction SilentlyContinue
Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue
if (-not $GarderDonnees) { Remove-Item $donnees -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host 'deR4Tizer désinstallé.' -ForegroundColor Green
