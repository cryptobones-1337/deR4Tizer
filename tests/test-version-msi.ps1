# Répétition de signature du 2026-11-22 : signer-version.ps1 s'arrêtait à la lecture de la version du MSI (chemin venu
# de Join-Path, refusé par l'appel COM). Lancé par la CI juste après la construction du MSI (bin\deR4Tizer.msi).
param([string]$Msi = (Join-Path $PSScriptRoot '..\bin\deR4Tizer.msi'))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\version-msi.ps1')
$echecs = 0
function Cas([string]$Nom, [bool]$Ok, [string]$Detail = '') {
    if ($Ok) { Write-Host "RÉUSSI  $Nom" } else { Write-Host "ÉCHOUÉ  $Nom $Detail" -ForegroundColor Red; $script:echecs++ }
}
$code = Get-Content -Raw (Join-Path $PSScriptRoot '..\service-rs\src\commun.rs')
$version = [regex]::Match($code, 'pub const VERSION: &str = "([0-9.]+)"').Groups[1].Value
$attendu = ($version.Split('.') + @('0', '0', '0'))[0..2] -join '.'
$dossier = Split-Path -Parent $Msi
# Chemin tel que signer-version.ps1 le construit : résultat de Join-Path, enveloppé
$lu = Get-VersionMsi (Join-Path $dossier (Split-Path -Leaf $Msi))
Cas "version lue avec un chemin de Join-Path ($attendu)" ($lu -eq $attendu) "lu : $lu"
$lu2 = Get-VersionMsi ([string](Resolve-Path -LiteralPath $Msi))
Cas 'version lue avec un chemin texte' ($lu2 -eq $attendu) "lu : $lu2"
$introuvable = $false
try { Get-VersionMsi (Join-Path $dossier 'absent.msi') | Out-Null } catch { $introuvable = $_.Exception.Message -match 'introuvable' }
Cas 'MSI absent : arrêt' $introuvable
# signer-version.ps1 lit la version par cette fonction
$script = Get-Content -Raw (Join-Path $PSScriptRoot '..\signer-version.ps1')
Cas 'signer-version.ps1 utilise Get-VersionMsi' ($script -match 'Get-VersionMsi' -and $script -notmatch "InvokeMember\('OpenDatabase'")
if ($echecs) { Write-Host "$echecs cas en échec" -ForegroundColor Red; exit 1 }
Write-Host 'Version du MSI : tous les cas réussis'
