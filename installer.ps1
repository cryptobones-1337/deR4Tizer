#Requires -RunAsAdministrator
# Installe (ou met à jour) deR4Tizer :
#   - C:\Program Files\deR4Tizer    deR4TizerSvc.exe (service) et deR4Tizer.exe (interface)
#   - C:\ProgramData\deR4Tizer      état, alertes, événements, journal (lecture : compte connecté et administrateurs)
#   - service "deR4Tizer" en compte SYSTEM, démarrage automatique, redémarré en cas de plantage
#   - raccourci dans le menu Démarrer, et au démarrage de session si vous le voulez
$ErrorActionPreference = 'Stop'
$source  = Join-Path $PSScriptRoot 'bin'
$dest    = Join-Path $env:ProgramFiles 'deR4Tizer'
$donnees = Join-Path $env:ProgramData 'deR4Tizer'
$menu    = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'

foreach ($exe in 'deR4TizerSvc.exe', 'deR4Tizer.exe') {
    if (-not (Test-Path (Join-Path $source $exe))) { throw "$exe introuvable dans $source : lancez d'abord compiler.ps1." }
}

# Mise à jour : arrêter l'existant
if (Get-Service deR4Tizer -ErrorAction SilentlyContinue) {
    Stop-Service deR4Tizer -Force
    (Get-Service deR4Tizer).WaitForStatus('Stopped', '00:00:20')
}
Get-Process deR4Tizer -ErrorAction SilentlyContinue | Stop-Process -Force

New-Item -ItemType Directory -Force -Path $dest, $donnees | Out-Null
Copy-Item (Join-Path $source 'deR4TizerSvc.exe'), (Join-Path $source 'deR4Tizer.exe') $dest -Force

# Données : SYSTEM et Administrateurs en écriture ; en lecture, seulement le compte connecté (l'interface lit
# sans droits admin). Les événements, sessions et alertes ne sont pas lisibles par les autres comptes du PC ;
# un autre compte peut être autorisé depuis l'interface (UAC). Le service repose ces droits toutes les heures.
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
$droits = [ordered]@{ 'S-1-5-18' = 'FullControl'; 'S-1-5-32-544' = 'FullControl' }
$connecte = (Get-CimInstance Win32_ComputerSystem).UserName
if ($connecte) { $droits[(New-Object Security.Principal.NTAccount($connecte)).Translate([Security.Principal.SecurityIdentifier]).Value] = 'ReadAndExecute' }
foreach ($sid in $droits.Keys) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        (New-Object Security.Principal.SecurityIdentifier $sid), $droits[$sid], 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
Set-Acl -Path $donnees -AclObject $acl

if (-not (Get-Service deR4Tizer -ErrorAction SilentlyContinue)) {
    New-Service -Name deR4Tizer -DisplayName 'deR4Tizer' -StartupType Automatic `
        -BinaryPathName "`"$dest\deR4TizerSvc.exe`"" `
        -Description 'Surveille les connexions sortantes, alerte sur les flux suspects et applique les blocages (hosts, pare-feu).' | Out-Null
}
sc.exe failure deR4Tizer reset= 86400 actions= restart/5000/restart/5000/restart/60000 | Out-Null
Start-Service deR4Tizer
Write-Host "Service deR4Tizer : $((Get-Service deR4Tizer).Status)" -ForegroundColor Green

$shell = New-Object -ComObject WScript.Shell
$raccourci = $shell.CreateShortcut((Join-Path $menu 'deR4Tizer.lnk'))
$raccourci.TargetPath = "$dest\deR4Tizer.exe"
$raccourci.Save()

$demarrage = Join-Path $menu 'Startup\deR4Tizer.lnk'
if ((Read-Host "Lancer l'interface (icône dans la zone de notification) à chaque ouverture de session ? (o/n)") -match '^[oOyY]') {
    $raccourci = $shell.CreateShortcut($demarrage)
    $raccourci.TargetPath = "$dest\deR4Tizer.exe"
    $raccourci.Arguments = '--cache'
    $raccourci.Save()
    Write-Host 'Interface ajoutée au démarrage de session.' -ForegroundColor Green
} elseif (Test-Path $demarrage) { Remove-Item $demarrage }

# Ouvre l'interface sans droits admin (via l'Explorateur)
Start-Process explorer.exe "`"$dest\deR4Tizer.exe`""
Write-Host 'Installation terminée.' -ForegroundColor Green
