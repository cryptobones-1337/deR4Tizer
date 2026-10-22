# Lot 3c : paquets MSI de test, signés par la PKI de test (maj-pki.ps1), à partir des exécutables compilés dans
# le job avec la clé de test épinglée. Rien de tout cela n'est jamais téléversé comme artefact.
#
#   <courante>.msi          version courante, clé épinglée (installée au départ ; paquet de retour arrière)
#   <nouvelle>.msi          version suivante, clé épinglée (mise à jour réussie)
#   <nouvelle>-autre.msi    version suivante, clé non épinglée
#   <nouvelle>-revoquee.msi version suivante, certificat révoqué (même clé épinglée)
#   <nouvelle>-sanscrl.msi  version suivante, certificat dont la CRL ne répond pas (même clé épinglée)
#   <nouvelle>-casse.msi    version suivante dont l'exécutable du service n'en est pas un (installation en échec)
#   <nouvelle>-ancien.msi   version suivante contenant l'exécutable de la version courante (répond mal)
#   <courante>-autre.msi    version courante, clé non épinglée (paquet de retour refusé)
#   <precedente>.msi        version précédente, clé épinglée (servie à la place du paquet de retour)
param(
    [Parameter(Mandatory)] [string]$Pki,
    [Parameter(Mandatory)] [string]$Executables,
    [Parameter(Mandatory)] [string]$Sortie,
    [Parameter(Mandatory)] [string]$Courante,
    [Parameter(Mandatory)] [string]$Nouvelle,
    [Parameter(Mandatory)] [string]$Precedente
)
$ErrorActionPreference = 'Stop'
$racine = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$bin = Join-Path $racine 'bin'
New-Item -ItemType Directory -Force -Path $Sortie, $bin | Out-Null
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" | Sort-Object FullName -Descending | Select-Object -First 1
$mdp = (Get-Content (Join-Path $Pki 'mot-de-passe.txt') -Raw).Trim()
$invalide = Join-Path $env:RUNNER_TEMP 'pas-un-executable.exe'
[IO.File]::WriteAllText($invalide, "deR4Tizer : fichier de test, ce n'est pas un exécutable`r`n")

function Paquet([string]$Nom, [string]$Version, [string]$Service, [string]$Certificat) {
    Copy-Item $Service (Join-Path $bin 'deR4TizerSvc.exe') -Force
    Copy-Item (Join-Path $Executables "$Courante\deR4Tizer.exe") (Join-Path $bin 'deR4Tizer.exe') -Force
    & (Join-Path $racine 'construire-msi.ps1') -Version $Version | Out-Null
    $msi = Join-Path $Sortie "$Nom.msi"
    Move-Item (Join-Path $bin 'deR4Tizer.msi') $msi -Force
    # Sans horodatage externe : les certificats de test sont valides pendant tout le job
    $s = & $signtool.FullName sign /f (Join-Path $Pki "$Certificat.pfx") /p $mdp /fd SHA256 /d deR4Tizer $msi 2>&1
    if ($LASTEXITCODE) { throw "signature de $Nom : $($s | Out-String)" }
    $signe = (Get-AuthenticodeSignature $msi).SignerCertificate
    if (-not $signe -or $signe.Thumbprint -ne (New-Object Security.Cryptography.X509Certificates.X509Certificate2((Join-Path $Pki "$Certificat.crt"))).Thumbprint) {
        throw "$Nom : signataire inattendu"
    }
    "{0,-28} version {1,-6} signé par {2}" -f "$Nom.msi", $Version, $Certificat
}

$svcCourante = Join-Path $Executables "$Courante\deR4TizerSvc.exe"
$svcNouvelle = Join-Path $Executables "$Nouvelle\deR4TizerSvc.exe"
Paquet $Courante $Courante $svcCourante 'epinglee'
Paquet $Nouvelle $Nouvelle $svcNouvelle 'epinglee'
Paquet "$Nouvelle-autre" $Nouvelle $svcNouvelle 'autre'
Paquet "$Nouvelle-revoquee" $Nouvelle $svcNouvelle 'revoquee'
Paquet "$Nouvelle-sanscrl" $Nouvelle $svcNouvelle 'sanscrl'
Paquet "$Nouvelle-casse" $Nouvelle $invalide 'epinglee'
Paquet "$Nouvelle-ancien" $Nouvelle $svcCourante 'epinglee'
Paquet "$Courante-autre" $Courante $svcCourante 'autre'
Paquet $Precedente $Precedente $svcCourante 'epinglee'
Remove-Item (Join-Path $bin 'deR4TizerSvc.exe'), (Join-Path $bin 'deR4Tizer.exe') -Force
