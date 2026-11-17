# Signe une version de deR4Tizer sur le poste du mainteneur, avec un certificat de signature de code dont la clé
# reste chez l'autorité (certificat « dans le nuage », par exemple Certum SimplySign : session ouverte avant de
# lancer ce script). La clé ne passe jamais par GitHub et aucun mot de passe n'apparaît sur une ligne de commande :
# signtool désigne le certificat par son empreinte dans le magasin de l'utilisateur.
#
# Étapes, chacune en échec fermé (arrêt à la première anomalie, rien n'est publié) :
#   1. arbre Git propre (la version signée est celle du commit annoncé) ;
#   2. certificat présent dans le magasin, avec sa clé privée ;
#   3. empreinte SHA-256 de la clé publique du certificat ÉPINGLÉE dans deR4TizerSvc.exe (même calcul que le service,
#      natif.rs : champ SubjectPublicKeyInfo.PublicKey) : sinon la mise à jour automatique refuserait la version ;
#   4. signature des deux exécutables, puis vérification (signature valide, bon certificat, bonne clé) ;
#   5. construction et signature du MSI (construire-msi.ps1), puis même vérification ;
#   6. manifeste de mise à jour et empreintes SHA-256 des fichiers.
# La publication (version GitHub) reste une décision du mainteneur : ce script n'envoie rien.
#
# Exemple : $env:DER4TIZER_CERT_SHA1 = '<empreinte du certificat>' ; .\signer-version.ps1 -Source C:\artefact
#   -Source : dossier des exécutables à signer (artefact de la CI, ou bin\ après compiler.ps1 compilé avec
#             DER4TIZER_CLES_SIGNATURE) ; ils sont copiés dans bin\ avant signature.
param(
    [string]$Source = (Join-Path $PSScriptRoot 'bin'),
    [string]$Certificat = $env:DER4TIZER_CERT_SHA1,
    [string]$Depot = 'cryptobones-1337/deR4Tizer'
)
$ErrorActionPreference = 'Stop'
$bin = Join-Path $PSScriptRoot 'bin'
$exes = 'deR4TizerSvc.exe', 'deR4Tizer.exe'

# 1. Arbre propre
if (Get-Command git -ErrorAction SilentlyContinue) {
    $modifs = @(git -C $PSScriptRoot status --porcelain)
    if ($LASTEXITCODE) { throw 'État Git illisible : signature refusée.' }
    if ($modifs.Count) { throw "Arbre Git modifié ($($modifs.Count) fichier(s)) : la version signée ne serait pas celle du commit annoncé." }
    "commit : $(git -C $PSScriptRoot rev-parse HEAD)"
    "arbre : $(git -C $PSScriptRoot rev-parse 'HEAD^{tree}')"
}
$version = (Select-String -Path (Join-Path $PSScriptRoot 'service-rs\src\commun.rs') -Pattern 'pub const VERSION: &str = "([^"]+)"').Matches[0].Groups[1].Value
if ($version -notmatch '^\d+(\.\d+){1,3}$') { throw "Version du code illisible ($version)." }
"version : $version"

# 2. Certificat
if ($Certificat -notmatch '^[0-9A-Fa-f]{40}$') { throw 'Empreinte du certificat absente ou mal formée (DER4TIZER_CERT_SHA1 ou -Certificat, 40 caractères hexadécimaux).' }
$cert = Get-Item "Cert:\CurrentUser\My\$Certificat" -ErrorAction SilentlyContinue
if (-not $cert) { throw 'Certificat introuvable dans le magasin de l''utilisateur : la session de signature (SimplySign) est-elle ouverte ?' }
if (-not $cert.HasPrivateKey) { throw 'Certificat sans clé privée accessible : signature impossible.' }
if ($cert.NotAfter -lt (Get-Date)) { throw "Certificat expiré le $($cert.NotAfter)." }
function Empreinte-Cle($c) {
    -join ([Security.Cryptography.SHA256]::Create().ComputeHash($c.PublicKey.EncodedKeyValue.RawData) | ForEach-Object { $_.ToString('x2') })
}
$cle = Empreinte-Cle $cert
"clé du certificat (valeur à épingler) : $cle"
"certificat valable jusqu'au : $($cert.NotAfter)"

# 3. Clé épinglée dans le service (constat E1 de l'audit du 2026-11-14)
foreach ($e in $exes) { if (-not (Test-Path (Join-Path $Source $e))) { throw "$e introuvable dans $Source." } }
$latin1 = [Text.Encoding]::GetEncoding(28591)
$texte = $latin1.GetString([IO.File]::ReadAllBytes((Join-Path $Source 'deR4TizerSvc.exe')))
if ($texte.IndexOf($cle, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "La clé de ce certificat n'est pas épinglée dans deR4TizerSvc.exe : recompiler le service avec DER4TIZER_CLES_SIGNATURE=$cle (variable de dépôt CLE_SIGNATURE pour la CI). Signer quand même rendrait la mise à jour automatique impossible."
}
'clé épinglée dans le service : oui'

# 4. Exécutables
New-Item -ItemType Directory -Force -Path $bin | Out-Null
if ((Resolve-Path $Source).Path -ne (Resolve-Path $bin).Path) {
    foreach ($e in $exes) { Copy-Item (Join-Path $Source $e) (Join-Path $bin $e) -Force }
}
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw 'signtool.exe introuvable (installez le SDK Windows).' }
function Verifier-Signature($f) {
    $s = Get-AuthenticodeSignature $f
    if ($s.Status -ne 'Valid') { throw "Signature de $(Split-Path $f -Leaf) non valide ($($s.Status) : $($s.StatusMessage))." }
    if ($s.SignerCertificate.Thumbprint -ne $cert.Thumbprint) { throw "$(Split-Path $f -Leaf) signé par un autre certificat." }
    if ((Empreinte-Cle $s.SignerCertificate) -ne $cle) { throw "$(Split-Path $f -Leaf) : clé du signataire différente." }
    if (-not $s.TimeStamperCertificate) { throw "$(Split-Path $f -Leaf) sans horodatage : la signature deviendrait invalide à l'expiration du certificat." }
    "$(Split-Path $f -Leaf) : signature valide, horodatée"
}
& $signtool.FullName sign /sha1 $cert.Thumbprint /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /d deR4Tizer @($exes | ForEach-Object { Join-Path $bin $_ })
if ($LASTEXITCODE) { throw 'Échec de la signature des exécutables.' }
foreach ($e in $exes) { Verifier-Signature (Join-Path $bin $e) }

# 5. Paquet MSI (construire-msi.ps1 le signe avec le même certificat)
$env:DER4TIZER_CERT_SHA1 = $cert.Thumbprint
& (Join-Path $PSScriptRoot 'construire-msi.ps1') -Version $version
$msi = Join-Path $bin 'deR4Tizer.msi'
Verifier-Signature $msi

# 6. Manifeste et empreintes
$base = "https://github.com/$Depot/releases/download/v$version"
$manifeste = [ordered]@{
    Version  = $version
    Fichiers = @([ordered]@{ Nom = 'deR4Tizer.msi'; Url = "$base/deR4Tizer.msi"; Sha256 = (Get-FileHash $msi -Algorithm SHA256).Hash.ToLower() })
}
[IO.File]::WriteAllText((Join-Path $bin 'manifeste.json'), ($manifeste | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
$liste = foreach ($f in @('deR4Tizer.msi') + $exes + @('manifeste.json')) { "$((Get-FileHash (Join-Path $bin $f) -Algorithm SHA256).Hash.ToLower())  $f" }
[IO.File]::WriteAllLines((Join-Path $bin 'SHA256SUMS.txt'), $liste, (New-Object Text.UTF8Encoding($false)))
''
'Empreintes SHA-256 :'
$liste
''
"Version v$version signée dans $bin. Rien n'a été publié : la publication est une décision du mainteneur"
"(fichiers à joindre : deR4Tizer.msi, deR4TizerSvc.exe, deR4Tizer.exe, manifeste.json, SHA256SUMS.txt)."
