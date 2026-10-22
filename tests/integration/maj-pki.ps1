# Lot 3c : infrastructure de test pour la mise à jour, générée dans le job et jamais conservée. Racine de test,
# liste de révocation (CRL) servie par le serveur local, certificat TLS de localhost (avec adresse de CRL :
# Schannel, donc curl.exe, vérifie la révocation), certificats de signature de code :
#   epinglee    clé K (épinglée dans les binaires de test), valide
#   autre       clé K2 (non épinglée), valide
#   revoquee    clé K, révoqué dans la CRL
#   sanscrl     clé K, adresse de CRL qui ne répond pas
# Les trois certificats de la clé K sont distincts : seule la révocation change, et le cache des CRL de Windows
# ne mélange pas les cas. Mots de passe aléatoires, jamais affichés. Ce script n'approuve rien : l'import de la
# racine dans le magasin de la machine est fait par le job, sur le runner jetable seulement.
param(
    [Parameter(Mandatory)] [string]$Dossier,
    [string]$OpenSsl = 'C:\Program Files\Git\mingw64\bin\openssl.exe',
    [string]$Hote = 'localhost',
    [int]$PortCrl = 8080,
    [int]$PortCrlMuet = 8081
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $OpenSsl)) { $OpenSsl = (Get-Command openssl.exe).Source }
New-Item -ItemType Directory -Force -Path $Dossier, (Join-Path $Dossier 'nouveaux') | Out-Null
$d = (Resolve-Path $Dossier).Path -replace '\\', '/'

# openssl écrit sur stderr même quand tout va bien : seul le code de retour fait foi
function O {
    $ErrorActionPreference = 'Continue'
    $sortie = & $OpenSsl @args 2>&1 | ForEach-Object { "$_" }
    if ($LASTEXITCODE) { throw "openssl $($args[0]) : $($sortie -join ' | ')" }
}

$o = New-Object byte[] 24
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($o)
$mdp = [Convert]::ToBase64String($o) -replace '[+/=]', 'x'
[IO.File]::WriteAllText("$Dossier\mot-de-passe.txt", $mdp)

$crl = "http://${Hote}:$PortCrl/racine.crl"
$crlMuet = "http://${Hote}:$PortCrlMuet/absent.crl"
$config = @"
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = deR4Tizer racine de test (CI, jetable)
[ ca ]
default_ca = ca_test
[ ca_test ]
dir = $d
database = $d/index.txt
new_certs_dir = $d/nouveaux
certificate = $d/racine.crt
private_key = $d/racine.key
serial = $d/serie
crlnumber = $d/crlnumero
default_md = sha256
default_days = 30
default_crl_days = 7
policy = politique
unique_subject = no
copy_extensions = none
[ politique ]
commonName = supplied
[ ext_racine ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[ ext_signature ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = codeSigning
authorityKeyIdentifier = keyid
crlDistributionPoints = URI:$crl
[ ext_signature_muet ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = codeSigning
authorityKeyIdentifier = keyid
crlDistributionPoints = URI:$crlMuet
[ ext_tls ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
authorityKeyIdentifier = keyid
subjectAltName = DNS:$Hote,IP:127.0.0.1
crlDistributionPoints = URI:$crl
"@
$cfg = "$d/openssl.cnf"
[IO.File]::WriteAllText($cfg, $config, (New-Object Text.ASCIIEncoding))
[IO.File]::WriteAllText("$Dossier\index.txt", '')
[IO.File]::WriteAllText("$Dossier\serie", "1000`n")
[IO.File]::WriteAllText("$Dossier\crlnumero", "1000`n")

# Racine
O req -x509 -config $cfg -newkey rsa:3072 -nodes -keyout "$d/racine.key" -out "$d/racine.crt" -days 30 -extensions ext_racine
# Clés : K (épinglée), K2 (non épinglée), TLS
foreach ($k in 'k', 'k2', 'tls') { O genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$d/$k.key" }

# Certificat émis par la racine : nom, clé, extensions
function Emettre([string]$Nom, [string]$Cle, [string]$Extensions, [string]$Cn) {
    O req -new -config $cfg -key "$d/$Cle.key" -subj "/CN=$Cn" -out "$d/$Nom.csr"
    O ca -batch -config $cfg -extensions $Extensions -notext -in "$d/$Nom.csr" -out "$d/$Nom.crt"
}
Emettre 'epinglee' 'k' 'ext_signature' 'deR4Tizer signature de test (cle epinglee)'
Emettre 'autre' 'k2' 'ext_signature' 'deR4Tizer signature de test (cle non epinglee)'
Emettre 'revoquee' 'k' 'ext_signature' 'deR4Tizer signature de test (revoque)'
Emettre 'sanscrl' 'k' 'ext_signature_muet' 'deR4Tizer signature de test (CRL muette)'
Emettre 'tls' 'tls' 'ext_tls' $Hote

# Révocation, puis CRL (DER) : produite une fois, avant tout usage
O ca -config $cfg -revoke "$d/revoquee.crt" -crl_reason keyCompromise
O ca -config $cfg -gencrl -out "$d/racine.crl.pem"
O crl -in "$d/racine.crl.pem" -outform DER -out "$d/racine.crl"

# Fichiers PFX pour signtool (chaîne comprise)
foreach ($n in 'epinglee', 'autre', 'revoquee', 'sanscrl') {
    $cle = if ($n -eq 'autre') { 'k2' } else { 'k' }
    O pkcs12 -export -inkey "$d/$cle.key" -in "$d/$n.crt" -certfile "$d/racine.crt" -out "$d/$n.pfx" -passout "pass:$mdp" `
        -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256
}

# Empreintes des clés publiques, calculées comme natif::cle_signataire_verifiee (SHA-256 du champ
# SubjectPublicKey du certificat)
function Empreinte([string]$Crt) {
    $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2($Crt)
    ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($c.GetPublicKey())) -replace '-', '').ToLower()
}
$k = Empreinte "$Dossier\epinglee.crt"
foreach ($n in 'revoquee', 'sanscrl') { if ((Empreinte "$Dossier\$n.crt") -ne $k) { throw "$n n'a pas la clé épinglée" } }
if ((Empreinte "$Dossier\autre.crt") -eq $k) { throw 'la clé non épinglée est égale à la clé épinglée' }
[IO.File]::WriteAllText("$Dossier\cle-epinglee.txt", $k)
[IO.File]::WriteAllText("$Dossier\cle-autre.txt", (Empreinte "$Dossier\autre.crt"))
"PKI de test prête : clé épinglée $k"
