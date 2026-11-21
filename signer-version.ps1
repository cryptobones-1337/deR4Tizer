# Signature locale d'une version (plan avant la première version signée, bloc 1.1 ; décisions du mainteneur du
# 2026-11-21). Le certificat (Certum, clé dans SimplySign) n'est pas exportable : la CI compile, le poste du mainteneur
# signe. Un seul script, qui s'arrête à la première vérification en échec :
#
#   1. le dépôt local est au commit du tag, propre ; le tag a la forme vX.Y(.Z) et la version du code ;
#   2. l'exécution « Publication » de ce tag est trouvée, sur ce commit, et son job « compiler » a réussi ;
#   3. l'artefact « a-signer » (exécutables à clé épinglée, jamais publié) est téléchargé, et son empreinte SHA-256
#      est comparée à celle que GitHub donne pour cet artefact ;
#   4. les deux exécutables sont signés (horodatage Certum, DigiCert en repli seulement) ;
#   5. le MSI est construit avec ces exécutables signés (WiX 3.14, archive vérifiée par son empreinte), puis signé ;
#   6. le manifeste est écrit d'après le MSI signé ;
#   7. verifier-signatures.ps1 contrôle les trois fichiers (signature valide, horodatée, clé de CLE_SIGNATURE, chaîne
#      et révocation) ; la version du MSI doit être celle du tag ;
#   8. un brouillon de version GitHub est créé avec les quatre fichiers ; le mainteneur le relit et le publie à la main.
#      -SansPublier s'arrête avant (répétition générale, bloc 1.2).
#
# Rien n'est écrit dans le dépôt : tout est fait dans un dossier de travail neuf. Le sujet du certificat (nom du
# titulaire) n'est jamais affiché par ce script.
#
# Usage : .\signer-version.ps1 -Tag v4.4 -Empreinte <empreinte SHA-1 du certificat dans le magasin> [-SansPublier]
param(
    [Parameter(Mandatory)] [string]$Tag,
    [Parameter(Mandatory)] [string]$Empreinte,
    [string]$Depot = 'cryptobones-1337/deR4Tizer',
    [string]$Travail = (Join-Path $env:TEMP ("deR4Tizer-signature-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [switch]$SansPublier
)
$ErrorActionPreference = 'Stop'
$racine = $PSScriptRoot
function Etape([string]$t) { Write-Host "== $t" }
function Arret([string]$t) { Write-Host "ARRÊT : $t" -ForegroundColor Red; exit 1 }
function Sha256([string]$f) { (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLowerInvariant() }
# Commande externe dont la sortie d'erreur ne doit pas lever d'exception (Windows PowerShell 5.1) : le code de retour
# est lu par l'appelant dans $LASTEXITCODE
function Natif { $ErrorActionPreference = 'Continue'; & $args[0] @($args | Select-Object -Skip 1) 2>$null }

# ---------------------------------------------------------------- 1. dépôt, tag, version
Etape 'Tag, version et dépôt local'
if ($Tag -cnotmatch '^v\d+\.\d+(\.\d+)?$') { Arret "tag « $Tag » : forme vX.Y ou vX.Y.Z attendue" }
if ($Empreinte -notmatch '^[0-9A-Fa-f]{40}$') { Arret 'empreinte du certificat : 40 caractères hexadécimaux attendus (SHA-1 du magasin)' }
foreach ($o in 'git', 'gh') { if (-not (Get-Command $o -ErrorAction SilentlyContinue)) { Arret "$o introuvable" } }
$commitTag = Natif git -C $racine rev-parse "$Tag^{commit}"
if ($LASTEXITCODE -or -not $commitTag) { Arret "tag $Tag absent du dépôt local (git fetch --tags)" }
$tete = git -C $racine rev-parse HEAD
if ($tete -ne $commitTag) { Arret "le dépôt local n'est pas au commit du tag ($commitTag) : git checkout $Tag" }
if (git -C $racine status --porcelain) { Arret 'dépôt local modifié : le MSI doit être construit depuis les sources exactes du tag' }
$version = (Select-String -Path (Join-Path $racine 'service-rs\src\commun.rs') -Pattern 'pub const VERSION: &str = "([^"]+)"').Matches[0].Groups[1].Value
if ("v$version" -ne $Tag) { Arret "tag $Tag différent de la version du code ($version)" }
$cles = Natif gh variable get CLE_SIGNATURE --repo $Depot
if ($LASTEXITCODE -or -not $cles) { Arret 'variable de dépôt CLE_SIGNATURE illisible (gh auth status ?)' }
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { Arret 'signtool introuvable (Windows SDK)' }
$cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $Empreinte.ToUpperInvariant() } | Select-Object -First 1
if (-not $cert) { Arret 'certificat absent des magasins personnels (SimplySign Desktop connecté ?)' }
# Même calcul que verifier-signatures.ps1 et que le service : seule l'empreinte de la clé est affichée
$sha = [Security.Cryptography.SHA256]::Create()
try { $cleCert = -join ($sha.ComputeHash($cert.PublicKey.EncodedKeyValue.RawData) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
if ($cleCert -notin @($cles -split ',' | ForEach-Object { $_.Trim().ToLowerInvariant() })) { Arret "la clé de ce certificat ($cleCert) n'est pas dans CLE_SIGNATURE" }
Write-Host "Tag $Tag, commit $commitTag, version $version ; clé du certificat $cleCert épinglée"

# ---------------------------------------------------------------- 2. exécution « Publication » du tag
Etape 'Exécution « Publication » du tag'
$runs = gh run list --repo $Depot --workflow publication.yml --limit 50 --json databaseId,headSha,headBranch,event | ConvertFrom-Json
$run = @($runs | Where-Object { $_.headSha -eq $commitTag -and $_.headBranch -eq $Tag -and $_.event -eq 'push' }) | Select-Object -First 1
if (-not $run) { Arret "aucune exécution « Publication » pour $Tag sur $commitTag" }
$jobs = (gh run view $run.databaseId --repo $Depot --json jobs | ConvertFrom-Json).jobs
$compiler = @($jobs | Where-Object { $_.name -eq 'compiler' }) | Select-Object -First 1
if (-not $compiler -or $compiler.conclusion -ne 'success') { Arret "job « compiler » de l'exécution $($run.databaseId) : $($compiler.conclusion)" }
Write-Host "Exécution $($run.databaseId), job « compiler » réussi"

# ---------------------------------------------------------------- 3. artefact « a-signer »
Etape 'Artefact « a-signer » et son empreinte'
New-Item -ItemType Directory -Path $Travail | Out-Null
$artefacts = (gh api "repos/$Depot/actions/runs/$($run.databaseId)/artifacts" | ConvertFrom-Json).artifacts
$a = @($artefacts | Where-Object { $_.name -eq 'a-signer' -and -not $_.expired }) | Select-Object -First 1
if (-not $a) { Arret "artefact « a-signer » absent ou expiré (7 jours) : relancer le job « compiler » de l'exécution $($run.databaseId)" }
if ($a.digest -notmatch '^sha256:([0-9a-f]{64})$') { Arret "empreinte de l'artefact non publiée par GitHub ($($a.digest))" }
$attendue = $Matches[1]
$zip = Join-Path $Travail 'a-signer.zip'
# Téléchargement en octets (une redirection de PowerShell réencoderait le contenu), jeton de gh jamais affiché
$jeton = gh auth token
try {
    Invoke-WebRequest -Uri "https://api.github.com/repos/$Depot/actions/artifacts/$($a.id)/zip" -Headers @{ Authorization = "Bearer $jeton"; Accept = 'application/vnd.github+json' } -OutFile $zip -UseBasicParsing
} catch { Arret "téléchargement de l'artefact impossible : $($_.Exception.Message)" } finally { $jeton = $null }
$recue = Sha256 $zip
if ($recue -ne $attendue) { Arret "empreinte de l'artefact $recue différente de celle de GitHub $attendue" }
$entree = Join-Path $Travail 'a-signer'
Expand-Archive -LiteralPath $zip -DestinationPath $entree
$noms = @(Get-ChildItem $entree -File | ForEach-Object Name | Sort-Object)
if (($noms -join ',') -ne 'deR4Tizer.exe,deR4TizerSvc.exe') { Arret "contenu inattendu de l'artefact : $($noms -join ', ')" }
foreach ($n in $noms) {
    $s = Get-AuthenticodeSignature (Join-Path $entree $n)
    if ($s.Status -ne 'NotSigned') { Arret "$n porte déjà une signature ($($s.Status)) : ce n'est pas un exécutable de la CI à signer" }
}
Write-Host "Artefact $($a.id) : SHA-256 $recue, conforme à GitHub"

# ---------------------------------------------------------------- 4. signature des exécutables
Etape 'Signature des exécutables (SimplySign demande votre code)'
$bin = Join-Path $Travail 'bin'
New-Item -ItemType Directory -Path $bin | Out-Null
Copy-Item (Join-Path $entree 'deR4Tizer.exe'), (Join-Path $entree 'deR4TizerSvc.exe') $bin
function Signer([string[]]$Fichiers, [string[]]$Plus = @()) {
    foreach ($serveur in 'http://time.certum.pl/', 'http://timestamp.digicert.com') {
        & $signtool.FullName sign /sha1 $Empreinte /fd SHA256 /tr $serveur /td SHA256 @Plus @Fichiers
        if (-not $LASTEXITCODE) { if ($serveur -ne 'http://time.certum.pl/') { Write-Host "Horodatage par $serveur (Certum injoignable)" }; return }
        Write-Host "Échec avec l'horodatage $serveur"
    }
    Arret "signature impossible : $($Fichiers -join ', ')"
}
Signer @((Join-Path $bin 'deR4Tizer.exe'), (Join-Path $bin 'deR4TizerSvc.exe'))

# ---------------------------------------------------------------- 5. MSI avec les exécutables signés
Etape 'Paquet MSI (WiX 3.14, archive vérifiée)'
$wix = Join-Path $Travail 'wix314'
$wixZip = "$wix.zip"
Invoke-WebRequest https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip -OutFile $wixZip -UseBasicParsing
if ((Get-FileHash $wixZip -Algorithm SHA256).Hash -ne '6AC824E1642D6F7277D0ED7EA09411A508F6116BA6FAE0AA5F2C7DAA2FF43D31') { Arret 'archive WiX inattendue' }
Expand-Archive $wixZip $wix
# construire-msi.ps1 lit bin\ du dépôt : copie des sources du tag dans le dossier de travail, rien n'est écrit dans le dépôt
$sources = Join-Path $Travail 'sources'
git -C $racine worktree add --detach $sources $commitTag 2>&1 | Out-Null
if ($LASTEXITCODE) { Arret 'copie des sources du tag impossible (git worktree)' }
try {
    New-Item -ItemType Directory -Force -Path (Join-Path $sources 'bin') | Out-Null
    Copy-Item (Join-Path $bin 'deR4Tizer.exe'), (Join-Path $bin 'deR4TizerSvc.exe') (Join-Path $sources 'bin')
    $env:WIX = $wix
    Remove-Item Env:\DER4TIZER_CERT_SHA1 -ErrorAction SilentlyContinue
    & (Join-Path $sources 'construire-msi.ps1') -Version $version | Out-Null
    Copy-Item (Join-Path $sources 'bin\deR4Tizer.msi') (Join-Path $bin 'deR4Tizer.msi')
} finally {
    git -C $racine worktree remove --force $sources 2>&1 | Out-Null
}
Signer @((Join-Path $bin 'deR4Tizer.msi')) @('/d', 'deR4Tizer')

# ---------------------------------------------------------------- 6. manifeste d'après le MSI signé
Etape 'Manifeste'
$base = "https://github.com/$Depot/releases/download/$Tag"
$manifeste = [ordered]@{ Version = $version; Fichiers = @([ordered]@{ Nom = 'deR4Tizer.msi'; Url = "$base/deR4Tizer.msi"; Sha256 = (Sha256 (Join-Path $bin 'deR4Tizer.msi')) }) }
[IO.File]::WriteAllText((Join-Path $bin 'manifeste.json'), ($manifeste | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding $false))

# ---------------------------------------------------------------- 7. vérifications
Etape 'Vérification des signatures (verifier-signatures.ps1)'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $racine 'verifier-signatures.ps1') -Cles $cles -Fichiers (Join-Path $bin 'deR4Tizer.msi'), (Join-Path $bin 'deR4TizerSvc.exe'), (Join-Path $bin 'deR4Tizer.exe')
if ($LASTEXITCODE) { Arret 'vérification des signatures en échec' }
$installeur = New-Object -ComObject WindowsInstaller.Installer
$base_msi = $installeur.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installeur, @((Join-Path $bin 'deR4Tizer.msi'), 0))
$vue = $base_msi.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $base_msi, @("SELECT Value FROM Property WHERE Property='ProductVersion'"))
$vue.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $vue, $null) | Out-Null
$ligne = $vue.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $vue, $null)
$versionMsi = $ligne.GetType().InvokeMember('StringData', 'GetProperty', $null, $ligne, 1)
$attenduMsi = ($version.Split('.') + @('0', '0', '0'))[0..2] -join '.'
if ($versionMsi -ne $attenduMsi) { Arret "version du MSI $versionMsi différente de $attenduMsi" }
Write-Host "ProductVersion du MSI : $versionMsi"
Write-Host ''
Write-Host 'Empreintes SHA-256 :'
foreach ($n in 'deR4Tizer.msi', 'deR4TizerSvc.exe', 'deR4Tizer.exe', 'manifeste.json') { Write-Host ("  {0,-18} {1}" -f $n, (Sha256 (Join-Path $bin $n))) }

# ---------------------------------------------------------------- 8. brouillon de version
if ($SansPublier) {
    Write-Host "Répétition terminée (-SansPublier) : rien n'est publié. Fichiers dans $bin"
    exit 0
}
Etape 'Brouillon de version GitHub'
Natif gh release view $Tag --repo $Depot | Out-Null
if (-not $LASTEXITCODE) { Arret "une version $Tag existe déjà sur GitHub : rien n'est remplacé" }
gh release create $Tag (Join-Path $bin 'deR4Tizer.msi') (Join-Path $bin 'deR4TizerSvc.exe') (Join-Path $bin 'deR4Tizer.exe') (Join-Path $bin 'manifeste.json') --repo $Depot --draft --verify-tag --title "deR4Tizer $Tag" --generate-notes
if ($LASTEXITCODE) { Arret 'création du brouillon impossible' }
Write-Host "Brouillon $Tag créé : relisez-le sur GitHub, puis publiez-le vous-même (Publish release)."
exit 0
