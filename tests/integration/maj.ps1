# Lot 3c : mise à jour automatique avec le service réel, sur un runner jetable. PKI de test (maj-pki.ps1), paquets
# signés (maj-paquets.ps1), serveur local journalisé (serveur-maj.py) qui reproduit l'arborescence des versions
# GitHub. Scénarios : paquet de retour refusé (clé non épinglée, version précédente), manifeste falsifié, empreinte
# fausse, clé non épinglée, certificat révoqué, CRL injoignable, paquet cassé, service qui répond mal (retour à une
# version plus ancienne), mise à jour réussie. Dossier de travail Program Files\deR4Tizer\maj contrôlé en SYSTEM.
# Audit du 2026-11-23, A-3-4 : manifeste plus ancien que la version installée (statut distinct, A-3-2), paquet signé par
# la seconde clé épinglée, certificat expiré pendant le job (horodaté : accepté ; non horodaté : refusé, témoin). Le cas
# « tube tenu par un autre processus » (A-8-2) reste déclaré non exécuté.
# Chaque requête attendue est exigée dans le journal du serveur, scénario par scénario.
param(
    [Parameter(Mandatory)] [string]$Pki,
    [Parameter(Mandatory)] [string]$Paquets,
    [Parameter(Mandatory)] [string]$Executables,
    [Parameter(Mandatory)] [string]$ArtefactCi,
    [Parameter(Mandatory)] [string]$Courante,
    [Parameter(Mandatory)] [string]$Nouvelle,
    [Parameter(Mandatory)] [string]$Precedente,
    [string]$Journaux = (Join-Path $env:RUNNER_TEMP 'journaux-msi')
)
. (Join-Path $PSScriptRoot 'commun.ps1')
New-Item -ItemType Directory -Force -Path $Journaux | Out-Null
$PortHttps = 8443; $PortHttp = 8080
$Www = Join-Path $env:RUNNER_TEMP 'd4t-www'
$Requetes = Join-Path $env:RUNNER_TEMP 'd4t-requetes.log'
$Chemin = 'cryptobones-1337/deR4Tizer/releases'
$UrlManifeste = "https://localhost:$PortHttps/$Chemin/latest/download/manifeste.json"
$Travail = Join-Path $script:Programme 'maj'
$DonneesMaj = Join-Path $script:Donnees 'maj'
$Toleres = @{ $script:Programme = @($script:SidTrustedInstaller) }
$cle = (Get-Content (Join-Path $Pki 'cle-epinglee.txt') -Raw).Trim()
$cleSeconde = (Get-Content (Join-Path $Pki 'cle-seconde.txt') -Raw).Trim()
$serveur = $null

function Msi([string]$Nom) { Join-Path $Paquets "$Nom.msi" }

# Publie un manifeste et les paquets : $Paquet sous v<Version>, $Retour sous v<Courante> (paquet de retour arrière)
function Publier([string]$Version, [string]$Paquet, [string]$Retour, [string]$Sha256 = '') {
    Remove-Item -LiteralPath (Join-Path $Www $Chemin) -Recurse -Force -ErrorAction SilentlyContinue
    foreach ($v in @($Version, $Courante) | Select-Object -Unique) { New-Item -ItemType Directory -Force -Path (Join-Path $Www "$Chemin/download/v$v") | Out-Null }
    New-Item -ItemType Directory -Force -Path (Join-Path $Www "$Chemin/latest/download") | Out-Null
    if ($Retour) { Copy-Item $Retour (Join-Path $Www "$Chemin/download/v$Courante/deR4Tizer.msi") -Force }
    Copy-Item $Paquet (Join-Path $Www "$Chemin/download/v$Version/deR4Tizer.msi") -Force
    if (-not $Sha256) { $Sha256 = (Sha256 $Paquet).ToLower() }
    $m = [ordered]@{ Version = $Version; Fichiers = @([ordered]@{ Nom = 'deR4Tizer.msi'; Url = "https://localhost:$PortHttps/$Chemin/download/v$Version/deR4Tizer.msi"; Sha256 = $Sha256 }) }
    [IO.File]::WriteAllText((Join-Path $Www "$Chemin/latest/download/manifeste.json"), (ConvertTo-Json -InputObject $m -Depth 4), (New-Object Text.UTF8Encoding($false)))
}

# Entre les scénarios : manifeste de la version installée (« à jour »), pour que la vérification quotidienne du
# service (10 minutes après son démarrage) n'installe rien à l'improviste
function Publier-Neutre { Publier $Courante (Msi $Courante) (Msi $Courante) }

function Lignes-Requetes { if (Test-Path $Requetes) { @(Get-Content $Requetes) } else { @() } }

function Etat-Maj {
    $f = Join-Path $script:Donnees 'maj.json'
    if (-not (Test-Path $f)) { return $null }
    try { (Get-Content $f -Raw -Encoding UTF8).TrimStart([char]0xFEFF) | ConvertFrom-Json } catch { $null }
}

# Lance une vérification (majVerifier) et attend que maj.json soit réécrit ; renvoie l'état et les requêtes reçues
# par le serveur pendant la vérification
function Verification {
    # Date de modification du fichier (VerifieLe n'est précis qu'à la seconde)
    $f = Join-Path $script:Donnees 'maj.json'
    $avant = if (Test-Path $f) { (Get-Item $f).LastWriteTimeUtc } else { [datetime]::MinValue }
    $n = @(Lignes-Requetes).Count
    $r = Commande '{"Action":"majVerifier"}' | ConvertFrom-Json
    if (-not $r.Ok) { throw "majVerifier : $($r.Message)" }
    $fin = (Get-Date).AddSeconds(240)
    do { Start-Sleep 2 } while (-not ((Test-Path $f) -and (Get-Item $f).LastWriteTimeUtc -gt $avant) -and (Get-Date) -lt $fin)
    if (-not ((Test-Path $f) -and (Get-Item $f).LastWriteTimeUtc -gt $avant)) { throw 'maj.json non réécrit (vérification sans fin ?)' }
    Start-Sleep 1
    $e = Etat-Maj
    if (-not $e) { throw 'maj.json illisible' }
    [pscustomobject]@{ Etat = $e; Requetes = @(Lignes-Requetes | Select-Object -Skip $n) }
}

# Requêtes exigées (motifs de chemins, servies avec le code 200) et interdites
function Requetes-Attendues($V, [string[]]$Exigees, [string[]]$Interdites = @()) {
    foreach ($x in $Exigees) {
        if (-not @($V.Requetes | Where-Object { $_ -match "^$PortHttps GET /$([regex]::Escape($Chemin))/$([regex]::Escape($x)) 200$" }).Count) {
            return "requête attendue absente : $x (reçues : $($V.Requetes -join ' / '))"
        }
    }
    foreach ($x in $Interdites) {
        if (@($V.Requetes | Where-Object { $_ -match "GET /$([regex]::Escape($Chemin))/$([regex]::Escape($x)) " }).Count) { return "requête inattendue : $x" }
    }
    $true
}

# Rien d'installé : version courante seule dans « Applications », service de la version courante, aucun journal
# d'installation de la mise à jour
function Rien-Installe {
    $p = @(Produits)
    if ($p.Count -ne 1 -or -not $p[0].DisplayVersion.StartsWith($Courante)) { return "Applications : $(($p | ForEach-Object DisplayVersion) -join ', ')" }
    $j = Attendre-Canal 30
    if (-not $j -or $j.Message -ne "deR4Tizer $Courante") { return "service : $($j.Message)" }
    if (Test-Path (Join-Path $DonneesMaj 'installation.log')) { return 'un journal d''installation existe : une installation a eu lieu' }
    $true
}

# Remet la version courante si un scénario a laissé autre chose (installation lancée à tort) : attend la fin de
# msiexec et du script, puis installe le paquet courant. Les scénarios suivants partent ainsi du même état.
function Remettre-Courante {
    $fin = (Get-Date).AddSeconds(420)
    do { Start-Sleep 10 } while ((@(Get-Process msiexec -ErrorAction SilentlyContinue).Count -gt 1 -or
        @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match 'Lire-Reponse' }).Count) -and (Get-Date) -lt $fin)
    Garder-Journaux 'remise-en-etat'
    $p = @(Produits)
    $j = Attendre-Canal 30
    if ($p.Count -eq 1 -and $p[0].DisplayVersion.StartsWith($Courante) -and $j -and $j.Message -eq "deR4Tizer $Courante") { return }
    [void](Installer (Msi $Courante) (Join-Path $Journaux "remise-en-etat-$(Get-Date -Format HHmmss).log"))
    [void](Attendre-Canal)
}

# Refus attendu : statut contenant $Motif, requêtes exigées, rien d'installé. Une installation lancée à tort est
# un échec, et l'état est remis avant de continuer.
function Refus([string]$Motif, [string[]]$Exigees, [string[]]$Interdites = @()) {
    $v = Verification
    if ($v.Etat.Statut -match 'installation de la version .* en cours') {
        Publier-Neutre
        Remettre-Courante
        return "installation lancée au lieu d'un refus (statut : $($v.Etat.Statut)) ; version courante remise"
    }
    if ($v.Etat.Statut -notmatch [regex]::Escape($Motif)) { return "statut : $($v.Etat.Statut)" }
    $r = Requetes-Attendues $v $Exigees $Interdites; if ($r -ne $true) { return $r }
    Rien-Installe
}

# Installation lancée puis attendue : jusqu'à echec.txt (retour arrière) ou la réponse de la version $Attendue
function Installation-Lancee([string]$Paquet) {
    $v = Verification
    if ($v.Etat.Statut -notmatch "installation de la version $([regex]::Escape($Nouvelle)) en cours") { throw "statut : $($v.Etat.Statut)" }
    $r = Requetes-Attendues $v @('latest/download/manifeste.json', "download/v$Nouvelle/deR4Tizer.msi")
    if ($r -ne $true) { throw $r }
}

function Attendre-Retour([int]$Secondes = 420) {
    $f = Join-Path $DonneesMaj 'echec.txt'
    $fin = (Get-Date).AddSeconds($Secondes)
    while ((Get-Date) -lt $fin -and -not (Test-Path $f)) { Start-Sleep 5 }
    if (-not (Test-Path $f)) { return $null }
    Start-Sleep 5
    (Get-Content $f -Raw -Encoding UTF8).TrimStart([char]0xFEFF).Trim()
}

function Garder-Journaux([string]$Scenario) {
    foreach ($n in 'installation.log', 'retour.log') {
        $f = Join-Path $DonneesMaj $n
        if (Test-Path $f) { Move-Item $f (Join-Path $Journaux "$Scenario-$n") -Force }
    }
    # Diagnostic du script d'installation (lancé caché par le service) : journal du service, contenu des deux
    # dossiers maj, démarrages et erreurs de Windows PowerShell (400, 403, 4100), événements de msiexec
    $d = Join-Path $Journaux "$Scenario-diagnostic.txt"
    $depuis = (Get-Date).AddMinutes(-15)
    & {
        '== journal du service (mise à jour)'
        Get-Content (Join-Path $script:Donnees 'journal.txt') -Encoding UTF8 -ErrorAction SilentlyContinue | Select-String 'mise à jour|maj' | Select-Object -Last 15 | ForEach-Object { $_.Line }
        '== dossiers maj'
        Get-ChildItem $DonneesMaj, $Travail -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { "$($_.FullName) $($_.Length) $($_.LastWriteTime)" }
        '== Windows PowerShell 400/403'
        Get-WinEvent -FilterHashtable @{ LogName = 'Windows PowerShell'; Id = 400, 403; StartTime = $depuis } -ErrorAction SilentlyContinue |
            ForEach-Object { "$($_.TimeCreated) $($_.Id) " + (($_.Message -split "`n" | Select-String 'HostApplication') -join ' ').Substring(0, [Math]::Min(300, (($_.Message -split "`n" | Select-String 'HostApplication') -join ' ').Length)) }
        '== PowerShell/Operational 4100'
        Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4100; StartTime = $depuis } -ErrorAction SilentlyContinue |
            ForEach-Object { "$($_.TimeCreated) " + ($_.Message -replace "`r?`n", ' ') }
        '== MsiInstaller'
        Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; StartTime = $depuis } -ErrorAction SilentlyContinue |
            ForEach-Object { "$($_.TimeCreated) $($_.Id) " + ($_.Message -replace "`r?`n", ' ') }
    } | Set-Content -LiteralPath $d -Encoding UTF8
}

# ---------------------------------------------------------------- isolement de la clé de test
Verifier 'Clé de test : absente de l''exécutable du job windows, présente dans celui compilé pour ce test' {
    $ci = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($ArtefactCi))
    foreach ($k in $cle, $cleSeconde) { if ($ci.IndexOf($k, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return 'empreinte de test trouvée dans l''artefact du job windows' } }
    $test = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes((Join-Path $Executables "$Courante\deR4TizerSvc.exe")))
    if ($test.IndexOf($cle, [StringComparison]::OrdinalIgnoreCase) -lt 0) { return 'empreinte de test absente de l''exécutable de test (témoin)' }
    if ($test.IndexOf($cleSeconde, [StringComparison]::OrdinalIgnoreCase) -lt 0) { return 'seconde clé de test absente de l''exécutable de test (A-3-4)' }
    $true
}

# ---------------------------------------------------------------- racine de test et serveur local
Verifier 'Racine de test approuvée sur le runner, serveur local démarré (HTTPS et CRL)' {
    Import-Certificate -FilePath (Join-Path $Pki 'racine.crt') -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    New-Item -ItemType Directory -Force -Path $Www | Out-Null
    Copy-Item (Join-Path $Pki 'racine.crl') (Join-Path $Www 'racine.crl') -Force
    [IO.File]::WriteAllText((Join-Path $Www 'sonde.txt'), 'sonde')
    Remove-Item $Requetes -Force -ErrorAction SilentlyContinue
    $script:serveur = Start-Process python -PassThru -WindowStyle Hidden -ArgumentList @(
        "`"$PSScriptRoot\serveur-maj.py`"", "`"$Www`"", $PortHttps, $PortHttp, "`"$Pki\tls.crt`"", "`"$Pki\tls.key`"", "`"$Requetes`"")
    if (-not (Attendre-Port $PortHttps 30) -or -not (Attendre-Port $PortHttp 10)) { return 'serveur local muet' }
    $true
}
Verifier 'curl.exe (Schannel) accepte le serveur local en HTTPS, révocation vérifiée par la CRL locale' {
    # Le curl.exe de System32 : celui que le service trouve (CreateProcess cherche dans System32 avant le PATH)
    $s = & (Join-Path $env:SystemRoot 'System32\curl.exe') -sS --fail --proto '=https' "https://localhost:$PortHttps/sonde.txt" 2>&1 | Out-String
    if ($LASTEXITCODE -or $s.Trim() -ne 'sonde') { return "curl : $s" }
    if (-not @(Lignes-Requetes | Where-Object { $_ -match "^$PortHttp GET /racine.crl 200$" }).Count) { return "CRL jamais demandée (requêtes : $((Lignes-Requetes) -join ' / '))" }
    $true
}

# ---------------------------------------------------------------- script de publication exécuté (bloc 0.1, revue
# externe du 2026-11-21, défaut 2) : verifier-signatures.ps1 sur de vrais paquets signés, avec la clé épinglée dans
# les binaires de test (même empreinte que le service). Code 1 et message attendu à chaque refus, code 0 seulement
# pour un paquet signé par la clé épinglée, horodaté, dont la chaîne et la révocation se vérifient
$verifierSig = Join-Path $PSScriptRoot '..\..\verifier-signatures.ps1'
# Exécuté par PowerShell 7 (pwsh, celui du workflow) et par Windows PowerShell 5.1 : même code de sortie exigé des
# deux (audit de #233, S233-02)
$hotesSig = @('pwsh.exe', 'powershell.exe') | Where-Object { Get-Command $_ -ErrorAction SilentlyContinue }
# Un hôte absent est dit, jamais écarté en silence (audit de #233, S233-03)
foreach ($h in @('pwsh.exe', 'powershell.exe') | Where-Object { $_ -notin $hotesSig }) { NonExecute "Publication : script sous $h" "$h absent du runner" }
function Publication([string]$Cles, [string]$Fichier) {
    $r = foreach ($h in $hotesSig) {
        # Par -Command : une chaîne vide passée par -File arrive comme un argument manquant (prérelecture de #233, D1).
        # Chemins et clés sans apostrophe (clé : 64 caractères hexadécimaux ou vide)
        $s = & $h -NoProfile -ExecutionPolicy Bypass -Command "& '$verifierSig' -Cles '$Cles' -Fichiers '$Fichier'; exit `$LASTEXITCODE" 2>&1 | Out-String
        @{ Hote = $h; Code = $LASTEXITCODE; Sortie = $s }
    }
    $codes = @($r | ForEach-Object { $_.Code } | Select-Object -Unique)
    if ($codes.Count -ne 1) { return @{ Code = -1; Sortie = "codes différents selon l'hôte : $(($r | ForEach-Object { "$($_.Hote)=$($_.Code)" }) -join ', ') ; $($r[0].Sortie)" } }
    @{ Code = $codes[0]; Sortie = (($r | ForEach-Object { $_.Sortie }) -join "`n") }
}
function Refus-Publication([string]$Cles, [string]$Fichier, [string]$Motif) {
    $r = Publication $Cles $Fichier
    if ($r.Code -ne 1) { return "code $($r.Code) au lieu de 1 : $($r.Sortie)" }
    if ($r.Sortie -notmatch $Motif) { return "refus sans le motif attendu « $Motif » : $($r.Sortie)" }
    $true
}
Verifier 'Publication : liste de clés vide, refus (code 1)' { Refus-Publication '' (Msi $Nouvelle) 'CLE_SIGNATURE absente ou invalide' }
Verifier 'Publication : fichier non signé, refus (code 1)' { Refus-Publication $cle $ArtefactCi 'signature NotSigned' }
Verifier 'Publication : clé épinglée sans horodatage, refus (code 1)' { Refus-Publication $cle (Msi $Nouvelle) 'sans horodatage' }
# Copies horodatées : seule la signature change (même certificat), l'horodatage vient d'une autorité publique
$horodates = Join-Path $env:RUNNER_TEMP 'd4t-horodates'
New-Item -ItemType Directory -Force -Path $horodates | Out-Null
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" | Sort-Object FullName -Descending | Select-Object -First 1
$mdpPki = (Get-Content (Join-Path $Pki 'mot-de-passe.txt') -Raw).Trim()
function Horodate([string]$Nom, [string]$Certificat) {
    $f = Join-Path $horodates "$Nom.msi"
    Copy-Item (Msi $Nom) $f -Force
    $ac = if ($Certificat -eq 'sanscrl') { @('/ac', (Join-Path $Pki 'muette.crt')) } else { @() }
    foreach ($essai in 1..3) {
        $null = & $signtool.FullName sign /f (Join-Path $Pki "$Certificat.pfx") /p $mdpPki /fd SHA256 @ac /tr http://timestamp.digicert.com /td SHA256 /d deR4Tizer $f 2>&1
        if (-not $LASTEXITCODE -and (Get-AuthenticodeSignature $f).TimeStamperCertificate) { return $f }
        Start-Sleep 5
    }
    $null
}
$horoEpinglee = Horodate $Nouvelle 'epinglee'
$horoRevoquee = Horodate "$Nouvelle-revoquee" 'revoquee'
$horoSansCrl = Horodate "$Nouvelle-sanscrl" 'sanscrl'
# Copie horodatée aussi pour la clé non épinglée : sans horodatage, le refus « sans horodatage » viendrait avant la
# comparaison de la clé (prérelecture de #233, D1)
$horoAutre = Horodate "$Nouvelle-autre" 'autre'
if (-not ($horoEpinglee -and $horoRevoquee -and $horoSansCrl -and $horoAutre)) {
    NonExecute 'Publication : paquets horodatés (clé non épinglée, révoqué, CRL muette, accepté)' 'autorité d''horodatage publique injoignable depuis le runner'
} else {
    Verifier 'Publication : clé non épinglée, horodatée, refus (code 1)' { Refus-Publication $cle $horoAutre 'non épinglée' }
    # La révocation est vue dès le contrôle Authenticode (statut non Valid) ou, à défaut, par la chaîne : les deux
    # motifs sont des refus justes (prérelecture de #233, D1)
    Verifier 'Publication : certificat révoqué, horodaté, refus (code 1)' { Refus-Publication $cle $horoRevoquee '(?i)revoked|r[ée]voqu|chaîne ou révocation non vérifiée' }
    Verifier 'Publication : CRL injoignable, horodaté, refus (échec fermé, code 1)' { Refus-Publication $cle $horoSansCrl 'chaîne ou révocation non vérifiée' }
    Verifier 'Publication : clé épinglée, horodaté, chaîne et révocation vérifiées, accepté (code 0) sans nom de titulaire' {
        $r = Publication $cle $horoEpinglee
        if ($r.Code -ne 0) { return "code $($r.Code) : $($r.Sortie)" }
        if ($r.Sortie -notmatch "clé épinglée $cle") { return "empreinte absente du journal : $($r.Sortie)" }
        # Le sujet du certificat ne doit jamais être écrit (journal public)
        $sujet = (Get-AuthenticodeSignature $horoEpinglee).SignerCertificate.GetNameInfo('SimpleName', $false)
        if ($sujet -and $r.Sortie.Contains($sujet)) { return 'le sujet du certificat est écrit dans le journal' }
        $true
    }
}
Remove-Item $horodates -Recurse -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------- certificat qui expire pendant le job (audit du
# 2026-11-23, A-3-4 ; question A-3-H1) : clé épinglée K, émis maintenant par la racine de test, valable 4 minutes. Deux
# copies du paquet $Nouvelle signées pendant sa validité : l'une horodatée par une autorité publique, l'autre sans
# horodatage (témoin). Les scénarios qui s'en servent attendent l'expiration.
$expires = Join-Path $env:RUNNER_TEMP 'd4t-expires'
New-Item -ItemType Directory -Force -Path $expires | Out-Null
$openssl = 'C:\Program Files\Git\mingw64\bin\openssl.exe'
if (-not (Test-Path $openssl)) { $openssl = (Get-Command openssl.exe -ErrorAction SilentlyContinue).Source }
function Openssl {
    # openssl écrit sur stderr même quand tout va bien : seul le code de retour fait foi
    $ErrorActionPreference = 'Continue'
    $null = & $openssl @args 2>&1
    if ($LASTEXITCODE) { throw "openssl $($args[0]) : code $LASTEXITCODE" }
}
$finExpire = $null; $expireHorodate = $null; $expireNu = $null
try {
    $p = (Resolve-Path $Pki).Path -replace '\\', '/'
    $debutUtc = (Get-Date).ToUniversalTime().AddMinutes(-2)
    $finUtc = (Get-Date).ToUniversalTime().AddMinutes(4)
    Openssl req -new -config "$p/openssl.cnf" -key "$p/k.key" -subj '/CN=deR4Tizer signature de test (expire pendant le job)' -out "$p/expire.csr"
    Openssl ca -batch -config "$p/openssl.cnf" -name ca_test -extensions ext_signature -notext -startdate ($debutUtc.ToString('yyMMddHHmmss') + 'Z') -enddate ($finUtc.ToString('yyMMddHHmmss') + 'Z') -in "$p/expire.csr" -out "$p/expire.crt"
    Openssl pkcs12 -export -inkey "$p/k.key" -in "$p/expire.crt" -certfile "$p/chaine-epinglee.pem" -out "$p/expire.pfx" -passout "pass:$mdpPki" -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256
    $finExpire = (New-Object Security.Cryptography.X509Certificates.X509Certificate2((Join-Path $Pki 'expire.crt'))).NotAfter.ToUniversalTime()
    $fNu = Join-Path $expires "$Nouvelle-expire-nu.msi"
    Copy-Item (Msi $Nouvelle) $fNu -Force
    $null = & $signtool.FullName sign /f (Join-Path $Pki 'expire.pfx') /p $mdpPki /fd SHA256 /d deR4Tizer $fNu 2>&1
    if (-not $LASTEXITCODE) { $expireNu = $fNu }
    $fHoro = Join-Path $expires "$Nouvelle-expire-horodate.msi"
    foreach ($essai in 1..3) {
        Copy-Item (Msi $Nouvelle) $fHoro -Force
        $null = & $signtool.FullName sign /f (Join-Path $Pki 'expire.pfx') /p $mdpPki /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /d deR4Tizer $fHoro 2>&1
        if (-not $LASTEXITCODE -and (Get-AuthenticodeSignature $fHoro).TimeStamperCertificate) { $expireHorodate = $fHoro; break }
        Start-Sleep 5
    }
} catch { "certificat expirant : $_" }
# Attend la fin de validité (marge de 30 s) ; faux si le certificat n'a pas pu être émis
function Attendre-Expiration {
    if (-not $finExpire) { return $false }
    while ((Get-Date).ToUniversalTime() -lt $finExpire.AddSeconds(30)) { Start-Sleep 5 }
    $true
}

# ---------------------------------------------------------------- version courante installée, adresse locale
Publier-Neutre
$debut = Get-Date
Verifier "Installation de la version $Courante (clé de test épinglée)" {
    $c = Installer (Msi $Courante) (Join-Path $Journaux 'installation-initiale.log')
    if ($c -ne 0) { return "msiexec a rendu $c" }
    $j = Attendre-Canal
    if (-not $j -or $j.Message -ne "deR4Tizer $Courante") { return "canal : $($j.Message)" }
    $true
}
Verifier 'majConfig : adresse du manifeste locale, installation automatique' {
    $valeur = @{ Auto = $true; Url = $UrlManifeste } | ConvertTo-Json -Compress
    $r = Commande (@{ Action = 'majConfig'; Valeur = $valeur } | ConvertTo-Json -Compress) | ConvertFrom-Json
    if (-not $r.Ok) { return "refusé : $($r.Message)" }
    $c = (Get-Content (Join-Path $script:Donnees 'config.json') -Raw -Encoding UTF8).TrimStart([char]0xFEFF) | ConvertFrom-Json
    if ($c.Maj.Url -ne $UrlManifeste -or -not $c.Maj.Auto) { return "config.json : $($c.Maj | ConvertTo-Json -Compress)" }
    $true
}
Verifier 'Témoin : manifeste de la version installée, « à jour », clé épinglée signalée' {
    $v = Verification
    if ($v.Etat.Statut -ne 'à jour') { return "statut : $($v.Etat.Statut)" }
    # Code de la page Santé : rien à signaler (A-3-2, T-12)
    if ($v.Etat.Controle -ne '') { return "code de contrôle : « $($v.Etat.Controle) » au lieu de vide" }
    if (-not $v.Etat.CleEpinglee) { return 'clé épinglée non signalée' }
    Requetes-Attendues $v @('latest/download/manifeste.json') @("download/v$Courante/deR4Tizer.msi")
}

# ---------------------------------------------------------------- paquet de retour arrière refusé
# D'abord : le paquet de retour est gardé en cache dès qu'il est valide (Program Files\deR4Tizer\maj\<courante>)
Publier $Nouvelle (Msi $Nouvelle) (Msi "$Courante-autre")
Verifier 'Paquet de retour signé par une clé non épinglée : mise à jour refusée, rien installé' {
    Refus 'paquet de la version installée refusé : signé par une autre clé que celles de deR4Tizer ; pas d''installation sans retour arrière possible' @('latest/download/manifeste.json', "download/v$Courante/deR4Tizer.msi") @("download/v$Nouvelle/deR4Tizer.msi")
}
Publier $Nouvelle (Msi $Nouvelle) (Msi $Precedente)
Verifier "Paquet de retour en version $Precedente à la place de $Courante : mise à jour refusée, rien installé" {
    Refus "différente de celle attendue ($Courante) ; pas d'installation sans retour arrière possible" @('latest/download/manifeste.json', "download/v$Courante/deR4Tizer.msi") @("download/v$Nouvelle/deR4Tizer.msi")
}
Publier-Neutre

# ---------------------------------------------------------------- refus du nouveau paquet
$falsifiee = '4.99'
Publier $falsifiee (Msi $Nouvelle) (Msi $Courante)
Verifier "Manifeste falsifié (version $falsifiee pour le paquet signé $Nouvelle) : refusé, rien installé" {
    Refus "différente de celle attendue ($falsifiee)" @('latest/download/manifeste.json', "download/v$Courante/deR4Tizer.msi", "download/v$falsifiee/deR4Tizer.msi")
}
Verifier 'Dossier de travail Program Files\deR4Tizer\maj : à SYSTEM seul, droits protégés, aucune entrée TrustedInstaller (contrôle en SYSTEM)' {
    if (-not (Test-Path $Travail)) { return 'dossier absent' }
    Controle-Systeme $Travail
}
Publier $Nouvelle (Msi $Nouvelle) (Msi $Courante) ((Sha256 (Msi $Courante)).ToLower())
Verifier 'Empreinte fausse dans le manifeste : refusée, rien installé' {
    Refus 'empreinte du paquet différente de celle du manifeste' @('latest/download/manifeste.json', "download/v$Nouvelle/deR4Tizer.msi")
}
Publier $Nouvelle (Msi "$Nouvelle-autre") (Msi $Courante)
Verifier 'Paquet signé par une clé non épinglée : refusé, rien installé' {
    Refus 'signé par une autre clé que celles de deR4Tizer' @('latest/download/manifeste.json', "download/v$Nouvelle/deR4Tizer.msi")
}
Publier $Nouvelle (Msi "$Nouvelle-revoquee") (Msi $Courante)
Verifier 'Certificat révoqué dans la CRL (même clé épinglée) : refusé, rien installé' {
    Refus 'signature absente, invalide ou révoquée' @('latest/download/manifeste.json', "download/v$Nouvelle/deR4Tizer.msi")
}
Publier $Nouvelle (Msi "$Nouvelle-sanscrl") (Msi $Courante)
Verifier 'Certificat dont la CRL ne répond pas (même clé épinglée) : refusé (échec fermé), rien installé' {
    Refus 'signature absente, invalide ou révoquée' @('latest/download/manifeste.json', "download/v$Nouvelle/deR4Tizer.msi")
}

# ---------------------------------------------------------------- audit du 2026-11-23, A-3-4
# Manifeste plus ancien que la version installée (A-3-2) : statut distinct, code « ManifesteAncien » pour la page Santé,
# aucun paquet demandé, rien installé
Publier $Precedente (Msi $Precedente) (Msi $Courante)
Verifier "Manifeste plus ancien ($Precedente sous $Courante) : statut « manifeste plus ancien », code ManifesteAncien, rien demandé ni installé" {
    $v = Verification
    if ($v.Etat.Statut -notmatch [regex]::Escape("manifeste plus ancien que la version installée (manifeste $Precedente, installée $Courante)")) { return "statut : $($v.Etat.Statut)" }
    if ($v.Etat.Controle -ne 'ManifesteAncien') { return "code de contrôle : $($v.Etat.Controle)" }
    if ($v.Etat.VersionDisponible -ne $Precedente) { return "version disponible : $($v.Etat.VersionDisponible)" }
    $r = Requetes-Attendues $v @('latest/download/manifeste.json') @("download/v$Precedente/deR4Tizer.msi", "download/v$Courante/deR4Tizer.msi")
    if ($r -ne $true) { return $r }
    Rien-Installe
}
# Seconde clé épinglée (passage de clé) : manifeste qui annonce $falsifiee pour le paquet $Nouvelle signé par la clé K3.
# Les propriétés du paquet ne sont lues qu'après une signature acceptée : le refus « version différente » prouve que la
# clé K3 est acceptée (témoin : la clé non épinglée K2 est refusée plus haut, « signé par une autre clé »)
Publier $falsifiee (Msi "$Nouvelle-seconde") (Msi $Courante)
Verifier "Paquet signé par la seconde clé épinglée : signature acceptée (refus suivant : version $falsifiee attendue), rien installé" {
    Refus "différente de celle attendue ($falsifiee)" @('latest/download/manifeste.json', "download/v$falsifiee/deR4Tizer.msi")
}
# Certificat expiré : même preuve par la version annoncée $falsifiee. Horodaté pendant sa validité : signature acceptée ;
# sans horodatage : refusée (témoin : le certificat est bien expiré au moment du contrôle)
if (-not $expireNu -or -not (Attendre-Expiration)) {
    NonExecute 'Certificat expiré, sans horodatage : refusé (témoin)' 'certificat expirant non émis ou paquet non signé dans le job'
} else {
    Publier $falsifiee $expireNu (Msi $Courante)
    Verifier 'Certificat expiré, sans horodatage : signature refusée (témoin), rien installé' {
        Refus 'signature absente, invalide ou révoquée' @('latest/download/manifeste.json', "download/v$falsifiee/deR4Tizer.msi")
    }
}
if (-not $expireHorodate -or -not (Attendre-Expiration)) {
    NonExecute 'Certificat expiré, horodaté pendant sa validité : accepté' 'autorité d''horodatage publique injoignable depuis le runner, ou certificat expirant non émis'
} else {
    Publier $falsifiee $expireHorodate (Msi $Courante)
    Verifier "Certificat expiré, horodaté pendant sa validité : signature acceptée (refus suivant : version $falsifiee attendue), rien installé" {
        Refus "différente de celle attendue ($falsifiee)" @('latest/download/manifeste.json', "download/v$falsifiee/deR4Tizer.msi")
    }
}
Remove-Item $expires -Recurse -Force -ErrorAction SilentlyContinue
Publier-Neutre

# ---------------------------------------------------------------- installations avec retour arrière
foreach ($cas in @(
    @{ Nom = 'casse'; Titre = "Paquet cassé (exécutable du service invalide) : retour à $Courante, une seule entrée « Applications »" },
    @{ Nom = 'ancien'; Titre = "Service qui répond mal ($Nouvelle contenant l'exécutable $Courante) : retour à $Courante (version plus ancienne), une seule entrée « Applications »" })) {
    Remettre-Courante
    Publier $Nouvelle (Msi "$Nouvelle-$($cas.Nom)") (Msi $Courante)
    Verifier $cas.Titre {
        Installation-Lancee
        $e = Attendre-Retour
        Publier-Neutre
        Garder-Journaux $cas.Nom
        if (-not $e) { return 'echec.txt jamais écrit' }
        if ($e -notmatch "paquet de la version $([regex]::Escape($Courante)) réinstallé") { return "echec.txt : $e" }
        $j = Attendre-Canal 120
        if (-not $j -or $j.Message -ne "deR4Tizer $Courante") { return "service après retour : $($j.Message)" }
        $p = @(Produits)
        if ($p.Count -ne 1 -or -not $p[0].DisplayVersion.StartsWith($Courante)) { return "Applications : $(($p | ForEach-Object DisplayVersion) -join ', ')" }
        $true
    }
}
NonExecute 'Service muet après l''installation (tube absent ou tenu par un autre processus)' 'couvert seulement par le mode simulation de script_installation (tests unitaires) ; essai réel prévu avec A-8-2, hors du lot 6 de l''audit du 2026-11-23'

# ---------------------------------------------------------------- mise à jour réussie
Remettre-Courante
Publier $Nouvelle (Msi $Nouvelle) (Msi $Courante)
# Témoin positif du contrôle de révocation : CRL qui répond, racine sans adresse de CRL (comme les vraies) ;
# le correctif ne refuse pas tout
Verifier "Mise à jour $Courante → $Nouvelle réussie (CRL qui répond, racine sans CRL) : service de la nouvelle version, une seule entrée, aucun retour arrière" {
    Installation-Lancee
    $fin = (Get-Date).AddSeconds(300)
    do {
        Start-Sleep 5
        $j = try { Commande '{"Action":"verification"}' 3000 | ConvertFrom-Json } catch { $null }
    } while ((-not $j -or $j.Message -ne "deR4Tizer $Nouvelle") -and (Get-Date) -lt $fin)
    if (-not $j -or $j.Message -ne "deR4Tizer $Nouvelle") { return "le service ne répond pas en $Nouvelle ($($j.Message))" }
    # Laisser au script le temps de conclure : il ne doit pas revenir en arrière
    Start-Sleep 90
    Garder-Journaux 'reussite'
    if (Test-Path (Join-Path $DonneesMaj 'echec.txt')) { return "echec.txt : $(Get-Content (Join-Path $DonneesMaj 'echec.txt') -Raw)" }
    $p = @(Produits)
    if ($p.Count -ne 1 -or -not $p[0].DisplayVersion.StartsWith($Nouvelle)) { return "Applications : $(($p | ForEach-Object DisplayVersion) -join ', ')" }
    $j = Attendre-Canal 30
    if (-not $j -or $j.Message -ne "deR4Tizer $Nouvelle") { return "service : $($j.Message)" }
    $true
}
Publier $Nouvelle (Msi $Nouvelle) (Msi $Courante)

# ---------------------------------------------------------------- droits après les scénarios
Verifier 'Dossier de travail après la mise à jour : à SYSTEM seul (contrôle en SYSTEM)' {
    if (-not (Test-Path $Travail)) { return 'dossier absent' }
    Controle-Systeme $Travail
}
Verifier 'Droits de chaque élément (données, Program Files hors maj, contrôlé en SYSTEM)' {
    Controle-Droits @($script:Donnees, $script:Programme) @() $Toleres @($Travail)
}

if ($serveur) { Stop-Process -Id $serveur.Id -Force -ErrorAction SilentlyContinue }
Copy-Item $Requetes (Join-Path $Journaux 'requetes-serveur.log') -ErrorAction SilentlyContinue
Bilan 'Lot 3c : mise à jour automatique (PKI de test, serveur local)'
