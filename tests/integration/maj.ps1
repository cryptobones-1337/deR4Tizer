# Lot 3c : mise à jour automatique avec le service réel, sur un runner jetable. PKI de test (maj-pki.ps1), paquets
# signés (maj-paquets.ps1), serveur local journalisé (serveur-maj.py) qui reproduit l'arborescence des versions
# GitHub. Scénarios : paquet de retour refusé (clé non épinglée, version précédente), manifeste falsifié, empreinte
# fausse, clé non épinglée, certificat révoqué, CRL injoignable, paquet cassé, service qui répond mal (retour à une
# version plus ancienne), mise à jour réussie. Dossier de travail Program Files\deR4Tizer\maj contrôlé en SYSTEM.
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
    if ($ci.IndexOf($cle, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return 'empreinte de test trouvée dans l''artefact du job windows' }
    $test = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes((Join-Path $Executables "$Courante\deR4TizerSvc.exe")))
    if ($test.IndexOf($cle, [StringComparison]::OrdinalIgnoreCase) -lt 0) { return 'empreinte de test absente de l''exécutable de test (témoin)' }
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
NonExecute 'Service muet après l''installation (tube absent ou tenu par un autre processus)' 'couvert seulement par le mode simulation de script_installation (tests unitaires)'

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
