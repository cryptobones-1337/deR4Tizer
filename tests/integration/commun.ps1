# Fonctions communes des tests d'intégration (lot 3). Prévu pour un runner Windows jetable, en administrateur :
# ces scripts installent et désinstallent deR4Tizer, créent un compte local et posent des pièges. Ne jamais les
# lancer sur un poste réel.
#
# Chaque scénario finit dans un tableau : RÉUSSI, ÉCHOUÉ ou NON EXÉCUTÉ (avec la raison). Un scénario qui n'a
# pas pu tourner n'est jamais compté comme réussi ; un seul ÉCHOUÉ fait échouer le job.

$ErrorActionPreference = 'Stop'
$script:Resultats = New-Object System.Collections.Generic.List[object]
$script:Donnees = Join-Path $env:ProgramData 'deR4Tizer'
$script:Programme = Join-Path $env:ProgramFiles 'deR4Tizer'
$script:Commun = 'C:\d4t-commun'

function Noter([string]$Scenario, [string]$Resultat, [string]$Detail) {
    $script:Resultats.Add([pscustomobject]@{ Scenario = $Scenario; Resultat = $Resultat; Detail = $Detail })
    Write-Host ("[{0}] {1}{2}" -f $Resultat, $Scenario, $(if ($Detail) { " : $Detail" } else { '' }))
}

# Le test renvoie $true, ou une chaîne qui dit ce qui ne va pas
function Verifier([string]$Scenario, [scriptblock]$Test) {
    try {
        $r = @(& $Test) | Select-Object -Last 1
        if ($r -eq $true) { Noter $Scenario 'RÉUSSI' '' } else { Noter $Scenario 'ÉCHOUÉ' ([string]$r) }
    } catch {
        Noter $Scenario 'ÉCHOUÉ' ('exception : ' + $_.Exception.Message)
    }
}

function NonExecute([string]$Scenario, [string]$Raison) { Noter $Scenario 'NON EXÉCUTÉ' $Raison }

function Bilan([string]$Titre) {
    $table = $script:Resultats | Format-Table -AutoSize -Wrap | Out-String -Width 250
    Write-Host $table
    if ($env:GITHUB_STEP_SUMMARY) {
        $l = @("## $Titre", '', '| Scénario | Résultat | Détail |', '|---|---|---|')
        foreach ($r in $script:Resultats) { $l += "| $($r.Scenario) | $($r.Resultat) | $(($r.Detail -replace '\|', '/') -replace "`r?`n", ' ') |" }
        [IO.File]::AppendAllText($env:GITHUB_STEP_SUMMARY, ($l -join "`n") + "`n", (New-Object Text.UTF8Encoding($false)))
    }
    $echecs = @($script:Resultats | Where-Object Resultat -eq 'ÉCHOUÉ').Count
    $non = @($script:Resultats | Where-Object Resultat -eq 'NON EXÉCUTÉ').Count
    Write-Host "Bilan : $(@($script:Resultats).Count) scénarios, $echecs échoué(s), $non non exécuté(s)"
    if ($echecs) { exit 1 }
}

# ---------------------------------------------------------------- service et canal

# Requête sur le canal du service, en administrateur ; renvoie la ligne de réponse
function Commande([string]$Json, [int]$Delai = 5000) {
    $c = New-Object IO.Pipes.NamedPipeClientStream('.', 'deR4Tizer', [IO.Pipes.PipeDirection]::InOut)
    try {
        $c.Connect($Delai)
        $w = New-Object IO.StreamWriter($c); $w.AutoFlush = $true
        $r = New-Object IO.StreamReader($c)
        $w.WriteLine($Json)
        return $r.ReadLine()
    } finally { $c.Dispose() }
}

# Attend que le service réponde à « verification » ; renvoie la réponse (objet) ou $null
function Attendre-Canal([int]$Secondes = 120) {
    $fin = (Get-Date).AddSeconds($Secondes)
    while ((Get-Date) -lt $fin) {
        try {
            $j = Commande '{"Action":"verification"}' 3000 | ConvertFrom-Json
            if ($j.Ok) { return $j }
        } catch { }
        Start-Sleep 2
    }
    return $null
}

# Dernières lignes du journal du service qui contiennent un motif (diagnostic des échecs)
function Journal([string]$Motif, [int]$Nombre = 6) {
    $f = Join-Path $script:Donnees 'journal.txt'
    if (-not (Test-Path $f)) { return '(pas de journal)' }
    (@(Get-Content $f -Encoding UTF8 -Tail 400 | Where-Object { $_ -match $Motif }) | Select-Object -Last $Nombre) -join ' || '
}

function Etat {
    $f = Join-Path $script:Donnees 'etat.json'
    if (-not (Test-Path $f)) { return $null }
    try { Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $null }
}

# Attend un etat.json écrit après $Depuis (le service l'écrit au moins toutes les 30 s)
function Attendre-Etat([datetime]$Depuis, [int]$Secondes = 90) {
    $f = Join-Path $script:Donnees 'etat.json'
    $fin = (Get-Date).AddSeconds($Secondes)
    while ((Get-Date) -lt $fin) {
        if ((Test-Path $f) -and (Get-Item $f).LastWriteTime -gt $Depuis) { $e = Etat; if ($e) { return $e } }
        Start-Sleep 2
    }
    return $null
}

function Installer([string]$Msi, [string]$Journal, [string[]]$Proprietes = @()) {
    $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList (@('/i', "`"$Msi`"", '/qn', '/norestart', '/l*v', "`"$Journal`"") + $Proprietes)
    return $p.ExitCode
}

# Code produit de la version installée (Programmes et fonctionnalités)
function Produits {
    @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq 'deR4Tizer' })
}

function Desinstaller([string]$Journal, [string[]]$Proprietes = @()) {
    $p = Produits | Select-Object -First 1
    if (-not $p) { return -1 }
    $r = Start-Process msiexec.exe -Wait -PassThru -ArgumentList (@('/x', $p.PSChildName, '/qn', '/norestart', '/l*v', "`"$Journal`"") + $Proprietes)
    return $r.ExitCode
}

# Droits relus en SID (sans traduction de noms) : propriétaire, héritage coupé, entrées (SID, droits,
# autorisation, entrée « héritage seulement », qui ne s'applique pas à l'élément lui-même)
function Droits([string]$Chemin) {
    $acl = Get-Acl -LiteralPath $Chemin
    $T = [Security.Principal.SecurityIdentifier]
    [pscustomobject]@{
        Proprietaire = $acl.GetOwner($T).Value
        Protege = $acl.AreAccessRulesProtected
        Entrees = @($acl.GetAccessRules($true, $true, $T) | ForEach-Object {
            [pscustomobject]@{
                Sid = $_.IdentityReference.Value; Droits = $_.FileSystemRights; Autorise = ($_.AccessControlType -eq 'Allow')
                HeritageSeul = (($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)
            }
        })
    }
}

# Droit d'écriture au sens large (mêmes bits que DROITS_ECRITURE de protection.rs) : données, ajout, attributs
# étendus, suppression d'enfants, attributs, DELETE, WRITE_DAC, WRITE_OWNER, MAXIMUM_ALLOWED, GENERIC_ALL, GENERIC_WRITE
function Ecriture($Droits) { ([int]$Droits -band 0x000D0156) -ne 0 -or ([int]$Droits -band 0x52000000) -ne 0 }

$script:SidsConfiance = 'S-1-5-18', 'S-1-5-32-544'
$script:SidTrustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'

# Éléments d'un dossier, récursivement, sans suivre les liens. Le contenu de « ecartes » (fichiers mis de côté,
# qui gardent leur propriétaire d'origine et ne sont jamais lus) est compté à part dans $Ecartes.
function Elements([string]$Racine, $Ecartes) {
    $pile = New-Object System.Collections.Generic.Stack[string]
    $pile.Push($Racine)
    $liste = New-Object System.Collections.Generic.List[object]
    $liste.Add((Get-Item -LiteralPath $Racine -Force))
    while ($pile.Count) {
        $d = $pile.Pop()
        foreach ($e in @(Get-ChildItem -LiteralPath $d -Force)) {
            $liste.Add($e)
            if ($e.PSIsContainer -and -not ($e.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                if ($e.Name -like 'ecartes*' -and $d -eq $script:Donnees) {
                    if ($Ecartes -is [ref]) { $Ecartes.Value += @(Get-ChildItem -LiteralPath $e.FullName -Force -Recurse).Count }
                } else { $pile.Push($e.FullName) }
            }
        }
    }
    $liste
}

# Contrôle récursif : chaque élément de chaque racine a pour propriétaire SYSTEM ou Administrateurs, et aucune
# entrée d'autorisation qui s'applique à lui ne donne un droit d'écriture à un autre SID. $Attendus : chemins
# relatifs dont l'écart est attendu (fichier tenu ouvert en échec fermé), signalés à part. $Toleres : SID
# admis en plus, par racine (TrustedInstaller sur Program Files). Renvoie $true ou la liste des écarts.
function Controle-Droits([string[]]$Racines, [string[]]$Attendus = @(), [hashtable]$Toleres = @{}) {
    $ecarts = New-Object System.Collections.Generic.List[string]
    $n = 0
    foreach ($r in $Racines) {
        if (-not (Test-Path -LiteralPath $r)) { $ecarts.Add("$r absent"); continue }
        $ec = 0
        foreach ($e in (Elements $r ([ref]$ec))) {
            $rel = $e.FullName.Substring($r.Length).TrimStart('\')
            if ($rel -in $Attendus) { continue }
            $n++
            $admis = $script:SidsConfiance + @($Toleres[$r])
            try { $d = Droits $e.FullName } catch { $ecarts.Add("$($e.FullName) : droits illisibles"); continue }
            if ($d.Proprietaire -notin $script:SidsConfiance) { $ecarts.Add("$($e.FullName) : propriétaire $($d.Proprietaire)") }
            foreach ($a in $d.Entrees) {
                if ($a.Autorise -and -not $a.HeritageSeul -and $a.Sid -notin $admis -and (Ecriture $a.Droits)) {
                    $ecarts.Add("$($e.FullName) : écriture pour $($a.Sid) ($($a.Droits))")
                }
            }
        }
    }
    if ($ecarts.Count) { return "$($ecarts.Count) écart(s) sur $n élément(s) : " + (($ecarts | Select-Object -First 8) -join ' ; ') }
    $true
}

# Attend qu'un port TCP soit en écoute (témoin positif) ; $false au bout du délai
function Attendre-Port([int]$Port, [int]$Secondes = 60) {
    $fin = (Get-Date).AddSeconds($Secondes)
    while ((Get-Date) -lt $fin) {
        if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) { return $true }
        Start-Sleep 2
    }
    $false
}

function Port-Ouvert([int]$Port) { [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) }

# Écrit un fichier du dossier de données en administrateur (ASCII, sans BOM), propriétaire Administrateurs
function Poser-EnAdministrateur([string]$Nom, [string]$Contenu) {
    $f = Join-Path $script:Donnees $Nom
    [IO.File]::WriteAllText($f, $Contenu, (New-Object Text.ASCIIEncoding))
    icacls $f /setowner '*S-1-5-32-544' /Q | Out-Null
    $o = (Droits $f).Proprietaire
    if ($o -ne 'S-1-5-32-544') { throw "propriétaire de $Nom : $o" }
}

function Redemarrer-Service {
    $d = Get-Date
    Restart-Service deR4Tizer -Force
    if (-not (Attendre-Canal)) { throw 'le service ne répond plus après le redémarrage' }
    $d
}

# Élément mis de côté dans « ecartes » (nom d'origine en suffixe)
function Ecarte([string]$Nom) {
    $q = Join-Path $script:Donnees 'ecartes'
    if (-not (Test-Path $q)) { return @() }
    @(Get-ChildItem -LiteralPath $q -Force | Where-Object { $_.Name -like "*-$Nom" })
}

# ---------------------------------------------------------------- compte standard

# Compte local standard (membre d'Utilisateurs seulement), mot de passe aléatoire jamais affiché
function Nouveau-CompteStandard([string]$Nom = 'd4t_standard') {
    $o = New-Object byte[] 24
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($o)
    $s = ConvertTo-SecureString ([Convert]::ToBase64String($o) + 'aA1!') -AsPlainText -Force
    New-LocalUser -Name $Nom -Password $s -PasswordNeverExpires -AccountNeverExpires -Description 'deR4Tizer : tests d''intégration' | Out-Null
    New-Item -ItemType Directory -Force -Path $script:Commun | Out-Null
    icacls $script:Commun /grant "${Nom}:(OI)(CI)M" | Out-Null
    [pscustomobject]@{ Nom = $Nom; Sid = (Get-LocalUser $Nom).SID.Value; Credential = New-Object Management.Automation.PSCredential($Nom, $s) }
}

# Exécute du PowerShell sous l'identité du compte standard ; renvoie sa sortie (texte), ou le processus si
# -SansAttendre. Le code est écrit dans un fichier (UTF-8 avec BOM), jamais sur la ligne de commande.
$script:NumeroScript = 0
function En-TantQue($Compte, [string]$Code, [switch]$SansAttendre, [int]$Secondes = 60) {
    $script:NumeroScript++
    $f = Join-Path $script:Commun "script-$($script:NumeroScript).ps1"
    $sortie = Join-Path $script:Commun "sortie-$($script:NumeroScript).txt"
    $corps = "`$ErrorActionPreference = 'Continue'`r`n& {`r`n$Code`r`n} *>&1 | Out-File -LiteralPath '$sortie' -Encoding utf8 -Width 4096"
    [IO.File]::WriteAllText($f, $corps, (New-Object Text.UTF8Encoding($true)))
    $p = Start-Process powershell.exe -Credential $Compte.Credential -PassThru -WindowStyle Hidden -WorkingDirectory $script:Commun `
        -ArgumentList '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', "`"$f`""
    if ($SansAttendre) { return $p }
    if (-not $p.WaitForExit($Secondes * 1000)) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; throw "délai dépassé ($Secondes s)" }
    if (Test-Path $sortie) { return (Get-Content -LiteralPath $sortie -Raw -Encoding UTF8) }
    return ''
}

# Ce que le compte standard peut faire sur le canal, dans chaque dossier réellement présent (créer un fichier,
# créer un sous-dossier) et sur chaque fichier présent (ouvrir en écriture), données et Program Files\deR4Tizer.
# Seule une UnauthorizedAccessException vaut refus : un délai dépassé, un service arrêté ou un chemin absent ne
# prouvent rien. Renvoie $true ou la liste de ce qui n'a pas été refusé. $Exclus : chemins complets écartés
# de l'essai (fichier tenu ouvert en échec fermé, attendu).
function Essais-Standard($Compte, [string[]]$Exclus = @()) {
    $cibles = New-Object System.Collections.Generic.List[string]
    foreach ($r in $script:Donnees, $script:Programme) {
        if (-not (Test-Path $r)) { return "cible absente : $r" }
        foreach ($e in (Elements $r $null)) {
            if ($e.FullName -in $Exclus) { continue }
            $cibles.Add($(if ($e.PSIsContainer) { 'D|' } else { 'F|' }) + $e.FullName)
        }
    }
    $script:NumeroScript++
    $liste = Join-Path $script:Commun "cibles-$($script:NumeroScript).txt"
    [IO.File]::WriteAllLines($liste, $cibles, (New-Object Text.UTF8Encoding($true)))
    $s = En-TantQue $Compte @"
function Type(`$err) { `$x = `$err.Exception; while (`$x.InnerException) { `$x = `$x.InnerException }; `$x.GetType().Name }
try { `$c = New-Object IO.Pipes.NamedPipeClientStream('.', 'deR4Tizer', [IO.Pipes.PipeDirection]::InOut); `$c.Connect(5000)
      `$w = New-Object IO.StreamWriter(`$c); `$w.AutoFlush = `$true; `$r = New-Object IO.StreamReader(`$c)
      `$w.WriteLine('{"Action":"toutDebloquer"}'); 'TUBE|canal|REPONSE ' + `$r.ReadLine() } catch { 'TUBE|canal|' + (Type `$_) }
`$n = [guid]::NewGuid().ToString('N')
foreach (`$l in [IO.File]::ReadAllLines('$liste')) {
    `$t, `$p = `$l -split '\|', 2
    if (`$t -eq 'D') {
        try { `$h = [IO.File]::Open((Join-Path `$p "piege-`$n.txt"), 'CreateNew', 'Write'); `$h.Dispose(); "CREERFICHIER|`$p|ECRIT" } catch { "CREERFICHIER|`$p|" + (Type `$_) }
        try { [void][IO.Directory]::CreateDirectory((Join-Path `$p "piege-`$n")); "CREERDOSSIER|`$p|CREE" } catch { "CREERDOSSIER|`$p|" + (Type `$_) }
    } else {
        try { `$h = [IO.File]::Open(`$p, 'Open', 'Write', 'ReadWrite, Delete'); `$h.Dispose(); "ECRIRE|`$p|OUVERT" } catch { "ECRIRE|`$p|" + (Type `$_) }
    }
}
'FIN'
"@ -Secondes 300
    $lignes = @($s -split "`r?`n" | Where-Object { $_ -match '\|' })
    if ($s -notmatch '(?m)^FIN') { return "essais interrompus : $($s -replace "`r?`n", ' ')" }
    $attendu = 1 + @($cibles | Where-Object { $_ -like 'D|*' }).Count * 2 + @($cibles | Where-Object { $_ -like 'F|*' }).Count
    if ($lignes.Count -ne $attendu) { return "$($lignes.Count) résultats pour $attendu essais" }
    $mauvais = @($lignes | Where-Object { ($_ -split '\|')[-1] -ne 'UnauthorizedAccessException' })
    if ($mauvais.Count) { return "$($mauvais.Count) essai(s) non refusé(s) sur $attendu : " + (($mauvais | Select-Object -First 8) -join ' ; ') }
    $true
}
