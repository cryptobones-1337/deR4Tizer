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
        Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value ($l -join "`n") -Encoding UTF8
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

# Droits relus : propriétaire (SID), héritage coupé, entrées (SID, droits, autorisation)
function Droits([string]$Chemin) {
    $acl = Get-Acl -LiteralPath $Chemin
    $sid = { param($n) try { (New-Object Security.Principal.NTAccount($n)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { $n } }
    [pscustomobject]@{
        Proprietaire = & $sid $acl.Owner
        Protege = $acl.AreAccessRulesProtected
        Entrees = @($acl.Access | ForEach-Object {
            [pscustomobject]@{ Sid = & $sid $_.IdentityReference.Value; Droits = $_.FileSystemRights; Autorise = ($_.AccessControlType -eq 'Allow') }
        })
    }
}

# Droit d'écriture (au sens large) dans des FileSystemRights
function Ecriture($Droits) { ([int]$Droits -band 0x000D0156) -ne 0 -or ([int]$Droits -band 0x50000000) -ne 0 }

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
    $corps = "`$ErrorActionPreference = 'Continue'`r`n& {`r`n$Code`r`n} *>&1 | Out-File -LiteralPath '$sortie' -Encoding utf8"
    [IO.File]::WriteAllText($f, $corps, (New-Object Text.UTF8Encoding($true)))
    $p = Start-Process powershell.exe -Credential $Compte.Credential -PassThru -WindowStyle Hidden -WorkingDirectory $script:Commun `
        -ArgumentList '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', "`"$f`""
    if ($SansAttendre) { return $p }
    if (-not $p.WaitForExit($Secondes * 1000)) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; throw "délai dépassé ($Secondes s)" }
    if (Test-Path $sortie) { return (Get-Content -LiteralPath $sortie -Raw -Encoding UTF8) }
    return ''
}

# Ce que le compte standard peut faire sur le canal et dans le dossier de données
function Essais-Standard($Compte) {
    En-TantQue $Compte @"
try { `$c = New-Object IO.Pipes.NamedPipeClientStream('.', 'deR4Tizer', [IO.Pipes.PipeDirection]::InOut); `$c.Connect(3000)
      `$w = New-Object IO.StreamWriter(`$c); `$w.AutoFlush = `$true; `$r = New-Object IO.StreamReader(`$c)
      `$w.WriteLine('{"Action":"toutDebloquer"}'); 'TUBE=REPONSE ' + `$r.ReadLine() } catch { 'TUBE=REFUSE ' + `$_.Exception.GetType().Name }
try { [IO.File]::WriteAllText('$script:Donnees\piege-ecriture.txt', 'x'); 'FICHIER=ECRIT' } catch { 'FICHIER=REFUSE' }
try { New-Item -ItemType Directory -Path '$script:Donnees\piege-dossier' -ErrorAction Stop | Out-Null; 'DOSSIER=CREE' } catch { 'DOSSIER=REFUSE' }
try { [IO.File]::WriteAllText('$script:Donnees\maj\piege.txt', 'x'); 'MAJ=ECRIT' } catch { 'MAJ=REFUSE' }
"@
}
