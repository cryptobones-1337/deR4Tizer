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
    # Pas de @() autour de la liste générique : PowerShell 5.1 y lève « Argument types do not match »
    $tous = $script:Resultats.ToArray()
    $echecs = @($tous | Where-Object Resultat -eq 'ÉCHOUÉ').Count
    $non = @($tous | Where-Object Resultat -eq 'NON EXÉCUTÉ').Count
    Write-Host "Bilan : $($tous.Count) scénarios, $echecs échoué(s), $non non exécuté(s)"
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
        # Lecture bornée : un service qui accepte le tube mais reste bloqué sur son verrou ferait attendre sans fin (relecture de #104, D4)
        $t = $r.ReadLineAsync()
        if (-not $t.Wait([Math]::Max($Delai, 60000))) { throw 'canal : pas de réponse' }
        return $t.Result
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
# Code de retour de schtasks sans sortie : sous Windows PowerShell 5.1 en mode Stop, une redirection de sa sortie d'erreur lève
# une exception quand il échoue (tâche absente), avant que le code puisse être lu
function Schtasks-Code {
    $ancien = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { schtasks @args *> $null; $LASTEXITCODE } finally { $ErrorActionPreference = $ancien }
}

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
# qui gardent leur propriétaire d'origine et ne sont jamais lus) est compté à part dans $Ecartes. $EnSysteme :
# dossiers laissés de côté, ni listés ni parcourus, parce que l'appelant les contrôle en SYSTEM (dossier de
# travail de la mise à jour, réservé à SYSTEM). Un dossier illisible en administrateur n'est jamais ignoré en
# silence : il est ajouté à $script:Illisibles, que les contrôles comptent comme écart.
$script:Illisibles = New-Object System.Collections.Generic.List[string]
function Elements([string]$Racine, $Ecartes, [string[]]$EnSysteme = @()) {
    $pile = New-Object System.Collections.Generic.Stack[string]
    $pile.Push($Racine)
    $liste = New-Object System.Collections.Generic.List[object]
    $liste.Add((Get-Item -LiteralPath $Racine -Force))
    while ($pile.Count) {
        $d = $pile.Pop()
        try { $contenu = @(Get-ChildItem -LiteralPath $d -Force -ErrorAction Stop) } catch { $script:Illisibles.Add($d); continue }
        foreach ($e in $contenu) {
            if ($e.FullName -in $EnSysteme) { continue }
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

# Contrôle récursif : chaque élément de chaque racine a pour propriétaire SYSTEM ou Administrateurs, n'est pas
# un lien (jonction, lien symbolique), et aucune entrée d'autorisation ne donne un droit d'écriture à un autre
# SID, y compris les entrées « héritage seulement » (elles s'appliqueraient aux éléments créés plus tard), sauf
# CREATOR OWNER (S-1-3-0), qui devient le propriétaire, déjà contrôlé. $Attendus : chemins
# relatifs dont l'écart est attendu (fichier tenu ouvert en échec fermé), signalés à part. $Toleres : SID
# admis en plus, par racine (TrustedInstaller sur Program Files). $EnSysteme : dossiers contrôlés à part en
# SYSTEM par l'appelant (Controle-Systeme). Renvoie $true ou la liste des écarts.
function Controle-Droits([string[]]$Racines, [string[]]$Attendus = @(), [hashtable]$Toleres = @{}, [string[]]$EnSysteme = @()) {
    $ecarts = New-Object System.Collections.Generic.List[string]
    $n = 0
    $script:Illisibles.Clear()
    foreach ($r in $Racines) {
        if (-not (Test-Path -LiteralPath $r)) { $ecarts.Add("$r absent"); continue }
        $ec = 0
        foreach ($e in (Elements $r ([ref]$ec) $EnSysteme)) {
            $rel = $e.FullName.Substring($r.Length).TrimStart('\')
            if ($rel -in $Attendus) { continue }
            $n++
            $admis = $script:SidsConfiance + @($Toleres[$r])
            # Fichier de travail du service (*.tmp écrit puis renommé : commun.rs, geoip.rs) disparu entre l'énumération et
            # la lecture de ses droits : ni écart ni élément contrôlé (passage de c14b997 : geoip\afrinic.tmp) ; écarté
            # seulement s'il n'existe plus, comme pour l'essai d'écriture. Toute autre lecture impossible reste un écart.
            try { $d = Droits $e.FullName } catch {
                if ($e.Name -like '*.tmp' -and -not (Test-Path -LiteralPath $e.FullName)) { $n--; continue }
                $ecarts.Add("$($e.FullName) : droits illisibles"); continue
            }
            if ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) { $ecarts.Add("$($e.FullName) : lien") }
            if ($d.Proprietaire -notin $script:SidsConfiance) { $ecarts.Add("$($e.FullName) : propriétaire $($d.Proprietaire)") }
            foreach ($a in $d.Entrees) {
                if ($a.HeritageSeul -and $a.Sid -eq 'S-1-3-0') { continue }
                if ($a.Autorise -and $a.Sid -notin $admis -and (Ecriture $a.Droits)) {
                    $ecarts.Add("$($e.FullName) : écriture pour $($a.Sid) ($($a.Droits))$(if ($a.HeritageSeul) { ' (héritage seulement)' })")
                }
            }
        }
    }
    foreach ($i in $script:Illisibles) { $ecarts.Add("$i : contenu illisible en administrateur (non contrôlé)") }
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
# Session 0 (exécuteur lancé par une tâche à ouverture de session par mot de passe, cas tests\vm\lancer.ps1
# -SessionStandard) : les actions lancées par Start-Process -Credential n'y ont rien produit (passage VM du 25/10/2026 :
# sorties vides ; mécanisme exact non isolé par un essai). Le script du compte standard part alors d'une tâche planifiée
# à son nom (ouverture par mot de passe : compte de test jetable de la VM, mot de passe aléatoire gardé par le
# Planificateur jusqu'à la remise à l'instantané). Renvoie le processus démarré, comme Start-Process -PassThru, ou $null
# s'il a déjà fini avec succès. Tâche jamais supprimée (son processus peut tenir un fichier ouvert) : l'instantané de la
# VM l'efface ; arrêtée si elle n'a pas démarré à temps, pour ne pas partir pendant les contrôles suivants.
#
# Un compte standard n'a pas le droit « ouvrir une session en tant que tâche » (SeBatchLogonRight : administrateurs,
# opérateurs de sauvegarde et utilisateurs du journal de performances seulement) : sans lui, la tâche ne démarre jamais
# (passage VM du 25/10/2026 : 0x41303, « pas encore exécutée »). Accordé au compte de test jetable, une fois, par l'API
# LSA ; seulement dans ce chemin (session 0 : VM -SessionStandard), effacé avec l'instantané.
$script:DroitTacheAccorde = @{}
function Accorder-OuvertureTache($Compte) {
    if ($script:DroitTacheAccorde[$Compte.Sid]) { return }
    if (-not ('D4tLsa' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class D4tLsa {
    [StructLayout(LayoutKind.Sequential)] struct LSA_UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)] struct LSA_OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }
    [DllImport("advapi32.dll")] static extern uint LsaOpenPolicy(IntPtr systemName, ref LSA_OBJECT_ATTRIBUTES attributes, uint access, out IntPtr policy);
    [DllImport("advapi32.dll")] static extern uint LsaAddAccountRights(IntPtr policy, byte[] sid, LSA_UNICODE_STRING[] rights, uint count);
    [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr policy);
    [DllImport("advapi32.dll")] static extern uint LsaNtStatusToWinError(uint status);
    // 0 si accordé, sinon le code d'erreur Windows
    public static uint Accorder(byte[] sid, string droit) {
        var oa = new LSA_OBJECT_ATTRIBUTES(); oa.Length = Marshal.SizeOf(oa);
        IntPtr h;
        uint s = LsaOpenPolicy(IntPtr.Zero, ref oa, 0x00000010 | 0x00000800, out h); // POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES
        if (s != 0) return LsaNtStatusToWinError(s);
        var u = new LSA_UNICODE_STRING();
        u.Buffer = Marshal.StringToHGlobalUni(droit); u.Length = (ushort)(droit.Length * 2); u.MaximumLength = (ushort)(u.Length + 2);
        try { s = LsaAddAccountRights(h, sid, new[] { u }, 1); return s == 0 ? 0 : LsaNtStatusToWinError(s); }
        finally { Marshal.FreeHGlobal(u.Buffer); LsaClose(h); }
    }
}
'@
    }
    $sid = New-Object Security.Principal.SecurityIdentifier($Compte.Sid)
    $octets = New-Object byte[] $sid.BinaryLength
    $sid.GetBinaryForm($octets, 0)
    $r = [D4tLsa]::Accorder($octets, 'SeBatchLogonRight')
    if ($r -ne 0) { throw "droit « ouvrir une session en tant que tâche » non accordé au compte de test (erreur $r)" }
    $script:DroitTacheAccorde[$Compte.Sid] = $true
}
function Demarrer-ParTache($Compte, [string]$Fichier) {
    Accorder-OuvertureTache $Compte
    $nom = "d4t-essai-standard-$($script:NumeroScript)"
    $action = New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Fichier`"" -WorkingDirectory $script:Commun
    $reglages = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1)
    Register-ScheduledTask -TaskName $nom -Action $action -Settings $reglages -User $Compte.Nom `
        -Password $Compte.Credential.GetNetworkCredential().Password -RunLevel Limited -Force | Out-Null
    Start-ScheduledTask -TaskName $nom
    # 90 s : la première ouverture de session du compte crée son profil
    $fin = (Get-Date).AddSeconds(90)
    do {
        Start-Sleep -Milliseconds 200
        $c = Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" | Where-Object { $_.CommandLine -like "*$Fichier*" } | Select-Object -First 1
        if ($c) { $p = Get-Process -Id $c.ProcessId -ErrorAction SilentlyContinue; if ($p) { return $p } }
        $info = Get-ScheduledTaskInfo -TaskName $nom
        # Déjà fini : la tâche a tourné (heure de dernier lancement posée) et n'est plus en cours ; succès exigé, sinon
        # la cause (ouverture de session refusée, droit « ouvrir une session en tant que tâche »…) serait perdue
        if ($info.LastRunTime -gt (Get-Date).AddMinutes(-5) -and (Get-ScheduledTask -TaskName $nom).State -eq 'Ready') {
            if ($info.LastTaskResult -eq 0) { return $null }
            # Sortie du script (même numéro) : la cause de l'échec
            $sortie = $Fichier -replace '\\script-(\d+)\.ps1$', '\sortie-$1.txt'
            $cause = if (Test-Path -LiteralPath $sortie) { ((Get-Content -LiteralPath $sortie -Encoding UTF8 -Tail 3) -join ' / ') } else { 'aucune sortie' }
            throw "tâche du compte standard en échec (résultat 0x$('{0:X8}' -f $info.LastTaskResult)) : $cause"
        }
    } while ((Get-Date) -lt $fin)
    Stop-ScheduledTask -TaskName $nom -ErrorAction SilentlyContinue
    throw "tâche du compte standard : processus non démarré en 90 s (résultat 0x$('{0:X8}' -f $info.LastTaskResult)), tâche arrêtée"
}
function En-TantQue($Compte, [string]$Code, [switch]$SansAttendre, [int]$Secondes = 60) {
    $script:NumeroScript++
    $f = Join-Path $script:Commun "script-$($script:NumeroScript).ps1"
    $sortie = Join-Path $script:Commun "sortie-$($script:NumeroScript).txt"
    $corps = "`$ErrorActionPreference = 'Continue'`r`n& {`r`n$Code`r`n} *>&1 | Out-File -LiteralPath '$sortie' -Encoding utf8 -Width 4096"
    [IO.File]::WriteAllText($f, $corps, (New-Object Text.UTF8Encoding($true)))
    if ([Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) { $p = Demarrer-ParTache $Compte $f }
    else {
        $p = Start-Process powershell.exe -Credential $Compte.Credential -PassThru -WindowStyle Hidden -WorkingDirectory $script:Commun `
            -ArgumentList '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', "`"$f`""
    }
    if ($SansAttendre) { return $p }
    if ($p -and -not $p.WaitForExit($Secondes * 1000)) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; throw "délai dépassé ($Secondes s)" }
    if (Test-Path $sortie) { return (Get-Content -LiteralPath $sortie -Raw -Encoding UTF8) }
    return ''
}

# Ce que le compte standard peut faire sur le canal, dans chaque dossier réellement présent (créer un fichier,
# créer un sous-dossier) et sur chaque fichier présent (ouvrir en écriture), données et Program Files\deR4Tizer.
# (Pas de fonction nommée « Type » : l'alias type, Get-Content, passerait avant.)
# Seule une UnauthorizedAccessException vaut refus : un délai dépassé, un service arrêté ou un chemin absent ne
# prouvent rien. Renvoie $true ou la liste de ce qui n'a pas été refusé. $Exclus : chemins complets écartés
# de l'essai (fichier tenu ouvert en échec fermé, attendu).
function Essais-Standard($Compte, [string[]]$Exclus = @(), [string[]]$EnSysteme = @()) {
    $cibles = New-Object System.Collections.Generic.List[string]
    $script:Illisibles.Clear()
    # Dossiers contrôlés en SYSTEM : pas parcourus, mais le compte essaie quand même d'y créer
    foreach ($d in $EnSysteme) { if (Test-Path -LiteralPath $d) { $cibles.Add("D|$d") } }
    foreach ($r in $script:Donnees, $script:Programme) {
        if (-not (Test-Path $r)) { return "cible absente : $r" }
        foreach ($e in (Elements $r $null $EnSysteme)) {
            if ($e.FullName -in $Exclus) { continue }
            $cibles.Add($(if ($e.PSIsContainer) { 'D|' } else { 'F|' }) + $e.FullName)
        }
    }
    if ($script:Illisibles.Count) { return "contenu illisible en administrateur, non essayé : $($script:Illisibles -join ', ')" }
    $script:NumeroScript++
    $liste = Join-Path $script:Commun "cibles-$($script:NumeroScript).txt"
    [IO.File]::WriteAllLines($liste, $cibles, (New-Object Text.UTF8Encoding($true)))
    $s = En-TantQue $Compte @"
function Nom-Exception(`$err) { `$x = `$err.Exception; while (`$x.InnerException) { `$x = `$x.InnerException }; `$x.GetType().Name }
try { `$c = New-Object IO.Pipes.NamedPipeClientStream('.', 'deR4Tizer', [IO.Pipes.PipeDirection]::InOut); `$c.Connect(5000)
      `$w = New-Object IO.StreamWriter(`$c); `$w.AutoFlush = `$true; `$r = New-Object IO.StreamReader(`$c)
      `$w.WriteLine('{"Action":"toutDebloquer"}'); 'TUBE|canal|REPONSE ' + `$r.ReadLine() } catch { 'TUBE|canal|' + (Nom-Exception `$_) }
`$n = [guid]::NewGuid().ToString('N')
foreach (`$l in [IO.File]::ReadAllLines('$liste')) {
    `$t, `$p = `$l -split '\|', 2
    if (`$t -eq 'D') {
        try { `$h = [IO.File]::Open((Join-Path `$p "piege-`$n.txt"), 'CreateNew', 'Write'); `$h.Dispose(); "CREERFICHIER|`$p|ECRIT" } catch { "CREERFICHIER|`$p|" + (Nom-Exception `$_) }
        try { [void][IO.Directory]::CreateDirectory((Join-Path `$p "piege-`$n")); "CREERDOSSIER|`$p|CREE" } catch { "CREERDOSSIER|`$p|" + (Nom-Exception `$_) }
    } else {
        try { `$h = [IO.File]::Open(`$p, 'Open', 'Write', 'ReadWrite, Delete'); `$h.Dispose(); "ECRIRE|`$p|OUVERT" } catch { "ECRIRE|`$p|" + (Nom-Exception `$_) }
    }
}
'FIN'
"@ -Secondes 300
    $lignes = @($s -split "`r?`n" | Where-Object { $_ -match '\|' })
    if ($s -notmatch '(?m)^FIN') { return "essais interrompus : $($s -replace "`r?`n", ' ')" }
    $attendu = 1 + @($cibles | Where-Object { $_ -like 'D|*' }).Count * 2 + @($cibles | Where-Object { $_ -like 'F|*' }).Count
    if ($lignes.Count -ne $attendu) { return "$($lignes.Count) résultats pour $attendu essais" }
    # Fichier de travail du service (*.tmp renommé) disparu entre l'énumération et l'essai : ni refus ni accès ;
    # écarté seulement s'il n'existe plus au moment du contrôle. Toute autre disparition reste un écart.
    $lignes = @($lignes | Where-Object {
        $c = $_ -split '\|'
        -not ($c[0] -eq 'ECRIRE' -and $c[1] -like '*.tmp' -and $c[-1] -eq 'FileNotFoundException' -and -not (Test-Path -LiteralPath $c[1]))
    })
    $mauvais = @($lignes | Where-Object { ($_ -split '\|')[-1] -ne 'UnauthorizedAccessException' })
    if ($mauvais.Count) { return "$($mauvais.Count) essai(s) non refusé(s) sur $attendu : " + (($mauvais | Select-Object -First 8) -join ' ; ') }
    $true
}

# ---------------------------------------------------------------- canaris et quarantaine (lot 3b)

# Empreinte d'un dossier témoin (canari) : chemin relatif, taille, SHA-256 et propriétaire de chaque élément,
# sans suivre les liens. Deux relevés identiques : rien n'a été écrit, lu pour modification ni supprimé.
function Empreinte-Dossier([string]$Racine) {
    if (-not (Test-Path -LiteralPath $Racine)) { return '(absent)' }
    $l = foreach ($e in (Elements $Racine $null)) {
        $rel = $e.FullName.Substring($Racine.Length)
        $h = if ($e.PSIsContainer) { 'dossier' } else { (Get-FileHash -LiteralPath $e.FullName -Algorithm SHA256).Hash }
        "$rel|$(if ($e.PSIsContainer) { '' } else { $e.Length })|$h|$((Droits $e.FullName).Proprietaire)"
    }
    ($l | Sort-Object) -join "`n"
}

# Canari : dossier de l'administrateur avec des fichiers témoins (dont un éventuel « appât » au nom donné)
function Nouveau-Canari([string]$Chemin, [string]$Appat = '', [byte[]]$Contenu = $null) {
    New-Item -ItemType Directory -Force -Path $Chemin | Out-Null
    [IO.File]::WriteAllText((Join-Path $Chemin 'temoin.txt'), "canari $Chemin")
    New-Item -ItemType Directory -Force -Path (Join-Path $Chemin 'sous') | Out-Null
    [IO.File]::WriteAllText((Join-Path $Chemin 'sous\temoin2.txt'), 'canari, sous-dossier')
    if ($Appat) { [IO.File]::WriteAllBytes((Join-Path $Chemin $Appat), $Contenu) }
    Empreinte-Dossier $Chemin
}

function Octets-Aleatoires([int]$Taille) {
    $o = New-Object byte[] $Taille
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($o)
    $o
}

function Sha256([string]$Chemin) { (Get-FileHash -LiteralPath $Chemin -Algorithm SHA256).Hash }

# Manifeste de quarantaine relu (tableau, éventuellement vide)
function Liste-Quarantaine {
    $f = Join-Path $script:Donnees 'quarantaine.json'
    if (-not (Test-Path $f)) { return @() }
    # ConvertFrom-Json (PowerShell 5.1) rend le tableau JSON comme UN objet : passer par une variable
    $j = (Get-Content $f -Raw -Encoding UTF8).TrimStart([char]0xFEFF) | ConvertFrom-Json
    @($j)
}

function Entree-Quarantaine([string]$Origine) { @(Liste-Quarantaine | Where-Object { $_.CheminOrigine -eq $Origine }) | Select-Object -Last 1 }

# Commande sur le canal avec une cible (et une raison) ; renvoie l'objet réponse
function Commande-Cible([string]$Action, [string]$Cible) {
    $j = @{ Action = $Action; Cible = $Cible; Raison = 'test d''intégration (lot 3b)' } | ConvertTo-Json -Compress
    Commande $j 30000 | ConvertFrom-Json
}

# Jonction (mklink /J) ; avec -Compte, créée sous l'identité de ce compte. Renvoie $true si elle existe.
function Nouvelle-Jonction([string]$Lien, [string]$Cible, $Compte = $null) {
    if ($Compte) {
        $s = En-TantQue $Compte "cmd.exe /c mklink /J `"$Lien`" `"$Cible`""
    } else {
        $s = cmd.exe /c mklink /J "$Lien" "$Cible" 2>&1 | Out-String
    }
    $i = Get-Item -LiteralPath $Lien -Force -ErrorAction SilentlyContinue
    [bool]($i -and ($i.Attributes -band [IO.FileAttributes]::ReparsePoint))
}

# ---------------------------------------------------------------- SYSTEM (lot 3c)

# Exécute du PowerShell en SYSTEM par une tâche planifiée (runner jetable) ; renvoie sa sortie (texte). Sert aux
# contrôles des dossiers réservés à SYSTEM, que l'administrateur ne peut pas lire.
# Script et sortie dans un dossier de l'administrateur, jamais dans C:\d4t-commun (ouvert au compte standard :
# un script exécuté en SYSTEM ne doit pas y être modifiable).
function En-TantQueSysteme([string]$Code, [int]$Secondes = 120) {
    $script:NumeroScript++
    $n = $script:NumeroScript
    $dossier = Join-Path $(if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }) 'd4t-systeme'
    New-Item -ItemType Directory -Force -Path $dossier | Out-Null
    $f = Join-Path $dossier "systeme-$n.ps1"
    $sortie = Join-Path $dossier "systeme-$n.txt"
    $corps = "`$ErrorActionPreference = 'Continue'`r`n& {`r`n$Code`r`n} *>&1 | Out-File -LiteralPath '$sortie' -Encoding utf8 -Width 4096"
    [IO.File]::WriteAllText($f, $corps, (New-Object Text.UTF8Encoding($true)))
    $nom = "d4t-essai-systeme-$n"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$f`""
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $nom -Action $action -Principal $principal -Force | Out-Null
    try {
        Start-ScheduledTask -TaskName $nom
        $fin = (Get-Date).AddSeconds($Secondes)
        do { Start-Sleep 1; $t = Get-ScheduledTask -TaskName $nom } while ($t.State -ne 'Ready' -and (Get-Date) -lt $fin)
        if ($t.State -ne 'Ready') { throw "tâche SYSTEM : délai dépassé ($Secondes s)" }
    } finally { Unregister-ScheduledTask -TaskName $nom -Confirm:$false }
    if (Test-Path $sortie) { return (Get-Content -LiteralPath $sortie -Raw -Encoding UTF8) }
    ''
}

# Contrôle, en SYSTEM, d'un dossier réservé à SYSTEM : la racine a ses droits protégés (héritage coupé) ; chaque
# élément (sans suivre de lien) a pour propriétaire SYSTEM, n'est pas un lien, et n'a d'entrées que pour SYSTEM
# (aucune pour TrustedInstaller ni pour aucun autre SID). Renvoie $true ou la liste des écarts.
function Controle-Systeme([string]$Racine) {
    $s = En-TantQueSysteme @"
`$T = [Security.Principal.SecurityIdentifier]
function Voir(`$e) {
    # -ErrorAction Stop : le script SYSTEM tourne en « Continue » ; sans lui, une lecture impossible donnait `$null et
    # des écarts trompeurs (« lien », propriétaire vide) au lieu d'atteindre le catch (relecture de #70)
    try { `$a = Get-Acl -LiteralPath `$e.FullName -ErrorAction Stop } catch {
        # Fichier de travail du service (*.tmp renommé) disparu : ni écart ni élément contrôlé (retiré du compte)
        if (`$e.Name -like '*.tmp' -and -not (Test-Path -LiteralPath `$e.FullName)) { "IGNORE|`$(`$e.FullName)"; return }
        "ECART|`$(`$e.FullName)|droits illisibles en SYSTEM"; return
    }
    if (`$e.Attributes -band [IO.FileAttributes]::ReparsePoint) { "ECART|`$(`$e.FullName)|lien" }
    `$o = `$a.GetOwner(`$T).Value
    if (`$o -ne 'S-1-5-18') { "ECART|`$(`$e.FullName)|propriétaire `$o" }
    foreach (`$r in `$a.GetAccessRules(`$true, `$true, `$T)) {
        if (`$r.IdentityReference.Value -ne 'S-1-5-18') { "ECART|`$(`$e.FullName)|entrée pour `$(`$r.IdentityReference.Value) (`$(`$r.FileSystemRights))" }
    }
}
`$racine = Get-Item -LiteralPath '$Racine' -Force
if (-not (Get-Acl -LiteralPath '$Racine').AreAccessRulesProtected) { 'ECART|$Racine|droits hérités (non protégés)' }
Voir `$racine
`$n = 1
`$pile = New-Object System.Collections.Generic.Stack[string]
`$pile.Push('$Racine')
while (`$pile.Count) {
    foreach (`$e in @(Get-ChildItem -LiteralPath `$pile.Pop() -Force)) {
        `$n++
        Voir `$e
        if (`$e.PSIsContainer -and -not (`$e.Attributes -band [IO.FileAttributes]::ReparsePoint)) { `$pile.Push(`$e.FullName) }
    }
}
"FIN|`$n"
"@
    if ($s -notmatch '(?m)^FIN\|(\d+)') { return "contrôle SYSTEM interrompu : $($s -replace "`r?`n", ' ')" }
    $n = [int]$Matches[1] - @($s -split "`r?`n" | Where-Object { $_ -like 'IGNORE|*' }).Count
    $ecarts = @($s -split "`r?`n" | Where-Object { $_ -like 'ECART|*' })
    if ($ecarts.Count) { return "$($ecarts.Count) écart(s) sur $n élément(s) (contrôle en SYSTEM) : " + (($ecarts | Select-Object -First 8) -join ' ; ') }
    $true
}

# Diagnostic d'une suppression incomplète du dossier de données : éléments restants (chemin relatif, attributs,
# propriétaire) et processus deR4Tizer encore présents
function Restes-Donnees([int]$Nombre = 40) {
    if (-not (Test-Path -LiteralPath $script:Donnees)) { return '(dossier absent)' }
    $e = @(Get-ChildItem -LiteralPath $script:Donnees -Recurse -Force -ErrorAction SilentlyContinue)
    $l = $e | Select-Object -First $Nombre | ForEach-Object {
        $o = try { (Get-Acl -LiteralPath $_.FullName).Owner } catch { 'illisible' }
        "$($_.FullName.Substring($script:Donnees.Length)) [$($_.Attributes)] $o"
    }
    $p = @(Get-Process deR4Tizer* -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)($($_.Id))" })
    "$($e.Count) élément(s) : $($l -join ' ; ') ; processus : $(if ($p.Count) { $p -join ', ' } else { 'aucun' })"
    $cr = Join-Path $env:SystemRoot 'Temp\deR4Tizer-desinstallation.txt'
    if (Test-Path $cr) { "compte rendu de la désinstallation : $(Get-Content $cr -Raw)" }
}
