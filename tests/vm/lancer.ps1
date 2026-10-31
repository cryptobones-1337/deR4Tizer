# Lance un scénario d'intégration dans la VM Hyper-V de test (Windows 11, Microsoft Defender actif, un compte connecté
# à la console), à la place de Windows Sandbox : mêmes scripts (tests\integration), même exécuteur
# (tests\bac-a-sable\executer.ps1), même dossier d'entrée (preparer.ps1). La VM est remise à son instantané avant et
# après le scénario : chaque scénario part du même Windows, et rien n'y reste (ni MSI, ni clés de test du 3c).
#
# Prérequis : VM avec un instantané « propre » (Defender actif, sans exclusion), PowerShell Direct ; compte
# administrateur de la VM enregistré par Export-Clixml (DPAPI, jamais affiché) ; membre du groupe « Administrateurs
# Hyper-V » ; preparer.ps1 exécuté (et preparer.ps1 -Maj pour le 3c).
# Entretien de l'instantané : les signatures de plus de 7 jours mettent le lot 3d en NON EXÉCUTÉ, et une plateforme de
# Defender dépassée se met à jour toute seule pendant un scénario, à une heure qui varie (redémarrage, réglage ajouté).
# Remettre l'instantané, laisser Defender se mettre à jour seul sans rien lui demander, vérifier qu'il est pleinement actif
# et sans exclusion, puis Checkpoint-VM sous un nom commençant par « propre » : le plus récent est pris par défaut.
# Defender n'est que relevé (avant et après, par l'exécuteur) ; son état « pleinement actif » n'est exigé que par le
# lot 3d (tests\vm\lot3d.ps1). Sans -SessionStandard, la session de console est celle de l'instantané.
#
# Usage : .\tests\vm\lancer.ps1 -Scenario installation|quarantaine|maj|lot3d|mesure [-Vm deR4Tizer-test-26H2] [-Instantane <nom>]
param(
    [Parameter(Mandatory)] [ValidateSet('installation', 'quarantaine', 'maj', 'lot3d', 'mesure')] [string]$Scenario,
    [string]$Racine = 'C:\d4t-bac-a-sable',
    [string]$Vm = 'deR4Tizer-test-26H2',
    # Par défaut : l'instantané le plus récent dont le nom commence par « propre »
    [string]$Instantane = '',
    [string]$Identifiants = (Join-Path $env:USERPROFILE '.d4t-vm-credential.xml'),
    [int]$Minutes = 60,
    # Compte local STANDARD connecté à la console pendant le scénario (ouverture de session automatique, puis
    # redémarrage) : scénarios « session standard » du lot 3d. Compte et réglage effacés par la remise à l'instantané.
    [switch]$SessionStandard
)
$ErrorActionPreference = 'Stop'
$entree = Join-Path $Racine 'entree'
$sortie = Join-Path $Racine "sortie-vm-$Scenario-$(if ($SessionStandard) { 'standard-' })$(Get-Date -Format yyyyMMdd-HHmmss)"
if (-not (Test-Path (Join-Path $entree 'deR4Tizer.msi'))) { throw 'Dossier d''entrée incomplet : lancer d''abord tests\bac-a-sable\preparer.ps1.' }
if ($Scenario -eq 'maj' -and -not (Test-Path (Join-Path $entree 'maj\versions.txt'))) { throw 'Scénario maj : lancer d''abord preparer.ps1 -Maj.' }
$cred = Import-Clixml $Identifiants
$point = if ($Instantane) { Get-VMSnapshot -VMName $Vm -Name $Instantane }
         else { Get-VMSnapshot -VMName $Vm | Where-Object Name -like 'propre*' | Sort-Object CreationTime | Select-Object -Last 1 }
if (-not $point) { throw "Aucun instantané « propre » pour la VM $Vm." }
New-Item -ItemType Directory -Force -Path $sortie | Out-Null

function Remettre {
    Restore-VMSnapshot -VMSnapshot $point -Confirm:$false
    if ((Get-VM $Vm).State -ne 'Running') { Start-VM $Vm }
}
function Session {
    $fin = (Get-Date).AddMinutes(5)
    do {
        $s = try { New-PSSession -VMName $Vm -Credential $cred -ErrorAction Stop } catch { Start-Sleep 5; $null }
    } while (-not $s -and (Get-Date) -lt $fin)
    if (-not $s) { throw "VM $Vm injoignable par PowerShell Direct." }
    $s
}

Write-Host "VM $Vm remise à l'instantané « $($point.Name) », scénario $Scenario, résultats dans $sortie"
$s = $null
try {
    Remettre
    $s = Session
    # Horloge resynchronisée après la reprise de l'instantané (certificats et CRL du 3c)
    $ecart = { [math]::Abs(((Invoke-Command -Session $s { Get-Date }) - (Get-Date)).TotalSeconds) }
    $fin = (Get-Date).AddMinutes(3)
    while ((& $ecart) -gt 120 -and (Get-Date) -lt $fin) {
        Invoke-Command -Session $s { w32tm /resync /force 2>&1 | Out-Null }
        Start-Sleep 10
    }
    if ((& $ecart) -gt 120) { throw 'Horloge de la VM non resynchronisée (écart de plus de 2 minutes).' }
    if ($SessionStandard) {
        # Compte standard jetable, mot de passe aléatoire tiré dans la VM, jamais affiché ni rapporté à l'hôte ;
        # ouverture de session automatique à la console, puis redémarrage
        # Écrit avant CHAQUE redémarrage (relecture de #56, M1) : compte créé ou nouveau mot de passe, puis valeurs de
        # Winlogon
        $preparerConsole = {
            $car = [char[]]'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
            $mdp = (-join (1..24 | ForEach-Object { $car | Get-Random })) + 'a7!K'
            $secret = ConvertTo-SecureString $mdp -AsPlainText -Force
            if (Get-LocalUser 'd4t_console' -ErrorAction SilentlyContinue) { Set-LocalUser -Name 'd4t_console' -Password $secret }
            else {
                New-LocalUser -Name 'd4t_console' -Password $secret -PasswordNeverExpires -AccountNeverExpires | Out-Null
                Add-LocalGroupMember -SID 'S-1-5-32-545' -Member 'd4t_console'
            }
            # Windows 11 ignore l'ouverture de session automatique tant que l'option « connexion sans mot de passe »
            # (DevicePasswordLessBuildVersion = 2) est active : constaté dans la VM, console vide après le redémarrage
            $sansMdp = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device'
            New-Item $sansMdp -Force | Out-Null
            Set-ItemProperty $sansMdp -Name DevicePasswordLessBuildVersion -Value 0 -Type DWord
            $w = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            Set-ItemProperty $w -Name AutoAdminLogon -Value '1'
            Set-ItemProperty $w -Name DefaultUserName -Value 'd4t_console'
            Set-ItemProperty $w -Name DefaultDomainName -Value $env:COMPUTERNAME
            Set-ItemProperty $w -Name DefaultPassword -Value $mdp
        }
        # État de l'ouverture automatique, sans le mot de passe (présent ou non) : preuve en cas d'échec
        $etatConsole = {
            $w = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            $d = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device' -ErrorAction SilentlyContinue).DevicePasswordLessBuildVersion
            "AutoAdminLogon=$($w.AutoAdminLogon) DefaultUserName=$($w.DefaultUserName) mot de passe=$(if ($w.DefaultPassword) { 'présent' } else { 'absent' }) DevicePasswordLessBuildVersion=$d compte=$([bool](Get-LocalUser d4t_console -ErrorAction SilentlyContinue))"
        }
        # Redémarrage PROPRE (arrêt du système par les services d'intégration, puis démarrage) : Restart-VM -Force est
        # une remise à zéro brutale, qui perdait les écritures du registre pas encore sur le disque (constaté le
        # 25/10/2026 : console vide une fois sur deux, valeurs de Winlogon et option sans mot de passe revenues à
        # celles de l'instantané)
        for ($essai = 1; $essai -le 2; $essai++) {
            Invoke-Command -Session $s $preparerConsole
            Remove-PSSession $s; $s = $null
            Stop-VM -Name $Vm -Force
            Start-VM -Name $Vm
            Wait-VM -Name $Vm -For Heartbeat -Timeout 600
            $s = Session
            $fin = (Get-Date).AddMinutes(8)
            do { Start-Sleep 10; $console = Invoke-Command -Session $s { (Get-CimInstance Win32_ComputerSystem).UserName } }
            while ($console -notlike '*\d4t_console' -and (Get-Date) -lt $fin)
            if ($console -like '*\d4t_console') { break }
            "Compte standard absent de la console après le redémarrage $essai ($console) : $(Invoke-Command -Session $s $etatConsole)"
        }
        if ($console -notlike '*\d4t_console') { throw "Compte standard absent de la console après deux redémarrages ($console) : $(Invoke-Command -Session $s $etatConsole)." }
        # Réellement standard : pas membre des Administrateurs (comptes locaux seulement dans la VM de test : pas de
        # groupe de domaine imbriqué)
        # Échec fermé : liste illisible = refus (Get-LocalGroupMember échoue sur un SID orphelin ; net localgroup non)
        $admin = Invoke-Command -Session $s {
            $nom = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
            $l = & net.exe localgroup $nom 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $l) { return 'illisible' }
            if (@($l | Where-Object { $_.Trim() -eq 'd4t_console' }).Count) { 'membre' } else { 'non' }
        }
        if ($admin -ne 'non') { throw "Compte de console : appartenance aux Administrateurs $admin, session standard impossible." }
        Write-Host "Console : $console (compte standard)"
    }
    Invoke-Command -Session $s { Remove-Item C:\entree, C:\sortie -Recurse -Force -ErrorAction SilentlyContinue }
    Copy-Item -Path $entree -Destination 'C:\entree' -ToSession $s -Recurse -Force
    # Empreinte du MSI calculée ici, sur l'hôte : le lot 3d la compare à celle du fichier reçu dans la VM
    $h = (Get-FileHash (Join-Path $entree 'deR4Tizer.msi') -Algorithm SHA256).Hash
    Invoke-Command -Session $s -ArgumentList $h { param($h) Set-Content C:\entree\msi-sha256-hote.txt $h -Encoding Ascii }
    # Exécuteur lancé par une tâche planifiée dans une vraie ouverture de session de l'administrateur (élevée), comme
    # la LogonCommand de Windows Sandbox : dans une session PowerShell Direct, Start-Process -Credential (scénarios
    # « compte standard ») ne produit rien (constaté au premier passage). Session interactive de l'administrateur
    # s'il est à la console, sinon ouverture de session par mot de passe (transmis à la VM par le canal chiffré de
    # PowerShell Direct, jamais affiché ni écrit sur l'hôte). -SansArret : la VM ne s'éteint pas.
    $resultat = Invoke-Command -Session $s -ArgumentList $Scenario, $Minutes, $cred -ScriptBlock {
        param($Scenario, $Minutes, $Cred)
        $nom = 'd4t-executeur'
        $utilisateur = $Cred.UserName -replace '^\.\\', "$env:COMPUTERNAME\"
        if ($utilisateur -notmatch '\\') { $utilisateur = "$env:COMPUTERNAME\$utilisateur" }
        $console = (Get-CimInstance Win32_ComputerSystem).UserName
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\entree\executer.ps1 -Scenario $Scenario -SansArret"
        $reglages = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes $Minutes) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        if ($console -and $console.Split('\')[-1] -eq $utilisateur.Split('\')[-1]) {
            $principal = New-ScheduledTaskPrincipal -UserId $console -LogonType Interactive -RunLevel Highest
            Register-ScheduledTask -TaskName $nom -Action $action -Principal $principal -Settings $reglages -Force | Out-Null
            $mode = 'session interactive'
        } else {
            Register-ScheduledTask -TaskName $nom -Action $action -User $utilisateur -Password $Cred.GetNetworkCredential().Password -RunLevel Highest -Settings $reglages -Force | Out-Null
            $mode = 'ouverture de session par mot de passe'
        }
        Start-ScheduledTask -TaskName $nom
        $code = "C:\sortie\$Scenario-code.txt"
        $fin = (Get-Date).AddMinutes($Minutes)
        # Fin de l'attente dès que la tâche ne tourne plus (échec au lancement : pas 60 minutes d'attente pour rien)
        Start-Sleep 15
        while (-not (Test-Path $code) -and (Get-Date) -lt $fin -and (Get-ScheduledTask -TaskName $nom).State -in 'Running', 'Queued') { Start-Sleep 10 }
        Start-Sleep 5
        $etat = "$((Get-ScheduledTask -TaskName $nom).State), résultat 0x$('{0:X}' -f (Get-ScheduledTaskInfo -TaskName $nom).LastTaskResult)"
        Stop-ScheduledTask -TaskName $nom -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $nom -Confirm:$false -ErrorAction SilentlyContinue
        if (Test-Path $code) { "exécuteur ($mode) terminé" } else { "exécuteur ($mode) arrêté sans résultat (tâche $etat)" }
    }
    Write-Host $resultat
    Invoke-Command -Session $s { "Windows de la VM : $((Get-CimInstance Win32_OperatingSystem).Version).$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR)" } |
        Set-Content (Join-Path $sortie "$Scenario-vm.txt")
} finally {
    # Sortie rapportée même si le scénario ou la session a échoué, avant la remise à l'instantané qui l'effacerait
    try {
        if (-not $s -or $s.State -ne 'Opened') { $s = Session }
        Copy-Item -Path 'C:\sortie\*' -Destination $sortie -FromSession $s -Recurse -Force -ErrorAction Stop
    } catch { Write-Warning "Sortie de la VM non rapportée : $($_.Exception.Message)" }
    if ($s) { Remove-PSSession $s -ErrorAction SilentlyContinue }
    # VM remise à son instantané : MSI, comptes de test, racine de test approuvée et clés du 3c n'y restent pas.
    # Échec : le lanceur échoue (le passage ne compte pas), le scénario suivant repartira de l'instantané.
    $remise = $true
    try { Remettre } catch { $remise = $false; Write-Warning "VM non remise à son instantané : $($_.Exception.Message)" }
    if ($Scenario -eq 'maj') {
        Remove-Item -LiteralPath (Join-Path $entree 'maj') -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Join-Path $Racine 'tmp') -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Clés et binaires de test effacés ($(Join-Path $entree 'maj'))"
    }
}
if (-not $remise) { throw "VM non remise à son instantané après le scénario (voir $sortie) : passage sans valeur de preuve." }
$fichierCode = Join-Path $sortie "$Scenario-code.txt"
if (-not (Test-Path $fichierCode)) { throw "Pas de résultat (voir $sortie)." }
$code = (Get-Content $fichierCode -Raw).Trim()
$tableau = Join-Path $sortie "$Scenario-tableau.md"
if (Test-Path $tableau) { Get-Content $tableau -Encoding UTF8 }
$detections = Join-Path $sortie "$Scenario-defender-detections.txt"
Write-Host "Code de sortie : $code ; détections Defender : $(if ((Test-Path $detections) -and (Get-Content $detections -Raw).Trim()) { 'OUI, voir ' + $detections } else { 'aucune' })"
