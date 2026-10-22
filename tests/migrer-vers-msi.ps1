# Migration d'une installation par scripts vers le paquet MSI, sans rien perdre : seuls l'ancien service,
# ses fichiers et ses raccourcis sont retirés ; données, règles de pare-feu, leurres et baseline restent.
# Se relance en administrateur (UAC). Résultat dans migrer-vers-msi.log.
$ErrorActionPreference = 'Stop'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    $p = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`""
    Get-Content (Join-Path $PSScriptRoot 'migrer-vers-msi.log')
    exit $p.ExitCode
}
Start-Transcript -Path (Join-Path $PSScriptRoot 'migrer-vers-msi.log') -Force | Out-Null
try {
    $msi = Join-Path (Split-Path $PSScriptRoot -Parent) 'bin\deR4Tizer.msi'
    $dejaMsi = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object DisplayName -eq 'deR4Tizer'
    if (-not $dejaMsi) {
        "== retrait de l'installation par scripts"
        Get-Process deR4Tizer -ErrorAction SilentlyContinue | Stop-Process -Force
        if (Get-Service deR4Tizer -ErrorAction SilentlyContinue) {
            Stop-Service deR4Tizer -Force; (Get-Service deR4Tizer).WaitForStatus('Stopped', '00:00:30')
            sc.exe delete deR4Tizer | Out-Null
            Start-Sleep 2
        }
        Remove-Item "$env:ProgramFiles\deR4Tizer" -Recurse -Force -ErrorAction SilentlyContinue
        $menu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
        Remove-Item (Join-Path $menu 'deR4Tizer.lnk'), (Join-Path $menu 'Startup\deR4Tizer.lnk') -ErrorAction SilentlyContinue
    }
    "== installation du MSI"
    $journal = Join-Path $PSScriptRoot 'installation-msi.log'
    $r = Start-Process msiexec.exe -Wait -PassThru -ArgumentList '/i', "`"$msi`"", '/qn', '/norestart', '/l*v', "`"$journal`""
    "   code de retour msiexec : $($r.ExitCode) (0 = succès)"
    Start-Sleep 5
    "== vérifications"
    "   service : " + (Get-Service deR4Tizer).Status + " / démarrage " + (Get-Service deR4Tizer).StartType
    "   compte : " + (Get-CimInstance Win32_Service -Filter "Name='deR4Tizer'").StartName
    "   reprise sur échec : " + ((sc.exe qfailure deR4Tizer | Select-String 'RESTART').Count) + " action(s) de redémarrage"
    $app = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object DisplayName -eq 'deR4Tizer'
    "   « Applications » : " + $app.DisplayName + " " + $app.DisplayVersion + " (" + $app.Publisher + ")"
    "   lancement à l'ouverture de session : " + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name deR4Tizer -ErrorAction SilentlyContinue).deR4Tizer
    "   raccourci du menu Démarrer : " + (Test-Path (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\deR4Tizer.lnk'))
    "   fichiers : " + ((Get-ChildItem "$env:ProgramFiles\deR4Tizer" -Name) -join ', ')
    "   données conservées : " + (Test-Path "$env:ProgramData\deR4Tizer\blocages.json")
}
catch { "ERREUR : $_" }
finally { Stop-Transcript | Out-Null }
