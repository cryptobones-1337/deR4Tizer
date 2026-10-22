# Test de la remontée des alertes, sans rien envoyer à l'extérieur : le canal ntfy vise une adresse locale
# fermée (https://127.0.0.1:9/test). Vérifie l'enregistrement des secrets (lisibles par les administrateurs
# seulement), l'appel à curl, la remontée de l'erreur et l'effacement des fichiers de paramètres.
# Se relance en administrateur (UAC). Résultat dans test-notifications.log. Remet ensuite les réglages d'origine.
$ErrorActionPreference = 'Stop'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    $p = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -WindowStyle Hidden `
        -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`""
    Get-Content (Join-Path $PSScriptRoot 'test-notifications.log')
    exit $p.ExitCode
}

$log = Join-Path $PSScriptRoot 'test-notifications.log'
Start-Transcript -Path $log -Force | Out-Null
$dossier = Join-Path $env:ProgramData 'deR4Tizer'

function Envoyer($commande) {
    $tube = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'deR4Tizer', [System.IO.Pipes.PipeDirection]::InOut)
    $tube.Connect(3000)
    $e = New-Object System.IO.StreamWriter($tube, (New-Object System.Text.UTF8Encoding($false)))
    $e.AutoFlush = $true
    $e.WriteLine(($commande | ConvertTo-Json -Compress -Depth 6))
    $r = (New-Object System.IO.StreamReader($tube)).ReadLine()
    $tube.Dispose()
    $r
}

$config = Get-Content (Join-Path $dossier 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$origine = $config.Notifications
try {
    $essai = [pscustomobject]@{ NiveauMin = 'Critique'; MaxParHeure = 10; Ntfy = $true; Teams = $false; Smtp = $false;
        SmtpServeur = ''; SmtpPort = 465; SmtpSecurite = 'SSL'; SmtpUtilisateur = ''; Expediteur = ''; Destinataires = '' }
    $demande = @{ Config = $essai; NtfyUrl = 'https://127.0.0.1:9/test'; NtfyJeton = 'jeton-de-test'; TeamsUrl = ''; SmtpMotDePasse = '' }
    "== test ntfy vers une adresse fermée : " + (Envoyer @{ Action = 'testerNotifications'; Valeur = ($demande | ConvertTo-Json -Compress -Depth 5) })
    "== droits du dossier des secrets :"
    icacls (Join-Path $dossier 'secrets')
    "== fichiers restants dans secrets\ : " + ((Get-ChildItem (Join-Path $dossier 'secrets') | Select-Object -ExpandProperty Name) -join ', ')
    "== état lisible par l'interface :"
    Get-Content (Join-Path $dossier 'notifications.json') -Raw
    "== le jeton n'apparaît pas dans notifications.json : " + (-not (Select-String -Path (Join-Path $dossier 'notifications.json') -Pattern 'jeton-de-test' -Quiet))
    "== le jeton n'apparaît pas dans config.json : " + (-not (Select-String -Path (Join-Path $dossier 'config.json') -Pattern 'jeton-de-test' -Quiet))
}
catch { "ERREUR : $_" }
finally {
    $retour = @{ Config = $origine; NtfyUrl = '-'; NtfyJeton = '-'; TeamsUrl = ''; SmtpMotDePasse = '' }
    "== retour aux réglages d'origine : " + (Envoyer @{ Action = 'notifications'; Valeur = ($retour | ConvertTo-Json -Compress -Depth 5) })
    Stop-Transcript | Out-Null
}
