# Test de bout en bout de l'export : syslog (JSON puis CEF) vers un récepteur local, puis API d'export.
# Remet ensuite les réglages d'origine. Se relance en administrateur (UAC). Résultat dans test-export.log.
# Le jeton de l'API n'est jamais affiché (seulement sa longueur).
$ErrorActionPreference = 'Stop'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    $p = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -WindowStyle Hidden `
        -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`""
    Get-Content (Join-Path $PSScriptRoot 'test-export.log')
    exit $p.ExitCode
}

$log = Join-Path $PSScriptRoot 'test-export.log'
Start-Transcript -Path $log -Force | Out-Null
$dossier = Join-Path $env:ProgramData 'deR4Tizer'

function Envoyer($commande) {
    $tube = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'deR4Tizer', [System.IO.Pipes.PipeDirection]::InOut)
    $tube.Connect(3000)
    $e = New-Object System.IO.StreamWriter($tube, (New-Object System.Text.UTF8Encoding($false)))
    $e.AutoFlush = $true
    $e.WriteLine(($commande | ConvertTo-Json -Compress -Depth 5))
    $r = (New-Object System.IO.StreamReader($tube)).ReadLine()
    $tube.Dispose()
    $r
}

function Recevoir($udp) {
    $distant = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    try { [System.Text.Encoding]::UTF8.GetString($udp.Receive([ref]$distant)) } catch { "(rien reçu : $($_.Exception.Message))" }
}

function Http($chemin, $jeton) {
    $req = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:8642$chemin")
    $req.Timeout = 5000
    if ($jeton) { $req.Headers.Add('Authorization', "Bearer $jeton") }
    try { $rep = $req.GetResponse() } catch [System.Net.WebException] { $rep = $_.Exception.Response }
    if (-not $rep) { return "pas de réponse" }
    $corps = (New-Object System.IO.StreamReader($rep.GetResponseStream())).ReadToEnd()
    "$([int]$rep.StatusCode) $($rep.ContentType) : $($corps.Substring(0, [Math]::Min(220, $corps.Length)))"
}

$fichierConfig = Join-Path $dossier 'config.json'
$origine = if (Test-Path $fichierConfig) { Get-Content $fichierConfig -Raw -Encoding UTF8 | ConvertFrom-Json }
           else { [pscustomobject]@{ BlocageAutoMenaces = $true; ReponseAutoRancongiciel = $true; Langue = 'fr' } }
$udp = New-Object System.Net.Sockets.UdpClient(5514)
$udp.Client.ReceiveTimeout = 5000
try {
    $config = $origine | ConvertTo-Json -Depth 5 | ConvertFrom-Json
    $config | Add-Member -Force -NotePropertyName Syslog -NotePropertyValue ([pscustomobject]@{ Actif = $true; Hote = '127.0.0.1'; Port = 5514; Protocole = 'UDP'; Format = 'JSON'; NiveauMin = 'Info' })
    $config | Add-Member -Force -NotePropertyName Api -NotePropertyValue ([pscustomobject]@{ Actif = $true; Port = 8642; Reseau = $false })

    "== réglages : " + (Envoyer @{ Action = 'reglages'; Valeur = ($config | ConvertTo-Json -Compress -Depth 5) })
    "== test syslog JSON : " + (Envoyer @{ Action = 'testerSyslog'; Valeur = ($config.Syslog | ConvertTo-Json -Compress) })
    "   reçu : " + (Recevoir $udp)
    $config.Syslog.Format = 'CEF'
    "== test syslog CEF : " + (Envoyer @{ Action = 'testerSyslog'; Valeur = ($config.Syslog | ConvertTo-Json -Compress) })
    "   reçu : " + (Recevoir $udp)

    Start-Sleep -Seconds 3
    $jeton = (Get-Content (Join-Path $dossier 'api-jeton.txt') -Raw).Trim()
    "== jeton : $($jeton.Length) caractères ; droits :"
    icacls (Join-Path $dossier 'api-jeton.txt')
    "== /sante sans jeton      : " + (Http '/api/v1/sante' $null)
    "== /alertes sans jeton    : " + (Http '/api/v1/alertes' $null)
    "== /alertes mauvais jeton : " + (Http '/api/v1/alertes' 'faux')
    "== /alertes?limite=2      : " + (Http '/api/v1/alertes?limite=2' $jeton)
    "== /alertes format cef    : " + (Http '/api/v1/alertes?limite=1&format=cef' $jeton)
    "== /exposition            : " + (Http '/api/v1/exposition' $jeton)
    "== /journal?lignes=2      : " + (Http '/api/v1/journal?lignes=2' $jeton)
    "== POST refusé            : " + $(try { Invoke-WebRequest -UseBasicParsing -Method Post 'http://127.0.0.1:8642/api/v1/alertes' -Headers @{ Authorization = "Bearer $jeton" } | % StatusCode } catch { [int]$_.Exception.Response.StatusCode })
    "== écoute :"
    Get-NetTCPConnection -LocalPort 8642 -State Listen -ErrorAction SilentlyContinue | Select LocalAddress, LocalPort | Format-Table -AutoSize | Out-String
}
catch { "ERREUR : $_" }
finally {
    $udp.Dispose()
    "== retour aux réglages d'origine : " + (Envoyer @{ Action = 'reglages'; Valeur = ($origine | ConvertTo-Json -Compress -Depth 5) })
    Stop-Transcript | Out-Null
}
