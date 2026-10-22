# Test du mini-SIEM : stockage des événements, corrélation (règle R1, force brute) et recherche par l'API.
# Provoque 6 échecs d'ouverture de session avec un compte qui n'existe pas (testder4tizer), sur cette machine seulement.
# Se relance en administrateur (UAC). Résultat dans test-siem.log. Le jeton de l'API n'est jamais affiché.
$ErrorActionPreference = 'Stop'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    $p = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -WindowStyle Hidden `
        -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`""
    Get-Content (Join-Path $PSScriptRoot 'test-siem.log')
    exit $p.ExitCode
}

$log = Join-Path $PSScriptRoot 'test-siem.log'
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

function Http($chemin, $jeton) {
    $req = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:8642$chemin")
    $req.Timeout = 15000
    $req.Headers.Add('Authorization', "Bearer $jeton")
    try { $rep = $req.GetResponse() } catch [System.Net.WebException] { $rep = $_.Exception.Response }
    (New-Object System.IO.StreamReader($rep.GetResponseStream())).ReadToEnd()
}

# Tableau JSON en objets (ConvertFrom-Json de PowerShell 5 renvoie le tableau d'un seul bloc)
function Liste($json) { @($json | ConvertFrom-Json | ForEach-Object { $_ }) }

Add-Type -Namespace Test -Name Session -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool LogonUser(string user, string domain, string password, int type, int provider, out System.IntPtr token);
'@

$fichierConfig = Join-Path $dossier 'config.json'
$origine = if (Test-Path $fichierConfig) { Get-Content $fichierConfig -Raw -Encoding UTF8 | ConvertFrom-Json }
           else { [pscustomobject]@{ BlocageAutoMenaces = $true; ReponseAutoRancongiciel = $true; Langue = 'fr' } }
try {
    "== audit des ouvertures de session (Logon) et de la validation des identifiants :"
    auditpol /get /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /r | ConvertFrom-Csv | Select-Object Subcategory, 'Inclusion Setting' | Format-Table -AutoSize | Out-String
    auditpol /get /subcategory:"{0CCE923F-69AE-11D9-BED3-505054503030}" /r | ConvertFrom-Csv | Select-Object Subcategory, 'Inclusion Setting' | Format-Table -AutoSize | Out-String
    "== 4625 dans le journal Sécurité (24 h) : " + @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddDays(-1) } -ErrorAction SilentlyContinue).Count
    "== 4688 (processus) dans le journal Sécurité, 10 dernières minutes : " + @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = (Get-Date).AddMinutes(-10) } -ErrorAction SilentlyContinue).Count
    "== tous événements Sécurité, 10 dernières minutes : " + @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; StartTime = (Get-Date).AddMinutes(-10) } -ErrorAction SilentlyContinue).Count
    "== journal du service (mini-SIEM) :"
    Select-String -Path (Join-Path $dossier 'journal.txt') -Pattern 'mini-SIEM|incident' | Select-Object -Last 6 | ForEach-Object { $_.Line }
    "== stockage :"
    Get-ChildItem (Join-Path $dossier 'siem') | Select-Object Name, Length | Format-Table -AutoSize | Out-String
    $tous = Get-Content (Join-Path $dossier 'siem\*.ndjson') -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json }
    "== répartition par source / type :"
    $tous | Group-Object Source, Type | Sort-Object Count -Descending | Select-Object -First 15 Count, Name | Format-Table -AutoSize | Out-String

    "== 6 échecs d'ouverture de session (compte inexistant testder4tizer, type réseau) :"
    $jeton = [IntPtr]::Zero
    1..6 | ForEach-Object { [void][Test.Session]::LogonUser('testder4tizer', '.', "faux-$_", 3, 0, [ref]$jeton) }
    Start-Sleep -Seconds 8
    "   4625 après le test : " + @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddMinutes(-2) } -ErrorAction SilentlyContinue).Count

    $config = $origine | ConvertTo-Json -Depth 5 | ConvertFrom-Json
    $config | Add-Member -Force -NotePropertyName Api -NotePropertyValue ([pscustomobject]@{ Actif = $true; Port = 8642; Reseau = $false })
    "== API : " + (Envoyer @{ Action = 'reglages'; Valeur = ($config | ConvertTo-Json -Compress -Depth 5) })
    Start-Sleep -Seconds 3
    $cle = (Get-Content (Join-Path $dossier 'api-jeton.txt') -Raw).Trim()

    $evts = Liste (Http '/api/v1/evenements?q=testder4tizer&limite=10' $cle)
    "== /evenements?q=testder4tizer : $(@($evts).Count) événement(s)"
    $evts | Select-Object -First 3 Heure, Niveau, Type, Utilisateur, Message | Format-Table -AutoSize -Wrap | Out-String -Width 200
    $inc = Liste (Http '/api/v1/incidents' $cle)
    "== /incidents : $(@($inc).Count) incident(s), dont :"
    $inc | Select-Object -Last 3 Heure, Regle, Niveau, Titre, Resume | Format-Table -AutoSize -Wrap | Out-String -Width 200
    $alertes = Liste (Http '/api/v1/alertes?limite=3' $cle)
    "== dernières alertes :"
    $alertes | Select-Object Heure, Niveau, Processus, Destination | Format-Table -AutoSize | Out-String -Width 200
    "== /evenements?source=processus&limite=3 :"
    Liste (Http '/api/v1/evenements?source=processus&limite=3' $cle) | Select-Object Heure, Processus, Message | Format-Table -AutoSize -Wrap | Out-String -Width 200
}
catch { "ERREUR : $_" }
finally {
    "== retour aux réglages d'origine : " + (Envoyer @{ Action = 'reglages'; Valeur = ($origine | ConvertTo-Json -Compress -Depth 5) })
    Stop-Transcript | Out-Null
}
