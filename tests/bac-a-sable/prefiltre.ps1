# Pré-filtre, à lancer avant un passage en Windows Sandbox (quelques minutes au lieu d'une heure). Il attrape le lint
# et des erreurs de syntaxe ou de logique simples ; il ne voit PAS les défauts qui n'apparaissent qu'à l'exécution
# (SACL remplacée en bloc, processus lancé détaché qui ne s'exécute pas, enfant qui survit à l'arrêt du service…).
# Il ne remplace ni le passage en Windows Sandbox ni la relecture externe, en particulier sur les chemins privilégiés.
#
# Contrôles : syntaxe de chaque script PowerShell (analyseur intégré) ; PSScriptAnalyzer (erreurs) et cargo clippy,
# s'ils sont installés (sinon signalé, jamais compté comme réussi) ; données personnelles dans les fichiers modifiés
# depuis la base (barrière locale .git/hooks/garde_pii.py, si elle est installée).
#
# Usage : .\tests\bac-a-sable\prefiltre.ps1 [-Base origin/main]
param([string]$Base = 'origin/main')
# Continue : sous Windows PowerShell 5.1, avec Stop, la sortie d'erreur d'un programme (cargo, python) devient une
# erreur fatale ; le résultat se lit au code de retour
$ErrorActionPreference = 'Continue'
$depot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$bilan = New-Object System.Collections.Generic.List[object]
function Noter([string]$Controle, [string]$Resultat, [string]$Detail = '') { $bilan.Add([pscustomobject]@{ Controle = $Controle; Resultat = $Resultat; Detail = $Detail }) }

# Syntaxe des scripts PowerShell
$erreurs = foreach ($f in Get-ChildItem -LiteralPath $depot -Recurse -Filter *.ps1 -File | Where-Object { $_.FullName -notmatch '\\(target|\.git)\\' }) {
    $e = $null
    [void][Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$e)
    foreach ($x in $e) { "$($f.FullName.Substring($depot.Length + 1)):$($x.Extent.StartLineNumber) $($x.Message)" }
}
if ($erreurs) { Noter 'Syntaxe PowerShell' 'ÉCHOUÉ' ($erreurs -join ' ; ') } else { Noter 'Syntaxe PowerShell' 'RÉUSSI' }

# PSScriptAnalyzer : erreurs seulement
if (Get-Module -ListAvailable PSScriptAnalyzer) {
    # Exceptions justifiées, par fichier et par règle (jamais une règle entière) :
    # - commun.ps1, PSAvoidUsingConvertToSecureStringWithPlainText : mot de passe aléatoire, tiré en mémoire, jamais
    #   affiché, d'un compte de test jetable (Windows Sandbox ou runner de CI) ; aucun mot de passe écrit en clair
    $exceptions = @(@{ Fichier = 'commun.ps1'; Regle = 'PSAvoidUsingConvertToSecureStringWithPlainText' })
    $r = @(Invoke-ScriptAnalyzer -Path (Join-Path $depot 'tests') -Recurse -Severity Error | Where-Object {
        $x = $_; -not @($exceptions | Where-Object { $_.Fichier -eq $x.ScriptName -and $_.Regle -eq $x.RuleName }).Count })
    if ($r.Count) { Noter 'PSScriptAnalyzer (erreurs)' 'ÉCHOUÉ' (($r | ForEach-Object { "$($_.ScriptName):$($_.Line) $($_.RuleName)" }) -join ' ; ') }
    else { Noter 'PSScriptAnalyzer (erreurs)' 'RÉUSSI' }
} else { Noter 'PSScriptAnalyzer (erreurs)' 'NON EXÉCUTÉ' 'module absent' }

# cargo clippy (avertissements signalés, non bloquants : base existante à assainir d'abord)
$env:PATH = "$(Join-Path $env:USERPROFILE '.cargo\bin');$env:PATH"
$chaine = 'stable-x86_64-pc-windows-msvc'
$sortie = & cargo "+$chaine" clippy --version 2>&1
if ($LASTEXITCODE -eq 0) {
    Push-Location (Join-Path $depot 'service-rs')
    try { $c = @(& cargo "+$chaine" clippy --release --all-targets 2>&1 | ForEach-Object { "$_" }); $code = $LASTEXITCODE } finally { Pop-Location }
    $av = @($c | Where-Object { $_ -match '^warning: ' -and $_ -notmatch 'generated \d+ warning' }).Count
    if ($code) { Noter 'cargo clippy' 'ÉCHOUÉ' (($c | Where-Object { $_ -match '^error' } | Select-Object -First 5) -join ' ; ') }
    else { Noter 'cargo clippy' 'RÉUSSI' "$av avertissement(s)" }
} else { Noter 'cargo clippy' 'NON EXÉCUTÉ' 'composant clippy absent de la chaîne MSVC' }

# Données personnelles dans les fichiers modifiés depuis la base
$garde = Join-Path $depot '.git\hooks\garde_pii.py'
if (Test-Path $garde) {
    $modifies = @(git -C $depot diff --name-only "$Base...HEAD") | Where-Object { $_ -and (Test-Path (Join-Path $depot $_)) }
    $trouves = foreach ($m in $modifies) {
        $env:PYTHONIOENCODING = 'utf-8'
        & python -I $garde message (Join-Path $depot $m) 2>$null
        if ($LASTEXITCODE) { $m }
    }
    if ($trouves) { Noter 'Données personnelles (fichiers modifiés)' 'ÉCHOUÉ' ($trouves -join ', ') } else { Noter 'Données personnelles (fichiers modifiés)' 'RÉUSSI' "$(@($modifies).Count) fichier(s)" }
} else { Noter 'Données personnelles (fichiers modifiés)' 'NON EXÉCUTÉ' 'barrière locale absente' }

$bilan | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Host
Write-Host 'Pré-filtre seulement : ni le passage en Windows Sandbox ni la relecture externe ne sont remplacés.'
if (@($bilan | Where-Object Resultat -eq 'ÉCHOUÉ').Count) { exit 1 }
