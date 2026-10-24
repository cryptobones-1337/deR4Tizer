# Pré-filtre, à lancer avant un passage en Windows Sandbox (quelques minutes au lieu d'une heure). Il attrape le lint
# et des erreurs de syntaxe ou de logique simples ; il ne voit PAS les défauts qui n'apparaissent qu'à l'exécution
# (SACL remplacée en bloc, processus lancé détaché qui ne s'exécute pas, enfant qui survit à l'arrêt du service…).
# Il ne remplace ni le passage en Windows Sandbox ni la relecture externe, en particulier sur les chemins privilégiés.
#
# Contrôles : syntaxe de chaque script PowerShell (analyseur intégré) ; PSScriptAnalyzer (erreurs, tous les scripts
# du dépôt) et cargo clippy, s'ils sont installés (sinon signalé, jamais compté comme réussi) ; données personnelles
# dans les fichiers modifiés depuis la base, commités ou non, et dans les messages de commit (barrière locale
# .git/hooks/garde_pii.py, si elle est installée).
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
    # Exceptions comparées au chemin relatif exact (pas au seul nom de fichier)
    $exceptions = @(@{ Fichier = 'tests\integration\commun.ps1'; Regle = 'PSAvoidUsingConvertToSecureStringWithPlainText' })
    # Tous les scripts du dépôt (racine, installeur, tests), hors dossiers de compilation
    $scripts = @(Get-ChildItem -LiteralPath $depot -Recurse -Filter *.ps1 -File | Where-Object { $_.FullName -notmatch '\\(target|\.git|bin)\\' })
    $r = @(foreach ($f in $scripts) { Invoke-ScriptAnalyzer -Path $f.FullName -Severity Error }) | Where-Object {
        $x = $_; $rel = $x.ScriptPath.Substring($depot.Length + 1)
        -not @($exceptions | Where-Object { $_.Fichier -eq $rel -and $_.Regle -eq $x.RuleName }).Count }
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

# Données personnelles : fichiers modifiés depuis la base (commités ou non) et messages de commit
# Dossier Git commun : dans un worktree, .git est un fichier ; les hooks sont dans le dépôt principal
$gitCommun = git -C $depot rev-parse --git-common-dir
$commun = (Resolve-Path $(if ([IO.Path]::IsPathRooted($gitCommun)) { $gitCommun } else { Join-Path $depot $gitCommun })).Path
$garde = Join-Path $commun 'hooks\garde_pii.py'
if (Test-Path $garde) {
    # La barrière lit ses motifs depuis le dépôt : lancée depuis le dépôt, quel que soit le dossier courant
    Push-Location $depot
    try {
        $env:PYTHONIOENCODING = 'utf-8'
        $modifies = @(@(git diff --name-only "$Base...HEAD") + @(git diff --name-only HEAD) + @(git ls-files --others --exclude-standard) |
            Where-Object { $_ -and (Test-Path -LiteralPath (Join-Path $depot $_)) } | Sort-Object -Unique)
        $trouves = @(foreach ($m in $modifies) { & python -I $garde message (Join-Path $depot $m) 2>$null; if ($LASTEXITCODE) { $m } })
        $messages = Join-Path $env:TEMP "d4t-messages-$PID.txt"
        git log --format='%an <%ae>%n%B' "$Base..HEAD" | Set-Content -LiteralPath $messages -Encoding UTF8
        & python -I $garde message $messages 2>$null
        if ($LASTEXITCODE) { $trouves += 'messages de commit' }
        Remove-Item -LiteralPath $messages -ErrorAction SilentlyContinue
    } finally { Pop-Location }
    if ($trouves.Count) { Noter 'Données personnelles' 'ÉCHOUÉ' ($trouves -join ', ') }
    else { Noter 'Données personnelles' 'RÉUSSI' "$($modifies.Count) fichier(s) et les messages de commit" }
} else { Noter 'Données personnelles' 'NON EXÉCUTÉ' 'barrière locale absente' }

$bilan | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Host
Write-Host 'Pré-filtre seulement : ni le passage en Windows Sandbox ni la relecture externe ne sont remplacés.'
if (@($bilan | Where-Object Resultat -eq 'ÉCHOUÉ').Count) { exit 1 }
