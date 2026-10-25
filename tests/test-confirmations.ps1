# Compile l'interface d'un dépôt et vérifie que chaque confirmation de Canal.Decrire neutralise un texte piégé venu de
# la commande (inversion du sens d'écriture, retour à la ligne injecté). Usage (Windows PowerShell 5.1) :
#   powershell -File tests\test-confirmations.ps1 [-Depot <racine du dépôt>]
param([string]$Depot = (Split-Path $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$src = Join-Path $Depot 'src'
$out = Join-Path $env:TEMP ("d4t-harnais-" + [guid]::NewGuid().ToString('N') + '.exe')
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $csc /nologo /platform:anycpu /codepage:65001 /target:winexe /r:System.dll /r:System.Core.dll /r:System.Web.Extensions.dll /r:System.ServiceProcess.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll "/out:$out" "$src\Commun.cs" "$src\Langue.cs" "$src\Theme.cs" "$src\Gui.cs" "$src\Reglages.cs" "$src\Siem.cs" "$src\Trafic.cs" "$src\Reseau.cs" "/resource:$src\carte-pays.txt,carte-pays.txt" | Out-Null
if ($LASTEXITCODE) { throw 'compilation' }
$asm = [Reflection.Assembly]::LoadFile($out)
$canal = $asm.GetType('DeR4Tizer.Canal'); $cmdT = $asm.GetType('DeR4Tizer.Commande')
$piege = "C:\x\" + [char]0x202E + "txt.exe" + "`r`nLIGNE-INJECTEE"
$actions = 'bloquer', 'bloquerIp', 'debloquer', 'config', 'tuer', 'tuerChaine', 'suspendre', 'reprendre', 'quarantaine', 'restaurer', 'restaurerRepli', 'isolerProgramme', 'baseline', 'exception', 'majConfig', 'autoriserLecteur', 'inconnue'
$ko = 0
foreach ($a in $actions) {
    $c = [Activator]::CreateInstance($cmdT)
    $c.Action = $a; $c.Cible = $piege; $c.Ip = $piege; $c.Valeur = $piege
    if ($a -eq 'majConfig') { $c.Valeur = '{"Auto":false,"Url":"https://exemple.invalid/' + [char]0x202E + 'x\r\nLIGNE-INJECTEE"}' }
    if ($a -eq 'inconnue') { $c.Action = "inconnue" + [char]0x202E + "`nLIGNE-INJECTEE" }
    try { $t = $canal.GetMethod('Decrire').Invoke($null, @($c)) } catch { "$a : EXCEPTION $($_.Exception.InnerException.Message)"; $ko++; continue }
    $mauvais = @($t.ToCharArray() | Where-Object { $_ -eq [char]0x202E -or $_ -eq "`r" }).Count -gt 0 -or $t -match "`nLIGNE-INJECTEE"
    if ($mauvais) { $ko++; "$a : NON NEUTRALISÉ" } else { "$a : ok" }
}
"bilan : $ko action(s) non neutralisée(s) sur $($actions.Count)"
Remove-Item $out -ErrorAction SilentlyContinue
if ($ko) { exit 1 }
