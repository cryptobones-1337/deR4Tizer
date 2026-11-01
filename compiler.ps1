# Compile deR4Tizer :
#   - l'interface (deR4Tizer.exe) avec le compilateur C# fourni par Windows (.NET Framework 4.8) ;
#   - le service (deR4TizerSvc.exe) en Rust, via compiler-rs.ps1.
$ErrorActionPreference = 'Stop'
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$src = Join-Path $PSScriptRoot 'src'
$sortie = Join-Path $PSScriptRoot 'bin'
New-Item -ItemType Directory -Force -Path $sortie | Out-Null

$icone = "$src\deR4Tizer.ico"
if (-not (Test-Path $icone)) { & (Join-Path $PSScriptRoot 'icone.ps1') | Out-Null }

& $csc /nologo /optimize+ /platform:anycpu /codepage:65001 /target:winexe `
    /r:System.dll /r:System.Core.dll /r:System.Web.Extensions.dll /r:System.ServiceProcess.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll `
    "/win32icon:$icone" "/resource:$icone,deR4Tizer.ico" "/out:$sortie\deR4Tizer.exe" "$src\Commun.cs" "$src\Langue.cs" "$src\Theme.cs" "$src\Gui.cs" "$src\Reglages.cs" "$src\Siem.cs" "$src\Incidents.cs" "$src\Trafic.cs" "$src\Reseau.cs" "/resource:$src\carte-pays.txt,carte-pays.txt"
if ($LASTEXITCODE) { throw 'Échec de la compilation de l''interface.' }

# -InterfaceSeulement : la CI compile le service elle-même (chaîne MSVC de GitHub Actions)
if ($args -notcontains '-InterfaceSeulement') { & (Join-Path $PSScriptRoot 'compiler-rs.ps1') }

# Signature de code, si un certificat est disponible sur cette machine (empreinte dans DER4TIZER_CERT_SHA1) :
# sans signature, Windows affiche « éditeur inconnu » et la mise à jour automatique ne s'installe pas
if ($env:DER4TIZER_CERT_SHA1) {
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signtool) { throw 'signtool.exe introuvable (installez le SDK Windows).' }
    & $signtool.FullName sign /sha1 $env:DER4TIZER_CERT_SHA1 /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 (Join-Path $sortie '*.exe')
    if ($LASTEXITCODE) { throw 'Échec de la signature.' }
}

Get-ChildItem $sortie -Filter *.exe | Select-Object Name, @{ n = 'Ko'; e = { [int]($_.Length / 1KB) } } | Format-Table -AutoSize
