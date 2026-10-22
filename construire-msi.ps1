# Construit le paquet d'installation bin\deR4Tizer.msi avec WiX 3.14 (licence MS-RL, sans redevance).
# Prérequis : bin\deR4TizerSvc.exe et bin\deR4Tizer.exe (compiler.ps1) ; WiX 3.14 dans $env:WIX ou
# %USERPROFILE%\.der4tizer-outils\wix314 (archive wix314-binaries.zip des versions officielles de WiX).
param([string]$Version)
$ErrorActionPreference = 'Stop'
if (-not $Version) {
    $Version = (Select-String -Path (Join-Path $PSScriptRoot 'service-rs\src\commun.rs') -Pattern 'pub const VERSION: &str = "([^"]+)"').Matches[0].Groups[1].Value
}
# Windows Installer exige trois nombres (4.1 → 4.1.0)
$v = ($Version.Split('.') + @('0', '0', '0'))[0..2] -join '.'
$wix = @($env:WIX, (Join-Path $env:USERPROFILE '.der4tizer-outils\wix314')) | Where-Object { $_ -and (Test-Path (Join-Path $_ 'candle.exe')) } | Select-Object -First 1
if (-not $wix) { throw 'WiX 3.14 introuvable : définissez WIX ou décompressez wix314-binaries.zip dans %USERPROFILE%\.der4tizer-outils\wix314.' }

$racine = $PSScriptRoot
$bin = Join-Path $racine 'bin'
$obj = Join-Path $racine 'installeur\obj'
New-Item -ItemType Directory -Force -Path $obj | Out-Null
foreach ($f in 'deR4TizerSvc.exe', 'deR4Tizer.exe') { if (-not (Test-Path (Join-Path $bin $f))) { throw "$f introuvable dans bin : lancez d'abord compiler.ps1." } }

& (Join-Path $wix 'candle.exe') -nologo -arch x64 -ext WixUtilExtension -ext WixUIExtension `
    "-dVersion=$v" "-dBin=$bin" "-dSrc=$(Join-Path $racine 'src')" "-dInstalleur=$(Join-Path $racine 'installeur')" `
    -out "$obj\" (Join-Path $racine 'installeur\deR4Tizer.wxs')
if ($LASTEXITCODE) { throw 'Échec de candle.' }
& (Join-Path $wix 'light.exe') -nologo -ext WixUtilExtension -ext WixUIExtension -cultures:fr-FR -spdb `
    -out (Join-Path $bin 'deR4Tizer.msi') (Join-Path $obj 'deR4Tizer.wixobj')
if ($LASTEXITCODE) { throw 'Échec de light.' }

# Signature du paquet, comme les exécutables (compiler.ps1)
if ($env:DER4TIZER_CERT_SHA1) {
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
    & $signtool.FullName sign /sha1 $env:DER4TIZER_CERT_SHA1 /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /d deR4Tizer (Join-Path $bin 'deR4Tizer.msi')
    if ($LASTEXITCODE) { throw 'Échec de la signature du paquet.' }
}
Get-Item (Join-Path $bin 'deR4Tizer.msi') | Select-Object Name, @{ n = 'Ko'; e = { [int]($_.Length / 1KB) } }, @{ n = 'Version'; e = { $v } } | Format-Table -AutoSize
