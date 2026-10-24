# Exécuté DANS Windows Sandbox à l'ouverture de session (lancer.ps1) : joue un scénario d'intégration comme le runner
# de la CI, écrit le tableau et les journaux dans le dossier de sortie monté, relève l'état de Microsoft Defender
# avant et après (lot 3d), puis éteint le bac à sable, qui est alors effacé. Aussi exécuté dans la VM de test
# (tests\vm\lancer.ps1, PowerShell Direct) avec -SansArret : la VM est remise à son instantané par le lanceur.
param([Parameter(Mandatory)] [ValidateSet('installation', 'quarantaine', 'maj', 'lot3d')] [string]$Scenario, [switch]$SansArret)
$sortie = 'C:\sortie'
$entree = 'C:\entree'
New-Item -ItemType Directory -Force -Path $sortie | Out-Null
$env:RUNNER_TEMP = 'C:\d4t-temp'
New-Item -ItemType Directory -Force -Path $env:RUNNER_TEMP | Out-Null
$env:GITHUB_STEP_SUMMARY = Join-Path $sortie "$Scenario-tableau.md"
Remove-Item $env:GITHUB_STEP_SUMMARY -ErrorAction SilentlyContinue
Start-Transcript -LiteralPath (Join-Path $sortie "$Scenario-transcription.txt") -Force | Out-Null
$code = 99
try {
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    "Compte : $([Security.Principal.WindowsIdentity]::GetCurrent().Name) ; administrateur élevé : $admin"
    try { Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, AMProductVersion, AntivirusSignatureVersion | Format-List | Out-String | Set-Content (Join-Path $sortie "$Scenario-defender-avant.txt") }
    catch { "Defender indisponible : $($_.Exception.Message)" | Set-Content (Join-Path $sortie "$Scenario-defender-avant.txt") }
    $version = (Get-Content (Join-Path $entree 'version.txt') -Raw).Trim()
    switch ($Scenario) {
        'installation' { & "$entree\integration\installation.ps1" -Msi "$entree\deR4Tizer.msi" -MsiAncien "$entree\deR4Tizer-ancien.msi" -Version $version }
        'quarantaine' { & "$entree\integration\quarantaine.ps1" -Msi "$entree\deR4Tizer.msi" }
        # VM seulement : empreinte du MSI calculée sur l'hôte et déposée par tests\vm\lancer.ps1
        'lot3d' {
            $attendu = if (Test-Path "$entree\msi-sha256-hote.txt") { (Get-Content "$entree\msi-sha256-hote.txt" -Raw).Trim() } else { '' }
            & "$entree\vm\lot3d.ps1" -Msi "$entree\deR4Tizer.msi" -Sha256Attendu $attendu
        }
        'maj' {
            # Python embarquable (lecture seule) pour le serveur local ; versions préparées par preparer.ps1 -Maj
            $env:PATH = "$entree\python;$env:PATH"
            $c, $n, $p = (Get-Content "$entree\maj\versions.txt" -Raw).Trim() -split ' '
            & "$entree\integration\maj.ps1" -Pki "$entree\maj\pki" -Paquets "$entree\maj\paquets" -Executables "$entree\maj\executables" `
                -ArtefactCi "$entree\maj\ci-bin\deR4TizerSvc.exe" -Courante $c -Nouvelle $n -Precedente $p
        }
    }
    $code = if ($LASTEXITCODE -ne $null) { $LASTEXITCODE } else { 0 }
} catch {
    "EXCEPTION : $($_.Exception.Message)"
    $code = 98
} finally {
    try { Get-MpThreatDetection | Format-List | Out-String | Set-Content (Join-Path $sortie "$Scenario-defender-detections.txt") } catch { }
    Copy-Item (Join-Path $env:RUNNER_TEMP 'journaux-msi') (Join-Path $sortie "$Scenario-journaux") -Recurse -Force -ErrorAction SilentlyContinue
    Stop-Transcript | Out-Null
    # Écrit en dernier : lancer.ps1 attend ce fichier
    Set-Content -LiteralPath (Join-Path $sortie "$Scenario-code.txt") -Value $code -Encoding Ascii
    if (-not $SansArret) { Stop-Computer -Force }
}
