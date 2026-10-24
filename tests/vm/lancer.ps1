# Lance un scénario d'intégration dans la VM Hyper-V de test (Windows 11, Microsoft Defender actif, un compte connecté
# à la console), à la place de Windows Sandbox : mêmes scripts (tests\integration), même exécuteur
# (tests\bac-a-sable\executer.ps1), même dossier d'entrée (preparer.ps1). La VM est remise à son instantané avant et
# après le scénario : chaque scénario part du même Windows, et rien n'y reste (ni MSI, ni clés de test du 3c).
#
# Prérequis : VM avec un instantané « propre » (Defender actif, sans exclusion), PowerShell Direct ; compte
# administrateur de la VM enregistré par Export-Clixml (DPAPI, jamais affiché) ; membre du groupe « Administrateurs
# Hyper-V » ; preparer.ps1 exécuté (et preparer.ps1 -Maj pour le 3c).
#
# Usage : .\tests\vm\lancer.ps1 -Scenario installation|quarantaine|maj [-Vm deR4Tizer-test-26H2] [-Instantane <nom>]
param(
    [Parameter(Mandatory)] [ValidateSet('installation', 'quarantaine', 'maj')] [string]$Scenario,
    [string]$Racine = 'C:\d4t-bac-a-sable',
    [string]$Vm = 'deR4Tizer-test-26H2',
    # Par défaut : l'instantané le plus récent dont le nom commence par « propre »
    [string]$Instantane = '',
    [string]$Identifiants = (Join-Path $env:USERPROFILE '.d4t-vm-credential.xml'),
    [int]$Minutes = 60
)
$ErrorActionPreference = 'Stop'
$entree = Join-Path $Racine 'entree'
$sortie = Join-Path $Racine "sortie-vm-$Scenario-$(Get-Date -Format yyyyMMdd-HHmmss)"
if (-not (Test-Path (Join-Path $entree 'deR4Tizer.msi'))) { throw 'Dossier d''entrée incomplet : lancer d''abord tests\bac-a-sable\preparer.ps1.' }
if ($Scenario -eq 'maj' -and -not (Test-Path (Join-Path $entree 'maj\versions.txt'))) { throw 'Scénario maj : lancer d''abord preparer.ps1 -Maj.' }
$cred = Import-Clixml $Identifiants
$point = if ($Instantane) { Get-VMSnapshot -VMName $Vm -Name $Instantane }
         else { Get-VMSnapshot -VMName $Vm | Where-Object Name -like 'propre*' | Sort-Object CreationTime | Select-Object -Last 1 }
if (-not $point) { throw "Aucun instantané « propre » pour la VM $Vm." }
New-Item -ItemType Directory -Force -Path $sortie | Out-Null

function Remettre {
    Restore-VMSnapshot -VMSnapshot $point -Confirm:$false
    if ((Get-VM $Vm).State -ne 'Running') { Start-VM $Vm }
}
function Session {
    $fin = (Get-Date).AddMinutes(5)
    do {
        $s = try { New-PSSession -VMName $Vm -Credential $cred -ErrorAction Stop } catch { Start-Sleep 5; $null }
    } while (-not $s -and (Get-Date) -lt $fin)
    if (-not $s) { throw "VM $Vm injoignable par PowerShell Direct." }
    $s
}

Write-Host "VM $Vm remise à l'instantané « $($point.Name) », scénario $Scenario, résultats dans $sortie"
$s = $null
try {
    Remettre
    $s = Session
    # Horloge resynchronisée après la reprise de l'instantané (certificats et CRL du 3c)
    $ecart = { [math]::Abs(((Invoke-Command -Session $s { Get-Date }) - (Get-Date)).TotalSeconds) }
    $fin = (Get-Date).AddMinutes(3)
    while ((& $ecart) -gt 120 -and (Get-Date) -lt $fin) {
        Invoke-Command -Session $s { w32tm /resync /force 2>&1 | Out-Null }
        Start-Sleep 10
    }
    if ((& $ecart) -gt 120) { throw 'Horloge de la VM non resynchronisée (écart de plus de 2 minutes).' }
    Invoke-Command -Session $s { Remove-Item C:\entree, C:\sortie -Recurse -Force -ErrorAction SilentlyContinue }
    Copy-Item -Path $entree -Destination 'C:\entree' -ToSession $s -Recurse -Force
    Invoke-Command -Session $s -ArgumentList $Scenario, $Minutes -ScriptBlock {
        param($Scenario, $Minutes)
        # Exécuteur dans un processus séparé, avec un délai maximal ; -SansArret : la VM ne s'éteint pas
        $p = Start-Process powershell.exe -PassThru -WindowStyle Hidden -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', 'C:\entree\executer.ps1', '-Scenario', $Scenario, '-SansArret'
        if (-not $p.WaitForExit($Minutes * 60000)) { $p.Kill(); 'délai dépassé : exécuteur arrêté' }
    }
    Copy-Item -Path 'C:\sortie\*' -Destination $sortie -FromSession $s -Recurse -Force
    Invoke-Command -Session $s { "Windows de la VM : $((Get-CimInstance Win32_OperatingSystem).Version).$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR)" } |
        Set-Content (Join-Path $sortie "$Scenario-vm.txt")
} finally {
    if ($s) { Remove-PSSession $s -ErrorAction SilentlyContinue }
    # VM remise à son instantané : MSI, comptes de test, racine de test approuvée et clés du 3c n'y restent pas
    try { Remettre } catch { Write-Warning "VM non remise à son instantané : $($_.Exception.Message)" }
    if ($Scenario -eq 'maj') {
        Remove-Item -LiteralPath (Join-Path $entree 'maj') -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Join-Path $Racine 'tmp') -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Clés et binaires de test effacés ($(Join-Path $entree 'maj'))"
    }
}
$fichierCode = Join-Path $sortie "$Scenario-code.txt"
if (-not (Test-Path $fichierCode)) { throw "Pas de résultat (voir $sortie)." }
$code = (Get-Content $fichierCode -Raw).Trim()
$tableau = Join-Path $sortie "$Scenario-tableau.md"
if (Test-Path $tableau) { Get-Content $tableau -Encoding UTF8 }
$detections = Join-Path $sortie "$Scenario-defender-detections.txt"
Write-Host "Code de sortie : $code ; détections Defender : $(if ((Test-Path $detections) -and (Get-Content $detections -Raw).Trim()) { 'OUI, voir ' + $detections } else { 'aucune' })"
