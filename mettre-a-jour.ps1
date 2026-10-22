# Met à jour une installation existante de deR4Tizer avec les exécutables de bin\ :
# arrêt du service et de l'interface, copie, redémarrage. Les données (alertes, blocages) sont conservées.
# Se relance tout seul en administrateur (demande UAC) si besoin. Résultat dans mise-a-jour.log.
$ErrorActionPreference = 'Stop'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    $p = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -WindowStyle Hidden `
        -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`""
    Get-Content (Join-Path $PSScriptRoot 'mise-a-jour.log')
    exit $p.ExitCode
}

$log = Join-Path $PSScriptRoot 'mise-a-jour.log'
Start-Transcript -Path $log -Force | Out-Null
try {
    $source = Join-Path $PSScriptRoot 'bin'
    $dest = Join-Path $env:ProgramFiles 'deR4Tizer'
    if (-not (Get-Service deR4Tizer -ErrorAction SilentlyContinue)) { throw 'deR4Tizer n''est pas installé : utilisez installer.ps1.' }

    $interfaceOuverte = [bool](Get-Process deR4Tizer -ErrorAction SilentlyContinue)
    Get-Process deR4Tizer -ErrorAction SilentlyContinue | Stop-Process -Force
    Stop-Service deR4Tizer -Force
    (Get-Service deR4Tizer).WaitForStatus('Stopped', '00:00:20')

    foreach ($exe in 'deR4TizerSvc.exe', 'deR4Tizer.exe') {
        Copy-Item (Join-Path $source $exe) $dest -Force
        Write-Output ("{0} copié ({1})" -f $exe, (Get-FileHash (Join-Path $dest $exe)).Hash.Substring(0, 12))
    }

    Start-Service deR4Tizer
    Write-Output "Service : $((Get-Service deR4Tizer).Status)"

    # Vérifie que le canal de commandes répond (une commande inconnue doit être refusée proprement)
    Start-Sleep -Seconds 3
    try {
        $tube = New-Object IO.Pipes.NamedPipeClientStream '.', 'deR4Tizer', 'InOut'
        $tube.Connect(5000)
        $ecrivain = New-Object IO.StreamWriter $tube; $ecrivain.AutoFlush = $true
        $ecrivain.WriteLine('{"Action":"verification"}')
        Write-Output "Canal de commandes : $((New-Object IO.StreamReader $tube).ReadLine())"
        $tube.Dispose()
    } catch { Write-Output "Canal de commandes : PAS DE RÉPONSE ($($_.Exception.Message))" }
    if ($interfaceOuverte) { Start-Process explorer.exe "`"$dest\deR4Tizer.exe`"" }
    Write-Output 'Mise à jour terminée.'
} catch {
    Write-Output "ÉCHEC : $($_.Exception.Message)"
    exit 1
} finally {
    Stop-Transcript | Out-Null
}
