# Version d'un paquet MSI (propriété ProductVersion), lue par l'interface COM de Windows Installer.
# Utilisé par signer-version.ps1 ; testé par tests\test-version-msi.ps1 sur le MSI construit par la CI.
# Le chemin est typé [string] : un résultat de Join-Path arrive enveloppé (PSObject) et l'appel COM OpenDatabase le
# refuse (« Type mismatch », 0x80020005). Défaut trouvé par la répétition de signature du 2026-11-22.
function Get-VersionMsi([string]$Chemin) {
    if (-not (Test-Path -LiteralPath $Chemin -PathType Leaf)) { throw "MSI introuvable : $Chemin" }
    $installeur = New-Object -ComObject WindowsInstaller.Installer
    $base = $installeur.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installeur, @([string]$Chemin, 0))
    $vue = $base.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $base, @("SELECT Value FROM Property WHERE Property='ProductVersion'"))
    try {
        $vue.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $vue, $null) | Out-Null
        $ligne = $vue.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $vue, $null)
        if ($null -eq $ligne) { return '' }
        [string]$ligne.GetType().InvokeMember('StringData', 'GetProperty', $null, $ligne, @(1))
    } finally {
        $vue.GetType().InvokeMember('Close', 'InvokeMethod', $null, $vue, $null) | Out-Null
    }
}
