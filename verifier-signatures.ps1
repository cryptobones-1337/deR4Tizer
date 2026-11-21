# Vérifie, avant toute publication, que chaque fichier porte une signature Authenticode valide, horodatée, faite
# par une clé épinglée (CLE_SIGNATURE : empreintes SHA-256 de la clé publique du certificat, séparées par des
# virgules ; même calcul que natif::cle_signataire_verifiee, sur SubjectPublicKeyInfo.PublicKey). Échec fermé :
# liste de clés vide ou invalide, fichier absent, signature non valide, sans horodatage ou d'une autre clé : code 1,
# rien n'est publié. Utilisé par .github/workflows/publication.yml et par la procédure de signature locale.
# Usage : .\verifier-signatures.ps1 -Cles <empreinte[,empreinte]> -Fichiers bin\deR4Tizer.msi, bin\deR4TizerSvc.exe, bin\deR4Tizer.exe
param(
    [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Cles,
    [Parameter(Mandatory = $true)][string[]]$Fichiers
)
$ErrorActionPreference = 'Stop'
$liste = @("$Cles" -split ',' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
$invalides = @($liste | Where-Object { $_ -notmatch '^[0-9a-f]{64}$' })
if ($liste.Count -eq 0 -or $invalides.Count) {
    Write-Host "Publication refusée : CLE_SIGNATURE absente ou invalide ($($invalides -join ', '))."
    exit 1
}
$refus = @()
foreach ($f in $Fichiers) {
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { $refus += "$f : absent"; continue }
    $s = Get-AuthenticodeSignature -LiteralPath $f
    if ($s.Status -ne 'Valid') { $refus += "$f : signature $($s.Status) ($($s.StatusMessage))"; continue }
    if (-not $s.TimeStamperCertificate) { $refus += "$f : signature sans horodatage"; continue }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $cle = -join ($sha.ComputeHash($s.SignerCertificate.PublicKey.EncodedKeyValue.RawData) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
    if ($cle -notin $liste) { $refus += "$f : clé du signataire $cle non épinglée"; continue }
    Write-Host "$f : signature valide, horodatée, clé épinglée $cle ($($s.SignerCertificate.Subject))"
}
if ($refus.Count) {
    Write-Host "Publication refusée :"
    $refus | ForEach-Object { Write-Host "  $_" }
    exit 1
}
Write-Host "$($Fichiers.Count) fichier(s) signés par une clé épinglée."
exit 0
