# Clés de signature compilées dans le service (revue de l'auditeur du 2026-11-22, point 3). Fichier chargé par
# signer-version.ps1 (point-source) et par tests\test-cles-compilees.ps1 : aucune action à son chargement.
#
# Le job « compiler » de la publication joint à l'artefact « a-signer » le fichier cles-compilees.txt, la valeur exacte
# de DER4TIZER_CLES_SIGNATURE donnée à la compilation. Avant de signer, on vérifie :
#   1. que ce fichier porte au moins une clé (sinon le service n'installerait aucune mise à jour) ;
#   2. que cette valeur est bien dans l'exécutable du service (option_env! l'y écrit telle quelle) : le fichier ne peut
#      pas dire autre chose que ce qui a été compilé ;
#   3. que la clé du certificat qui va signer est l'une d'elles : sinon les postes refuseraient cette version et les
#      suivantes signées par ce certificat.
# Même découpage que le service (maj::cles_epinglees) : virgule, point-virgule ou blanc ; 64 caractères hexadécimaux.

function Get-ClesCompilees([string]$Brut) {
    @("$Brut" -split '[,; \r\n\t]' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ -match '^[0-9a-f]{64}$' })
}

# Rend un texte vide si tout concorde, sinon la raison de l'arrêt
function Test-ClesCompilees([string]$Brut, [byte[]]$Service, [string]$CleCertificat) {
    $cles = Get-ClesCompilees $Brut
    if ($cles.Count -eq 0) { return "aucune clé compilée dans le service (CLE_SIGNATURE vide ou mal formée à la compilation) : il n'installerait aucune mise à jour" }
    # Latin-1 : un octet par caractère, la valeur ASCII se retrouve telle quelle
    $texte = [Text.Encoding]::GetEncoding(28591).GetString($Service)
    if (-not $texte.Contains($Brut)) { return "cles-compilees.txt ne correspond pas à la valeur compilée dans deR4TizerSvc.exe" }
    if ("$CleCertificat".ToLowerInvariant() -notin $cles) { return "la clé de ce certificat ($CleCertificat) n'est pas celle compilée dans le service ($($cles -join ', ')) : les postes refuseraient cette version" }
    return ''
}
