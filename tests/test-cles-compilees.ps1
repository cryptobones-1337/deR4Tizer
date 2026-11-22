# Revue de l'auditeur du 2026-11-22, point 3 : la clé du certificat est comparée à la clé compilée dans le service,
# avant toute signature (cles-compilees.ps1, appelé par signer-version.ps1)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\cles-compilees.ps1')
$echecs = 0
function Cas([string]$Nom, [bool]$Ok, [string]$Detail = '') {
    if ($Ok) { Write-Host "RÉUSSI  $Nom" } else { Write-Host "ÉCHOUÉ  $Nom $Detail" -ForegroundColor Red; $script:echecs++ }
}
$a = 'a' * 64; $b = 'b' * 64; $c = 'c' * 64
function Binaire([string]$Contenu) { [byte[]](@(0x4D, 0x5A, 0, 1) + [Text.Encoding]::ASCII.GetBytes("xx$Contenu`0yy") + @(0, 0)) }

Cas 'clé du certificat compilée : accepté' ((Test-ClesCompilees "$a,$b" (Binaire "$a,$b") $b) -eq '')
Cas 'majuscules dans la clé du certificat : accepté' ((Test-ClesCompilees $a (Binaire $a) $a.ToUpperInvariant()) -eq '')
Cas 'autre clé que celle compilée : arrêt' ((Test-ClesCompilees $a (Binaire $a) $b) -match "n'est pas celle compilée")
Cas 'aucune clé compilée : arrêt' ((Test-ClesCompilees '' (Binaire '') $a) -match 'aucune clé compilée')
Cas 'valeur mal formée : arrêt' ((Test-ClesCompilees 'pas-une-cle' (Binaire 'pas-une-cle') $a) -match 'aucune clé compilée')
# Le fichier joint ne peut pas dire autre chose que le binaire
Cas 'fichier différent du binaire : arrêt' ((Test-ClesCompilees "$a,$c" (Binaire "$a,$b") $c) -match 'ne correspond pas')
# Audit de #256, S256-01 : « 0<clé> » compilée (65 caractères hexadécimaux) n'épingle rien ; « <clé> » jointe ne doit pas
# passer. Une lettre non hexadécimale voisine est admise (chaînes accolées dans le binaire)
Cas 'clé précédée d''un caractère hexadécimal : arrêt' ((Test-ClesCompilees $a (Binaire "0$a") $a) -match 'ne correspond pas')
Cas 'clé voisine d''une lettre non hexadécimale : acceptée' ((Test-ClesCompilees $a (Binaire "xyz${a}zz") $a) -eq '')
Cas 'clé suivie d''un caractère hexadécimal : arrêt' ((Test-ClesCompilees $a (Binaire "${a}0") $a) -match 'ne correspond pas')
Cas 'même découpage que le service' ((Get-ClesCompilees "$a ; $b`n$c").Count -eq 3)

if ($echecs) { Write-Host "$echecs échec(s)"; exit 1 }
Write-Host 'Tous les cas réussis.'
