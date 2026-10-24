# Scénarios d'intégration à rejouer en Windows Sandbox pour un changement, d'après les fichiers modifiés depuis une
# base (par défaut origin/main). Sert aux itérations : la preuve avant fusion reste le passage complet (3a, 3b et 3c
# sur le commit à fusionner, CLAUDE.md section 4). Par prudence, un fichier inconnu de la table fait tout rejouer.
#
# Usage : .\tests\bac-a-sable\scenarios-concernes.ps1 [-Base origin/main]
# Sortie : liste des scénarios (installation, quarantaine, maj), vide si aucun ; détail des raisons sur l'hôte.
param([string]$Base = 'origin/main')
$ErrorActionPreference = 'Stop'
$depot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$tous = @('installation', 'quarantaine', 'maj')

# Règles dans l'ordre : la première qui correspond au chemin donne ses scénarios
$regles = @(
    # Aucun effet sur le service installé
    @{ Motif = '^(docs/|README\.md$|LICENSE|CLAUDE\.md$|\.gitignore$|\.gitattributes$)'; Scenarios = @() }
    @{ Motif = '^\.github/'; Scenarios = @() }                       # CI seulement (jouée par GitHub)
    @{ Motif = '^service-rs/src/tests\.rs$'; Scenarios = @() }       # tests unitaires : déjà joués par preparer.ps1
    # Scripts des scénarios
    @{ Motif = '^tests/integration/installation\.ps1$'; Scenarios = @('installation') }
    @{ Motif = '^tests/integration/quarantaine\.ps1$'; Scenarios = @('quarantaine') }
    @{ Motif = '^tests/integration/(maj|maj-pki|maj-paquets)\.ps1$|^tests/integration/serveur-maj\.py$'; Scenarios = @('maj') }
    @{ Motif = '^tests/integration/commun\.ps1$|^tests/bac-a-sable/(preparer|lancer|executer)\.ps1$'; Scenarios = $tous }
    @{ Motif = '^tests/bac-a-sable/(prefiltre|scenarios-concernes)\.ps1$'; Scenarios = @() }   # outils, hors des passages
    # Service : modules transverses (droits, fichiers par handle, canal, démarrage) : tout
    @{ Motif = '^service-rs/src/(natif|commun|protection|main|canal|moniteur)\.rs$'; Scenarios = $tous }
    @{ Motif = '^service-rs/src/maj\.rs$'; Scenarios = @('installation', 'maj') }
    @{ Motif = '^service-rs/src/(reponse|hygiene|vol_donnees)\.rs$'; Scenarios = @('installation', 'quarantaine') }
    # Autre module du service : installation et démarrage au moins
    @{ Motif = '^service-rs/src/[a-z_]+\.rs$'; Scenarios = @('installation') }
    # Compilation, paquet, interface : tout
    @{ Motif = '^(service-rs/(Cargo\.(toml|lock)|\.cargo/)|installeur/|construire-msi\.ps1$|compiler(-rs)?\.ps1$|src/)'; Scenarios = $tous }
)

$fichiers = @(git -C $depot diff --name-only "$Base...HEAD") + @(git -C $depot diff --name-only HEAD) | Where-Object { $_ } | Sort-Object -Unique
$retenus = New-Object System.Collections.Generic.HashSet[string]
foreach ($f in $fichiers) {
    $r = $regles | Where-Object { $f -match $_.Motif } | Select-Object -First 1
    $s = if ($r) { $r.Scenarios } else { $tous }
    Write-Host ("  {0} -> {1}{2}" -f $f, $(if ($s.Count) { $s -join ', ' } else { 'aucun' }), $(if ($r) { '' } else { ' (inconnu : tout, par prudence)' }))
    foreach ($x in $s) { [void]$retenus.Add($x) }
}
$tous | Where-Object { $retenus.Contains($_) }
