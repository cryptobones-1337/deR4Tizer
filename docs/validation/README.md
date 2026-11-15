# Validation de deR4Tizer (campagne Kali, boucle continue)

Ce dossier documente la campagne de validation de fin de phase 7 et la boucle continue qui la suit (CLAUDE.md,
section 5, campagne Kali).

| Document | Contenu |
|---|---|
| [campagne-kali-phase1.md](campagne-kali-phase1.md) | Audit initial des capacités, cartographie ATT&CK, liste fermée de scénarios (version 1.3, approuvée par l'agent de validation le 2026-11-14) |
| [campagne-kali-premier-passage.md](campagne-kali-premier-passage.md) | Résultats du premier passage (liste v1.3) : chaîne de mesure validée, force brute RDP/SMB, persistance, corrélations système, et le constat produit sur la corrélation R3 |

## À savoir

- Les scénarios sont décrits au niveau du comportement : technique ATT&CK, simulation ou émulation, préconditions,
  résultat attendu, délai maximal, nettoyage, preuves. Aucune commande offensive détaillée.
- Les classes a priori (A à E) de la cartographie sont des **hypothèses**, pas des résultats mesurés.
- L'approbation de la liste est celle de l'agent de validation : elle n'est **ni humaine ni indépendante**. Chaque
  version approuvée est transmise au mainteneur avant exécution.
- Un scénario est publié ici avant sa première exécution ; chaque rapport de campagne, ajouté à ce dossier, note la
  version de la liste exécutée.
- Premier passage publié le 2026-11-15 (liste v1.3) : voir
  [campagne-kali-premier-passage.md](campagne-kali-premier-passage.md). Les résultats bruts restent hors dépôt.
