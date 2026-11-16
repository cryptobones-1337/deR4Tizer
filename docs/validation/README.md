# Validation de deR4Tizer (campagne Kali, boucle continue)

Ce dossier documente la campagne de validation de fin de phase 7 et la boucle continue qui la suit (CLAUDE.md,
section 5, campagne Kali).

| Document | Contenu |
|---|---|
| [campagne-kali-phase1.md](campagne-kali-phase1.md) | Audit initial des capacités, cartographie ATT&CK, liste fermée de scénarios (version 1.4, approuvée par l'agent de validation le 2026-11-15) |
| [campagne-kali-premier-passage.md](campagne-kali-premier-passage.md) | Résultats du premier passage (liste v1.3) : chaîne de mesure validée, force brute RDP/SMB, persistance, corrélations système, et le constat produit sur la corrélation R3 |
| [campagne-kali-second-lot.md](campagne-kali-second-lot.md) | Résultats du second lot (liste v1.4) : vol d'identifiants (VOL-001) et listes de menaces (DNS-001, RES-001 + blocage automatique 7 jours), en configurations A et C |
| [campagne-kali-troisieme-lot.md](campagne-kali-troisieme-lot.md) | Résultats du troisième lot (liste v1.4) : détection du changement de serveur DNS sur une carte (DNS-002), en configurations A et C — la **jambe DNS-002 de S-06** (la jambe filtrage de S-06 et DNS-003/S-18 restent à exécuter) |
| [campagne-kali-quatrieme-lot.md](campagne-kali-quatrieme-lot.md) | Résultats du quatrième lot (liste v1.4) : **jambe filtrage de S-06** (un nom listé bloqué en adresse nulle), en configurations A et C — S-06 est couvert en entier ; et pourquoi **DNS-003 (S-18)** n'est pas mesurable de bout en bout en laboratoire |
| [campagne-kali-cinquieme-lot.md](campagne-kali-cinquieme-lot.md) | Résultats du cinquième lot (liste v1.4) : **lot 3d Defender formel** (le produit installé n'est pas détecté par un Defender pleinement actif, configurations A et C, binaire non encore signé) et **sessions standard** (spécificité : N-01 et N-02 sans alerte forte ; N-05 déjà couvert) |

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
