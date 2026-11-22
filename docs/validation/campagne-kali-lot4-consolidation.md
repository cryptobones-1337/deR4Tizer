# Campagne Kali, lot 4 de la couverture ATT&CK : consolidation (10 essais), partie 1 : S-09

- **Date** : 2026-11-22.
- **Liste** : v1.7 (`campagne-kali-phase1.md`, protocole de répétition 3.4, témoins N-02 et N-06, règle D-3).
- **Profil** : `carte-attack.md`, profil validé par le mainteneur le 2026-11-21.
- **Résultats bruts** : hors dépôt, dossiers de sortie du banc nommés plus bas. Aucune donnée personnelle.

Cette partie consolide les deux lignes de la carte que S-09 exerce : T1547.001 (clé Run) et T1053.005 (tâche
planifiée). Les autres lignes du lot 4 suivront dans des parties de ce même rapport, au fil des séries.

## Environnement

| Champ | A | B | C |
|---|---|---|---|
| Binaire du service | construit sur le poste par `preparer.ps1` depuis main 5c33e76 (plus des scripts de test seuls), installé dans les trois instantanés ; SHA-256 8E97200A2820… relevé dans chaque série et par S-19 | identique | identique |
| Instantané | « campagne A 2026-11-22 » | « campagne B 2026-11-22 » (A + Sysmon + Atomic Red Team) | « campagne C 2026-11-22 » (A + trois profils + bureau-distance seule) |
| Windows | 26300.9974 | 26300.9974 | 26300.9974 |
| Sysmon | absent | 15.22 (SHA-256 83D31F24…, configuration minimale du script de préparation : créations de processus, réseau, threads distants, accès à LSASS, clés Run) | absent |
| Atomic Red Team | absent | module 2.3.0, fiches au commit a0e3f9bc… ; aucune fiche utilisée | absent |
| Apprentissage | terminé (instantané ; commande renvoyée par le banc) | terminé | terminé |
| Contrôle de la configuration | s/o | s/o | S-19 essai 4 : RÉUSSI (Defender 28 réglages, 0 plus faible ; scores 100/100/100 ; 0 alerte en 25 min) |

Préparation de B : Microsoft Defender a détecté 24 éléments dans les fichiers d'Atomic Red Team pendant leur pose
(noté, rien n'est touché, comme le 2026-11-14) ; aucune fiche n'a servi à S-09.

## Protocole

Banc `tests/vm/s09.ps1` (#248, #250), lancé par `tests/vm/lancer.ps1 -Scenario s09 -Instantane <instantané>` :
- série de 10 essais enchaînés dans une même session (3.4, point 2), avec remise à l'instantané au début et à la fin ;
- (a) valeur Run de l'utilisateur vers un interpréteur qui écrit un fichier témoin ; (b) tâche planifiée équivalente ;
  nom distinct à chaque essai ;
- apprentissage terminé avant le premier essai ;
- VP : PER-001 au niveau Alerte citant l'entrée ; C : Info d'apprentissage ou de comportement appris ; FN : rien en
  180 s ;
- nettoyage prouvé par le relevé suivant des démarrages automatiques avant l'essai d'après ; collecte Persistance
  « Active » avant chaque essai (D-2) ;
- témoins N-06 (valeur Run vers un programme signé) et N-02 (tâche vers un programme signé), 3 essais chacun : conformes
  si l'entrée est vue au relevé et qu'aucune alerte ne dépasse le niveau Info dans les 180 s ;
- latence : `HeureUtc` de l'alerte moins l'heure de pose de l'entrée (horloge de la VM), arrondie au dixième (moitié
  vers le haut). Le relevé des démarrages automatiques tourne toutes les minutes : la latence suit ce rythme.

## Résultats

| Ligne | Scénario | Config. | Exécutés | Valides | VP | C | FN | D | Détection | Latence médiane / max (s) | Témoin : essais, FP |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1547.001 | S-09 (a) | A | 10 | 10 | 10 | 0 | 0 | 0 | 10/10 | 60,8 / 62,2 | N-06 : 3, 0 |
| T1547.001 | S-09 (a) | B | 10 | 10 | 10 | 0 | 0 | 0 | 10/10 | 60,7 / 62,2 | N-06 : 3, 0 |
| T1547.001 | S-09 (a) | C | 10 | 10 | 10 | 0 | 0 | 0 | 10/10 | 60,4 / 61,8 | N-06 : 3, 0 |
| T1053.005 | S-09 (b) | A | 10 | 10 | 10 | 0 | 0 | 0 | 10/10 | 60,1 / 61,7 | N-02 : 3, 0 |
| T1053.005 | S-09 (b) | B | 10 | 10 | 10 | 0 | 0 | 0 | 10/10 | 61,2 / 62,7 | N-02 : 3, 0 |
| T1053.005 | S-09 (b) | C | 10 | 10 | 10 | 0 | 0 | 0 | 10/10 | 60,1 / 62,6 | N-02 : 3, 0 |

Les témoins ont tous donné PER-001 au niveau Info (entrée nouvelle, sans remarque), entrée vue au relevé : conformes.
Aucun arrêt de série. Règle D-3 : une alerte de persistance (PER-001 Alerte) sur la tâche d'exécution du banc dans
chaque configuration (A, B et C), étiquetée artefact et exclue. Sorties : `sortie-vm-s09-20261122-083803` (A),
`-102956` (B), `-093213` (C).

Pilotes, hors décompte : deux séries en configuration A sur l'instantané « propre » avec installation, le 2026-11-22
(binaire main 0bfea32 puis banc final) : 20/20 chacune, témoins conformes.

## Avant et après

| Ligne | État avant (carte du 2026-11-21) | État après | Ligne de la carte modifiée |
|---|---|---|---|
| T1547.001 | Testé en labo, clé Run (S-09, 2026-11-15) | Testé en labo, consolidé, clé Run : 10/10 en A, B et C (campagne Kali, lot 4, 2026-11-22) | Persistance / T1547.001 (reste à faire : dossier Démarrage, hors liste) |
| T1053.005 | Testé en labo (S-09, 2026-11-15) | Testé en labo, consolidé : 10/10 en A, B et C (campagne Kali, lot 4, 2026-11-22) | Exécution / T1053.005 |

Bilan de la carte : « consolidé » 1 → 3 ; « testé en labo, non consolidé » 13 → 11.

## Limites

- Campagne menée par un agent dans une VM de test, sur une liste approuvée par l'agent de validation : ni humaine ni
  indépendante.
- Une seule forme d'action par technique (interpréteur qui écrit un fichier témoin) ; le dossier Démarrage
  (T1547.001) n'est pas exercé.
- La latence de 60 s environ est celle du relevé des démarrages automatiques, toutes les minutes ; une persistance posée
  et retirée entre deux relevés n'est pas vue.
- Faux positifs comptés sur les témoins seulement ; aucune mesure sur poste réel.
