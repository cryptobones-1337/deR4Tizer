# Campagne Kali — troisième lot (changement de serveur DNS, règle DNS-002)

Date : 2026-11-15. Liste des scénarios : v1.4 (`campagne-kali-phase1.md`). Résultats bruts hors dépôt.

> **Note du 2026-11-19** (audit documentaire ; les résultats ci-dessous ne sont pas réécrits) : « couverture » et « vrais positifs mesurés » désignent des essais isolés : aucun nombre d'essais n'est donné, aucune mesure n'est consolidée (10 essais valides, `CLAUDE.md`). Le constat COR-R3 reste ouvert, non corrigé au 2026-11-19.
Aucune donnée personnelle, aucun nom de poste, aucun mot de passe. Adresses du labo : plages de documentation
(RFC 5737), non routables. Prolonge le second lot (`campagne-kali-second-lot.md`), qui notait S-06 « non exécuté » :
ce lot exécute **la jambe DNS-002 de S-06** (changement de serveur DNS). La liste v1.4 définit S-06 en **deux jambes** —
(a) DNS-002 et (b) le filtrage par résolveur local (un nom `.test` de la liste résolu en adresse nulle, dans les
« derniers blocages ») ; **seule la jambe (a) est exécutée ici**. La jambe filtrage (b) et DNS-003 (S-18) restent pour
un prochain lot (voir « Portée de ce lot »).

**Réserve (latences)** : comme aux passages précédents, l'horloge de la VM est décalée dans les résultats bruts ; le
verdict VP repose sur la présence règle/niveau/entité, pas sur l'heure. Précondition auto-validée (voir ci-dessous).

## Changement de serveur DNS sur une carte (DNS-002)

| Scénario | Configuration | Verdict | Résumé |
|---|---|---|---|
| S-06 (un programme règle un serveur DNS statique sur une carte physique) | C (baseline 100 %) | **VP (Alerte)** | Le réglage d'un **serveur DNS statique** (adresse de documentation) sur la **carte physique** active fait passer ses résolutions par ce serveur. Le service le détecte au relevé périodique des cartes : **1 alerte DNS-002** (niveau Alerte, score 3) « serveur DNS réglé à la main », citant la carte et le nouveau serveur. |
| S-06 | A (sans baseline) | **VP (Alerte)** | Identique. La détection repose sur la lecture des cartes par le service lui-même (collecte ConfigDns), indépendante de la baseline. |

**Précondition auto-validée** : l'essai n'est retenu que si (1) la collecte **ConfigDns** est « Active » (le service lit
bien les cartes), (2) la carte retenue est **physique** (Ethernet ou Wi-Fi) et (3) son serveur DNS n'était **pas déjà
réglé à la main** au départ (référence prise sur une configuration donnée par le réseau). À défaut, l'essai est déclaré
invalide, jamais un faux négatif. Les deux configurations ont satisfait ces trois conditions.

**Témoin négatif (N-05)** : après la mesure, la carte est **remise en configuration automatique** (serveur DNS redonné
par le réseau). Ce retour ne doit **pas** produire d'alerte DNS-002 (changement attendu, non réglé à la main). Les deux
configurations l'ont confirmé : **zéro alerte** DNS-002 au retour. La règle distingue donc un réglage manuel d'un
changement normal.

## Portée de ce lot

Ce lot exécute **la jambe DNS-002 de S-06** : la détection du changement de serveur DNS, entièrement locale et non
destructrice (réglage réversible, remise à l'instantané en fin d'essai). Il **ne couvre pas la jambe filtrage de S-06**
(activation du moteur de filtrage par résolveur local, réglage des cartes sur le résolveur de deR4Tizer, un nom `.test`
résolu en adresse nulle et vu dans les « derniers blocages »), **ni la règle DNS-003** (port de la boucle locale tenu par
un autre programme, S-18) — deux scénarios distincts. Tous deux demandent un préalable de labo supplémentaire (l'amont
DNS du labo doit répondre au nom de contrôle que le service interroge avant de régler les cartes) et une orchestration
plus intrusive, prévus pour un prochain lot.

## Grille de couverture — mise à jour (cumul premier + second + troisième lot)

| Domaine / technique | Règle attendue | Config A | Config C |
|---|---|---|---|
| Vol d'identifiants de navigateur (T1555 / T1539) | VOL-001 | **VP (Critique)** | **VP (Critique)** |
| Requête vers domaine malveillant connu (T1071 / renseignement) | DNS-001 | **VP (Critique)** | **VP (Critique)** |
| Connexion vers IP de menace connue (T1071) | RES-001 + blocage auto | **VP (Critique + blocage 7 j)** | **VP (Critique + blocage 7 j)** |
| Changement de serveur DNS sur une carte (T1557 / détournement de résolution) | DNS-002 | **VP (Alerte)** | **VP (Alerte)** |

Avec les deux premiers lots, la campagne couvre désormais, en vrais positifs mesurés : **témoin négatif propre,
durcissement, force brute (RDP, SMB), persistance, corrélations système, vol d'identifiants, renseignement sur les
menaces (domaine + IP + blocage), et détournement du serveur DNS d'une carte**. Le constat produit R3 (corrélation
« nouveau compte administrateur ») reste ouvert, correctif proposé au mainteneur.

## Scénarios restant pour un prochain lot

- **Jambe filtrage de S-06** (résolveur local branché sur les cartes : un nom `.test` de la liste résolu en adresse
  nulle, vu dans les « derniers blocages ») et **S-18 (DNS-003)** (port de la boucle locale tenu par un autre
  programme) : deux scénarios distincts, testables, code présent dans la source ; même préalable de labo à monter
  (amont DNS du labo répondant au nom de contrôle d'activation) et orchestration intrusive mais bornée par l'instantané.

## Méthode (rappel)

Instantanés de campagne « campagne A » (sans baseline) et « campagne C » (baseline à 100 % appliquée par le service).
Remise à l'instantané avant et après chaque essai. Defender jamais modifié à la main. Aucun outil offensif détaillé ;
S-06 est entièrement local (aucune orchestration externe) ; aucune adresse réelle n'est contactée (serveur DNS de
documentation, jamais joint).
