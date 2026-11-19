# Campagne Kali — quatrième lot (filtrage DNS : jambe filtrage de S-06 ; limite de testabilité de DNS-003)

Date : 2026-11-15. Liste des scénarios : v1.4 (`campagne-kali-phase1.md`). Résultats bruts hors dépôt.

> **Note du 2026-11-19** (audit documentaire ; les résultats ci-dessous ne sont pas réécrits) : « couverture » et « vrais positifs mesurés » désignent des essais isolés : aucun nombre d'essais n'est donné, aucune mesure n'est consolidée (10 essais valides, `CLAUDE.md`). Le constat COR-R3 reste ouvert, non corrigé au 2026-11-19.
Aucune donnée personnelle, aucun nom de poste, aucun mot de passe. Adresses du labo : plages de documentation
(RFC 5737) ; noms de test en `.test` (RFC 2606). Prolonge le troisième lot (`campagne-kali-troisieme-lot.md`) : il
exécute **la jambe filtrage (b) de S-06**, après la jambe DNS-002 (a) du troisième lot. S-06 est donc **couvert en
entier**. Il documente aussi pourquoi **DNS-003 (S-18)** n'est pas mesurable de bout en bout en laboratoire.

**Réserve (latences)** : comme aux passages précédents, l'horloge de la VM est décalée dans les résultats bruts ; le
verdict VP repose sur la présence du comportement attendu, pas sur l'heure. Préconditions auto-validées (ci-dessous).

## Jambe filtrage de S-06 (un nom de la liste est bloqué par le résolveur local)

| Scénario | Configuration | Verdict | Résumé |
|---|---|---|---|
| S-06 jambe (b) (filtrage par résolveur local) | C (baseline 100 %) | **VP** | Une liste de filtrage synthétique (un seul nom `.test`, propriétaire de fichier contrôlé) est chargée dans une catégorie active ; après activation du résolveur local sur la carte, une requête vers ce nom est **résolue en adresse nulle** (0.0.0.0) et le blocage **apparaît dans les « derniers blocages »** (nom, liste, catégorie). Un nom **non listé** n'est **pas** bloqué (témoin négatif). |
| S-06 jambe (b) | A (sans baseline) | **VP** | Identique. Le filtrage est une fonction propre du service, indépendante de la baseline. |

**Précondition auto-validée** : l'essai n'est retenu que si (1) la liste synthétique est **effectivement chargée**
(au moins une entrée, vue dans l'état du filtrage) et (2) l'**activation du résolveur sur la carte réussit** ; sinon
l'essai est déclaré invalide, jamais un faux négatif. En laboratoire isolé, le téléchargement réel des listes échoue et
le service **conserve et charge la copie locale** — comportement attendu, exploité ici comme pour les listes de menaces.
**Témoin négatif** : un nom absent de la liste n'est pas résolu en adresse nulle. Entièrement réversible (désactivation
du filtrage + remise à l'instantané).

## Grille de couverture — mise à jour (cumul des quatre lots)

| Domaine / technique | Règle attendue | Config A | Config C |
|---|---|---|---|
| Vol d'identifiants de navigateur (T1555 / T1539) | VOL-001 | **VP (Critique)** | **VP (Critique)** |
| Requête vers domaine malveillant connu (T1071 / renseignement) | DNS-001 | **VP (Critique)** | **VP (Critique)** |
| Connexion vers IP de menace connue (T1071) | RES-001 + blocage auto | **VP (Critique + blocage 7 j)** | **VP (Critique + blocage 7 j)** |
| Changement de serveur DNS sur une carte (T1557) | DNS-002 | **VP (Alerte)** | **VP (Alerte)** |
| Filtrage DNS : nom listé bloqué (adresse nulle) | filtrage par résolveur local | **VP** | **VP** |

**S-06 est désormais couvert en entier** : jambe (a) DNS-002 (troisième lot) et jambe (b) filtrage (ce lot), en
configurations A et C.

## DNS-003 (S-18) : limite de testabilité, pas un défaut

**DNS-003** alerte lorsqu'une carte pointe encore sur le résolveur local alors qu'un **autre programme tient le port DNS
de la boucle locale**. À la lecture de la source (`origin/main`), cette alerte n'est émise qu'au **démarrage du service**,
et **seulement si une carte reste sur la boucle locale après une tentative de remise des cartes**. Or, pour une carte
fonctionnelle, cette remise **réussit** (la carte est rendue à son état d'origine) : un scénario externe
« activer → arrêt brutal du service → un tiers prend le port 53 → redémarrage » **ne laisse donc pas** de carte sur la
boucle, et l'alerte n'est pas émise. La faire émettre exigerait de **forcer l'échec de la remise d'une carte**, ce qui
n'est pas provocable proprement depuis l'extérieur sans dégrader la carte autrement.

**Conclusion** : DNS-003 n'est **pas mesurable en vrai positif de bout en bout** en laboratoire par un moyen externe.
La logique de l'alerte est correcte et **couverte par un test unitaire** du dépôt. Ce point est une **limite de
testabilité en laboratoire**, pas un défaut du produit ; il est signalé au mainteneur.

## Méthode (rappel)

Instantanés de campagne « campagne A » (sans baseline) et « campagne C » (baseline à 100 %). Remise à l'instantané avant
et après chaque essai. Defender jamais modifié à la main. Aucun outil offensif détaillé ; la jambe filtrage de S-06 est
entièrement locale (aucune adresse réelle contactée ; un résolveur de laboratoire sert d'amont, sans accès à Internet).
