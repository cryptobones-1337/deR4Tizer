# Modèle d'événement (phase 3)

Ce document décrit le format des alertes du service (`Alerte`, `service-rs/src/commun.rs`) tel que la phase 3 le
versionne. Depuis la PR 3.1, les champs `Modele`, `Regle` et `Collecte` existent (et `Signature` depuis la PR 3.1b) et toute nouvelle alerte porte `Modele` 1, et `alertes.json`
est lu élément par élément. Depuis la PR 3.2, chaque alerte porte l'identifiant de sa règle dans `Regle` (registre
`regles.rs`). Depuis la PR 3.3c, `Collecte` porte une **présomption** de la collecte d'où vient l'alerte
(`collectes::collecte_de` : la première source lue du premier groupe de télémétrie de sa règle, sinon la première
listée), pas la source réellement lue par le producteur. Exemples d'écart : DNS-001 venue de Sysmon est notée
`JournalDns` si les deux sont lus ; COR-R4 et COR-R5 venues du journal Système sont notées `JournalSecurite` ; LEU-002,
tirée des 4663, est notée `Leurres`. Elle reste vide, et n'est pas écrite, pour une règle qui ne suit aucune source
(INT-*, COR-R6…). Elle n'entre pas dans la signature des exceptions.

## Principe

- **Ajout de champs seulement** : aucun champ existant ne change de nom ni de type.
- **Version portée par chaque alerte**, pas par le fichier : `alertes.json` reste un tableau d'alertes. Une enveloppe
  (`{ "Version": 1, "Alertes": [...] }`) casserait l'interface, l'API (`/api/v1/alertes`) et le retour arrière vers une
  version précédente, qui ne lirait plus rien puis réécrirait un fichier vide.

## Champs ajoutés (version 1)

| Champ | Type | Absent (alertes d'avant la phase 3) | Sens |
|---|---|---|---|
| `Modele` | entier | 0 | version du modèle ; 1 pour les alertes créées par la version qui l'introduit |
| `Regle` | texte, omis si vide | « » | identifiant de la règle (`docs/detection/regles.md`), « » si l'alerte n'est rattachée à aucune |
| `Collecte` | texte, omis si vide | « » | collecte d'où vient l'alerte (identifiant de `etat.json`, `Collectes`), PR 3.3c |
| `Signature` | texte, omis si vide | « » | empreinte (`sha256:…`) du comportement, calculée sur le texte entier avant le bornage ; posée sur les alertes de niveau « Alerte » avant le filtrage (y compris celles que l'apprentissage baisse en « Info ») ; c'est elle qu'une exception posée depuis l'alerte vise |
| `HeureUtc` | texte, omis si vide | « » | heure UTC de création (RFC 3339 à la seconde, « …Z »), phase 4, PR 4.1 ; bornée à 32 caractères |
| `Seq` | entier, omis si 0 | 0 | numéro d'ordre de création, croissant depuis le démarrage du service (remis à zéro à chaque démarrage), phase 4, PR 4.1 |
| `Entite` | texte, omis si vide | « » | entité du suivi des incidents, quand le producteur la connaît (phase 4, PR 4.3) : `source:<adresse, ou « compte X » sans adresse>` pour COR-R1 ; `compte:<compte sans domaine>` pour COR-R2 et R9 (le compte qui a ouvert la session ; à défaut, la source) ; `compte:<membre>` pour COR-R3 et R3b ; `COR-R<n>:<clé>` pour les autres corrélations. Au-delà de 10 entités distinctes d'une même règle R1, R2 ou R9 en une heure, les suivantes sont regroupées sous `COR-R<n>:regroupees` : une attaque répartie sur des centaines d'adresses n'ouvre pas des centaines d'incidents. Bornée à 160 caractères |

- `Modele` est posé à un seul endroit (`ajouter_alerte_brute`), et seulement s'il vaut 0 : une alerte relue d'un
  ancien fichier garde 0, son histoire n'est pas réécrite.
- Une alerte est **toujours** produite, même si la recherche de sa règle échoue (`Regle` vide).
- Événements du SIEM (`siem::Evenement`, PR 3.2) : seuls `Modele` et `Regle` y sont ajoutés (pas `Collecte` ni
  `Signature`). `Modele` vaut 1 sur **tous** les événements enregistrés depuis cette version, qu'ils viennent d'une
  alerte ou d'un journal de Windows ; `Regle` est repris de l'alerte d'origine (vide pour un événement qui n'en vient pas).
  Les lignes NDJSON existantes se relisent, avec `Modele` 0.
- **Ordre total** (phase 4, PR 4.1, décision D4-4) : `HeureUtc` et `Seq` sont posés sur chaque nouvelle alerte (au même
  endroit que `Modele`) et sur chaque événement du SIEM à son enregistrement. L'événement tiré d'une alerte reprend son
  `HeureUtc`. L'heure locale (`Heure`) reste, inchangée ; elle est ambiguë pendant l'heure répétée du passage à l'heure
  d'hiver, l'ordre se fait sur (`HeureUtc`, `Seq`). Une alerte ou une ligne d'avant la phase 4 se relit avec ces champs
  vides, et n'est pas réhorodatée.
- **Actions de réponse dans le SIEM** (phase 4, PR 4.1) : chaque commande de réponse (`bloquer`, `bloquerIp`,
  `debloquer`, `toutDebloquer`, `tuer`, `suspendre`, `reprendre`, `tuerChaine`, `quarantaine`, `restaurer`,
  `restaurerRepli`, `isolerProgramme`, `panique`), le blocage automatique d'une adresse (listes de menaces, IPS) et sa
  levée à l'échéance, et la suspension automatique d'un programme qui touche un leurre (LEU-002, chaque tentative)
  produisent un événement `Source` « reponse », `Type` le nom de l'action, `Destination` la cible, niveau « Info » si
  l'action a réussi, « Alerte » sinon, et un message qui dit le résultat et le déclencheur (« commande
  d'administrateur » ou « automatique : … »). Cible, message et déclencheur sont bornés à 300 caractères et nettoyés
  (caractères de contrôle et de mise en forme remplacés par « ? », audit de #94, S94-01). La logique des actions ne
  change pas. Seule action qui n'y passe pas : la levée du mode panique au nettoyage de la désinstallation.
- **Pertes de la file du SIEM** (phase 4, PR 4.1) : un événement qui ne trouve pas de place dans la file (20 000) est
  compté (`siem::pertes`), avec une ligne de journal à la 1re, 10e, 100e… perte ; avant, il disparaissait sans trace. Le
  compteur sera publié avec la santé de la remontée (PR 4.4b).

## Compatibilité

- **Lecture des anciens fichiers** : les champs absents prennent leur valeur par défaut (`Modele` 0, textes vides).
- **Lecture tolérante** (PR 3.1, `commun::lire_alertes`, décision `decision_alertes`). Ordre des contrôles :
  - lecture refusée (propriétaire, protection du dossier) : rien n'est lu ni déplacé, même si le fichier est trop grand ;
  - plus de 16 Mo : mis de côté (`alertes-trop-grand-<horodatage>.json`, dans le dossier de données) ;
  - contenu qui n'est pas de l'UTF-8, ou qui n'est pas un tableau JSON : mis de côté (`alertes-illisible-…`) ;
  - sinon, chaque élément est lu à part ; un élément illisible est écarté et compté (une ligne au journal), les autres
    sont gardés, et une copie du fichier d'origine est gardée d'abord (`alertes-partiel-…`).

  Avant, une seule alerte mal formée faisait perdre tout l'historique, puis le fichier était réécrit vide. Une mise de
  côté qui échoue (fichier tenu ouvert ailleurs) est retentée à chaque écriture, et `alertes.json` n'est pas réécrit
  tant qu'elle n'a pas réussi : les nouvelles alertes restent en mémoire. Le nom de mise de côté n'écrase jamais un
  fichier existant.
- **Limites** : une erreur de lecture passagère (fichier tenu ouvert ailleurs pendant la lecture) reprend à vide, et le
  premier ajout réécrit le fichier ; les fichiers mis de côté ne sont jamais purgés ; seule la décision est testée en
  labo, la mise de côté elle-même (renommage, copie) ne l'est ni en labo ni en VM.
- **Champs bornés** (audit de sécurité de #72, S72-01, S72-06, S72-07) : dans `ajouter_alerte_brute`, les décisions sont
  prises sur le texte **entier** (technique MITRE, signal fort, apprentissage), puis l'alerte est bornée (`borner_alerte`)
  avant tout usage (journal, export, notifications, SIEM, `alertes.json`). `Raisons` est gardé à 1000 caractères,
  `Chemin` et `Parent` à 520, `Processus`, `Destination`, `Conseil`, `Ip` et `NomDns` à 256, les champs posés par le code
  plus court encore (`Mitre` 128, `Regle` et `Collecte` 64, `Signature` 80, `Niveau`, `Heure`, `Id`), en gardant le
  **début et la fin** (« … » au milieu) :
  la conclusion d'une alerte (remarque, motif) est souvent à la fin, après une donnée externe longue. Les caractères de
  contrôle deviennent « ? ». Une alerte bornée tient en moins de 16 Ko même si **tous** ses champs sont remplis de
  caractères de 4 octets (test du pire cas), 1000 alertes en moins de 16 Mo : un compte
  standard ne peut plus faire mettre l'historique de côté en créant quelques démarrages automatiques géants, ni faire
  disparaître le motif d'une persistance en le repoussant au-delà de la borne.
- **Apprentissage** : un fichier mis de côté compte comme historique (`historique_alertes_existe`) : une mise de côté ne
  fait pas prendre un poste déjà en service pour une première installation (relecture de #72, D7).
- **Exceptions et comportements appris** (audit de sécurité de #72, S72-10 ; relecture, R7) : une exception posée depuis
  une alerte vise l'empreinte `Signature` du comportement entier, pas l'alerte bornée. Avant, une exception posée sur une
  alerte au chemin long ne s'appliquait jamais, et un programme posé au chemin borné littéral pouvait en hériter. Les
  nouveaux comportements appris sont mémorisés par leur empreinte (taille fixe : `apprentissage.json` reste borné). Les
  exceptions et comportements déjà enregistrés en clair restent reconnus. Une alerte d'avant cette version n'a pas
  d'empreinte : une exception posée depuis elle reprend l'ancienne signature, seulement si elle est de niveau « Alerte »
  et qu'aucun champ de sa signature n'a été borné ; sinon l'exception est refusée (audit de sécurité de #73, S73-01). Une
  empreinte mal formée est refusée aussi (S73-02).
- **Limite supplémentaire** : si la protection du dossier est en échec, quelqu'un qui pré-crée tous les noms de mise de
  côté possibles (100 par seconde d'horodatage) peut empêcher la mise de côté, donc retenir l'écriture d'`alertes.json` :
  les nouvelles alertes restent en mémoire (1000 au plus) et sont perdues à l'arrêt. L'échec n'est écrit qu'une fois au
  journal par série.
- **Interface** : elle lit `alertes.json` avec un lecteur JSON qui ignore les champs qu'elle ne connaît pas (vérifié :
  une alerte avec `Modele`, `Regle` et `Collecte` se lit).
- **Retour arrière** vers une version précédente : elle ignore les champs inconnus, puis réécrit le fichier sans eux.
  Après une nouvelle mise à niveau, ces alertes repassent en `Modele` 0. Accepté. Dans `apprentissage.json`, la version
  précédente ignore les exceptions et comportements appris mémorisés par empreinte (PR 3.1b) : les alertes concernées
  reviennent au niveau « Alerte » (échec fermé) ; ces entrées comptent quand même dans le plafond de 5000.
- **Signature d'apprentissage** : son contenu ne change pas pendant la phase 3 (elle dépend du texte `Mitre`, qui ne
  change pas : `mitre.rs` reste la source) ; seule sa forme mémorisée change avec la PR 3.1b (empreinte, voir plus bas).
  La clé de déduplication des alertes ne change pas.
- **Export** : l'export JSON (syslog) et l'API (`/api/v1/alertes`, JSON et NDJSON) sérialisent l'alerte entière : `Modele`
  y apparaît dès la PR 3.1, `Signature` dès la PR 3.1b (alertes de niveau « Alerte »), `Regle` et `Collecte` quand ils
  seront remplis (vides, ils ne sont pas écrits). Le CEF ne
  change pas. L'API lit `alertes.json` par la même lecture tolérante, sans rien déplacer (`lire_alertes_sans_effet`) :
  un élément illisible ne vide plus sa réponse.

## Santé des collectes (phase 4, PR 4.4a)

Chaque changement d'état d'une collecte (`collectes::instantane`) est écrit dans le SIEM par le fil « sante » (toutes
les 30 s, hors du verrou du moniteur), au changement seulement :

| Champ | Valeur |
|---|---|
| `Source` | `sante` |
| `Type` | `collecte` |
| `Niveau` | `Alerte` si la collecte devient `Indisponible`, sinon `Info` |
| `Destination` | identifiant de la collecte (`JournalSecurite`, `Connexions`…) |
| `Message` | « collecte <id> : <avant> → <après> (<raison>) », borné à 400 caractères, nettoyé |

- Le passage d'« Inconnue » à « Active » du démarrage n'est pas écrit.
- Plus de 6 changements dans l'heure : collecte « instable », une ligne par heure au plus (le message le dit).
- Une coupure plus courte que la période du fil (30 s) peut ne pas être vue.
- Constats SAN-001, SAN-002, SAN-003 et SAN-012 : `docs/detection/regles.md`.

## Santé de la remontée (phase 4, PR 4.4b)

`notifications.json` (lu par l'interface, sans secret) gagne :

| Champ | Valeur |
|---|---|
| `EchecDepuis` | heure locale du premier lot non remis d'une panne en cours ; vide sinon |
| `EnAttente` | alertes dans la file de reprise |
| `Abandonnees` | alertes abandonnées par la file (pleine, ou plus de 24 h) depuis le démarrage |
| `DernierBattement` | date locale (AAAA-MM-JJ) du dernier battement ; relue au démarrage |

- **Remis** : un lot est remis si au moins un canal tenté a réussi ; remis sur un seul canal, il n'est pas retenté (il
  y arriverait en double). Aucun canal tenté (secrets absents) : non remis.
- **File de reprise** : les alertes critiques et les constats SAN-* (sauf SAN-004) d'un lot non remis ; sans doublon
  (même `Id`) ; 100 au plus (la plus ancienne part) ; 24 h au plus ; essais à +1, +5, +15, +60 min, puis toutes les
  heures, en un lot. **En mémoire** (D4-8) : un redémarrage la vide ; les alertes restent dans `alertes.json`.
- **SAN-004** : remontée en échec depuis plus d'une heure ; constat local, jamais remonté ni mis en file.
- **Battement** (D4-6) : quand la remontée est configurée, un message par jour à partir de 09:00 locale, niveau
  « Info », hors plafond et hors niveau minimal : incidents non clos, collectes actives et indisponibles (identifiants
  des collectes critiques indisponibles), alertes en attente. Compteurs seulement : aucun nom de compte, de programme
  ni de ligne de commande. Sans battement, le prestataire sait que le service est arrêté, le poste éteint ou la
  remontée coupée.
- Remontée coupée par l'administrateur : la file est vidée et l'échec effacé.

## Suivi des incidents (phase 4, PR 4.2)

`suivi-incidents.json` (dossier de données) est un tableau d'incidents, écrit par le moniteur seul, au même moment
qu'`alertes.json` et après chaque transition. `incidents.json` (corrélations du SIEM) ne change pas.

| Champ | Sens |
|---|---|
| `Modele` | 1 |
| `Id`, `Ouverture`, `OuvertureUtc` | identifiant, heure d'ouverture (locale et UTC) |
| `DerniereActiviteUtc` | heure UTC de la dernière alerte jointe |
| `Niveau` | le plus haut des alertes jointes (Alerte ou Critique) ; ne baisse jamais |
| `Entite` | l'`Entite` de l'alerte si le producteur l'a posée (corrélations du SIEM, PR 4.3) ; sinon `programme:<chemin complet, en minuscules>` si le chemin est connu ; sinon `destination:<destination>` ; sinon `regle:<identifiant>`. Jamais un nom de programme seul : deux programmes de même nom à des chemins différents font deux incidents |
| `Regles` | identifiants distincts des alertes jointes (16 au plus) |
| `Etat`, `MotifCloture` | `Ouvert`, `PrisEnCharge` ou `Clos` ; motif `Resolu`, `FauxPositif` ou `Accepte` pour un incident clos |
| `Precedent` | incident clos de la même entité, s'il y en a un (récidive) |
| `Alertes`, `NombreAlertes` | résumés des 5 premières et des 5 dernières alertes jointes (chemin 260, processus 64, destination 128 et raisons 200 caractères au plus, sans caractère de contrôle ni de mise en forme), et leur nombre |
| `Transitions` | 20 au plus : heure locale et UTC, état de départ et d'arrivée, motif, auteur (SID lu sur le jeton du client du tube, jamais pris dans la commande ; une transition sans auteur connu est refusée), note (300 caractères au plus, sans caractère de contrôle ni de mise en forme) |

- **Rattachement** : une alerte « Info » ne crée rien ; une alerte « Alerte » ou « Critique » rejoint l'incident non
  clos de la même entité dont la dernière activité date de moins de 24 h ; sinon elle ouvre un incident. Un incident
  clos n'est jamais rouvert en silence : la récidive ouvre un nouvel incident, qui nomme le précédent.
- **Transitions** (commande `incident`, administrateurs seulement : `Cible` = identifiant, `Valeur` = état visé,
  `Type` = motif, `Raison` = note) : Ouvert vers PrisEnCharge ou Clos ; PrisEnCharge vers Clos ; Clos vers Ouvert
  (réouverture explicite, motif effacé, historique gardé). Toute autre transition est refusée, sans rien écrire. Clore
  avec « FauxPositif » ne pose aucune exception (D4-10). Aucune fermeture automatique (D4-3).
- **Bornes** : 500 incidents au plus. Au-delà, les plus anciens clos partent les premiers ; un incident non clos n'est
  jamais retiré. S'il n'y a que des incidents non clos, une alerte d'une nouvelle entité n'est pas suivie : elle est
  comptée (constat de santé SAN-012, PR 4.4) et reste dans `alertes.json`.
- **Lecture** (`incidents::decision_suivi`) : propriétaire contrôlé, élément par élément (un élément illisible est
  écarté et compté, les autres sont gardés et bornés aux mêmes bornes qu'à la création).
  - Lu en partie : une copie d'origine est mise de côté (`suivi-incidents-partiel-<horodatage>.json`) avant d'autoriser
    la réécriture ; si la copie échoue, le suivi n'est pas réécrit (relecture de #95, D1).
  - Plus de 64 Mo : mis de côté (`suivi-incidents-trop-grand-<horodatage>.json`), suivi repris à vide (audit de #95,
    S95-01). Les bornes garantissent qu'un suivi plein (500 incidents au pire) reste sous cette taille.
  - Illisible (droits, pas un tableau JSON) : suivi vide, **jamais réécrit**, commande `incident` refusée **jusqu'à une
    intervention manuelle** (déplacer le fichier). C'est plus prudent que pour `alertes.json`, et ce sera signalé par
    la santé (PR 4.4b).
- **Retour arrière** vers une version sans suivi : le fichier est ignoré, puis repris tel quel à la mise à niveau
  suivante.

## Chronologie d'un incident (phase 4, PR 4.3)

`chronologies\<id>.json` (dossier de données) : pour chaque incident suivi, une liste datée et ordonnée, recalculée par
le service **hors du verrou du moniteur** (fil « chronologies », toutes les minutes) quand l'incident change (nouvelle
alerte jointe, nouvelle transition), 50 incidents au plus par tour. L'interface la lit sans rien demander ; les
fichiers des incidents qui ne sont plus suivis sont effacés.

- **Dossier** : préparé comme `restaurations` : rien n'est écrit ni effacé quand la protection du dossier de données est
  en échec ; le dossier est créé avec les droits du dossier de données (SYSTEM et administrateurs, lecteurs en lecture),
  ouvert sans suivre de lien, ses droits vérifiés. Le nom d'un fichier est l'identifiant de l'incident, vérifié
  (`[A-Za-z0-9-]`, 64 caractères) : un incident relu avec un autre identifiant est écarté ; le ménage n'efface que des
  fichiers ordinaires ainsi nommés.

- **Éléments** : les résumés des alertes jointes, les transitions, et les événements du SIEM de l'entité dans la fenêtre
  [ouverture − 30 min, dernière activité + 30 min] : actions de réponse, événements des journaux, connexions, et tout
  changement d'état d'une collecte (`Source` « sante », PR 4.4 : un trou de collecte apparaît dans la chronologie). Les
  alertes du SIEM sont écartées, déjà présentes par les résumés. Ordre : heure UTC, puis numéro d'ordre.
- **Lien avec l'entité** (`incidents::lien`) : programme (chemin complet de l'événement ou cité ; sans chemin, nom du
  fichier seul, et l'élément porte alors `ParNom` : un autre programme du même nom peut en être l'auteur), destination
  (destination, adresse ou texte), source d'une corrélation (adresse, ou compte avec ou sans domaine), compte, règle.
- **Lecture du SIEM** : pour chaque incident, sur sa fenêtre seulement, les lignes qui citent son entité
  (`incidents::cle_recherche`) puis la santé des collectes ; les connexions des autres programmes ne remplissent donc
  pas la lecture.
- **Bornes** (dossier de phase 4) : 3 jours de fichiers au plus (fenêtre plus longue : les 3 derniers jours) ; 20 000
  événements par lecture ; 5 s par chronologie et 10 s par tour (une chronologie n'est commencée qu'avec ses 5 s pleines ; les incidents restants attendent le tour suivant) ; 2000 éléments (au-delà, les 1000 premiers et les 1000 derniers,
  `Tronquee`) ; texte de chaque élément borné à 400 caractères, nettoyé. Si une borne de lecture est atteinte,
  `FenetreSiemIncomplete` le dit. `SansHeureUtc` compte les événements d'avant la phase 4, qui ne peuvent pas être
  placés ; `PertesSiem` dit combien d'événements la file du SIEM a perdus depuis le démarrage : des étapes peuvent
  manquer.
- **Après un redémarrage** : une chronologie déjà écrite pour le même état de l'incident (`Repere` : dernière activité,
  transitions, alertes) est gardée telle quelle, pas recalculée. Quand l'incident change, elle est recalculée sur ce que
  le SIEM a encore (30 jours de fichiers) : au-delà restent les résumés et les transitions de l'incident.

## Règles de stabilité

- Un champ ne change jamais de type.
- Un champ retiré reste lu (valeur par défaut).
- Toute rupture fait passer `Modele` à 2, avec une migration testée.
