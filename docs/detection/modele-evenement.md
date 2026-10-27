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
  compteur sera publié avec la santé (PR 4.4).

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

## Prévu en phase 4 (pas encore dans le code)

Décrit ici pour fixer le format avant le code (`docs/roadmap/phase4.md`) ; chaque point devient vrai avec la PR qui
l'apporte, et cette section sera réécrite à ce moment-là.

- **Ordre approximatif** : dans la chronologie (PR 4.3), les éléments d'avant la phase 4, qui n'ont que l'heure locale,
  seront signalés « ordre approximatif ».
- **Source « sante »** (PR 4.4) : chaque changement d'état d'une collecte, écrit au changement seulement.
- **Suivi des incidents** (PR 4.2) : nouveau fichier `suivi-incidents.json`, tableau d'incidents, écrit par le moniteur
  seul ; chaque élément porte `Modele` 1, un identifiant, l'heure d'ouverture (locale et UTC), la dernière activité, le
  niveau (le plus haut des alertes jointes, qui ne baisse jamais), l'entité (chemin complet du programme, sinon
  destination, sinon compte, sinon règle ; jamais un nom de programme seul), les règles jointes, l'état (Ouvert,
  PrisEnCharge, Clos) et le motif de clôture, l'incident précédent de la même entité, des résumés bornés des alertes et
  les transitions (auteur : SID de l'administrateur). 500 incidents au plus, les plus anciens clos partant les premiers ;
  même plafond de taille et même lecture tolérante qu'`alertes.json`. `incidents.json` (corrélations du SIEM) ne change
  pas.

## Règles de stabilité

- Un champ ne change jamais de type.
- Un champ retiré reste lu (valeur par défaut).
- Toute rupture fait passer `Modele` à 2, avec une migration testée.
