# Modèle d'événement (phase 3)

Ce document décrit le format des alertes du service (`Alerte`, `service-rs/src/commun.rs`) tel que la phase 3 le
versionne. Depuis la PR 3.1, les trois champs existent et toute nouvelle alerte porte `Modele` 1, et `alertes.json`
est lu élément par élément. `Regle` reste vide jusqu'à la PR 3.2 (registre des règles), `Collecte` jusqu'à la PR 3.3
(état des collectes) : vides, ils ne sont pas écrits.

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
| `Collecte` | texte, omis si vide | « » | collecteur d'où vient l'alerte (état des collectes, PR 3.3) |

- `Modele` est posé à un seul endroit (`ajouter_alerte_brute`), et seulement s'il vaut 0 : une alerte relue d'un
  ancien fichier garde 0, son histoire n'est pas réécrite.
- Une alerte est **toujours** produite, même si la recherche de sa règle échoue (`Regle` vide).
- Les mêmes champs seront ajoutés aux événements du SIEM (`siem::Evenement`) avec la PR 3.2, en même temps que les
  identifiants de règle ; les lignes NDJSON existantes resteront lisibles.

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
  `Chemin`, `Parent` et `Conseil` à 520, les autres champs à 256, en gardant le **début et la fin** (« … » au milieu) :
  la conclusion d'une alerte (remarque, motif) est souvent à la fin, après une donnée externe longue. Les caractères de
  contrôle deviennent « ? ». Une alerte bornée tient en moins de 16 Ko, 1000 alertes en moins de 16 Mo : un compte
  standard ne peut plus faire mettre l'historique de côté en créant quelques démarrages automatiques géants, ni faire
  disparaître le motif d'une persistance en le repoussant au-delà de la borne.
- **Apprentissage** : un fichier mis de côté compte comme historique (`historique_alertes_existe`) : une mise de côté ne
  fait pas prendre un poste déjà en service pour une première installation (relecture de #72, D7).
- **Limite supplémentaire** : si la protection du dossier est en échec, quelqu'un qui pré-crée tous les noms de mise de
  côté possibles (100 par seconde d'horodatage) peut empêcher la mise de côté, donc retenir l'écriture d'`alertes.json` :
  les nouvelles alertes restent en mémoire (1000 au plus) et sont perdues à l'arrêt. L'échec n'est écrit qu'une fois au
  journal par série.
- **Interface** : elle lit `alertes.json` avec un lecteur JSON qui ignore les champs qu'elle ne connaît pas (vérifié :
  une alerte avec `Modele`, `Regle` et `Collecte` se lit).
- **Retour arrière** vers une version précédente : elle ignore les champs inconnus, puis réécrit le fichier sans eux.
  Après une nouvelle mise à niveau, ces alertes repassent en `Modele` 0. Accepté.
- **Exceptions et apprentissage** : inchangés pendant la phase 3. Leur signature dépend du texte `Mitre`, qui ne change
  pas (`mitre.rs` reste la source) ; la clé de déduplication des alertes ne change pas non plus.
- **Export** : l'export JSON (syslog) et l'API (`/api/v1/alertes`, JSON et NDJSON) sérialisent l'alerte entière : `Modele`
  y apparaît dès la PR 3.1, `Regle` et `Collecte` quand ils seront remplis (vides, ils ne sont pas écrits). Le CEF ne
  change pas. L'API lit `alertes.json` par la même lecture tolérante, sans rien déplacer (`lire_alertes_sans_effet`) :
  un élément illisible ne vide plus sa réponse.

## Règles de stabilité

- Un champ ne change jamais de type.
- Un champ retiré reste lu (valeur par défaut).
- Toute rupture fait passer `Modele` à 2, avec une migration testée.
