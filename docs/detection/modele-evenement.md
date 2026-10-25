# Modèle d'événement (phase 3)

Ce document décrit le format des alertes du service (`Alerte`, `service-rs/src/commun.rs`) tel que la phase 3 le
versionne. **Il est en avance sur le code** : les champs ci-dessous arrivent avec la PR 3.1 (version) et la PR 3.2
(identifiant de règle). Tant qu'elles ne sont pas fusionnées, `alertes.json` reste au format actuel, sans ces champs.

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
- Les mêmes champs sont ajoutés aux événements du SIEM (`siem::Evenement`) ; les lignes NDJSON existantes restent
  lisibles.

## Compatibilité

- **Lecture des anciens fichiers** : les champs absents prennent leur valeur par défaut (`Modele` 0, textes vides).
- **Lecture tolérante** (PR 3.1) : `alertes.json` est lu élément par élément. Un élément illisible est écarté et compté,
  les autres sont gardés ; aujourd'hui, une seule alerte mal formée fait perdre tout l'historique, puis le fichier est
  réécrit vide. Au-delà d'une taille maximale (16 Mo), rien n'est lu et le fichier est mis de côté au lieu d'être écrasé.
- **Retour arrière** vers une version précédente : elle ignore les champs inconnus, puis réécrit le fichier sans eux.
  Après une nouvelle mise à niveau, ces alertes repassent en `Modele` 0. Accepté.
- **Exceptions et apprentissage** : inchangés pendant la phase 3. Leur signature dépend du texte `Mitre`, qui ne change
  pas (`mitre.rs` reste la source) ; la clé de déduplication des alertes ne change pas non plus.
- **Export** : `Regle` et l'état des collectes sont ajoutés à l'API et à l'export JSON ; le syslog texte et CEF ne
  changent pas.

## Règles de stabilité

- Un champ ne change jamais de type.
- Un champ retiré reste lu (valeur par défaut).
- Toute rupture fait passer `Modele` à 2, avec une migration testée.
