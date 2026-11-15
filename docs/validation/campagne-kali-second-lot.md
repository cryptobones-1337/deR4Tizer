# Campagne Kali — second lot (vol d'identifiants, listes de menaces)

Date : 2026-11-15. Liste des scénarios : v1.4 (`campagne-kali-phase1.md`). Résultats bruts hors dépôt.
Aucune donnée personnelle, aucun nom de poste, aucun mot de passe. Adresses du labo : plages de documentation (RFC 5737),
non routables. Prolonge le rapport du premier passage (`campagne-kali-premier-passage.md`) : il lève deux des préalables
qui y étaient notés (profil de navigateur pour VOL-001, listes de menaces actives pour DNS-001/RES-001).

**Réserve (latences)** : comme au premier passage, l'horloge de la VM est décalée dans les résultats bruts ; les
verdicts VP reposent sur la présence règle/niveau/entité, pas sur l'heure. Préconditions auto-validées (voir ci-dessous).

## Vol d'identifiants (VOL-001)

| Scénario | Configuration | Verdict | Résumé |
|---|---|---|---|
| S-14 (lecture d'une base d'identifiants de navigateur par un programme inattendu) | C (baseline 100 %) | **VP (Critique)** | Un programme **non signé**, au nom neutre, lancé depuis un **emplacement temporaire**, ouvre **en lecture** le fichier d'identifiants d'un profil de navigateur de leurre (créé pour l'essai, sans secret) → **1 alerte VOL-001 Critique** (score 10, T1555 / T1539). Aucun mot de passe lu, aucune copie, aucune exfiltration. |
| S-14 | A (sans baseline) | **VP (Critique)** | Identique. L'audit de lecture nécessaire (« Système de fichiers ») est posé par le service lui-même, donc la détection ne dépend pas de la baseline. |

**Précondition auto-validée** : l'essai n'est retenu que si le service a effectivement posé l'audit de lecture sur le
dossier surveillé **et** qu'un événement d'audit de lecture est produit sur le fichier ciblé ; sinon l'essai est déclaré
invalide (D), jamais un faux négatif. Les deux configurations ont satisfait cette précondition (audit posé sur les
dossiers de données sensibles présents, événement de lecture produit).

## Listes de menaces (DNS-001, RES-001)

| Scénario | Configuration | Verdict | Résumé |
|---|---|---|---|
| S-07 (domaine malveillant connu + IP de menace connue) | C | **VP (DNS-001 + RES-001 + blocage 7 j)** | **DNS-001** : une requête DNS vers un **domaine de la liste de menaces** → **alerte Critique** « domaine malveillant connu ». **RES-001** : une connexion vers une **IP d'une liste de confiance haute** → **alerte Critique** « menace connue » **et blocage automatique au pare-feu, échéance à 7 jours** (relevé dans le journal des blocages). |
| S-07 | A | **VP (DNS-001 + RES-001 + blocage 7 j)** | Identique. Les listes de menaces et le journal du client DNS sont actifs indépendamment de la baseline. |

**Précondition auto-validée** : les listes synthétiques (une entrée de documentation chacune : un domaine `.test`, une IP
en plage RFC 5737) sont fournies au service comme entrées des sources correspondantes, avec un **propriétaire de fichier
contrôlé** (SYSTEM ou Administrateurs), puis activées par le **canal de commandes** du service. En labo isolé, le
téléchargement réel des listes échoue (pas de résolution DNS sortante) et le service **conserve et charge la copie
locale** — comportement attendu. L'essai n'est retenu que si l'état des menaces confirme le chargement (entrées ≥ 1 pour
la source IP et pour la source domaine) ; les deux configurations l'ont confirmé.

## Grille de couverture — mise à jour (cumul premier passage + second lot)

| Domaine / technique | Règle attendue | Config A | Config C |
|---|---|---|---|
| Vol d'identifiants de navigateur (T1555 / T1539) | VOL-001 | **VP (Critique)** | **VP (Critique)** |
| Requête vers domaine malveillant connu (T1071 / renseignement) | DNS-001 | **VP (Critique)** | **VP (Critique)** |
| Connexion vers IP de menace connue (T1071) | RES-001 + blocage auto | **VP (Critique + blocage 7 j)** | **VP (Critique + blocage 7 j)** |

Avec le premier passage (chaîne de mesure, force brute RDP/SMB, persistance, corrélations système), la campagne couvre
désormais, en vrais positifs mesurés : **témoin négatif propre, durcissement, force brute (RDP, SMB), persistance,
corrélations service/compte/journal/audit, vol d'identifiants, et renseignement sur les menaces (domaine + IP + blocage)**.
Le constat produit R3 (corrélation « nouveau compte administrateur ») reste ouvert, correctif proposé au mainteneur.

## Scénario non exécuté dans ce lot

- **S-06 (filtrage DNS, règle DNS-002)** : non exécuté dans ce lot — ses préalables de labo (résolveur local actif,
  filtrage activé sur les cartes, liste de filtrage synthétique `.test`, amont DNS de labo) restent à monter. Le code
  correspondant (détection d'un changement de serveur DNS et filtrage par résolveur local) **est présent** dans la
  source : S-06 est testable et planifié pour un prochain lot. La détection DNS de bout en bout est déjà couverte ici par
  S-07 (DNS-001).

## Méthode (rappel)

Instantanés de campagne « campagne A » (sans baseline) et « campagne C » (baseline à 100 % appliquée par le service).
Remise à l'instantané avant et après chaque essai. Defender jamais modifié à la main. Aucun outil offensif détaillé ;
S-14 est entièrement local (aucune orchestration externe) ; S-07 n'émet aucun trafic vers un vrai domaine ou hôte
malveillant (entrées de documentation seulement).
