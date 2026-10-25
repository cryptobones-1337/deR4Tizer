# deR4Tizer : consignes pour Claude Code

Ce fichier cadre tout le travail de Claude Code sur ce dépôt. Il prime sur toute autre demande implicite. En cas de doute, s'arrêter et demander.

## 1. Mission

deR4Tizer est une couche de défense en profondeur pour Windows, complémentaire à Microsoft Defender, destinée aux petites structures sans SOC (TPE, commerces, petites communes) et aux particuliers. Tout fonctionne en local ; les alertes critiques partent vers le prestataire ou le référent. En dehors des téléchargements déjà documentés (listes de menaces, JA3, GeoIP, LOLDrivers, mise à jour) et des alertes, aucune donnée de l'utilisateur ne part vers un tiers, sauf par une fonctionnalité qu'il active lui-même et qui l'annonce (phases 7 et 9, section 5).

Ce n'est pas un antivirus, ni un remplaçant de Defender, ni un EDR d'entreprise. Une capacité n'existe que si elle est démontrée par des tests reproductibles. Le code qui compile ne prouve rien.

## 2. Règles non négociables

1. **Gel des fonctionnalités.** Aucune nouvelle capacité, aucun nouveau module, aucun nouveau paquet, aucune nouvelle option tant que la file de travail de la section 5 n'est pas terminée, validée par la relecture (section 4) et par cryptobones-1337. Seules exceptions : les phases 7, 8 et 9 (section 5), ouvertes par écrit par le mainteneur, chacune une fois les phases qui la précèdent validées par la relecture et par cryptobones-1337, et pour son seul contenu. Corriger, tester, documenter : oui. Ajouter : non. Si une correction semble exiger une nouvelle fonction, s'arrêter et demander.
2. **Defender intouchable.** Ne jamais désactiver, affaiblir, arrêter ou exclure quoi que ce soit dans Microsoft Defender ou les protections de Windows, même pour faire passer un test.
3. **Échec fermé** pour tout ce qui touche à la sécurité : vérification de signature, autorisation, génération de secret, pose de droits (ACL), validation de mise à jour. Si l'opération de sécurité échoue, l'opération dépendante n'a pas lieu, et l'échec est journalisé et visible dans l'interface.
4. **Aucune panique dans le service.** Le service est compilé avec `panic = "abort"` et tourne en SYSTEM : une panique l'arrête. Pas de `[a..b]` sur une `&str` venue de l'extérieur (utiliser `get()` ou travailler sur des octets), pas de `unwrap()` sur une donnée externe. Chaque parseur nouveau ou modifié passe par `torturer` ou `torturer_texte` dans `service-rs/src/tests.rs`.
5. **Pas d'allowlist par nom de fichier.** Toute décision de confiance sur un programme repose sur le chemin complet ET le signataire exact (`vol_donnees::editeur_correspond`), ou sur `natif::binaire_windows`. Jamais sur le nom seul, jamais sur une sous-chaîne du signataire.
6. **Fichiers du dossier de données = données non fiables** tant que leur propriétaire et leurs droits n'ont pas été vérifiés (voir lot 1).
7. **Aucune publication.** Ne jamais créer de tag `v*`, de version GitHub, ni lancer `publication.yml`. Ne jamais pousser directement sur `main` si la protection de branche est active : passer par une pull request.
8. **Aucun résultat inventé.** Ne jamais affirmer qu'un test est passé, qu'une compatibilité Windows est vérifiée ou qu'une performance est mesurée sans l'avoir fait. Un test non exécutable ici est déclaré comme tel, avec la raison.
9. **Pas de test destructif sur le poste hôte.** Pas de malware réel. Les scénarios sont bénins et reproductibles, en CI ou en VM.
10. **Petits changements.** Un lot = un commit (ou une pull request) cohérent et relisible. Pas de réécriture de module quand une correction ciblée suffit. Pas de nouvelle dépendance sans justification (maintenance, licence, nécessité) écrite dans le message de commit.
11. **Aucun secret** dans les journaux, les messages d'erreur, la ligne de commande ou les fichiers lisibles par les comptes autorisés.
12. **Langue.** Code, commentaires, messages, documentation et commits en français, comme le reste du dépôt.

## 3. Repères d'architecture

- `service-rs/` : service Windows en Rust, compte SYSTEM. Point d'entrée `main.rs`, cœur `moniteur.rs`, commandes reçues par `canal.rs` (tube `\\.\pipe\deR4Tizer`), fichiers partagés `commun.rs`, mise à jour `maj.rs`, protection du dossier de données `protection.rs`.
- `src/` : interface C# (.NET Framework 4.8), sans droits admin ; les actions passent par une instance élevée (`--commande-fichier`) qui affiche la commande en clair avant envoi.
- `installeur/deR4Tizer.wxs` + `construire-msi.ps1` : paquet MSI (WiX 3.14).
- `C:\ProgramData\deR4Tizer` : état et données ; `secrets\` réservé à SYSTEM et aux administrateurs.
- Tests : `cargo test --release` dans `service-rs` ; CI dans `.github/workflows/ci.yml` (runner `windows-latest`, administrateur et jetable).

## 4. Protocole de travail

### Avant chaque lot

1. Lire le code concerné, ses appelants et ses tests. Ne pas se fier au README.
2. Écrire un plan court dans la conversation : fichiers touchés, comportement actuel, comportement visé, tests à ajouter, risques de régression.
3. Si le lot modifie un comportement privilégié, le modèle de confiance des mises à jour, ou une action irréversible : attendre l'accord explicite.

### Pendant

- Écrire d'abord le test qui échoue sur le code actuel quand c'est possible, puis la correction. Pour tout test
  ajouté ou modifié, avant la PR : le test échoue quand on retire le correctif (ou sous une mutation du correctif),
  puis réussit quand on le remet, chaque variante recompilée dans son propre dossier de compilation. Un test qui n'a
  jamais échoué ne prouve pas qu'il attrape le défaut.
- Aucune affirmation « corrigé », « réussi » ou « vert » sans une sortie fraîche de la commande qui le prouve, sur le
  commit et l'arbre annoncés ; le rapport d'un agent n'est pas une preuve : relire le diff ou le tableau.
- Une cause reste une hypothèse, et se dit comme telle, tant qu'un essai ne l'a pas confirmée ; relever l'état (journal,
  registre, valeurs) avant de corriger, et avant toute remise à l'instantané qui l'effacerait (passage bloqué compris).
- Un contrôle qui n'a rien eu à vérifier (zéro événement, zéro fichier, lecture impossible) ne vaut pas réussite :
  prévoir un témoin qui doit être retenu et un témoin qui doit être écarté, et faire échouer une lecture impossible.
- Lancer `cargo test --release` et la compilation de l'interface quand l'environnement le permet.
- Relire son propre diff : régressions, changements hors sujet, secrets, découpages de chaînes.

### Après chaque lot

Rapport dans la conversation ET dans le message de commit :

```
Lot N : <titre>

Corrigé
- <constat> : <ce qui a changé> (<fichier>:<fonction>)

Tests
- Ajoutés : <nom du test> : <ce qu'il prouve>
- Exécutés : <commande> : <résultat réel>
- Non exécutés : <test> : <raison>

Critères d'acceptation
- [x] / [ ] <critère repris de la section 5>

Risques restants
- <limite connue, ou « aucun identifié »>
```

Puis s'arrêter : chaque PR est relue avant que le lot suivant commence.

### Relecture des PR (depuis le 2026-10-24)

Sur décision de cryptobones-1337, la relecture des PR est faite par un agent de relecture Claude Code, à la place du
relecteur externe :
1. Sans l'historique de la session qui a écrit le code, mais sur une consigne rédigée par elle ; aucune écriture dans
   le dépôt ni sur GitHub (ni poussée, ni fusion, ni commentaire), les fusions de contrôle se faisant dans un clone
   temporaire ; sur les têtes des PR lues sur GitHub.
2. Contrôles : arbre intégré reproduit et égal à l'arbre de la preuve ; pas d'empilement ; fusion sans conflit ;
   `cargo test --release` (MSVC) et, pour chaque correctif, un test qui échoue sans lui ; documentation et règles de
   ce fichier ; données personnelles ; description exacte.
3. Verdict par PR : « Go » ou « Pas go » motivé ; sans preuve Windows Sandbox sur l'arbre annoncé, « Go sous réserve
   du passage Sandbox ».
4. Le verdict ne remplace ni le passage en Windows Sandbox ni la décision de fusion, qui reste à cryptobones-1337.

Limite : l'agent est le même modèle que l'auteur des changements ; leurs angles morts peuvent coïncider. Cette
relecture n'est donc pas une relecture indépendante, et rien ne doit la présenter comme telle (README, matrice,
publications).

### Exception temporaire : GitHub Actions désactivé sur le dépôt (depuis le 2026-10-22)

Tant que GitHub Actions est désactivé, la CI obligatoire est remplacée par une preuve locale, avec l'accord de cryptobones-1337 :
1. Les PR relues sont fusionnées, dans l'ordre fixé, sur une branche d'intégration locale partie de main.
2. Sur ce commit : cargo test --release (MSVC), MSI construit depuis ce commit, scénarios 3a, 3b et 3c dans la VM Hyper-V de test, remise à son instantané « propre » avant et après chaque scénario (tests/vm/lancer.ps1 ; instantané pris avec Microsoft Defender actif et sans exclusion : son état est relevé à chaque scénario, et n'est exigé « pleinement actif » que par le lot 3d, tests/vm/lot3d.ps1 ; compte standard connecté à la console avec -SessionStandard, sinon la session de l'instantané). Windows Sandbox (tests/bac-a-sable/lancer.ps1) reste un secours, signalé comme tel dans la preuve. Passage complet : tests/bac-a-sable/passage-complet.ps1. Aucun ÉCHOUÉ ; seuls les NON EXÉCUTÉ déjà connus et justifiés. Un passage dans la VM ne vaut pas, à lui seul, réussite du lot 3d.
   Tout passage est surveillé par une vigie (tests/bac-a-sable/vigie.ps1, une vérification par minute) qui signale chaque scénario terminé, tout blocage (bac à sable jamais ouvert ou fermé sans résultat, VM arrêtée, aucun fichier de travail du scénario écrit pendant 30 minutes) et la fin. Un passage bloqué est arrêté, nettoyé (bac à sable fermé, clés de test effacées, VM remise à son instantané) et relancé ; il ne compte jamais comme preuve.
   Dispense (mainteneur, 2026-10-25 : « No vm for documentation », en réponse à la proposition « exempt PRs that touch only *.md files outside src/ and service-rs/ ») : une PR qui ne modifie que des fichiers Markdown (`*.md`) hors de `src/` et de `service-rs/` n'a pas de passage VM. Relecture et contrôle des données personnelles restent obligatoires ; le verdict est « Go » (sans réserve de passage) ; la preuve en commentaire le dit (« documentation seule : passage non requis », liste des fichiers modifiés, arbre relu). Barrière d'arbre : le commit relu tient lieu de commit testé (`git diff <commit relu> main` vide après la fusion). Une PR qui touche aussi un autre fichier, même un script de test ou un .md sous `src/` ou `service-rs/`, a son passage. Une PR de documentation fusionnée entre le passage d'une PR de code et sa fusion change main : elle passe avant le passage, ou le passage est refait.
3. Preuve en commentaire de chaque PR concernée : hash du commit et de l'arbre testés, SHA-256 du MSI, version de Windows, tableaux complets.
4. Les PR sont fusionnées dans le même ordre, sans modification après le test ; ensuite, git diff <commit testé> main doit être vide, sinon nouveau test.
5. Au retour de GitHub Actions : vérifications obligatoires rétablies par cryptobones-1337, CI complète relancée sur main, tout échec corrigé avant tout autre travail.

Aucune distribution tant que la CI GitHub n'est pas verte sur main, que le lot 3d n'a pas réussi en VM, que les binaires ne sont pas signés et qu'une relecture indépendante (personne ou organisme autre que Claude) n'a pas été faite.

## 5. File de travail (dans cet ordre)

### Lot 1 : propriété et droits du dossier de données (bloquant, élévation de privilèges)

**Constat :** le MSI ne crée pas `C:\ProgramData\deR4Tizer` ; le service le crée avec les droits hérités de `ProgramData` (`Utilisateurs` peut y créer fichiers et dossiers) ; `protection.rs` ne pose les droits qu'après l'ouverture d'une session et ne change jamais le propriétaire. Un compte standard qui crée le dossier (ou `maj\`) avant le service en reste propriétaire, donc peut toujours réécrire ses droits. Il peut alors remplacer `maj\<version>\deR4Tizer.msi` entre la vérification et `msiexec` (SYSTEM), ou `maj\sauvegarde\*.exe` copié par le retour arrière dans `Program Files`.

**À faire :**

- MSI : créer le dossier (`CreateFolder` + `util:PermissionEx`), SYSTEM et Administrateurs en contrôle total, sans héritage.
- Service, au démarrage et avant toute lecture de fichier de données : imposer le propriétaire Administrateurs (`S-1-5-32-544`) sur le dossier et tout son contenu, poser les droits protégés (SYSTEM, Administrateurs, lecteurs autorisés en lecture), sans attendre de session ouverte. Vérifier le résultat ; en cas d'échec, journaliser, signaler dans l'interface et ne charger aucun fichier de configuration ou de secret (valeurs par défaut sûres).
- `commun::lire` (et la lecture des secrets) : refuser un fichier dont le propriétaire n'est ni SYSTEM ni Administrateurs. Décision pure testable séparément de l'appel Windows.
- `maj.rs` : préparer l'installation dans un dossier de travail réservé à SYSTEM sous `%ProgramFiles%\deR4Tizer` (créé par le service, propriétaire vérifié) ; y copier les fichiers vérifiés ; revérifier empreinte et signature dans ce dossier ; y garder aussi la sauvegarde du retour arrière.
- `api.rs` et `notifications.rs` : créer jeton et secrets avec leurs droits dès la création (pas d'écriture puis `icacls`), et traiter l'échec d'`icacls` comme un échec.

**Critères d'acceptation :**

- Après installation MSI : propriétaire Administrateurs, aucun droit d'écriture pour `Utilisateurs`, `Utilisateurs authentifiés` ni le compte connecté (vérifié par `Get-Acl`).
- Un compte standard ne peut créer aucun fichier ni dossier dans `C:\ProgramData\deR4Tizer`, ni avant ni après la première ouverture de session.
- Dossier précréé par un compte standard avant l'installation : après installation, propriétaire Administrateurs et plus aucun accès en écriture pour ce compte.
- Un fichier de configuration appartenant à un compte standard est ignoré et signalé.
- Tests unitaires de la décision « propriétaire acceptable » ; test d'intégration CI (lot 3) couvrant les trois scénarios.

### Lot 1 bis : quarantaine et mise à l'écart sans perte de données

**Constat :** `protection.rs:trier` supprime un élément quand sa mise à l'écart échoue ; et `reponse.rs:mettre_en_quarantaine` déplace le fichier par `fs::rename`, qui conserve le propriétaire d'origine (le compte de l'utilisateur). Au démarrage suivant, le fichier quarantainé est donc écarté (restauration impossible) ou supprimé (perte du fichier d'un faux positif).

**À faire :**

- `trier` : jamais de suppression ; déplacement impossible = élément intact, échec journalisé, démarrage en échec fermé.
- Quarantaine : copie vers un fichier créé par le service avec ses droits (propriétaire SYSTEM), SHA-256 enregistré dans `quarantaine.json`, puis suppression de l'original ; empreinte vérifiée à la restauration.
- Migration : fichiers de `quarantaine\` présents dans `quarantaine.json` recopiés ainsi au démarrage, pas écartés.

**Critères :** tests « quarantaine, redémarrage, restauration », « ancien fichier quarantainé migré sans perte », « déplacement impossible : intact et échec fermé », « création de ecartes impossible : intact et échec fermé ». Scénario « quarantaine, redémarrage, restauration » ajouté au lot 3.

### Lot 1 ter : opérations de fichiers SYSTEM sur des chemins de l'utilisateur

**Constat :** plusieurs opérations du service, en SYSTEM, portent sur des chemins choisis ou contrôlés par
l'utilisateur, avec un contrôle puis une opération par chemin. Une jonction ou un lien posé entre les deux
redirige l'opération vers un dossier système (élévation de privilèges) :
- `reponse.rs`, restauration : écriture du fichier et de sa marque Internet à `chemin_origine` ;
- `reponse.rs`, mise en quarantaine : lecture puis suppression de l'original (pause de 500 ms entre l'arrêt
  des processus et la copie) ;
- `reponse.rs`, reprise au démarrage : lecture de l'empreinte de `chemin_origine` à chaque démarrage.

**À faire :**

- Quarantaine : ouvrir l'original une seule fois par handle sans suivre les liens
  (`FILE_FLAG_OPEN_REPARSE_POINT`), vérifier son chemin final (`GetFinalPathNameByHandle`) contre le chemin
  attendu, lire le contenu et la marque Internet, puis supprimer par ce même handle (`FileDispositionInfo`) ;
  aucune opération par chemin après le contrôle.
- Restauration : écrire le fichier et sa marque en empruntant le jeton de l'utilisateur propriétaire de
  l'emplacement (session ouverte), pour que les droits de Windows s'appliquent à lui et pas à SYSTEM ; si
  aucune session de cet utilisateur n'est ouverte, refuser et proposer une restauration dans un dossier créé
  par le service.
- Reprise au démarrage : lire l'empreinte de l'original par handle sans suivre les liens, avec vérification
  du chemin final ; un élément de chemin qui est un lien = original « différent » (la copie est gardée).
- Outillage : compilation locale alignée sur la CI (chaîne MSVC) dans `compiler-rs.ps1` et le README ; les
  tests sur un poste se font avec l'artefact de la CI, jamais avec une compilation locale GNU.

**Critères d'acceptation :**

- Test « jonction posée avant restauration » : rien n'est écrit hors du dossier d'origine.
- Test « jonction posée pendant la quarantaine » : rien n'est lu ni supprimé hors du fichier visé.
- Test « lien dans le chemin d'origine au démarrage » : la copie est gardée, rien n'est lu hors du chemin.
- Restauration sans session de l'utilisateur : refusée ou dirigée vers le dossier du service, jamais écrite
  en SYSTEM à l'emplacement d'origine.
- Scénarios correspondants ajoutés au lot 3.

### Lot 2 : mise à jour, retour en arrière par manifeste et transaction

**Constat :** la version n'est lue que dans le manifeste, qui n'est pas signé. Un manifeste falsifié annonçant « 99.0 » peut faire installer une ancienne version signée par la bonne clé mais vulnérable. Depuis la v4.3, le MSI porte `AllowDowngrades="yes"` (pour le retour arrière) : le refus d'installer une version plus ancienne, seule barrière restante, a disparu. Le lot 2 doit lire la version dans l'artefact signé avant toute installation, ou rétablir ce refus et faire le retour arrière autrement.

**À faire :**

- Lire la version réelle dans l'artefact après vérification de signature : ressource de version de l'exécutable, `ProductVersion` du MSI. Exiger : version de l'artefact = version du manifeste, et strictement plus récente que la version installée. Sinon refuser.
- Manifeste strict : champs connus seulement, pas de doublon de fichier, liste attendue complète (MSI obligatoire, exécutables cohérents), taille bornée.
- Santé après installation : envoyer la commande `{"Action":"verification"}` dans le tube et exiger une réponse JSON valide du service, pas seulement l'existence du tube. En cas d'échec : réinstaller le MSI précédent conservé dans le dossier de travail (pas une copie d'exécutables qui laisse la base Windows Installer incohérente).
- Clés épinglées : liste (clé actuelle et clé suivante) dans `DER4TIZER_CLES_SIGNATURE`, chaque entrée de 64 caractères hexadécimaux ; l'interface n'affiche « clé épinglée » que si au moins une entrée est valide.

**Critères d'acceptation :** tests unitaires sur la décision d'installation couvrant : version artefact ≠ manifeste, version égale ou plus ancienne, fichier manquant, fichier en double, fichier inattendu, empreinte fausse, signature absente, clé inattendue, liste de clés vide ou mal formée. Retour arrière décrit et testé au moins par simulation (service qui ne répond pas).

### Lot 3 : CI d'intégration et chaîne de publication

- Nouveau job CI sur `windows-latest` qui, avec le MSI construit : installe ; vérifie service (compte, démarrage, reprise), droits du dossier (lot 1) ; crée un compte local standard et vérifie depuis ce compte (`Start-Process -Credential`) que le tube refuse ses commandes et qu'il ne peut rien écrire dans le dossier de données ; scénario du dossier précréé, y compris avec des fichiers à DACL vide (`D:P`, propriétaire illisible pour SYSTEM) comme `config.json`, `lecteurs.json` ou `apprentissage.json` : ils doivent être écartés et jamais chargés ; fichier piégé tenu ouvert (sans partage de suppression) pendant le démarrage du service, puis redémarrage : jamais chargé, ni au premier ni au second démarrage ; quarantaine d'un fichier, redémarrage du service, restauration : fichier restauré à l'identique ; lot 1 ter avec le service réel : jonction posée avant une restauration (rien d'écrit hors du dossier d'origine), jonction posée pendant une mise en quarantaine (rien de lu ni de supprimé hors du fichier visé), lien dans le chemin d'origine au démarrage (copie gardée), restauration sans session du propriétaire (refusée, repli dans le dossier du service, jamais d'écriture en SYSTEM à l'emplacement d'origine), restauration avec session (fichier créé sous l'identité de l'utilisateur) ; mise à niveau depuis le MSI de la version précédente ; désinstallation avec et sans `GARDER_DONNEES=1`.
- Scénario d'exécution avec Microsoft Defender actif, avec l'artefact MSVC de la CI : installation,
  mise en quarantaine d'un fichier de test bénin, redémarrage, restauration. Aucune détection.
  Tant que ce scénario n'a pas réussi, aucune distribution, même à un testeur.
- WiX : vérifier l'empreinte SHA-256 de `wix314-binaries.zip` (valeur figée dans le workflow) dans `ci.yml` et `publication.yml`.
- `publication.yml` : séparer compilation (sans secret) et signature (reçoit seulement les artefacts, environnement `publication`). Aucune compilation ni script de dépendance dans le job qui détient le certificat.

**Critère :** tous ces contrôles s'exécutent à chaque pull request et échouent bruyamment.

### Lot 4 : état des lieux documenté (phase 0, une journée au plus)

Créer à partir du code et des revues déjà faites, sans réaudit complet :

- `docs/roadmap/capability-matrix.md` : chaque capacité avec un état parmi « prévu », « implémenté non vérifié », « testé en labo », « validé sur Windows », « prêt pour la production » ; fichiers sources ; prérequis Windows ; tests existants ; limites. L'IDS, le DPI et le NDR sont classés expérimentaux. Limite connue à y inscrire : en échec de la protection du dossier de données, l'alerte critique reste locale (les secrets de remontée sont ignorés), le prestataire n'est pas prévenu. Risque résiduel à y inscrire : le MSI accepte une version plus ancienne (`AllowDowngrades`, nécessaire au retour arrière) ; le refus d'une version plus ancienne est assuré par le service, sur la version lue dans le paquet signé, et un administrateur peut toujours installer une version plus ancienne à la main. Limite à y inscrire : l'export syslog (`export.rs`) part en clair (UDP ou TCP, sans TLS) ; à réserver à un réseau local de confiance.
- `docs/security/threat-model.md` : frontières de privilège (service SYSTEM, interface, tube, API, mise à jour, dossier de données, capture réseau), attaquants considérés (compte standard local, appareil du LAN, compte GitHub compromis, liste de menaces corrompue), mesures et risques résiduels.
- `docs/architecture/current-state.md` et `docs/testing/baseline.md` (commandes de compilation et de test réellement exécutées, résultats).
- `docs/reponse/politique.md` : niveaux de réponse 0 à 3. Seules actions de niveau 3 (automatiques) autorisées : blocage des IP Spamhaus DROP et Feodo Tracker, suspension du programme qui touche un leurre. Tout le reste, IPS compris, au niveau 2 au plus (désactivé par défaut ou confirmation).
- README aligné sur la matrice : aucune affirmation plus forte que l'état réel.

### Lot 5 : correctifs non bloquants des revues

- `apprentissage.rs`, `editeur()` : clé de cache = chemin + date de modification.
- `api.rs`, `nouveau_jeton()` : le résultat de `BCryptGenRandom` est ignoré ; en cas d'échec, un jeton nul serait accepté. Échouer fermé : pas d'API sans jeton valide.
- `api.rs`, `/api/v1/sante` : ne plus renvoyer le nom de la machine sans jeton.
- `canal.rs` : délai maximal de lecture d'une commande (un client admin silencieux bloque aujourd'hui tout le canal) et taille maximale déjà bornée, à tester.
- Documenter dans le README que `msiexec /fa` (réparation) par un compte standard arrête puis relance brièvement le service.
- Lectures du dossier de données hors de `commun::lire_fichier` (menaces.rs, ids.rs `regles\`, hygiene.rs
  `loldrivers.json`, dpi.rs JA3, siem.rs) : propriétaire contrôlé partout ; en échec fermé, aucune réponse
  automatique alimentée par ces fichiers (blocage automatique, IPS).
- `commun::lisible_en_echec` : retirer `dns.json`.
- `natif::avec_privilege_restauration` : si `RevertToSelf` échoue, arrêter le service.
- canal.rs : tube occupé par un autre processus au démarrage (squat) : alerte critique locale
  avec le PID et le chemin du processus qui le détient, plutôt qu'une simple ligne de journal.

### Ensuite (après validation des lots 1 à 5, une phase à la fois, avec accord)

1. Phase 1 complète : autorisation vérifiée par commande, validation de chaque champ reçu, limites de débit et de concurrence, tests de messages malformés, tronqués, silencieux.
   Architecture, dans la même phase (à faire après la fusion des PR ouvertes, qui touchent ces fichiers) :
   - Condition préalable : mesure du cycle de surveillance (durée de chaque étape, PowerShell lancés pendant le cycle, temps passé sous le verrou). Sans ces chiffres, ni découpage de `Moniteur` ni optimisation.
   - `Moniteur` (moniteur.rs), une fois la mesure faite et seulement là où elle le justifie : les actions longues (quarantaine, restauration, baseline, panique) faites hors du verrou `Arc<Mutex<Moniteur>>`, pris seulement pour enregistrer le résultat : une quarantaine ne doit plus aveugler la surveillance, ni un cycle lent bloquer l'interface ; `executer()` (28 commandes dans un seul `match`) découpé en un gestionnaire par domaine (réponse, blocages, configuration, mise à jour, protection) ; `passage()` (cycle de 3 s) découpé en étapes, chacune avec sa minuterie.
   - Pas de découpage de `natif.rs` pour lui-même : du seul déplacement de code, en conflit avec toutes les PR ouvertes. Seulement si une mesure ou une correction le justifie, au moment de celle-ci.

   Validation par le mainteneur, le 2026-10-25, par ces mots : « Yes: once the remaining Phase 1 fixes are merged with a clean VM pass, I validate Phase 1, and Phase 3 can open with the local VM proof replacing GitHub CI. Record it in CLAUDE.md. »
   - Derniers correctifs de la phase 1, ceux qui lui avaient été présentés :
     - #64 : outillage de test ;
     - #65 : files d'alertes reprises à l'arrêt du service ;
     - texte des confirmations de l'assistant élevé passé par `Visible()` partout ;
     - fenêtre de confirmation qui renvoie à la ligne et défile, et montre le domaine enregistrable (S60-06/07).
   - Une fois ces correctifs fusionnés, chacun relu et couvert par un passage VM sans ÉCHOUÉ sur l'arbre intégré, la phase 1 est validée par cryptobones-1337.
   - La phase 3 s'ouvre alors. Pour son ouverture et pour ses PR, la preuve locale en VM (section 4, « Exception temporaire ») tient lieu de CI GitHub.
   - Le 2026-10-25, le mainteneur a levé, pour l'ouverture de la phase 3, la condition du lot 3d, par ces mots : « Phase 3 can open ». Le lot 3d est encore « non exécuté » dans `docs/roadmap/capability-matrix.md`, alors que cet en-tête pose la condition « après validation des lots 1 à 5 ». La phase 3 s'ouvre donc à la validation de la phase 1 (puce précédente), sans attendre le lot 3d.
   - Rien ne change pour la distribution : la règle de la section 4 reste entière (CI GitHub verte, lot 3d réussi, binaires signés, relecture indépendante).
2. Phase 3 : un modèle d'événement versionné ; chaque règle de détection avec identifiant, justification, télémétrie requise, test positif, test négatif, faux positifs attendus. Distinguer « rien de suspect » de « collecte indisponible ».
3. Phase 4 : cycle de vie des incidents, chronologie reconstituable, santé des collecteurs visible.
   Santé de l'interface, dans la même phase : l'interface (deR4Tizer.exe) tourne sous le compte de l'utilisateur, qui peut l'arrêter, comme tout programme lancé sous ce compte. Le service (SYSTEM) repère qu'elle a disparu d'une session ouverte et, au choix à trancher, la relance dans cette session ou lève une alerte remontée au prestataire. Les notifications locales n'apparaissent plus sans elle ; la détection et la remontée par le service continuent.
4. Phase 6 : application de `docs/reponse/politique.md` dans le code, revalidation de l'identité du processus juste avant chaque action, protection contre les boucles d'actions. Chaque action de réponse a une durée maximale et une procédure de récupération testée ; à l'échéance, jamais de reprise automatique d'un processus suspendu ni de levée automatique d'une isolation : l'alerte est relancée vers le prestataire, la récupération est une action humaine.
5. Phase 7 : filtrage par nom de domaine (DNS, publicités, pistage). Ouverte par le mainteneur le 2026-10-25, par ces
   mots : « Open a phase for the feature > do it like your example », l'exemple proposé étant « Phase 7: domain-name
   filtering (DNS, ads, tracking) ». Commence une fois les phases 1, 3, 4 et 6 validées par la relecture et par
   cryptobones-1337 ; c'est l'une des exceptions au gel (section 2, règle 1), avec les phases 8 et 9.
   - Contenu : navigation sécurisée par le DNS (domaines malveillants des listes de menaces, changement de serveur DNS
     détecté, DNS chiffré si le dossier de conception le justifie) et blocage des domaines de publicité et de pistage,
     par un même mécanisme.
   - Pour toute la phase : dossier de conception d'abord (agent concepteur-fonctionnalites), puis une PR par étape ;
     désactivé par défaut ; retour arrière garanti (désinstallation, panne du service) ; aucun pilote noyau ; aucune
     dépendance nouvelle sans accord ; lignes de l'utilisateur du fichier hosts jamais réécrites ; jamais d'exclusion
     ni d'affaiblissement de Defender (règle 2) : si Defender signale le mécanisme, on en change ; effets sur les VPN,
     les réseaux d'entreprise et les portails captifs traités dans le dossier ; un résolveur DNS tiers n'est utilisé que
     si l'utilisateur le choisit, et il est nommé dans l'interface.
   - L'IDS, le DPI et le NDR restent gelés pendant la phase 7 : elle ne les dégèle pas.
6. Phase 8 : configuration standard (utilisateurs finaux) et avancée (utilisateurs techniques). Ouverte par le mainteneur
   le 2026-10-25 (« Add the phases », en réponse à la proposition « Phase 8: standard/advanced settings »). Commence
   une fois la phase 7 validée par la relecture et par cryptobones-1337. Le mode ne change que ce que l'interface
   montre, jamais les droits ni la validation du service ; mode standard par défaut ; bascule visible et réversible ;
   aucune option du mode avancé n'affaiblit la protection. Mêmes garde-fous que la phase 7 (dossier de
   conception d'abord, une PR par étape, aucune dépendance nouvelle sans accord).
7. Phase 9 : surveillance des fuites de données. Ouverte par le mainteneur le 2026-10-25 (« Add the phases », en réponse
   à la proposition « Phase 9: breach monitoring »), avec cette condition : « Breach monitoring > ok to rely on third
   party as long as it's free ». Commence une fois la phase 8 validée par la relecture et par cryptobones-1337. Pour des
   adresses de courriel indiquées par l'utilisateur, par un service tiers gratuit seulement (sans service gratuit qui
   convienne, la fonctionnalité n'est pas faite), jamais par la lecture de fichiers de données volées ; propriété de
   l'adresse vérifiée par le service tiers ou par un code envoyé à l'adresse (à trancher dans le dossier, qui nomme
   alors le serveur d'envoi) ; adresse jamais journalisée ni envoyée ailleurs qu'à ce service (et au serveur d'envoi du
   code, s'il est retenu) ; désactivée par défaut ; service tiers nommé dans l'interface. Mêmes garde-fous que la phase
   7.
   L'IDS, le DPI et le NDR restent gelés pendant les phases 8 et 9.

L'IDS, le DPI et le NDR restent gelés en l'état (corrections de sûreté uniquement) tant que ces phases ne sont pas validées.
Seule exception, pour la phase 3 (mainteneur, 2026-10-25, par ces mots : « Yes: add the rule identifier line to IDS, DPI and NDR alerts, with no other change to their logic. They stay frozen otherwise. ») : une ligne qui pose l'identifiant de règle (`EXP-*`, `docs/detection/regles.md`) dans leurs alertes, sans autre changement de leur logique.

## 6. Actions réservées à l'humain

Claude Code ne les fait pas ; il peut les rappeler.

- Supprimer la version GitHub v4.1 (publiée avec l'ancien mécanisme de mise à jour) et vérifier que tous les postes sont en 4.2 ou plus.
- Activer la protection de `main` : pull request obligatoire, CI verte obligatoire, pas de poussée forcée.
- Protéger les tags `v*` ; exiger une approbation sur l'environnement `publication`.
- Obtenir le certificat de signature (SignPath Foundation ou Azure Trusted Signing) et renseigner la variable `CLE_SIGNATURE`.
- Décider de toute publication.

## 7. Définition de « terminé »

Un changement n'est terminé que si :

- son comportement est documenté ;
- ses modes d'échec ont été examinés, et ceux qui touchent la sécurité échouent fermés ;
- des tests positifs, négatifs et aux limites existent et ont été exécutés, ou leur non-exécution est déclarée ;
- aucun secret ne fuit dans les journaux ni sur la ligne de commande ;
- la matrice des capacités et le README reflètent l'état démontré, pas l'état espéré ;
- le rapport de lot (section 4) est écrit, la relecture a rendu « Go » et cryptobones-1337 a donné son accord pour fusionner.
