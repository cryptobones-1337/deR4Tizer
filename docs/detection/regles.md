# Règles de détection : fiches (phase 3)

Inventaire des détections **qui existent déjà** dans le service. Aucune règle nouvelle. Chaque fiche donne l'identifiant
de la règle, ce qu'elle couvre, la télémétrie dont elle dépend et ce qui se passe si cette télémétrie manque, son niveau,
ses faux positifs attendus, ses tests et son état de mesure.

État de mesure de toutes les fiches à ce jour : **non mesurée**. Aucune n'a encore de test positif et négatif à son nom,
ni de faux positifs comptés. Les PR de domaine de la phase 3 les mesurent une à une (en labo, puis en VM quand c'est
permis) et mettent la fiche et `docs/roadmap/capability-matrix.md` à jour.

Règles de forme :

- identifiant `DOM-NNN`, jamais réutilisé ; une règle retirée reste listée, marquée « retirée » ;
- `COR-R1` à `COR-R10` gardent les numéros actuels du SIEM (`incidents.json`) ;
- `EXP-*` : modules expérimentaux gelés (IDS, DPI, NDR). Seule une ligne d'identifiant de règle est ajoutée à leurs
  alertes, sans autre changement de logique (mainteneur, 2026-10-25, voir `CLAUDE.md`) ;
- une alerte qui réunit plusieurs indices d'un même domaine porte l'identifiant de la règle la plus forte (par exemple
  PRC-001 et PRC-002 dans la même alerte : PRC-001).

« Si la télémétrie manque » décrit le comportement **actuel** : dans la plupart des cas, la règle se tait sans le dire.
L'état des collectes (PR 3.3) rendra ce silence visible.

Domaines : `RES` connexions, `DNS`, `PRC` processus, `CHA` chaînes de processus, `PER` persistance, `DEF` Defender,
`LEU` leurres, `VOL` vol de données, `SYS` fichier hosts et pare-feu, `PIL` pilotes, `EXT` extensions de navigateur,
`VIE` vie privée et accès distant, `BAS` baseline, `COR` corrélations du SIEM, `INT` intégrité du service, `EXP`
modules expérimentaux.

---

## RES : connexions

### RES-001 : connexion vers une adresse ou un domaine des listes de menaces
- **Code** : `moniteur.rs` (passage, branche « menace », niveau Critique).
- **Justification** : un programme du poste parle à une infrastructure malveillante connue (Spamhaus DROP, Feodo
  Tracker, listes de domaines) ; c'est le signe le plus direct d'une infection active.
- **Télémétrie** : table des connexions TCP, listes de menaces chargées ; journal DNS pour rattacher un domaine.
- **Si elle manque** : table illisible : aucune connexion vue ; listes vides ou absentes : la règle se tait.
- **Niveau** : Critique. Peut déclencher le blocage automatique (niveau 3 de `docs/reponse/politique.md`).
- **Faux positifs attendus** : adresse partagée (hébergement mutualisé) ajoutée à une liste ; liste périmée.
- **Tests** : à écrire (`res_001_positif`, `res_001_negatif`).

### RES-002 : nouvelle connexion au score suspect (≥ 3)
- **Code** : `moniteur.rs` (calcul du score des flux, niveau Alerte).
- **Justification** : réunit des indices faibles qui, ensemble, décrivent un programme malveillant qui sort sur Internet.
- **Indices** (une seule règle, chaque indice nommé dans `Raisons`) : programme non signé ; dossier temporaire ou
  téléchargements ; fichier téléchargé récemment ; ligne de commande suspecte ; adresse IP directe sans requête DNS ;
  balise (connexions régulières) ; port inhabituel ; télémétrie.
- **Télémétrie** : connexions, processus (chemin, signature, ligne de commande) ; l'indice « IP directe » exige le
  journal DNS.
- **Si elle manque** : sans journal DNS, l'indice « IP directe » peut se déclencher à tort ou manquer ; sans ligne de
  commande (WMI), l'indice correspondant manque.
- **Niveau** : Alerte.
- **Faux positifs attendus** : applications de messagerie ou de jeu qui se connectent sans DNS ; outils internes non
  signés.
- **Tests** : à écrire, un positif et un négatif par indice.

### RES-003 : première connexion à Internet d'un programme
- **Code** : `moniteur.rs` (niveau Info).
- **Justification** : donne l'historique de « qui parle à Internet » ; utile à l'enquête, pas une alarme.
- **Télémétrie** : connexions.
- **Si elle manque** : la règle se tait.
- **Niveau** : Info.
- **Faux positifs attendus** : chaque nouveau programme ou nouvelle version (attendu, par nature).
- **Tests** : à écrire.

### RES-004 : adresse publique directement sur le PC
- **Code** : `moniteur.rs` (« PC EXPOSÉ À INTERNET : adresse publique directement sur le PC »).
- **Justification** : un PC sans box ni NAT devant lui est joignable depuis Internet.
- **Télémétrie** : adresses des cartes réseau.
- **Si elle manque** : la règle se tait.
- **Niveau** : Alerte.
- **Faux positifs attendus** : réseau d'entreprise avec adresses publiques volontaires ; IPv6 globale (selon le cas).
- **Tests** : à écrire.

### RES-005 : paquet entrant venu d'Internet
- **Code** : `parefeu.rs` (journal du pare-feu, « PC EXPOSÉ À INTERNET : paquet entrant … »).
- **Justification** : un paquet entrant depuis une adresse publique, surtout accepté, montre un PC exposé.
- **Télémétrie** : `pfirewall.log` (journalisation des paquets du pare-feu Windows).
- **Si elle manque** : journal du pare-feu désactivé ou illisible : la règle se tait.
- **Niveau** : Critique si le paquet est accepté, Alerte s'il est bloqué. Une alerte par source, port et action en
  24 h.
- **Faux positifs attendus** : box en DMZ ou redirection de port voulue (signalé aussi par la revue UX).
- **Tests** : à écrire.

## DNS

### DNS-001 : requête DNS vers un domaine malveillant connu
- **Code** : `moniteur.rs` (« requête DNS vers un domaine MALVEILLANT connu »).
- **Justification** : la résolution d'un domaine de commande ou de distribution de malware, même sans connexion.
- **Télémétrie** : journal DNS-Client (ou Sysmon 22), listes de domaines.
- **Si elle manque** : journal DNS coupé après le démarrage : jamais vu aujourd'hui, la règle se tait.
- **Niveau** : Critique.
- **Faux positifs attendus** : domaine retiré tardivement d'une liste ; résolution provoquée par un outil de sécurité.
- **Tests** : à écrire. En VM, domaine de test placé dans une liste locale de test, jamais un vrai domaine malveillant.

## PRC : processus

### PRC-001 : document bureautique qui lance un interpréteur
- **Code** : `processus.rs` (`analyser`, « macro ou exploit probable »).
- **Justification** : Word, Excel ou un lecteur PDF qui lance PowerShell, cmd, wscript… est la marque d'une macro ou
  d'un exploit.
- **Télémétrie** : création de processus (Sysmon 1 ou WMI) avec le parent.
- **Si elle manque** : flux WMI arrêté : la source reste affichée « WMI » et la règle se tait.
- **Niveau** : Critique (signal fort, jamais adouci par l'apprentissage).
- **Faux positifs attendus** : modèles d'entreprise qui lancent un script légitime.
- **Tests** : à écrire.

### PRC-002 : PowerShell obscurci ou qui télécharge du code
- **Code** : `processus.rs` (expression « PowerShell obscurci ou qui télécharge du code »).
- **Justification** : `-EncodedCommand` long, `DownloadString`, `IEX` d'une adresse : chargement de code typique.
- **Télémétrie** : ligne de commande (Sysmon 1, ou WMI tant que le processus vit).
- **Si elle manque** : processus terminé avant la lecture WMI : ligne de commande absente, la règle se tait.
- **Niveau** : Alerte.
- **Faux positifs attendus** : scripts d'administration ou d'installation encodés.
- **Tests** : à écrire. En VM, `powershell -enc` d'un `Write-Output 1` ; à remplacer si Defender (AMSI) réagit.

### PRC-003 : détournement d'outil Windows (LOLBin)
- **Code** : `processus.rs` (certutil, bitsadmin, mshta, regsvr32, rundll32, wmic).
- **Justification** : outils signés Microsoft utilisés pour télécharger ou exécuter du code.
- **Télémétrie** : ligne de commande.
- **Si elle manque** : comme PRC-002.
- **Niveau** : Alerte.
- **Faux positifs attendus** : `certutil -decode` dans des scripts d'administration.
- **Tests** : à écrire.

### PRC-004 : navigateur lancé en débogage à distance
- **Code** : `processus.rs` (`--remote-debugging-port` ou `-pipe` sur Chrome, Edge, Brave).
- **Justification** : technique de vol de cookies qui contourne le chiffrement des navigateurs.
- **Télémétrie** : ligne de commande.
- **Si elle manque** : comme PRC-002.
- **Niveau** : Alerte.
- **Faux positifs attendus** : développeurs web, outils de test automatisé.
- **Tests** : à écrire.

### PRC-005 : suppression des sauvegardes
- **Code** : `processus.rs` (`vssadmin delete shadows`, `wbadmin delete`, `bcdedit … recoveryenabled no`,
  `wmic shadowcopy delete`).
- **Justification** : étape qui précède presque toujours le chiffrement par un rançongiciel.
- **Télémétrie** : ligne de commande.
- **Si elle manque** : comme PRC-002.
- **Niveau** : Critique (signal fort, jamais adouci).
- **Faux positifs attendus** : nettoyage volontaire des clichés par un administrateur.
- **Tests** : à écrire. En VM, `cmd /c echo vssadmin delete shadows` (vssadmin n'est pas lancé) ; négatif :
  `vssadmin list shadows`.

## CHA : chaînes de processus

### CHA-001 : chaîne de processus au score cumulé
- **Code** : `chaines.rs` (au moins deux signaux et score au-dessus du seuil).
- **Justification** : plusieurs actions suspectes d'une même descendance de processus forment une attaque en étapes.
- **Télémétrie** : arbre des processus et signaux des autres règles.
- **Si elle manque** : sans processus, aucune chaîne.
- **Niveau** : Critique.
- **Faux positifs attendus** : installeurs qui enchaînent des outils signalés.
- **Tests** : à écrire.

## PER : persistance

### PER-001 : démarrage automatique nouveau
- **Code** : `persistance.rs` (« NOUVEAU démarrage automatique »).
- **Justification** : un malware s'installe presque toujours pour survivre au redémarrage.
- **Télémétrie** : relevé des démarrages automatiques (clés Run, services, tâches…), toutes les minutes.
- **Si elle manque** : premier relevé (apprentissage) : aucune alerte, voulu ; relevé impossible : silence.
- **Niveau** : Alerte si la cible est jugée suspecte, sinon Info.
- **Faux positifs attendus** : installation d'un logiciel.
- **Tests** : 3a, « Alerte de persistance produite juste avant un arrêt » (bout en bout) ; à écrire à son nom. En VM,
  clé Run de test vers `cmd.exe /c rem`.

### PER-002 : démarrage automatique modifié
- **Code** : `persistance.rs` (« démarrage automatique MODIFIÉ »).
- **Justification** : un démarrage légitime détourné vers une autre commande.
- **Télémétrie** : comme PER-001.
- **Si elle manque** : comme PER-001.
- **Niveau** : Alerte si suspecte, sinon Info.
- **Faux positifs attendus** : mises à jour des logiciels (nouveau chemin de version).
- **Tests** : à écrire.

## DEF : Microsoft Defender

Les règles DEF-003 à DEF-006 et DEF-010 à DEF-012 supposent un Defender affaibli : elles ne sont **jamais** exercées en
VM (Defender intouchable) et restent au mieux « testé en labo ».

| Id | Événement ou état | Niveau |
|---|---|---|
| DEF-001 | 1116 : menace détectée | Critique |
| DEF-002 | 1117 : menace traitée | Info |
| DEF-003 | 5001 : protection en temps réel désactivée | Critique |
| DEF-004 | 5010 / 5012 : analyse antivirus désactivée | Critique |
| DEF-005 | 5007 : exclusion ajoutée | Critique |
| DEF-006 | 5007 : protection affaiblie (temps réel, antispyware, falsification) | Critique |
| DEF-007 | 1121 / 1122 : règle ASR (blocage / audit) | Alerte / Info |
| DEF-008 | 1123 / 1124 : accès contrôlé aux dossiers (blocage / audit) | Alerte / Info |
| DEF-009 | 1125 / 1126 : protection réseau (blocage / audit) | Alerte / Info |
| DEF-010 | État WMI : protection en temps réel coupée entre deux relevés | Critique |
| DEF-011 | État WMI : protection contre les falsifications désactivée | Critique |
| DEF-012 | État WMI : antivirus désactivé | Critique |

- **Code** : `defender.rs` (`traduire` pour DEF-001 à 009, `ecarts` pour DEF-010 à 012).
- **Justification** : Defender est la protection de base du poste ; ses détections et toute tentative de l'affaiblir
  doivent remonter.
- **Télémétrie** : journal Microsoft-Windows-Windows Defender/Operational (DEF-001 à 009) ; état WMI de Defender,
  toutes les 10 min (DEF-010 à 012).
- **Si elle manque** : le résultat de l'abonnement au journal est ignoré aujourd'hui (silence) ; état WMI illisible :
  aucun écart calculé.
- **Faux positifs attendus** : DEF-005 et DEF-006 quand un administrateur règle Defender lui-même ; DEF-007 à 009 en
  mode audit sur des logiciels métier.
- **Tests** : à écrire, par exemple `def_005_positif` (5007 dont la valeur contient `\Exclusions\`) et
  `def_005_negatif` (5007, autre valeur). DEF-001 avec un fichier EICAR : non en VM tant que le lot 3d exige « aucune
  détection ».

## LEU : leurres anti-rançongiciel

### LEU-001 : leurre modifié (empreinte)
- **Code** : `hygiene.rs` (contrôle des empreintes des leurres).
- **Justification** : un fichier que rien ne devrait toucher a changé : chiffrement en cours probable.
- **Télémétrie** : leurres posés et leurs empreintes.
- **Si elle manque** : leurres absents : la règle se tait.
- **Niveau** : Critique.
- **Faux positifs attendus** : outil de nettoyage ou de synchronisation qui réécrit tout un dossier.
- **Tests** : à écrire.

### LEU-002 : leurre touché (audit des accès)
- **Code** : `vol_donnees.rs` (événement 4663 sur un leurre).
- **Justification** : même raison que LEU-001, au moment de l'accès ; peut suspendre le programme (réponse automatique
  au rançongiciel, niveau 3).
- **Télémétrie** : journal Sécurité 4663 et audit (SACL) posé sur les leurres.
- **Si elle manque** : audit des objets désactivé : la règle se tait.
- **Niveau** : Critique ; Info si le programme est un logiciel connu et signé (sauvegarde, synchronisation, antivirus),
  qui n'est pas suspendu.
- **Faux positifs attendus** : logiciel de sauvegarde ou d'indexation non encore reconnu.
- **Tests** : à écrire.

## VOL : vol de données

### VOL-001 : accès aux secrets des navigateurs par un autre programme
- **Code** : `vol_donnees.rs` (« comportement typique d'un VOLEUR DE DONNÉES »).
- **Justification** : les voleurs d'identifiants lisent les bases de mots de passe et de cookies des navigateurs.
- **Télémétrie** : journal Sécurité 4663 et audit (SACL) sur les fichiers des profils.
- **Si elle manque** : audit désactivé : la règle se tait.
- **Niveau** : Critique si le programme vient d'un dossier temporaire, des téléchargements ou du profil public, sinon
  Alerte.
- **Faux positifs attendus** : gestionnaires de mots de passe, outils de migration de profil.
- **Tests** : à écrire.

## SYS : fichier hosts et pare-feu

### SYS-001 : fichier hosts modifié par un autre programme
- **Code** : `moniteur.rs` (empreinte du fichier hosts).
- **Justification** : redirection de domaines vers un serveur de l'attaquant, ou blocage des mises à jour de sécurité.
- **Télémétrie** : empreinte du fichier hosts.
- **Si elle manque** : fichier illisible : aucune comparaison.
- **Niveau** : Alerte.
- **Faux positifs attendus** : logiciels de blocage de publicités, outils de développement.
- **Tests** : à écrire. En VM, ligne de commentaire ajoutée au fichier hosts.

### SYS-002 : règle de pare-feu ajoutée ou modifiée
- **Code** : `parefeu.rs` (suivi des modifications du pare-feu).
- **Justification** : ouvrir un port entrant est un moyen classique de garder un accès au poste.
- **Variantes** : auteur non signé : Critique ; port entrant ouvert en ligne de commande : Alerte ; autorisation
  entrante par un auteur introuvable : Alerte ; par un programme tiers signé ou un installeur de mise à jour : Info.
- **Télémétrie** : journal du pare-feu (Windows Firewall With Advanced Security), signature de l'auteur.
- **Si elle manque** : le résultat de l'abonnement est ignoré aujourd'hui (silence).
- **Faux positifs attendus** : installeurs de logiciels qui ouvrent leurs ports.
- **Tests** : à écrire.

### SYS-003 : règles du pare-feu disparues
- **Code** : `parefeu.rs` (après une suppression de toutes les règles, moins de 50 revenues en 60 s).
- **Justification** : un pare-feu vidé désarme le poste.
- **Télémétrie** : journal du pare-feu, nombre de règles.
- **Si elle manque** : comme SYS-002.
- **Niveau** : Critique.
- **Faux positifs attendus** : réinitialisation volontaire du pare-feu par un administrateur.
- **Tests** : à écrire.

## PIL : pilotes

### PIL-001 : pilote vulnérable connu présent
- **Code** : `hygiene.rs` (liste LOLDrivers, une fois par jour).
- **Justification** : un pilote signé mais vulnérable permet de désactiver les protections (BYOVD).
- **Télémétrie** : liste LOLDrivers chargée, pilotes du disque.
- **Si elle manque** : liste vide ou illisible : « aucun pilote vulnérable », à tort.
- **Niveau** : Critique.
- **Faux positifs attendus** : ancien pilote de matériel encore présent mais inutilisé.
- **Tests** : à écrire.

## EXT : extensions de navigateur

### EXT-001 : nouvelle extension de navigateur
- **Code** : `hygiene.rs` (`verifier_extensions`, toutes les 10 min, sauf au premier relevé).
- **Justification** : une extension malveillante lit tout ce que l'utilisateur fait dans le navigateur.
- **Télémétrie** : profils des navigateurs.
- **Si elle manque** : profil illisible : la règle se tait.
- **Niveau** : Alerte.
- **Faux positifs attendus** : chaque extension installée volontairement.
- **Tests** : à écrire.

## VIE : vie privée et accès distant

| Id | Détection | Code | Niveau |
|---|---|---|---|
| VIE-001 | Programme qui utilise la caméra ou le micro pour la première fois | `surveillances.rs` | Alerte |
| VIE-002 | Outil de prise en main à distance en cours d'exécution | `surveillances.rs` | Alerte |
| VIE-003 | Bureau à distance activé | `surveillances.rs` | Alerte |

- **Justification** : espionnage par la caméra ou le micro ; arnaques au faux support qui font installer un outil de
  prise en main ; Bureau à distance ouvert par un attaquant.
- **Télémétrie** : registre (consentements d'accès aux périphériques, réglage du Bureau à distance), processus.
- **Si elle manque** : registre illisible : la règle se tait ; l'interface affiche « CAM / MIC OFF » comme si rien
  n'était utilisé.
- **Faux positifs attendus** : VIE-001 à la visioconférence ; VIE-002 pour un support informatique légitime.
- **Tests** : à écrire. En VM, VIE-003 : Bureau à distance activé, puis effacé par l'instantané.

## BAS : baseline

### BAS-001 : réglage de sécurité de la baseline défait
- **Code** : `baseline.rs` (`derives`, toutes les 10 min).
- **Justification** : un réglage de durcissement qui revient en arrière (par un malware, une mise à jour ou une
  personne) rouvre une faiblesse.
- **Télémétrie** : évaluation de la baseline.
- **Si elle manque** : évaluation impossible : aucune dérive calculée.
- **Niveau** : Alerte.
- **Faux positifs attendus** : stratégie de groupe ou administrateur qui change le réglage volontairement.
- **Tests** : à écrire.

## COR : corrélations du SIEM

| Id | Corrélation | Niveau | MITRE |
|---|---|---|---|
| COR-R1 | Tentatives de mot de passe en série | Alerte | T1110 |
| COR-R2 | Session ouverte après une série d'échecs | Critique | T1110 |
| COR-R3 | Nouveau compte administrateur | Critique | T1136.001 |
| COR-R4 | Journal d'événements effacé | Critique | T1070.001 |
| COR-R5 | Service installé depuis un emplacement suspect | Critique | T1543.003 |
| COR-R6 | Attaque en plusieurs étapes (3 détections d'un même programme en 10 min) | Critique | — |
| COR-R7 | Protection affaiblie (service de sécurité arrêté, politique d'audit modifiée) | Alerte | selon l'événement |
| COR-R8 | **Numéro non attribué** : aucune règle R8 dans `siem.rs` à ce jour ; le numéro reste libre, il n'est pas réutilisé pour une autre règle sans décision | — | — |
| COR-R9 | Session ouverte depuis une adresse publique (Bureau à distance : Critique ; autre : Alerte) | Critique / Alerte | T1133 |
| COR-R10 | Pilote vulnérable installé (BYOVD) | Critique | T1068 |

- **Code** : `siem.rs` (`Correlation`).
- **Télémétrie** : journaux Sécurité et Système ; audit avancé (profil de baseline « journalisation »).
- **Si elle manque** : audit désactivé ou journal illisible : la corrélation se tait.
- **Faux positifs attendus** : COR-R1 aux mots de passe mal saisis ; COR-R9 pour un accès distant volontaire.
- **Tests** : à écrire. En VM, COR-R1 : cinq échecs d'ouverture de session d'un compte de test.

## INT : intégrité du service

| Id | Détection | Code | Niveau |
|---|---|---|---|
| INT-001 | Échec de la protection du dossier de données (échec fermé) | `protection.rs` | Critique |
| INT-002 | Tube de commandes déjà pris par un autre processus (squat) | `canal.rs` | Critique |

- **Justification** : un dossier de données mal protégé ou un tube squatté donnerait la main sur le service.
- **Télémétrie** : aucune externe (contrôles du service lui-même).
- **Faux positifs attendus** : aucun connu.
- **Tests** : 3a (premier démarrage en échec fermé) pour INT-001 ; à écrire à leur nom.

## EXP : modules expérimentaux (gelés)

| Id | Module | Code |
|---|---|---|
| EXP-IDS-&lt;sid&gt; | IDS (règles au format Suricata), identifiant de la règle IDS | `ids.rs` |
| EXP-DPI-* | DPI (SNI, JA3, HTTP, DNS) | `dpi.rs` |
| EXP-NDR-* | NDR | `ndr.rs` |

- Gelés par `CLAUDE.md` : seule une ligne qui pose l'identifiant de règle est ajoutée à leurs alertes, sans autre
  changement de logique (mainteneur, 2026-10-25).
- **Télémétrie** : capture réseau.
- **Tests** : ceux des modules, inchangés ; aucune mesure de faux positifs pendant la phase 3.
