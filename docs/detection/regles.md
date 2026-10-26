# Règles de détection : fiches (phase 3)

Inventaire des détections **qui existent déjà** dans le service. Aucune règle nouvelle. Chaque fiche donne l'identifiant
de la règle, ce qu'elle couvre, la télémétrie dont elle dépend et ce qui se passe si cette télémétrie manque, son niveau,
ses faux positifs attendus, ses tests et son état de mesure.

**Depuis la PR 3.2, chaque alerte porte l'identifiant de sa règle** (champ `Regle`, registre `service-rs/src/regles.rs`). Un test vérifie
que ce document et le registre listent les mêmes identifiants.

Les niveaux indiqués sont ceux que le code produit **avant** l'apprentissage et les exceptions : `apprentissage::filtrer`
peut faire passer une « Alerte » en « Info ». Seuls les niveaux « Critique » et « Info » sont garantis tels quels.

État de mesure de toutes les fiches à ce jour : **non mesurée**. Aucune n'a encore de test positif et négatif à son nom,
ni de faux positifs comptés. Les PR de domaine de la phase 3 les mesurent une à une (en labo, puis en VM quand c'est
permis) et mettent la fiche et `docs/roadmap/capability-matrix.md` à jour.

Règles de forme :

- identifiant `DOM-NNN`, jamais réutilisé ; une règle retirée reste listée, marquée « retirée » ;
- `COR-R1` à `COR-R10` gardent les numéros actuels du SIEM (`incidents.json`) ;
- `EXP-*` : modules expérimentaux gelés (IDS, DPI, NDR). Seule une ligne d'identifiant de règle est ajoutée à leurs
  alertes (PR 3.2), sans autre changement de logique (mainteneur, 2026-10-25, voir `CLAUDE.md`) ;
- une alerte qui réunit plusieurs indices d'un même domaine porte l'identifiant de la règle la plus forte qu'elle
  contient (par exemple PRC-001 et PRC-002 dans la même alerte : PRC-001 ; `processus::regle_retenue`). Une alerte ne
  porte qu'une règle. Limite actuelle : pour les lignes de commande, `processus::suspicion_regle` ne rend que le
  **premier** motif trouvé (voir PRC-002 à PRC-005).

« Si la télémétrie manque » décrit le comportement des détections elles-mêmes : dans la plupart des cas, la règle se
tait. Depuis la PR 3.3a, ce silence est publié dans `etat.json` : `Collectes` donne l'état de chaque source de
télémétrie et `ReglesSansCollecte` les règles dont une source nécessaire n'est pas lue (une source jamais notée compte
comme non lue). Depuis la PR 3.4, l'interface le montre : la liste des alertes vide ne dit « Aucune alerte. » que si
chaque détection a sa collecte, sinon elle nomme les détections muettes et les sources qui leur manquent ; une
pastille jaune compte les collectes en panne. Correspondance règle → sources :
`collectes::besoins`. Depuis la PR 3.3b, toutes les sources sont notées : connexions, liste des processus, journaux
(Defender, Sécurité, Système, pare-feu, DNS, Sysmon), état de Defender, WMI des processus, listes de menaces et de
domaines, LOLDrivers, relevé des démarrages automatiques, baseline, leurres, audit des données (SACL), `pfirewall.log`,
extensions, magasin des consentements (caméra, micro), capture du trafic et du réseau local. Ne suivent aucune
source : RES-004, SYS-001, VIE-003, COR-R6, INT-001, INT-002. Par défaut, les listes de domaines sont toutes à licence
restreinte et coupées : `ListesDomaines` est « Desactivee » et DNS-001 « sans collecte ».

Ce que garantit « Active » : la source se **lit** (pour un journal suivi, le numéro du dernier événement et les
nouveaux événements sont lus ; une lecture interrompue passe en « Indisponible » et les événements sont relus au tour
suivant ; depuis la PR 3.3c, un journal désactivé passe en « Indisponible » même s'il reste lisible, et le journal
DNS-Client est réactivé : décision D4). Cela ne garantit pas que Windows **produit** les événements attendus. Cas
connus non détectés :
- politique d'audit modifiée (ouvertures de session non auditées : COR-R1, R2, R3, R9 restent couvertes) ;
- Sysmon configuré sans l'événement 22 (il couvre quand même DNS-001), ou service Sysmon arrêté alors que son journal
  reste lisible ;
- listes de menaces chargées depuis une copie locale ancienne (l'âge n'est pas suivi) ;
- `JournalSecurite` noté par deux lecteurs (SIEM et accès aux fichiers 4663) : un seul en panne ne se voit pas, l'autre
  continuant de lire le même journal ;
- l'audit des données (SACL) posé ne prouve pas que la politique d'audit des accès aux objets est active : sans elle,
  aucun 4663 n'est produit (VOL-001, LEU-002) ; l'audit posé sur les leurres eux-mêmes n'est pas suivi (journal seul) ;
- capture : « Active » dit que le fil de capture tourne, pas qu'il reçoit des paquets (une réception toujours en
  échec n'est pas vue) ;
- leurres : « Active » dit qu'au moins un leurre est suivi, pas que chaque profil en a un ;
- audit des données : un dossier dont le parcours est tronqué (20 000 éléments) ou dont des éléments sont écartés
  (liens) compte comme audité ;
- `pfirewall.log` : un fichier présent alors que la journalisation des paquets a été coupée reste lu (« Active ») ;
- démarrages automatiques : un relevé partiel mais non vide compte comme lu ;
- veille ou hibernation : le délai de trois intervalles se compte en heure murale ; au réveil, les sources à long
  intervalle (baseline, Defender, extensions : 10 min ; audit, listes : 1 h) peuvent rester « Indisponible » jusqu'à
  leur prochaine lecture (échec fermé).

Lecture d'un journal suivi :
- par fenêtres de 5 000 numéros au plus (PR 3.3c) : une fenêtre lue jusqu'au bout avance jusqu'à sa borne, même sans
  événement retenu ; un journal inondé d'événements que la requête écarte ne fige donc plus la lecture ; les fenêtres
  s'enchaînent dans un même tour tant qu'elles se lisent jusqu'au bout, 1,5 s au plus, puis le tour suivant reprend ;
- journal désactivé (encore lisible, mais Windows n'y écrit plus) : « Indisponible », une ligne dans `journal.txt` ; le
  journal DNS-Client est réactivé (une tentative par épisode, D4), les autres sont seulement signalés ; un journal coupé
  par le service lui-même (retour arrière de la baseline, demandé par l'administrateur) est laissé coupé et noté
  « Desactivee », jusqu'à ce qu'il soit réactivé par un autre moyen (une coupure ultérieure par un tiers est alors de
  nouveau réactivée) ; limite : cette coupure n'est retenue qu'en mémoire, et au redémarrage du service le journal
  DNS-Client est réactivé comme à chaque démarrage (le retour arrière ne vaut que jusque-là) ;
- angles morts de la désactivation : une coupure suivie d'une réactivation ne laisse aucune trace de la plage pendant
  laquelle Windows n'a rien écrit ; une coupure et une réactivation par un tiers entre deux tours (2 s) ne sont pas
  vues ; une configuration du canal illisible est prise pour « activé » ;
- un délai dépassé (journal très chargé) n'est pas un blocage : rien n'est sauté, la lecture reprend au tour suivant là
  où elle s'est arrêtée ; la collecte est « Partielle » tant que la lecture progresse ;
- tours sans progrès (délais dépassés et erreurs comptés ensemble) : après 30 tours (une minute), sur un délai, rien
  n'est sauté et la collecte passe « Indisponible » ; sur une erreur (événement illisible), un seul numéro est sauté,
  juste après le dernier lu, puis 2, 4… si le blocage persiste ; le saut est écrit dans `journal.txt` ; les événements
  perdus sont ceux des numéros sautés : au plus deux fois l'écart entre le dernier lu et l'événement fautif ;
- événements écrasés par la rotation du journal avant d'être lus : vérifié avant chaque fenêtre lue (un petit
  journal, comme DNS-Client ou Defender, tourne en quelques milliers d'événements) ; la lecture reprend au plus ancien
  numéro encore présent, la perte est comptée et écrite dans `journal.txt` ; un journal qui grossit plus vite que le
  service ne le lit (plus de 5 000 numéros par fenêtre, 1,5 s de lecture par tour de 2 s) finit ainsi par perdre des
  événements, comptés ;
- après un saut ou une rotation, la collecte reste « Partielle » une heure (« N numéro(s) d'événement perdu(s) »).

Un journal illisible au démarrage est suivi quand même : son fil réessaie toutes les 2 s et le suivi part de la
première lecture réussie (les événements écrits entre-temps ne sont pas relus). Sysmon illisible au démarrage : WMI
prend le relais.
« Partielle » (WMI sans Sysmon) : les processus brefs peuvent manquer, PRC-001 à PRC-005 sont publiées dégradées.

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
- **Si elle manque** : sans lecture du journal DNS depuis plus de trois intervalles (90 s), l'indice « IP directe » n'est
  pas compté (PR 3.3b : il suivait l'état du journal au démarrage et pouvait se déclencher à tort) ; un journal DNS coupé
  est réactivé, ou, s'il ne peut l'être, noté indisponible (PR 3.3c, D4), et l'indice tombe 90 s plus tard ; sans ligne
  de commande (WMI), l'indice correspondant manque.
- **Niveau** : Alerte.
- **Faux positifs attendus** : applications de messagerie ou de jeu qui se connectent sans DNS ; outils internes non
  signés.
- **Tests** : existant pour l'indice « IP directe » : `ip_directe_editeurs_exacts` ; à écrire, un positif et un négatif
  par indice.

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
- **Conditions** : contrôle tous les 100 passages du cycle ; l'alerte ne part que si le **nombre** d'adresses publiques
  augmente. Un PC déjà exposé au démarrage du service ne déclenche donc aucune alerte.
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
- **Tests** : existants : `exposition_reelle_sans_faux_positifs`, `exposition_udp_reponse_reconnue_par_le_flux`,
  `exposition_paquet_bloque_reponse_a_un_flux`.

### RES-006 : nouveau port ouvert en écoute sur le réseau
- **Code** : `surveillances.rs` (`ports_ouverts`).
- **Justification** : un programme qui se met à écouter sur le réseau peut être une porte dérobée.
- **Télémétrie** : table des connexions TCP (ports en écoute), signature du programme.
- **Si elle manque** : table illisible : aucun port vu ; premier relevé (`ecoutes-connues.json` absent) : apprentissage,
  aucune alerte, voulu.
- **Niveau** : Alerte si le programme n'est pas signé, Info sinon.
- **Faux positifs attendus** : logiciels qui ouvrent un port de service local (synchronisation, partage).
- **Tests** : à écrire.

### RES-007 : connexion entrante depuis Internet
- **Code** : `surveillances.rs` (`ports_ouverts`, « CONNEXION ENTRANTE depuis Internet »).
- **Justification** : quelqu'un d'Internet est connecté à un port en écoute du PC. Distincte de RES-005 : elle vient de
  la table TCP (connexion établie), pas du journal du pare-feu.
- **Télémétrie** : table des connexions TCP, signature du programme.
- **Si elle manque** : table illisible : la règle se tait.
- **Niveau** : Critique si le programme n'est pas signé, Alerte sinon.
- **Faux positifs attendus** : serveur volontairement exposé (jeu, accès distant voulu).
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
- **Tests** : à écrire. En VM, `powershell -enc` d'un `Write-Output 1` (40 caractères en base64 : juste au minimum du
  motif, à allonger) ; à remplacer si Defender (AMSI) réagit.

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
- **Tests** : existant : `debogage_a_distance_ancre_sur_l_executable` (cas positifs et négatifs).

### PRC-005 : suppression des sauvegardes
- **Code** : `processus.rs` (`vssadmin delete shadows`, `wbadmin delete`, `bcdedit … recoveryenabled no`,
  `wmic shadowcopy delete`).
- **Justification** : étape qui précède presque toujours le chiffrement par un rançongiciel.
- **Télémétrie** : ligne de commande.
- **Si elle manque** : comme PRC-002.
- **Niveau** : Critique (signal fort, jamais adouci). **Limite** : `processus::suspicion` ne rend que le premier motif
  trouvé, dans l'ordre PowerShell, LOLBin, débogage, sauvegardes. Une ligne qui contient aussi un motif PowerShell (par
  exemple `… DownloadString(…); vssadmin delete shadows`) ne porte que PRC-002, au niveau Alerte : faux négatif connu.
- **Faux positifs attendus** : nettoyage volontaire des clichés par un administrateur.
- **Tests** : à écrire. En VM, `cmd /c echo vssadmin delete shadows` (vssadmin n'est pas lancé) ; négatif :
  `vssadmin list shadows`. Sans Sysmon, la ligne de commande d'un processus aussi bref est souvent perdue par WMI : le
  scénario risque d'être instable.

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
- **Si elle manque** : premier relevé (apprentissage) : aucune alerte, voulu. Relevé **partiel**, sans échec signalé :
  une tâche illisible est sautée, un échec WMI n'est noté qu'au journal. L'entrée sort alors de la référence, puis
  revient au relevé suivant comme un « NOUVEAU démarrage automatique » : faux positif (au niveau Alerte pour une entrée
  WMI, marquée « technique de persistance rare »), pas un silence.
- **Niveau** : Alerte si la cible est jugée suspecte, sinon Info.
- **Faux positifs attendus** : installation d'un logiciel ; relevé partiel (ci-dessus) ; première session d'un compte
  (OneDrive, tâches de Windows par utilisateur).
- **Faux positifs mesurés** (scénario `mesure`, 22 min en VM, service en apprentissage, avant la PR 3.6) : PER-001 Info 11,
  PER-001 Alerte 5 à 6. Les alertes venaient de deux causes, corrigées à la source par la PR 3.6 :
  - tâches `\SoftLanding\…` de Windows « serveur COM non enregistré pour la machine » : leur classe COM est empaquetée
    (`Classes\PackagedCom`, écrite par les administrateurs seulement), désormais résolue vers le fichier de son paquet,
    signé (le chemin lu dans le registre ne peut pas sortir du dossier du paquet) ;
  - `RunOnce` de OneDrive « lancé via cmd » : la commande exacte de nettoyage de son installeur n'est plus suspecte
    (toute variante l'est toujours).
  Restent en Info : entrées OneDrive, services et tâches de Windows qui apparaissent à la première session.
- **Tests** : `per_001_positif`, `per_001_negatif` (`persistance::comparer`), `per_001_com_empaquete_chemin_borne`,
  `per_001_nettoyage_onedrive` ; existants : `tache_com_cible_le_serveur_du_clsid`,
  `tache_com_hors_windows_sans_serveur_signalee`. En VM : clé Run de test vers `cmd.exe /c rem` (3a, « Alerte de
  persistance produite juste avant un arrêt », bout en bout). État : validé sur Windows (VM) pour la clé Run.

### PER-002 : démarrage automatique modifié
- **Code** : `persistance.rs` (« démarrage automatique MODIFIÉ »).
- **Justification** : un démarrage légitime détourné vers une autre commande.
- **Télémétrie** : comme PER-001.
- **Si elle manque** : comme PER-001 (relevé partiel : faux « nouveau »).
- **Niveau** : Alerte si suspecte, sinon Info.
- **Faux positifs attendus** : mises à jour des logiciels (nouveau chemin de version).
- **Faux positifs mesurés** (scénario `mesure`, 22 min en VM) : PER-002 Info 4, les tâches de Defender dont la commande
  passe de `Program Files` au dossier de sa plateforme après une mise à jour. Gardées (Info) : un changement de commande
  est exactement ce que la règle doit voir.
- **Tests** : `per_002_positif` (commande changée vers un dossier suspect : Alerte), `per_002_negatif` (signataire changé
  seul, commande changée pendant l'apprentissage : pas d'alerte). État : testé en labo.

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
- **Si elle manque** : journal illisible ou coupé : collecte `JournalDefender` « Indisponible », DEF-001 à 009 publiées
  sans collecte (PR 3.3) ; état WMI illisible : aucun écart calculé, collecte `EtatDefender` « Indisponible », DEF-010
  à 012 sans collecte.
- **Faux positifs attendus** : DEF-005 et DEF-006 quand un administrateur règle Defender lui-même ; DEF-007 à 009 en
  mode audit sur des logiciels métier.
- **Faux positifs mesurés** : comptage par règle et par heure du scénario `mesure` (22 min d'activité synthétique en VM,
  alertes produites après le début de l'activité, PR 3.5) ; le service y est fraîchement installé, donc en apprentissage
  (7 jours : les alertes non critiques y sont notées « Info ») ; aucune règle DEF n'y est attendue, ce qui ne dit rien
  d'un poste réel (limite D12 : pas de mesure sur poste réel). Mesuré au passage de la PR 3.5 (#81, tête 68a4ce1) :
  **0 alerte DEF** sur 33 alertes en 22 min (preuve en commentaire de la #81).
- **Limite** : DEF-006 ne voit que `DisableRealtimeMonitoring = 0x1`, `DisableAntiSpyware = 0x1` et
  `TamperProtection = 0x4` ; les autres réglages `Disable*` (comportement, IOAV, scripts) et `TamperProtection = 0x0`
  ne lèvent rien (DEF-010 à 012 voient l'effet sur l'état WMI pour le temps réel, la falsification et l'antivirus).
- **Tests** (PR 3.5, `service-rs/src/tests_detection.rs`) : un positif et un négatif par règle, de `def_001_positif` à
  `def_012_negatif`, et `def_traduire_sans_panique` (mini-fuzz de `traduire`). Négatifs : événement voisin non suivi
  (2000, 1118, 5000, 5009, 5011, 1120, 1127) ; exclusion retirée et autre réglage modifié (DEF-005) ; protection
  rétablie (DEF-006) ; audit jamais au niveau « Alerte » (1122 pour DEF-007, 1124 pour DEF-008) ; état déjà coupé au relevé précédent ou illisible (DEF-010 à 012). Ils décrivent le comportement existant
  (aucun changement de `defender.rs`) ; 9 mutations de `defender.rs` les font échouer.
- **En VM** : aucune règle DEF n'est exercée (Defender intouchable, lot 3d) ; DEF-001 avec un fichier EICAR : non tant
  que le lot 3d exige « aucune détection » (D10). Le journal et l'état sont lus en VM (collectes « Active » au 3a).
  État : testé en labo.

## LEU : leurres anti-rançongiciel

### LEU-001 : leurre modifié, supprimé, renommé ou remplacé par un lien
- **Code** : `hygiene.rs` (`verifier_leurres`, empreinte lue par handle vérifié).
- **Justification** : un fichier que rien ne devrait toucher a changé ou disparu : chiffrement en cours probable.
- **Télémétrie** : leurres posés et leurs empreintes. Les leurres ne sont pas posés en mode console.
- **Si elle manque** : leurres non posés : la règle se tait.
- **Niveau** : Critique.
- **Faux positifs attendus** : outil de nettoyage ou de synchronisation qui réécrit tout un dossier.
- **Tests** : existant : `leurres_par_handle_jamais_a_travers_un_lien`.

### LEU-002 : leurre touché (audit des accès)
- **Code** : `vol_donnees.rs` (événement 4663 sur un leurre).
- **Justification** : même raison que LEU-001, au moment de l'accès ; peut suspendre le programme (réponse automatique
  au rançongiciel, niveau 3).
- **Télémétrie** : journal Sécurité 4663 et audit (SACL) posé sur les leurres.
- **Si elle manque** : audit des objets désactivé : la règle se tait.
- **Niveau** : Critique ; Info si le programme est un logiciel connu et signé (sauvegarde, synchronisation, antivirus),
  qui n'est pas suspendu.
- **Faux positifs attendus** : logiciel de sauvegarde ou d'indexation non encore reconnu.
- **Tests** : existant : `b1_leurre_touche_par_rundll32_suspendu`.

## VOL : vol de données

### VOL-001 : accès aux secrets d'un logiciel par un autre programme
- **Code** : `vol_donnees.rs` (« comportement typique d'un VOLEUR DE DONNÉES »).
- **Justification** : les voleurs d'identifiants lisent les bases de mots de passe et de cookies des navigateurs, les
  jetons de Discord et de Telegram, les portefeuilles de cryptomonnaie (Ledger, Exodus, Electrum, MetaMask).
- **Conditions** : une alerte au plus par programme et par cible toutes les 24 h.
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
- **Si elle manque** : fichier illisible : l'empreinte vaut « » (`empreinte_hosts`), différente de la précédente :
  l'alerte « modifié par un autre programme » part **à tort**, puis repart quand le fichier redevient lisible.
- **Niveau** : Alerte.
- **Faux positifs attendus** : logiciels de blocage de publicités, outils de développement ; fichier momentanément
  illisible (ci-dessus).
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

### SYS-003 : toutes les règles du pare-feu supprimées
- **Code** : `parefeu.rs` (opération « toutes supprimées »).
- **Justification** : un pare-feu vidé désarme le poste.
- **Variantes** :
  - par un autre auteur que le service Windows (svchost, binaire Windows) : Critique, tout de suite ;
  - par svchost (rechargement par la stratégie de groupe, `gpupdate`) : Info (« règles du pare-feu rechargées par
    Windows ») ; puis, si moins de 50 règles sont revenues 60 s après : Critique (« pare-feu vidé »).
- **Télémétrie** : journal du pare-feu, nombre de règles.
- **Si elle manque** : comme SYS-002.
- **Niveau** : Critique ; Info pour le rechargement par la stratégie de groupe.
- **Faux positifs attendus** : réinitialisation volontaire du pare-feu par un administrateur.
- **Tests** : à écrire.

## PIL : pilotes

### PIL-001 : pilote vulnérable connu présent
- **Code** : `hygiene.rs` (liste LOLDrivers, une fois par jour).
- **Justification** : un pilote signé mais vulnérable permet de désactiver les protections (BYOVD).
- **Télémétrie** : liste LOLDrivers chargée, pilotes du disque.
- **Si elle manque** : liste vide ou illisible : aucune alerte (silence), comme s'il n'y avait aucun pilote vulnérable.
- **Niveau** : Critique.
- **Faux positifs attendus** : ancien pilote de matériel encore présent mais inutilisé.
- **Tests** : à écrire.

## EXT : extensions de navigateur

### EXT-001 : nouvelle extension de navigateur
- **Code** : `hygiene.rs` (`verifier_extensions`, toutes les 10 min, sauf au premier relevé).
- **Justification** : une extension malveillante lit tout ce que l'utilisateur fait dans le navigateur.
- **Télémétrie** : profils des navigateurs.
- **Si elle manque** : profil illisible : la règle se tait.
- **Niveau** : Alerte si l'extension a des permissions sensibles, Info sinon.
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
- **Conditions** : seuls les réglages appliqués par deR4Tizer, passés de « conforme » à « non conforme », sont suivis.
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
| COR-R3 | Nouveau compte administrateur (créé il y a moins de 30 min puis ajouté aux Administrateurs) | Critique | T1136.001 |
| COR-R3b | Ajout d'un compte existant au groupe Administrateurs | Alerte | T1098 |
| COR-R4 | Journal d'événements effacé | Critique | T1070.001 |
| COR-R5 | Service installé depuis un emplacement suspect | Critique | T1543.003 |
| COR-R6 | Attaque en plusieurs étapes (3 détections d'un même programme en 10 min) | Critique | — |
| COR-R7 | Protection affaiblie (service de sécurité arrêté, politique d'audit modifiée) | Alerte | selon l'événement |
| COR-R8 | **Numéro non attribué** : aucune règle R8 dans `siem.rs` à ce jour ; le numéro reste libre, il n'est pas réutilisé pour une autre règle sans décision | — | — |
| COR-R9 | Session ouverte depuis une adresse publique (Bureau à distance : Critique ; autre : Alerte) | Critique / Alerte | T1133 |
| COR-R10 | Pilote vulnérable installé (BYOVD) | Critique | T1068 |

- **Code** : `siem.rs` (`Correlation`).
- **Télémétrie** : journaux Sécurité et Système ; audit avancé (profil de baseline « journalisation »).
- **Si elle manque** : audit désactivé ou journal illisible : la corrélation se tait. Sauf COR-R6, qui se nourrit des
  alertes du service et non de l'audit.
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
- **Tests** : existants : `lot1_alerte_critique_locale_en_echec` (INT-001), `lot5_canal_squat_pid_et_alerte_critique`
  (INT-002) ; 3a (premier démarrage en échec fermé) pour INT-001.

## EXP : modules expérimentaux (gelés)

| Id | Module | Code |
|---|---|---|
| EXP-IDS-001 | IDS (règles au format Suricata) ; l'identifiant (sid) et le fichier de la règle IDS restent dans les raisons | `ids.rs` |
| EXP-DPI-001 | DPI (SNI, JA3, HTTP, DNS) | `dpi.rs` |
| EXP-NDR-001 | NDR | `ndr.rs` |

- Gelés par `CLAUDE.md` : seule une ligne qui pose l'identifiant de règle est ajoutée à leurs alertes (PR 3.2), sans
  autre changement de logique (mainteneur, 2026-10-25).
- Un identifiant par module (PR 3.2) : chacun de ces modules produit ses alertes à un seul endroit, et la règle précise
  (sid de l'IDS, motif du DPI ou du NDR) reste dans les raisons. Un découpage plus fin attendra leur dégel.
- **Télémétrie** : capture réseau.
- **Tests** : ceux des modules, inchangés ; aucune mesure de faux positifs pendant la phase 3.
