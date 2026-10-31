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
  porte qu'une règle. Pour les lignes de commande, tous les motifs sont cherchés et nommés dans les raisons, et la
  suppression des sauvegardes (PRC-005) l'emporte sur les autres motifs (PR 3.7).

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
source : RES-004, SYS-001, VIE-003, COR-R6, INT-001, INT-002, et les constats de santé SAN-* (qui portent sur les
collectes elles-mêmes). Par défaut, les listes de domaines sont toutes à licence
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
- **Faux positifs attendus** : adresse partagée (hébergement mutualisé) ajoutée à une liste ; liste périmée. Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique, service en apprentissage) : aucun ; aucune liste de menaces n'est chargée dans la VM. La
  mesure les sous-estime : compte neuf, peu de programmes, connexions locales seulement.
- **Tests** : `res_001_positif` (adresse d'une liste synthétique trouvée, score 10, alerte même pour une connexion déjà
  ouverte au démarrage), `res_001_negatif` (adresse privée refusée au chargement de la liste ; adresse absente) ;
  décisions pures `moniteur::score_flux` et `moniteur::regle_flux` (PR 3.8). Non exercée en VM.

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
  signés. Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique, service en apprentissage) : aucun. La
  mesure les sous-estime : compte neuf, peu de programmes, connexions locales seulement.
- **Tests** : `res_002_positif` (non signé ; IP directe et port inhabituel ; non signé, téléchargé hier et balise),
  `res_002_negatif` (connexion banale ; origine Internet d'un programme signé ; navigateur sans DNS ; journal DNS non lu ;
  connexion déjà ouverte au démarrage ; connexion déjà vue ou premier passage) ; existant pour l'indice « IP directe » :
  `ip_directe_editeurs_exacts`. Décision pure `moniteur::score_flux` (PR 3.8) : les indices sont lus dans le cycle, le
  calcul est testé à part. Les indices non couverts un par un : dossier temporaire, ligne de commande suspecte,
  télémétrie (chacun ajoute son poids, comme ceux testés).

### RES-003 : première connexion à Internet d'un programme
- **Code** : `moniteur.rs` (niveau Info).
- **Justification** : donne l'historique de « qui parle à Internet » ; utile à l'enquête, pas une alarme.
- **Télémétrie** : connexions.
- **Si elle manque** : la règle se tait.
- **Niveau** : Info.
- **Faux positifs attendus** : chaque nouveau programme ou nouvelle version (attendu, par nature). Mesurés en VM
  (scénario `mesure`, 22 min, compte neuf) : 9 à 13 alertes Info, soit 24 à 35 par heure, surtout au premier usage
  (OneDrive, Edge, services de Windows).
- **Tests** : `res_003_positif`, `res_003_negatif` (apprentissage ; premier passage) ; décision pure
  `moniteur::premiere_connexion_signalee` (PR 3.8). Exercée en VM (alertes Info du scénario `mesure`).

### RES-004 : adresse publique directement sur le PC
- **Code** : `moniteur.rs` (« PC EXPOSÉ À INTERNET : adresse publique directement sur le PC »).
- **Justification** : un PC sans box ni NAT devant lui est joignable depuis Internet.
- **Conditions** : contrôle tous les 100 passages du cycle ; l'alerte part quand un réseau public apparaît sur une carte
  réseau depuis le relevé précédent : une adresse IPv4 publique, ou un préfixe /64 IPv6 global, sans tenir compte du
  nom de la carte. Les adresses IPv6 temporaires, que Windows renouvelle chaque jour dans le même préfixe, ne comptent
  pas (relecture de #87, D1 et R2-D1). Avant la
  PR 3.8, seul un **nombre** d'adresses en hausse alertait. Un PC déjà exposé au démarrage du service ne déclenche aucune
  alerte (adresses relevées au démarrage). Limite inchangée : un relevé qui échoue rend une liste vide, et les adresses
  revues au relevé suivant passent pour nouvelles.
- **Télémétrie** : adresses des cartes réseau.
- **Si elle manque** : la règle se tait.
- **Niveau** : Alerte.
- **Faux positifs attendus** : réseau d'entreprise avec adresses publiques volontaires ; IPv6 globale (selon le cas) ;
  opérateur qui change le préfixe IPv6 chaque jour : au plus une alerte par jour, cohérent avec la règle (relecture de
  #87).
  Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique, service en apprentissage) : aucun ; la VM n'a pas d'adresse publique. La
  mesure les sous-estime : compte neuf, peu de programmes, connexions locales seulement.
- **Tests** : `res_004_positif` (adresse apparue ; adresse qui en remplace une autre ; nouveau préfixe IPv6),
  `res_004_negatif` (mêmes adresses ; adresse disparue ; adresse temporaire IPv6 renouvelée dans le même préfixe ; même
  adresse sur une autre carte), sur la forme relevée « adresse (carte) », que `res_004_forme_du_releve` lie au code qui
  la produit ; décision pure `moniteur::alerte_adresses_publiques`. PR 3.8 : comparaison adresse par adresse ;
  avant, seul un nombre d'adresses en hausse alertait, et une adresse publique qui en remplaçait une autre passait
  inaperçue (faux négatif, corrigé). Non exercée en VM.

### RES-005 : paquet entrant venu d'Internet
- **Code** : `parefeu.rs` (journal du pare-feu, « PC EXPOSÉ À INTERNET : paquet entrant … »).
- **Justification** : un paquet entrant depuis une adresse publique, surtout accepté, montre un PC exposé.
- **Télémétrie** : `pfirewall.log` (journalisation des paquets du pare-feu Windows).
- **Si elle manque** : journal du pare-feu désactivé ou illisible : la règle se tait.
- **Niveau** : Critique si le paquet est accepté, Alerte s'il est bloqué. Une alerte par source, port et action en
  24 h.
- **Faux positifs attendus** : box en DMZ ou redirection de port voulue (signalé aussi par la revue UX).
- **Tests** : `res_005_positif` (paquet vers un port en écoute ; demande d'écho), `res_005_negatif` (réponse vers un port
  éphémère ; réponse UDP ; réponse d'écho), sur `parefeu::exposition_reelle` ; existants, du journal à l'alerte :
  `exposition_reelle_sans_faux_positifs`, `exposition_udp_reponse_reconnue_par_le_flux`,
  `exposition_paquet_bloque_reponse_a_un_flux`. Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique, service en apprentissage) : aucun ; la VM n'est pas exposée à Internet. La
  mesure les sous-estime : compte neuf, peu de programmes, connexions locales seulement.

### RES-006 : nouveau port ouvert en écoute sur le réseau
- **Code** : `surveillances.rs` (`ports_ouverts`).
- **Justification** : un programme qui se met à écouter sur le réseau peut être une porte dérobée.
- **Télémétrie** : table des connexions TCP (ports en écoute), signature du programme.
- **Si elle manque** : table illisible : aucun port vu ; premier relevé (`ecoutes-connues.json` absent) : apprentissage,
  aucune alerte, voulu.
- **Niveau** : Alerte si le programme n'est pas signé, Info sinon.
- **Faux positifs attendus** : logiciels qui ouvrent un port de service local (synchronisation, partage).
  Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique, service en apprentissage) : aucun. La
  mesure les sous-estime : compte neuf, peu de programmes, connexions locales seulement.
- **Tests** : `res_006_positif` (apprentissage au premier relevé ; port nouveau : Alerte si non signé, Info sinon),
  `res_006_negatif` (boucle locale ; port RPC dynamique de Windows ; port déjà connu) ; `surveillances::ports_ouverts`
  rendu testable (chemin d'un PID passé en paramètre, écriture de `ecoutes-connues.json` laissée à l'appelant, PR 3.8).

### RES-007 : connexion entrante depuis Internet
- **Code** : `surveillances.rs` (`ports_ouverts`, « CONNEXION ENTRANTE depuis Internet »).
- **Justification** : quelqu'un d'Internet est connecté à un port en écoute du PC. Distincte de RES-005 : elle vient de
  la table TCP (connexion établie), pas du journal du pare-feu.
- **Télémétrie** : table des connexions TCP, signature du programme.
- **Si elle manque** : table illisible : la règle se tait.
- **Niveau** : Critique si le programme n'est pas signé, Alerte sinon.
- **Faux positifs attendus** : serveur volontairement exposé (jeu, accès distant voulu). Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique, service en apprentissage) : aucun ; la VM n'est pas exposée à Internet. La
  mesure les sous-estime : compte neuf, peu de programmes, connexions locales seulement.
- **Tests** : `res_007_positif` (connexion établie depuis Internet sur un port en écoute : Critique si non signé, Alerte
  sinon), `res_007_negatif` (connexion entrante du réseau local ; connexion sortante) ; `surveillances::ports_ouverts`.
  Non exercée en VM.

## DNS

### DNS-001 : requête DNS vers un domaine malveillant connu
- **Code** : `moniteur.rs` (« requête DNS vers un domaine MALVEILLANT connu »).
- **Justification** : la résolution d'un domaine de commande ou de distribution de malware, même sans connexion.
- **Télémétrie** : journal DNS-Client (ou Sysmon 22), listes de domaines.
- **Si elle manque** : journal DNS coupé après le démarrage : jamais vu aujourd'hui, la règle se tait.
- **Niveau** : Critique.
- **Faux positifs attendus** : domaine retiré tardivement d'une liste ; résolution provoquée par un outil de sécurité.
  Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique, service en apprentissage) : aucun ; aucune liste de domaines n'est activée par défaut. La
  mesure les sous-estime : compte neuf, peu de programmes, connexions locales seulement.
- **Tests** : `dns_001_positif` (domaine d'une liste synthétique, sans tenir compte de la casse), `dns_001_negatif` (autre
  domaine ; sous-domaine, les listes portant des noms exacts ; nom vide) ; décision pure `moniteur::alerte_dns`
  (PR 3.8). Non exercée en VM : il faudrait une liste de domaines de test chargée par le service, que rien ne prévoit.

## PRC : processus

### PRC-001 : document bureautique qui lance un interpréteur
- **Code** : `processus.rs` (`analyser`, « macro ou exploit probable »).
- **Justification** : Word, Excel ou un lecteur PDF qui lance PowerShell, cmd, wscript… est la marque d'une macro ou
  d'un exploit.
- **Télémétrie** : création de processus (Sysmon 1 ou WMI) avec le parent.
- **Si elle manque** : flux WMI arrêté : la source reste affichée « WMI » et la règle se tait.
- **Niveau** : Critique (signal fort, jamais adouci par l'apprentissage).
- **Faux positifs attendus** : modèles d'entreprise qui lancent un script légitime. Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique : programmes lancés, fichiers écrits, connexions
  locales) : aucun, chiffre qui les sous-estime : la VM n'a pas Sysmon (lignes de commande des processus brefs perdues par WMI),
  et l'activité ne lance ni interpréteur, ni outil LOLBin, ni Office.
- **Tests** : `prc_001_positif` (Word qui lance PowerShell, avec ou sans ligne de commande, et avec un motif PowerShell en
  plus : PRC-001 l'emporte), `prc_001_negatif` (PowerShell lancé par l'Explorateur ; Word qui lance un programme qui
  n'est pas un interpréteur) ; décision pure `processus::alerte_processus`. Non exercée en VM : aucun Office dans la VM.

### PRC-002 : PowerShell obscurci ou qui télécharge du code
- **Code** : `processus.rs` (expression « PowerShell obscurci ou qui télécharge du code »).
- **Justification** : `-EncodedCommand` long, `DownloadString`, `IEX` d'une adresse : chargement de code typique.
- **Télémétrie** : ligne de commande (Sysmon 1, ou WMI tant que le processus vit).
- **Si elle manque** : processus terminé avant la lecture WMI : ligne de commande absente, la règle se tait.
- **Niveau** : Alerte.
- **Faux positifs attendus** : scripts d'administration ou d'installation encodés. Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique : programmes lancés, fichiers écrits, connexions
  locales) : aucun, chiffre qui les sous-estime : la VM n'a pas Sysmon (lignes de commande des processus brefs perdues par WMI),
  et l'activité ne lance ni interpréteur, ni outil LOLBin, ni Office.
- **Tests** : `prc_002_positif` (`-enc` d'une charge de plus de 40 caractères ; `IEX` d'un `DownloadString`),
  `prc_002_negatif` (script lancé par `-File` ; `-enc` d'un texte court). Non exercée en VM : sans Sysmon, la ligne de
  commande d'un processus bref est souvent perdue par WMI, et un motif de téléchargement ferait réagir Defender (AMSI),
  qu'on ne touche pas.

### PRC-003 : détournement d'outil Windows (LOLBin)
- **Code** : `processus.rs` (certutil, bitsadmin, mshta, regsvr32, rundll32, wmic).
- **Justification** : outils signés Microsoft utilisés pour télécharger ou exécuter du code.
- **Télémétrie** : ligne de commande.
- **Si elle manque** : comme PRC-002.
- **Niveau** : Alerte.
- **Faux positifs attendus** : `certutil -decode` dans des scripts d'administration. Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique : programmes lancés, fichiers écrits, connexions
  locales) : aucun, chiffre qui les sous-estime : la VM n'a pas Sysmon (lignes de commande des processus brefs perdues par WMI),
  et l'activité ne lance ni interpréteur, ni outil LOLBin, ni Office.
- **Tests** : `prc_003_positif` (`certutil -urlcache … http`, `mshta vbscript:`), `prc_003_negatif` (`certutil -store`,
  `rundll32 shell32.dll,Control_RunDLL`). Non exercée en VM (comme PRC-002).

### PRC-004 : navigateur lancé en débogage à distance
- **Code** : `processus.rs` (`--remote-debugging-port` ou `-pipe` sur Chrome, Edge, Brave).
- **Justification** : technique de vol de cookies qui contourne le chiffrement des navigateurs.
- **Télémétrie** : ligne de commande.
- **Si elle manque** : comme PRC-002.
- **Niveau** : Alerte.
- **Faux positifs attendus** : développeurs web, outils de test automatisé. Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique : programmes lancés, fichiers écrits, connexions
  locales) : aucun, chiffre qui les sous-estime : la VM n'a pas Sysmon (lignes de commande des processus brefs perdues par WMI),
  et l'activité ne lance ni interpréteur, ni outil LOLBin, ni Office.
- **Tests** : `prc_004_positif` (Chrome avec `--remote-debugging-port`), `prc_004_negatif` (WebView2 en débogage ;
  Chrome normal) ; existant : `debogage_a_distance_ancre_sur_l_executable`. Non exercée en VM (comme PRC-002).

### PRC-005 : suppression des sauvegardes
- **Code** : `processus.rs` (`vssadmin delete shadows`, `wbadmin delete`, `bcdedit … recoveryenabled no`,
  `wmic shadowcopy delete`).
- **Justification** : étape qui précède presque toujours le chiffrement par un rançongiciel.
- **Télémétrie** : ligne de commande.
- **Si elle manque** : comme PRC-002.
- **Niveau** : Critique (signal fort, jamais adouci), même quand la ligne contient d'autres motifs. Avant la PR 3.7,
  seul le premier motif trouvé comptait : une ligne comme `… DownloadString(…); vssadmin delete shadows` ne portait que
  PRC-002, au niveau Alerte (faux négatif, corrigé).
- **Faux positifs attendus** : nettoyage volontaire des clichés par un administrateur. Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique : programmes lancés, fichiers écrits, connexions
  locales) : aucun, chiffre qui les sous-estime : la VM n'a pas Sysmon (lignes de commande des processus brefs perdues par WMI),
  et l'activité ne lance ni interpréteur, ni outil LOLBin, ni Office.
- **Tests** : `prc_005_positif` (`vssadmin delete shadows`, `bcdedit … recoveryenabled No`, et la ligne qui télécharge du
  code puis supprime les sauvegardes : PRC-005, Critique, les deux motifs dans les raisons), `prc_005_negatif`
  (`vssadmin list shadows`, `wbadmin get versions`). Non exercée en VM : sans Sysmon, la ligne de commande d'un processus
  aussi bref est souvent perdue par WMI, le scénario serait instable.

## CHA : chaînes de processus

### CHA-001 : chaîne de processus au score cumulé
- **Code** : `chaines.rs` (au moins deux signaux et score au-dessus du seuil).
- **Justification** : plusieurs actions suspectes d'une même descendance de processus forment une attaque en étapes.
- **Télémétrie** : arbre des processus et signaux des autres règles.
- **Si elle manque** : sans processus, aucune chaîne.
- **Niveau** : Critique.
- **Faux positifs attendus** : installeurs qui enchaînent des outils signalés. Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique : programmes lancés, fichiers écrits, connexions
  locales) : aucun, chiffre qui les sous-estime : la VM n'a pas Sysmon (lignes de commande des processus brefs perdues par WMI),
  et l'activité ne lance ni interpréteur, ni outil LOLBin, ni Office.
- **Tests** : `cha_001_positif` (deux signaux dans la même descendance, score cumulé au seuil de 12 : une alerte
  Critique, pas de nouvelle alerte au même score, une autre quand le score monte), `cha_001_negatif` (un seul signal,
  même fort ; deux signaux sous le seuil ; deux signaux dans deux descendances distinctes de l'Explorateur, qui est une
  racine). Non exercée en VM (signaux des autres règles nécessaires).

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
- **Dossier des tâches, borné** : les comptes authentifiés peuvent y créer des éléments. Aucun lien n'est suivi. Bornes : 8
  niveaux, 5 000 éléments par dossier, 100 000 au total, 1 Mo par fichier, 64 Mo au total ; pour les éléments dont le propriétaire
  n'est ni SYSTEM ni Administrateurs, 64 fichiers et 8 Mo, sur un budget à part, et leurs dossiers après les autres (mesuré
  en VM : 252 fichiers, 6 de tiers pour 2 comptes ; un seul poste mesuré). Au-delà de 5 000 éléments, les fichiers du dossier ne sont plus lus,
  mais ses sous-dossiers restent parcourus, jusqu'à 2 millions d'éléments énumérés. Le relevé a 30 s pour finir. Chaque lien ou fichier
  trop gros, et chaque borne atteinte, lève une entrée « Dossier des tâches : » au niveau Alerte, jamais adoucie ni apprise, à
  chaque apparition, y compris au premier relevé. Tant que le relevé est incomplet, la collecte est « partielle » et les tâches
  connues non vues restent dans la référence. Limites : un premier relevé incomplet termine quand même l'apprentissage, sinon toute la persistance se tairait : les tâches
  qu'il n'a pas lues lèvent une fois « NOUVEAU » au relevé complet suivant ; des dossiers vides ne comptent pas dans le total
  (175 µs chacun mesurés) : environ 170 000 feraient expirer le relevé à chaque tour, par extrapolation ; dans un dossier saturé, un fichier de
  tâche classé après la borne n'est plus vu (l'alerte le dit) ; une tâche connue reste en référence, ancienne version comprise,
  tant que le relevé reste incomplet ; 64 fichiers de tiers bien classés masquent les tâches de comptes standard suivantes ; plus
  de 64 fichiers de tiers sur un poste sain, soit une vingtaine de comptes d'après la mesure, laisserait le relevé incomplet en permanence ;
  un compte standard peut lever 64 fausses tâches par relevé, et 16 anomalies, en renommant ses éléments, soit 1 000 alertes
  en 16 min environ, qui chassent les vraies ; remplacer
  un dossier par une jonction entre le contrôle et la lecture reste possible, avec pour seul effet le texte de `<Command>` d'un
  fichier lu ailleurs ; un verrou opportuniste sur son propre fichier fait perdre tout le relevé des tâches, qui reste « partiel » sans SAN-001 et
  ne repart pas tant que le verrou tient. **À corriger avant la distribution** : le calcul de signature sous le verrou du
  moniteur (S103-07, d'après le code, service non rejoué : un verrou sur un exécutable pourrait figer tout le service, SAN-001
  compris) ; le relevé bloqué (S103-06) ; la lecture par le Planificateur (énumération COM), où un fichier non enregistré ne
  serait plus une tâche (S103-02, S103-03).
- **Faux positifs mesurés** (scénario `mesure`, 22 min en VM, service en apprentissage, avant la PR 3.6) : PER-001 Info 11,
  PER-001 Alerte 5 à 6. Les alertes venaient de deux causes, corrigées à la source par la PR 3.6 :
  - tâches `\SoftLanding\…` de Windows « serveur COM non enregistré pour la machine » : leur classe COM est empaquetée
    (`Classes\PackagedCom`, écrite par le système, c'est-à-dire le service de déploiement des paquets), désormais
    résolue vers le fichier de son paquet, signé. Seulement pour un paquet de Windows (éditeur Microsoft) installé sous
    `Windows\SystemApps` ou `Program Files\WindowsApps` ; le chemin lu dans le registre ne peut pas sortir du dossier du
    paquet ; une classe surchargée dans le profil d'un utilisateur chargé (HKCU) n'est jamais résolue : la remarque
    reste, et la tâche est signalée comme avant (détournement COM possible) ;
  - `RunOnce` de OneDrive « lancé via cmd » : la commande exacte de nettoyage de son installeur n'est plus suspecte, dans
    `RunOnce` seulement ; le nom du profil n'accepte ni `%` (variable remplacée par cmd avant l'analyse de la ligne), ni
    `^ ! ( )`, ni caractère de contrôle ; toute variante reste suspecte.
  Limite : la surcharge dans le profil d'un utilisateur dont la ruche n'est pas chargée n'est pas vue.
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
- **Devenu suspect** (PR 3.6) : une entrée connue dont la commande n'a pas changé, sans remarque au relevé précédent et
  avec une remarque maintenant, lève aussi PER-002 (« DEVENU SUSPECT ») : classe COM surchargée après coup dans le profil
  d'un utilisateur, fichier remplacé par un fichier non signé ou déplacé vers un dossier suspect. Une seule alerte, si la
  remarque est encore là au relevé suivant (une minute plus tard) ; aucune pendant l'apprentissage. Un échec de
  vérification de signature n'est gardé en cache que 30 s : le relevé suivant refait la vérification au lieu de
  confirmer l'échec. Limites : une vérification impossible au moins deux relevés de suite (services de chiffrement
  lents plus d'une minute au démarrage du PC, fichier verrouillé par une mise à jour) peut lever une fausse alerte
  « NON SIGNÉ » ; aucun scénario ne redémarre la VM avec le service installé pour le mesurer. L'attente de confirmation
  ne vit qu'en mémoire : si le service s'arrête entre les deux relevés, l'entrée devenue suspecte n'est jamais signalée
  (la référence relue porte déjà la remarque).
- **Tests** : `per_002_positif` (commande changée vers un dossier suspect ; entrée COM devenue suspecte : Alerte),
  `per_002_negatif` (signataire changé seul, commande changée pendant l'apprentissage : pas d'alerte),
  `per_002_devenu_suspect_negatif` (déjà suspecte, redevenue propre, apprentissage). État : testé en labo.

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
  Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique) : aucun ; la mesure les sous-estime :
  les leurres sont posés (le contrôle du 3a exige la collecte `Leurres` « Active »), mais aucun
  programme de l'activité synthétique ne les touche.
- **Tests** : `leu_001_positif` (leurre modifié, leurre supprimé, sur de vrais fichiers : deux alertes Critique, et les
  leurres signalés ne sont plus suivis, pour ne pas alerter à chaque tour), `leu_001_negatif` (leurre lu sans être
  modifié) ; existant : `leurres_par_handle_jamais_a_travers_un_lien`. Pose des leurres exercée en VM (scénario 3b) ;
  la règle elle-même n'y est pas déclenchée.

### LEU-002 : leurre touché (audit des accès)
- **Code** : `vol_donnees.rs` (événement 4663 sur un leurre).
- **Justification** : même raison que LEU-001, au moment de l'accès ; peut suspendre le programme (réponse automatique
  au rançongiciel, niveau 3).
- **Télémétrie** : journal Sécurité 4663 et audit (SACL) posé sur les leurres.
- **Si elle manque** : audit des objets désactivé : la règle se tait.
- **Niveau** : Critique ; Info si le programme est un logiciel connu et signé (sauvegarde, synchronisation, antivirus),
  qui n'est pas suspendu.
- **Faux positifs attendus** : logiciel de sauvegarde ou d'indexation non encore reconnu.
  Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique) : aucun ; la mesure les sous-estime :
  aucun programme de l'activité ne touche un leurre.
- **Tests** : `leu_002_positif` (événement 4663 sur un leurre, nom sans tenir compte de la casse : Critique, suspension
  annoncée seulement si elle a eu lieu), `leu_002_negatif` (autre fichier ; logiciel connu : Info, non suspendu) ;
  décisions pures `hygiene::pid_touchant_leurre_parmi` et `vol_donnees::alerte_leurre_touche` (PR 3.9 : noms des
  leurres passés en paramètre, sans lire ni créer le fichier des noms) ; existant : `b1_leurre_touche_par_rundll32_suspendu`
  (décision de suspension). Non exercée en VM.

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
  Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique) : aucun ; la mesure les sous-estime :
  aucun navigateur ni portefeuille n'est installé ou ouvert pendant la mesure.
- **Tests** : `vol_001_positif` (lecture d'une base de mots de passe de Chrome par un programme d'un dossier temporaire :
  Critique ; d'ailleurs : Alerte ; par un « chrome.exe » non signé par Google : alerte), `vol_001_negatif` (fichier hors
  des dossiers surveillés ; dossier parcouru sans lecture ; notre propre service ; une alerte par programme et par cible
  en 24 h, `vol_donnees::premiere_en_24h`, PR 3.9) ; décision `vol_donnees::analyser` sur des événements 4663
  synthétiques. Non exercée en VM.

## SYS : fichier hosts et pare-feu

### SYS-001 : fichier hosts modifié par un autre programme
- **Code** : `moniteur.rs` (empreinte du fichier hosts).
- **Justification** : redirection de domaines vers un serveur de l'attaquant, ou blocage des mises à jour de sécurité.
- **Télémétrie** : empreinte du fichier hosts.
- **Si elle manque** : fichier illisible : l'empreinte vaut « » (`empreinte_hosts`). Depuis la PR 3.10, ce relevé ne
  déclenche rien et l'empreinte connue est gardée : un changement fait pendant la panne est signalé dès que le fichier
  redevient lisible. Avant, l'alerte partait **à tort** à la panne, puis repartait au retour du fichier.
- **Limites** (audit de #90) :
  - un fichier gardé illisible en permanence (un compte standard peut l'ouvrir sans partage) rend la règle muette, sans
    aucun signal dans `etat.json` ni dans le journal (S90-01). Aucune modification n'est possible pendant ce verrou, et
    une modification faite après sa levée est signalée ;
  - une référence vide (fichier illisible au démarrage du service, ou relecture ratée juste après une écriture du
    service) fait adopter le premier relevé lisible sans alerte (S90-02) ;
  - la référence n'est pas conservée d'un démarrage à l'autre : une modification faite service arrêté n'est jamais
    signalée (S90-03, antérieure à la PR 3.10).
  Ces trois limites demandent les droits d'administrateur pour modifier le fichier, qui suffisent déjà à le modifier
  avant le démarrage du service. Correction prévue : empreinte conservée dans le dossier de données, calculée sur le
  contenu écrit par le service, et panne durable notée.
- **Niveau** : Alerte.
- **Faux positifs attendus** : logiciels de blocage de publicités, outils de développement. Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique) : aucun.
- **Tests** : `sys_001_positif` (empreinte changée ; changement fait pendant une panne de lecture, signalé au retour),
  `sys_001_negatif` (même empreinte ; fichier illisible) ; décision pure `moniteur::alerte_hosts` (PR 3.10). Non
  exercée en VM (le scénario n'écrit pas dans le fichier hosts).

### SYS-002 : règle de pare-feu ajoutée ou modifiée
- **Code** : `parefeu.rs` (suivi des modifications du pare-feu).
- **Justification** : ouvrir un port entrant est un moyen classique de garder un accès au poste.
- **Variantes** : auteur non signé : Critique ; port entrant ouvert en ligne de commande : Alerte ; autorisation
  entrante par un auteur introuvable : Alerte ; par un programme tiers signé ou un installeur de mise à jour : Info.
- **Télémétrie** : journal du pare-feu (Windows Firewall With Advanced Security), signature de l'auteur.
- **Si elle manque** : le résultat de l'abonnement est ignoré aujourd'hui (silence).
- **Faux positifs attendus** : installeurs de logiciels qui ouvrent leurs ports. Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique) : aucun.
- **Tests** : `sys_002_positif` (port entrant ouvert par netsh : Alerte ; règle modifiée par un programme non signé :
  Critique), `sys_002_negatif` (nos propres règles ; règle sortante changée par Windows ; événement sans rapport), sur
  `parefeu::traduire` avec des événements synthétiques.

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
- **Faux positifs attendus** : réinitialisation volontaire du pare-feu par un administrateur. Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique) : une alerte Info par passage, le rechargement des règles par la stratégie de groupe au démarrage de la VM (attendu, Info).
- **Tests** : `sys_003_positif` (toutes supprimées par un autre programme : Critique), `sys_003_negatif` (svchost de
  Windows : Info ; un « svchost.exe » hors de Windows reste Critique), sur `parefeu::traduire`. La vérification du
  retour des règles, une minute après, n'est pas testée (appel Windows).

## PIL : pilotes

### PIL-001 : pilote vulnérable connu présent
- **Code** : `hygiene.rs` (liste LOLDrivers, une fois par jour).
- **Justification** : un pilote signé mais vulnérable permet de désactiver les protections (BYOVD).
- **Télémétrie** : liste LOLDrivers chargée, pilotes du disque.
- **Si elle manque** : liste vide ou illisible : aucune alerte (silence), comme s'il n'y avait aucun pilote vulnérable.
- **Niveau** : Critique.
- **Faux positifs attendus** : ancien pilote de matériel encore présent mais inutilisé. Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique) : aucun ; la liste LOLDrivers est vide dans la VM (PIL-001 sans collecte, contrôle du 3a).
- **Tests** : `pil_001_positif` (pilote .sys dont l'empreinte est dans la liste : Critique, une seule fois),
  `pil_001_negatif` (pilote sain ; même contenu sous un autre type de fichier ; pilote absent), sur de vrais fichiers
  temporaires ; décision `hygiene::pilotes_vulnerables` (PR 3.10). Existant : `chemins_des_pilotes`.

## EXT : extensions de navigateur

### EXT-001 : nouvelle extension de navigateur
- **Code** : `hygiene.rs` (`verifier_extensions`, toutes les 10 min, sauf au premier relevé).
- **Justification** : une extension malveillante lit tout ce que l'utilisateur fait dans le navigateur.
- **Télémétrie** : profils des navigateurs.
- **Si elle manque** : profil illisible : la règle se tait.
- **Niveau** : Alerte si l'extension a des permissions sensibles, Info sinon.
- **Faux positifs attendus** : chaque extension installée volontairement. Faux positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique) : aucun ; aucun navigateur n'installe d'extension pendant la mesure.
- **Tests** : `ext_001_positif` (apprentissage au premier relevé ; puis nouvelle extension : Alerte si ses permissions
  sont sensibles, sinon Info ; date de première vue notée), `ext_001_negatif` (extension déjà connue, date reprise ; même
  identifiant dans un autre navigateur : nouvelle) ; décision pure `hygiene::nouvelles_extensions` (PR 3.10, sans
  fichier de données).

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
- **Faux positifs attendus** : VIE-001 à la visioconférence ; VIE-002 pour un support informatique légitime. Faux
  positifs mesurés en VM (scénario `mesure`, 22 min d'activité synthétique) : aucun ; la mesure les sous-estime, car
  l'activité n'utilise ni caméra ni micro et ne lance aucun outil de prise en main à distance.
- **Tests** (PR 3.12), sans registre ni fichier de données :
  - `vie_001_positif` (apprentissage au premier relevé, puis un nouveau programme qui utilise la caméra : Alerte),
    `vie_001_negatif` (programme connu ; usage terminé ; usage déjà en cours au relevé précédent), sur
    `surveillances::premiers_usages` ;
  - `vie_002_positif` (outil lancé, nom sans tenir compte de la casse ; relancé après sa fin : nouvelle alerte),
    `vie_002_negatif` (programme ordinaire ; outil toujours en cours, une seule alerte), sur
    `surveillances::outils_distants`, avec le chemin d'un PID passé en paramètre ;
  - `vie_003_positif`, `vie_003_negatif` (premier relevé, toujours activé, désactivé), sur
    `surveillances::alerte_bureau_a_distance`.
  Non exercées en VM ; le relevé du magasin des consentements et du registre n'est pas testé.

## BAS : baseline

### BAS-001 : réglage de sécurité de la baseline défait
- **Code** : `baseline.rs` (`derives`, toutes les 10 min).
- **Justification** : un réglage de durcissement qui revient en arrière (par un malware, une mise à jour ou une
  personne) rouvre une faiblesse.
- **Conditions** : seuls les réglages appliqués par deR4Tizer, passés de « conforme » à « non conforme », sont suivis.
- **Télémétrie** : évaluation de la baseline.
- **Si elle manque** : évaluation impossible : aucune dérive calculée.
- **Niveau** : Alerte.
- **Faux positifs attendus** : stratégie de groupe ou administrateur qui change le réglage volontairement. Faux
  positifs mesurés en VM (scénario `mesure`, 22 min) : aucun ; aucun réglage n'est changé pendant la mesure.
- **Tests** : `bas_001_positif` (règle appliquée par deR4Tizer, conforme puis non conforme : Alerte, valeurs attendue
  et actuelle dans les raisons), `bas_001_negatif` (règle non appliquée par deR4Tizer ; déjà non conforme ; état
  inconnu ; règle nouvelle), sur `baseline::derives`. Non exercée en VM.

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
- **Tests** : `cor_r1_positif` à `cor_r9_negatif` (PR 3.11), sur `siem::Correlation::analyser` avec des événements
  synthétiques déjà traduits :
  - COR-R1 : cinq échecs de la même source ; pas quatre, ni cinq répartis sur deux sources ;
  - COR-R2 : session ouverte après cinq échecs de la même source ; pas après quatre, ni d'une autre source ;
  - COR-R3 et COR-R3b : compte créé puis ajouté, compte existant ajouté, une fois par heure ;
  - COR-R4 : effacement d'un journal, une fois par heure ;
  - COR-R5 : service depuis un dossier temporaire, `ProgramData` ou PowerShell ; pas depuis Program Files ni Windows ;
  - COR-R6 : trois détections différentes d'un même programme, sans tenir compte de la casse ; pas deux, ni trois
    programmes, ni des alertes Info ;
  - COR-R7 : service de sécurité arrêté, politique d'audit modifiée ; pas un changement d'état Info ;
  - COR-R9 : Bureau à distance depuis une adresse publique (Critique), autre session (Alerte) ; pas depuis le réseau
    local.
  Les fenêtres de temps (5 min, 30 min, 10 min, une heure) ne sont pas exercées : le moteur lit l'horloge lui-même.
  COR-R10 n'est pas testée : sa vérification télécharge la liste LOLDrivers. Aucune n'est exercée en VM. Faux positifs
  mesurés en VM (scénario `mesure`, 22 min d'activité synthétique) : aucun incident ; la mesure les sous-estime, car
  l'activité n'ouvre aucune session, n'installe aucun service et ne change aucun compte.

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

## SAN : santé de deR4Tizer (phase 4)

| Id | Constat | Code | Niveau |
|---|---|---|---|
| SAN-001 | Collecte critique indisponible (ou jamais lue) depuis plus de 30 min ; collectes critiques (D4-5) : `JournalDefender`, `EtatDefender`, `JournalSecurite`, `Connexions`, `Processus`, `ListesMenaces`, `Persistance` | `sante.rs` | Alerte |
| SAN-002 | Collecte rétablie après un constat SAN-001 ou SAN-003 (« rétablie après N min ») | `sante.rs` | Info |
| SAN-003 | Defender aveugle : journal **et** état illisibles depuis plus de 30 min (remplace SAN-001 pour ces deux collectes) | `sante.rs` | Critique |
| SAN-004 | Remontée des alertes configurée et en échec depuis plus d'une heure : constat **local** (jamais remonté, on ne peut pas) | `sante.rs`, `notifications.rs` | Alerte |
| SAN-010 | Interface absente d'une session active plus de 15 min (après un délai de grâce de 5 min à l'ouverture de la session ou au démarrage du service), malgré la tâche de relance | `sante.rs`, `natif.rs` | Critique (décision du mainteneur, 2026-10-31 : sans interface, un constat local n'est vu par personne) |
| SAN-011 | Interface arrêtée à répétition : 3 disparitions en une heure dans une même session | `sante.rs`, `natif.rs` | Alerte |
| SAN-012 | Alertes non suivies faute de place : plus de 500 incidents non clos (l'alerte reste dans `alertes.json`) | `sante.rs` | Critique |

- **Justification** : une collecte coupée fait taire les règles qui en dépendent ; sans constat, ce silence ressemble à
  un poste calme. Couper la vue sur Defender est ce qu'un attaquant gagne le plus à faire (SAN-003).
- **Télémétrie** : l'état publié des collectes (`collectes::instantane`, PR 3.3) ; le compteur des alertes non suivies
  du moniteur (SAN-012). Fil « sante », toutes les 30 s, hors du verrou du moniteur.
- **Bornes** : un constat par collecte (SAN-001), ou par règle (SAN-003, SAN-012), et par 24 h au plus **pour une même
  panne** : rétablie, la collecte peut de nouveau être signalée (audit de #98, S98-01). `Inconnue`
  compte comme indisponible (échec fermé) ; une collecte relue moins souvent que toutes les 15 min (listes de menaces :
  toutes les heures) ne compte que l'indisponibilité notée par sa source, pas son seul silence, qu'elle rattrape après
  une veille (relecture de #98, D1) ; `Desactivee` (Sysmon absent, mode console) ne lève jamais rien. Jamais
  adoucis par l'apprentissage (`apprentissage::signal_fort`). Décision en mémoire : après un redémarrage, une panne
  déjà signalée peut l'être une fois de plus.
- **Historique** : chaque changement d'état d'une collecte est écrit dans le SIEM (`Source` « sante », `Type`
  « collecte »), au changement seulement ; le passage d'« Inconnue » à « Active » du démarrage est tu ; plus de 6
  changements dans l'heure : collecte « instable », une ligne par heure au plus. La chronologie d'un incident les
  reprend (PR 4.3).
- **Faux positifs attendus** : redémarrage de Defender pendant une mise à jour de sa plateforme ; journal Sécurité plein
  (à mesurer en VM) ; listes de menaces jamais téléchargées (poste sans Internet). Écarté : la veille d'un portable
  (silence des listes de menaces jusqu'à leur prochain tour, test `sante_veille_silence_des_listes_sans_constat`).
- **Limite** : une collecte coupée à répétition, moins de 30 min chaque fois, ne lève jamais SAN-001 (l'historique la dit
  « instable » au-delà de 6 changements dans l'heure) ; un constat « instable » pour les collectes critiques est à
  reprendre plus tard.
- **Tests** : `sante_collecte_muette_30_min`, `sante_collecte_revenue_avant_30_min`, `sante_collecte_retablie`,
  `sante_desactivee_sans_alerte`, `sante_inconnue_compte_indisponible`, `sante_defender_aveugle_critique`,
  `sante_defender_un_seul_collecteur`, `sante_rappel_apres_24_h`, `sante_historique_au_changement_et_instable`,
  `sante_veille_silence_des_listes_sans_constat`, `sante_rappel_remis_a_zero_au_retablissement`,
  `incidents_plafond_non_clos`, `sante_jamais_adoucie_par_l_apprentissage` ; 3a (événement « sante » à l'arrêt d'une
  collecte).
- **SAN-004** (PR 4.4b) : une panne de remontée commence au premier lot non remis (aucun canal tenté n'a réussi) et
  finit au premier lot remis ; un constat par panne et par 24 h au plus ; remontée non configurée : rien. Tests :
  `sante_remontee_echec_1h`, `sante_remontee_non_configuree`.
- **SAN-010 et SAN-011** (PR 4.5a) : collecte `Sessions` (fil « sante », toutes les 30 s) ; sessions `WTSActive` avec un
  jeton d'utilisateur ; interface reconnue par son chemin complet **égal** au chemin installé (`deR4Tizer.exe` à côté
  du service) : une copie posée ailleurs ne compte pas. Installation avec `LANCEMENT_SESSION=0` (pas de valeur Run) : aucune session attendue, aucun constat. Énumération impossible : collecte indisponible, jamais
  « interface présente », et SAN-010/011 sans collecte. Un constat par session, par épisode (SAN-010 : remis à zéro au
  retour de l'interface, 3 constats au plus par session et par 24 h, le dernier constat le disant, puis une ligne dans le SIEM ; le plafond est en mémoire : il repart de zéro au redémarrage du service et à la fermeture de la session) et par 24 h au plus ; chaque disparition et chaque retour sont écrits dans le SIEM (`Type`
  « interface »). Le service ne relance rien : une tâche planifiée posée par le MSI le fait sous l'identité de l'utilisateur (PR 4.5b), toutes les 5 min, et SAN-010 signale l'absence au-delà. Il ne distingue pas un
  « Quitter » volontaire d'un arrêt forcé. Limite : une interface au bon chemin mais suspendue compte comme présente ; un programme sous le compte de l'utilisateur peut donc couper les notifications locales sans SAN-010 (audit de #100, S100-01) ; la surveillance et la remontée continuent ; il faudrait un signe de vie de l'interface pour aller plus loin. Autres faux positifs attendus : tâche de relance retirée ou interdite (poste géré) ; compte non autorisé à lire les données, qui
  ferme l'interface ; session Bureau à distance sans bureau. Tests : `sante_interface_absente_15_min`,
  `sante_grace_ouverture_session`, `sante_interface_trois_disparitions`, `sante_interface_deux_disparitions`,
  `sante_interface_retour_et_session_fermee`.

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
