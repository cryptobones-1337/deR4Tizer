# Matrice des capacités de deR4Tizer

État au 2026-10-24, branche `main` (commit `c60d9b3`, version 4.3), après la fusion des PR #10, #12 à #27 et #31 à
#35 ; les PR fusionnées ensuite sont décrites dans les lignes concernées. Aucune affirmation ici n'est plus forte
que la preuve citée. Une PR encore ouverte est signalée comme telle : tant qu'elle n'est pas fusionnée, `main` ne
contient pas son contenu.

## États

| État | Sens |
|---|---|
| prévu | Rien dans le code. |
| implémenté non vérifié | Le code existe ; aucun test automatisé n'en vérifie le comportement. |
| testé en labo | Fonctions pures ou parseurs vérifiés par `cargo test --release` (décisions, formats, mini-fuzz) ; le comportement sur un Windows réel n'est pas prouvé. |
| validé sur Windows | Scénarios réussis avec le service réel, installé par le MSI, sur un runner Windows jetable de la CI (jobs `integration-*`, tableaux cités). |
| réussi en Windows Sandbox | Mêmes scénarios, réussis dans une Windows Sandbox jetable (`tests/bac-a-sable`), pendant la désactivation de GitHub Actions. Signal, pas preuve : ni poste réel, ni Defender actif ; jamais « validé sur Windows (VM) ». |
| prêt pour la production | Aucune capacité aujourd'hui : binaires non signés, scénario Defender (lot 3d) non exécuté, aucun audit. |

L'IDS, le DPI et le NDR sont **expérimentaux**, quel que soit l'état de leurs tests.

## Preuves de CI citées

- **3a** (`integration-installation`, `tests/integration/installation.ps1`) : run 39822711631 (PR #9, `3194bb6`), 42 scénarios, 0 échoué, 0 non exécuté.
- **3b** (`integration-quarantaine`, `tests/integration/quarantaine.ps1`) : même run, 21 scénarios, 0 échoué, 1 non exécuté (refus par `creer_sans_lien` : course non reproductible).
- **3c** (`integration-maj`) : jamais exécuté en CI (GitHub Actions désactivé sur le dépôt depuis le 2026-10-22).
- Windows Sandbox, arbre `370e4d27`, celui de `main` après la fusion des PR #10 à #27 (l'historique a été réécrit le 2026-10-24 pour en retirer des données personnelles : l'arbre testé `370e4d27`
est identique, aux adresses IP des données de test près, à celui de `main` `7ff8309` ; anciens identifiants de
commit cités pour mémoire) : 3a 41 réussis,
  0 échoué, 2 non exécutés ; 3b 23 réussis, 0 échoué, 3 non exécutés ; 3c 19 réussis, 0 échoué, 1 non exécuté.
  Tableaux complets en commentaire des PR #10 à #27 ; raisons des non exécutés dans `docs/testing/baseline.md`.
- Windows Sandbox, arbre `4bdcc38dd6e99aa52376d1d44b78ebad7c61db15`, celui de `main` `c60d9b3` (fusion des PR #34, #31,
  #32, #33, #35) : 3a 41 réussis, 0 échoué, 2 non exécutés ; 3b 24, 0, 3 ; 3c 19, 0, 1. Tableaux en commentaire de ces PR.
- Tests unitaires : `cargo test --release` (chaîne MSVC) sur ce même arbre, 80 réussis (voir `docs/testing/baseline.md`).

## Matrice

| Capacité | État | Sources | Prérequis Windows | Tests existants | Limites |
|---|---|---|---|---|---|
| Installation, désinstallation (avec et sans `GARDER_DONNEES=1`), mise à niveau par MSI | validé sur Windows | `installeur/deR4Tizer.wxs`, `construire-msi.ps1` | Windows 10 ou plus récent, 64 bits ; administrateur ; aucun runtime Visual C++ (CRT liée statiquement, PR #23) | 3a | Le MSI accepte une version plus ancienne (`AllowDowngrades`, nécessaire au retour arrière) : le refus d'une version plus ancienne est assuré par le service, sur la version lue dans le paquet signé, et un administrateur peut toujours installer une version plus ancienne à la main. Binaires non signés. |
| Service SYSTEM, démarrage automatique, redémarrage sur échec | validé sur Windows | `main.rs` | — | 3a | Un attaquant administrateur peut arrêter le service. |
| Canal de commandes (tube nommé) | validé sur Windows (refus du compte standard) ; testé en labo (PID du serveur) | `canal.rs`, `maj.rs` (`ps_canal`) | — | 3a (essais du compte standard : `UnauthorizedAccessException` exigée) ; `serveur_tube`, `lot2_canal_code_de_production_sur_un_vrai_tube` | Lecture d'une commande bornée dans le temps et alerte critique si le tube est déjà pris au démarrage (PR #15) : testées en labo (`lot5_canal_*`), pas sur Windows. |
| Protection du dossier de données (propriétaire, droits, échec fermé, dossier précréé, fichiers piégés) | validé sur Windows | `protection.rs`, `commun.rs`, `natif.rs` | NTFS | 3a ; `securite`, `m1_proprietaire_du_dossier_de_donnees`, `lot1_*`, `lot1ter_reinitialisation_*`, `lot1ter_garder_tel_quel_*` | Lecture accordée à un compte **standard** connecté à la console : non testée (la session du runner est celle d'un administrateur ; VM nécessaire). En échec de la protection, l'alerte critique reste locale (les secrets de remontée sont ignorés) : le prestataire n'est pas prévenu. Les éléments mis de côté dans `ecartes` gardent leur propriétaire d'origine et restent modifiables par leur auteur (jamais lus). |
| Quarantaine et restauration (copie encodée, reprise au démarrage, repli dans le dossier du service, jonctions) | validé sur Windows | `reponse.rs`, `natif.rs` | — | 3b ; `lot1bis_*`, `lot1ter_*` | Restauration avec la session d'un utilisateur **standard** : non testée (VM). Refus par `creer_sans_lien` (jonction posée entre le contrôle du propriétaire et la création) : non couvert de façon reproductible. Jonction « pendant » une quarantaine : testée sous sa forme déterministe seulement. |
| Mise à jour automatique (manifeste, paquet MSI signé, clé épinglée, retour arrière) | testé en labo ; réussi en Windows Sandbox (3c, PKI de test) ; jamais exécuté en CI | `maj.rs`, `natif.rs`, `.github/workflows/publication.yml` | `curl.exe` de Windows (Schannel), Windows Installer | `lot2_*`, `n2_mise_a_jour_cle_epinglee`, `script_installation_lance_s_execute` | **Inopérante dans les versions publiées 4.2 et 4.3** : le script d'installation, lancé détaché (`DETACHED_PROCESS`), ne s'exécutait jamais (Windows PowerShell 5.1 sans console sort sans rien exécuter) ; corrigée par la PR #26, fusionnée, **non encore publiée**. Une version installée se met à jour à la main. Aucune version signée n'est publiée : en pratique, aucune mise à jour automatique n'est possible aujourd'hui. Certificat dont la liste de révocation ne répond pas : refusé (PR #12) ; prouvé par le 3c en Windows Sandbox avec un certificat d'une autorité intermédiaire sans CRL. Dossier de travail à SYSTEM, propriétaire compris, vérifié avant l'installation (PR #24). Installation automatique désactivée par défaut ; sans clé épinglée dans le binaire, une version est seulement signalée. Service muet après l'installation : couvert seulement par le mode simulation de `script_installation`. |
| Tuer, suspendre, reprendre un processus ; isoler un programme du réseau ; mode panique | implémenté non vérifié (mode panique : plages testées en labo) | `reponse.rs`, `blocage.rs` | Pare-feu Windows | `plages_du_mode_panique`, `reseaux_reserves` | Mode panique : les serveurs DNS et de notification restent joignables pour tous les programmes. |
| Blocages (fichier hosts, pare-feu) et blocage automatique par les listes de menaces | testé en labo (levée des blocages) | `blocage.rs`, `moniteur.rs`, `menaces.rs` | Pare-feu Windows | `blocages_leves_a_expiration_ou_hors_liste` | Le blocage automatique (activé par défaut) porte sur les listes de confiance « haute » : par défaut Spamhaus DROP et Feodo Tracker ; avec le réglage « listes restreintes », aussi FireHOL niveau 1 et ThreatView Cobalt Strike, au-delà de la politique de réponse (`docs/reponse/politique.md`). |
| Listes de menaces (téléchargement toutes les 12 h, chargement compact) | implémenté non vérifié | `menaces.rs` | Accès à Internet | `reseaux_reserves` (réseaux réservés seulement) | Licences de plusieurs listes « à vérifier » (désactivées par défaut). Une liste corrompue peut bloquer des adresses légitimes (voir `docs/security/threat-model.md`). |
| Surveillance des connexions, score de suspicion, balises, première connexion | implémenté non vérifié (critère « IP directe » testé en labo) | `moniteur.rs`, `natif.rs` | — | `ip_directe_editeurs_exacts` | — |
| Chaînes de processus et score cumulé | implémenté non vérifié | `chaines.rs` | — | — | — |
| Origine des processus et règles inspirées de Sigma | implémenté non vérifié (débogage à distance testé en labo) | `processus.rs` | Sysmon facultatif (sinon WMI) | `debogage_a_distance_ancre_sur_l_executable` | Sans Sysmon, couverture réduite. |
| Persistance (clés Run, services, tâches, WMI, Démarrage) | implémenté non vérifié (cible des tâches COM testée en labo) | `persistance.rs` | — | `tache_com_cible_le_serveur_du_clsid` | Tâche à gestionnaire COM : la cible est le serveur du CLSID enregistré pour la machine (InprocServer32, sinon LocalServer32), dont la signature est vérifiée ; avant ce correctif, la cible était le dossier `System32\COM` et ces tâches de Windows sortaient « NON SIGNÉ ». CLSID non enregistré pour la machine : signataire « ? », sans remarque. Les CLSID enregistrés dans le profil d'un utilisateur (HKCU, détournement COM) ne sont pas lus. |
| Leurres anti-rançongiciel et suspension automatique | testé en labo (décision) | `hygiene.rs`, `vol_donnees.rs` | Audit du système de fichiers (4663) | `b1_leurre_touche_par_rundll32_suspendu`, `b2_noms_des_leurres_dans_le_dossier_des_secrets` ; 3b (jonction vers un canari) | Création, suppression et nettoyage par handle sans suivre de lien, sous l'identité du propriétaire du profil (PR #20). Audit d'écriture des leurres posé par `SetKernelObjectSecurity`, comme l'audit des données sensibles (PR #28) ; avant la #28, l'écriture de la SACL par `SetSecurityInfo` était refusée et aucun leurre n'était audité. Leurre déjà présent dans un profil sans session, audité après redémarrage : réussi en Windows Sandbox (3b). Création des leurres dans un profil qui a une session : non validée (VM). |
| Pilotes vulnérables (LOLDrivers) | testé en labo (chemins) | `hygiene.rs` | — | `chemins_des_pilotes` | `loldrivers.json` lu avec le contrôle du propriétaire (PR #16), testé en labo. |
| Extensions de navigateur | implémenté non vérifié | `hygiene.rs` | — | — | — |
| Vol de données (audit des fichiers des navigateurs et applications) | testé en labo (décision) | `vol_donnees.rs` | Audit « Système de fichiers » (profil de baseline « journalisation ») | `alerte`, `editeurs_compares_exactement`, `audit_donnees_sacl_completee` ; 3b | Audit posé par handle, sans suivre de lien, SACL complétée et non remplacée (PR #25) ; réussi en Windows Sandbox (3b : jonction vers un canari, règle d'audit tierce gardée, étiquette d'intégrité Low gardée). Au-delà de 20 000 éléments par dossier, l'audit n'est posé que sur une partie des fichiers déjà présents (signalé dans le journal du service). Ne voit pas l'injection de code dans le navigateur. Poste géré sans audit des fichiers : non surveillé (signalé). |
| Vie privée et accès à distance (caméra, micro, prise en main, ports ouverts) | implémenté non vérifié | `surveillances.rs` | — | — | — |
| Pare-feu : changements de règles, exposition à Internet | implémenté non vérifié (décision d'exposition testée en labo) | `parefeu.rs` | Journal du pare-feu, `pfirewall.log` | `exposition_reelle_sans_faux_positifs`, `exposition_udp_reponse_reconnue_par_le_flux`, `exposition_paquet_bloque_reponse_a_un_flux` | Faux positifs corrigés (PR #22) : lignes de la socket de capture du service, réponses TCP vers un port sans écoute, réponses UDP reconnues par l'état du flux (cas NTP), y compris quand le pare-feu les bloque après la perte de l'état du flux (PR #37 : flux appris d'un envoi du poste ou d'une réponse acceptée vers un port dynamique, jamais d'une ligne de la socket de capture du service). TCP non traité de cette façon. Les alertes enregistrées par une version antérieure restent dans l'historique (aucune commande pour l'effacer). |
| Redirections UPnP de la box | testé en labo (parseur) | `upnp.rs` | — | `n1_upnp_sans_panique_sur_utf8_coupe` | — |
| Surveillance de Microsoft Defender | implémenté non vérifié | `defender.rs` | Microsoft Defender | — | Exécution avec Defender actif non vérifiée (lot 3d, non exécuté). Au démarrage du PC, tant que Defender répond « Not running », l'état est relu toutes les 30 s pendant 10 minutes au plus avant d'être publié : une désactivation réelle dès le démarrage n'est signalée qu'au bout de ces 10 minutes. |
| Baseline de sécurité par la GPO locale | testé en labo (partiel) | `baseline.rs`, `gpo.rs` | Poste non géré (sur un poste géré : lecture seule) | `baseline_reglage_asr_partage_conserve` | — |
| Mini-SIEM (événements, recherche, corrélation, incidents) | implémenté non vérifié | `siem.rs`, `evenements.rs` | Journaux de Windows | — | Fichiers lus avec le contrôle du propriétaire (PR #16), testé en labo. |
| Analyse du trafic, pays (GeoIP) | implémenté non vérifié (décodage testé en labo) | `trafic.rs`, `geoip.rs`, `capture.rs` | Règle de pare-feu « deR4Tizer capture » | `paquet_udp`, `decoder_paquet_udp`, `decoder_sans_panique` | IPv4 seulement ; sur un réseau commuté, seul le trafic du poste est vu ; pays du titulaire du bloc. |
| NDR local (ARP, DHCP, LLMNR/NBNS/mDNS) | expérimental ; implémenté non vérifié | `ndr.rs` | — | — | — |
| DPI (SNI, JA3, HTTP, DNS) | expérimental ; testé en labo (parseurs, mini-fuzz) | `dpi.rs` | — | `client_hello*`, `question_dns`, `noms_dns` | Empreintes JA3 lues avec le contrôle du propriétaire (PR #16), testé en labo. |
| IDS / IPS (règles au format Suricata) | expérimental ; testé en labo (règles, mini-fuzz) | `ids.rs` | — | `regles_*`, `regle_contenu_hexa_et_correspondance` | IPS désactivé par défaut. Options `pcre`, `byte_test` et quelques autres ignorées. Règle intégrée 9000011 (Shellshock) resserrée hors phase 3, comme correction de bruit (faux positif CRITIQUE sur un téléchargement chiffré) : requêtes vers les ports HTTP en clair du poste (80, 8000, 8008, 8080, 8888), motif de l'attaque ; compromis accepté : une tentative vers un autre port HTTP en clair, ou dont le corps de fonction dépasse 10 octets, n'est plus détectée ; à revoir en phase 3 avec les autres règles. Règles `regles\` lues avec le contrôle du propriétaire ; en échec de la protection, blocage par l'IPS et blocage automatique refusés (PR #16), testé en labo. |
| Remontée des alertes (ntfy, Teams, SMTP) | testé en labo (regroupement, plafond, critiques jamais retenues) | `notifications.rs` | `curl.exe` de Windows | `notifications_critiques_jamais_retenues`, `regroupement_second_niveau`, `b3_vraie_alerte_visible_parmi_300_usurpations`, `horodatage_et_base64` | Secrets ignorés en échec de la protection du dossier. |
| Export syslog (RFC 5424, JSON ou CEF) | implémenté non vérifié (horodatage testé en labo) | `export.rs` | — | `horodatage_et_base64` | **En clair** (UDP ou TCP, sans TLS) : à réserver à un réseau local de confiance. |
| API HTTP d'export (lecture seule, jeton) | testé en labo (adresses autorisées) ; écoute validée sur Windows (port témoin de 3a) | `api.rs` | — | `api_adresses_autorisees` ; 3a | Jeton en échec fermé si `BCryptGenRandom` échoue, jeton existant validé (64 caractères hexadécimaux, pas tous nuls), `/api/v1/sante` sans nom de machine (PR #14) : testés en labo, pas sur Windows. |
| Apprentissage et exceptions | testé en labo | `apprentissage.rs` | — | `n3_apprentissage_par_chemin_editeur_et_destination` | — (cache de l'éditeur indexé par chemin et date de modification depuis la 4.2) |
| Techniques MITRE ATT&CK et conseils | implémenté non vérifié | `mitre.rs` | — | — | — |
| Interface (C#, français et anglais) | implémenté non vérifié (compilée par la CI) | `src/*.cs` | .NET Framework 4.8 | Compilation dans le job `windows` | Rendu à 125 % et 150 % non vérifié sur un écran réel. |
| Signature des binaires et du MSI | prévu | `.github/workflows/publication.yml` | Certificat de signature de code | — | Binaires non signés. SignPath Foundation non utilisable en l'état pour les mises à jour (certificat à son nom, peut-être commun à plusieurs projets) : seconde signature propre au projet ou nom de produit exigé, à décider ; Azure Trusted Signing (clé qui changerait souvent) à vérifier. Voir `docs/security/threat-model.md`. |
| Exécution avec Microsoft Defender actif (lot 3d) | prévu | — | VM ou runner auto-hébergé | — | Non exécuté : dernier verrou avant toute distribution. |

## Scénarios non exécutés (à faire sur une VM)

- Pose des leurres dans le profil d'une session ouverte (3b).
- Restauration avec la session d'un utilisateur standard (3b).
- Lecture des données par un compte standard connecté à la console (3a).
- Refus par `creer_sans_lien` d'une jonction posée entre le contrôle et la création (course).
- Service muet après une mise à jour (3c : simulation seulement).
- Exécution complète avec Microsoft Defender actif (3d).

## Limites ouvertes

- Rien n'est prouvé sur un poste réel avec Microsoft Defender actif : lot 3d non exécuté (VM nécessaire).
- Export syslog en clair (UDP ou TCP, sans TLS).
- Détection non mesurée : pas de règles testées avec cas positif et négatif ni de taux de faux positifs (phase 3).
- Autorisation non vérifiée commande par commande sur le canal (phase 1).
- Aucun audit humain indépendant du code n'a été fait.
- GitHub Actions désactivé sur le dépôt : les scénarios n'ont tourné qu'en Windows Sandbox depuis le 2026-10-22.
