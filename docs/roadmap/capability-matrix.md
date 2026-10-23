# Matrice des capacités de deR4Tizer

État au 2026-10-22, branche `main` (commit `1007795`, version 4.3). Aucune affirmation ici n'est plus forte
que la preuve citée. Les PR ouvertes sont signalées comme telles : tant qu'elles ne sont pas fusionnées, `main`
ne contient pas leur contenu.

## États

| État | Sens |
|---|---|
| prévu | Rien dans le code. |
| implémenté non vérifié | Le code existe ; aucun test automatisé n'en vérifie le comportement. |
| testé en labo | Fonctions pures ou parseurs vérifiés par `cargo test --release` (décisions, formats, mini-fuzz) ; le comportement sur un Windows réel n'est pas prouvé. |
| validé sur Windows | Scénarios réussis avec le service réel, installé par le MSI, sur un runner Windows jetable de la CI (jobs `integration-*`, tableaux cités). |
| prêt pour la production | Aucune capacité aujourd'hui : binaires non signés, scénario Defender (lot 3d) non exécuté, aucun audit. |

L'IDS, le DPI et le NDR sont **expérimentaux**, quel que soit l'état de leurs tests.

## Preuves de CI citées

- **3a** (`integration-installation`, `tests/integration/installation.ps1`) : run 39822711631 (PR #9, `3194bb6`), 42 scénarios, 0 échoué, 0 non exécuté.
- **3b** (`integration-quarantaine`, `tests/integration/quarantaine.ps1`) : même run, 21 scénarios, 0 échoué, 1 non exécuté (refus par `creer_sans_lien` : course non reproductible).
- **3c** (`integration-maj`) : PR #10, **non fusionnée** ; tableau à reporter ici après sa validation.
- Tests unitaires : `cargo test --release` sur `main` (`1007795`), 66 réussis (voir `docs/testing/baseline.md`).

## Matrice

| Capacité | État | Sources | Prérequis Windows | Tests existants | Limites |
|---|---|---|---|---|---|
| Installation, désinstallation (avec et sans `GARDER_DONNEES=1`), mise à niveau par MSI | validé sur Windows | `installeur/deR4Tizer.wxs`, `construire-msi.ps1` | Windows 10 ou plus récent, 64 bits ; administrateur | 3a | Le MSI accepte une version plus ancienne (`AllowDowngrades`, nécessaire au retour arrière) : le refus d'une version plus ancienne est assuré par le service, sur la version lue dans le paquet signé, et un administrateur peut toujours installer une version plus ancienne à la main. Binaires non signés. |
| Service SYSTEM, démarrage automatique, redémarrage sur échec | validé sur Windows | `main.rs` | — | 3a | Un attaquant administrateur peut arrêter le service. |
| Canal de commandes (tube nommé) | validé sur Windows (refus du compte standard) ; testé en labo (PID du serveur) | `canal.rs`, `maj.rs` (`ps_canal`) | — | 3a (essais du compte standard : `UnauthorizedAccessException` exigée) ; `serveur_tube`, `lot2_canal_code_de_production_sur_un_vrai_tube` | Pas de délai maximal de lecture d'une commande ; tube occupé au démarrage (squat) signalé seulement dans le journal (correctifs proposés, PR #15, non fusionnée). |
| Protection du dossier de données (propriétaire, droits, échec fermé, dossier précréé, fichiers piégés) | validé sur Windows | `protection.rs`, `commun.rs`, `natif.rs` | NTFS | 3a ; `securite`, `m1_proprietaire_du_dossier_de_donnees`, `lot1_*`, `lot1ter_reinitialisation_*`, `lot1ter_garder_tel_quel_*` | Lecture accordée à un compte **standard** connecté à la console : non testée (la session du runner est celle d'un administrateur ; VM nécessaire). En échec de la protection, l'alerte critique reste locale (les secrets de remontée sont ignorés) : le prestataire n'est pas prévenu. Les éléments mis de côté dans `ecartes` gardent leur propriétaire d'origine et restent modifiables par leur auteur (jamais lus). |
| Quarantaine et restauration (copie encodée, reprise au démarrage, repli dans le dossier du service, jonctions) | validé sur Windows | `reponse.rs`, `natif.rs` | — | 3b ; `lot1bis_*`, `lot1ter_*` | Restauration avec la session d'un utilisateur **standard** : non testée (VM). Refus par `creer_sans_lien` (jonction posée entre le contrôle du propriétaire et la création) : non couvert de façon reproductible. Jonction « pendant » une quarantaine : testée sous sa forme déterministe seulement. |
| Mise à jour automatique (manifeste, paquet MSI signé, clé épinglée, retour arrière) | testé en labo ; validation sur Windows en cours (PR #10, non fusionnée) | `maj.rs`, `natif.rs`, `.github/workflows/publication.yml` | `curl.exe` de Windows (Schannel), Windows Installer | `lot2_*`, `n2_mise_a_jour_cle_epinglee` | Sur `main`, un certificat dont la liste de révocation ne répond pas est **accepté** (constaté par le lot 3c ; correctif proposé, PR #12, non fusionnée). Installation automatique désactivée par défaut ; sans clé épinglée dans le binaire, une version est seulement signalée. Service muet après l'installation : couvert seulement par le mode simulation de `script_installation`. |
| Tuer, suspendre, reprendre un processus ; isoler un programme du réseau ; mode panique | implémenté non vérifié (mode panique : plages testées en labo) | `reponse.rs`, `blocage.rs` | Pare-feu Windows | `plages_du_mode_panique`, `reseaux_reserves` | Mode panique : les serveurs DNS et de notification restent joignables pour tous les programmes. |
| Blocages (fichier hosts, pare-feu) et blocage automatique par les listes de menaces | testé en labo (levée des blocages) | `blocage.rs`, `moniteur.rs`, `menaces.rs` | Pare-feu Windows | `blocages_leves_a_expiration_ou_hors_liste` | Le blocage automatique (activé par défaut) porte sur les listes de confiance « haute » : par défaut Spamhaus DROP et Feodo Tracker ; avec le réglage « listes restreintes », aussi FireHOL niveau 1 et ThreatView Cobalt Strike, au-delà de la politique de réponse (`docs/reponse/politique.md`). |
| Listes de menaces (téléchargement toutes les 12 h, chargement compact) | implémenté non vérifié | `menaces.rs` | Accès à Internet | `reseaux_reserves` (réseaux réservés seulement) | Licences de plusieurs listes « à vérifier » (désactivées par défaut). Une liste corrompue peut bloquer des adresses légitimes (voir `docs/security/threat-model.md`). |
| Surveillance des connexions, score de suspicion, balises, première connexion | implémenté non vérifié (critère « IP directe » testé en labo) | `moniteur.rs`, `natif.rs` | — | `ip_directe_editeurs_exacts` | — |
| Chaînes de processus et score cumulé | implémenté non vérifié | `chaines.rs` | — | — | — |
| Origine des processus et règles inspirées de Sigma | implémenté non vérifié (débogage à distance testé en labo) | `processus.rs` | Sysmon facultatif (sinon WMI) | `debogage_a_distance_ancre_sur_l_executable` | Sans Sysmon, couverture réduite. |
| Persistance (clés Run, services, tâches, WMI, Démarrage) | implémenté non vérifié | `persistance.rs` | — | — | — |
| Leurres anti-rançongiciel et suspension automatique | testé en labo (décision) | `hygiene.rs`, `vol_donnees.rs` | Audit du système de fichiers (4663) | `b1_leurre_touche_par_rundll32_suspendu`, `b2_noms_des_leurres_dans_le_dossier_des_secrets` | — |
| Pilotes vulnérables (LOLDrivers) | testé en labo (chemins) | `hygiene.rs` | — | `chemins_des_pilotes` | Lecture de `loldrivers.json` sans contrôle du propriétaire (correctif proposé, PR #16, non fusionnée). |
| Extensions de navigateur | implémenté non vérifié | `hygiene.rs` | — | — | — |
| Vol de données (audit des fichiers des navigateurs et applications) | testé en labo (décision) | `vol_donnees.rs` | Audit « Système de fichiers » (profil de baseline « journalisation ») | `alerte`, `editeurs_compares_exactement` | Ne voit pas l'injection de code dans le navigateur. Poste géré sans audit des fichiers : non surveillé (signalé). |
| Vie privée et accès à distance (caméra, micro, prise en main, ports ouverts) | implémenté non vérifié | `surveillances.rs` | — | — | — |
| Pare-feu : changements de règles, exposition à Internet | implémenté non vérifié | `parefeu.rs` | Journal du pare-feu, `pfirewall.log` | — | — |
| Redirections UPnP de la box | testé en labo (parseur) | `upnp.rs` | — | `n1_upnp_sans_panique_sur_utf8_coupe` | — |
| Surveillance de Microsoft Defender | implémenté non vérifié | `defender.rs` | Microsoft Defender | — | Exécution avec Defender actif non vérifiée (lot 3d, non exécuté). |
| Baseline de sécurité par la GPO locale | testé en labo (partiel) | `baseline.rs`, `gpo.rs` | Poste non géré (sur un poste géré : lecture seule) | `baseline_reglage_asr_partage_conserve` | — |
| Mini-SIEM (événements, recherche, corrélation, incidents) | implémenté non vérifié | `siem.rs`, `evenements.rs` | Journaux de Windows | — | Lecture des événements sans contrôle du propriétaire (correctif proposé, PR #16, non fusionnée). |
| Analyse du trafic, pays (GeoIP) | implémenté non vérifié (décodage testé en labo) | `trafic.rs`, `geoip.rs`, `capture.rs` | Règle de pare-feu « deR4Tizer capture » | `paquet_udp`, `decoder_paquet_udp`, `decoder_sans_panique` | IPv4 seulement ; sur un réseau commuté, seul le trafic du poste est vu ; pays du titulaire du bloc. |
| NDR local (ARP, DHCP, LLMNR/NBNS/mDNS) | expérimental ; implémenté non vérifié | `ndr.rs` | — | — | — |
| DPI (SNI, JA3, HTTP, DNS) | expérimental ; testé en labo (parseurs, mini-fuzz) | `dpi.rs` | — | `client_hello*`, `question_dns`, `noms_dns` | Lecture des empreintes JA3 sans contrôle du propriétaire (correctif proposé, PR #16, non fusionnée). |
| IDS / IPS (règles au format Suricata) | expérimental ; testé en labo (règles, mini-fuzz) | `ids.rs` | — | `regles_*`, `regle_contenu_hexa_et_correspondance` | IPS désactivé par défaut. Options `pcre`, `byte_test` et quelques autres ignorées. Règles `regles\` lues sans contrôle du propriétaire ; en échec de la protection, l'IPS activé bloquerait encore (correctifs proposés, PR #16, non fusionnée). |
| Remontée des alertes (ntfy, Teams, SMTP) | testé en labo (regroupement, plafond, critiques jamais retenues) | `notifications.rs` | `curl.exe` de Windows | `notifications_critiques_jamais_retenues`, `regroupement_second_niveau`, `b3_vraie_alerte_visible_parmi_300_usurpations`, `horodatage_et_base64` | Secrets ignorés en échec de la protection du dossier. |
| Export syslog (RFC 5424, JSON ou CEF) | implémenté non vérifié (horodatage testé en labo) | `export.rs` | — | `horodatage_et_base64` | **En clair** (UDP ou TCP, sans TLS) : à réserver à un réseau local de confiance. |
| API HTTP d'export (lecture seule, jeton) | testé en labo (adresses autorisées) ; écoute validée sur Windows (port témoin de 3a) | `api.rs` | — | `api_adresses_autorisees` ; 3a | Échec de `BCryptGenRandom` non vérifié à la création du jeton, jeton existant repris dès 32 caractères ; `/api/v1/sante` renvoie le nom de la machine sans jeton (correctifs proposés, PR #14, non fusionnée). |
| Apprentissage et exceptions | testé en labo | `apprentissage.rs` | — | `n3_apprentissage_par_chemin_editeur_et_destination` | — (cache de l'éditeur indexé par chemin et date de modification depuis la 4.2) |
| Techniques MITRE ATT&CK et conseils | implémenté non vérifié | `mitre.rs` | — | — | — |
| Interface (C#, français et anglais) | implémenté non vérifié (compilée par la CI) | `src/*.cs` | .NET Framework 4.8 | Compilation dans le job `windows` | Rendu à 125 % et 150 % non vérifié sur un écran réel. |
| Signature des binaires et du MSI | prévu | `.github/workflows/publication.yml` | Certificat de signature de code | — | Binaires non signés ; choix du certificat en attente (SignPath Foundation ou Azure Trusted Signing : voir `docs/security/threat-model.md`). |
| Exécution avec Microsoft Defender actif (lot 3d) | prévu | — | VM ou runner auto-hébergé | — | Non exécuté : dernier verrou avant toute distribution. |

## Scénarios de CI non exécutés (à faire sur une VM)

- Restauration avec la session d'un utilisateur standard (3b).
- Lecture des données par un compte standard connecté à la console (3a).
- Refus par `creer_sans_lien` d'une jonction posée entre le contrôle et la création (course).
- Service muet après une mise à jour (3c : simulation seulement).
- Exécution complète avec Microsoft Defender actif (3d).
