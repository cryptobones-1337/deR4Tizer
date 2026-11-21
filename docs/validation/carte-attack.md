# Carte ATT&CK : profil « rançongiciel et intrusion opportuniste, petite structure »

- **Date** : 2026-11-21.
- **Profil validé par le mainteneur le 2026-11-21.**
- **Version d'ATT&CK** : Enterprise v20.1 (13 octobre 2026), identifiants vérifiés le 2026-11-21 sur attack.mitre.org.
- **Origine** : carte de départ établie en lecture seule par l'auditeur sur `main` (`7421f82`), à partir de
  `service-rs/src/mitre.rs`, `docs/detection/regles.md` et des rapports de ce dossier ; reprise ici après deux
  vérifications (section « Vérifications du lot 0 ») et deux corrections.
- **Ce que la carte n'est pas** : ni une couverture, ni une validation. Un état ne change que sur un rapport de campagne
  publié dans ce dossier ; les tests en labo de la campagne Kali sont faits en VM, par un agent, sur une liste approuvée
  par l'agent de validation (`README.md`, « À savoir »).

## Le profil

54 lignes (une soixantaine de techniques et sous-techniques, certaines regroupées), choisies pour un poste Windows
d'une petite structure : ce qu'utilisent les rançongiciels et les intrusions opportunistes, de l'entrée à l'impact. La
liste vient de la connaissance qu'a l'auditeur des classements publics (rapports annuels de détection, travaux du centre
de MITRE sur les rançongiciels) ; elle n'a pas été confrontée à leur édition en cours.

## Lecture des états

| État | Sens |
|---|---|
| **Testé en labo, consolidé** | 10 essais valides dans un rapport de campagne (`CLAUDE.md`) |
| **Testé en labo** | Détection constatée dans un rapport de campagne, moins de 10 essais : « non consolidé » |
| **Règle, non testée** | Une règle existe, avec ses tests unitaires, jamais exercée en campagne |
| **Partiel** | Une partie seulement du comportement est vue, ou seulement dans un cas (adresse publique, Sysmon présent) |
| **Vu sans alerte** | L'événement est collecté, aucune règle ne le lit |
| **Prévention seule** | La baseline ou Defender l'empêche ; deR4Tizer ne le détecte pas lui-même |
| **Aucune règle** | Rien, mais faisable avec la télémétrie actuelle |
| **Hors portée** | Infaisable sans pilote noyau ou sans capteur que le produit s'interdit |

Rapports cités (tous dans ce dossier) : S-01, S-09 et S-13 dans `campagne-kali-premier-passage.md` (2026-11-15) ;
S-07 et S-14 dans `campagne-kali-second-lot.md` (2026-11-15) ; S-02, S-08, S-10, S-11, S-12, S-15, S-16 et S-17 dans
`campagne-kali-sixieme-lot.md` (2026-11-16) ; S-20 à S-27 dans `campagne-kali-detection-reseau-lot1.md` à `lot5.md`
(2026-11-16 et 2026-11-17).

## La carte

Les tactiques suivent ATT&CK v20 : l'ancienne « Defense Evasion » (TA0005) s'appelle « Stealth » (discrétion), et une
tactique nouvelle, « Defense Impairment » (TA0112), réunit la neutralisation des protections.

### Accès initial

| Technique | Règle | État | Ce qui manque |
|---|---|---|---|
| T1566.001 Pièce jointe piégée | PRC-001 ; ASR Office (baseline) | Règle, non testée | Scénario de campagne |
| T1566.002 Lien piégé | DNS-001, filtrage DNS | Partiel : domaine listé testé en labo (S-07, 2026-11-15) | Rien pour un domaine non listé |
| T1133 Services distants exposés | COR-R9, RES-005, RES-007, VIE-003, UPnP (EXP-NDR-001) | Testé en labo (S-02, S-17, 2026-11-16 ; S-27, 2026-11-16) | 10 essais |
| T1078.003 Comptes locaux valides | COR-R2, COR-R9 | Partiel (après des échecs, ou depuis une adresse publique) | Connexion réussie sans échec depuis le réseau local |
| T1091 Supports amovibles | Baseline (ASR, exécution automatique) | Prévention seule | Règle sur le branchement et l'exécution depuis une clé |

### Exécution

| Technique | Règle | État | Ce qui manque |
|---|---|---|---|
| T1059.001 PowerShell | PRC-002 | Partiel : testé en labo avec Sysmon seulement (S-10, 2026-11-16) | Lecture des 4688, défaut structurel 1 |
| T1059.003 Invite de commandes | CHA-001 | Partiel | Idem |
| T1059.005 / .007 VBScript, JScript | PRC-001 ; baseline (WSH, ASR) | Règle, non testée | wscript et cscript absents de PRC-003 |
| T1204.002 Fichier lancé par l'utilisateur | PRC-001, CHA-001, RES-003 | Règle, non testée | Scénario |
| T1047 WMI | ASR (profil renforcé) | Prévention seule | Règle sur `wmic process call create` et WmiPrvSE parent |
| T1053.005 Tâche planifiée | PER-001 | **Testé en labo (S-09, 2026-11-15)**, configurations A et C | 10 essais |
| T1569.002 Exécution par service | COR-R5 | Testé en labo, en partie (S-13, 2026-11-15) | Service lancé depuis un dossier système |
| T1218 Binaires système détournés | PRC-003 (certutil, bitsadmin, mshta, regsvr32, rundll32, wmic) | Règle, non testée | Scénario ; msiexec, installutil absents |

### Persistance

| Technique | Règle | État | Ce qui manque |
|---|---|---|---|
| T1547.001 Clés Run, dossier Démarrage | PER-001, PER-002 | Testé en labo, clé Run (S-09, 2026-11-15) | Dossier Démarrage ; 10 essais |
| T1543.003 Service Windows | PER-001, COR-R5 | Testé en labo, en partie (S-13, 2026-11-15) | 10 essais |
| T1546.003 Abonnement WMI | PER-001 ; ASR | Règle, non testée | Scénario |
| T1136.001 Compte local créé | COR-R3 | Défaut ouvert : ne se déclenche pas par le vecteur courant (S-13 donne COR-R3b) | Correctif, puis test |
| T1098 Compte ajouté aux administrateurs | COR-R3b | Testé en labo (S-13, 2026-11-15) | 10 essais |
| T1176.001 Extension de navigateur | EXT-001 | Règle, non testée | Scénario |
| T1197 Tâches BITS | PRC-003 (bitsadmin) | Partiel | Tâche créée par PowerShell |

### Élévation de privilèges

| Technique | Règle | État | Ce qui manque |
|---|---|---|---|
| T1548.002 Contournement de l'UAC | Baseline (UAC « toujours notifier ») | Prévention seule | Règle sur les contournements connus |
| T1068 Pilote vulnérable | PIL-001, COR-R10 ; ASR | Règle, non testée | Scénario (fiche inoffensive) |
| T1055 Injection dans un processus | aucune | Hors portée | Dit comme limite |

### Neutralisation des défenses (Defense Impairment)

| Technique | Règle | État | Ce qui manque |
|---|---|---|---|
| T1685 Protections désactivées (ex-T1562.001) | DEF-003 à 006, 010 à 012, BAS-001 | Règle, non testée : Defender intouchable en VM | Reste « testé en labo » au mieux, par règle du projet |
| T1685.001 Journalisation coupée (ex-T1562.002) | COR-R7 | Testé en labo (S-13, 2026-11-15) | 10 essais |
| T1686.003 Pare-feu de l'hôte modifié (ex-T1562.004) | SYS-002, SYS-003 | Règle, non testée | Scénario |
| T1685.005 Journaux effacés (ex-T1070.001) | COR-R4 | Testé en labo (S-13, 2026-11-15) | 10 essais |
| T1112 Registre modifié | BAS-001, PER-002 | Partiel | Limité aux réglages suivis |

### Discrétion (Stealth)

| Technique | Règle | État | Ce qui manque |
|---|---|---|---|
| T1027 Code obscurci | PRC-002 | Partiel (Sysmon) | Défaut structurel 1 |
| T1036 Programme déguisé | étiquette « non signé » seulement | Aucune règle | Outil système copié ou renommé (T1036.003) |

### Vol d'identifiants

| Technique | Règle | État | Ce qui manque |
|---|---|---|---|
| T1110 Force brute | COR-R1, COR-R2 | **Testé en labo, consolidé : 10 sur 10 (S-01, 2026-11-15)** | Rien : seule mesure consolidée |
| T1555.003 / T1539 Secrets et cookies des navigateurs | VOL-001, PRC-004 | Testé en labo (S-14, 2026-11-15) | 10 essais |
| T1003.001 Mémoire de LSASS | ASR (baseline) | Vu sans alerte (S-15, 2026-11-16, Sysmon) | Règle ; audit « Kernel Object » proposé |
| T1003.002 Base SAM | aucune | Aucune règle | `reg save` des ruches SAM et SYSTEM |
| T1557.001 Empoisonnement de la résolution de noms | EXP-NDR-001 | Testé en labo (S-22, S-23, S-25, S-26, 2026-11-16) | 10 essais ; NBNS passif jamais exercé |
| T1557.002 Usurpation ARP | EXP-NDR-001 | Testé en labo (S-20, 2026-11-16) | 10 essais |

### Découverte

| Technique | Règle | État | Ce qui manque |
|---|---|---|---|
| T1046 Balayage de ports | aucune | Aucune règle (S-08, 2026-11-16 : non détecté) | Le journal du pare-feu est déjà lu |
| T1087, T1018, T1135 Comptes, machines, partages | aucune | Aucune règle | À compter dans le score des chaînes (net, nltest, whoami) |

### Mouvement latéral

| Technique | Règle | État | Ce qui manque |
|---|---|---|---|
| T1021.001 Bureau à distance | COR-R9, VIE-003 | Partiel (adresse publique seulement) | Session depuis le réseau local |
| T1021.002 Partages administratifs | COR-R9 | Partiel (S-17, 2026-11-16) ; 5140 produit, non lu | Lecture des 5140 |
| T1570 Transfert d'outils | aucune | Aucune règle | Exécutable écrit sur un partage administratif |

### Collecte, commande et contrôle

| Technique | Règle | État | Ce qui manque |
|---|---|---|---|
| T1560.001 Archivage avant exfiltration | aucune | Aucune règle | 7z, rar en ligne de commande sur des dossiers d'utilisateur |
| T1123, T1125 Micro, caméra | VIE-001 | Règle, non testée | Scénario |
| T1056.001 Enregistreur de frappe | aucune | Hors portée | Dit comme limite |
| T1071.001 Protocole web | RES-001, RES-002, RES-003, balise | Testé en labo (S-11, 2026-11-16) | Balise jamais testée ; 10 essais |
| T1071.004 DNS | DNS-001, EXP-DPI-001 | Partiel (domaine listé) | Tunnel DNS jamais testé |
| T1105 Téléchargement d'outils | RES-002, PRC-003 | Partiel (connexion vue, contenu non) | Scénario avec certutil, bitsadmin |
| T1219 Outils d'accès à distance | VIE-002 | Règle, non testée | Scénario |
| T1572, T1090 Tunnel, relais | VIE-002 (ngrok, par le nom du processus) | **Partiel** : ngrok seulement, règle non testée | chisel, plink ; un tunnel renommé |

### Exfiltration et impact

| Technique | Règle | État | Ce qui manque |
|---|---|---|---|
| T1041 Exfiltration par le canal de contrôle | RES-002 | Partiel (connexion, pas le volume, S-12, 2026-11-16) | Volume par programme (le module Trafic l'a) |
| T1567.002 Vers un stockage en ligne | aucune | Aucune règle | rclone, MEGA ; volume sortant inhabituel |
| T1486 Chiffrement des données | LEU-001, LEU-002, suspension | Testé en labo (S-16, 2026-11-16) | 10 essais |
| T1490 Sauvegardes supprimées | PRC-005 | Règle, non testée | Scénario (commande portée sans être exécutée) |
| T1489 Services arrêtés | COR-R7 | Partiel (services de sécurité) | Arrêt en série de services |

## Bilan

| État | Lignes |
|---|---|
| Testé en labo, consolidé | 1 |
| Testé en labo, non consolidé | 13 |
| Partiel | 14 |
| Règle, non testée | 12 |
| Vu sans alerte | 1 |
| Prévention seule | 3 |
| Aucune règle | 7 |
| Hors portée | 2 |
| Défaut ouvert (T1136.001) | 1 |
| **Total** | **54** |

Le décompte porte sur les lignes de la carte : certaines regroupent deux techniques voisines.

## Vérifications du lot 0

### Identifiants (attack.mitre.org, ATT&CK v20.1, le 2026-11-21)

Les identifiants de la carte de départ venaient de la mémoire de l'auditeur. Chaque page de technique a été lue ; les
écarts :

| Carte de départ | ATT&CK v20.1 | Remarque |
|---|---|---|
| T1562.001 Disable or Modify Tools | **T1685** Disable or Modify Tools | La page T1562.001 renvoie vers T1685 (tactique Defense Impairment, créée le 2026-04-14) |
| T1562.002 Disable Windows Event Logging | **T1685.001** Disable or Modify Windows Event Log | Renvoi de page |
| T1562.004 Disable or Modify System Firewall | **T1686.003** Windows Host Firewall | La page renvoie vers T1686 ; la sous-technique de l'hôte Windows est T1686.003 |
| T1070.001 Clear Windows Event Logs | **T1685.005** Clear Windows Event Logs | Renvoi de page ; T1070.001 ne figure plus sous T1070 |
| T1176 Browser Extensions | T1176 Software Extensions, sous-technique **T1176.001** Browser Extensions | Renommée ; T1176.002 IDE Extensions |
| T1219 Remote Access Software | T1219 **Remote Access Tools** | Renommée ; sous-techniques T1219.001 à .003 |
| T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay | T1557.001 **Name Resolution Poisoning and SMB Relay** | Renommée (couvre aussi mDNS) |

Les autres identifiants sont inchangés. Le code pose encore les anciens identifiants (`mitre.rs` : T1562.001,
T1562.004, T1176 ; `regles.md` et le SIEM : T1070.001) : le lot 2 (technique tirée de l'identifiant de règle) les
remplacera par une seule table, alignée sur cette carte.

### Lignes « Aucune règle » contre `docs/detection/regles.md`, lu en entier

| Ligne | Résultat |
|---|---|
| T1036 Programme déguisé | Confirmé. Deux gardes voisines, qui ne sont pas des règles de déguisement : VOL-001 lève l'alerte pour un « chrome.exe » non signé par Google qui lit des secrets ; SYS-003 traite un « svchost.exe » hors de Windows comme un auteur tiers |
| T1003.002 Base SAM | Confirmé : VOL-001 n'audite que des fichiers de profils |
| T1046 Balayage de ports | Confirmé (S-08 : non détecté). L'IDS livre une signature de contenu « Nmap Scripting Engine » (EXP-IDS-001), qui voit les scripts de Nmap, pas un balayage |
| T1087, T1018, T1135 | Confirmé |
| T1570 Transfert d'outils | Confirmé |
| T1560.001 Archivage | Confirmé |
| T1572, T1090 Tunnel, relais | **Corrigé** : VIE-002 lève une alerte pour un processus nommé `ngrok` (« ngrok (tunnel) », `surveillances.rs`). La ligne passe en « Partiel » |
| T1567.002 Stockage en ligne | Confirmé |

### Autre correction, d'après un rapport publié

- **T1053.005 Tâche planifiée** : la carte de départ disait « Partiel (témoin négatif N-02 seulement) ». Le premier
  passage (`campagne-kali-premier-passage.md`, 2026-11-15, S-09 « clé Run + tâche planifiée ») a levé deux alertes
  PER-001, une par mécanisme, en configurations A et C. La ligne passe en « Testé en labo », non consolidé ; elle
  rejoint les lignes à consolider.

## Trois défauts structurels, à traiter avant d'ajouter des règles

**1. Les règles de processus ne lisent pas les événements 4688.**
- La baseline active l'audit des créations de processus avec la ligne de commande, et le mini-SIEM stocke ces 4688.
- Les règles PRC-001 à PRC-005 et les chaînes prennent la ligne de commande dans Sysmon s'il est installé, sinon dans
  WMI après coup (`processus.rs`). Un processus bref se termine avant l'interrogation : la détection devient aléatoire
  (S-10, 2026-11-16 : sans Sysmon, non déterministe).
- Brancher ces règles sur les 4688 rendrait fiables, sans Sysmon, les lignes « Partiel (Sysmon) ».

**2. La technique ATT&CK est attribuée par mots-clés français dans le texte de l'alerte.**
- `mitre.rs` cherche des mots (« leurre », « chaîne d'attaque », « pare-feu ») dans les raisons ; la première
  correspondance gagne. Toute chaîne reçoit T1204, quel que soit son contenu.
- Chaque alerte porte déjà un identifiant de règle : la technique doit venir de lui, dans une seule table.

**3. Les fiches de règles ne portent pas la technique.**
- `docs/detection/regles.md` cite quelques techniques pour une cinquantaine de règles : une ligne « ATT&CK » par fiche,
  tirée de la même table que le code.

## Ordre de travail

1. Défauts structurels 1, 2 et 3 (lots 1 à 3).
2. Consolider ce qui est déjà testé en labo : 10 essais valides pour les 13 lignes non consolidées (lot 4).
3. Tester les 12 lignes « Règle, non testée » : aucune règle à écrire, seulement des scénarios (lot 5).
4. Fermer les lignes « Partiel » et « Vu sans alerte » qui ne demandent qu'un événement déjà collecté.
5. Écrire les règles des lignes « Aucune règle ».
6. Publier la carte, générée depuis les résultats, avec les deux lignes « Hors portée » dites comme telles (lot 6).

Les étapes 4 et 5 ajoutent des capacités : il leur faut une phase ouverte par écrit par le mainteneur dans `CLAUDE.md`.

## Limites

- Les états viennent des rapports du dépôt, pas d'un essai fait pour cette carte.
- Le profil n'a pas été confronté à l'édition en cours des classements publics dont il s'inspire.
- La campagne Kali est menée par un agent, dans une VM de test, sur une liste approuvée par l'agent de validation :
  ni humaine ni indépendante.
