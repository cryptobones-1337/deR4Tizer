# deR4Tizer

**Protection locale pour Windows : détection type EDR, mini-SIEM et durcissement, sans cloud.**
*Local protection for Windows: EDR-style detection, mini-SIEM and hardening, no cloud.*

[Français](#français) · [English](#english)

> ⚠️ **Preuve de concept / Proof of concept.** Projet en développement actif, non audité. Ne remplace pas un antivirus ni un EDR commercial.
> Under active development, not audited. Does not replace an antivirus or a commercial EDR.

---

## Français

### Pourquoi

deR4Tizer s'adresse aux structures qui n'ont ni SOC ni budget EDR : petites communes, TPE, artisans, commerces. Tout tourne **sur le poste**, sans compte, sans cloud et sans télémétrie. Les alertes critiques arrivent chez le prestataire ou le référent (ntfy, Teams, e-mail) et peuvent aussi partir vers le SIEM de votre choix.

### Fonctionnalités (v4.3)

| Domaine | Ce que fait deR4Tizer |
|---|---|
| **Réseau** | Connexions sortantes en direct par programme, score de suspicion, détection de balises (beaconing), première connexion d'un programme à Internet |
| **Renseignement sur les menaces** | Listes open source mises à jour toutes les 12 h, blocage automatique facultatif au pare-feu |
| **Processus** | Arbre des processus et score cumulé par chaîne, PowerShell obscurci, techniques MITRE ATT&CK |
| **Persistance** | Clés Run, services, tâches planifiées, WMI, dossiers Démarrage : alerte sur toute entrée nouvelle ou modifiée |
| **Rançongiciels** | Fichiers leurres, suspension automatique du programme qui y touche |
| **Vol de données** | Audit d'accès aux dossiers sensibles des navigateurs et applications |
| **Vie privée** | Caméra, micro, outils de prise en main à distance, ports ouverts |
| **Pare-feu** | Suivi des changements de règles (avec le programme auteur), exposition à Internet (paquets entrants depuis une IP publique) |
| **Durcissement** | Baseline inspirée d'Intune et de Microsoft, appliquée par la stratégie de groupe locale, réversible |
| **Réponse** | Tuer, suspendre, isoler du réseau, mettre en quarantaine, bouton PANIQUE (coupe Internet) |
| **Mini-SIEM** | Événements normalisés (sessions, comptes, groupes, processus, services, connexions, pare-feu, alertes) conservés 30 jours, recherche, chronologie, incidents de corrélation (force brute, session après échecs, nouvel administrateur, journal effacé, service suspect, protection affaiblie, attaque en plusieurs étapes, accès depuis Internet) |
| **Analyse du trafic** | Capture passive des paquets (sockets brutes de Windows, sans pilote) : débit, programmes, destinations, ports et pays (registres Internet régionaux), carte du monde en direct |
| **NDR local** | Usurpation ARP de la passerelle, nouveaux appareils, serveur DHCP pirate, empoisonnement LLMNR/NBNS/mDNS (Responder) avec leurre actif ; fonctionne aussi derrière un VPN |
| **DPI** | Nom des sites TLS (SNI) et empreintes JA3 (liste SSLBL), HTTP en clair (identifiants envoyés sans chiffrement), DNS (tunnel DNS), SMB/Telnet/FTP vers Internet, noms comparés aux listes de menaces |
| **IDS / IPS** | Règles au format Suricata (sous-ensemble : content, nocase, offset/depth/distance/within, flags, dsize…), règles intégrées + fichiers `.rules` (par exemple Emerging Threats Open) ; en mode IPS, blocage au pare-feu |
| **Remontée des alertes** | Vers le prestataire ou le référent : ntfy, Microsoft Teams (webhook de flux de travail, carte avec le « quoi faire »), e-mail SMTP chiffré ; regroupement des alertes, plafond horaire, secrets réservés aux administrateurs |
| **Intégration** | Syslog RFC 5424 (UDP/TCP, JSON ou CEF), API HTTP d'export en lecture seule avec jeton |
| **Confidentialité** | Données (événements, sessions, alertes, appareils) lisibles seulement par SYSTEM, les administrateurs et les comptes autorisés ; jeton de l'API réservé aux administrateurs ; dossier créé avec ses droits par l'installation, propriétaire et droits réimposés et vérifiés à chaque démarrage, fichiers d'un autre propriétaire ignorés ; si la vérification échoue, configuration et secrets sont ignorés et l'interface l'affiche |
| **Moins de bruit** | Mode apprentissage les 7 premiers jours (comportements mémorisés), exceptions « ne plus alerter pour ce comportement », critère « IP directe » neutralisé pour les VPN, messageries et jeux connus ; les alertes critiques ne sont jamais adoucies |
| **Mise à jour** | Vérification quotidienne ; installation (désactivée par défaut) seulement si l'empreinte SHA-256 est juste et si le fichier est signé par l'une des clés épinglées dans le binaire, révocation vérifiée, fichiers gardés dans un dossier réservé à SYSTEM, avec retour à l'ancienne version si le service ne répond plus |
| **Interface** | Français / anglais |

### Architecture

```
deR4TizerSvc.exe   service Windows en Rust, compte SYSTEM (surveillance, réponse, export)
deR4Tizer.exe      interface C# (.NET Framework 4.8, fourni avec Windows), sans droits admin
C:\ProgramData\deR4Tizer   état partagé (JSON), journal ; lecture : administrateurs et comptes autorisés
\\.\pipe\deR4Tizer         commandes interface → service (administrateurs et SYSTEM seulement)
```

Aucun pilote noyau, aucune dépendance à installer : uniquement des API Windows (ETW, journal d'événements, WMI, pare-feu, IP Helper, WinVerifyTrust).

### Compiler

Prérequis : Windows 10/11, Visual Studio Build Tools 2022 (charge de travail « Développement Desktop en C++ »), [rustup](https://rustup.rs) avec la chaîne **stable-x86_64-pc-windows-msvc**, la même que la CI. Les tests sur un poste se font avec l'artefact compilé par la CI.

```powershell
rustup toolchain install stable-x86_64-pc-windows-msvc
.\compiler.ps1          # interface (csc de Windows) + service Rust → bin\
```

### Installer

Télécharger `deR4Tizer.msi` depuis la [dernière version](https://github.com/cryptobones-1337/deR4Tizer/releases/latest)
et l'ouvrir. Le service démarre aussitôt ; l'interface se trouve dans le menu Démarrer et se lance à l'ouverture de
session. Les nouvelles versions sont signalées ; leur installation automatique s'active dans les réglages (versions signées).

Déploiement sur un parc (GPO, Intune, prestataire) :

```bat
msiexec /i deR4Tizer.msi /qn
msiexec /i deR4Tizer.msi /qn LANCEMENT_SESSION=0     :: sans lancement de l'interface à l'ouverture de session
```

Désinstallation depuis « Applications », ou `msiexec /x deR4Tizer.msi /qn`. Elle retire les blocages, les règles de
pare-feu et les leurres, remet les réglages de sécurité d'origine et efface les données ; `GARDER_BASELINE=1` et
`GARDER_DONNEES=1` conservent respectivement les réglages et les données.

La réparation (`msiexec /fa`) est réservée aux administrateurs et absente de « Applications » : elle arrête et
relance le service, ce qu'un compte standard ne doit pas pouvoir déclencher.

Développement : `.\construire-msi.ps1` construit le paquet (WiX 3.14, licence MS-RL, sans redevance) ;
`.\mettre-a-jour.ps1` remplace les exécutables d'une installation existante.

### Intégration SIEM

**Syslog** : Réglages → *Envoi des alertes*. Format JSON (en-tête RFC 5424, détail en JSON) ou CEF.

**API d'export** : Réglages → *API d'export*. Écoute sur `127.0.0.1:8642` par défaut. Le réseau local est possible (profils Domaine et Privé uniquement).

```bash
curl -H "Authorization: Bearer <jeton>" "http://127.0.0.1:8642/api/v1/alertes?niveau=Alerte&format=ndjson"
```

| Route | Contenu |
|---|---|
| `/api/v1/sante` | Disponibilité (sans jeton) |
| `/api/v1/alertes?depuis=&niveau=&limite=&format=json\|ndjson\|cef` | Alertes |
| `/api/v1/connexions`, `/exposition`, `/baseline`, `/regles-parefeu`, `/blocages` | État |
| `/api/v1/evenements?q=&source=&type=&niveau=&depuis=&jusqua=&limite=&format=json\|ndjson` | Recherche dans les événements (mini-SIEM) |
| `/api/v1/incidents` | Incidents de corrélation |
| `/api/v1/journal?lignes=200` | Journal du service (texte) |

### Mise à jour automatique et signature

Chaque tag `vX.Y` lance le workflow *Publication* : tests, compilation, signature, empreintes et `manifeste.json`
joints à la version GitHub. Les postes lisent ce manifeste une fois par jour (`releases/latest/download/manifeste.json`).
Le manifeste est strict (champs connus seulement, 64 Ko au plus, un seul fichier : le paquet MSI) et ne fait jamais
foi seul, puisqu'il n'est pas signé. L'installation automatique est désactivée par défaut ; activée, elle n'installe
un paquet que si son empreinte est celle du manifeste, s'il est signé par l'une des **clés épinglées dans le
binaire** (empreintes SHA-256 des clés publiques, variable de dépôt `CLE_SIGNATURE`, transmise à la compilation
sous le nom `DER4TIZER_CLES_SIGNATURE` : la clé actuelle et la suivante, séparées par une virgule, pour passer le
renouvellement du certificat), révocation vérifiée, et si la **version lue dans le paquet signé** (`ProductVersion`,
avec l'`UpgradeCode` de deR4Tizer) est celle du manifeste et strictement plus récente que la version installée.
Avant toute installation, le service se procure aussi le paquet de **sa propre version**, vérifié de la même façon,
pour pouvoir y revenir ; sans lui, rien n'est installé. Les fichiers sont gardés dans `%ProgramFiles%\deR4Tizer\maj`,
réservé à SYSTEM (droits vérifiés avant chaque usage), et les empreintes sont revérifiées juste avant l'exécution.
Le service doit ensuite répondre en JSON valide sur son canal, avec la nouvelle version, dans les 60 s ; sinon le
paquet de la version précédente est réinstallé. Sans clé épinglée, une version est seulement signalée : un compte
GitHub compromis ne suffit pas à faire exécuter un binaire en SYSTEM sur le parc.

Protéger la publication : ranger les secrets de signature dans l'environnement GitHub « publication » avec une
approbation obligatoire (Settings › Environments), protéger les tags `v*` (Settings › Rules). La compilation (où
s'exécutent les scripts des dépendances) se fait dans un job sans secret ; la signature, dans un job à part qui ne
reçoit que les exécutables ; l'archive WiX est vérifiée par son empreinte et les actions sont épinglées par SHA.
L'idéal reste une clé hors de GitHub (Azure Trusted Signing, SignPath).

Pour signer : obtenir un certificat de signature de code (gratuit pour l'open source via
[SignPath Foundation](https://signpath.org), ou Azure Trusted Signing, ou un certificat OV au format .pfx), puis
ajouter les secrets `CERTIFICAT_PFX` (fichier .pfx en base64) et `CERTIFICAT_MOT_DE_PASSE`. En local,
`DER4TIZER_CERT_SHA1` (empreinte d'un certificat du magasin) fait signer `compiler.ps1`. Tant que les binaires ne sont
pas signés, Windows affiche « éditeur inconnu » et les postes signalent les nouvelles versions sans les installer.

### Limites connues

- Un PC sur un réseau commuté ne voit que son propre trafic, le broadcast et le multicast : ce n'est pas un NDR de tout le réseau (il faudrait un port miroir).
- La règle de pare-feu « deR4Tizer capture » autorise tout l'entrant vers le service : c'est nécessaire, une règle
  bloquant le TCP entrant vers le service fait aussi tomber la capture (mesuré : 3 Ko reçus en 20 s au lieu de 304 Ko).
  Le service n'écoute aucun port réseau, sauf l'API facultative, filtrée par adresse et bloquée sur le profil Public.
- Capture IPv4 seulement pour l'instant ; le pays est celui du titulaire du bloc d'adresses (un CDN peut apparaître aux États-Unis).
- Les exécutables ne sont pas encore signés (certificat de signature de code à obtenir, par exemple SignPath
  Foundation pour les projets open source) ; le service reconnaît ses propres fichiers par leur empreinte SHA-256.
- deR4Tizer complète Microsoft Defender, il ne le remplace pas : un attaquant administrateur peut arrêter le service.
- Mode panique : les serveurs DNS et de notification restent joignables pour tous les programmes (un malware
  pourrait s'en servir pour faire sortir des données) ; préférez un serveur ntfy auto-hébergé à ntfy.sh.
- La détection des voleurs de données repose sur l'identité du programme qui lit les fichiers : elle ne voit pas
  l'injection de code dans le navigateur. Le lancement d'un navigateur en débogage à distance
  (`--remote-debugging-port`, technique courante de vol de cookies) est en revanche signalé.
- Sur un poste géré (domaine, Intune), la baseline est en lecture seule ; si l'organisation n'active pas l'audit
  du système de fichiers, une pastille signale que le vol de données n'est pas surveillé.
- Les règles IDS utilisant `pcre`, `byte_test` et quelques autres options sont ignorées plutôt que mal appliquées.

### Feuille de route

1. ✅ Réglages, langue FR/EN, syslog, API d'export
2. ✅ Mini-SIEM local : stockage, recherche, chronologie, corrélation
3. ✅ Analyse du trafic, géolocalisation par pays (données publiques des RIR), carte du monde
4. ✅ NDR local : usurpation ARP, serveur DHCP pirate, empoisonnement LLMNR/NBNS/mDNS
5. ✅ DPI et IDS/IPS : SNI, DNS, empreintes JA3, règles compatibles Suricata

### Licence

[EUPL-1.2](LICENSE) (licence publique de l'Union européenne).

---

## English

### Why

deR4Tizer targets organisations with neither a SOC nor an EDR budget: small municipalities, micro-businesses, craftspeople, shops. Everything runs **on the endpoint**, with no account, no cloud and no telemetry. Critical alerts reach the IT provider or contact person (ntfy, Teams, e-mail) and can also go to the SIEM of your choice.

### Features (v4.3)

| Area | What deR4Tizer does |
|---|---|
| **Network** | Live outbound connections per program, suspicion score, beaconing detection, first Internet connection of a program |
| **Threat intelligence** | Open-source lists refreshed every 12 h, optional automatic firewall blocking |
| **Processes** | Process tree with cumulative chain score, obfuscated PowerShell, MITRE ATT&CK techniques |
| **Persistence** | Run keys, services, scheduled tasks, WMI, Startup folders: alert on any new or changed entry |
| **Ransomware** | Canary files, automatic suspension of the program touching them |
| **Data theft** | Access auditing on sensitive browser and application folders |
| **Privacy** | Camera, microphone, remote-control tools, open ports |
| **Firewall** | Rule-change tracking (with the authoring program), Internet exposure (inbound packets from public IPs) |
| **Hardening** | Baseline inspired by Intune and Microsoft, applied through local Group Policy, reversible |
| **Response** | Kill, suspend, network-isolate, quarantine, PANIC button (cuts Internet) |
| **Mini-SIEM** | Normalised events (logons, accounts, groups, processes, services, connections, firewall, alerts) kept 30 days, search, timeline, correlation incidents (brute force, logon after failures, new administrator, log cleared, suspicious service, weakened protection, multi-stage attack, access from the Internet) |
| **Traffic analysis** | Passive packet capture (Windows raw sockets, no driver): throughput, programs, destinations, ports and countries (regional Internet registries), live world map |
| **Local NDR** | Gateway ARP spoofing, new devices, rogue DHCP server, LLMNR/NBNS/mDNS poisoning (Responder) with an active decoy; also works behind a VPN |
| **DPI** | TLS site names (SNI) and JA3 fingerprints (SSLBL list), cleartext HTTP (credentials sent unencrypted), DNS (DNS tunnelling), SMB/Telnet/FTP to the Internet, names checked against threat lists |
| **IDS / IPS** | Suricata-format rules (subset: content, nocase, offset/depth/distance/within, flags, dsize…), built-in rules + `.rules` files (e.g. Emerging Threats Open); IPS mode blocks at the firewall |
| **Alert forwarding** | To the IT provider or contact person: ntfy, Microsoft Teams (workflow webhook, card with the "what to do"), encrypted SMTP e-mail; alert grouping, hourly cap, secrets restricted to administrators |
| **Integration** | Syslog RFC 5424 (UDP/TCP, JSON or CEF), read-only HTTP export API with token |
| **Privacy** | Data (events, sessions, alerts, devices) readable only by SYSTEM, administrators and authorised accounts; API token restricted to administrators; folder created with its permissions by the installer, owner and permissions enforced and checked at every start, files owned by anyone else ignored; if the check fails, settings and secrets are ignored and the interface shows it |
| **Less noise** | 7-day learning mode (behaviours remembered), "no longer alert for this behaviour" exceptions, "direct IP" criterion neutralised for known VPNs, messengers and games; critical alerts are never softened |
| **Updates** | Daily check; installation (off by default) only with a correct SHA-256 hash and a signature by one of the keys pinned in the binary, revocation checked, files kept in a SYSTEM-only folder, with rollback if the service stops answering |
| **Interface** | French / English |

### Architecture

```
deR4TizerSvc.exe   Rust Windows service, SYSTEM account (monitoring, response, export)
deR4Tizer.exe      C# interface (.NET Framework 4.8, ships with Windows), no admin rights
C:\ProgramData\deR4Tizer   shared state (JSON), log; readable by administrators and authorised accounts
\\.\pipe\deR4Tizer         interface → service commands (Administrators and SYSTEM only)
```

No kernel driver and nothing extra to install: only Windows APIs (ETW, Event Log, WMI, Firewall, IP Helper, WinVerifyTrust).

### Build

Requirements: Windows 10/11, Visual Studio Build Tools 2022 ("Desktop development with C++" workload), [rustup](https://rustup.rs) with the **stable-x86_64-pc-windows-msvc** toolchain, the same as the CI. Tests on a machine use the artifact built by the CI.

```powershell
rustup toolchain install stable-x86_64-pc-windows-msvc
.\compiler.ps1          # interface (Windows csc) + Rust service → bin\
```

### Install

Download `deR4Tizer.msi` from the [latest release](https://github.com/cryptobones-1337/deR4Tizer/releases/latest) and
open it. The service starts immediately; the interface is in the Start menu and starts at logon. New versions are reported;
automatic installation can be turned on in the settings (signed releases).

Fleet deployment (GPO, Intune, IT provider): `msiexec /i deR4Tizer.msi /qn` (`LANCEMENT_SESSION=0` to skip the logon
launch). Uninstall from "Apps" or with `msiexec /x deR4Tizer.msi /qn`: blocks, firewall rules and canaries are removed,
original security settings restored and data deleted (`GARDER_BASELINE=1`, `GARDER_DONNEES=1` keep them).
Repair (`msiexec /fa`) is restricted to administrators and hidden from "Apps": it stops and restarts the service.

### SIEM integration

**Syslog**: Settings → *Alert forwarding*. JSON format (RFC 5424 header, JSON detail) or CEF.

**Export API**: Settings → *Export API*. Listens on `127.0.0.1:8642` by default. Local-network access is optional (Domain and Private profiles only).

```bash
curl -H "Authorization: Bearer <token>" "http://127.0.0.1:8642/api/v1/alertes?niveau=Alerte&format=ndjson"
```

Routes are listed in the French section above (paths are identical).

### Roadmap

1. ✅ Settings, FR/EN language, syslog, export API
2. ✅ Local mini-SIEM: storage, search, timeline, correlation
3. ✅ Traffic analysis, per-country geolocation (public RIR data), world map
4. ✅ Local NDR: ARP spoofing, rogue DHCP server, LLMNR/NBNS/mDNS poisoning
5. ✅ DPI and IDS/IPS: SNI, DNS, JA3 fingerprints, Suricata-compatible rules

### License

[EUPL-1.2](LICENSE) (European Union Public Licence).

---

## Sources de renseignement / Threat-intelligence credits

Par défaut, seules les listes dont les conditions autorisent tout usage sont utilisées : Spamhaus DROP (citation, un
téléchargement par jour) et abuse.ch Feodo Tracker / SSLBL (usage équitable). Les autres (FireHOL niveau 1, qui agrège
DShield, ThreatView, Emerging Threats, CINS Army, IPsum, Phishing Army en CC BY-NC 4.0) sont non commerciales ou à
vérifier : elles ne s'activent que par un réglage explicite, pour un usage personnel. Chaque liste est téléchargée en
HTTPS, limitée à 100 Mo, rejetée si elle se vide ou s'effondre, et ignorée si elle couvrirait plus de 134 millions
d'adresses ; les réseaux privés, CGNAT, de lien local et multicast ne sont jamais signalés ni bloqués.

By default only lists whose terms allow any use are enabled (Spamhaus DROP, abuse.ch Feodo Tracker / SSLBL). The others
are non-commercial or unverified and must be enabled explicitly, for personal use. Lists are fetched over HTTPS only,
capped at 100 MB, rejected when empty or collapsing, and ignored when covering more than 134 million addresses; private,
CGNAT, link-local and multicast networks are never flagged or blocked.

Spamhaus DROP · FireHOL level 1 · abuse.ch Feodo Tracker et SSLBL (JA3) · ThreatView · Emerging Threats · CINS Army · IPsum · Phishing Army · LOLDrivers.
Géolocalisation / geolocation : statistiques « delegated » d'ARIN, RIPE NCC, APNIC, LACNIC et AFRINIC. Carte / map : Natural Earth 1:110m (domaine public / public domain).
Ces listes appartiennent à leurs auteurs et restent soumises à leurs propres conditions d'utilisation.
These lists belong to their authors and remain subject to their own terms of use.
