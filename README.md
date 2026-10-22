# deR4Tizer

**Protection locale pour Windows : détection type EDR, mini-SIEM et durcissement, sans cloud.**
*Local protection for Windows: EDR-style detection, mini-SIEM and hardening, no cloud.*

[Français](#français) · [English](#english)

> ⚠️ **Preuve de concept / Proof of concept.** Projet en développement actif, non audité. Ne remplace pas un antivirus ni un EDR commercial.
> Under active development, not audited. Does not replace an antivirus or a commercial EDR.

---

## Français

### Pourquoi

deR4Tizer s'adresse aux structures qui n'ont ni SOC ni budget EDR : petites communes, TPE, artisans, commerces. Tout tourne **sur le poste**, sans compte, sans cloud et sans télémétrie. Les alertes peuvent être envoyées au SIEM de votre choix.

### Fonctionnalités (v4.0)

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
| **Intégration** | Syslog RFC 5424 (UDP/TCP, JSON ou CEF), API HTTP d'export en lecture seule avec jeton |
| **Confidentialité** | Données (événements, sessions, alertes, appareils) lisibles seulement par SYSTEM, les administrateurs et les comptes autorisés ; jeton de l'API réservé aux administrateurs |
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

Prérequis : Windows 10/11, [rustup](https://rustup.rs) avec la chaîne **stable-x86_64-pc-windows-gnu**.

```powershell
rustup toolchain install stable-x86_64-pc-windows-gnu
.\compiler.ps1          # interface (csc de Windows) + service Rust → bin\
```

### Installer, mettre à jour, désinstaller

```powershell
.\installer.ps1         # en administrateur
.\mettre-a-jour.ps1     # demande l'UAC si besoin
.\desinstaller.ps1      # -GarderBaseline pour conserver les réglages de sécurité
```

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

### Limites connues

- Un PC sur un réseau commuté ne voit que son propre trafic, le broadcast et le multicast : ce n'est pas un NDR de tout le réseau (il faudrait un port miroir).
- Capture IPv4 seulement pour l'instant ; le pays est celui du titulaire du bloc d'adresses (un CDN peut apparaître aux États-Unis).
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

deR4Tizer targets organisations with neither a SOC nor an EDR budget: small municipalities, micro-businesses, craftspeople, shops. Everything runs **on the endpoint**, with no account, no cloud and no telemetry. Alerts can be forwarded to the SIEM of your choice.

### Features (v4.0)

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
| **Integration** | Syslog RFC 5424 (UDP/TCP, JSON or CEF), read-only HTTP export API with token |
| **Privacy** | Data (events, sessions, alerts, devices) readable only by SYSTEM, administrators and authorised accounts; API token restricted to administrators |
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

Requirements: Windows 10/11, [rustup](https://rustup.rs) with the **stable-x86_64-pc-windows-gnu** toolchain.

```powershell
rustup toolchain install stable-x86_64-pc-windows-gnu
.\compiler.ps1          # interface (Windows csc) + Rust service → bin\
```

### Install, update, uninstall

```powershell
.\installer.ps1         # as administrator
.\mettre-a-jour.ps1     # asks for UAC if needed
.\desinstaller.ps1      # -GarderBaseline keeps the security settings
```

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

Spamhaus DROP · FireHOL level 1 · abuse.ch Feodo Tracker et SSLBL (JA3) · ThreatView · Emerging Threats · CINS Army · IPsum · Phishing Army · LOLDrivers.
Géolocalisation / geolocation : statistiques « delegated » d'ARIN, RIPE NCC, APNIC, LACNIC et AFRINIC. Carte / map : Natural Earth 1:110m (domaine public / public domain).
Ces listes appartiennent à leurs auteurs et restent soumises à leurs propres conditions d'utilisation.
These lists belong to their authors and remain subject to their own terms of use.
