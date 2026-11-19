# Campagne Kali — premier lot « détection réseau » (NDR / IDS dégelés)

Date : 2026-11-16. La phase « détection réseau » a été **ouverte par le mainteneur** (dégel du 2026-11-16) :

> **Note du 2026-11-19** (audit documentaire ; les résultats ci-dessous ne sont pas réécrits) : Ces scénarios S-20 à S-27 ont été exécutés avant d'être inscrits dans la liste approuvée : ajoutés à la liste (version 1.5) le 2026-11-19 sur décision du mainteneur, approbation après coup (`campagne-kali-phase1.md`, §6). Aucun nombre d'essais n'est donné : mesures non consolidées. Les constats du §2 (leurre actif sauté 10 minutes après un échec de `bind`, injection de faux positifs) ne sont pas corrigés au 2026-11-19.
le NDR local (`ndr.rs`, `EXP-NDR-001`) et l'IDS (`ids.rs`, `EXP-IDS-001`), jusque-là expérimentaux et gelés,
entrent en validation. Ce premier lot éprouve les détections accessibles **sans privilège root** sur la machine
attaquante. Lab isolé ; adresses en plages de documentation (RFC 5737) ; noms de test en `.test` (RFC 2606) ;
résultats bruts hors dépôt. Aucune donnée personnelle, aucun nom de poste, aucun mot de passe.

## Contexte topologique (honnête)

La VM cible a **deux cartes** ; le service surveille, via `adresse_lan()`/`adresse_locale()`, la carte **qui
porte une passerelle** (réseau hôte), pas le segment de la machine attaquante. Pour éprouver la détection sur le
segment de l'attaquant, le harnais **réoriente la cible sur le segment du labo de façon réversible** : il
désactive les autres cartes, pose une passerelle sur la carte du labo (`netsh`), relance le service, puis
**restaure l'instantané** en fin d'essai (aucune modification durable de la baseline). Cette topologie **mono-LAN**
(une carte, une passerelle, attaquant sur le même réseau) est le **cas réaliste d'un poste ordinaire** ; la
double-carte des instantanés de campagne est un artefact de labo. La machine attaquante n'utilise **aucun droit
root** : un répondeur LLMNR et un émetteur UDP en espace utilisateur (ports non privilégiés), en Python.

## 1. Scénarios mesurés

| Scénario | Config A | Config C | Règle mesurée | Détail |
|---|---|---|---|---|
| **S-22** — leurre LLMNR actif (empoisonneur de type Responder) | **VP** | **VP** | `EXP-NDR-001` **Critique**, T1557.001 | un répondeur LLMNR **sans root** sur le segment labo répond à la sonde du leurre → « EMPOISONNEMENT LLMNR/NBNS … a répondu pour le nom inexistant » |
| **S-24** — signature IDS (règle de test intégrée) | **VP** | **VP** | `EXP-IDS-001`, sid 9000000 | 3 datagrammes UDP porteurs du motif de test capturés → chaîne **capture (`SIO_RCVALL`) → IDS → alerte** |

**S-22 (leurre LLMNR).** Au démarrage du service, le NDR émet une question LLMNR pour un **nom aléatoire
inexistant** ; le répondeur du labo y répond (réponse de 30 octets reçue côté attaquant), ce qui déclenche
`EXP-NDR-001` **Critique** (`EMPOISONNEMENT LLMNR/NBNS … "srv-26dada1d" (A) / "srv-f5d3a5d6" (C)`, T1557.001).
Le leurre actif est le **signal le plus sûr** du NDR (aucun faux positif plausible : seul un vrai empoisonneur
répond au nom inexistant). Le volet **responder passif** (≥ 3 noms distincts en 10 min) n'a pas été exercé (une
seule sonde) : jambe suivante.

**S-24 (IDS).** La machine attaquante envoie trois datagrammes UDP contenant le motif de la **règle de test
intégrée** (sid 9000000, `deR4Tizer-test-IDS-7f3a`, priorité 3 → Info). deR4Tizer les capture (socket brute
`SIO_RCVALL`, indépendante de tout pilote) et produit la détection `EXP-IDS-001` (15 règles chargées, 0 ignorée).
Cela valide **toute la chaîne capture → analyse Aho-Corasick → règle → alerte** sur le segment du labo, **sans
root ni risque Defender** (charge bénigne).

## 2. Constats produits (à transmettre au mainteneur)

1. **Leurre actif désarmé 600 s sur échec de `bind`.** Dans `ndr.rs` `demarrer()`, `leurre_fait` et
   `dernier_leurre` sont mis à jour **inconditionnellement après** l'appel à `leurre()`, alors que `leurre()`
   sort tôt si `UdpSocket::bind(locale)` échoue. Donc si l'interface est **transitoirement indisponible** à la
   première itération du NDR (démarrage lent, sortie de veille, reconnexion VPN, changement de réseau), le leurre
   est **silencieusement sauté pendant 10 minutes**. *(Découvert en mesurant : le premier essai S-22 a été D/limite
   pour cette raison ; stabiliser l'interface avant l'armement a donné le VP.)* Candidat correctif : ne passer
   `leurre_fait = true` que si le leurre a réellement tourné, ou réessayer plus tôt après un échec.
2. **Injection de faux positifs (revue de code, à mesurer quand le root sera disponible).** Deux détections
   passives reposent sur une **source usurpable** : le **DHCP pirate** identifie le serveur par l'**option 54
   contrôlée par l'attaquant** (un paquet forgé peut désigner une IP bénigne ≠ serveur de l'interface → fausse
   Critique visant un innocent) ; le **responder passif** LLMNR/NBNS/mDNS peut **cadrer une machine victime** par
   usurpation de source. Le **leurre actif** n'est pas injectable de la sorte. Candidat : corroborer avant de
   lever une Critique, et porter le niveau fort par le leurre.

## 3. Limites assumées

- **Plafond root.** `arpspoof` (ARP, S-20), `dnsmasq` en mode DHCP (serveur pirate, S-21) et le NBNS réel
  (port 137) exigent **root** sur la machine attaquante (seuls `systemctl`/`nmcli`/`apt` y sont sans mot de passe,
  jamais saisi). Ces scénarios **ne sont pas mesurés dans ce lot** : en attente d'une décision d'infrastructure.
- **Règles IDS directionnelles et signatures de contenu.** Les règles `$EXTERNAL_NET → $HOME_NET` et les
  signatures de contenu (EICAR…) exigent un **adressage RFC 1918** (le labo est en RFC 5737, donc hors
  `$HOME_NET`) et une **méthode sans déclencher Defender** ; cadrées pour une jambe suivante. Ce lot valide le
  moteur via la règle de test `any any`.
- **Responder passif** (≥ 3 noms) : non exercé (une seule sonde de leurre) ; jambe suivante.
- **Artefacts d'exposition labo (décision D-1).** En config C (journalisation du pare-feu active), le NBNS du
  leurre (port 137) lève une Critique « PC EXPOSÉ À INTERNET » parce que `203.0.113.x` est hors RFC 1918 →
  **artefact d'adressage RFC 5737**, exclu des VP/FP.
- **Harnais.** Réorientation **réversible** (annulée par l'instantané), mono-LAN délibéré. La capture suit la
  **route par défaut** (fiable après pose d'une passerelle de métrique 1 sur la carte labo) ; le NDR
  (`adresse_lan`, choix par énumération des cartes) reste à surveiller.

## 4. Méthode

Instantanés « campagne A » (sans baseline) et « campagne C » (baseline renforcée), 2026-11-14. Réorientation
réversible, répondeur/émetteur **sans root** (Python, ports non privilégiés), remise à l'instantané **avant et
après** chaque essai, VM remise en veille à la fin. Defender **jamais** modifié à la main. VM unique ⇒ essais
**strictement en série**. Décision D-1 (artefacts d'exposition de labo exclus des VP/FP) appliquée. Jamais le mot
de passe de la machine attaquante (accès par clé SSH). Programmes de test bénins (une chaîne de signature, une
réponse LLMNR), réversibles, aucune charge hostile, aucune infrastructure réelle contactée.
