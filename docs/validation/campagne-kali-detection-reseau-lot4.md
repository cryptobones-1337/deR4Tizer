# Campagne Kali — quatrième lot « détection réseau » (redirection UPnP)

Date : 2026-11-16. Ce lot mesure la détection des **redirections de ports UPnP** (`EXP-NDR-001`, T1133 : le PC
rendu joignable depuis Internet). Lab isolé ; résultats bruts hors dépôt ; aucune donnée personnelle, aucun nom de
poste, aucun mot de passe.

## Pourquoi un ré-adressage RFC 1918 (honnête)

Le module UPnP n'interroge que des adresses **privées** : le garde `locale()` de `upnp.rs` vaut
`is_private() || is_link_local()`. Les instantanés de campagne utilisent des adresses de documentation (RFC 5737,
`203.0.113.0/24`), que ce garde **rejette** — à raison (protection contre une requête vers Internet). Pour éprouver
la détection, le harnais **ré-adresse le segment labo en RFC 1918 de façon réversible** : la machine attaquante
ajoute une IP secondaire `192.168.50.20` (via `nmcli`, sans mot de passe), la cible est réorientée en
`192.168.50.10` (via `netsh`) ; l'instantané **annule tout** en fin d'essai (l'IP secondaire est aussi retirée).
Aucune modification durable. L'IGD est **émulé en espace utilisateur, sans root** (SSDP sur le port 1900 non
privilégié + un serveur HTTP sur un port haut).

## 1. Scénario mesuré

| Scénario | Config A | Config C | Règle mesurée | Détail |
|---|---|---|---|---|
| **S-27** — redirection UPnP vers ce PC | **VP** | **VP** | `EXP-NDR-001` **Alerte**, T1133 | l'IGD émulé répond au M-SEARCH et annonce une redirection du port 3389/TCP **vers la cible** → « la box ouvre le port 3389 (TCP) d'Internet vers ce PC » |

**S-27 (UPnP).** À la première itération après démarrage (comme le leurre), `verifier_upnp` émet un M-SEARCH SSDP ;
l'IGD émulé renvoie une `LOCATION`, deR4Tizer récupère la description, trouve le service `WANIPConnection`, puis
lit les redirections en SOAP (`GetGenericPortMappingEntry`). La première redirection désigne la cible
(`NewInternalClient = 192.168.50.10`, `NewExternalPort = 3389`, actif) ; comme `client == locale`, deR4Tizer lève
`EXP-NDR-001` **Alerte** « le PC est joignable depuis Internet sur ce port » (T1133). Le champ d'état confirme la
découverte : « 1 redirection(s) sur la box, dont 1 vers ce PC ». **VP en A et C** : la vérification est **active**
(pilotée par le service), indépendante de la configuration de la baseline. **Précondition D-2** vérifiée : sans
découverte d'IGD (champ `Upnp`), l'essai serait D, jamais un faux négatif.

## 2. Limites assumées

- **DHCP pirate (S-21)** : nécessite un **serveur légitime + un pirate** sur le segment (dossier de montage
  préparé, décision en attente).
- **IDS directionnel** : les règles `$HOME_NET`/`$EXTERNAL_NET` supposent un côté **privé** (victime) et un côté
  **public** (Internet) ; or, sur un seul segment L2, on ne peut pas placer à la fois une source publique et une
  destination privée mutuellement joignables sans routeur/NAT. À éprouver avec une topologie étendue (routeur labo).
- **Durcissement du code** (fuzzing des décodeurs, revue des `unsafe`, corroboration anti-FP) : chemin privilégié,
  sous audit sécurité, nécessite de compiler (dossier préparé, décision CI/exception en attente).

## 3. Bilan de la phase « détection réseau »

Détections **mesurées en VP** (configurations A et C sauf indication) : leurre actif LLMNR (S-22, Critique),
leurre actif NBNS (S-25, Critique), usurpation ARP (S-20, Critique), responder passif LLMNR (S-23, Alerte, VP A /
P-baseline C), responder passif mDNS (S-26, Alerte), **redirection UPnP (S-27, Alerte, T1133)**, et la signature
IDS de test (S-24). La couverture NDR accessible par émulation en espace utilisateur est **complète**. Restent le
DHCP pirate et l'IDS directionnel (contraintes d'infrastructure documentées), et le durcissement du code (audit).
