# Validation de deR4Tizer (campagne Kali, boucle continue)

Ce dossier documente la campagne de validation de fin de phase 7 et la boucle continue qui la suit (CLAUDE.md,
section 5, campagne Kali).

| Document | Contenu |
|---|---|
| [campagne-kali-phase1.md](campagne-kali-phase1.md) | Audit initial des capacités, cartographie ATT&CK, liste fermée de scénarios (version 1.4, approuvée par l'agent de validation le 2026-11-15) |
| [campagne-kali-premier-passage.md](campagne-kali-premier-passage.md) | Résultats du premier passage (liste v1.3) : chaîne de mesure validée, force brute RDP/SMB, persistance, corrélations système, et le constat produit sur la corrélation R3 |
| [campagne-kali-second-lot.md](campagne-kali-second-lot.md) | Résultats du second lot (liste v1.4) : vol d'identifiants (VOL-001) et listes de menaces (DNS-001, RES-001 + blocage automatique 7 jours), en configurations A et C |
| [campagne-kali-troisieme-lot.md](campagne-kali-troisieme-lot.md) | Résultats du troisième lot (liste v1.4) : détection du changement de serveur DNS sur une carte (DNS-002), en configurations A et C — la **jambe DNS-002 de S-06** (la jambe filtrage de S-06 et DNS-003/S-18 restent à exécuter) |
| [campagne-kali-quatrieme-lot.md](campagne-kali-quatrieme-lot.md) | Résultats du quatrième lot (liste v1.4) : **jambe filtrage de S-06** (un nom listé bloqué en adresse nulle), en configurations A et C — S-06 est couvert en entier ; et pourquoi **DNS-003 (S-18)** n'est pas mesurable de bout en bout en laboratoire |
| [campagne-kali-cinquieme-lot.md](campagne-kali-cinquieme-lot.md) | Résultats du cinquième lot (liste v1.4) : **lot 3d Defender formel** (le produit installé n'est pas détecté par un Defender pleinement actif, configurations A et C, binaire non encore signé) et **sessions standard** (spécificité : N-01 et N-02 sans alerte forte ; N-05 déjà couvert) |
| [campagne-kali-sixieme-lot.md](campagne-kali-sixieme-lot.md) | Résultats du sixième lot (liste v1.4) : scénarios restants — sessions et corrélations (S-17 session admin distante, S-04 tube IPC, S-02 force brute RDP + réussite), réseau (S-11 C2 HTTP, S-12 exfiltration, S-08 balayage), exécution et simulations (S-10 PowerShell encodé, S-15 LSASS, S-16 leurre), présence de l'interface (S-05 SAN-010) ; deux constats produits (COR-R9 par RDP en Alerte ; PRC-002 non déterministe sans Sysmon) |
| [campagne-kali-detection-reseau-lot1.md](campagne-kali-detection-reseau-lot1.md) | Premier lot de la phase « détection réseau » (NDR/IDS dégelés) : S-22 leurre LLMNR actif (EXP-NDR-001 Critique, T1557.001) et S-24 signature IDS de test (EXP-IDS-001, sid 9000000), VP en configurations A et C, **sans root** ; deux constats produits (leurre désarmé 600 s sur échec de bind ; injection de faux positifs DHCP/Responder) ; limites assumées (plafond root pour ARP/DHCP/NBNS ; règles IDS directionnelles) |
| [campagne-kali-detection-reseau-lot2.md](campagne-kali-detection-reseau-lot2.md) | Second lot de la phase « détection réseau » : **S-20 usurpation ARP** (EXP-NDR-001 Critique, T1557.002) et **S-25 NBNS réel** (jambe NBNS du leurre actif, EXP-NDR-001 Critique, T1557.001), VP en configurations A et C ; **S-23 responder passif LLMNR** (Alerte, T1557.001) VP en A, P-baseline en C (la baseline désactive LLMNR côté client) ; root borné par unités systemd auditables ; un constat produit (DHCP pirate S-21 non mesurable sans montage à deux serveurs) ; limites (IDS directionnel en RFC 1918) |
| [campagne-kali-detection-reseau-lot3.md](campagne-kali-detection-reseau-lot3.md) | Troisième lot de la phase « détection réseau » : **S-26 responder passif mDNS** (EXP-NDR-001 Alerte, T1557.001, seuil 15 noms), VP en configurations A et C ; ferme la couverture responder passif (LLMNR S-23 + NBNS S-25 + mDNS) ; note d’honnêteté (émission mDNS brute → éprouve le détecteur, pas la posture client) ; restent DHCP pirate, UPnP et IDS directionnel, qui exigent un ré-adressage RFC 1918 |
| [campagne-kali-detection-reseau-lot4.md](campagne-kali-detection-reseau-lot4.md) | Quatrième lot de la phase « détection réseau » : **S-27 redirection UPnP vers ce PC** (EXP-NDR-001 Alerte, T1133), VP en configurations A et C ; IGD émulé en espace utilisateur (SANS root), labo ré-adressé en RFC 1918 de façon réversible (le garde `locale()` de upnp.rs n’accepte que les adresses privées) ; bilan de la phase ; restent DHCP pirate, IDS directionnel et durcissement du code |
| [campagne-kali-detection-reseau-lot5.md](campagne-kali-detection-reseau-lot5.md) | Cinquième lot de la phase « détection réseau » : **durcissement volet 1 — fuzzing des décodeurs** (`nom_dns`/`nom_nbns`/`decoder`, ~151 M d’appels, **0 panique**) ; **S-21 serveur DHCP pirate** : **constat de limite mesuré** — la détection ne s’arme pas car `dhcp_interface` reste vide (le service lit le serveur DHCP via `GetAdaptersInfo`, vide sur carte Hyper-V alors que l’OS a le serveur) → durcissement identifié : `GetAdaptersAddresses` (`Dhcpv4Server`) ; caveat option 54 forgeable conservé |

## À savoir

- Les scénarios sont décrits au niveau du comportement : technique ATT&CK, simulation ou émulation, préconditions,
  résultat attendu, délai maximal, nettoyage, preuves. Aucune commande offensive détaillée.
- Les classes a priori (A à E) de la cartographie sont des **hypothèses**, pas des résultats mesurés.
- L'approbation de la liste est celle de l'agent de validation : elle n'est **ni humaine ni indépendante**. Chaque
  version approuvée est transmise au mainteneur avant exécution.
- Un scénario est publié ici avant sa première exécution ; chaque rapport de campagne, ajouté à ce dossier, note la
  version de la liste exécutée.
- Premier passage publié le 2026-11-15 (liste v1.3) : voir
  [campagne-kali-premier-passage.md](campagne-kali-premier-passage.md). Les résultats bruts restent hors dépôt.
