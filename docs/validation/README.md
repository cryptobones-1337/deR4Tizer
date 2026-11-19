# Validation de deR4Tizer (campagne Kali, boucle continue)

Ce dossier documente la campagne de validation de fin de phase 7 et la boucle continue qui la suit (CLAUDE.md,
section 5, campagne Kali).

| Document | Contenu |
|---|---|
| [campagne-kali-phase1.md](campagne-kali-phase1.md) | Audit initial des capacités, cartographie ATT&CK, liste fermée de scénarios (version 1.4, approuvée par l'agent de validation le 2026-11-15 ; version 1.5, S-20 à S-27 ajoutés le 2026-11-19 sur décision du mainteneur, après leur exécution) |
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

## État au 2026-11-19 (audit documentaire)

- **Versions de liste** : premier passage, liste v1.3 ; lots 2 à 6, liste v1.4 ; cinq lots « détection réseau »,
  scénarios S-20 à S-27, inscrits dans la liste v1.5 après leur exécution (approbation après coup, décision du
  mainteneur du 2026-11-19).
- **Scénarios v1.4 encore sans résultat** : N-03, N-04, S-18 (non reproductible de bout en bout en labo), S-05 (a)
  Bureau à distance et (b) bascule rapide d'utilisateur, S-10 (b), S-11 (b) et (c), l'option longue de S-16,
  « Débloquer » de S-07, le volet réussite de S-03 ; S-21 (v1.5) à remesurer après la PR #190.
- **Écarts aux règles de mesure (`CLAUDE.md`)** :
  - nombre d'essais : seul S-01 en configuration A a 10 essais (S-10 : 2) ; toutes les autres mesures sont des essais
    isolés, donc **non consolidées**, même là où un rapport écrit « couverture » ou « acquis » ;
  - délais : les verdicts VP sont rendus sans le délai maximal que la liste exige, et les latences ne sont dans aucun
    rapport (horloge de la VM décalée dans les résultats bruts) ;
  - versions de Sysmon, d'Atomic Red Team et de Windows : absentes des rapports ;
  - vocabulaire hors des classes A à E : « RÉUSSI » (témoin négatif sans alerte forte), « P-baseline » et
    « P-Defender » (attaque prévenue en amont, classe P de la liste v1.3), « GAP (C/E) » (aucune règle), « B2 »
    (classe B en configuration B), « D/limite » (essai invalide, classe D) ;
  - S-14 et les volets simulés de S-13 sont des simulations, non marqués SIMULATION dans le premier passage.
- **Techniques ATT&CK : le code fait foi** : DNS-002 ne porte aucune technique dans le code (les rapports qui écrivent
  T1557 le font de leur propre chef ; la liste v1.4 dit « sans correspondance exacte ») ; VOL-001 porte « T1555 / T1539 »
  (la liste écrit T1555.003) ; COR-R1 et COR-R2 portent T1110 (la liste écrit T1110.001) ; niveaux et techniques
  d'EXP-NDR-001 et EXP-IDS-001 dans `docs/detection/regles.md`.
- **Couverture « responder passif »** : LLMNR (S-23) et mDNS (S-26) exercés ; NBNS passif non exercé (S-25 est la
  jambe NBNS du leurre actif).
- **Constats ouverts, non corrigés** : COR-R3 (rapprochement par nom au lieu du SID) ; COR-R9 par Bureau à distance en
  Alerte ; PRC-002 non déterministe sans Sysmon ; leurre actif sauté 10 minutes après un échec de `bind` ; injection de
  faux positifs DHCP et responder passif. Corrigé : DHCP pirate inerte (PR #190, S-21 à remesurer).
