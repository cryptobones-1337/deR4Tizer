# Campagne Kali — second lot « détection réseau » (usurpation ARP, NBNS réel, responder passif)

Date : 2026-11-16. Suite du premier lot de la phase « détection réseau ». Ce lot éprouve les détections qui

> **Note du 2026-11-19** (audit documentaire ; les résultats ci-dessous ne sont pas réécrits) : Ces scénarios S-20 à S-27 ont été exécutés avant d'être inscrits dans la liste approuvée : ajoutés à la liste (version 1.5) le 2026-11-19 sur décision du mainteneur, approbation après coup (`campagne-kali-phase1.md`, §6). Aucun nombre d'essais n'est donné : mesures non consolidées. Le §2 conclut que l'absence d'alerte DHCP pirate « n'est pas un défaut » : le cinquième lot « détection réseau » mesure le contraire (serveur DHCP de l'interface lu vide sur une carte Hyper-V, détection inerte), corrigé par la PR #190 (2026-11-17) ; S-21 reste à remesurer, jamais mesuré positif.
exigeaient un **accès privilégié** sur la machine attaquante. Le root y est désormais disponible mais **strictement
borné** : trois **unités systemd figées et auditables** — un responder NBNS/LLMNR/mDNS (sans poisoner DHCP ni
WPAD), un `dnsmasq` en DHCP seul, et un `arpspoof` ciblé sur la seule adresse de la cible — pilotées par
`systemctl` sans mot de passe. Le mot de passe de la machine attaquante n'est **jamais saisi**. Lab isolé ;
adresses en plages de documentation (RFC 5737) ; noms de test en `.test` (RFC 2606) ; résultats bruts hors dépôt.
Aucune donnée personnelle, aucun nom de poste, aucun mot de passe.

## Contexte topologique (honnête)

Comme au premier lot, le harnais **réoriente la cible sur le segment du labo de façon réversible** (désactivation
des autres cartes, passerelle posée par `netsh`, relance du service), puis **restaure l'instantané** en fin
d'essai — aucune modification durable de la baseline. La topologie **mono-LAN** (une carte, une passerelle,
attaquant sur le même réseau) reste le cas réaliste d'un poste ordinaire. Chaque essai vérifie d'abord sa
**précondition de mesure** (règle D-2) avant de conclure : un essai dont la précondition n'est pas remplie est
**D (invalide)**, jamais un faux négatif.

## 1. Scénarios mesurés

| Scénario | Config A | Config C | Règle mesurée | Détail |
|---|---|---|---|---|
| **S-20** — usurpation ARP (homme du milieu) | **VP** | **VP** | `EXP-NDR-001` **Critique**, T1557.002 | la table de voisinage de la cible voit deux IP (une adresse bidon + la passerelle) sur la **même MAC** → « USURPATION ARP probable : la MAC de la passerelle est aussi annoncée par un autre appareil » |
| **S-25** — NBNS réel (jambe NBNS du leurre actif) | **VP** | **VP** | `EXP-NDR-001` **Critique**, T1557.001 | le responder root répond au leurre sur **NBNS (137)** *et* **LLMNR (5355)** → « EMPOISONNEMENT LLMNR/NBNS … a répondu pour le nom inexistant » |
| **S-23** — responder passif LLMNR (≥ 3 noms) | **VP** | **P-baseline** | `EXP-NDR-001` **Alerte**, T1557.001 | la cible interroge plusieurs noms, le responder répond à chacun → « répond en LLMNR pour ≥ 3 noms » ; **en C, la baseline désactive LLMNR côté client** → attaque **prévenue en amont** |

**S-20 (usurpation ARP).** Après réorientation, la passerelle de la cible est la machine attaquante. L'unité
`arpspoof` annonce une adresse bidon (`203.0.113.1`) à la **MAC de l'attaquant**. **Précondition D-2 vérifiée** :
le harnais confirme d'abord que `203.0.113.1` **et** la passerelle portent la **même MAC** dans la table de
voisinage de la cible (sinon : D). `analyser_arp` (cycle 10 s, via `GetIpNetTable2`) lève alors `EXP-NDR-001`
**Critique** « USURPATION ARP probable … le trafic peut être intercepté (homme du milieu) » (T1557.002). VP
identique en A et C (la détection est indépendante de la baseline).

**S-25 (NBNS réel).** Ce scénario **complète S-22** : au premier lot, le leurre n'avait été éprouvé que sur
**LLMNR** (répondeur Python sans root, port non privilégié). Avec le responder root (port 137 privilégié), le
leurre actif de deR4Tizer — question **LLMNR (224.0.0.252:5355) *et* NBNS (137)** pour un nom aléatoire inexistant
— reçoit une réponse **sur les deux protocoles** : `resultat_leurre = « RÉPONSE … 203.0.113.20 (LLMNR),
203.0.113.20 (NBNS) »`, et `EXP-NDR-001` **Critique** « EMPOISONNEMENT LLMNR/NBNS » (T1557.001). **VP en A et C** :
le leurre part **côté service** quelle que soit la politique LLMNR du client — à la différence du responder passif
ci-dessous. Le leurre actif reste le **signal le plus sûr** du NDR.

**S-23 (responder passif LLMNR).** La cible émet 6 requêtes LLMNR de noms distincts ; le responder répond à
chacune ; la capture voit ≥ 3 réponses distinctes du même hôte → `EXP-NDR-001` **Alerte** « répond en LLMNR pour
≥ 3 noms » (T1557.001). **VP en A.** **En C : P-baseline (prévention)** — la baseline renforcée **désactive LLMNR
côté client** (`EnableMulticast(Policy) = 0`, vérifié dans la VM) : la cible n'émet plus de requêtes LLMNR, donc
l'empoisonnement passif est **prévenu en amont**. Ce n'est pas un défaut de détection : c'est la défense en
profondeur qui joue (et le **leurre actif**, lui, continue de veiller même en C — cf. S-25). Détection passive
(`Alerte`) et défense active (`Critique` par le leurre) sont complémentaires.

## 2. Constat produit — DHCP pirate (S-21) non mesurable en l'état (revue de code)

Le scénario **DHCP pirate** (S-21) **n'est pas mesuré** dans ce lot, pour une raison de conception et non de
privilège. Dans `ndr.rs`, un serveur DHCP observé est jugé pirate si `serveur != dhcp_interface`, avec
`legitime = dhcp_interface.is_empty() || dhcp_interface == serveur`. Or, après réorientation, la cible est en **IP
statique** → `dhcp_interface` est **vide** → **tout** serveur DHCP est jugé légitime, aucune alerte. Et si la cible
passe en DHCP avec l'attaquant pour **seul** serveur, elle prend son bail de l'attaquant → `dhcp_interface ==`
attaquant → légitime aussi. **Ce n'est pas un défaut** : on ne peut pas qualifier de « pirate » le **seul** serveur
DHCP présent. Un VP fidèle exige un **serveur légitime *et* un pirate** sur le segment (deux serveurs), montage à
préparer. La logique de détection (lecture de l'**option 54**, table bornée ≤ 50 serveurs) est, elle, correcte en
revue.

## 3. Limites assumées

- **S-21 (DHCP pirate)** : en attente du montage à deux serveurs DHCP (légitime + pirate) sur le segment labo.
- **IDS directionnel / contenu** : les règles IDS dépendant de `$HOME_NET`/`$EXTERNAL_NET` supposent un adressage
  **RFC 1918** ; le labo est en **RFC 5737** (hors `$HOME_NET`), donc ces règles ne sont pas exerçables tel quel.
  Jambe suivante : rejouer en adressage RFC 1918, ou éprouver des règles non directionnelles.
- **Durcissement du code** (fuzzing des décodeurs ARP/DHCP/LLMNR/NBNS, revue des `unsafe`, corroboration anti-FP)
  reste le **chemin privilégié** vers la bascule « pris en charge » — sous **audit sécurité obligatoire** (chemin
  privilégié), hors de ce lot de validation.

## 4. Bilan

Avec ce lot, la couverture **LLMNR + NBNS + ARP** est complète : leurre actif (LLMNR **et** NBNS, Critique, A+C),
responder passif (Alerte, A ; prévenu en C), usurpation ARP (Critique, A+C). Restent le DHCP pirate (montage à
deux serveurs) et l'IDS directionnel (adressage RFC 1918).
