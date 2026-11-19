# Campagne Kali — cinquième lot « détection réseau » : durcissement (fuzzing des décodeurs) + DHCP pirate

Date : 2026-11-17. Ce lot couvre deux choses : (1) le **durcissement volet 1** — fuzzing des décodeurs de paquets,

> **Note du 2026-11-19** (audit documentaire ; les résultats ci-dessous ne sont pas réécrits) : Ces scénarios S-20 à S-27 ont été exécutés avant d'être inscrits dans la liste approuvée : ajoutés à la liste (version 1.5) le 2026-11-19 sur décision du mainteneur, approbation après coup (`campagne-kali-phase1.md`, §6). Aucun nombre d'essais n'est donné : mesures non consolidées. Le « durcissement proposé » et le « correctif identifié » du §2 et du §3 sont faits : PR #190, fusionnée le 2026-11-17 ; S-21 reste à remesurer.
et (2) le scénario **S-21 (serveur DHCP pirate)**, qui aboutit à un **constat de limite mesuré** et à une piste de
durcissement. Lab isolé ; résultats bruts hors dépôt ; aucune donnée personnelle, aucun nom de poste, aucun mot de
passe.

## 1. Durcissement des décodeurs — fuzzing (volet privilégié)

Trois fonctions parsent des octets **entièrement contrôlés par l'attaquant** sur le réseau : `nom_dns` et `nom_nbns`
(`ndr.rs`), et `decoder` (`capture.rs`, en-têtes IPv4/TCP/UDP). Une panique dans le fil de capture tuerait la
surveillance réseau : le critère est **zéro panique**, et le décodeur doit **toujours renvoyer `None`** sur entrée
malformée.

**Méthode.** Les trois fonctions ont été extraites **verbatim** (copie à l'identique, mêmes gardes) dans un harnais
std pur, sans aucune dépendance ni API Windows : toute panique du harnais serait une panique du décodeur réel.
Compilation locale **ciblée sur les seuls décodeurs** (pas le service), profil optimisé avec les **contrôles de
débordement arithmétique et de tranche activés**. Pilote : exhaustif court (toutes les longueurs 0 à 80, variantes
multiples), aléatoire biaisé (longueurs 0 à 1500, octets « intéressants » surreprésentés), puis **graines
semi-valides** (DNS/LLMNR, NBNS, DHCP, IPv4+UDP, IPv4+TCP) **mutées** (retournement de bits, troncature, extension).
Chaque appel sous capture de panique.

**Résultat.** **50 324 000 appels par fonction (~151 millions au total), 0 panique.** Les trois décodeurs renvoient
`None` sur entrée malformée sans jamais paniquer : un paquet forgé ne peut pas tuer le fil de capture (sur cette
campagne). La revue manuelle concorde : chaque accès de tranche est gardé (p. ex. `p + 1 + l > m.len()` pour les
labels DNS ; `m.len() < 46` et `m[12] != 32` pour NBNS ; `ihl`/`total` bornés pour l'en-tête IP), l'arithmétique est
en `wrapping`/`usize`, et `from_utf8_lossy`/`to_lowercase` ne paniquent pas. Le corpus de graines mutées est conservé
comme base de non-régression.

## 2. S-21 — serveur DHCP pirate : constat de limite mesuré

**Montage** (deux serveurs du point de vue de la cible, car la règle `legitime = dhcp_interface.is_empty() ||
dhcp_interface == serveur` n'alerte que sur un serveur **différent** de celui de l'interface). **Légitime** : un
serveur DHCP du labo (RFC 5737, `203.0.113.20`, plage `.100-.200`) donne un bail à la cible. **Pirate** : un
injecteur émet des `OFFER` non sollicités portant l'**option 54 = `203.0.113.50`** (identifiant de serveur étranger),
en paquets bruts. Attendu : `serveur = .50 ≠ dhcp_interface = .20` → Critique « SERVEUR DHCP PIRATE » (T1557.003).

**Résultat mesuré : la détection ne s'arme pas sur cette cible.** La cible obtient un bail correct (`203.0.113.180`,
passerelle `.20`, et côté Windows **`DHCP Server = 203.0.113.20`, `DHCPEnabled = True`** — confirmé par CIM et
`ipconfig /all`). Mais le champ `dhcp_interface` que publie le service **reste vide**, y compris après un bail
**acquis au redémarrage** (voie normale, pas seulement un renouvellement forcé). Un dump complet montre que
`interface`, `passerelle` et `masque` sont **tous** renseignés — seul `dhcp_interface` est vide.

**Cause racine.** Le service lit le serveur DHCP via **`GetAdaptersInfo`** (API héritée, dépréciée par Microsoft) :
`dhcp = if DhcpEnabled != 0 { texte_ip(&DhcpServer) } else { "" }`. Sur la carte réseau synthétique de la VM, ce
champ revient **vide** alors que l'OS connaît parfaitement le serveur. Tous les autres champs de la **même**
structure (passerelle, masque) passent : le point faible est précisément la lecture du serveur DHCP.

**Conséquence (sécurité).** Quand `dhcp_interface` est vide, `legitime = is_empty() || …` est **toujours vrai** : la
détection de serveur DHCP pirate (`EXP-NDR-001`, T1557.003) est alors **inerte**. Portée du constat : mesuré sur
cible Hyper-V ; non vérifiable sur matériel physique depuis le labo (VM seulement).

**Durcissement proposé (suivi, code privilégié → audit + passage compilé).** Lire le serveur DHCP via
**`GetAdaptersAddresses` (`Dhcpv4Server`)**, fiable et non déprécié, au lieu de `GetAdaptersInfo.DhcpServer`. Après
ce correctif, S-21 redevient mesurable. Le **caveat d'honnêteté** est conservé pour ce moment-là : l'option 54 étant
contrôlée par l'attaquant, un `OFFER` forgé peut désigner une IP **bénigne** → la règle repère un serveur
**distinct**, elle ne distingue pas un vrai pirate d'une usurpation visant un innocent.

## 3. Bilan et limites

- **Décodeurs** : panic-free sur ~151 M de cas (volet 1 du durcissement : acquis).
- **S-21 DHCP pirate** : **constat de limite** — la détection ne s'arme pas tant que la source du serveur DHCP reste
  `GetAdaptersInfo`. Correctif identifié (`GetAdaptersAddresses`), à porter en code puis à remesurer.
- **IDS directionnel** : hors de portée du labo actuel (il faut une source publique et une destination privée
  mutuellement joignables, donc un routeur/NAT), laissé documenté.
- **Revue des blocs `unsafe`** et **corroboration anti-faux-positifs** : rédigées (volets 2 et 3 du durcissement),
  à instruire avec le correctif ci-dessus.

Lab isolé, résultats bruts hors dépôt. Aucune donnée personnelle.
