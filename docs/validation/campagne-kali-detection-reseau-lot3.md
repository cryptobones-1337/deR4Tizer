# Campagne Kali — troisième lot « détection réseau » (responder passif mDNS)

Date : 2026-11-16. Ce lot ferme la couverture **responder passif** en ajoutant le volet **mDNS**, après LLMNR
(S-23, deuxième lot) et la jambe NBNS du leurre actif (S-25). Lab isolé ; adresses en plages de documentation
(RFC 5737) ; noms de test en `.test` / `.local` (RFC 2606, RFC 6762) ; résultats bruts hors dépôt. Aucune donnée
personnelle, aucun nom de poste, aucun mot de passe. Root borné par les mêmes unités systemd auditables (pilotage
`systemctl` sans mot de passe).

## 1. Scénario mesuré

| Scénario | Config A | Config C | Règle mesurée | Détail |
|---|---|---|---|---|
| **S-26** — responder passif mDNS (≥ 15 noms) | **VP** | **VP** | `EXP-NDR-001` **Alerte**, T1557.001 | la cible émet ≥ 20 requêtes mDNS distinctes, le responder root répond à chacune → la capture voit ≥ 15 réponses mDNS distinctes du même hôte → « répond en mDNS pour N noms » |

**S-26 (responder passif mDNS).** Le code applique un **seuil plus élevé pour mDNS (15 noms, contre 3 pour
LLMNR/NBNS)**, car un appareil mDNS légitime annonce souvent plusieurs services ; ce seuil réduit les faux positifs.
La cible émet 22 requêtes mDNS de noms de service distincts (`svc-mdnsN-x.local`) ; l'unité responder y répond ;
`EXP-NDR-001` **Alerte** « répond en mDNS pour N noms différents en 10 minutes : comportement d'empoisonneur de
type Responder » (T1557.001). L'affichage des noms dans `reseau.json` plafonne à 10 par répondeur, mais le
décompte interne (jusqu'à 100) déclenche l'alerte au vrai seuil de 15 : le verdict se fonde donc sur **l'alerte**,
pas sur l'affichage.

## 2. Ce que mesure (et ne mesure pas) S-26 — note d'honnêteté

Pour garantir l'émission indépendamment de la configuration, la cible envoie des requêtes mDNS **brutes** (socket
UDP vers `224.0.0.251:5353`), et **non** via le client mDNS de Windows. S-26 éprouve donc le **chemin de détection**
(capture → moteur → règle → alerte), et le VP en **A et C** confirme que ce chemin fonctionne dans les deux
configurations. En revanche, S-26 **ne mesure pas** la posture mDNS **côté client** de la baseline durcie : c'est
une question distincte (à l'inverse de S-23, où l'émission passait par le client LLMNR de Windows, ce qui révélait
la prévention côté client — `EnableMulticast = 0` — et donnait un P-baseline). Autrement dit : S-26 valide le
détecteur, pas la prévention.

## 3. Bilan

Avec ce lot, la détection **responder passif** est couverte sur ses trois protocoles : **LLMNR** (S-23, Alerte, VP A /
P-baseline C), **NBNS** (via le leurre actif, S-25) et **mDNS** (S-26, Alerte, VP A+C). Combinée au leurre actif
(S-22/S-25, Critique) et à l'usurpation ARP (S-20, Critique), la couverture NDR sans montage supplémentaire est
complète. Restent, et exigent chacun un **ré-adressage RFC 1918** du laboratoire (le garde `locale()` du module
UPnP n'accepte que les adresses privées ; les règles IDS directionnelles s'appuient sur `$HOME_NET`/`$EXTERNAL_NET`) :
le **DHCP pirate** (S-21, montage à deux serveurs), les **redirections UPnP** (T1133) et l'**IDS directionnel**.
