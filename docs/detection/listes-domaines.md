# Listes de domaines du filtrage DNS (phase 7) : sources, licences, choix

État : **moteur livré, sans effet réseau** (PR 7.2, `filtrage.rs`). Ce document fixe ce que le filtrage par nom de
domaine de la phase 7 télécharge, et pourquoi. Il reprend le dossier de conception de la phase 7 (section 5, recherche
documentaire du 2026-10-25).

## Dans le code (PR 7.2)

- **Sources compilées** : EasyPrivacy et EasyList, catégorie « publicité et pistage » (D7-3 : recommandation du dossier
  appliquée, révisable par le mainteneur avant l'activation, PR 7.4). **Aucune liste de sécurité** (D7-2 : licences non
  commerciales ou inconnues ; HaGeZi TIF seulement sur décision du mainteneur).
- **Rien n'est téléchargé** tant qu'aucune catégorie n'est active (`Config.Filtrage.Categories`, vide par défaut).
  Une catégorie active : ses listes sont téléchargées toutes les 12 h dans `filtrage\` (HTTPS seulement, 32 Mo au
  plus), relues avec le contrôle du propriétaire. En échec de la protection du dossier de données : rien téléchargé ni
  chargé.
- **Formats acceptés** : hosts (`0.0.0.0 domaine`), domaine seul, `||domaine^` et `@@||domaine^`. Toute autre règle
  (chemin, options `$…`, expressions régulières, règles cosmétiques) est écartée et comptée. Nom en ASCII, deux
  étiquettes au moins (un nom accentué est attendu en `xn--`), jamais un suffixe public de deux étiquettes (`co.uk`,
  `gouv.fr`, `com.br`…) : une telle règle bloquerait tous les sites sous ce suffixe ; elle est écartée et comptée.
- **Recherche** : le nom et ses parents (`a.b.exemple.fr` est bloqué par `exemple.fr`), jamais le domaine de premier
  niveau seul ; 10 recherches au plus, le nom lui-même puis les parents les plus courts.
- **Ordre** : liste de protection, puis autorisations de l'utilisateur, puis exceptions `@@` d'une liste (elles ne lèvent
  que les blocages de leur catégorie), puis listes de sécurité, puis de publicité.
- **Garde-fous** : une nouvelle copie vide, effondrée (moins de la moitié de la précédente) ou explosée (plus du double)
  est refusée et la précédente gardée ; un domaine de la liste de protection présent dans une liste est ignoré et compté ;
  1 000 000 d'entrées au plus au total (une liste qui dépasserait n'est pas chargée).
- **Liste de protection** (jamais bloquée, sous-domaines compris) : Windows Update, activation, Defender et SmartScreen,
  test de connectivité de Windows, heure, révocation et OCSP des autorités courantes, serveur de mise à jour de
  deR4Tizer, plus les hôtes de remontée configurés (ntfy, Teams, SMTP) et celui du manifeste de mise à jour. Établie
  d'après la documentation de Microsoft ; à compléter par les journaux d'une VM avec la PR 7.3, et à relire.
- **Autorisations de l'utilisateur** : commandes `filtrageAutoriser` et `filtrageRetirer` (administrateurs), 1000
  domaines au plus, dans `config.json` ; refusées en échec de la protection du dossier.
- **Liste refusée** (vide, effondrée, explosée) : copie précédente gardée, nouvel essai dans 12 h.

## Activation sur les cartes (PR 7.4)

Commande `filtrage` (`on` ou `off`, administrateurs ; l'interface viendra en 7.5). Activation : refus si le poste a un
suffixe DNS principal (poste joint à un domaine) ou une stratégie DNS ou NRPT (D7-5, recommandation appliquée) ;
origine des cartes enregistrée dans `filtrage-origine.json` avant toute modification ; résolveur permanent lancé et
contrôlé ; cartes Ethernet et Wi-Fi physiques actives réglées (`127.0.0.1` puis leurs serveurs, `::1` puis leurs
serveurs IPv6) et vérifiées ; au moindre écart, tout est rendu. Repris au démarrage du service. Écarts au dossier :
la collecte `FiltrageDns` et l'affichage viendront avec l'interface (7.5) ; une carte branchée après l'activation n'est
pas réglée (réactiver) ; la restauration avant une mise à jour se fait à l'arrêt du service par msiexec, pour toute
mise à jour, pas seulement un retour arrière.

## Résolveur local (PR 7.3, non branché)

Le résolveur local (`dns_local.rs`) consulte ce moteur. En 7.3, il ne tourne que pendant un **essai** de 10 minutes
lancé par un administrateur (commande `filtrageEssai`), sur `127.0.0.1:53` et `[::1]:53` seulement ; aucune carte n'est
réglée sur lui.

Décisions ouvertes du dossier appliquées sur sa recommandation, révisables par le mainteneur avant 7.4 :

- **D7-1** (mécanisme) : M2, le résolveur local ;
- **D7-4** (réponse à un nom bloqué) : A `0.0.0.0`, AAAA `::`, autres types sans réponse (NODATA), TTL de 60 s ;
- **D7-6** (nom spécial de Firefox) : `use-application-dns.net` répond NXDOMAIN quand le filtrage a une catégorie
  active.

Écarts au dossier, voulus :

- pas de file de 256 requêtes : au-delà de 16 requêtes en cours (dont 4 connexions TCP), la requête est ignorée et le
  client réessaie ;

- une réponse tronquée en UDP est rendue telle quelle au client, qui réessaie en TCP auprès du résolveur (qui relaie
  alors en TCP), au lieu d'un nouvel essai en TCP par le résolveur lui-même ;
- la dégradation ouverte arrête l'essai (les cartes ne pointent pas encore sur le résolveur) ; la collecte
  `FiltrageDns` et la suspension de 5 minutes viendront avec l'activation (7.4) ;
- le cas en VM est dans le scénario 3a, pas dans un scénario `filtrage` à part (qui demanderait d'étendre l'outillage
  du passage complet) ; à reprendre en 7.4 si les cas se multiplient.

## Principe

- Le poste téléchargera chaque liste **directement chez sa source**, comme les listes de menaces d'aujourd'hui
  (`menaces.rs` : HTTPS seulement, taille et délai bornés, copie précédente gardée si la nouvelle s'effondre).
  deR4Tizer ne **redistribue** aucune liste.
- Les obligations de partage des licences GPL et CC BY-SA portent sur la redistribution, pas sur l'usage. Une licence
  « non commerciale » restreint en revanche l'**usage**, ce qui exclut les TPE et les communes.
- Ce qui suit est une **lecture technique** des pages des projets, **pas un avis juridique**. Les choix restent au
  mainteneur (décisions D7-2, D7-3 et D7-8 du dossier, ouvertes).
- Les sources seront compilées dans le binaire : aucune adresse de liste ne sera lue d'un fichier.

## Listes examinées

| Liste | Catégorie | Licence ou conditions (d'après la page du projet) | Usage par une TPE | Proposition du dossier |
|---|---|---|---|---|
| EasyPrivacy, EasyList | publicité, pistage | double licence GPLv3 ou CC BY-SA 3.0, au choix ; citer « The EasyList authors » | permis | Par défaut quand « Publicités et pistage » est activé ; règles `||domaine^` sans option seulement ; attribution affichée. |
| AdGuard DNS filter | publicité, pistage | dépôt sous GPL-3.0 ; agrège des listes tierces dont les licences ne sont pas données sur la page | probablement permis, sources amont à vérifier | Alternative si EasyList casse trop de sites. |
| HaGeZi « Multi Light » | publicité, pistage, une partie des logiciels malveillants | GPL-3.0 pour les listes publiées, sans droit sur les données amont d'après le projet | incertain | Alternative, sur décision du mainteneur. |
| HaGeZi « TIF » (Mini) | sécurité | même réserve sur les sources amont | incertain | Seule liste de sécurité gratuite trouvée qui semble utilisable ; sur décision du mainteneur seulement, réserve affichée. |
| URLhaus (abuse.ch) | sécurité | usage commercial soumis à un abonnement payant, d'après les conditions d'abuse.ch | non | Écartée. |
| Phishing Army | sécurité | CC BY-NC 4.0 | non | Reste sous « listes restreintes » pour DNS-001, jamais pour le blocage. |
| ThreatView domaines | sécurité | à vérifier | inconnu | Idem. |
| StevenBlack « unified » | publicité, logiciels malveillants | dépôt sous MIT, mais agrège des listes non commerciales (MVPS, Dan Pollock) | non | Écartée. |
| Résolveur Quad9 (au lieu d'une liste) | sécurité | service gratuit ; conditions à relire par le mainteneur | à confirmer | Proposé comme amont choisi, nommé, pour « Navigation sécurisée ». |

## Ce qui sera bloqué par défaut : rien

Le filtrage sera désactivé à l'installation et après une mise à niveau.

| Activation | Ce qui serait bloqué |
|---|---|
| « Navigation sécurisée » | Domaines des listes de sécurité retenues par le mainteneur, plus le filtrage de l'amont si Quad9 est choisi. Sans liste ni Quad9, l'interface dira « aucune liste de sécurité active : rien n'est bloqué ; les alertes DNS-001 restent ». |
| « Publicités et pistage » | Règles de domaine d'EasyPrivacy et d'EasyList. Jamais groupée avec la sécurité : le risque de casser un site n'est pas le même. |
| Toujours | Rien de la liste de protection compilée, rien de ce que l'utilisateur a autorisé. |
