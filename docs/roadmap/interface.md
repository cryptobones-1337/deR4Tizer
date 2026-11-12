# Phase « Interface et assistant d'installation »

Décidée par le mainteneur le 2026-11-03, par ces mots : « fais la refonte avant la phase 7 », en réponse au dossier de
conception de l'interface du 2026-11-03 (revue UI/UX après la phase 6, conservé hors dépôt). Elle commence une fois les
corrections de la phase 6 fusionnées **et la phase inscrite dans `CLAUDE.md`** (section 2, règle 1 ; inscrite le
2026-11-03 sur l'autorisation du mainteneur). La phase 7 commence une fois
celle-ci validée. Ce document fixe le périmètre,
le découpage et les décisions de la phase. Rien de ce qu'il prévoit n'existe encore dans le code : chaque élément passe
à « testé en labo » dans la matrice (`docs/roadmap/capability-matrix.md`) seulement avec la PR qui l'apporte.

## Besoin

L'interface WinForms d'aujourd'hui est fonctionnelle mais datée : esthétique « néon », capitales forcées, contraste
insuffisant du texte secondaire, navigation à plat, pages denses. La revue UX externe du 2026-10-25 et la revue faite
après la phase 6 vont dans le même sens : un utilisateur sans informaticien doit comprendre d'un coup d'œil ce qui va,
ce qui ne va pas et ce qu'il peut faire. L'installation se limite aux dialogues standard de Windows Installer, et rien
n'explique les premiers réglages.

## Décisions du mainteneur (2026-11-03)

| Question du dossier | Réponse |
|---|---|
| Technologie | WPF sur .NET Framework 4.8, sans bibliothèque de style (aucune dépendance nouvelle). **Confirmé par le mainteneur le 2026-11-09** sur les captures réelles du pilote en VM (« Continuer en WPF ») : le repli WebView2 est abandonné |
| Palette | Neutre, à un seul accent ; le cyan reste la couleur du logo |
| Polices et icônes | Segoe UI (Variable) et icônes Segoe Fluent ou MDL2, livrées avec Windows ; rien d'ajouté |
| Assistant d'installation | MSI WiX sobre (images et textes revus) ; l'assistant de premier lancement est dans l'interface |
| Ordre | Avant la phase 7 |

## Points non tranchés (défaut retenu, à confirmer par le mainteneur)

| Point | Défaut retenu |
|---|---|
| Diagnostic « PC exposé » (il touche le service) | Dans cette phase, en U5, comme le proposait le dossier ; le mainteneur n'a pas répondu à cette question |
| Étape « Réponses automatiques » de l'assistant | Le réglage d'aujourd'hui est gardé : blocage automatique du niveau 3 activé par défaut. Le dossier proposait « désactivées par défaut » ; ce changement de défaut n'a pas été décidé |

## Direction visuelle

Contrastes calculés selon WCAG (4,5:1 au moins pour le texte) :

| Jeton | Valeur | Emploi |
|---|---|---|
| Fond | `#141518` | fenêtre |
| Carte | `#1E2024` | panneaux |
| Surface | `#262A30` | champs, lignes survolées |
| Texte | `#E6E8EB` | texte courant |
| Texte secondaire | `#9AA3AF` | remplace `#6B7A90`, trop pâle |
| Accent | `#3BA7F0` | un seul accent, texte foncé dessus |
| Danger | `#F0605A` | risque confirmé et actions destructrices |
| Attention | `#F2A93B` | à surveiller |
| Succès | `#2FBF71` | avec parcimonie |

- Segoe UI partout ; chasse fixe réservée aux chemins et aux empreintes ; fin des capitales forcées. Écart provisoire
  (relecture de #133, R2) : dans le pilote, les pages d'aujourd'hui hébergées sont entièrement en Segoe UI, chemins et
  empreintes compris (leur police unique `Theme.Mono` sert aussi aux tableaux) ; la chasse fixe revient avec leur
  réécriture (U3 à U6).
- Coins de 6 à 8 px ; transitions de 100 à 200 ms, coupées si Windows désactive les animations ; plus de balayage ni
  d'effet « glitch » ; un seul clignotement à la fois.
- Navigation : « Vue d'ensemble », puis Surveillance, Protection, Système et confidentialité ; Réponses en cours, Santé
  et Réglages toujours visibles. Panneau de détails à droite, avec des boutons explicites.

## Découpage

| PR | Contenu |
|---|---|
| U0 | Script de captures réelles en VM ; captures de référence ; corrections WinForms bon marché (textes par `L.T`, contraste) — **fait** : `tests/vm/captures.ps1` (`tests\vm\lancer.ps1 -Scenario captures`), 19 pages en français et en anglais à 96 ppp, capturées en VM avant les corrections qui suivent (les captures après correction attendent la levée de la détection de Defender) ; texte secondaire `#9AA3AF` ; en-tête et barre d'état traduits ; pastilles jamais sous le titre, coupées par gravité (« +N » de la couleur de la plus grave cachée) |
| U1 | **En cours (pilote, ouvert par `--fluent`)** : `src/Fluent.cs`, C# pur compilé par `csc` (aucun XAML compilé, aucune dépendance : assemblys WPF de .NET Framework 4.8) ; jetons, navigation regroupée, pages d'aujourd'hui hébergées par `WindowsFormsHost` ; `tests/rendu-pilote.ps1` (contrastes, navigation, rendu hors écran à 100, 125 et 150 %, assistant élevé sans WPF). Captures réelles du pilote en VM (`tests/vm/captures.ps1`, 20 pages, français et anglais). Rendu logiciel imposé (le rendu matériel laissait la coquille blanche dans la VM Hyper-V) ; fenêtre ramenée à la zone de travail ; en mode pilote, les pages d'aujourd'hui prennent la palette et la police de la coquille (`Theme.cs`), sans titre « // » en double. **WPF confirmé par le mainteneur (2026-11-09).** Reste à mesurer : mémoire en zone de notification, démarrage par la tâche de relance, netteté à 125 et 150 % en VM |
| U2a | **Fait (#134)** : Vue d'ensemble native dans le pilote : faits de l'en-tête d'aujourd'hui (mêmes règles, mêmes textes, remis en casse de phrase) rangés par gravité, compteurs colorés de la navigation « à surveiller » au plus, phrase de tête sans promesse (« État inconnu » si rien n'est publié), bouton panique par le même chemin et la même confirmation qu'aujourd'hui, ligne d'état du service ; compteurs dans la navigation ; la zone de notification (ouvrir, double-clic, clic sur une notification) montre la coquille ; fermer la coquille la cache, seul « Quitter » l'arrête (relecture de #133, R3) |
| U2b | **Fait (#136)** : page Alertes réécrite en WPF : filtres par niveau avec leur nombre, liste des plus récentes (500 au plus), non lues marquées, panneau de détails à droite (heure, destination, règle, technique, que faire, raisons, chemin en chasse fixe) avec des boutons explicites, offerts selon ce que l'alerte permet (bloquer, ne plus alerter sauf pour une critique, isoler, suspendre, tuer, quarantaine, ouvrir l'emplacement) et passant par les mêmes méthodes et les mêmes questions que le menu d'aujourd'hui ; textes du service neutralisés ; lecture des alertes marquée depuis la coquille |
| U2c | **Fait (#137)** : Incidents et Réponses en cours réécrites en WPF, même panneau de détails : liste triée comme aujourd'hui, état toujours écrit, « Lecture en cours… » avant la première lecture (jamais un vide rassurant), dernière liste gardée si le fichier devient illisible ; boutons par les mêmes actions que les pages d'aujourd'hui (`ActionsIncidents`, `ActionsReponses` : même commande, même dialogue de clôture, mêmes contrôles de récupération, même confirmation élevée). Préalables de la relecture de #136 : niveau d'alerte neutralisé ; suspendre ou tuer depuis une alerte refusé si le processus qui porte ce PID a été lancé après l'alerte, les deux heures dites sinon (une alerte ne garde pas l'heure de création du processus) |
| U3a | **Fait (#138)** : Santé et Détection en WPF : mêmes lignes que la page Santé d'aujourd'hui (source et date de chaque ligne), « Lecture en cours… » avant la première lecture ; Détection en cinq vues (IDS, TLS, HTTP, DNS, JA3), textes du réseau et des règles neutralisés (la page d'aujourd'hui aussi), IPS réglé par la même commande et la même confirmation élevée, bouton caché tant que son état n'est pas lu. Préalables de #137 : sorte de réponse inconnue neutralisée, limites de la garde sur le PID écrites dans la matrice |
| U3b | **Fait (#139)** : Événements en WPF : même recherche que la page d'aujourd'hui (`RechercheSiem`, extraite sans changement de logique, lecture seule hors du fil de l'interface), mêmes filtres (période, niveau, source), chronologie en 48 tranches cliquables, incidents de corrélation puis événements (500 affichés au plus), panneau de détails ; textes neutralisés, la page d'aujourd'hui aussi. Préalables de #138 : état de l'IPS « inconnu » si config.json est illisible (aucun bouton, case grisée) ; « Copier » rend la valeur d'origine, caractères de contrôle et de mise en forme échappés (audit de #139, S139-01) |
| U4a | **Fait (#140)** : Connexions et Chaînes en WPF : lues dans etat.json hors du fil de l'interface, « Lecture en cours… » avant la première lecture, dernière liste gardée et dite si l'état devient illisible, collecte en panne dite (liste incomplète) ; Connexions : filtres (toutes, suspectes, menaces), plus graves d'abord, 500 au plus ; Chaînes : arbre « qui a lancé quoi » dans le panneau, seuil de 12 ; boutons par les mêmes méthodes et les mêmes questions que les menus d'aujourd'hui ; textes neutralisés, les pages d'aujourd'hui aussi ; « Copier » échappé. U4 coupée en U4a et U4b |
| U4b | **Fait (#141)** : Trafic en WPF : même fichier que la page d'aujourd'hui (trafic.json, lu hors du fil de l'interface et seulement quand il change), résumé du débit et des totaux, carte des pays (échelle logarithmique, bulle par pays, arcs fixes vers les échanges des 10 dernières secondes, aucune animation continue), courbe des 10 dernières minutes avec son maximum, puis programmes, pays ou destinations et leur détail ; « Lecture en cours… » avant la première lecture, rien de conclu sans fichier, dernier affichage gardé et dit s'il devient illisible ; textes neutralisés, page d'aujourd'hui comprise |
| U5a | **Fait (#142)** : Blocages, Quarantaine et Menaces en WPF : mêmes fichiers, lus hors du fil de l'interface (absent : rien d'enregistré ; illisible : rien de conclu, dernier affichage gardé et dit) ; mêmes commandes et mêmes questions dans les deux interfaces (`ActionsProtection`) ; réglages des réponses automatiques offerts seulement quand config.json est lu (audit de #139, S139-02) ; textes neutralisés, pages d'aujourd'hui comprises ; légende de la carte du Trafic coupée proprement. U5 coupée en U5a, U5b et U5c |
| U5b | **Fait (#143)** : Baseline et Pare-feu en WPF : Baseline par profil (journalisation, recommandé, renforcé) avec son score, mêmes boutons et mêmes questions qu'aujourd'hui (`ActionsProtection.Baseline`), appliquer ou annuler une règle depuis son panneau ; Pare-feu en deux vues (exposition à Internet, changements de règles), lecture seule, journal des paquets inactif dit ; « Lecture en cours… », absent et illisible distingués ; textes neutralisés, pages d'aujourd'hui comprises |
| U5c-0 | **Fait (#144)** : interface seule. Sans exposition relevée, chaque contrôle est dit vu ou non vérifié, et le verdict dit sur quoi il repose ; « contrôles incomplets » si le journal des paquets est inactif ou si UPnP n'est pas vérifié ; jamais « aucune exposition ». Constat C1 du dossier de conception de U5c |
| U5c-1 | **Fait (#148)** : service. Diagnostic par contrôle publié dans etat.json (Exposition.Diagnostic) : IPv4 publique, IPv6 globale, connexions acceptées, sources bloquées, UPnP (vérifié d'après le texte et la fraîcheur de reseau.json, NDR gelé), état du pare-feu de Windows (lecture INetFwPolicy2) ; verdict à quatre valeurs, jamais « protégé » ; lecture seule, aucune requête vers un tiers ni vers la box ; `Exposee` inchangé. Décidé par le mainteneur le 2026-11-10 (« Oui » : dans cette phase) |
| U5c-2 | **Fait (#149)** : `Exposee` suit le verdict du diagnostic ; IPv6 globale seule et sources bloquées seules en « exposition à surveiller » (orange, sans clignoter) plutôt qu'en « PC exposé », décidé par le mainteneur le 2026-11-10 (« Oui ») ; page Pare-feu : vue « Pourquoi » (constat, état, que faire), bilan titré selon le verdict dans les deux interfaces ; ancien service sans diagnostic : constat de U5c-0 |
| U6a | **Fait (#145)** : Démarrage auto, Extensions et Vie privée en WPF : mêmes fichiers, lus hors du fil de l'interface ; Démarrage avec le même filtre (Microsoft et Windows masqués sauf remarque), remarques d'abord, quarantaine de la cible par la même question ; Extensions, permissions sensibles d'abord, lecture seule ; Vie privée en trois vues (caméra et micro, prise en main à distance, ports ouverts), collecte en panne dite ; textes neutralisés, pages d'aujourd'hui comprises. U6 coupée en U6a et U6b |
| U6b | **Fait (#146)** : Réseau local en WPF (reseau.json, lecture seule, quatre vues, leurre et DHCP pirate dits, textes neutralisés, page d'aujourd'hui comprise) ; questions des boutons d'aujourd'hui traduites (relecture de #143, constat 5), question de blocage neutralisée. U6 coupée encore : Réglages et retrait de `WindowsFormsHost` en U6c |
| U6c | **Fait (#147)** : Réglages en WPF : mêmes réglages, mêmes contrôles et mêmes commandes que la page d'aujourd'hui (`ActionsReglages`, partagée) ; choix par boutons (pas de liste déroulante claire), secrets en champs masqués jamais réaffichés ; config.json illisible : dit, rien n'est enregistré (les deux interfaces) ; export CSV sans formule ; textes neutralisés ; aucune action avant la première lecture. Retrait de `WindowsFormsHost` : toutes les pages de la coquille sont natives. Préalable de #146 : test des emplacements {0} {1} sur toute la table des traductions |
| U7-0 | **Fait (#150)** : préalables des relectures. Restes de l'hébergement WinForms retirés (paramètre `pages` de la coquille, `Fenetre.PageDe`, référence `WindowsFormsIntegration.dll` des compilations, relecture de #147) ; lecture du pare-feu de Windows hors du verrou du moniteur (relecture de #148) ; effet d'une vérification UPnP ancienne écrit (relecture de #149, constat 1) |
| U7a | **Fait (#151)** : « Premiers réglages », socle en lecture seule (dossier de conception U7). Page de la coquille hors de la navigation, six étapes (bienvenue, vérification, apprentissage, qui prévenir, réponses automatiques, résumé) ; aucune commande : chaque étape lit les fichiers du service et renvoie vers Santé, Réglages ou Menaces ; apprentissage dit en trois cas (en cours, terminé, pas d'apprentissage automatique quand le début vaut la fin) ; « Personne n'est prévenu » dit tel quel ; repère par utilisateur (`%LOCALAPPDATA%\deR4Tizer\premiers-reglages.txt`) écrit seulement par « Plus tard » et « Terminer » ; ouverture d'office au premier lancement de la coquille, jamais en administrateur, avec `--page` ou `--cache` ; carte dans la Vue d'ensemble tant que le repère manque, bouton « Revoir » dans Réglages |
| U7b | **Fait (#152)** : actions des étapes. Apprentissage : terminer s'il est en cours, rien sinon ; jamais recommencer depuis l'assistant (pendant 7 jours, toute alerte non critique sans signal fort serait apprise, programme malveillant actif compris : relecture de #152, constat 1), seulement dans Réglages, avertissement écrit ; réponses automatiques : activer ou désactiver les deux de niveau 3 (blocage par les listes, suspension par leurre), l'IPS restant dans Détection ; mêmes commandes que les pages Réglages et Menaces, construites par les mêmes fonctions pour la confirmation et l'envoi (audit de #152, S152-01) ; interface élevée : confirmation détaillée montrée par l'assistant avant l'action ; résultat dit « demandé » et état relu ; textes repris (remarques R2, R5, R6 de #151) |
| U7-1 | **Fait (#153)** : suites des audits de #151 et #152. Interface élevée : « config » (réponses automatiques, IPS, listes) et « apprentissage » confirmés par Canal dans toutes les pages, l'assistant n'en montre plus une seconde (S152-02), ainsi que « debloquer », « reglages », « notifications », « majConfig », « autoriserLecteur » (S153-01) et « exception » (S153-02) ; confirmation avec le nom lisible du réglage et, pour « recommencer », le risque des 7 jours (R8) ; `derniere-alerte-lue.txt` jamais écrit par une interface élevée (S151-01) |
| U7c | **Fait (#154)** : Qui prévenir, option B du dossier (destinataires, canaux et secrets restent dans Réglages). L'étape envoie un message de test aux canaux déjà réglés : réglages relus au clic (le service les applique avant le test, S154-01), secrets vides (le service garde les siens), « testerNotifications » confirmé en administrateur dans toutes les pages, commande construite par la fonction de la page Réglages (`CommandeNotifications`) ; seulement si config.json est lu et qu'un canal est activé |
| U7 | Assistant de premier lancement : **fait** (U7a à U7c, #151 à #154) |
| U8a | **Fait (#155)** : textes de l'installeur (dossier de conception U8). Licence en français et en anglais (leurres, réponses automatiques et leurs durées, lancement, téléchargements, Defender complété et jamais affaibli, options de désinstallation, binaires non signés) ; dernière page : un texte posé par quatre affectations de propriété côté client (type 51), selon la langue (UserLanguageID) et le lancement effectif (miroir de la condition d'exécution), jamais de case « Lancer » ni d'action qui lance l'interface : lancée d'ici, elle pourrait tourner élevée (selon le mode de lancement de l'installeur) et garder le mutex de la session ; « protection » retiré des descriptions ; `tests/test-msi.ps1` ; 3a : interface venue de la tâche, jeton non élevé |
| U8b | Images de l'installeur (bannière, dialogue), générées à la construction, sur la nouvelle icône ; captures des dialogues en VM |
| B1 | **Fait (#156)** : bascule, la coquille devient l'interface par défaut (dossier de la bascule) ; `--classique` pour l'interface d'avant ; démarrage caché sans fenêtre, coquille construite au premier geste ; page déchargée quand la coquille est cachée ; palette neutre sauf `--classique` ; repli automatique sur l'interface classique si la coquille ne démarre pas, y compris au premier geste après un démarrage caché, la fenêtre cachée libérée |
| B2 | **En cours** : seconde instance, montrer l'interface déjà ouverte (événement de la session sans donnée, écouté sur un fil d'arrière-plan ; décision pure `SignalerPremiere` : jamais avec `--cache`, `--relance`, `--commande-fichier`, `--dossier` ni `--classique` ; page demandée ignorée) |
| B3 | Dernière page du MSI : phrase « Premiers réglages », après B1 et B2 |
| B4 | Allègement (veille sans pages WinForms), sur les mesures de B1 ; retrait de `--classique` après la campagne Kali, sur décision |

**Assistant de premier lancement (U7)** : non élevé, rejouable depuis les réglages ; chaque choix privilégié passe par la
commande existante et sa confirmation élevée. Étapes : Bienvenue ; Vérification (lecture seule, une collecte
indisponible est dite) ; Apprentissage (7 jours) ; Qui prévenir ; Réponses automatiques (niveau 3 seulement, défaut
d'aujourd'hui : voir les points non tranchés) ; Résumé avec « Plus tard ». Fermer l'assistant ne change rien ; il ne dit jamais « vous êtes protégé ».

## Garde-fous

- Aucune dépendance nouvelle sans accord du mainteneur (WebView2 compris).
- XAML chargé seulement depuis la ressource de l'exécutable signé.
- Toute chaîne non fiable affichée passe par `Visible`, panneau de détails compris (corriger d'abord S105-09).
- `--commande-fichier` ne charge pas WPF : test qui le prouve.
- Le service, le canal et les droits ne changent pas, sauf le diagnostic d'exposition de U5.
- `tests/test-confirmations.ps1` inchangé : les confirmations élevées disent toujours ce que fait la commande.
- « Collecte indisponible » n'est jamais montré comme « rien de suspect ».
- README français et anglais à chaque PR qui change ce que l'on voit.

## Tests

- Unitaires, par réflexion : une seule pastille du mode panique ; textes d'en-tête par `L.T` ; contraste des jetons
  ≥ 4,5:1 ; `Visible` dans le panneau de détails ; regroupement de la navigation ; Vue d'ensemble (collecte
  indisponible) ; assistant (fermer ne change rien).
- Intégration : script de captures réelles en VM (chaque page, 100, 125 et 150 %, français et anglais, données
  synthétiques), clavier, relance par la tâche, mémoire ; passage complet avant chaque fusion.

## Modèle de menaces

Option WPF : plus d'endroits qui affichent des chaînes non fiables (`Visible` partout), XAML seulement depuis la
ressource de l'exécutable. Repli WebView2 (abandonné le 2026-11-09, gardé pour mémoire) : surface XSS et pont entre l'hôte et la page, frontière
nouvelle à décrire dans `docs/security/threat-model.md` avant tout code (contenu des seules ressources de l'exécutable,
CSP stricte et Trusted Types, ni framework JS ni npm, `textContent`, pont fermé, assistant élevé natif, données sous
`%LOCALAPPDATA%`, runtime absent dit et jamais installé en silence).

## Risques

Coût du pilote inconnu tant que la compilation n'est pas essayée ; mémoire de WPF non mesurée ; mélange WinForms et WPF
pendant la transition ; un écran plus beau peut promettre plus que le service ne fait ; même modèle pour l'auteur et le
prérelecteur.

## Inscription dans `CLAUDE.md`

Inscrite le 2026-11-03, sur l'autorisation du mainteneur (« Ok pour modifier Claude. Md je t'autorise ») ; texte
proposé alors, repris dans `CLAUDE.md` :

- Section 2, règle 1 : « Seules exceptions : la phase « Interface et assistant d'installation » et les phases 7, 8 et
  9 (section 5), … » (l'assistant de premier lancement est une capacité nouvelle).
- Section 5, nouveau point avant la phase 7 : « Phase « Interface et assistant d'installation », avant la phase 7.
  Ouverte par le mainteneur le 2026-11-03, par ces mots : « fais la refonte avant la phase 7 ». Commence une fois les
  corrections de la phase 6 fusionnées et ce point inscrit ; la phase 7 commence une fois celle-ci validée par la relecture et par
  cryptobones-1337. Décisions, découpage et garde-fous : `docs/roadmap/interface.md`. Comme pour les phases 3, 4 et 6,
  la preuve locale en VM tient lieu de CI GitHub pour ses PR ; rien ne change pour la distribution. »
- Section 5, phase 7 : ajouter « et après la phase « Interface et assistant d'installation » » à sa condition de
  début.
