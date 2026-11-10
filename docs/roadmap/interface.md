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
| U5a | **En cours** : Blocages, Quarantaine et Menaces en WPF : mêmes fichiers, lus hors du fil de l'interface (absent : rien d'enregistré ; illisible : rien de conclu, dernier affichage gardé et dit) ; mêmes commandes et mêmes questions dans les deux interfaces (`ActionsProtection`) ; réglages des réponses automatiques offerts seulement quand config.json est lu (audit de #139, S139-02) ; textes neutralisés, pages d'aujourd'hui comprises ; légende de la carte du Trafic coupée proprement. U5 coupée en U5a, U5b et U5c |
| U5b | Baseline et Pare-feu |
| U5c | Diagnostic d'exposition du poste (seul changement du service de la phase : dossier de conception d'abord) |
| U6 | Système : Démarrage, Extensions, Vie privée, Réseau local, Réglages ; retrait de `WindowsFormsHost` |
| U7 | Assistant de premier lancement |
| U8 | MSI : images, textes ; l'interface n'est pas lancée depuis la dernière page (elle tournerait élevée) : la tâche de relance la démarre |

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
