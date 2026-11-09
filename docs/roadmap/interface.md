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
| Technologie | WPF sur .NET Framework 4.8, sans bibliothèque de style (aucune dépendance nouvelle). WebView2 en repli, seulement sur décision du mainteneur après les captures de U1 (dépendance nouvelle) |
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

- Segoe UI partout ; chasse fixe réservée aux chemins et aux empreintes ; fin des capitales forcées.
- Coins de 6 à 8 px ; transitions de 100 à 200 ms, coupées si Windows désactive les animations ; plus de balayage ni
  d'effet « glitch » ; un seul clignotement à la fois.
- Navigation : « Vue d'ensemble », puis Surveillance, Protection, Système et confidentialité ; Réponses en cours, Santé
  et Réglages toujours visibles. Panneau de détails à droite, avec des boutons explicites.

## Découpage

| PR | Contenu |
|---|---|
| U0 | Script de captures réelles en VM ; captures de référence ; corrections WinForms bon marché (textes par `L.T`, contraste) — **fait** : `tests/vm/captures.ps1` (`tests\vm\lancer.ps1 -Scenario captures`), 19 pages en français et en anglais à 96 ppp, capturées en VM avant les corrections qui suivent (les captures après correction attendent la levée de la détection de Defender) ; texte secondaire `#9AA3AF` ; en-tête et barre d'état traduits ; pastilles jamais sous le titre, coupées par gravité (« +N » de la couleur de la plus grave cachée) |
| U1 | Pilote WPF : jetons, coquille, anciennes pages hébergées ; mode de compilation (`csc` en C# pur, XAML embarqué, ou MSBuild de .NET Framework) ; mesures (mémoire en zone de notification, démarrage par la tâche de relance, netteté à 100, 125 et 150 %). **Décision du mainteneur sur captures : WPF confirmé, ou repli sur WebView2** |
| U2 | Vue d'ensemble, panneau de détails ; Alertes, Incidents, Réponses en cours |
| U3 | Santé, Détection, Événements |
| U4 | Connexions, Trafic, Chaînes |
| U5 | Protection : Blocages, Quarantaine, Menaces, Baseline, Pare-feu ; diagnostic d'exposition du poste |
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
ressource de l'exécutable. Repli WebView2, s'il est décidé : surface XSS et pont entre l'hôte et la page, frontière
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
