# Langue de l'interface

État au 2026-11-23 (constat T-17, étape 1). Description du code tel qu'il est.

## 1. Choix de la langue (étape 1)

Une seule décision, `L.Choisir` (`src/Langue.cs`), appelée une fois au démarrage par `Programme.ChoisirLangue`
(`src/Gui.cs`), avant toute fenêtre. Elle fixe `L.En` (langue affichée) et `L.Reglage` (réglage en vigueur) pour tout le
processus : interface WPF, interface classique (`--classique`), fenêtre cachée de la zone de notification, notifications
locales, et assistant élevé (même exécutable, `--commande-fichier`). Aucune autre affectation de `L.En` ; la culture de
Windows n'est lue que par `L.CultureAnglaise` (`tests/test-langue.ps1` le vérifie).

Ordre de décision :

1. Assistant élevé : langue passée par l'interface qui le lance (`--commande-fichier <fichier> --langue fr|en`). Il
   tourne sous un autre compte (compte standard qui tape le mot de passe d'un administrateur) ou une autre élévation :
   sa culture n'est pas celle de l'utilisateur. Le fichier de réglage du compte élevé n'est jamais lu. Valeur hors de
   « fr » et « en » : ignorée. Lancé sans `--langue` (par une version précédente) : config.json puis culture, comme
   avant. Ses arguments sont fixés : un `--dossier` parmi eux n'est pas une option (`Programme.DossierDemande`, audit de
   #298, A298-2). L'interface élevée n'applique jamais `--dossier` non plus, et l'interface non élevée seulement sur un
   disque local fixe (audit de #298, A298-3) : sous jeton administrateur, config.json est toujours lu dans le dossier de
   données normal.
2. Réglage de l'utilisateur, `%LOCALAPPDATA%\deR4Tizer\langue.txt` : `auto`, `fr` ou `en` (toute autre valeur, ou un
   fichier de plus de 64 octets, est ignorée). Écrit et lu par l'interface non élevée seulement : jamais sous jeton
   administrateur, ni pour l'écriture ni pour la lecture (le dossier est contrôlé par les programmes non élevés du
   compte, même règle que le repère des premiers réglages, S151-01 ; audit de #298, A298-1). Une interface élevée suit
   donc config.json puis la culture. Lu sur un seul handle ouvert sans suivre de point de reparse
   (`FILE_FLAG_OPEN_REPARSE_POINT`) : lien, jonction ou dossier refusés, 65 octets lus au plus. Aucune commande, rien
   n'est envoyé au service.
3. Sans réglage de l'utilisateur : « en » si `config.json` porte `"Langue": "en"`, seul choix explicite qu'une version
   précédente a pu y laisser. « fr » n'y dit pas un choix : c'est aussi la valeur par défaut que le service écrit avec
   n'importe quel réglage (IPS, filtrage, mise à jour…), et elle imposait le français à un Windows anglais.
4. Sinon, automatique : français pour toute culture d'affichage française de l'utilisateur (`fr-FR`, `fr-CA`…),
   anglais pour toute autre.

Format des données inchangé : `config.json` garde son champ `Langue`, renvoyé quand la page Réglages enregistre le
syslog et l'API (`ActionsReglages.Composer`) : « en » gardé, toute autre valeur (null, vide, « EN »…) ramenée à « fr »,
que le service accepte (liste fermée ; sinon il refuserait chaque enregistrement). La confirmation de cette commande le
dit « langue gardée dans config.json (sans effet sur la langue affichée) ».

Conséquence : un « Français » choisi par une version précédente sous un Windows non français n'est pas gardé (il est à
rechoisir dans Réglages).

Page Réglages (WPF et classique) : trois valeurs, « Automatique (Windows : <langue>) », « Français », « English ». La
valeur active est le réglage en vigueur dans ce processus, jamais la valeur par défaut de `config.json` (constat T-13 :
« Français » sélectionné dans une interface anglaise). Le libellé « Automatique » dit la langue qu'il donne sur ce
poste. Sous le choix, la langue affichée est toujours dite ; un choix enregistré depuis est dit à part (« Choix
enregistré : Français, appliqué au prochain lancement de l'interface ») et, dans la page WPF, son bouton est bordé en
gris. Dans l'interface classique, le choix est écrit à la validation (liste refermée, sortie du champ, Entrée), pas à
chaque changement de sélection : les flèches parcourent les trois valeurs. Le changement ne s'applique pas sans relancer
l'interface : les pages sont construites dans la langue du démarrage. En administrateur, rien n'est lu ni écrit et la
page le dit.

Corrigé dans la même étape (textes de l'interface, pas du service) :

- page Pare-feu : l'état d'un contrôle disait « not found » (« pas constaté ») ; à côté de « Windows Firewall », il se
  lisait « pare-feu introuvable » alors que le service publiait le pare-feu actif (`parefeu.rs:diagnostiquer`, état
  `pas_constate` : aucun problème relevé). Cause dans l'interface (`VueParefeuFluent.Etat`), pas dans la lecture ni
  dans le service : l'état dit maintenant « no issue found » / « rien relevé », « issue found » / « constaté » ;
- notification locale de plusieurs alertes (« 2 nouvelles alertes ») et bulle de l'icône près de l'horloge, qui
  restaient en français (`Fenetre.TexteNotification`, `Fenetre.TexteIcone`) ;
- niveaux (« Critique », « Alerte », « Info ») affichés bruts dans la liste des incidents (WPF et classique), le
  mini-SIEM, les détections IDS et la liste classique des alertes : passés par `L.T`.

Limite : un programme non élevé qui lance lui-même l'assistant (il lui faut un fichier de commande de deR4Tizer dans
`%LOCALAPPDATA%\deR4Tizer` et l'accord de l'invite UAC) choisit la langue de la confirmation, entre français et anglais
seulement ; le contenu de la confirmation, les délais et le bandeau des commandes qui affaiblissent ne changent pas.

Tests : `tests/test-langue.ps1` (décisions pures ; un processus par culture, en-US et fr-FR, sans `config.json` ni
réglage, qui construit hors écran la page Réglages WPF et classique, la fenêtre de l'assistant élevé et la notification
locale ; `-Rendus` : images hors écran). Non vérifié en session Windows ouverte ni derrière une invite UAC réelle (VM).

## 2. Textes du service affichés tels quels (inventaire, étape 2 non commencée)

Le service écrit ses textes en français. L'interface les affiche tels quels, sous des titres traduits : `Canal.Visible`
neutralise les caractères sans rien traduire (« brut » ci-dessous) ; `L.T` ne traduit qu'une phrase exacte présente
dans `src/Langue.cs` (un texte composé par `format!` n'y est jamais). Rien n'est traduit dans cette étape. L'étape 2
est une phase à part, à proposer au mainteneur : codes de message et paramètres, tables FR/EN testées, compatibilité
des alertes enregistrées, signature d'apprentissage indépendante du texte, langue de la remontée choisie par
l'administrateur.

Chemins : service sous `service-rs/src/`, interface sous `src/`.

### Alertes (`alertes.json`)

| Champ | Produit par (service) | Affiché par (interface) | Traduction |
|---|---|---|---|
| `Raisons` des flux (« MENACE CONNUE (…), NON SIGNÉ, IP DIRECTE… ») | `moniteur.rs` : `score_flux`, `ajouter_alerte` | `Fluent.cs` : `VueAlertesFluent.Detail` ; `Gui.cs` : `RemplirAlertes`, `DetaillerAlerte` | brut |
| `Raisons` des autres règles (texte libre) | `alerte()` de `defender.rs`, `hygiene.rs`, `surveillances.rs` ; `persistance.rs` : `alerter` ; `baseline.rs`, `chaines.rs`, `dns_surveillance.rs`, `parefeu.rs` : `traduire`, `ids.rs`, `dpi.rs` / `ndr.rs` : `alerter`, `sante.rs`, `vol_donnees.rs`, `politique.rs`, `protection.rs`, `reponse.rs`, `canal.rs`, `moniteur.rs` | mêmes vues | brut |
| `Destination` composée par le service (« mode panique », « baseline : … », « incident : … », « IDS : … ») | mêmes fichiers | `Fluent.cs` : carte de la liste, `VueAlertesFluent.Detail` ; `Gui.cs` : `RemplirAlertes` | brut |
| `Processus` (parfois « ? » ou un libellé du service) | `moniteur.rs`, `dns_surveillance.rs` | `Fluent.cs` : liste des alertes | brut |
| `Conseil` | `mitre.rs` : `enrichir`, table `CONSEILS` | `Fluent.cs` : `VueAlertesFluent.Detail` ; `Gui.cs` : `DetaillerAlerte` | `L.T` (textes fixes au dictionnaire) |
| `Mitre` | `mitre.rs` : `libelle` | `L.Mitre` dans `Fluent.cs` et `Gui.cs` | `L.T` par technique |
| Notification locale : titre `Processus`, texte `Destination : Raisons` | (champs ci-dessus) | `Gui.cs` : `Fenetre.TexteNotification` | brut (niveau et compte traduits) |
| Confirmation d'une exception : `Processus`, `Destination`, `Raisons` | (champs ci-dessus) | `Gui.cs` : `Canal.Decrire`, cas `exception` | brut |

### Incidents et corrélation

| Champ | Produit par | Affiché par | Traduction |
|---|---|---|---|
| `ResumeAlerte.Raisons`, `Destination` | `incidents.rs` (copie de l'alerte) | `Incidents.cs` : `VueIncidents.Detail` ; `Fluent.cs` : `PageIncidentsFluent` | brut |
| `ElementChronologie.Texte` (« processus : raisons », transitions « Ouvert vers Clos… (par S-1-5-…) », message d'événement) | `incidents.rs` (chronologie) | `Incidents.cs` : `VueIncidents.Detail` | brut, avec des noms d'énumération Rust |
| `ElementChronologie.Source` (`alerte`, `transition`, `reponse`…) | `incidents.rs` | `Incidents.cs` : `VueIncidents.Detail` | code brut |
| Incident de corrélation : `Titre`, `Resume` | `siem.rs` : `analyser` | `Fluent.cs` : `VueEvenementsFluent.Ligne` ; `Siem.cs` | brut |
| Alerte de corrélation (`Destination` « incident : … », `Raisons` = résumé) | `siem.rs` : `alerte_de_correlation` | vues des alertes | brut |
| `Evenement.Message` du mini-SIEM | `siem.rs` | `Fluent.cs` : `VueEvenementsFluent.Ligne` ; `Siem.cs` | brut |

### Santé, collectes, exposition

| Champ | Produit par | Affiché par | Traduction |
|---|---|---|---|
| `EtatCollecte.Raison` (« Sysmon absent ou son journal inactif »…) | `collectes.rs` : `evaluer` ; appelants dans `evenements.rs`, `processus.rs`, `moniteur.rs`, `capture.rs`, `hygiene.rs` | `Commun.cs` : `Couverture.Detail` ; `Fluent.cs` : `VueReseauFluent.Panne`, `VueAssistantFluent.Verification` ; `Incidents.cs` : `VueSante.Lignes` | brut (nom et état traduits) |
| `Etat.ProtectionDonnees` | `protection.rs` | `Incidents.cs` : `VueSante.Lignes` | brut |
| Noms des outils de prise en main dans les pastilles | `surveillances.rs` | `Gui.cs` : en-tête | noms propres |
| `Diagnostic.Constats[].Texte` (« pare-feu de Windows actif, connexions entrantes bloquées par défaut… ») | `parefeu.rs` : `diagnostiquer` | `Fluent.cs` : `VueParefeuFluent.DetailVerdict`, `LignesPourquoi` | brut (piste et état traduits) |
| `Exposition.Raisons` | `parefeu.rs` : `LecteurJournal::bilan` | `Fluent.cs` : `VueParefeuFluent` | brut |
| `Exposition.Base` (inclut le texte UPnP) | `parefeu.rs` : `bilan` | `Fluent.cs` : « Repose sur » ; `Gui.cs` | brut ; l'interface y cherche aussi le texte UPnP (`UpnpVerifie`) |
| `EntreeExposee.Action` (« ACCEPTÉ », « BLOQUÉ ») | `parefeu.rs` | `Fluent.cs` : `VueParefeuFluent.Ligne` ; `Gui.cs` | code brut |
| `EvenementRegle.Operation`, `Sens`, `Action` (« ajoutée », « entrant », « autoriser (contournement) ») | `parefeu.rs` : `sens`, `action`, `traduire` | `Fluent.cs` : `VueParefeuFluent.Ligne`, `Description` ; `Gui.cs` | brut |

### Réponses, blocages, quarantaine, mises à jour, remontée

| Champ | Produit par | Affiché par | Traduction |
|---|---|---|---|
| `ActionEnCours.Declencheur` (« automatique : leurre », « administrateur ») | `politique.rs` | `Reponses.cs` : `VueReponses.Lignes` ; `Fluent.cs` : `VueReponsesFluent.Detail` | brut |
| `Blocage.Raison` (« blocage automatique : … », IPS, raison de la commande) | `moniteur.rs` ; pour un blocage manuel, raison rédigée en français par l'interface (`Gui.cs`) et renvoyée | `Fluent.cs` : `PageBlocagesFluent`, `VueBlocagesFluent.Detail` ; `Gui.cs` | brut |
| `ElementQuarantaine.Raison` | `reponse.rs` (raison venue de la commande) | `Fluent.cs` ; `Gui.cs` | brut |
| `EtatMaj.Statut` (« à jour », « version … disponible… », échec du manifeste) | `maj.rs` : `statut_comparaison`, `texte_echec_manifeste`, vérification, `publier` | `Reglages.cs` : `ActionsReglages.TexteMaj` ; `Incidents.cs` : `VueSante.LigneMaj` | brut |
| `DerniereErreur` des notifications (peut citer le serveur distant) | `notifications.rs` | `Reglages.cs` : `TexteNotifications` ; `Incidents.cs` : `VueSante.Lignes` | brut |
| Contenu envoyé au prestataire (ntfy, Teams, SMTP, syslog) | `notifications.rs` : `alerte` ; `export.rs` : `alerte` | hors interface | français |

### Détection réseau, réseau local, autres pages

| Champ | Produit par | Affiché par | Traduction |
|---|---|---|---|
| `DetectionIds.Message`, `Classe` (message des règles Suricata, souvent anglais) | `ids.rs` | `Fluent.cs` : `VueDetectionFluent.Lignes` ; `Reseau.cs` | brut |
| `SessionDpi.Remarque` (« identifiants en clair », « empreinte JA3 malveillante : … ») | `dpi.rs` | `Fluent.cs` : `VueDetectionFluent.Session` | brut |
| `EtatReseau.Upnp` (« aucune box UPnP ne répond… ») | `ndr.rs`, `upnp.rs` : `redirections` | `Fluent.cs` : `PageReseauLocalFluent` | brut |
| `EtatReseau.ResultatLeurre` | `ndr.rs` | `Fluent.cs` : `VueReseauLocalFluent.Resume` ; `Reseau.cs` | brut ; l'interface y cherche « RÉPONSE » |
| `FluxInfo.Raisons`, `Origine` (« téléchargé depuis Internet… ») | `moniteur.rs`, `reponse.rs` | `Fluent.cs` : `VueConnexionsFluent.Detail` ; `Gui.cs` : `RemplirFlux` | brut ; l'interface y cherche « MENACE », « BLOQUÉ » |
| `NoeudChaine.Raisons` | `chaines.rs` | `Fluent.cs` : `VueChainesFluent.Detail` ; `Gui.cs` | brut |
| Baseline : `Categorie`, `Titre`, `Pourquoi`, `Compat`, `Actuel`, `Attendu`, `Message`, état (« conforme », « non conforme ») | `baseline.rs` | `Fluent.cs` : `PageBaselineFluent`, `VueBaselineFluent` ; `Gui.cs` | brut |
| Démarrage automatique : `Remarque` (« NON SIGNÉ », « lancé via … »), `Categorie` | `persistance.rs` : `evaluer` | `Fluent.cs` : `VueDemarrageFluent` ; `Gui.cs` | brut |
| Listes de menaces : `Statut` (« pas encore téléchargée », « rejetée : … »), `Confiance`, `Licence` | `menaces.rs` | `Fluent.cs` : `VueMenacesFluent.Detail`, `PageMenacesFluent` ; `Gui.cs` | brut (étiquette courte traduite) ; l'interface teste `StartsWith("désactivée")` |
| Filtrage DNS : catégorie (« sécurité », « publicité et pistage »), état | `filtrage.rs` : `Categorie::libelle` | `Fluent.cs` : `VueNavigationFluent.Lignes` | brut (état traduit pour une liste fixe) |
| Caméra et micro : `Peripherique` | `surveillances.rs` | `Fluent.cs` : `VueVieFluent.Lignes` ; `Gui.cs` | brut |

### Réponses du canal et journal

| Texte | Produit par | Affiché par | Traduction |
|---|---|---|---|
| `Reponse.Message` des commandes (« Commande refusée : … », « Connexions sortantes vers … bloquées… ») | `canal.rs` ; `moniteur.rs` : `executer`, `executer_action` ; erreurs relayées de `notifications.rs`, `filtrage.rs`, `politique.rs`, `reponse.rs`, `maj.rs` | `Gui.cs` : `Canal.Afficher`, dans l'assistant élevé | `L.T` (quelques phrases fixes au dictionnaire, aucun texte composé) |
| `journal.txt` | `commun::journal`, tout le service | exporté tel quel (`Reglages.cs` : `ExporterJournal`), ouvert tel quel (`Gui.cs`) | français |

Codes déjà rendus par un texte fixe bilingue, hors de l'inventaire : niveau des alertes, des incidents, des événements
et des détections ; état, piste et verdict de l'exposition ; état et identifiant des collectes ; registre des
réponses ; mode panique ; contrôle des mises à jour ; sorte et état des réponses ; état et motif des incidents ;
étiquette courte des listes de menaces.

Logique de l'interface qui dépend du texte français du service, à garder en tête pour l'étape 2 : « MENACE » et
« BLOQUÉ » dans `FluxInfo.Raisons`, « RÉPONSE » dans `ResultatLeurre`, le texte UPnP dans `Exposition.Base`,
`StartsWith("désactivée")` sur le statut d'une liste de menaces, `EtatTexte` du filtrage.
