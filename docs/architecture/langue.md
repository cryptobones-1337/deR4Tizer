# Interface language

State as of 2026-11-23 (finding T-17, step 1). A description of the code as it is.

## 1. Choice of language (step 1)

A single decision, `L.Choisir` (`src/Langue.cs`), called once at start by `Programme.ChoisirLangue`
(`src/Gui.cs`), before any window. It sets `L.En` (displayed language) and `L.Reglage` (setting in force) for the whole
process: WPF interface, classic interface (`--classique`), hidden window of the notification area, local
notifications, and elevated assistant (same executable, `--commande-fichier`). No other assignment of `L.En`; the Windows
culture is read only by `L.CultureAnglaise` (`tests/test-langue.ps1` checks it).

Order of decision:

1. Elevated assistant: language passed by the interface that launches it (`--commande-fichier <fichier> --langue fr|en`). It
   runs under another account (a standard account that types an administrator's password) or another elevation:
   its culture is not the user's. The setting file of the elevated account is never read. A value other than
   "fr" and "en": ignored. Launched without `--langue` (by a previous version): config.json then culture, as
   before. Its arguments are fixed: a `--dossier` among them is not an option (`Programme.DossierDemande`, audit of
   #298, A298-2). The elevated interface never applies `--dossier` either, and the non-elevated interface only on a
   fixed local disk (audit of #298, A298-3): under an administrator token, config.json is always read in the normal data
   folder.
2. User setting, `%LOCALAPPDATA%\deR4Tizer\langue.txt`: `auto`, `fr` or `en` (any other value, or a
   file of more than 64 bytes, is ignored). Written and read by the non-elevated interface only: never under an
   administrator token, neither for writing nor for reading (the folder is controlled by the account's non-elevated
   programs, same rule as the first-settings marker, S151-01; audit of #298, A298-1). An elevated interface therefore
   follows config.json then the culture. Read on a single handle opened without following a reparse point
   (`FILE_FLAG_OPEN_REPARSE_POINT`): link, junction or folder refused, 65 bytes read at most. No command, nothing
   is sent to the service.
3. Without a user setting: "en" if `config.json` holds `"Langue": "en"`, the only explicit choice a previous
   version may have left there. "fr" there does not express a choice: it is also the default value the service writes with
   any setting (IPS, filtering, update…), and it forced French on an English Windows.
4. Otherwise, automatic: French for any French display culture of the user (`fr-FR`, `fr-CA`…),
   English for any other.

Data format unchanged: `config.json` keeps its `Langue` field, sent back when the Settings page saves the
syslog and the API (`ActionsReglages.Composer`): "en" kept, any other value (null, empty, "EN"…) brought back to "fr",
which the service accepts (closed list; otherwise it would refuse every save). The confirmation of this command
says so: "langue gardée dans config.json (sans effet sur la langue affichée)".

Consequence: a "Français" chosen by a previous version under a non-French Windows is not kept (it has to be
chosen again in Settings).

Settings page (WPF and classic): three values, "Automatique (Windows : <langue>)", "Français", "English". The
active value is the setting in force in this process, never the default value of `config.json` (finding T-13:
"Français" selected in an English interface). The "Automatique" label says which language it gives on this
computer. Below the choice, the displayed language is always stated; a choice saved since then is stated separately ("Choix
enregistré : Français, appliqué au prochain lancement de l'interface") and, in the WPF page, its button has a grey
border. In the classic interface, the choice is written on validation (list closed, leaving the field, Enter), not on
each change of selection: the arrow keys go through the three values. The change does not apply without restarting
the interface: the pages are built in the language of the start. As administrator, nothing is read or written and the
page says so.

Fixed in the same step (interface texts, not service texts):

- Firewall page: the state of a check said "not found" ("pas constaté"); next to "Windows Firewall", it
  read "pare-feu introuvable" whereas the service published the firewall as active (`parefeu.rs:diagnostiquer`, state
  `pas_constate`: no issue found). Cause in the interface (`VueParefeuFluent.Etat`), not in the reading nor
  in the service: the state now says "no issue found" / "rien relevé", "issue found" / "constaté";
- local notification of several alerts ("2 nouvelles alertes") and balloon of the icon near the clock, which
  stayed in French (`Fenetre.TexteNotification`, `Fenetre.TexteIcone`);
- levels ("Critique", "Alerte", "Info") displayed raw in the list of incidents (WPF and classic), the
  mini-SIEM, the IDS detections and the classic list of alerts: now passed through `L.T`.

Limit: a non-elevated program that launches the assistant itself (it needs a deR4Tizer command file in
`%LOCALAPPDATA%\deR4Tizer` and the consent of the UAC prompt) chooses the language of the confirmation, between French and English
only; the content of the confirmation, the delays and the banner of the commands that weaken protection do not change.

Tests: `tests/test-langue.ps1` (pure decisions; one process per culture, en-US and fr-FR, without `config.json` or
setting, which builds off screen the WPF and classic Settings pages, the window of the elevated assistant and the local
notification; `-Rendus`: off-screen images). Not checked in an open Windows session nor behind a real UAC prompt (VM).

## 2. Service texts displayed as they are (inventory, step 2 not started)

The service writes its texts in French. The interface displays them as they are, under translated headings: `Canal.Visible`
neutralizes characters without translating anything ("raw" below); `L.T` only translates an exact sentence present
in `src/Langue.cs` (a text built by `format!` is never there). Nothing is translated in this step. Step 2
is a separate phase, to be proposed to the maintainer: message codes and parameters, tested FR/EN tables, compatibility
of saved alerts, learning signature independent of the text, language of escalation chosen by the
administrator.

Paths: service under `service-rs/src/`, interface under `src/`.

### Alerts (`alertes.json`)

| Field | Produced by (service) | Displayed by (interface) | Translation |
|---|---|---|---|
| `Raisons` of flows ("MENACE CONNUE (…), NON SIGNÉ, IP DIRECTE…") | `moniteur.rs`: `score_flux`, `ajouter_alerte` | `Fluent.cs`: `VueAlertesFluent.Detail`; `Gui.cs`: `RemplirAlertes`, `DetaillerAlerte` | raw |
| `Raisons` of the other rules (free text) | `alerte()` in `defender.rs`, `hygiene.rs`, `surveillances.rs`; `persistance.rs`: `alerter`; `baseline.rs`, `chaines.rs`, `dns_surveillance.rs`, `parefeu.rs`: `traduire`, `ids.rs`, `dpi.rs` / `ndr.rs`: `alerter`, `sante.rs`, `vol_donnees.rs`, `politique.rs`, `protection.rs`, `reponse.rs`, `canal.rs`, `moniteur.rs` | same views | raw |
| `Destination` built by the service ("mode panique", "baseline : …", "incident : …", "IDS : …") | same files | `Fluent.cs`: list card, `VueAlertesFluent.Detail`; `Gui.cs`: `RemplirAlertes` | raw |
| `Processus` (sometimes "?" or a service label) | `moniteur.rs`, `dns_surveillance.rs` | `Fluent.cs`: list of alerts | raw |
| `Conseil` | `mitre.rs`: `enrichir`, table `CONSEILS` | `Fluent.cs`: `VueAlertesFluent.Detail`; `Gui.cs`: `DetaillerAlerte` | `L.T` (fixed texts in the dictionary) |
| `Mitre` | `mitre.rs`: `libelle` | `L.Mitre` in `Fluent.cs` and `Gui.cs` | `L.T` per technique |
| Local notification: title `Processus`, text `Destination : Raisons` | (fields above) | `Gui.cs`: `Fenetre.TexteNotification` | raw (level and count translated) |
| Confirmation of an exception: `Processus`, `Destination`, `Raisons` | (fields above) | `Gui.cs`: `Canal.Decrire`, case `exception` | raw |

### Incidents and correlation

| Field | Produced by | Displayed by | Translation |
|---|---|---|---|
| `ResumeAlerte.Raisons`, `Destination` | `incidents.rs` (copy of the alert) | `Incidents.cs`: `VueIncidents.Detail`; `Fluent.cs`: `PageIncidentsFluent` | raw |
| `ElementChronologie.Texte` ("processus : raisons", transitions "Ouvert vers Clos… (par S-1-5-…)", event message) | `incidents.rs` (timeline) | `Incidents.cs`: `VueIncidents.Detail` | raw, with Rust enumeration names |
| `ElementChronologie.Source` (`alerte`, `transition`, `reponse`…) | `incidents.rs` | `Incidents.cs`: `VueIncidents.Detail` | raw code |
| Correlation incident: `Titre`, `Resume` | `siem.rs`: `analyser` | `Fluent.cs`: `VueEvenementsFluent.Ligne`; `Siem.cs` | raw |
| Correlation alert (`Destination` "incident : …", `Raisons` = summary) | `siem.rs`: `alerte_de_correlation` | alert views | raw |
| `Evenement.Message` of the mini-SIEM | `siem.rs` | `Fluent.cs`: `VueEvenementsFluent.Ligne`; `Siem.cs` | raw |

### Health, collections, exposure

| Field | Produced by | Displayed by | Translation |
|---|---|---|---|
| `EtatCollecte.Raison` ("Sysmon absent ou son journal inactif"…) | `collectes.rs`: `evaluer`; callers in `evenements.rs`, `processus.rs`, `moniteur.rs`, `capture.rs`, `hygiene.rs` | `Commun.cs`: `Couverture.Detail`; `Fluent.cs`: `VueReseauFluent.Panne`, `VueAssistantFluent.Verification`; `Incidents.cs`: `VueSante.Lignes` | raw (name and state translated) |
| `Etat.ProtectionDonnees` | `protection.rs` | `Incidents.cs`: `VueSante.Lignes` | raw |
| Names of remote-control tools in the badges | `surveillances.rs` | `Gui.cs`: header | proper names |
| `Diagnostic.Constats[].Texte` ("pare-feu de Windows actif, connexions entrantes bloquées par défaut…") | `parefeu.rs`: `diagnostiquer` | `Fluent.cs`: `VueParefeuFluent.DetailVerdict`, `LignesPourquoi` | raw (track and state translated) |
| `Exposition.Raisons` | `parefeu.rs`: `LecteurJournal::bilan` | `Fluent.cs`: `VueParefeuFluent` | raw |
| `Exposition.Base` (includes the UPnP text) | `parefeu.rs`: `bilan` | `Fluent.cs`: "Repose sur"; `Gui.cs` | raw; the interface also looks for the UPnP text in it (`UpnpVerifie`) |
| `EntreeExposee.Action` ("ACCEPTÉ", "BLOQUÉ") | `parefeu.rs` | `Fluent.cs`: `VueParefeuFluent.Ligne`; `Gui.cs` | raw code |
| `EvenementRegle.Operation`, `Sens`, `Action` ("ajoutée", "entrant", "autoriser (contournement)") | `parefeu.rs`: `sens`, `action`, `traduire` | `Fluent.cs`: `VueParefeuFluent.Ligne`, `Description`; `Gui.cs` | raw |

### Responses, blocks, quarantine, updates, escalation

| Field | Produced by | Displayed by | Translation |
|---|---|---|---|
| `ActionEnCours.Declencheur` ("automatique : leurre", "administrateur") | `politique.rs` | `Reponses.cs`: `VueReponses.Lignes`; `Fluent.cs`: `VueReponsesFluent.Detail` | raw |
| `Blocage.Raison` ("blocage automatique : …", IPS, reason of the command) | `moniteur.rs`; for a manual block, reason written in French by the interface (`Gui.cs`) and sent back | `Fluent.cs`: `PageBlocagesFluent`, `VueBlocagesFluent.Detail`; `Gui.cs` | raw |
| `ElementQuarantaine.Raison` | `reponse.rs` (reason coming from the command) | `Fluent.cs`; `Gui.cs` | raw |
| `EtatMaj.Statut` ("à jour", "version … disponible…", manifest failure) | `maj.rs`: `statut_comparaison`, `texte_echec_manifeste`, verification, `publier` | `Reglages.cs`: `ActionsReglages.TexteMaj`; `Incidents.cs`: `VueSante.LigneMaj` | raw |
| `DerniereErreur` of notifications (may quote the remote server) | `notifications.rs` | `Reglages.cs`: `TexteNotifications`; `Incidents.cs`: `VueSante.Lignes` | raw |
| Content sent to the provider (ntfy, Teams, SMTP, syslog) | `notifications.rs`: `alerte`; `export.rs`: `alerte` | outside the interface | French |

### Network detection, local network, other pages

| Field | Produced by | Displayed by | Translation |
|---|---|---|---|
| `DetectionIds.Message`, `Classe` (message of the Suricata rules, often English) | `ids.rs` | `Fluent.cs`: `VueDetectionFluent.Lignes`; `Reseau.cs` | raw |
| `SessionDpi.Remarque` ("identifiants en clair", "empreinte JA3 malveillante : …") | `dpi.rs` | `Fluent.cs`: `VueDetectionFluent.Session` | raw |
| `EtatReseau.Upnp` ("aucune box UPnP ne répond…") | `ndr.rs`, `upnp.rs`: `redirections` | `Fluent.cs`: `PageReseauLocalFluent` | raw |
| `EtatReseau.ResultatLeurre` | `ndr.rs` | `Fluent.cs`: `VueReseauLocalFluent.Resume`; `Reseau.cs` | raw; the interface looks for "RÉPONSE" in it |
| `FluxInfo.Raisons`, `Origine` ("téléchargé depuis Internet…") | `moniteur.rs`, `reponse.rs` | `Fluent.cs`: `VueConnexionsFluent.Detail`; `Gui.cs`: `RemplirFlux` | raw; the interface looks for "MENACE", "BLOQUÉ" in it |
| `NoeudChaine.Raisons` | `chaines.rs` | `Fluent.cs`: `VueChainesFluent.Detail`; `Gui.cs` | raw |
| `NoeudChaine.Signaux[].Raison` (T-20, same text as `Raisons`); `Lien` and `Signaux[].Code` are ASCII codes for the interface to translate | `chaines.rs` | `Fluent.cs`: Chains page (T-20, step 2): the reason is shown raw (French view; English view: under "Service text"); the code is shown as an English label per rule identifier (`VueChainesFluent.LibelleSignal`, titles of `docs/detection/regles.md`), the raw reason when the rule is not in the table; `Lien` as a sentence in both languages (`VueChainesFluent.TexteLien`) | raw (reason); translated (code, link) |
| Baseline: `Categorie`, `Titre`, `Pourquoi`, `Compat`, `Actuel`, `Attendu`, `Message`, state ("conforme", "non conforme") | `baseline.rs` | `Fluent.cs`: `PageBaselineFluent`, `VueBaselineFluent`; `Gui.cs` | raw |
| Automatic start: `Remarque` ("NON SIGNÉ", "lancé via …"), `Categorie` | `persistance.rs`: `evaluer` | `Fluent.cs`: `VueDemarrageFluent`; `Gui.cs` | raw |
| Threat lists: `Statut` ("pas encore téléchargée", "rejetée : …"), `Confiance`, `Licence` | `menaces.rs` | `Fluent.cs`: `VueMenacesFluent.Detail`, `PageMenacesFluent`; `Gui.cs` | raw (short label translated); the interface tests `StartsWith("désactivée")` |
| DNS filtering: category ("sécurité", "publicité et pistage"), state | `filtrage.rs`: `Categorie::libelle` | `Fluent.cs`: `VueNavigationFluent.Lignes` | raw (state translated for a fixed list) |
| Camera and microphone: `Peripherique` | `surveillances.rs` | `Fluent.cs`: `VueVieFluent.Lignes`; `Gui.cs` | raw |

### Channel replies and log

| Text | Produced by | Displayed by | Translation |
|---|---|---|---|
| `Reponse.Message` of the commands ("Commande refusée : …", "Connexions sortantes vers … bloquées…") | `canal.rs`; `moniteur.rs`: `executer`, `executer_action`; errors relayed from `notifications.rs`, `filtrage.rs`, `politique.rs`, `reponse.rs`, `maj.rs` | `Gui.cs`: `Canal.Afficher`, in the elevated assistant | `L.T` (a few fixed sentences in the dictionary, no built text) |
| `journal.txt` | `commun::journal`, the whole service | exported as it is (`Reglages.cs`: `ExporterJournal`), opened as it is (`Gui.cs`) | French |

Codes already rendered by a fixed bilingual text, outside the inventory: level of alerts, incidents, events
and detections; state, track and verdict of the exposure; state and identifier of the collections; register of
responses; panic mode; update check; kind and state of responses; state and reason of incidents;
short label of the threat lists.

Interface logic that depends on the French text of the service, to keep in mind for step 2: "MENACE" and
"BLOQUÉ" in `FluxInfo.Raisons`, "RÉPONSE" in `ResultatLeurre`, the UPnP text in `Exposition.Base`,
`StartsWith("désactivée")` on the status of a threat list, `EtatTexte` of filtering.
