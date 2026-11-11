// Page Réglages : langue, envoi des alertes en syslog, API d'export et export des journaux.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace DeR4Tizer
{
    // Actions de la page Réglages (U6c), partagées par la page d'aujourd'hui et celle de la coquille : mêmes commandes,
    // mêmes contrôles de saisie. Jamais d'enregistrement sur une configuration illisible (audit de #139, S139-02, étendu) ;
    // les textes venus du service ou d'un serveur (statut de mise à jour, erreur d'envoi, noms de comptes) sont neutralisés
    public static class ActionsReglages
    {
        public static readonly string[] Niveaux = { "Info", "Alerte", "Critique" };
        public static readonly string[] Protocoles = { "UDP", "TCP" };
        public static readonly string[] Formats = { "JSON", "CEF" };
        public static readonly string[] Securites = { "SSL", "STARTTLS" };
        static readonly string[] OperationsApprentissage = { "terminer", "recommencer", "oublier" };

        public static string Choix(string valeur, string[] permis) { return Array.IndexOf(permis, valeur) >= 0 ? valeur : permis[0]; }

        public static string ConfigIllisible()
        {
            return L.En ? "config.json unreadable: the settings are unknown; nothing is saved until it can be read."
                        : "config.json illisible : réglages inconnus ; rien n'est enregistré tant qu'il n'est pas lu.";
        }

        // null si les ports sont valides (syslog : 1 à 65535, API : 1024 à 65535), sinon le message
        public static string PortsInvalides(string syslog, string api, out int portSyslog, out int portApi)
        {
            bool ok = int.TryParse((syslog ?? "").Trim(), out portSyslog) & int.TryParse((api ?? "").Trim(), out portApi);
            if (ok && portSyslog >= 1 && portSyslog <= 65535 && portApi >= 1024 && portApi <= 65535) return null;
            return L.En ? "Invalid port (syslog: 1-65535, API: 1024-65535)." : "Port invalide (syslog : 1 à 65535, API : 1024 à 65535).";
        }

        // null si valides (messages par heure : 1 à 1000, port SMTP : 1 à 65535), sinon le message
        public static string NotificationsInvalides(string maxHeure, string port, out int max, out int portSmtp)
        {
            bool ok = int.TryParse((maxHeure ?? "").Trim(), out max) & int.TryParse((port ?? "").Trim(), out portSmtp);
            if (ok && max >= 1 && max <= 1000 && portSmtp >= 1 && portSmtp <= 65535) return null;
            return L.En ? "Invalid number (messages per hour: 1-1000, port: 1-65535)." : "Nombre invalide (messages par heure : 1 à 1000, port : 1 à 65535).";
        }

        // Réglages à enregistrer : la configuration lue, avec la langue, le syslog et l'API saisis ; null si elle est illisible
        public static Config Composer(Config lue, bool anglais, ConfigSyslog syslog, ConfigApi api)
        {
            if (lue == null) return null;
            lue.Langue = anglais ? "en" : "fr";
            lue.Syslog = syslog;
            lue.Api = api;
            return lue;
        }

        public static bool Enregistrer(Config c)
        {
            if (c == null) { MessageBox.Show(ConfigIllisible(), "deR4Tizer", MessageBoxButtons.OK, MessageBoxIcon.Warning); return false; }
            Canal.Executer(new Commande { Action = "reglages", Valeur = Commun.Json().Serialize(c) });
            return true;
        }

        public static void TesterSyslog(ConfigSyslog s) { if (s != null) Canal.Executer(new Commande { Action = "testerSyslog", Valeur = Commun.Json().Serialize(s) }); }

        // Commande d'apprentissage, liste fermée ; la même sert à la confirmation de l'assistant (audit de #152, S152-01)
        public static Commande CommandeApprentissage(string operation)
        {
            if (Array.IndexOf(OperationsApprentissage, operation) < 0) return null;
            return new Commande { Action = "apprentissage", Valeur = operation };
        }

        public static void Apprentissage(string operation)
        {
            var c = CommandeApprentissage(operation);
            if (c != null) Canal.Executer(c);
        }

        public static void AfficherJeton() { Canal.Executer(new Commande { Action = "jetonApi" }); }

        public static bool NouveauJeton()
        {
            if (MessageBox.Show(L.T("Remplacer le jeton ? Les outils qui utilisent l'ancien devront être mis à jour."), "deR4Tizer", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return false;
            Canal.Executer(new Commande { Action = "nouveauJeton" });
            return true;
        }

        public static void MajConfig(bool auto, string url) { Canal.Executer(new Commande { Action = "majConfig", Valeur = Commun.Json().Serialize(new ConfigMaj { Auto = auto, Url = (url ?? "").Trim() }) }); }

        public static void MajVerifier() { Canal.Executer(new Commande { Action = "majVerifier" }); }

        // Notifications : « notifications » enregistre, « testerNotifications » envoie un message de test ; rien d'autre
        // Commande des notifications, deux actions seulement ; secrets vides : le service garde ceux qu'il a. La même sert au
        // message de test de « Premiers réglages » (U7c), comme CommandeApprentissage (audit de #152, S152-01)
        public static Commande CommandeNotifications(string action, ConfigNotifications c, string ntfyUrl, string ntfyJeton, string teamsUrl, string smtpMotDePasse)
        {
            if ((action != "notifications" && action != "testerNotifications") || c == null) return null;
            var demande = new Dictionary<string, object>
            {
                { "Config", c }, { "NtfyUrl", (ntfyUrl ?? "").Trim() }, { "NtfyJeton", (ntfyJeton ?? "").Trim() },
                { "TeamsUrl", (teamsUrl ?? "").Trim() }, { "SmtpMotDePasse", smtpMotDePasse ?? "" }
            };
            return new Commande { Action = action, Valeur = Commun.Json().Serialize(demande) };
        }

        public static void Notifications(string action, ConfigNotifications c, string ntfyUrl, string ntfyJeton, string teamsUrl, string smtpMotDePasse)
        {
            var commande = CommandeNotifications(action, c, ntfyUrl, ntfyJeton, teamsUrl, smtpMotDePasse);
            if (commande != null) Canal.Executer(commande);
        }

        // Identifiant de sécurité d'un compte local saisi, ou null s'il est introuvable
        public static string Sid(string compte)
        {
            if (string.IsNullOrWhiteSpace(compte)) return null;
            try { return new System.Security.Principal.NTAccount(compte.Trim()).Translate(typeof(System.Security.Principal.SecurityIdentifier)).Value; }
            catch { return null; }
        }

        public static void AutoriserLecteur(string sid) { if (!string.IsNullOrEmpty(sid)) Canal.Executer(new Commande { Action = "autoriserLecteur", Valeur = sid }); }

        // Champ CSV : une valeur qui commence par =, +, -, @, une tabulation ou un retour chariot serait prise pour une formule
        // par un tableur (un nom de programme ou un chemin vient d'un programme) : préfixée d'une apostrophe (U6c). Le premier
        // caractère compte après les espaces et les caractères invisibles de tête, qu'un tableur ou un import peut rogner
        // (audit de #147, S147-01)
        public static string ChampCsv(object v)
        {
            string s = v == null ? "" : v.ToString();
            int i = 0;
            while (i < s.Length && s[i] != '\t' && s[i] != '\r' && (char.IsWhiteSpace(s[i]) || char.GetUnicodeCategory(s[i]) == System.Globalization.UnicodeCategory.Format)) i++;
            if (i < s.Length && "=+-@\t\r".IndexOf(s[i]) >= 0) s = "'" + s;
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        }

        public static string Csv(IEnumerable<Alerte> alertes)
        {
            var sb = new StringBuilder("Heure;Niveau;Score;Programme;Destination;Port;Raisons;MITRE;Chemin;PID\r\n");
            foreach (var a in alertes ?? new List<Alerte>())
                if (a != null) sb.AppendLine(string.Join(";", new[] { ChampCsv(a.Heure), ChampCsv(a.Niveau), ChampCsv(a.Score), ChampCsv(a.Processus), ChampCsv(a.Destination),
                    ChampCsv(a.Port), ChampCsv(a.Raisons), ChampCsv(a.Mitre), ChampCsv(a.Chemin), ChampCsv(a.Pid) }));
            return sb.ToString();
        }

        public static void ExporterAlertes(string fichier, bool csv)
        {
            var alertes = Commun.Lire<List<Alerte>>("alertes.json") ?? new List<Alerte>();
            if (csv) File.WriteAllText(fichier, Csv(alertes), new UTF8Encoding(true));
            else File.WriteAllText(fichier, Commun.Json().Serialize(alertes), new UTF8Encoding(false));
        }

        // null si la copie a réussi, sinon le message
        public static string ExporterJournal(string fichier)
        {
            try { File.Copy(Path.Combine(Commun.Dossier, "journal.txt"), fichier, true); return null; }
            catch (Exception e) { return e.Message; }
        }

        public static string NomExport(string quoi) { return "deR4Tizer-" + quoi + "-" + DateTime.Now.ToString("yyyyMMdd-HHmm"); }

        public static string TexteApprentissage(EtatApprentissage app)
        {
            if (app == null) return "";
            bool en = L.En;
            bool enCours = string.CompareOrdinal(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), app.Fin ?? "") < 0;
            return string.Format(en ? "{0} · {1} learned behaviour(s) · {2} exception(s)" : "{0} · {1} comportement(s) appris · {2} exception(s)",
                (enCours ? (en ? "Learning until " : "Apprentissage jusqu'au ") : (en ? "Learning finished on " : "Apprentissage terminé le ")) + Canal.Visible(app.Fin),
                (app.Appris ?? new List<string>()).Count, (app.Exceptions ?? new List<ExceptionApprise>()).Count);
        }

        public static string TexteMaj(EtatMaj em)
        {
            bool en = L.En;
            return (en ? "Installed version: " : "Version installée : ") + Commun.Version
                + (em != null && !em.CleEpinglee ? (en ? " · no signing key pinned in this version: updates are only reported" : " · aucune clé de signature épinglée dans cette version : les mises à jour sont seulement signalées") : "")
                + (em == null ? (en ? " · not checked yet (daily check)" : " · pas encore vérifiée (vérification quotidienne)")
                    : " · " + (en ? "checked on " : "vérifiée le ") + Canal.Visible(em.VerifieLe) + " : " + Canal.Visible(em.Statut));
        }

        // Dernière erreur d'envoi : elle reprend ce qu'un serveur a répondu ; neutralisée
        public static string TexteNotifications(EtatNotifications e)
        {
            if (e == null) return "";
            bool en = L.En;
            Func<bool, string> fait = b => b ? L.T("enregistrée") : L.T("non renseignée");
            return string.Format(en ? "ntfy address: {0} · Teams webhook: {1} · SMTP password: {2} · {3} message(s) sent{4}{5}" : "Adresse ntfy : {0} · webhook Teams : {1} · mot de passe SMTP : {2} · {3} message(s) envoyé(s){4}{5}",
                fait(e.NtfyConfigure), fait(e.TeamsConfigure), fait(e.SmtpMotDePasse), e.Envoyes,
                string.IsNullOrEmpty(e.DernierEnvoi) ? "" : (en ? ", last on " : ", dernier le ") + Canal.Visible(e.DernierEnvoi),
                string.IsNullOrEmpty(e.DerniereErreur) ? "" : (en ? " · last error: " : " · dernière erreur : ") + Canal.Visible(e.DerniereErreur));
        }

        public static string TexteLecteurs(List<Lecteur> lecteurs)
        {
            var l = (lecteurs ?? new List<Lecteur>()).Where(x => x != null).ToList();
            return L.T("Les événements, sessions, alertes et appareils du réseau ne sont lisibles que par SYSTEM, les administrateurs et ces comptes :")
                + " " + (l.Count == 0 ? "—" : string.Join(", ", l.Select(x => Canal.Visible(x.Nom))));
        }
    }

    class PageReglages : Panel
    {
        readonly ComboBox cbLangue = Liste("Français", "English");
        readonly CheckBox chkSyslog = Case("Envoyer les alertes à un serveur syslog / SIEM");
        readonly TextBox txtHote = Saisie(220), txtPortSyslog = Saisie(70);
        readonly ComboBox cbProtocole = Liste("UDP", "TCP"), cbFormat = Liste("JSON", "CEF"), cbNiveau = Liste("Info", "Alerte", "Critique");
        readonly CheckBox chkApi = Case("Activer l'API d'export"), chkReseau = Case("Accessible depuis le réseau local (sinon cet ordinateur seulement)");
        readonly TextBox txtPortApi = Saisie(70), txtAdressesApi = Saisie(300);
        readonly ComboBox cbNiveauNotif = Liste("Info", "Alerte", "Critique");
        readonly Label lblApprentissage = new Label { AutoSize = true, ForeColor = Theme.Texte, Font = Theme.Petit, MaximumSize = new Size(900, 0), Margin = new Padding(0, 4, 0, 4) };
        readonly Label lblMaj = new Label { AutoSize = true, ForeColor = Theme.Texte, Font = Theme.Petit, MaximumSize = new Size(900, 0), Margin = new Padding(0, 4, 0, 4) };
        readonly CheckBox chkMajAuto = Case("Installer automatiquement une version signée par la clé épinglée dans deR4Tizer (révocation vérifiée)");
        readonly TextBox txtMajUrl = Saisie(520);
        readonly TextBox txtMaxHeure = Saisie(50);
        readonly CheckBox chkNtfy = Case("ntfy (application mobile ou de bureau, serveur public ou auto-hébergé)");
        // Adresse ntfy masquée comme les autres secrets : le nom du sujet sert souvent de secret (audit de #147, S147-02)
        readonly TextBox txtNtfyUrl = Secret(360), txtNtfyJeton = Secret(220);
        readonly CheckBox chkTeams = Case("Microsoft Teams (webhook d'un flux de travail « publier dans un canal »)");
        readonly TextBox txtTeamsUrl = Secret(520);
        readonly CheckBox chkSmtp = Case("E-mail (SMTP chiffré)");
        readonly TextBox txtSmtpServeur = Saisie(220), txtSmtpPort = Saisie(60), txtSmtpUtilisateur = Saisie(220), txtSmtpMotDePasse = Secret(160),
            txtExpediteur = Saisie(220), txtDestinataires = Saisie(360);
        readonly ComboBox cbSmtpSecurite = Liste("SSL", "STARTTLS");
        readonly Label lblNotif = new Label { AutoSize = true, ForeColor = Theme.TexteDim, Font = Theme.Petit, MaximumSize = new Size(900, 0), Margin = new Padding(0, 4, 0, 4) };
        // config.json illisible : dit en tête, et « Enregistrer » refuse (S139-02 étendu, U6c)
        readonly Label lblConfig = new Label { AutoSize = true, ForeColor = Theme.Jaune, Font = Theme.Petit, MaximumSize = new Size(900, 0), Margin = new Padding(0, 4, 0, 4) };
        readonly Label lblLecteurs = new Label { AutoSize = true, ForeColor = Theme.TexteDim, Font = Theme.Petit, MaximumSize = new Size(900, 0), Margin = new Padding(0, 2, 0, 6) };
        Config config;
        bool configIllisible;

        public PageReglages()
        {
            Dock = DockStyle.Fill;
            BackColor = Theme.Fond;
            AutoScroll = true;
            Visible = false;
            Theme.DefilementSombre(this);

            var pile = new FlowLayoutPanel
            {
                FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Location = new Point(0, 0),
                Padding = new Padding(22, 14, 22, 16), BackColor = Theme.Fond
            };
            pile.Controls.Add(Theme.TitreDePage(L.T("Réglages"), new Padding(0, 0, 0, 2)));
            pile.Controls.Add(Note("Langue, envoi des alertes à un SIEM (syslog), API d'export et export des journaux."));
            pile.Controls.Add(lblConfig);

            // ---------------- Langue
            pile.Controls.Add(Section("LANGUE"));
            pile.Controls.Add(Ligne(Etiquette("Langue de l'interface"), cbLangue));
            pile.Controls.Add(Note("La langue s'applique au prochain lancement de l'interface."));

            // ---------------- Mode apprentissage et exceptions
            pile.Controls.Add(Section("MODE APPRENTISSAGE ET EXCEPTIONS"));
            pile.Controls.Add(Note("Les premiers jours, les alertes non critiques sont notées en information et leur comportement est mémorisé (logiciel de caisse, outils du prestataire, scripts…). Ensuite, seul un comportement nouveau alerte. Les alertes critiques ne sont jamais adoucies. Clic droit sur une alerte : « Ne plus alerter pour ce comportement »."));
            pile.Controls.Add(lblApprentissage);
            var btnFinApp = new BoutonNeon("Terminer l'apprentissage", Theme.TexteDim);
            btnFinApp.Click += (s, e) => { ActionsReglages.Apprentissage("terminer"); Charger(); };
            var btnReApp = new BoutonNeon("Recommencer (7 jours)", Theme.TexteDim);
            btnReApp.Click += (s, e) => { ActionsReglages.Apprentissage("recommencer"); Charger(); };
            var btnOublier = new BoutonNeon("Supprimer les exceptions", Theme.Magenta);
            btnOublier.Click += (s, e) => { ActionsReglages.Apprentissage("oublier"); Charger(); };
            pile.Controls.Add(Ligne(btnFinApp, btnReApp, btnOublier));

            // ---------------- Remontée des alertes
            pile.Controls.Add(Section("REMONTÉE DES ALERTES (PRESTATAIRE, RÉFÉRENT)"));
            pile.Controls.Add(Note("Envoie les alertes de ce poste à la personne qui s'en occupe, avec le « quoi faire ». Les alertes d'un quart de minute sont regroupées en un seul message, et un plafond par heure évite l'inondation."));
            pile.Controls.Add(Ligne(Etiquette("Niveau minimal"), cbNiveauNotif, Etiquette("Messages par heure au plus"), txtMaxHeure));
            pile.Controls.Add(chkNtfy);
            pile.Controls.Add(Note("Conseil : un serveur ntfy auto-hébergé plutôt que ntfy.sh, que des malwares utilisent aussi pour faire sortir des données (il reste joignable en mode panique)."));
            pile.Controls.Add(Ligne(Etiquette("Adresse du sujet"), txtNtfyUrl, Etiquette("Jeton (facultatif)"), txtNtfyJeton));
            pile.Controls.Add(chkTeams);
            pile.Controls.Add(Ligne(Etiquette("Adresse du webhook"), txtTeamsUrl));
            pile.Controls.Add(chkSmtp);
            pile.Controls.Add(Ligne(Etiquette("Serveur"), txtSmtpServeur, Etiquette("Port"), txtSmtpPort, Etiquette("Sécurité"), cbSmtpSecurite));
            pile.Controls.Add(Ligne(Etiquette("Utilisateur"), txtSmtpUtilisateur, Etiquette("Mot de passe"), txtSmtpMotDePasse));
            pile.Controls.Add(Ligne(Etiquette("Expéditeur"), txtExpediteur, Etiquette("Destinataires"), txtDestinataires));
            pile.Controls.Add(Note("Les adresses ntfy et Teams, le jeton et le mot de passe sont gardés à part, lisibles par les administrateurs seulement : laissez le champ vide pour conserver la valeur enregistrée, tapez « - » pour l'effacer."));
            pile.Controls.Add(lblNotif);
            var btnNotif = new BoutonNeon("Enregistrer les notifications", Theme.Cyan);
            btnNotif.Click += (s, e) => EnvoyerNotifications("notifications");
            var btnTestNotif = new BoutonNeon("Envoyer un message de test", Theme.TexteDim);
            btnTestNotif.Click += (s, e) => EnvoyerNotifications("testerNotifications");
            pile.Controls.Add(Ligne(btnNotif, btnTestNotif));

            // ---------------- Syslog
            pile.Controls.Add(Section("ENVOI DES ALERTES (SYSLOG)"));
            pile.Controls.Add(chkSyslog);
            pile.Controls.Add(Ligne(Etiquette("Serveur"), txtHote, Etiquette("Port"), txtPortSyslog, Etiquette("Protocole"), cbProtocole));
            pile.Controls.Add(Ligne(Etiquette("Format"), cbFormat, Etiquette("Niveau minimal"), cbNiveau));
            pile.Controls.Add(Note("JSON : en-tête RFC 5424 et détail en JSON. CEF : reconnu par la plupart des SIEM (Splunk, QRadar, Sentinel, Wazuh, Graylog…)."));
            var btnTester = new BoutonNeon("Tester l'envoi", Theme.TexteDim);
            btnTester.Click += (s, e) => { var c = Saisis(); if (c != null) ActionsReglages.TesterSyslog(c.Item1); };
            pile.Controls.Add(Ligne(btnTester));

            // ---------------- API
            pile.Controls.Add(Section("API D'EXPORT (HTTP, LECTURE SEULE)"));
            pile.Controls.Add(chkApi);
            pile.Controls.Add(Ligne(Etiquette("Port"), txtPortApi));
            pile.Controls.Add(chkReseau);
            pile.Controls.Add(Ligne(Etiquette("Adresses autorisées (SIEM)"), txtAdressesApi));
            pile.Controls.Add(Note("Chaque requête doit porter l'en-tête « Authorization: Bearer <jeton> ». Routes : /api/v1/alertes, /connexions, /exposition, /baseline, /regles-parefeu, /blocages, /journal."));
            var btnJeton = new BoutonNeon("Afficher le jeton", Theme.TexteDim);
            btnJeton.Click += (s, e) => ActionsReglages.AfficherJeton();
            var btnNouveau = new BoutonNeon("Nouveau jeton", Theme.Magenta);
            btnNouveau.Click += (s, e) => ActionsReglages.NouveauJeton();
            pile.Controls.Add(Ligne(btnJeton, btnNouveau));

            var btnEnregistrer = new BoutonNeon("Enregistrer", Theme.Cyan) { Margin = new Padding(0, 14, 8, 6) };
            btnEnregistrer.Click += (s, e) => Enregistrer();
            pile.Controls.Add(btnEnregistrer);

            // ---------------- Mise à jour
            pile.Controls.Add(Section("MISE À JOUR"));
            pile.Controls.Add(lblMaj);
            pile.Controls.Add(chkMajAuto);
            pile.Controls.Add(Ligne(Etiquette("Manifeste"), txtMajUrl));
            var btnMajEnr = new BoutonNeon("Enregistrer", Theme.Cyan);
            btnMajEnr.Click += (s, e) => { ActionsReglages.MajConfig(chkMajAuto.Checked, txtMajUrl.Text); Charger(); };
            var btnMajVerif = new BoutonNeon("Rechercher maintenant", Theme.TexteDim);
            btnMajVerif.Click += (s, e) => { ActionsReglages.MajVerifier(); Charger(); };
            pile.Controls.Add(Ligne(btnMajEnr, btnMajVerif));

            // ---------------- Accès aux données
            pile.Controls.Add(Section("ACCÈS AUX DONNÉES"));
            pile.Controls.Add(lblLecteurs);
            var btnAutoriser = new BoutonNeon("Autoriser un autre compte…", Theme.TexteDim);
            btnAutoriser.Click += (s, e) => AutoriserCompte();
            pile.Controls.Add(Ligne(btnAutoriser));

            // ---------------- Export
            pile.Controls.Add(Section("EXPORT DES JOURNAUX"));
            var btnAlertes = new BoutonNeon("Exporter les alertes…", Theme.Cyan);
            btnAlertes.Click += (s, e) => ExporterAlertes();
            var btnJournal = new BoutonNeon("Exporter le journal du service…", Theme.TexteDim);
            btnJournal.Click += (s, e) => ExporterJournal();
            pile.Controls.Add(Ligne(btnAlertes, btnJournal));

            Controls.Add(pile);
            Charger();
        }

        // ------------------------------------------------------------ construction

        static Label Section(string texte)
        {
            return new Label { Text = L.T(texte), Font = Theme.PetitGras, ForeColor = Theme.Magenta, AutoSize = true, Margin = new Padding(0, 18, 0, 6) };
        }

        static Label Note(string texte)
        {
            return new Label { Text = L.T(texte), Font = Theme.Petit, ForeColor = Theme.TexteDim, AutoSize = true, MaximumSize = new Size(900, 0), Margin = new Padding(0, 2, 0, 6) };
        }

        static Label Etiquette(string texte)
        {
            return new Label { Text = L.T(texte), Font = Theme.Petit, ForeColor = Theme.Texte, AutoSize = true, Margin = new Padding(0, 7, 6, 0) };
        }

        static CheckBox Case(string texte)
        {
            return new CheckBox { Text = L.T(texte), AutoSize = true, ForeColor = Theme.Texte, Font = Theme.Petit, FlatStyle = FlatStyle.Flat, Margin = new Padding(0, 4, 0, 4), Cursor = Cursors.Hand };
        }

        static TextBox Saisie(int largeur)
        {
            return new TextBox { Width = largeur, BackColor = Theme.Panneau2, ForeColor = Theme.Texte, BorderStyle = BorderStyle.FixedSingle, Font = Theme.Mono, Margin = new Padding(0, 3, 14, 3) };
        }

        static TextBox Secret(int largeur)
        {
            var t = Saisie(largeur);
            t.UseSystemPasswordChar = true;
            return t;
        }

        static ComboBox Liste(params string[] valeurs)
        {
            var c = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, FlatStyle = FlatStyle.Flat, BackColor = Theme.Panneau2, ForeColor = Theme.Texte, Font = Theme.Petit, Width = 110, Margin = new Padding(0, 3, 14, 3) };
            c.Items.AddRange(valeurs);
            c.SelectedIndex = 0;
            return c;
        }

        static FlowLayoutPanel Ligne(params Control[] controles)
        {
            var l = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 2, 0, 2) };
            l.Controls.AddRange(controles);
            return l;
        }

        static void Choisir(ComboBox c, string valeur)
        {
            int i = c.Items.IndexOf(valeur);
            c.SelectedIndex = i >= 0 ? i : 0;
        }

        // ------------------------------------------------------------ lecture et enregistrement

        void Charger()
        {
            config = ActionsProtection.LireConfig(out configIllisible) ?? new Config();
            lblConfig.Text = configIllisible ? ActionsReglages.ConfigIllisible() : "";
            lblLecteurs.Text = ActionsReglages.TexteLecteurs(Commun.Lire<List<Lecteur>>("lecteurs.json"));
            if (config.Syslog == null) config.Syslog = new ConfigSyslog();
            if (config.Api == null) config.Api = new ConfigApi();
            cbLangue.SelectedIndex = config.Langue == "en" ? 1 : 0;
            chkSyslog.Checked = config.Syslog.Actif;
            txtHote.Text = config.Syslog.Hote;
            txtPortSyslog.Text = config.Syslog.Port.ToString();
            Choisir(cbProtocole, config.Syslog.Protocole);
            Choisir(cbFormat, config.Syslog.Format);
            Choisir(cbNiveau, config.Syslog.NiveauMin);
            chkApi.Checked = config.Api.Actif;
            txtPortApi.Text = config.Api.Port.ToString();
            chkReseau.Checked = config.Api.Reseau;
            txtAdressesApi.Text = config.Api.Adresses ?? "";
            var app = Commun.Lire<EtatApprentissage>("apprentissage.json");
            if (app != null) lblApprentissage.Text = ActionsReglages.TexteApprentissage(app);
            var mj = config.Maj ?? new ConfigMaj();
            chkMajAuto.Checked = mj.Auto;
            txtMajUrl.Text = mj.Url ?? "";
            lblMaj.Text = ActionsReglages.TexteMaj(Commun.Lire<EtatMaj>("maj.json"));
            var n = config.Notifications ?? new ConfigNotifications();
            Choisir(cbNiveauNotif, n.NiveauMin);
            txtMaxHeure.Text = n.MaxParHeure.ToString();
            chkNtfy.Checked = n.Ntfy;
            chkTeams.Checked = n.Teams;
            chkSmtp.Checked = n.Smtp;
            txtSmtpServeur.Text = n.SmtpServeur;
            txtSmtpPort.Text = n.SmtpPort.ToString();
            Choisir(cbSmtpSecurite, n.SmtpSecurite);
            txtSmtpUtilisateur.Text = n.SmtpUtilisateur;
            txtExpediteur.Text = n.Expediteur;
            txtDestinataires.Text = n.Destinataires;
            foreach (var t in new[] { txtNtfyUrl, txtNtfyJeton, txtTeamsUrl, txtSmtpMotDePasse }) t.Text = "";
            lblNotif.Text = ActionsReglages.TexteNotifications(Commun.Lire<EtatNotifications>("notifications.json"));
        }

        void EnvoyerNotifications(string action)
        {
            int max, port;
            string erreur = ActionsReglages.NotificationsInvalides(txtMaxHeure.Text, txtSmtpPort.Text, out max, out port);
            if (erreur != null) { MessageBox.Show(erreur, "deR4Tizer", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            ActionsReglages.Notifications(action, new ConfigNotifications
            {
                NiveauMin = (string)cbNiveauNotif.SelectedItem, MaxParHeure = max, Ntfy = chkNtfy.Checked, Teams = chkTeams.Checked, Smtp = chkSmtp.Checked,
                SmtpServeur = txtSmtpServeur.Text.Trim(), SmtpPort = port, SmtpSecurite = (string)cbSmtpSecurite.SelectedItem,
                SmtpUtilisateur = txtSmtpUtilisateur.Text.Trim(), Expediteur = txtExpediteur.Text.Trim(), Destinataires = txtDestinataires.Text.Trim()
            }, txtNtfyUrl.Text, txtNtfyJeton.Text, txtTeamsUrl.Text, txtSmtpMotDePasse.Text);
            Charger();
        }

        // Syslog et API saisis, ou null (avec un message) si un port est invalide
        Tuple<ConfigSyslog, ConfigApi> Saisis()
        {
            int portSyslog, portApi;
            string erreur = ActionsReglages.PortsInvalides(txtPortSyslog.Text, txtPortApi.Text, out portSyslog, out portApi);
            if (erreur != null) { MessageBox.Show(erreur, "deR4Tizer", MessageBoxButtons.OK, MessageBoxIcon.Warning); return null; }
            return Tuple.Create(
                new ConfigSyslog { Actif = chkSyslog.Checked, Hote = txtHote.Text.Trim(), Port = portSyslog, Protocole = (string)cbProtocole.SelectedItem, Format = (string)cbFormat.SelectedItem, NiveauMin = (string)cbNiveau.SelectedItem },
                new ConfigApi { Actif = chkApi.Checked, Port = portApi, Reseau = chkReseau.Checked, Adresses = txtAdressesApi.Text.Trim() });
        }

        // Relit config.json au moment d'enregistrer : illisible, rien n'est écrit (S139-02 étendu, U6c)
        void Enregistrer()
        {
            var saisis = Saisis();
            if (saisis == null) return;
            bool illisible;
            var lue = ActionsProtection.LireConfig(out illisible);
            if (ActionsReglages.Enregistrer(ActionsReglages.Composer(illisible ? null : lue, cbLangue.SelectedIndex == 1, saisis.Item1, saisis.Item2))) Charger();
        }

        // Autorise un compte local à lire les données (nom saisi, converti en identifiant de sécurité)
        void AutoriserCompte()
        {
            using (var f = new Form { Text = "deR4Tizer", Size = new Size(420, 150), FormBorderStyle = FormBorderStyle.FixedDialog, StartPosition = FormStartPosition.CenterParent, MinimizeBox = false, MaximizeBox = false, BackColor = Theme.Fond, ForeColor = Theme.Texte, Font = Theme.Petit })
            {
                var t = Saisie(360);
                t.Location = new Point(16, 36);
                var lbl = new Label { Text = L.T("Nom du compte (par exemple : PC-ACCUEIL\\marie)"), AutoSize = true, Location = new Point(16, 12) };
                var ok = new BoutonNeon("Autoriser", Theme.Cyan) { DialogResult = DialogResult.OK, Location = new Point(16, 70) };
                f.Controls.AddRange(new Control[] { lbl, t, ok });
                f.AcceptButton = ok;
                if (f.ShowDialog(this) != DialogResult.OK || t.Text.Trim().Length == 0) return;
                string sid = ActionsReglages.Sid(t.Text);
                if (sid == null) { MessageBox.Show(L.T("Compte introuvable."), "deR4Tizer", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
                ActionsReglages.AutoriserLecteur(sid);
            }
        }

        // ------------------------------------------------------------ export

        void ExporterAlertes()
        {
            using (var d = new SaveFileDialog { Filter = "JSON (*.json)|*.json|CSV (*.csv)|*.csv", FileName = ActionsReglages.NomExport("alertes") })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                // CSV sans formule pour le tableur (U6c)
                ActionsReglages.ExporterAlertes(d.FileName, d.FilterIndex == 2);
            }
        }

        void ExporterJournal()
        {
            using (var d = new SaveFileDialog { Filter = "Texte (*.txt)|*.txt", FileName = ActionsReglages.NomExport("journal") })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                string erreur = ActionsReglages.ExporterJournal(d.FileName);
                if (erreur != null) MessageBox.Show(erreur, "deR4Tizer", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
