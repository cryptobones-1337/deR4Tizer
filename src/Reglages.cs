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
    class PageReglages : Panel
    {
        readonly ComboBox cbLangue = Liste("Français", "English");
        readonly CheckBox chkSyslog = Case("Envoyer les alertes à un serveur syslog / SIEM");
        readonly TextBox txtHote = Saisie(220), txtPortSyslog = Saisie(70);
        readonly ComboBox cbProtocole = Liste("UDP", "TCP"), cbFormat = Liste("JSON", "CEF"), cbNiveau = Liste("Info", "Alerte", "Critique");
        readonly CheckBox chkApi = Case("Activer l'API d'export"), chkReseau = Case("Accessible depuis le réseau local (sinon cet ordinateur seulement)");
        readonly TextBox txtPortApi = Saisie(70);
        Config config;

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
            pile.Controls.Add(new Label { Text = "// " + L.T("Réglages").ToUpperInvariant(), Font = Theme.TitrePage, ForeColor = Theme.Cyan, AutoSize = true, Margin = new Padding(0, 0, 0, 2) });
            pile.Controls.Add(Note("Langue, envoi des alertes à un SIEM (syslog), API d'export et export des journaux."));

            // ---------------- Langue
            pile.Controls.Add(Section("LANGUE"));
            pile.Controls.Add(Ligne(Etiquette("Langue de l'interface"), cbLangue));
            pile.Controls.Add(Note("La langue s'applique au prochain lancement de l'interface."));

            // ---------------- Syslog
            pile.Controls.Add(Section("ENVOI DES ALERTES (SYSLOG)"));
            pile.Controls.Add(chkSyslog);
            pile.Controls.Add(Ligne(Etiquette("Serveur"), txtHote, Etiquette("Port"), txtPortSyslog, Etiquette("Protocole"), cbProtocole));
            pile.Controls.Add(Ligne(Etiquette("Format"), cbFormat, Etiquette("Niveau minimal"), cbNiveau));
            pile.Controls.Add(Note("JSON : en-tête RFC 5424 et détail en JSON. CEF : reconnu par la plupart des SIEM (Splunk, QRadar, Sentinel, Wazuh, Graylog…)."));
            var btnTester = new BoutonNeon("Tester l'envoi", Theme.TexteDim);
            btnTester.Click += (s, e) => { var c = Lire(); if (c != null) Canal.Executer(new Commande { Action = "testerSyslog", Valeur = Commun.Json().Serialize(c.Syslog) }); };
            pile.Controls.Add(Ligne(btnTester));

            // ---------------- API
            pile.Controls.Add(Section("API D'EXPORT (HTTP, LECTURE SEULE)"));
            pile.Controls.Add(chkApi);
            pile.Controls.Add(Ligne(Etiquette("Port"), txtPortApi));
            pile.Controls.Add(chkReseau);
            pile.Controls.Add(Note("Chaque requête doit porter l'en-tête « Authorization: Bearer <jeton> ». Routes : /api/v1/alertes, /connexions, /exposition, /baseline, /regles-parefeu, /blocages, /journal."));
            var btnJeton = new BoutonNeon("Afficher le jeton", Theme.TexteDim);
            btnJeton.Click += (s, e) => Canal.Executer(new Commande { Action = "jetonApi" });
            var btnNouveau = new BoutonNeon("Nouveau jeton", Theme.Magenta);
            btnNouveau.Click += (s, e) =>
            {
                if (MessageBox.Show(L.T("Remplacer le jeton ? Les outils qui utilisent l'ancien devront être mis à jour."), "deR4Tizer",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
                    Canal.Executer(new Commande { Action = "nouveauJeton" });
            };
            pile.Controls.Add(Ligne(btnJeton, btnNouveau));

            var btnEnregistrer = new BoutonNeon("Enregistrer", Theme.Cyan) { Margin = new Padding(0, 14, 8, 6) };
            btnEnregistrer.Click += (s, e) => Enregistrer();
            pile.Controls.Add(btnEnregistrer);

            // ---------------- Accès aux données
            pile.Controls.Add(Section("ACCÈS AUX DONNÉES"));
            var lecteurs = Commun.Lire<List<Lecteur>>("lecteurs.json") ?? new List<Lecteur>();
            pile.Controls.Add(Note(L.T("Les événements, sessions, alertes et appareils du réseau ne sont lisibles que par SYSTEM, les administrateurs et ces comptes :")
                + " " + (lecteurs.Count == 0 ? "—" : string.Join(", ", lecteurs.Select(x => x.Nom)))));
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
            config = Commun.Lire<Config>("config.json") ?? new Config();
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
        }

        // Réglages saisis, ou null (avec un message) si un port est invalide
        Config Lire()
        {
            int portSyslog, portApi;
            if (!int.TryParse(txtPortSyslog.Text.Trim(), out portSyslog) || portSyslog < 1 || portSyslog > 65535 ||
                !int.TryParse(txtPortApi.Text.Trim(), out portApi) || portApi < 1024 || portApi > 65535)
            {
                MessageBox.Show(L.En ? "Invalid port (syslog: 1-65535, API: 1024-65535)." : "Port invalide (syslog : 1 à 65535, API : 1024 à 65535).",
                    "deR4Tizer", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return null;
            }
            var c = Commun.Lire<Config>("config.json") ?? new Config();
            c.Langue = cbLangue.SelectedIndex == 1 ? "en" : "fr";
            c.Syslog = new ConfigSyslog
            {
                Actif = chkSyslog.Checked, Hote = txtHote.Text.Trim(), Port = portSyslog,
                Protocole = (string)cbProtocole.SelectedItem, Format = (string)cbFormat.SelectedItem, NiveauMin = (string)cbNiveau.SelectedItem
            };
            c.Api = new ConfigApi { Actif = chkApi.Checked, Port = portApi, Reseau = chkReseau.Checked };
            return c;
        }

        void Enregistrer()
        {
            var c = Lire();
            if (c == null) return;
            Canal.Executer(new Commande { Action = "reglages", Valeur = Commun.Json().Serialize(c) });
            Charger();
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
                string sid;
                try { sid = new System.Security.Principal.NTAccount(t.Text.Trim()).Translate(typeof(System.Security.Principal.SecurityIdentifier)).Value; }
                catch { MessageBox.Show(L.T("Compte introuvable."), "deR4Tizer", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
                Canal.Executer(new Commande { Action = "autoriserLecteur", Valeur = sid });
            }
        }

        // ------------------------------------------------------------ export

        void ExporterAlertes()
        {
            var alertes = Commun.Lire<List<Alerte>>("alertes.json") ?? new List<Alerte>();
            using (var d = new SaveFileDialog
            {
                Filter = "JSON (*.json)|*.json|CSV (*.csv)|*.csv", FileName = "deR4Tizer-alertes-" + DateTime.Now.ToString("yyyyMMdd-HHmm")
            })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                if (d.FilterIndex == 2)
                {
                    Func<object, string> champ = v => "\"" + (v == null ? "" : v.ToString()).Replace("\"", "\"\"") + "\"";
                    var sb = new StringBuilder("Heure;Niveau;Score;Programme;Destination;Port;Raisons;MITRE;Chemin;PID\r\n");
                    foreach (var a in alertes)
                        sb.AppendLine(string.Join(";", new[] { champ(a.Heure), champ(a.Niveau), champ(a.Score), champ(a.Processus), champ(a.Destination),
                            champ(a.Port), champ(a.Raisons), champ(a.Mitre), champ(a.Chemin), champ(a.Pid) }));
                    File.WriteAllText(d.FileName, sb.ToString(), new UTF8Encoding(true));
                }
                else File.WriteAllText(d.FileName, Commun.Json().Serialize(alertes), new UTF8Encoding(false));
            }
        }

        void ExporterJournal()
        {
            string source = Path.Combine(Commun.Dossier, "journal.txt");
            using (var d = new SaveFileDialog { Filter = "Texte (*.txt)|*.txt", FileName = "deR4Tizer-journal-" + DateTime.Now.ToString("yyyyMMdd-HHmm") })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                try { File.Copy(source, d.FileName, true); }
                catch (Exception e) { MessageBox.Show(e.Message, "deR4Tizer", MessageBoxButtons.OK, MessageBoxIcon.Error); }
            }
        }
    }
}
