// Page Événements (mini-SIEM) : recherche dans les événements stockés par le service (siem\*.ndjson),
// chronologie par niveau (cliquer une barre restreint la recherche à cette tranche) et incidents de corrélation.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace DeR4Tizer
{
    class PageSiem : TableLayoutPanel
    {
        const int MaxAffiches = 2000;
        static readonly string[] Sources = { "", "alerte", "connexion", "processus", "securite", "parefeu", "systeme" };
        static readonly TimeSpan[] Periodes = { TimeSpan.FromHours(1), TimeSpan.FromHours(24), TimeSpan.FromDays(7), TimeSpan.FromDays(30) };

        readonly TextBox txtRecherche = new TextBox { Width = 300, BackColor = Theme.Panneau2, ForeColor = Theme.Texte, BorderStyle = BorderStyle.FixedSingle, Font = Theme.Mono, Margin = new Padding(0, 3, 10, 3) };
        readonly ComboBox cbSource = Choix(130, "Toutes les sources", "alerte", "connexion", "processus", "securite", "parefeu", "systeme");
        readonly ComboBox cbNiveau = Choix(110, "Tous niveaux", "Alerte", "Critique");
        readonly ComboBox cbPeriode = Choix(110, "1 heure", "24 heures", "7 jours", "30 jours");
        readonly Label lblResultat = new Label { AutoSize = true, ForeColor = Theme.TexteDim, Font = Theme.Petit, Margin = new Padding(6, 8, 0, 0) };
        readonly Chronologie chrono = new Chronologie { Dock = DockStyle.Fill };
        readonly Liste lvIncidents = new Liste(), lvEvenements = new Liste();
        readonly Label detail = new Label
        {
            Dock = DockStyle.Bottom, Height = 110, BackColor = Theme.Panneau2, ForeColor = Theme.Texte, Font = Theme.Mono,
            Padding = new Padding(12, 8, 12, 8), Text = L.T("Sélectionnez un incident ou un événement pour voir le détail.")
        };
        DateTime? trancheDebut, trancheFin;
        int recherche;

        public PageSiem()
        {
            Dock = DockStyle.Fill; ColumnCount = 1; RowCount = 6; BackColor = Theme.Fond; Padding = new Padding(22, 14, 22, 16); Visible = false;
            RowStyles.Add(new RowStyle(SizeType.AutoSize));
            RowStyles.Add(new RowStyle(SizeType.AutoSize));
            RowStyles.Add(new RowStyle(SizeType.AutoSize));
            RowStyles.Add(new RowStyle(SizeType.Absolute, 110));
            RowStyles.Add(new RowStyle(SizeType.Absolute, 150));
            RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            Controls.Add(new Label { Text = "// " + L.T("Événements").ToUpperInvariant(), Font = Theme.TitrePage, ForeColor = Theme.Cyan, AutoSize = true, Margin = new Padding(0, 0, 0, 2) }, 0, 0);
            Controls.Add(new Label
            {
                Text = L.T("Mini-SIEM local : sessions, comptes, processus, services, connexions, pare-feu et alertes, conservés 30 jours. Les règles de corrélation lèvent des incidents."),
                Font = Theme.Petit, ForeColor = Theme.TexteDim, AutoSize = true, Margin = new Padding(0, 0, 0, 10)
            }, 0, 1);

            var barre = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 0, 0, 6), WrapContents = true };
            var btnChercher = new BoutonNeon("Rechercher", Theme.Cyan);
            btnChercher.Click += (s, e) => { trancheDebut = trancheFin = null; Charger(); };
            txtRecherche.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; trancheDebut = trancheFin = null; Charger(); } };
            cbPeriode.SelectedIndex = 1;
            foreach (var c in new[] { cbSource, cbNiveau, cbPeriode }) c.SelectedIndexChanged += (s, e) => { trancheDebut = trancheFin = null; Charger(); };
            barre.Controls.AddRange(new Control[] { txtRecherche, cbSource, cbNiveau, cbPeriode, btnChercher, lblResultat });
            Controls.Add(barre, 0, 2);

            chrono.TrancheChoisie += (debut, fin) => { trancheDebut = debut; trancheFin = fin; Charger(); };
            Controls.Add(Cadre(chrono), 0, 3);

            lvIncidents.Colonnes("Heure", 160, "Niveau", 85, "Règle", 60, "Incident", 300, "MITRE", 100, "Résumé", 700);
            lvIncidents.SelectedIndexChanged += (s, e) => Detailler(lvIncidents);
            Controls.Add(Cadre(lvIncidents), 0, 4);

            lvEvenements.Colonnes("Heure", 160, "Niveau", 85, "Source", 95, "Type", 170, "Utilisateur", 170, "Programme", 150, "IP", 130, "Message", 800);
            lvEvenements.SelectedIndexChanged += (s, e) => Detailler(lvEvenements);
            var menu = new ContextMenuStrip { Renderer = new RenduSombre(), Font = Theme.Petit };
            menu.Items.Add(L.T("Copier"), null, (s, e) => Copier());
            menu.Items.Add(L.T("Chercher cette valeur"), null, (s, e) => ChercherValeur());
            lvEvenements.ContextMenuStrip = menu;
            var cadre = Cadre(lvEvenements);
            cadre.Controls.Add(detail);
            Controls.Add(cadre, 0, 5);

            VisibleChanged += (s, e) => { if (Visible) Charger(); };
        }

        static ComboBox Choix(int largeur, params string[] valeurs)
        {
            var c = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, FlatStyle = FlatStyle.Flat, BackColor = Theme.Panneau2, ForeColor = Theme.Texte, Font = Theme.Petit, Width = largeur, Margin = new Padding(0, 3, 10, 3) };
            c.Items.AddRange(valeurs.Select(L.T).ToArray());
            c.SelectedIndex = 0;
            return c;
        }

        static Panel Cadre(Control c)
        {
            var cadre = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bordure, Padding = new Padding(1), Margin = new Padding(0, 0, 0, 8) };
            cadre.Controls.Add(c);
            return cadre;
        }

        // ------------------------------------------------------------ recherche (fil de fond)

        class Resultat
        {
            public List<Evenement> Evenements = new List<Evenement>();
            public int Total;
            public DateTime Debut, Fin;
            public int[,] Compteurs;     // [tranche, niveau 0 Info / 1 Alerte / 2 Critique]
            public List<Incident> Incidents = new List<Incident>();
        }

        public void Charger()
        {
            string texte = txtRecherche.Text.Trim();
            string source = Sources[cbSource.SelectedIndex];
            int niveauMin = cbNiveau.SelectedIndex;
            DateTime fin = DateTime.Now, debut = fin - Periodes[cbPeriode.SelectedIndex];
            DateTime? fDebut = trancheDebut, fFin = trancheFin;
            int numero = ++recherche;
            lblResultat.Text = L.T("Recherche…");
            ThreadPool.QueueUserWorkItem(_ =>
            {
                Resultat r;
                try { r = Chercher(texte, source, niveauMin, debut, fin, fDebut, fFin); }
                catch (Exception e) { r = new Resultat(); r.Compteurs = new int[1, 3]; r.Debut = debut; r.Fin = fin; Console.WriteLine(e); }
                try { BeginInvoke(new Action(() => { if (numero == recherche) Afficher(r, fDebut, fFin); })); } catch { }
            });
        }

        static string Champ(string ligne, string nom)
        {
            string motif = "\"" + nom + "\":\"";
            int i = ligne.IndexOf(motif, StringComparison.Ordinal);
            if (i < 0) return "";
            i += motif.Length;
            int j = ligne.IndexOf('"', i);
            return j < 0 ? "" : ligne.Substring(i, j - i);
        }

        static int Rang(string niveau) { return niveau == "Critique" ? 2 : niveau == "Alerte" ? 1 : 0; }

        static Resultat Chercher(string texte, string source, int niveauMin, DateTime debut, DateTime fin, DateTime? fDebut, DateTime? fFin)
        {
            const int tranches = 48;
            var r = new Resultat { Debut = debut, Fin = fin, Compteurs = new int[tranches, 3] };
            string sDebut = (fDebut ?? debut).ToString("yyyy-MM-dd HH:mm:ss"), sFin = (fFin ?? fin).ToString("yyyy-MM-dd HH:mm:ss");
            string bDebut = debut.ToString("yyyy-MM-dd HH:mm:ss");
            double duree = (fin - debut).TotalSeconds;
            var json = Commun.Json();
            string dossier = Path.Combine(Commun.Dossier, "siem");
            var fichiers = Directory.Exists(dossier) ? Directory.GetFiles(dossier, "evenements-*.ndjson") : new string[0];
            foreach (var f in fichiers.OrderByDescending(x => x))
            {
                string jour = Path.GetFileNameWithoutExtension(f).Substring(11);
                if (string.CompareOrdinal(jour, debut.ToString("yyyyMMdd")) < 0) continue;
                string[] lignes;
                try
                {
                    using (var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    using (var lecteur = new StreamReader(fs, Encoding.UTF8))
                        lignes = lecteur.ReadToEnd().Split('\n');
                }
                catch { continue; }
                for (int k = lignes.Length - 1; k >= 0; k--)
                {
                    string ligne = lignes[k];
                    if (ligne.Length < 10) continue;
                    if (texte.Length > 0 && ligne.IndexOf(texte, StringComparison.OrdinalIgnoreCase) < 0) continue;
                    string heure = Champ(ligne, "Heure");
                    if (string.CompareOrdinal(heure, bDebut) < 0) continue;
                    if (source.Length > 0 && Champ(ligne, "Source") != source) continue;
                    int rang = Rang(Champ(ligne, "Niveau"));
                    if (rang < niveauMin) continue;
                    // Chronologie : toute la période (sans la tranche choisie)
                    DateTime h;
                    if (DateTime.TryParseExact(heure, "yyyy-MM-dd HH:mm:ss", null, System.Globalization.DateTimeStyles.None, out h))
                    {
                        int t = (int)((h - debut).TotalSeconds / duree * tranches);
                        if (t >= 0 && t < tranches) r.Compteurs[t, rang]++;
                    }
                    if (string.CompareOrdinal(heure, sDebut) < 0 || string.CompareOrdinal(heure, sFin) > 0) continue;
                    r.Total++;
                    if (r.Evenements.Count < MaxAffiches)
                        try { r.Evenements.Add(json.Deserialize<Evenement>(ligne)); } catch { }
                }
            }
            var incidents = Commun.Lire<List<Incident>>("incidents.json") ?? new List<Incident>();
            r.Incidents = incidents.Where(i => string.CompareOrdinal(i.Heure ?? "", bDebut) >= 0).OrderByDescending(i => i.Heure).ToList();
            return r;
        }

        void Afficher(Resultat r, DateTime? fDebut, DateTime? fFin)
        {
            chrono.Definir(r.Debut, r.Fin, r.Compteurs, fDebut, fFin);
            lvIncidents.BeginUpdate();
            lvIncidents.Items.Clear();
            foreach (var i in r.Incidents)
            {
                var item = new ListViewItem(new[] { i.Heure, i.Niveau, i.Regle, i.Titre, i.Mitre, i.Resume }) { Tag = i };
                Colorer(item, i.Niveau);
                lvIncidents.Items.Add(item);
            }
            lvIncidents.EndUpdate();
            lvEvenements.BeginUpdate();
            lvEvenements.Items.Clear();
            foreach (var e in r.Evenements)
            {
                var item = new ListViewItem(new[] { e.Heure, e.Niveau, e.Source, e.Type, e.Utilisateur, e.Processus, e.Ip, e.Message }) { Tag = e, ToolTipText = e.Message };
                Colorer(item, e.Niveau);
                lvEvenements.Items.Add(item);
            }
            lvEvenements.EndUpdate();
            string tranche = fDebut.HasValue ? string.Format(L.En ? " · slice {0:HH:mm}–{1:HH:mm} (click the timeline again to clear)" : " · tranche {0:HH:mm}–{1:HH:mm} (recliquer la chronologie pour l'enlever)", fDebut, fFin) : "";
            lblResultat.Text = string.Format(L.En ? "{0} event(s){1}, {2} incident(s){3}" : "{0} événement(s){1}, {2} incident(s){3}",
                r.Total, r.Total > MaxAffiches ? (L.En ? " (latest " + MaxAffiches + " shown)" : " (les " + MaxAffiches + " plus récents affichés)") : "", r.Incidents.Count, tranche);
        }

        static void Colorer(ListViewItem item, string niveau)
        {
            if (niveau == "Critique") { item.BackColor = Theme.FondCritique; item.ForeColor = Color.White; }
            else if (niveau == "Alerte") { item.BackColor = Theme.FondAlerte; item.ForeColor = Theme.Texte; }
            else { item.BackColor = Theme.Panneau; item.ForeColor = Theme.Texte; }
        }

        void Detailler(Liste lv)
        {
            if (lv.SelectedItems.Count == 0) return;
            var i = lv.SelectedItems[0].Tag as Incident;
            if (i != null)
            {
                detail.Text = i.Titre + " (" + i.Regle + (string.IsNullOrEmpty(i.Mitre) ? "" : ", " + i.Mitre) + ")\n" + i.Resume + "\n\n"
                    + string.Join("\n", (i.Evenements ?? new List<string>()).Take(5));
                return;
            }
            var e = lv.SelectedItems[0].Tag as Evenement;
            if (e != null)
                detail.Text = e.Heure + "  [" + e.Source + " / " + e.Type + "]  " + e.Niveau + (string.IsNullOrEmpty(e.Mitre) ? "" : "  " + e.Mitre) + "\n"
                    + (string.IsNullOrEmpty(e.Utilisateur) ? "" : L.T("Utilisateur") + " : " + e.Utilisateur + "   ")
                    + (string.IsNullOrEmpty(e.Processus) ? "" : L.T("Programme") + " : " + e.Processus + (e.Pid.HasValue ? " (PID " + e.Pid + ")" : "") + "   ")
                    + (string.IsNullOrEmpty(e.Ip) ? "" : "IP : " + e.Ip + (e.Port > 0 ? ":" + e.Port : "") + "   ")
                    + (string.IsNullOrEmpty(e.Destination) ? "" : L.T("Destination") + " : " + e.Destination)
                    + "\n" + e.Message;
        }

        void Copier()
        {
            var sb = new StringBuilder();
            foreach (ListViewItem item in lvEvenements.SelectedItems)
                sb.AppendLine(string.Join("\t", item.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(s => s.Text)));
            if (sb.Length > 0) Clipboard.SetText(sb.ToString());
        }

        // Relance la recherche sur l'utilisateur, l'IP ou le programme de l'événement sélectionné
        void ChercherValeur()
        {
            if (lvEvenements.SelectedItems.Count == 0) return;
            var e = (Evenement)lvEvenements.SelectedItems[0].Tag;
            string v = !string.IsNullOrEmpty(e.Ip) ? e.Ip : !string.IsNullOrEmpty(e.Utilisateur) ? e.Utilisateur : e.Processus;
            if (string.IsNullOrEmpty(v)) return;
            txtRecherche.Text = v;
            cbSource.SelectedIndex = 0;
            trancheDebut = trancheFin = null;
            Charger();
        }
    }

    // Histogramme de la période : barres empilées Info / Alerte / Critique ; un clic choisit une tranche
    class Chronologie : Control
    {
        DateTime debut, fin;
        int[,] compteurs = new int[1, 3];
        DateTime? choixDebut, choixFin;
        int survol = -1;
        public event Action<DateTime?, DateTime?> TrancheChoisie;

        public Chronologie()
        {
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            BackColor = Theme.Panneau;
            Cursor = Cursors.Hand;
        }

        public void Definir(DateTime d, DateTime f, int[,] c, DateTime? cd, DateTime? cf)
        {
            debut = d; fin = f; compteurs = c; choixDebut = cd; choixFin = cf;
            Invalidate();
        }

        int Tranches { get { return compteurs.GetLength(0); } }
        Rectangle Zone { get { return new Rectangle(44, 8, Math.Max(1, Width - 56), Math.Max(1, Height - 30)); } }

        int TrancheSous(int x)
        {
            var z = Zone;
            if (x < z.Left || x >= z.Right) return -1;
            return Math.Min(Tranches - 1, (x - z.Left) * Tranches / z.Width);
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            int t = TrancheSous(e.X);
            if (t != survol) { survol = t; Invalidate(); }
            base.OnMouseMove(e);
        }

        protected override void OnMouseLeave(EventArgs e) { survol = -1; Invalidate(); base.OnMouseLeave(e); }

        protected override void OnMouseClick(MouseEventArgs e)
        {
            int t = TrancheSous(e.X);
            if (t < 0 || TrancheChoisie == null) return;
            double pas = (fin - debut).TotalSeconds / Tranches;
            DateTime d = debut.AddSeconds(pas * t), f = debut.AddSeconds(pas * (t + 1));
            if (choixDebut.HasValue && Math.Abs((choixDebut.Value - d).TotalSeconds) < 1) TrancheChoisie(null, null);
            else TrancheChoisie(d, f);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.None;
            var z = Zone;
            int max = 1;
            for (int t = 0; t < Tranches; t++) max = Math.Max(max, compteurs[t, 0] + compteurs[t, 1] + compteurs[t, 2]);
            // Échelle racine carrée : quelques critiques restent visibles à côté de milliers d'événements
            Func<int, float> hauteur = n => n <= 0 ? 0 : Math.Max(2f, (float)(Math.Sqrt(n) / Math.Sqrt(max) * z.Height));
            var couleurs = new[] { Theme.Melange(Theme.Panneau, Theme.Cyan, 0.55f), Theme.Jaune, Theme.Rouge };
            using (var trait = new Pen(Theme.Bordure)) g.DrawLine(trait, z.Left, z.Bottom, z.Right, z.Bottom);
            TextRenderer.DrawText(g, max.ToString(), Theme.PetitGras, new Rectangle(0, z.Top - 4, 40, 16), Theme.TexteDim, TextFormatFlags.Right);
            float largeur = (float)z.Width / Tranches;
            double pas = (fin - debut).TotalSeconds / Tranches;
            for (int t = 0; t < Tranches; t++)
            {
                float x = z.Left + t * largeur;
                bool choisie = choixDebut.HasValue && Math.Abs((debut.AddSeconds(pas * t) - choixDebut.Value).TotalSeconds) < 1;
                if (t == survol || choisie)
                    using (var b = new SolidBrush(choisie ? Theme.Selection : Theme.Panneau2)) g.FillRectangle(b, x, z.Top, largeur, z.Height);
                float bas = z.Bottom;
                // Info d'abord, puis Alerte, puis Critique au sommet
                for (int n = 0; n < 3; n++)
                {
                    int total = compteurs[t, 0] + (n >= 1 ? compteurs[t, 1] : 0) + (n >= 2 ? compteurs[t, 2] : 0);
                    int precedent = n == 0 ? 0 : compteurs[t, 0] + (n >= 2 ? compteurs[t, 1] : 0);
                    float h = hauteur(total) - hauteur(precedent);
                    if (h <= 0) continue;
                    using (var b = new SolidBrush(couleurs[n])) g.FillRectangle(b, x + 1, bas - h, Math.Max(1, largeur - 2), h);
                    bas -= h;
                }
            }
            // Graduations : début, milieu, fin
            string format = (fin - debut).TotalDays > 2 ? "dd/MM HH:mm" : "HH:mm";
            for (int k = 0; k <= 4; k++)
            {
                var d = debut.AddSeconds((fin - debut).TotalSeconds * k / 4);
                int x = z.Left + z.Width * k / 4;
                TextRenderer.DrawText(g, d.ToString(format), Theme.PetitGras, new Rectangle(x - 50, z.Bottom + 3, 100, 16), Theme.TexteDim, TextFormatFlags.HorizontalCenter);
            }
            if (survol >= 0)
            {
                var d = debut.AddSeconds(pas * survol);
                string bulle = string.Format("{0:dd/MM HH:mm}  Info {1}  Alerte {2}  Critique {3}", d, compteurs[survol, 0], compteurs[survol, 1], compteurs[survol, 2]);
                var taille = TextRenderer.MeasureText(bulle, Theme.PetitGras);
                int x = Math.Min(Width - taille.Width - 8, Math.Max(4, z.Left + (int)(survol * largeur)));
                using (var b = new SolidBrush(Theme.Fond)) g.FillRectangle(b, x - 4, 2, taille.Width + 8, taille.Height + 2);
                TextRenderer.DrawText(g, bulle, Theme.PetitGras, new Point(x, 3), Theme.Texte);
            }
        }
    }
}
