// Page Trafic : débit en direct, carte du monde des pays de destination (contours Natural Earth intégrés à
// l'exécutable, aucun fond de carte chargé d'Internet), programmes, pays et destinations depuis minuit.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Windows.Forms;

namespace DeR4Tizer
{
    static class Format
    {
        public static string Octets(long o)
        {
            if (o >= 1L << 30) return (o / (double)(1L << 30)).ToString("0.0") + (L.En ? " GB" : " Go");
            if (o >= 1L << 20) return (o / (double)(1L << 20)).ToString("0.0") + (L.En ? " MB" : " Mo");
            if (o >= 1L << 10) return (o / 1024.0).ToString("0") + (L.En ? " KB" : " Ko");
            return o + (L.En ? " B" : " o");
        }

        public static string Debit(long o) { return Octets(o) + "/s"; }
    }

    // Pays de la carte : contours (projection équirectangulaire), nom, centre du plus grand polygone
    class PaysCarte
    {
        public string Code, NomFr, NomEn;
        public List<PointF[]> Anneaux = new List<PointF[]>();
        public PointF Centre;
        public string Nom { get { return L.En ? NomEn : NomFr; } }

        static Dictionary<string, PaysCarte> tous;

        public static Dictionary<string, PaysCarte> Tous
        {
            get
            {
                if (tous != null) return tous;
                tous = new Dictionary<string, PaysCarte>();
                try
                {
                    using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("carte-pays.txt"))
                    using (var r = new StreamReader(s))
                    {
                        string ligne;
                        while ((ligne = r.ReadLine()) != null)
                        {
                            if (ligne.StartsWith("#")) continue;
                            var c = ligne.Split('|');
                            if (c.Length < 4) continue;
                            var p = new PaysCarte { Code = c[0], NomFr = c[1], NomEn = c[2] };
                            foreach (var anneau in c[3].Split(';'))
                                p.Anneaux.Add(anneau.Split(' ').Select(xy =>
                                {
                                    var v = xy.Split(',');
                                    return new PointF(float.Parse(v[0], CultureInfo.InvariantCulture), float.Parse(v[1], CultureInfo.InvariantCulture));
                                }).ToArray());
                            // Centre : barycentre des sommets du plus grand anneau (la métropole plutôt que les territoires d'outre-mer)
                            var plus = p.Anneaux.OrderByDescending(Aire).First();
                            p.Centre = new PointF(plus.Average(q => q.X), plus.Average(q => q.Y));
                            tous[p.Code] = p;
                        }
                    }
                }
                catch { }
                return tous;
            }
        }

        static double Aire(PointF[] a)
        {
            double s = 0;
            for (int i = 0; i < a.Length; i++) { var p = a[i]; var q = a[(i + 1) % a.Length]; s += p.X * q.Y - q.X * p.Y; }
            return Math.Abs(s / 2);
        }

        public static string NomDe(string code)
        {
            PaysCarte p;
            return Tous.TryGetValue(code ?? "", out p) ? p.Nom : code;
        }
    }

    // Carte du monde : pays colorés selon le volume échangé, arcs animés vers les pays actifs
    class Carte : Control
    {
        List<TraficPays> pays = new List<TraficPays>();
        string survol;
        float phase;
        readonly Timer animation = new Timer { Interval = 40 };
        readonly ToolTip bulle = new ToolTip();
        readonly string origine;

        public Carte()
        {
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            BackColor = Theme.Panneau;
            try { origine = RegionInfo.CurrentRegion.TwoLetterISORegionName; } catch { origine = "LU"; }
            animation.Tick += (s, e) => { phase = (phase + 0.012f) % 1f; if (pays.Any(p => p.Active)) Invalidate(); };
            VisibleChanged += (s, e) => animation.Enabled = Visible;
        }

        public void Definir(List<TraficPays> p) { pays = p ?? new List<TraficPays>(); Invalidate(); }

        RectangleF Zone
        {
            get
            {
                // Longitude -180..180, latitude -58..84 (sans l'Antarctique), proportions conservées
                float l = Width - 16, h = Height - 16;
                float echelle = Math.Min(l / 360f, h / 142f);
                float lw = 360 * echelle, lh = 142 * echelle;
                return new RectangleF((Width - lw) / 2, (Height - lh) / 2, lw, lh);
            }
        }

        PointF Projeter(PointF lonlat)
        {
            var z = Zone;
            return new PointF(z.X + (lonlat.X + 180) / 360f * z.Width, z.Y + (84 - lonlat.Y) / 142f * z.Height);
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            string trouve = null;
            foreach (var p in PaysCarte.Tous.Values)
                foreach (var a in p.Anneaux)
                {
                    using (var chemin = new GraphicsPath())
                    {
                        chemin.AddPolygon(a.Select(Projeter).ToArray());
                        if (chemin.IsVisible(e.Location)) { trouve = p.Code; break; }
                    }
                }
            if (trouve != survol)
            {
                survol = trouve;
                var t = pays.FirstOrDefault(x => x.Code == trouve);
                bulle.SetToolTip(this, trouve == null ? "" : PaysCarte.NomDe(trouve) + (t == null ? "" :
                    "\n" + Format.Octets(t.Entrant + t.Sortant) + " · " + t.Destinations + " destination(s)\n" + string.Join(", ", t.Programmes ?? new List<string>())));
                Invalidate();
            }
            base.OnMouseMove(e);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            var volumes = pays.ToDictionary(p => p.Code, p => p.Entrant + p.Sortant);
            double max = Math.Max(1, volumes.Values.DefaultIfEmpty(1).Max());
            using (var trait = new Pen(Theme.Bordure, 1f))
            {
                foreach (var p in PaysCarte.Tous.Values)
                {
                    long v;
                    Color fond = Theme.Panneau2;
                    if (volumes.TryGetValue(p.Code, out v) && v > 0)
                    {
                        // Échelle logarithmique : quelques Ko restent visibles à côté de plusieurs Go
                        float t = (float)(Math.Log(1 + v) / Math.Log(1 + max));
                        fond = Theme.Melange(Theme.Melange(Theme.Panneau2, Theme.Cyan, 0.25f), Theme.Cyan, t * 0.75f);
                    }
                    if (p.Code == survol) fond = Theme.Melange(fond, Color.White, 0.25f);
                    using (var b = new SolidBrush(fond))
                        foreach (var a in p.Anneaux)
                        {
                            var pts = a.Select(Projeter).ToArray();
                            if (pts.Length < 3) continue;
                            g.FillPolygon(b, pts);
                            g.DrawPolygon(trait, pts);
                        }
                }
            }
            // Arcs animés de l'origine (région de Windows) vers les pays actifs
            PaysCarte depart;
            if (!PaysCarte.Tous.TryGetValue(origine ?? "", out depart)) return;
            var a0 = Projeter(depart.Centre);
            using (var halo = new SolidBrush(Color.FromArgb(200, Theme.Magenta))) g.FillEllipse(halo, a0.X - 4, a0.Y - 4, 8, 8);
            foreach (var p in pays.Where(x => x.Active))
            {
                PaysCarte arrivee;
                if (!PaysCarte.Tous.TryGetValue(p.Code, out arrivee) || arrivee == depart) continue;
                var a1 = Projeter(arrivee.Centre);
                float dx = a1.X - a0.X, dy = a1.Y - a0.Y;
                var milieu = new PointF((a0.X + a1.X) / 2 - dy * 0.25f, (a0.Y + a1.Y) / 2 - Math.Abs(dx) * 0.25f - 10);
                using (var arc = new Pen(Color.FromArgb(150, Theme.Magenta), 1.4f))
                    g.DrawBezier(arc, a0, milieu, milieu, a1);
                // Point lumineux qui parcourt l'arc
                float t = (phase + Math.Abs(p.Code.GetHashCode() % 100) / 100f) % 1f;
                float u = 1 - t;
                var point = new PointF(u * u * a0.X + 2 * u * t * milieu.X + t * t * a1.X, u * u * a0.Y + 2 * u * t * milieu.Y + t * t * a1.Y);
                using (var b = new SolidBrush(Theme.Jaune)) g.FillEllipse(b, point.X - 3, point.Y - 3, 6, 6);
                using (var b = new SolidBrush(Color.FromArgb(220, Theme.Magenta))) g.FillEllipse(b, a1.X - 3.5f, a1.Y - 3.5f, 7, 7);
            }
        }
    }

    // Courbe du débit (entrant et sortant) sur les 10 dernières minutes
    class Courbe : Control
    {
        List<PointTrafic> serie = new List<PointTrafic>();

        public Courbe()
        {
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            BackColor = Theme.Panneau;
        }

        public void Definir(List<PointTrafic> s) { serie = s ?? new List<PointTrafic>(); Invalidate(); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            var z = new Rectangle(8, 22, Width - 16, Height - 30);
            long max = Math.Max(1024, serie.Select(p => Math.Max(p.Entrant, p.Sortant)).DefaultIfEmpty(0).Max());
            TextRenderer.DrawText(g, (L.En ? "max " : "max ") + Format.Debit(max), Theme.PetitGras, new Point(8, 3), Theme.TexteDim);
            TextRenderer.DrawText(g, L.En ? "▬ in" : "▬ entrant", Theme.PetitGras, new Point(Width - 170, 3), Theme.Cyan);
            TextRenderer.DrawText(g, L.En ? "▬ out" : "▬ sortant", Theme.PetitGras, new Point(Width - 85, 3), Theme.Magenta);
            if (serie.Count < 2) return;
            Func<int, long, PointF> point = (i, v) => new PointF(z.Left + i * z.Width / (float)(Math.Max(serie.Count, 120) - 1), z.Bottom - v / (float)max * z.Height);
            using (var pe = new Pen(Theme.Cyan, 1.6f)) g.DrawLines(pe, serie.Select((p, i) => point(i, p.Entrant)).ToArray());
            using (var ps = new Pen(Theme.Magenta, 1.6f)) g.DrawLines(ps, serie.Select((p, i) => point(i, p.Sortant)).ToArray());
        }
    }

    class PageTrafic : TableLayoutPanel
    {
        readonly Label lblStats = new Label { AutoSize = true, ForeColor = Theme.Texte, Font = Theme.PetitGras, Margin = new Padding(0, 0, 0, 6) };
        readonly Carte carte = new Carte { Dock = DockStyle.Fill };
        readonly Courbe courbe = new Courbe { Dock = DockStyle.Fill };
        readonly Liste lvApplications = new Liste(), lvPays = new Liste(), lvDestinations = new Liste();
        readonly Timer minuteur = new Timer { Interval = 3000 };
        DateTime vu;

        public PageTrafic()
        {
            Dock = DockStyle.Fill; ColumnCount = 1; RowCount = 5; BackColor = Theme.Fond; Padding = new Padding(22, 14, 22, 16); Visible = false;
            RowStyles.Add(new RowStyle(SizeType.AutoSize));
            RowStyles.Add(new RowStyle(SizeType.AutoSize));
            RowStyles.Add(new RowStyle(SizeType.AutoSize));
            RowStyles.Add(new RowStyle(SizeType.Percent, 55));
            RowStyles.Add(new RowStyle(SizeType.Percent, 45));
            Controls.Add(new Label { Text = "// " + L.T("Trafic").ToUpperInvariant(), Font = Theme.TitrePage, ForeColor = Theme.Cyan, AutoSize = true, Margin = new Padding(0, 0, 0, 2) }, 0, 0);
            Controls.Add(new Label
            {
                Text = L.T("Analyse passive des paquets de ce PC depuis minuit. Pays d'enregistrement des adresses (registres Internet régionaux) ; les arcs montrent les échanges des 10 dernières secondes."),
                Font = Theme.Petit, ForeColor = Theme.TexteDim, AutoSize = true, Margin = new Padding(0, 0, 0, 8)
            }, 0, 1);
            Controls.Add(lblStats, 0, 2);

            var haut = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = new Padding(0, 0, 0, 8) };
            haut.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 72));
            haut.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 28));
            haut.Controls.Add(Cadre(carte, new Padding(0, 0, 8, 0)), 0, 0);
            haut.Controls.Add(Cadre(courbe, Padding.Empty), 1, 0);
            Controls.Add(haut, 0, 3);

            lvApplications.Colonnes("Programme", 130, "Reçu", 80, "Envoyé", 80, "Destinations", 90);
            lvPays.Colonnes("Pays", 150, "Volume", 80, "Destinations", 90, "Programmes", 220);
            lvDestinations.Colonnes("Destination", 220, "Pays", 50, "Programme", 110, "Port", 55, "Reçu", 75, "Envoyé", 75);
            var bas = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, Margin = Padding.Empty };
            bas.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 28));
            bas.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 32));
            bas.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));
            bas.Controls.Add(Cadre(lvApplications, new Padding(0, 0, 8, 0)), 0, 0);
            bas.Controls.Add(Cadre(lvPays, new Padding(0, 0, 8, 0)), 1, 0);
            bas.Controls.Add(Cadre(lvDestinations, Padding.Empty), 2, 0);
            Controls.Add(bas, 0, 4);

            minuteur.Tick += (s, e) => Charger();
            VisibleChanged += (s, e) => { minuteur.Enabled = Visible; if (Visible) { vu = DateTime.MinValue; Charger(); } };
        }

        static Panel Cadre(Control c, Padding marge)
        {
            var cadre = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bordure, Padding = new Padding(1), Margin = marge };
            cadre.Controls.Add(c);
            return cadre;
        }

        void Charger()
        {
            DateTime d;
            try { d = File.GetLastWriteTime(Path.Combine(Commun.Dossier, "trafic.json")); } catch { return; }
            if (d == vu) return;
            vu = d;
            var t = Commun.Lire<EtatTrafic>("trafic.json");
            if (t == null) { lblStats.Text = L.T("Pas encore de données de trafic (le service capture les paquets au démarrage)."); return; }
            lblStats.Text = string.Format(L.En
                ? "Now: ↓ {0}  ↑ {1}      Since {2}: ↓ {3}  ↑ {4} · {5:N0} packets · interface {6} · {7:N0} address ranges"
                : "En ce moment : ↓ {0}  ↑ {1}      Depuis {2} : ↓ {3}  ↑ {4} · {5:N0} paquets · interface {6} · {7:N0} plages d'adresses",
                Format.Debit(t.DebitEntrant), Format.Debit(t.DebitSortant), (t.Depuis ?? "").Length >= 16 ? t.Depuis.Substring(11, 5) : t.Depuis,
                Format.Octets(t.TotalEntrant), Format.Octets(t.TotalSortant), t.Paquets, t.Interface, t.PlagesGeoip);
            carte.Definir(t.Pays);
            courbe.Definir(t.Serie);
            Remplir(lvApplications, (t.Applications ?? new List<TraficApplication>()).Select(a => new[] { a.Nom, Format.Octets(a.Entrant), Format.Octets(a.Sortant), a.Destinations.ToString() }), null);
            Remplir(lvPays, (t.Pays ?? new List<TraficPays>()).Select(p => new[] { PaysCarte.NomDe(p.Code) + " (" + p.Code + ")", Format.Octets(p.Entrant + p.Sortant), p.Destinations.ToString(), string.Join(", ", p.Programmes ?? new List<string>()) }),
                (t.Pays ?? new List<TraficPays>()).Select(p => p.Active).ToList());
            Remplir(lvDestinations, (t.Destinations ?? new List<TraficDestination>()).Select(x => new[] { string.IsNullOrEmpty(x.Nom) ? x.Ip : x.Nom + " (" + x.Ip + ")", x.Pays, x.Programme, x.Port.ToString(), Format.Octets(x.Entrant), Format.Octets(x.Sortant) }),
                (t.Destinations ?? new List<TraficDestination>()).Select(x => x.Active).ToList());
        }

        static void Remplir(Liste lv, IEnumerable<string[]> lignes, List<bool> actives)
        {
            int haut = lv.Items.Count > 0 ? lv.TopItem.Index : 0;
            lv.BeginUpdate();
            lv.Items.Clear();
            int i = 0;
            foreach (var l in lignes)
            {
                var item = new ListViewItem(l) { BackColor = Theme.Panneau, ForeColor = Theme.Texte };
                if (actives != null && i < actives.Count && actives[i]) item.ForeColor = Theme.Cyan;
                lv.Items.Add(item);
                i++;
            }
            lv.EndUpdate();
            if (haut > 0 && haut < lv.Items.Count) lv.TopItem = lv.Items[haut];
        }
    }
}
