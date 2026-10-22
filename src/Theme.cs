// Thème « néon » de l'interface : couleurs, polices et contrôles dessinés à la main
// (liste sombre, boutons de navigation, boutons néon, menus contextuels sombres).
using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace DeR4Tizer
{
    static class Theme
    {
        public static readonly Color Fond = C("#0A0E14"), Panneau = C("#0F1520"), Panneau2 = C("#151D2C"), Bordure = C("#1E2A3D"),
            Texte = C("#C8D3E0"), TexteDim = C("#6B7A90"), Cyan = C("#00E5FF"), Magenta = C("#FF2BD6"), Jaune = C("#FFD60A"),
            Rouge = C("#FF3B5C"), Vert = C("#2BFF88"), Selection = C("#0E3442"),
            FondCritique = C("#40101F"), FondAlerte = C("#2E1322"), FondAttention = C("#29230F"), FondActif = C("#3A0F1A");

        public static readonly Font Mono, MonoGras, Titre, TitrePage, Nav, Petit, PetitGras;

        static Theme()
        {
            Mono = Police(9f, FontStyle.Regular, "Cascadia Mono", "Consolas");
            MonoGras = new Font(Mono, FontStyle.Bold);
            Titre = Police(21f, FontStyle.Regular, "Bahnschrift SemiBold", "Bahnschrift", "Segoe UI Semibold");
            TitrePage = Police(14f, FontStyle.Regular, "Bahnschrift SemiBold", "Bahnschrift", "Segoe UI Semibold");
            Nav = Police(10.5f, FontStyle.Regular, "Bahnschrift SemiBold", "Bahnschrift", "Segoe UI Semibold");
            Petit = Police(9f, FontStyle.Regular, "Segoe UI");
            PetitGras = Police(8.5f, FontStyle.Regular, "Bahnschrift SemiBold", "Segoe UI Semibold");
        }

        static Color C(string hex) { return ColorTranslator.FromHtml(hex); }

        // Première police installée de la liste (Windows remplace silencieusement une police absente)
        static Font Police(float taille, FontStyle style, params string[] noms)
        {
            foreach (string n in noms)
            {
                var f = new Font(n, taille, style);
                if (f.Name.Equals(n, StringComparison.OrdinalIgnoreCase)) return f;
                f.Dispose();
            }
            return new Font(FontFamily.GenericSansSerif, taille, style);
        }

        // Couleur de la barre latérale d'une ligne, selon son fond
        public static Color Accent(Color fond)
        {
            if (fond == FondCritique || fond == FondActif) return Rouge;
            if (fond == FondAlerte) return Magenta;
            if (fond == FondAttention) return Jaune;
            return Color.Empty;
        }

        public static Color Melange(Color a, Color b, float t)
        {
            return Color.FromArgb((int)(a.R + (b.R - a.R) * t), (int)(a.G + (b.G - a.G) * t), (int)(a.B + (b.B - a.B) * t));
        }

        public static Icon IconeApplication(int taille)
        {
            using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("deR4Tizer.ico"))
                return s != null ? new Icon(s, taille, taille) : SystemIcons.Shield;
        }

        // Image d'une taille donnée lue dans l'icône (les images y sont en PNG, qu'Icon.ToBitmap ne sait pas convertir)
        public static Image ImageApplication(int taille)
        {
            using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("deR4Tizer.ico"))
            {
                if (s == null) return SystemIcons.Shield.ToBitmap();
                var octets = new byte[s.Length];
                s.Read(octets, 0, octets.Length);
                int n = BitConverter.ToUInt16(octets, 4);
                for (int i = 0; i < n; i++)
                {
                    int e = 6 + 16 * i, l = octets[e] == 0 ? 256 : octets[e];
                    if (l != taille) continue;
                    int longueur = BitConverter.ToInt32(octets, e + 8), position = BitConverter.ToInt32(octets, e + 12);
                    return Image.FromStream(new MemoryStream(octets, position, longueur));
                }
                return SystemIcons.Shield.ToBitmap();
            }
        }

        // Pastille rouge sur l'icône de la zone de notification quand des alertes ne sont pas lues
        public static Icon IconeAvecPastille(Icon baseIcone)
        {
            using (var b = new Bitmap(32, 32))
            {
                using (var g = Graphics.FromImage(b))
                {
                    g.SmoothingMode = SmoothingMode.AntiAlias;
                    g.DrawIcon(new Icon(baseIcone, 32, 32), new Rectangle(0, 0, 32, 32));
                    g.FillEllipse(new SolidBrush(Fond), 17, 17, 15, 15);
                    g.FillEllipse(new SolidBrush(Rouge), 19, 19, 11, 11);
                }
                return Icon.FromHandle(b.GetHicon());
            }
        }

        public static GraphicsPath Arrondi(RectangleF r, float rayon)
        {
            var p = new GraphicsPath();
            float d = rayon * 2;
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        [DllImport("dwmapi.dll")]
        static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribut, ref int valeur, int taille);

        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
        static extern int SetWindowTheme(IntPtr hwnd, string appli, string liste);

        [DllImport("user32.dll")]
        public static extern IntPtr SendMessage(IntPtr hwnd, int message, IntPtr w, IntPtr l);

        static int Colorref(Color c) { return c.R | (c.G << 8) | (c.B << 16); }

        // Barre de titre sombre (Windows 10/11) avec bordure cyan (Windows 11)
        public static void FenetreSombre(Form f)
        {
            f.BackColor = Fond;
            f.ForeColor = Texte;
            f.HandleCreated += (s, e) =>
            {
                int oui = 1, legende = Colorref(Fond), bordure = Colorref(Cyan), titre = Colorref(Cyan);
                DwmSetWindowAttribute(f.Handle, 20, ref oui, 4);
                DwmSetWindowAttribute(f.Handle, 35, ref legende, 4);
                DwmSetWindowAttribute(f.Handle, 34, ref bordure, 4);
                DwmSetWindowAttribute(f.Handle, 36, ref titre, 4);
            };
        }

        public static void DefilementSombre(Control c)
        {
            SetWindowTheme(c.Handle, "DarkMode_Explorer", null);
        }

        public static void ThemeEnTete(IntPtr entete)
        {
            SetWindowTheme(entete, "DarkMode_ItemsView", null);
        }
    }

    // Liste sombre dessinée à la main : barre de couleur à gauche des lignes signalées, sections en magenta
    class Liste : ListView
    {
        public const string Section = "§";

        public Liste()
        {
            DoubleBuffered = true;
            View = View.Details;
            FullRowSelect = true;
            HideSelection = false;
            ShowItemToolTips = true;
            OwnerDraw = true;
            Dock = DockStyle.Fill;
            BorderStyle = BorderStyle.None;
            BackColor = Theme.Panneau;
            ForeColor = Theme.Texte;
            Font = Theme.Mono;
            HeaderStyle = ColumnHeaderStyle.Nonclickable;
        }

        public void Colonnes(params object[] nomsEtLargeurs)
        {
            for (int i = 0; i < nomsEtLargeurs.Length; i += 2) Columns.Add(L.T((string)nomsEtLargeurs[i]), (int)nomsEtLargeurs[i + 1]);
        }

        public ListViewItem AjouterSection(string titre)
        {
            var item = new ListViewItem(titre) { Tag = Section };
            Items.Add(item);
            return item;
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            Theme.DefilementSombre(this);
            Theme.ThemeEnTete(Theme.SendMessage(Handle, 0x101F, IntPtr.Zero, IntPtr.Zero));     // LVM_GETHEADER
        }

        protected override void OnItemSelectionChanged(ListViewItemSelectionChangedEventArgs e)
        {
            if (e.IsSelected && (e.Item.Tag as string) == Section) e.Item.Selected = false;
            base.OnItemSelectionChanged(e);
        }

        protected override void OnDrawColumnHeader(DrawListViewColumnHeaderEventArgs e)
        {
            using (var fond = new SolidBrush(Theme.Fond)) e.Graphics.FillRectangle(fond, e.Bounds);
            var r = new Rectangle(e.Bounds.X + 8, e.Bounds.Y, e.Bounds.Width - 10, e.Bounds.Height);
            TextRenderer.DrawText(e.Graphics, e.Header.Text.ToUpperInvariant(), Theme.PetitGras, r, Theme.Cyan,
                TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine);
            using (var trait = new Pen(Theme.Bordure))
            {
                e.Graphics.DrawLine(trait, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
                e.Graphics.DrawLine(trait, e.Bounds.Right - 1, e.Bounds.Top + 6, e.Bounds.Right - 1, e.Bounds.Bottom - 6);
            }
        }

        protected override void OnDrawItem(DrawListViewItemEventArgs e)
        {
            if ((e.Item.Tag as string) != Section) return;
            // Ligne de section : texte magenta sur toute la largeur
            using (var fond = new SolidBrush(Theme.Fond)) e.Graphics.FillRectangle(fond, e.Bounds);
            var r = new Rectangle(e.Bounds.X + 8, e.Bounds.Y, e.Bounds.Width - 8, e.Bounds.Height);
            TextRenderer.DrawText(e.Graphics, "▌ " + e.Item.Text.ToUpperInvariant(), Theme.PetitGras, r, Theme.Magenta,
                TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
        }

        protected override void OnDrawSubItem(DrawListViewSubItemEventArgs e)
        {
            if ((e.Item.Tag as string) == Section) return;
            Color fond = e.Item.Selected ? Theme.Selection : e.Item.BackColor;
            using (var b = new SolidBrush(fond)) e.Graphics.FillRectangle(b, e.Bounds);
            int retrait = 8;
            if (e.ColumnIndex == 0)
            {
                Color accent = e.Item.Selected ? Theme.Cyan : Theme.Accent(e.Item.BackColor);
                if (accent != Color.Empty)
                    using (var b = new SolidBrush(accent)) e.Graphics.FillRectangle(b, e.Bounds.X, e.Bounds.Y + 1, 3, e.Bounds.Height - 2);
                retrait = 12;
            }
            var r = new Rectangle(e.Bounds.X + retrait, e.Bounds.Y, e.Bounds.Width - retrait - 4, e.Bounds.Height);
            TextRenderer.DrawText(e.Graphics, e.SubItem.Text, e.Item.Font, r, e.Item.Selected ? Color.White : e.Item.ForeColor,
                TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);
        }
    }

    // Entrée de la barre de navigation, avec compteur
    class BoutonNav : Control
    {
        bool actif, survol;
        int badge;
        public Color CouleurBadge = Theme.Magenta;
        public string TexteBadge;
        public string Cle;      // texte français d'origine (--page)

        public BoutonNav(string texte, int largeur)
        {
            Cle = texte;
            Text = L.T(texte);
            Size = new Size(largeur, 36);
            Margin = Padding.Empty;
            Cursor = Cursors.Hand;
            Font = Theme.Nav;
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        }

        public bool Actif { get { return actif; } set { if (actif != value) { actif = value; Invalidate(); } } }
        public void PerformClick() { OnClick(EventArgs.Empty); }
        public int Badge { get { return badge; } set { if (badge != value) { badge = value; Invalidate(); } } }

        protected override void OnMouseEnter(EventArgs e) { survol = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { survol = false; Invalidate(); base.OnMouseLeave(e); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            Color fond = actif ? Theme.Panneau2 : survol ? Theme.Melange(Theme.Fond, Theme.Panneau2, 0.6f) : Theme.Fond;
            using (var b = new SolidBrush(fond)) g.FillRectangle(b, ClientRectangle);
            if (actif)
            {
                using (var b = new SolidBrush(Theme.Cyan)) g.FillRectangle(b, 0, 8, 3, Height - 16);
                using (var halo = new LinearGradientBrush(new Rectangle(3, 0, 60, Height), Color.FromArgb(40, Theme.Cyan), Color.FromArgb(0, Theme.Cyan), 0f))
                    g.FillRectangle(halo, 3, 0, 60, Height);
            }
            Color texte = actif ? Theme.Cyan : survol ? Theme.Texte : Theme.TexteDim;
            TextRenderer.DrawText(g, Text.ToUpperInvariant(), Font, new Rectangle(20, 0, Width - 70, Height), texte,
                TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis);
            string b2 = TexteBadge ?? (badge > 0 ? (badge > 999 ? "999+" : badge.ToString()) : null);
            if (b2 != null)
            {
                var taille = TextRenderer.MeasureText(b2, Theme.PetitGras);
                var r = new RectangleF(Width - taille.Width - 26, (Height - 18) / 2f, taille.Width + 12, 18);
                using (var chemin = Theme.Arrondi(r, 9))
                using (var b = new SolidBrush(CouleurBadge)) g.FillPath(b, chemin);
                TextRenderer.DrawText(g, b2, Theme.PetitGras, Rectangle.Round(r), Theme.Fond,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
            }
        }
    }

    // Bouton plat au contour néon
    class BoutonNeon : Button
    {
        public BoutonNeon(string texte, Color couleur)
        {
            Text = L.T(texte).ToUpperInvariant();
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderColor = couleur;
            FlatAppearance.BorderSize = 1;
            FlatAppearance.MouseOverBackColor = Theme.Melange(Theme.Fond, couleur, 0.18f);
            FlatAppearance.MouseDownBackColor = Theme.Melange(Theme.Fond, couleur, 0.32f);
            BackColor = Theme.Fond;
            ForeColor = couleur;
            Font = Theme.PetitGras;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Padding = new Padding(10, 4, 10, 4);
            Margin = new Padding(0, 0, 8, 6);
            Cursor = Cursors.Hand;
            UseVisualStyleBackColor = false;
        }
    }

    // Menus contextuels sombres
    class RenduSombre : ToolStripProfessionalRenderer
    {
        public RenduSombre() : base(new Couleurs()) { RoundedEdges = false; }

        protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
        {
            e.TextColor = e.Item.Selected ? Theme.Cyan : Theme.Texte;
            base.OnRenderItemText(e);
        }

        class Couleurs : ProfessionalColorTable
        {
            public override Color ToolStripDropDownBackground { get { return Theme.Panneau2; } }
            public override Color ImageMarginGradientBegin { get { return Theme.Panneau2; } }
            public override Color ImageMarginGradientMiddle { get { return Theme.Panneau2; } }
            public override Color ImageMarginGradientEnd { get { return Theme.Panneau2; } }
            public override Color MenuBorder { get { return Theme.Bordure; } }
            public override Color MenuItemBorder { get { return Theme.Cyan; } }
            public override Color MenuItemSelected { get { return Theme.Selection; } }
            public override Color MenuItemSelectedGradientBegin { get { return Theme.Selection; } }
            public override Color MenuItemSelectedGradientEnd { get { return Theme.Selection; } }
            public override Color SeparatorDark { get { return Theme.Bordure; } }
            public override Color SeparatorLight { get { return Theme.Panneau2; } }
        }
    }
}
