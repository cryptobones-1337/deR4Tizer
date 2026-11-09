// Pilote de la refonte (phase « Interface et assistant d'installation », U1 : docs/roadmap/interface.md) : coquille WPF
// compilée par csc seul (C# pur, sans XAML compilé ni bibliothèque), jetons de la direction visuelle, navigation
// regroupée ; les pages WinForms d'aujourd'hui y sont hébergées telles quelles jusqu'à leur migration (U2 à U6).
// Ouverte seulement par « --fluent » : l'interface par défaut ne change pas tant que le mainteneur n'a pas décidé, sur
// captures, entre WPF et le repli WebView2.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Forms.Integration;
using System.Windows.Input;
using System.Windows.Media;
using WinForms = System.Windows.Forms;

namespace DeR4Tizer
{
    // Jetons de la direction visuelle (contrastes calculés selon WCAG, testés)
    public static class Jetons
    {
        public static readonly Color Fond = Hex("#141518"), Carte = Hex("#1E2024"), Surface = Hex("#262A30"),
            Texte = Hex("#E6E8EB"), TexteSecondaire = Hex("#9AA3AF"), Accent = Hex("#3BA7F0"), TexteSurAccent = Hex("#0B1220"),
            Danger = Hex("#F0605A"), Attention = Hex("#F2A93B"), Succes = Hex("#2FBF71"), Separateur = Hex("#2E3238");
        public static readonly FontFamily Police = new FontFamily("Segoe UI Variable Text, Segoe UI");
        public static readonly FontFamily PoliceTitre = new FontFamily("Segoe UI Variable Display, Segoe UI");
        public static readonly FontFamily Icones = new FontFamily("Segoe Fluent Icons, Segoe MDL2 Assets");
        public const double Rayon = 6;

        public static Color Hex(string h) { return (Color)ColorConverter.ConvertFromString(h); }
        public static SolidColorBrush Pinceau(Color c) { var b = new SolidColorBrush(c); b.Freeze(); return b; }

        // Rapport de contraste WCAG 2 entre deux couleurs (décision pure, testée)
        public static double Contraste(Color a, Color b)
        {
            Func<Color, double> lum = c =>
            {
                Func<byte, double> canal = x => { double s = x / 255.0; return s <= 0.03928 ? s / 12.92 : Math.Pow((s + 0.055) / 1.055, 2.4); };
                return 0.2126 * canal(c.R) + 0.7152 * canal(c.G) + 0.0722 * canal(c.B);
            };
            double la = lum(a), lb = lum(b);
            return (Math.Max(la, lb) + 0.05) / (Math.Min(la, lb) + 0.05);
        }
    }

    // Entrée de la navigation : clé (celle de la page WinForms, texte français), icône Segoe Fluent
    public class EntreeNav
    {
        public string Cle;
        public string Icone;
        public EntreeNav(string cle, string icone) { Cle = cle; Icone = icone; }
    }

    public class GroupeNav
    {
        public string Titre;
        public List<EntreeNav> Entrees = new List<EntreeNav>();
    }

    public static class NavigationFluent
    {
        public const string VueEnsemble = "Vue d'ensemble";

        // Navigation regroupée (dossier de l'interface) ; le groupe sans titre du bas reste toujours visible (pure, testée)
        public static List<GroupeNav> Groupes()
        {
            Func<string, string[], GroupeNav> g = (titre, e) =>
            {
                var r = new GroupeNav { Titre = titre };
                for (int i = 0; i < e.Length; i += 2) r.Entrees.Add(new EntreeNav(e[i], e[i + 1]));
                return r;
            };
            return new List<GroupeNav>
            {
                g(null, new[] { VueEnsemble, "" }),
                g("Surveillance", new[] { "Connexions", "", "Trafic", "", "Alertes", "", "Incidents", "",
                    "Événements", "", "Détection", "", "Chaînes", "" }),
                g("Protection", new[] { "Blocages", "", "Quarantaine", "", "Menaces", "", "Baseline", "", "Pare-feu", "" }),
                g("Système et confidentialité", new[] { "Démarrage auto", "", "Extensions", "", "Vie privée", "", "Réseau local", "" }),
                g("", new[] { "Réponses en cours", "", "Santé", "", "Réglages", "" }),
            };
        }
    }

    // Un fait de l'état du poste, tel que l'en-tête d'aujourd'hui le montre : texte et gravité (2 à traiter, 1 à
    // surveiller, 0 en ordre ou information)
    public class PointEtat
    {
        public string Texte;
        public int Gravite;
    }

    // Ce que la coquille lit de la fenêtre d'aujourd'hui (U2) : mêmes faits, même chemin pour la panique
    public interface ISourceEtat
    {
        event Action Change;
        List<PointEtat> Points();
        string Statut();
        string TextePanique();
        bool PaniqueActive();
        void DemanderPanique();
        Dictionary<string, PointEtat> Badges();
        // La zone de notification montre la coquille (page demandée, ou celle ouverte si null)
        void Rattacher(Action<string> montrer);
    }

    // Décisions pures de la Vue d'ensemble (testées)
    public static class VueEnsembleFluent
    {
        // Sigles et noms propres gardés tels quels quand un texte en capitales est remis en casse de phrase
        static readonly string[] Sigles = { "DNS", "IP", "PC", "WMI", "OK", "OFF", "CAM", "MIC", "LIVE", "IPv6", "SIEM", "API", "URL", "USB", "UAC" };
        static readonly string[] Noms = { "Defender", "Sysmon", "Internet", "Windows", "Microsoft", "deR4Tizer", "Spamhaus", "Feodo", "Tracker" };

        // Texte en capitales (style néon) remis en casse de phrase ; un texte qui n'est pas tout en capitales est rendu tel
        // quel (noms de programmes, chiffres)
        public static string Phrase(string t)
        {
            if (string.IsNullOrEmpty(t)) return t ?? "";
            var lettres = t.Where(char.IsLetter).ToList();
            if (lettres.Count == 0 || lettres.Any(char.IsLower)) return t.TrimStart('◉', ' ');
            string r = t.TrimStart('◉', ' ').ToLowerInvariant();
            foreach (var s in Sigles)
                r = System.Text.RegularExpressions.Regex.Replace(r, @"(?<![\p{L}])" + System.Text.RegularExpressions.Regex.Escape(s.ToLowerInvariant()) + @"(?![\p{L}])", s);
            foreach (var n in Noms)
                r = System.Text.RegularExpressions.Regex.Replace(r, @"(?<![\p{L}])" + System.Text.RegularExpressions.Regex.Escape(n.ToLowerInvariant()) + @"(?![\p{L}])", n);
            int i = 0;
            while (i < r.Length && !char.IsLetter(r[i])) i++;
            return i < r.Length && char.IsLower(r[i]) ? r.Substring(0, i) + char.ToUpperInvariant(r[i]) + r.Substring(i + 1) : r;
        }

        // Faits de l'en-tête, plus les compteurs colorés de la navigation (baseline peu conforme, démarrage à revoir…) :
        // « à surveiller » au plus, ce ne sont pas des menaces avérées ; sans eux, la tête disait « aucun problème » à côté
        // d'un compteur rouge (capture en VM d'U2)
        public static List<PointEtat> AvecCompteurs(IList<PointEtat> points, IDictionary<string, PointEtat> badges)
        {
            var r = new List<PointEtat>(points ?? new List<PointEtat>());
            if (badges == null) return r;
            foreach (var g in NavigationFluent.Groupes())
                foreach (var e in g.Entrees)
                {
                    PointEtat b;
                    if (badges.TryGetValue(e.Cle, out b) && b.Gravite >= 1)
                        r.Add(new PointEtat { Texte = L.T(e.Cle) + " : " + b.Texte, Gravite = 1 });
                }
            return r;
        }

        // Phrase de tête : jamais « vous êtes protégé » ; un état inconnu n'est pas un état sain
        public static string Resume(IList<PointEtat> points, out int gravite)
        {
            if (points == null || points.Count == 0) { gravite = 1; return L.T("État inconnu : rien n'est publié par le service pour l'instant."); }
            int rouges = points.Count(p => p.Gravite == 2), jaunes = points.Count(p => p.Gravite == 1);
            if (rouges > 0) { gravite = 2; return string.Format(L.T(rouges == 1 ? "{0} point à traiter" : "{0} points à traiter"), rouges); }
            if (jaunes > 0) { gravite = 1; return string.Format(L.T(jaunes == 1 ? "Rien d'avéré, {0} point à surveiller" : "Rien d'avéré, {0} points à surveiller"), jaunes); }
            gravite = 0;
            return L.T("Aucun problème relevé");
        }
    }

    // Coquille du pilote : la fenêtre WinForms d'aujourd'hui reste cachée (zone de notification, rafraîchissement,
    // commandes) ; ses pages sont prêtées une à une à la coquille
    class Coquille : Window
    {
        // État du poste lu de la fenêtre d'aujourd'hui (absent pour un rendu de test)
        readonly ISourceEtat source;
        string ouverte;
        readonly Dictionary<string, TextBlock> pastillesNav = new Dictionary<string, TextBlock>();
        // Pages WinForms prêtées par clé : celles de la fenêtre d'aujourd'hui (Fenetre.PageDe), ou rien pour un rendu de test
        readonly Func<string, WinForms.Control> pages;
        readonly ContentControl zone = new ContentControl();
        readonly TextBlock titrePage = new TextBlock();
        readonly List<Button> boutons = new List<Button>();
        WindowsFormsHost hote;

        public Coquille(Func<string, WinForms.Control> pages) : this(pages, null) { }

        public Coquille(Func<string, WinForms.Control> pages, ISourceEtat source)
        {
            this.pages = pages;
            this.source = source;
            Title = "deR4Tizer";
            // Taille voulue 1200 x 780, ramenée à la zone de travail de l'écran (1024 x 768 sur la VM de test : la fenêtre
            // débordait sous la barre des tâches), centrée
            var travail = SystemParameters.WorkArea;
            MinWidth = Math.Min(900, travail.Width); MinHeight = Math.Min(560, travail.Height);
            Width = Math.Max(MinWidth, Math.Min(1200, travail.Width)); Height = Math.Max(MinHeight, Math.Min(780, travail.Height));
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            Background = Jetons.Pinceau(Jetons.Fond);
            FontFamily = Jetons.Police;
            FontSize = 14;
            Foreground = Jetons.Pinceau(Jetons.Texte);
            UseLayoutRounding = true;
            TextOptions.SetTextFormattingMode(this, TextFormattingMode.Display);

            var grille = new Grid();
            grille.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(248) });
            grille.ColumnDefinitions.Add(new ColumnDefinition());
            var nav = Navigation();
            Grid.SetColumn(nav, 0);
            grille.Children.Add(nav);

            var droite = new DockPanel { Margin = new Thickness(28, 20, 28, 20) };
            titrePage.FontFamily = Jetons.PoliceTitre;
            titrePage.FontSize = 26;
            titrePage.FontWeight = FontWeights.SemiBold;
            titrePage.Margin = new Thickness(0, 0, 0, 16);
            DockPanel.SetDock(titrePage, Dock.Top);
            droite.Children.Add(titrePage);
            droite.Children.Add(zone);
            Grid.SetColumn(droite, 1);
            grille.Children.Add(droite);
            Content = grille;

            int iPage = Array.IndexOf(Environment.GetCommandLineArgs(), "--page");
            string demandee = iPage > 0 && iPage + 1 < Environment.GetCommandLineArgs().Length ? Environment.GetCommandLineArgs()[iPage + 1] : null;
            Ouvrir(demandee != null && NavigationFluent.Groupes().SelectMany(x => x.Entrees).Any(x => x.Cle == demandee) ? demandee : NavigationFluent.VueEnsemble);
            if (source != null)
            {
                Action suivre = () => { MettreAJourPastillesNav(); if (ouverte == NavigationFluent.VueEnsemble) zone.Content = VueEnsemble(); };
                source.Change += suivre;
                source.Rattacher(cle =>
                {
                    Show();
                    if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
                    Activate();
                    if (cle != null) Ouvrir(cle);
                });
                Closed += (s, a) => { source.Change -= suivre; source.Rattacher(null); };
                MettreAJourPastillesNav();
            }
        }

        // Fermeture : avec une source (application réelle), la coquille se cache dans la zone de notification ; elle ne se
        // ferme vraiment que sur « Quitter » (Quitter appelé avant l'arrêt de l'application)
        bool quitter;
        internal void Quitter() { quitter = true; Close(); }
        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            if (source != null && !quitter) { e.Cancel = true; Hide(); return; }
            base.OnClosing(e);
        }

        // Compteurs de la navigation, repris de la fenêtre d'aujourd'hui (alertes non lues, démarrage, vie privée…)
        void MettreAJourPastillesNav()
        {
            var badges = source.Badges();
            foreach (var kv in pastillesNav)
            {
                PointEtat b;
                if (badges.TryGetValue(kv.Key, out b))
                {
                    kv.Value.Text = b.Texte;
                    kv.Value.Foreground = Jetons.Pinceau(b.Gravite == 2 ? Jetons.Danger : b.Gravite == 1 ? Jetons.Attention : Jetons.TexteSecondaire);
                    kv.Value.Visibility = Visibility.Visible;
                }
                else kv.Value.Visibility = Visibility.Collapsed;
            }
        }

        UIElement Navigation()
        {
            var fond = new Border { Background = Jetons.Pinceau(Jetons.Carte) };
            var dock = new DockPanel { Margin = new Thickness(12, 16, 12, 16) };
            var marque = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(8, 0, 0, 20) };
            marque.Children.Add(new TextBlock { Text = "", FontFamily = Jetons.Icones, FontSize = 22, Foreground = Jetons.Pinceau(Jetons.Accent), VerticalAlignment = VerticalAlignment.Center });
            marque.Children.Add(new TextBlock { Text = "deR4Tizer", FontFamily = Jetons.PoliceTitre, FontSize = 20, FontWeight = FontWeights.SemiBold, Margin = new Thickness(10, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center });
            DockPanel.SetDock(marque, Dock.Top);
            dock.Children.Add(marque);

            var groupes = NavigationFluent.Groupes();
            var bas = new StackPanel { Margin = new Thickness(0, 8, 0, 0) };
            bas.Children.Add(new Border { Height = 1, Background = Jetons.Pinceau(Jetons.Separateur), Margin = new Thickness(8, 0, 8, 8) });
            foreach (var e in groupes.Last().Entrees) bas.Children.Add(Bouton(e));
            DockPanel.SetDock(bas, Dock.Bottom);
            dock.Children.Add(bas);

            var haut = new StackPanel();
            foreach (var g in groupes.Take(groupes.Count - 1))
            {
                if (!string.IsNullOrEmpty(g.Titre))
                    haut.Children.Add(new TextBlock { Text = L.T(g.Titre), FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(12, 12, 0, 4) });
                foreach (var e in g.Entrees) haut.Children.Add(Bouton(e));
            }
            // Barre de défilement de Windows masquée (elle jurait avec le thème) ; la molette fait défiler
            dock.Children.Add(new ScrollViewer { Content = haut, VerticalScrollBarVisibility = ScrollBarVisibility.Hidden });
            fond.Child = dock;
            return fond;
        }

        // Bouton de navigation : icône et libellé, fond arrondi, barre d'accent pour la page ouverte
        Button Bouton(EntreeNav e)
        {
            var contenu = new DockPanel { LastChildFill = true };
            var icone = new TextBlock { Text = e.Icone, FontFamily = Jetons.Icones, FontSize = 16, Width = 28, VerticalAlignment = VerticalAlignment.Center };
            DockPanel.SetDock(icone, Dock.Left);
            contenu.Children.Add(icone);
            // Compteur à droite (texte coloré, pas une pastille pleine : la couleur seule ne porte pas le sens, le nombre oui)
            var compteur = new TextBlock { FontSize = 12, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 0, 0), Visibility = Visibility.Collapsed };
            DockPanel.SetDock(compteur, Dock.Right);
            contenu.Children.Add(compteur);
            pastillesNav[e.Cle] = compteur;
            contenu.Children.Add(new TextBlock { Text = L.T(e.Cle), VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis });
            // Couleur donnée au bouton : sans elle, WPF écrit le libellé et l'icône en noir (vu sur le rendu : noir sur gris)
            var b = new Button { Content = contenu, Foreground = Jetons.Pinceau(Jetons.Texte), HorizontalContentAlignment = HorizontalAlignment.Stretch, Padding = new Thickness(12, 6, 12, 6), Margin = new Thickness(0, 1, 0, 1), Cursor = Cursors.Hand };
            b.Template = Modele();
            b.Click += (s, a) => Ouvrir(e.Cle);
            boutons.Add(b);
            cles[b] = e.Cle;
            return b;
        }

        static ControlTemplate modele;
        // Modèle sans le chrome de Windows : fond transparent, survol en surface, page ouverte en surface avec barre d'accent
        static ControlTemplate Modele()
        {
            if (modele != null) return modele;
            var t = new ControlTemplate(typeof(Button));
            var bord = new FrameworkElementFactory(typeof(Border), "fond");
            bord.SetValue(Border.CornerRadiusProperty, new CornerRadius(Jetons.Rayon));
            bord.SetValue(Border.BackgroundProperty, Brushes.Transparent);
            bord.SetValue(Border.PaddingProperty, new TemplateBindingExtension(Control.PaddingProperty));
            var grille = new FrameworkElementFactory(typeof(Grid));
            var barre = new FrameworkElementFactory(typeof(Border), "barre");
            barre.SetValue(FrameworkElement.WidthProperty, 3.0);
            barre.SetValue(FrameworkElement.HeightProperty, 16.0);
            barre.SetValue(FrameworkElement.HorizontalAlignmentProperty, HorizontalAlignment.Left);
            barre.SetValue(FrameworkElement.MarginProperty, new Thickness(-12, 0, 0, 0));
            barre.SetValue(Border.CornerRadiusProperty, new CornerRadius(2));
            barre.SetValue(Border.BackgroundProperty, Jetons.Pinceau(Jetons.Accent));
            barre.SetValue(UIElement.VisibilityProperty, Visibility.Hidden);
            var presentation = new FrameworkElementFactory(typeof(ContentPresenter));
            presentation.SetValue(ContentPresenter.HorizontalAlignmentProperty, new TemplateBindingExtension(Control.HorizontalContentAlignmentProperty));
            grille.AppendChild(barre);
            grille.AppendChild(presentation);
            bord.AppendChild(grille);
            t.VisualTree = bord;
            var survol = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            survol.Setters.Add(new Setter(Border.BackgroundProperty, Jetons.Pinceau(Jetons.Surface), "fond"));
            t.Triggers.Add(survol);
            var ouverte = new Trigger { Property = FrameworkElement.TagProperty, Value = "ouverte" };
            ouverte.Setters.Add(new Setter(Border.BackgroundProperty, Jetons.Pinceau(Jetons.Surface), "fond"));
            ouverte.Setters.Add(new Setter(UIElement.VisibilityProperty, Visibility.Visible, "barre"));
            t.Triggers.Add(ouverte);
            modele = t;
            return t;
        }

        // Ouvre une page : la Vue d'ensemble est native (U2 la remplit) ; les autres sont les pages WinForms prêtées
        internal void Ouvrir(string cle)
        {
            // Une seule entrée ouverte : l'état est dans Tag, la clé reste dans `cles`
            foreach (var b in boutons) b.Tag = cles[b] == cle ? "ouverte" : null;
            ouverte = cle;
            titrePage.Text = L.T(cle);
            if (hote != null) { hote.Child = null; hote.Dispose(); hote = null; }
            if (cle == NavigationFluent.VueEnsemble) { zone.Content = VueEnsemble(); return; }
            WinForms.Control page = pages(cle);
            if (page == null) { zone.Content = new TextBlock { Text = L.T("Page introuvable."), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire) }; return; }
            if (page.Parent != null) page.Parent.Controls.Remove(page);
            page.Visible = true;
            page.Dock = WinForms.DockStyle.Fill;
            hote = new WindowsFormsHost { Child = page, Background = Jetons.Pinceau(Jetons.Fond) };
            zone.Content = hote;
        }

        readonly Dictionary<Button, string> cles = new Dictionary<Button, string>();

        // Entrées ouvertes (une seule attendue), pour les tests
        internal int Ouvertes() { return boutons.Count(b => (string)b.Tag == "ouverte"); }

        // Plus faible contraste entre la couleur réellement donnée à un bouton de navigation et le fond du panneau, pour
        // les tests : le jeton seul ne prouve rien si le bouton ne le reçoit pas
        internal double ContrasteNavigation()
        {
            return boutons.Min(b => { var p = b.Foreground as SolidColorBrush; return p == null ? 0 : Jetons.Contraste(p.Color, Jetons.Carte); });
        }

        // Vue d'ensemble (U2) : les faits de l'en-tête d'aujourd'hui, rangés par gravité, une phrase de tête qui ne promet
        // rien, le bouton panique (même chemin et même confirmation qu'aujourd'hui) et la ligne d'état du service
        UIElement VueEnsemble()
        {
            var pile = new StackPanel { MaxWidth = 760, HorizontalAlignment = HorizontalAlignment.Left };
            var points = source == null ? new List<PointEtat>() : VueEnsembleFluent.AvecCompteurs(source.Points(), source.Badges());
            int gravite;
            string resume = VueEnsembleFluent.Resume(points, out gravite);
            var couleurTete = gravite == 2 ? Jetons.Danger : gravite == 1 ? Jetons.Attention : Jetons.Succes;
            var tete = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 20) };
            tete.Children.Add(new TextBlock { Text = gravite == 2 ? "" : gravite == 1 ? "" : "", FontFamily = Jetons.Icones, FontSize = 22, Foreground = Jetons.Pinceau(couleurTete), VerticalAlignment = VerticalAlignment.Center });
            tete.Children.Add(new TextBlock { Text = resume, FontSize = 20, FontWeight = FontWeights.SemiBold, Margin = new Thickness(12, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center, TextWrapping = TextWrapping.Wrap });
            pile.Children.Add(tete);

            Action<string, int, Color> section = (titre, g, couleur) =>
            {
                var faits = points.Where(p => p.Gravite == g).ToList();
                if (faits.Count == 0) return;
                var carte = new Border { Background = Jetons.Pinceau(Jetons.Carte), CornerRadius = new CornerRadius(8), Padding = new Thickness(20, 16, 20, 16), Margin = new Thickness(0, 0, 0, 12) };
                var contenu = new StackPanel();
                contenu.Children.Add(new TextBlock { Text = L.T(titre), FontSize = 13, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(couleur), Margin = new Thickness(0, 0, 0, 8) });
                foreach (var f in faits)
                {
                    var ligne = new DockPanel { Margin = new Thickness(0, 3, 0, 3) };
                    var puce = new Border { Width = 6, Height = 6, CornerRadius = new CornerRadius(3), Background = Jetons.Pinceau(couleur), Margin = new Thickness(0, 0, 10, 0), VerticalAlignment = VerticalAlignment.Center };
                    DockPanel.SetDock(puce, Dock.Left);
                    ligne.Children.Add(puce);
                    // Texte des faits : chaînes de l'état du service (noms de programmes compris), affichées en texte brut
                    ligne.Children.Add(new TextBlock { Text = f.Texte, TextWrapping = TextWrapping.Wrap });
                    contenu.Children.Add(ligne);
                }
                carte.Child = contenu;
                pile.Children.Add(carte);
            };
            section("À traiter", 2, Jetons.Danger);
            section("À surveiller", 1, Jetons.Attention);
            section("En ordre et informations", 0, Jetons.TexteSecondaire);

            if (source != null)
            {
                bool active = source.PaniqueActive();
                var panique = new Button
                {
                    Content = source.TextePanique(), HorizontalAlignment = HorizontalAlignment.Left, Padding = new Thickness(16, 8, 16, 8),
                    Margin = new Thickness(0, 8, 0, 0), Cursor = Cursors.Hand, FontWeight = FontWeights.SemiBold,
                    Foreground = Jetons.Pinceau(active ? Jetons.TexteSurAccent : Jetons.Danger),
                    Background = Jetons.Pinceau(active ? Jetons.Accent : Jetons.Carte), BorderBrush = Jetons.Pinceau(active ? Jetons.Accent : Jetons.Danger), BorderThickness = new Thickness(1)
                };
                panique.Template = ModeleSimple();
                panique.Click += (s, a) => source.DemanderPanique();
                pile.Children.Add(panique);
                pile.Children.Add(new TextBlock
                {
                    // Phrase selon l'état (audit de #134, S134-01) : quand la panique est active, le bouton sert à la retirer
                    Text = L.T(active ? "Rétablit Internet sur ce poste ; ce qui sera fait est dit avant d'agir."
                                      : "Coupe Internet sur ce poste ; la portée et le retour arrière sont dits avant d'agir."),
                    FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, 6, 0, 16), TextWrapping = TextWrapping.Wrap
                });
                string statut = (source.Statut() ?? "").Replace("▸", "·").Trim(' ', '·');
                if (statut != "")
                    pile.Children.Add(new TextBlock { Text = statut, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap });
            }
            return new ScrollViewer { Content = pile, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        }

        static ControlTemplate modeleSimple;
        // Bouton d'action : fond, bordure et coins arrondis donnés par le bouton, sans le chrome de Windows
        static ControlTemplate ModeleSimple()
        {
            if (modeleSimple != null) return modeleSimple;
            var t = new ControlTemplate(typeof(Button));
            var bord = new FrameworkElementFactory(typeof(Border), "fond");
            bord.SetValue(Border.CornerRadiusProperty, new CornerRadius(Jetons.Rayon));
            bord.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Control.BackgroundProperty));
            bord.SetValue(Border.BorderBrushProperty, new TemplateBindingExtension(Control.BorderBrushProperty));
            bord.SetValue(Border.BorderThicknessProperty, new TemplateBindingExtension(Control.BorderThicknessProperty));
            bord.SetValue(Border.PaddingProperty, new TemplateBindingExtension(Control.PaddingProperty));
            var presentation = new FrameworkElementFactory(typeof(ContentPresenter));
            bord.AppendChild(presentation);
            t.VisualTree = bord;
            var survol = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            survol.Setters.Add(new Setter(UIElement.OpacityProperty, 0.85, "fond"));
            t.Triggers.Add(survol);
            modeleSimple = t;
            return t;
        }
    }
}
