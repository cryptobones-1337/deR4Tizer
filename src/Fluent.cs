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

    // Ce que la page Alertes de la coquille lit de la fenêtre d'aujourd'hui (U2b) ; les actions passent par les mêmes
    // méthodes et les mêmes questions que le menu de la liste d'aujourd'hui
    public interface ISourceAlertes
    {
        List<Alerte> Alertes();
        string AucuneAlerte();
        bool CollectesEnAlarme();
        string Collectes();
        string DerniereLue();
        void MarquerAlertesLues();
        void AgirAlerte(Alerte a, string action);
    }

    // Ligne du panneau de détails : titre, texte neutralisé, chasse fixe pour les chemins
    public class LigneDetail
    {
        public string Titre;
        public string Texte;
        public bool Chasse;
    }

    // Décisions pures de la page Alertes (testées)
    public static class VueAlertesFluent
    {
        public const int Maximum = 500;
        public static readonly string[] Reponses = { "isolerProgramme", "suspendre", "tuerChaine", "quarantaine" };

        public static int Gravite(string niveau) { return niveau == "Critique" ? 2 : niveau == "Alerte" ? 1 : 0; }

        // Plus récentes d'abord ; niveau null : toutes ; au plus Maximum (les plus récentes)
        public static List<Alerte> Filtrer(IList<Alerte> alertes, string niveau)
        {
            return (alertes ?? new List<Alerte>()).Where(a => a != null && (niveau == null || a.Niveau == niveau))
                .Reverse().Take(Maximum).ToList();
        }

        public static bool NonLue(Alerte a, string derniereLue) { return string.CompareOrdinal(a.Heure, derniereLue ?? "") > 0; }

        // Actions offertes, dans l'ordre des boutons, selon ce que l'alerte permet (mêmes conditions que les méthodes
        // d'aujourd'hui : destination connue pour bloquer, jamais d'exception pour une critique, PID pour suspendre et
        // tuer, chemin pour isoler, mettre en quarantaine et ouvrir l'emplacement)
        public static List<string> Actions(Alerte a)
        {
            var r = new List<string>();
            if (a == null) return r;
            bool chemin = !string.IsNullOrEmpty(a.Chemin), pid = a.Pid != null && a.Pid > 4;
            if (!string.IsNullOrEmpty(a.Ip) || !string.IsNullOrEmpty(a.NomDns)) r.Add("bloquer");
            if (a.Niveau != "Critique") r.Add("exception");
            if (chemin) r.Add("isolerProgramme");
            if (pid) { r.Add("suspendre"); r.Add("tuerChaine"); }
            if (chemin) { r.Add("quarantaine"); r.Add("emplacement"); }
            return r;
        }

        public static string Libelle(string action)
        {
            switch (action)
            {
                case "bloquer": return L.T("Bloquer cette destination");
                case "exception": return L.T("Ne plus alerter pour ce comportement");
                case "isolerProgramme": return L.T("Isoler ce programme du réseau");
                case "suspendre": return L.T("Suspendre le processus");
                case "tuerChaine": return L.T("Tuer le processus et ses enfants");
                case "quarantaine": return L.T("Mettre le programme en quarantaine");
                case "emplacement": return L.T("Ouvrir l'emplacement du programme");
                default: return action;
            }
        }

        // Détails, chaque texte venu du service neutralisé (Canal.Visible) ; lignes vides omises
        public static List<LigneDetail> Detail(Alerte a)
        {
            var r = new List<LigneDetail>();
            if (a == null) return r;
            Action<string, string, bool> ajouter = (titre, texte, chasse) => { if (!string.IsNullOrEmpty(texte)) r.Add(new LigneDetail { Titre = L.T(titre), Texte = Canal.Visible(texte), Chasse = chasse }); };
            ajouter("Heure", a.Heure, false);
            ajouter("Destination", string.IsNullOrEmpty(a.Destination) ? null : a.Destination + (a.Port > 0 ? ", port " + a.Port : ""), false);
            ajouter("Règle", string.IsNullOrEmpty(a.Regle) ? null : a.Regle + (string.IsNullOrEmpty(a.Collecte) ? "" : " (" + L.T("collecte présumée") + VueEnsembleFluent.DeuxPoints + a.Collecte + ")"), false);
            ajouter("Technique", a.Mitre, false);
            ajouter("Que faire", a.Conseil, false);
            ajouter("Raisons", a.Raisons, false);
            ajouter("Chemin", a.Chemin, true);
            return r;
        }
    }

    // Décisions pures de la Vue d'ensemble (testées)
    public static class VueEnsembleFluent
    {
        // Deux-points selon la langue : espace avant en français, pas en anglais (capture U2a : « Baseline : 12% » en anglais)
        public static string DeuxPoints { get { return L.En ? ": " : " : "; } }

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

        // Texte venu du service (noms de programmes, d'outils de prise en main, version) prêt à afficher : casse de phrase,
        // puis caractères de contrôle et de mise en forme invisibles (sens d'écriture, largeur nulle, retours à la ligne)
        // neutralisés par Canal.Visible, garde-fou de la phase (relecture de #134, D1)
        public static string Affichable(string t) { return Canal.Visible(Phrase(t)); }

        // Texte de plusieurs lignes (bandeau des collectes) : chaque ligne neutralisée à part, les retours à la ligne de la
        // mise en page gardés (sinon « non vues?○ ListesDomaines » : capture U2b)
        public static string Lignes(string t)
        {
            if (string.IsNullOrEmpty(t)) return "";
            return string.Join("\n", t.Replace("\r\n", "\n").Split('\n').Select(Canal.Visible));
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
                        r.Add(new PointEtat { Texte = L.T(e.Cle) + DeuxPoints + b.Texte, Gravite = 1 });
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
        PageAlertes pageAlertes;
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
                Action suivre = () =>
                {
                    MettreAJourPastillesNav();
                    if (ouverte == NavigationFluent.VueEnsemble) zone.Content = VueEnsemble();
                    else if (ouverte == "Alertes" && pageAlertes != null) { pageAlertes.Rafraichir(); if (IsVisible) ((ISourceAlertes)source).MarquerAlertesLues(); }
                };
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
            pageAlertes = null;
            if (cle == NavigationFluent.VueEnsemble) { zone.Content = VueEnsemble(); return; }
            // Page Alertes en WPF (U2b) quand la fenêtre d'aujourd'hui la fournit ; sinon la page hébergée
            var alertes = source as ISourceAlertes;
            if (cle == "Alertes" && alertes != null)
            {
                pageAlertes = new PageAlertes(alertes);
                zone.Content = pageAlertes;
                alertes.MarquerAlertesLues();
                return;
            }
            // Incidents et Réponses en cours en WPF (U2c) : elles lisent leurs fichiers elles-mêmes, sans droit nouveau
            if (cle == "Incidents") { zone.Content = new PageIncidentsFluent(); return; }
            if (cle == "Réponses en cours") { zone.Content = new PageReponsesFluent(); return; }
            // Santé et Détection en WPF (U3a)
            if (cle == "Santé") { zone.Content = new PageSanteFluent(); return; }
            if (cle == "Détection") { zone.Content = new PageDetectionFluent(); return; }
            // Événements en WPF (U3b)
            if (cle == "Événements") { zone.Content = new PageEvenementsFluent(); return; }
            // Connexions et Chaînes en WPF (U4a) : actions par la fenêtre d'aujourd'hui (mêmes questions)
            if (cle == "Connexions") { zone.Content = new PageConnexionsFluent(source as ISourceReponses); return; }
            if (cle == "Chaînes") { zone.Content = new PageChainesFluent(source as ISourceReponses); return; }
            // Trafic en WPF (U4b) : lecture seule, aucune action
            if (cle == "Trafic") { zone.Content = new PageTraficFluent(); return; }
            // Blocages, Quarantaine et Menaces en WPF (U5a) : mêmes commandes et mêmes questions (ActionsProtection)
            if (cle == "Blocages") { zone.Content = new PageBlocagesFluent(); return; }
            if (cle == "Quarantaine") { zone.Content = new PageQuarantaineFluent(); return; }
            if (cle == "Menaces") { zone.Content = new PageMenacesFluent(); return; }
            // Baseline et Pare-feu en WPF (U5b)
            if (cle == "Baseline") { zone.Content = new PageBaselineFluent(); return; }
            if (cle == "Pare-feu") { zone.Content = new PageParefeuFluent(); return; }
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
                    // Texte des faits : déjà neutralisé par la source (VueEnsembleFluent.Affichable, Canal.Visible), affiché en texte brut
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
            presentation.SetValue(ContentPresenter.HorizontalAlignmentProperty, new TemplateBindingExtension(Control.HorizontalContentAlignmentProperty));
            bord.AppendChild(presentation);
            t.VisualTree = bord;
            var survol = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
            survol.Setters.Add(new Setter(UIElement.OpacityProperty, 0.85, "fond"));
            t.Triggers.Add(survol);
            modeleSimple = t;
            return t;
        }

        internal static ControlTemplate ModeleBouton() { return ModeleSimple(); }
    }

    // Page Alertes en WPF (U2b) : filtres par niveau, liste, panneau de détails à droite avec des boutons explicites.
    // Les actions passent par la fenêtre d'aujourd'hui (mêmes méthodes, mêmes questions) ; chaque texte venu du service
    // est neutralisé (Canal.Visible) avant affichage
    class PageAlertes : Grid
    {
        readonly ISourceAlertes source;
        readonly StackPanel liste = new StackPanel();
        readonly ContentControl detail = new ContentControl();
        readonly TextBlock bandeau = new TextBlock { TextWrapping = TextWrapping.Wrap, FontSize = 12, Margin = new Thickness(0, 0, 0, 12) };
        readonly StackPanel filtres = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 12) };
        string niveau;          // null : toutes
        string choisie;         // identifiant de l'alerte affichée dans le panneau
        static readonly FontFamily Chasse = new FontFamily("Cascadia Mono, Consolas");

        public PageAlertes(ISourceAlertes source)
        {
            this.source = source;
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            RowDefinitions.Add(new RowDefinition());
            ColumnDefinitions.Add(new ColumnDefinition());
            ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(340) });
            Grid.SetColumnSpan(filtres, 2); Children.Add(filtres);
            Grid.SetRow(bandeau, 1); Grid.SetColumnSpan(bandeau, 2); Children.Add(bandeau);
            var defile = new ScrollViewer { Content = liste, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(0, 0, 16, 0) };
            Grid.SetRow(defile, 2); Children.Add(defile);
            var panneau = new Border { Background = Jetons.Pinceau(Jetons.Carte), CornerRadius = new CornerRadius(8), Padding = new Thickness(20) };
            panneau.Child = new ScrollViewer { Content = detail, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            Grid.SetRow(panneau, 2); Grid.SetColumn(panneau, 1); Children.Add(panneau);
            Rafraichir();
        }

        string vu;              // signature du dernier affichage : rien n'est reconstruit si rien n'a changé

        // Reconstruit filtres, liste et panneau ; filtre et alerte choisie sont gardés. Appelé à chaque rafraîchissement de
        // la fenêtre d'aujourd'hui (2 s) : seulement si les alertes, la lecture ou les collectes ont changé (défilement gardé)
        internal void Rafraichir()
        {
            var toutes = source.Alertes() ?? new List<Alerte>();
            string signature = toutes.Count + "|" + (toutes.Count > 0 ? toutes[toutes.Count - 1].Id : "") + "|" + source.DerniereLue() + "|" + source.Collectes() + "|" + niveau + "|" + choisie;
            if (signature == vu) return;
            vu = signature;
            filtres.Children.Clear();
            foreach (var f in new[] { new { Cle = (string)null, Texte = "Toutes" }, new { Cle = "Critique", Texte = "Critiques" }, new { Cle = "Alerte", Texte = "Alertes" }, new { Cle = "Info", Texte = "Infos" } })
            {
                int n = f.Cle == null ? toutes.Count : toutes.Count(a => a.Niveau == f.Cle);
                bool actif = niveau == f.Cle;
                var b = new Button
                {
                    Content = L.T(f.Texte) + " (" + n + ")", Padding = new Thickness(12, 4, 12, 4), Margin = new Thickness(0, 0, 8, 0), Cursor = Cursors.Hand,
                    Background = Jetons.Pinceau(actif ? Jetons.Surface : Jetons.Fond), BorderBrush = Jetons.Pinceau(actif ? Jetons.Accent : Jetons.Separateur),
                    BorderThickness = new Thickness(1), Foreground = Jetons.Pinceau(Jetons.Texte)
                };
                b.Template = Coquille.ModeleBouton();
                string cle = f.Cle;
                b.Click += (s, e) => { niveau = cle; Rafraichir(); };
                filtres.Children.Add(b);
            }
            string collectes = source.Collectes();
            bandeau.Text = collectes ?? "";
            bandeau.Visibility = string.IsNullOrEmpty(collectes) ? Visibility.Collapsed : Visibility.Visible;
            bandeau.Foreground = Jetons.Pinceau(source.CollectesEnAlarme() ? Jetons.Attention : Jetons.TexteSecondaire);

            liste.Children.Clear();
            var visibles = VueAlertesFluent.Filtrer(toutes, niveau);
            if (visibles.Count == 0)
                liste.Children.Add(new TextBlock
                {
                    Text = niveau == null ? source.AucuneAlerte() : L.T("Aucune alerte de ce niveau."), TextWrapping = TextWrapping.Wrap,
                    Foreground = Jetons.Pinceau(niveau == null && source.CollectesEnAlarme() ? Jetons.Attention : Jetons.TexteSecondaire)
                });
            string lue = source.DerniereLue();
            foreach (var a in visibles) liste.Children.Add(Ligne(a, VueAlertesFluent.NonLue(a, lue)));
            if (toutes.Count(a => niveau == null || a.Niveau == niveau) > VueAlertesFluent.Maximum)
                liste.Children.Add(new TextBlock { Text = string.Format(L.T("Les {0} plus récentes sont affichées."), VueAlertesFluent.Maximum), FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, 8, 0, 0) });
            Afficher(visibles.FirstOrDefault(a => a.Id == choisie) ?? visibles.FirstOrDefault());
        }

        UIElement Ligne(Alerte a, bool nonLue)
        {
            int g = VueAlertesFluent.Gravite(a.Niveau);
            var couleur = g == 2 ? Jetons.Danger : g == 1 ? Jetons.Attention : Jetons.TexteSecondaire;
            bool ouverte = a.Id == choisie;
            var cadre = new Border
            {
                Background = Jetons.Pinceau(ouverte ? Jetons.Surface : Jetons.Carte), CornerRadius = new CornerRadius(6), Padding = new Thickness(14, 8, 14, 8),
                Margin = new Thickness(0, 0, 0, 6), BorderThickness = new Thickness(3, 0, 0, 0), BorderBrush = Jetons.Pinceau(couleur), Cursor = Cursors.Hand
            };
            var pile = new StackPanel();
            var haut = new DockPanel();
            var niveauTexte = new TextBlock { Text = Canal.Visible(L.T(a.Niveau ?? "")), FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(couleur), Margin = new Thickness(8, 0, 0, 0) };
            DockPanel.SetDock(niveauTexte, Dock.Right);
            haut.Children.Add(niveauTexte);
            haut.Children.Add(new TextBlock { Text = (nonLue ? "• " : "") + Canal.Visible(a.Processus), FontWeight = nonLue ? FontWeights.SemiBold : FontWeights.Normal, TextTrimming = TextTrimming.CharacterEllipsis });
            pile.Children.Add(haut);
            string sous = Canal.Visible(a.Heure) + (string.IsNullOrEmpty(a.Destination) ? "" : "  ·  " + Canal.Visible(a.Destination));
            pile.Children.Add(new TextBlock { Text = sous, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextTrimming = TextTrimming.CharacterEllipsis });
            cadre.Child = pile;
            cadre.MouseLeftButtonUp += (s, e) => { choisie = a.Id; Rafraichir(); };
            return cadre;
        }

        void Afficher(Alerte a)
        {
            if (a == null) { detail.Content = new TextBlock { Text = L.T("Sélectionnez une alerte pour voir la technique d'attaque et quoi faire."), TextWrapping = TextWrapping.Wrap, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire) }; return; }
            choisie = a.Id;
            int g = VueAlertesFluent.Gravite(a.Niveau);
            var pile = new StackPanel();
            pile.Children.Add(new TextBlock { Text = Canal.Visible(a.Processus), FontSize = 18, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            pile.Children.Add(new TextBlock { Text = Canal.Visible(L.T(a.Niveau ?? "")), FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(g == 2 ? Jetons.Danger : g == 1 ? Jetons.Attention : Jetons.TexteSecondaire), Margin = new Thickness(0, 2, 0, 12) });
            foreach (var l in VueAlertesFluent.Detail(a))
            {
                pile.Children.Add(new TextBlock { Text = l.Titre, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, 6, 0, 2) });
                var t = new TextBlock { Text = l.Texte, TextWrapping = TextWrapping.Wrap };
                if (l.Chasse) { t.FontFamily = Chasse; t.FontSize = 12; }
                pile.Children.Add(t);
            }
            var actions = VueAlertesFluent.Actions(a);
            if (actions.Count > 0)
                pile.Children.Add(new TextBlock { Text = L.T("Agir"), FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, 18, 0, 6) });
            foreach (var act in actions)
            {
                bool reponse = VueAlertesFluent.Reponses.Contains(act);
                var b = new Button
                {
                    Content = VueAlertesFluent.Libelle(act), HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Left,
                    Padding = new Thickness(12, 6, 12, 6), Margin = new Thickness(0, 0, 0, 6), Cursor = Cursors.Hand, Background = Jetons.Pinceau(Jetons.Carte),
                    BorderBrush = Jetons.Pinceau(reponse ? Jetons.Danger : Jetons.Separateur), BorderThickness = new Thickness(1),
                    Foreground = Jetons.Pinceau(reponse ? Jetons.Danger : Jetons.Texte)
                };
                b.Template = Coquille.ModeleBouton();
                string action = act;
                b.Click += (s, e) => source.AgirAlerte(a, action);
                pile.Children.Add(b);
            }
            detail.Content = pile;
        }
    }

    // Décisions pures de la page Incidents de la coquille (U2c), testées par tests\rendu-pilote.ps1. Le texte vient de
    // VueIncidents.Detail, déjà neutralisé (Canal.Visible) ; il est seulement découpé en sections
    public static class VueIncidentsFluent
    {
        // Transitions offertes, dans l'ordre des boutons : les mêmes que la page d'aujourd'hui (VueIncidents.Permise)
        public static List<string> Actions(IncidentSuivi i)
        {
            var l = new List<string>();
            if (i == null) return l;
            foreach (var vers in new[] { "PrisEnCharge", "Clos", "Ouvert" }) if (VueIncidents.Permise(i.Etat, vers)) l.Add(vers);
            return l;
        }

        public static string Libelle(string vers)
        {
            return vers == "PrisEnCharge" ? L.T("Prendre en charge") : vers == "Clos" ? L.T("Clore…") : L.T("Rouvrir");
        }

        // 2 : risque confirmé (rouge) ; 1 : critique non clos (à surveiller) ; 0 : le reste. L'état est toujours écrit
        public static int Gravite(IncidentSuivi i)
        {
            if (i == null || i.Etat == "Clos") return 0;
            return VueIncidents.RisqueConfirme(i) ? 2 : i.Niveau == "Critique" ? 1 : 0;
        }

        // Sections du panneau : la première (résumé) sans titre, puis une par ligne « -- Titre » de VueIncidents.Detail.
        // Les lignes gardent leur ordre ; aucune n'est perdue
        public static List<LigneDetail> Sections(string detail)
        {
            var l = new List<LigneDetail>();
            var courante = new LigneDetail { Titre = "", Texte = "" };
            var lignes = new List<string>();
            foreach (var brute in (detail ?? "").Replace("\r\n", "\n").Split('\n'))
            {
                if (brute.StartsWith("-- "))
                {
                    courante.Texte = string.Join("\n", lignes).Trim('\n');
                    if (courante.Titre != "" || courante.Texte != "") l.Add(courante);
                    courante = new LigneDetail { Titre = brute.Substring(3), Texte = "" };
                    lignes = new List<string>();
                }
                else lignes.Add(brute);
            }
            courante.Texte = string.Join("\n", lignes).Trim('\n');
            if (courante.Titre != "" || courante.Texte != "") l.Add(courante);
            return l;
        }
    }

    // Décisions pures de la page Réponses en cours de la coquille (U2c). Les textes viennent de VueReponses.Lignes (cible
    // et déclencheur déjà neutralisés)
    public static class VueReponsesFluent
    {
        public static List<LigneDetail> Detail(LigneReponse x)
        {
            bool en = L.En;
            var l = new List<LigneDetail>();
            if (x == null) return l;
            Action<string, string, bool> ajout = (t, v, chasse) => { if (!string.IsNullOrEmpty(v)) l.Add(new LigneDetail { Titre = t, Texte = v, Chasse = chasse }); };
            ajout(en ? "Target" : "Cible", x.Cible, true);
            ajout(en ? "Triggered by" : "Déclencheur", x.Declencheur, false);
            ajout(en ? "Since" : "Depuis", x.Depuis, false);
            ajout(en ? "Reminder" : "Relance", x.Echeance, false);
            ajout(en ? "State" : "État", x.Etat, false);
            ajout(en ? "Recovery" : "Récupération", x.Recuperation, false);
            return l;
        }
    }

    // Briques communes aux pages natives de la coquille : ligne de liste, titre de section, bouton d'action, disposition
    static class Briques
    {
        public static readonly FontFamily Chasse = new FontFamily("Cascadia Mono, Consolas");

        public static Color Couleur(int gravite) { return gravite == 2 ? Jetons.Danger : gravite == 1 ? Jetons.Attention : Jetons.TexteSecondaire; }

        // Carte de liste : barre de couleur à gauche, titre et étiquette d'état à droite, sous-ligne secondaire
        public static Border Ligne(string titre, string etiquette, string sous, int gravite, bool ouverte, bool estompee, Action choisir)
        {
            var couleur = Couleur(gravite);
            var cadre = new Border
            {
                Background = Jetons.Pinceau(ouverte ? Jetons.Surface : Jetons.Carte), CornerRadius = new CornerRadius(6), Padding = new Thickness(14, 8, 14, 8),
                Margin = new Thickness(0, 0, 0, 6), BorderThickness = new Thickness(3, 0, 0, 0), BorderBrush = Jetons.Pinceau(couleur), Cursor = Cursors.Hand
            };
            var pile = new StackPanel();
            var haut = new DockPanel();
            var et = new TextBlock { Text = etiquette, FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(estompee ? Jetons.TexteSecondaire : couleur), Margin = new Thickness(8, 0, 0, 0) };
            DockPanel.SetDock(et, Dock.Right);
            haut.Children.Add(et);
            haut.Children.Add(new TextBlock { Text = titre, Foreground = Jetons.Pinceau(estompee ? Jetons.TexteSecondaire : Jetons.Texte), TextTrimming = TextTrimming.CharacterEllipsis });
            pile.Children.Add(haut);
            if (!string.IsNullOrEmpty(sous)) pile.Children.Add(new TextBlock { Text = sous, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextTrimming = TextTrimming.CharacterEllipsis });
            cadre.Child = pile;
            cadre.MouseLeftButtonUp += (s, e) => choisir();
            return cadre;
        }

        public static TextBlock Titre(string texte, double haut)
        {
            return new TextBlock { Text = texte, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, haut, 0, 4) };
        }

        public static Button Action(string texte, bool fort, RoutedEventHandler clic)
        {
            var b = new Button
            {
                Content = texte, HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Left,
                Padding = new Thickness(12, 6, 12, 6), Margin = new Thickness(0, 0, 0, 6), Cursor = Cursors.Hand, Background = Jetons.Pinceau(Jetons.Carte),
                BorderBrush = Jetons.Pinceau(fort ? Jetons.Accent : Jetons.Separateur), BorderThickness = new Thickness(1), Foreground = Jetons.Pinceau(Jetons.Texte)
            };
            b.Template = Coquille.ModeleBouton();
            b.Click += clic;
            return b;
        }

        // Grille commune : résumé en haut, liste à gauche, panneau de détails à droite
        public static void Disposer(Grid g, TextBlock resume, StackPanel liste, ContentControl detail) { Disposer(g, resume, null, liste, detail); }

        // Barre d'outils facultative (vues, réglages) entre le résumé et la liste
        public static void Disposer(Grid g, TextBlock resume, UIElement outils, StackPanel liste, ContentControl detail)
        {
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition());
            if (outils != null) { Grid.SetRow(outils, 1); Grid.SetColumnSpan(outils, 2); g.Children.Add(outils); }
            g.ColumnDefinitions.Add(new ColumnDefinition());
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(380) });
            resume.TextWrapping = TextWrapping.Wrap; resume.FontSize = 12; resume.Margin = new Thickness(0, 0, 0, 12);
            Grid.SetColumnSpan(resume, 2); g.Children.Add(resume);
            var defile = new ScrollViewer { Content = liste, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(0, 0, 16, 0) };
            Grid.SetRow(defile, 2); g.Children.Add(defile);
            var panneau = new Border { Background = Jetons.Pinceau(Jetons.Carte), CornerRadius = new CornerRadius(8), Padding = new Thickness(20) };
            panneau.Child = new ScrollViewer { Content = detail, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            Grid.SetRow(panneau, 2); Grid.SetColumn(panneau, 1); g.Children.Add(panneau);
        }
    }

    // Page Incidents en WPF (U2c) : mêmes fichiers, mêmes règles et mêmes commandes que la page d'aujourd'hui
    // (VueIncidents, ActionsIncidents) ; lectures hors du fil de l'interface, une à la fois ; dernière liste gardée si le
    // suivi devient illisible
    class PageIncidentsFluent : Grid
    {
        readonly TextBlock resume = new TextBlock();
        readonly StackPanel liste = new StackPanel();
        readonly ContentControl detail = new ContentControl();
        readonly System.Windows.Threading.DispatcherTimer minuteur = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        List<IncidentSuivi> incidents = new List<IncidentSuivi>();
        bool lu;                // rien n'est dit « vide » avant la première lecture
        string choisi, vu;
        int enCours, chargement;
        DateTime debutLecture = DateTime.MinValue;
        readonly Dictionary<string, ChronologieIncident> chronologies = new Dictionary<string, ChronologieIncident>();
        readonly HashSet<string> chronologiesEnCours = new HashSet<string>();

        public PageIncidentsFluent()
        {
            Briques.Disposer(this, resume, liste, detail);
            minuteur.Tick += (s, e) => Charger();
            Loaded += (s, e) => { minuteur.Start(); Charger(); };
            Unloaded += (s, e) => minuteur.Stop();
            Afficher();
        }

        internal void Charger()
        {
            if (System.Threading.Interlocked.CompareExchange(ref enCours, 1, 0) != 0)
            {
                if (VueSante.LectureBloquee(debutLecture, DateTime.Now)) { resume.Text = L.T("Lecture bloquée : affichage ancien."); resume.Foreground = Jetons.Pinceau(Jetons.Attention); }
                return;
            }
            debutLecture = DateTime.Now;
            int numero = ++chargement;
            System.Threading.ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    var lu = Commun.Lire<List<IncidentSuivi>>("suivi-incidents.json");
                    bool absent = lu == null && VueIncidents.SuiviAbsent(Commun.Dossier);
                    var etat = Commun.Lire<Etat>("etat.json");
                    int? pannes = etat == null ? (int?)null : Couverture.EnPannes(etat).Count;
                    Dispatcher.BeginInvoke((Action)(() => { if (numero == chargement) Recevoir(lu, absent, pannes); }));
                }
                finally { System.Threading.Interlocked.Exchange(ref enCours, 0); }
            });
        }

        void Recevoir(List<IncidentSuivi> lu, bool absent, int? pannes)
        {
            resume.Text = VueIncidents.ResumeListe(lu, absent, pannes);
            resume.Foreground = Jetons.Pinceau(VueIncidents.ResumeAVerifier(lu, absent, pannes) ? Jetons.Attention : Jetons.TexteSecondaire);
            // Illisible : la dernière liste reste affichée, plutôt qu'un vide qui rassure
            if (lu == null && !absent) return;
            this.lu = true;
            incidents = VueIncidents.Trier(lu ?? new List<IncidentSuivi>());
            Afficher();
        }

        void Afficher()
        {
            var i = incidents.FirstOrDefault(x => x.Id == choisi) ?? incidents.FirstOrDefault();
            choisi = i == null ? null : i.Id;
            ChronologieIncident c = null;
            if (choisi != null) chronologies.TryGetValue(choisi, out c);
            string signature = string.Join(";", incidents.Select(x => x.Id + "|" + x.Etat + "|" + x.DerniereActiviteUtc + "|" + x.NombreAlertes)) + "#" + choisi + "#" + (c == null ? "" : c.CalculeeUtc) + "#" + lu + resume.Text;
            if (signature == vu) return;
            vu = signature;
            liste.Children.Clear();
            // Liste vide : le résumé, au-dessus, dit pourquoi (collectes en panne, suivi illisible) ; avant la première lecture, rien n'est conclu
            if (incidents.Count == 0 && !lu) liste.Children.Add(new TextBlock { Text = L.T("Lecture en cours…"), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap });
            foreach (var x in incidents)
            {
                string id = x.Id;
                string sous = Canal.Visible(x.Niveau) + "  ·  " + string.Join(", ", (x.Regles ?? new List<string>()).Select(Canal.Visible)) + "  ·  " + x.NombreAlertes + " " + L.T("alertes") + "  ·  " + Canal.Visible(x.DerniereActiviteUtc);
                liste.Children.Add(Briques.Ligne(Canal.Visible(x.Entite), VueIncidents.EtatComplet(x), sous, VueIncidentsFluent.Gravite(x), id == choisi, x.Etat == "Clos", () => { choisi = id; Afficher(); }));
            }
            Detailler(i, c);
        }

        void Detailler(IncidentSuivi i, ChronologieIncident c)
        {
            if (i == null) { detail.Content = new TextBlock { Text = L.T("Sélectionnez un incident."), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap }; return; }
            var pile = new StackPanel();
            pile.Children.Add(new TextBlock { Text = Canal.Visible(i.Entite), FontSize = 18, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            pile.Children.Add(new TextBlock { Text = VueIncidents.EtatComplet(i), FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Briques.Couleur(VueIncidentsFluent.Gravite(i))), Margin = new Thickness(0, 2, 0, 8) });
            foreach (var vers in VueIncidentsFluent.Actions(i))
            {
                string v = vers;
                pile.Children.Add(Briques.Action(VueIncidentsFluent.Libelle(v), v == "PrisEnCharge", (s, e) => Agir(i, v)));
            }
            foreach (var sct in VueIncidentsFluent.Sections(VueIncidents.Detail(i, c)))
            {
                if (sct.Titre != "") pile.Children.Add(Briques.Titre(sct.Titre, 14));
                pile.Children.Add(new TextBlock { Text = sct.Texte, TextWrapping = TextWrapping.Wrap, FontSize = sct.Titre == "" ? 14 : 12, FontFamily = sct.Titre == "" ? Jetons.Police : Briques.Chasse });
            }
            detail.Content = pile;
            if (c == null) ChargerChronologie(i.Id);
        }

        // Une chronologie par incident à la fois ; verrouillée, elle ne bloque ni n'empile rien (S105-13)
        void ChargerChronologie(string id)
        {
            if (!VueIncidents.IdentifiantValide(id)) return;
            lock (chronologiesEnCours) { if (!chronologiesEnCours.Add(id)) return; }
            System.Threading.ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    var c = Commun.Lire<ChronologieIncident>(System.IO.Path.Combine("chronologies", id + ".json"));
                    if (c != null) Dispatcher.BeginInvoke((Action)(() => { chronologies[id] = c; if (choisi == id) Afficher(); }));
                }
                finally { lock (chronologiesEnCours) chronologiesEnCours.Remove(id); }
            });
        }

        // Mêmes actions que la page d'aujourd'hui : même commande, même dialogue de clôture, même confirmation élevée
        void Agir(IncidentSuivi i, string vers)
        {
            if (vers == "Clos")
            {
                string motif, note;
                if (!ActionsIncidents.DemanderCloture(null, out motif, out note)) return;
                ActionsIncidents.Passer(i, vers, motif, note);
            }
            else ActionsIncidents.Passer(i, vers, "", "");
            chronologies.Remove(i.Id);
            Charger();
        }
    }

    // Page Réponses en cours en WPF (U2c) : même registre, mêmes contrôles et même récupération que la page d'aujourd'hui
    // (VueReponses, ActionsReponses). Une échéance n'est jamais une levée : chaque action attend une décision humaine
    class PageReponsesFluent : Grid
    {
        readonly TextBlock resume = new TextBlock();
        readonly StackPanel liste = new StackPanel();
        readonly ContentControl detail = new ContentControl();
        readonly System.Windows.Threading.DispatcherTimer minuteur = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        List<LigneReponse> lignes = new List<LigneReponse>();
        bool lu;                // rien n'est dit « aucune réponse » avant la première lecture
        string choisie, vu;
        int enCours, chargement;

        public PageReponsesFluent()
        {
            Briques.Disposer(this, resume, liste, detail);
            minuteur.Tick += (s, e) => Charger();
            Loaded += (s, e) => { minuteur.Start(); Charger(); };
            Unloaded += (s, e) => minuteur.Stop();
            Afficher();
        }

        internal void Charger()
        {
            if (System.Threading.Interlocked.CompareExchange(ref enCours, 1, 0) != 0) return;
            int numero = ++chargement;
            System.Threading.ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    bool illisible;
                    var l = ActionsReponses.Lire(out illisible);
                    Dispatcher.BeginInvoke((Action)(() => { if (numero == chargement) Recevoir(l, illisible); }));
                }
                finally { System.Threading.Interlocked.Exchange(ref enCours, 0); }
            });
        }

        void Recevoir(List<LigneReponse> l, bool illisible)
        {
            bool en = L.En;
            if (illisible)
            {
                // Illisible n'est pas « aucune réponse en cours » : le dernier affichage est gardé, et c'est dit
                resume.Text = en ? "Response register unreadable (reponses.json): the last display is kept; it may be out of date." : "Registre des réponses illisible (reponses.json) : dernier affichage gardé, peut-être dépassé.";
                resume.Foreground = Jetons.Pinceau(Jetons.Attention);
                return;
            }
            lignes = l;
            lu = true;
            Afficher();
        }

        void Afficher()
        {
            bool en = L.En;
            int dues = lignes.Count(x => x.Gravite == 1);
            resume.Text = !lu ? L.T("Lecture en cours…") : (lignes.Count == 0 ? (en ? "No ongoing response." : "Aucune réponse en cours.")
                : string.Format(en ? "{0} ongoing response(s), {1} awaiting a decision." : "{0} réponse(s) en cours, dont {1} en attente de décision.", lignes.Count, dues))
                + " " + (en ? "None is ever lifted automatically: at its deadline, a reminder is sent and a human decision is awaited."
                            : "Aucune n'est jamais levée automatiquement : à son échéance, une relance part et une décision humaine est attendue.");
            resume.Foreground = Jetons.Pinceau(lignes.Any(x => x.Gravite == 2) ? Jetons.Danger : dues > 0 ? Jetons.Attention : Jetons.TexteSecondaire);
            var x0 = lignes.FirstOrDefault(x => x.Action.Id == choisie) ?? lignes.FirstOrDefault();
            choisie = x0 == null ? null : x0.Action.Id;
            string signature = string.Join(";", lignes.Select(x => x.Action.Id + "|" + x.Etat + "|" + x.Gravite)) + "#" + choisie + "#" + lu;
            if (signature == vu) return;
            vu = signature;
            liste.Children.Clear();
            // Liste vide après lecture : le résumé, au-dessus, le dit déjà
            if (lignes.Count == 0 && !lu) liste.Children.Add(new TextBlock { Text = L.T("Lecture en cours…"), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire) });
            foreach (var x in lignes)
            {
                string id = x.Action.Id;
                liste.Children.Add(Briques.Ligne(x.Quoi, x.Etat, x.Cible + "  ·  " + (en ? "since " : "depuis ") + x.Depuis, x.Gravite, id == choisie, false, () => { choisie = id; Afficher(); }));
            }
            Detailler(x0);
        }

        void Detailler(LigneReponse x)
        {
            bool en = L.En;
            if (x == null) { detail.Content = new TextBlock { Text = en ? "Select a line to read how to recover it." : "Sélectionnez une ligne pour lire comment la récupérer.", Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap }; return; }
            var pile = new StackPanel();
            pile.Children.Add(new TextBlock { Text = x.Quoi, FontSize = 18, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap, Foreground = Jetons.Pinceau(x.Gravite == 2 ? Jetons.Danger : Jetons.Texte) });
            foreach (var l in VueReponsesFluent.Detail(x))
            {
                pile.Children.Add(Briques.Titre(l.Titre, 10));
                var t = new TextBlock { Text = l.Texte, TextWrapping = TextWrapping.Wrap };
                if (l.Chasse) { t.FontFamily = Briques.Chasse; t.FontSize = 12; }
                pile.Children.Add(t);
            }
            if (!string.IsNullOrEmpty(x.Bouton))
            {
                pile.Children.Add(Briques.Titre(L.T("Agir"), 18));
                // Même récupération que la page d'aujourd'hui : objet retrouvé, PID vérifié, question, confirmation élevée
                pile.Children.Add(Briques.Action(x.Bouton, true, (s, e) => { ActionsReponses.Recuperer(x); Charger(); }));
            }
            detail.Content = pile;
        }
    }

    // Ligne d'une page d'état de la coquille (U3a) : textes déjà neutralisés, détail en sections
    public class LigneEtatFluent
    {
        public string Titre, Etiquette, Sous;
        public int Gravite;
        public List<LigneDetail> Detail = new List<LigneDetail>();
    }

    // Décisions pures de la page Détection de la coquille (U3a), testées par tests\rendu-pilote.ps1. Tout ce qui vient de
    // ids.json et dpi.json (noms TLS, chemins HTTP, noms DNS, messages des règles) est écrit par le réseau ou par des
    // fichiers de règles : neutralisé par Canal.Visible
    public static class VueDetectionFluent
    {
        public const int Maximum = 500;
        public static readonly string[] Vues = { "Détections IDS", "Sessions TLS (SNI, JA3)", "Requêtes HTTP en clair", "Requêtes DNS", "Empreintes JA3" };

        static LigneDetail D(string titre, string texte, bool chasse = false) { return new LigneDetail { Titre = L.T(titre), Texte = Canal.Visible(texte ?? ""), Chasse = chasse }; }

        static List<LigneDetail> Sans(params LigneDetail[] l) { return l.Where(x => x.Texte != "").ToList(); }

        public static List<LigneEtatFluent> Lignes(EtatIds ids, EtatDpi dpi, int vue)
        {
            Func<string, string> v = x => Canal.Visible(x ?? "");
            ids = ids ?? new EtatIds(); dpi = dpi ?? new EtatDpi();
            var l = new List<LigneEtatFluent>();
            switch (vue)
            {
                case 0:
                    foreach (var d in ids.Detections ?? new List<DetectionIds>())
                        l.Add(new LigneEtatFluent
                        {
                            Titre = v(d.Message), Etiquette = v(L.T(d.Niveau ?? "")) + (d.Bloque ? " · " + L.T("bloqué") : ""),
                            Sous = v(d.Heure) + "  ·  " + v(d.Source) + " → " + v(d.Destination) + (string.IsNullOrEmpty(d.Programme) ? "" : "  ·  " + v(d.Programme)),
                            Gravite = d.Niveau == "Critique" ? 2 : d.Niveau == "Alerte" ? 1 : 0,
                            Detail = Sans(D("Heure", d.Heure), D("Règle", "SID " + d.Sid + (string.IsNullOrEmpty(d.Classe) ? "" : " · " + d.Classe)), D("Source", d.Source, true), D("Destination", d.Destination, true), D("Programme", d.Programme), D("Bloqué", d.Bloque ? L.T("oui") : L.T("non")))
                        });
                    break;
                case 1:
                    foreach (var x in dpi.Tls ?? new List<SessionDpi>())
                        l.Add(Session(x, "Site (SNI)", string.IsNullOrEmpty(x.Remarque) ? 0 : 2, true));
                    break;
                case 2:
                    foreach (var x in dpi.Http ?? new List<SessionDpi>())
                        l.Add(Session(x, "Hôte et chemin", string.IsNullOrEmpty(x.Remarque) ? 0 : 1, false));
                    break;
                case 3:
                    foreach (var x in dpi.Dns ?? new List<SessionDpi>())
                        l.Add(new LigneEtatFluent
                        {
                            Titre = v(x.Nom), Etiquette = "", Sous = v(x.Heure) + "  ·  " + v(x.Programme) + "  ·  " + L.T("Serveur DNS") + " " + v(x.Ip),
                            Detail = Sans(D("Heure", x.Heure), D("Nom demandé", x.Nom, true), D("Programme", x.Programme), D("Serveur DNS", x.Ip, true))
                        });
                    break;
                default:
                    foreach (var x in dpi.Empreintes ?? new List<EmpreinteJa3>())
                        l.Add(new LigneEtatFluent
                        {
                            Titre = v(x.Ja3), Etiquette = x.Nombre + " " + L.T("sessions"), Sous = string.Join(", ", (x.Programmes ?? new List<string>()).Select(v)),
                            Detail = Sans(D("Empreinte JA3", x.Ja3, true), D("Sessions", x.Nombre.ToString()), D("Programmes", string.Join(", ", x.Programmes ?? new List<string>())))
                        });
                    break;
            }
            return l;
        }

        static LigneEtatFluent Session(SessionDpi x, string titreNom, int gravite, bool tls)
        {
            Func<string, string> v = y => Canal.Visible(y ?? "");
            return new LigneEtatFluent
            {
                Titre = v(x.Nom), Etiquette = v(x.Remarque), Gravite = gravite,
                Sous = v(x.Heure) + "  ·  " + v(x.Programme) + "  ·  " + v(x.Ip) + ":" + x.Port,
                Detail = Sans(D("Heure", x.Heure), D(titreNom, x.Nom, true), D("Programme", x.Programme), D("Destination", x.Ip + ":" + x.Port, true), tls ? D("JA3", x.Ja3, true) : D("JA3", ""), D("Remarque", x.Remarque))
            };
        }
    }

    // Page Santé en WPF (U3a) : les mêmes lignes que la page d'aujourd'hui (VueSante.Lignes, déjà neutralisées), chacune
    // avec sa source et sa date ; jamais « rien à vérifier » avant la première lecture ni sur une lecture bloquée
    class PageSanteFluent : Grid
    {
        readonly TextBlock resume = new TextBlock();
        readonly StackPanel liste = new StackPanel();
        readonly ContentControl detail = new ContentControl();
        readonly System.Windows.Threading.DispatcherTimer minuteur = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        List<LigneSante> lignes = new List<LigneSante>();
        bool lu;
        string choisi, vu;
        int enCours, chargement;
        DateTime debutLecture = DateTime.MinValue;

        public PageSanteFluent()
        {
            Briques.Disposer(this, resume, null, liste, detail);
            minuteur.Tick += (s, e) => Charger();
            Loaded += (s, e) => { minuteur.Start(); Charger(); };
            Unloaded += (s, e) => minuteur.Stop();
            Afficher();
        }

        internal void Charger()
        {
            if (System.Threading.Interlocked.CompareExchange(ref enCours, 1, 0) != 0)
            {
                // « Rien à vérifier » ne doit pas rester affiché sur des lignes figées (S105-11)
                if (VueSante.LectureBloquee(debutLecture, DateTime.Now)) { resume.Text = L.T("Lecture bloquée : affichage ancien."); resume.Foreground = Jetons.Pinceau(Jetons.Attention); }
                return;
            }
            debutLecture = DateTime.Now;
            int numero = ++chargement;
            System.Threading.ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    var l = VueSante.Lignes(Commun.Lire<Etat>("etat.json"), Commun.Lire<EtatRemontee>("notifications.json"), DateTime.Now);
                    Dispatcher.BeginInvoke((Action)(() => { if (numero == chargement) { lignes = l; lu = true; vu = null; Afficher(); } }));
                }
                finally { System.Threading.Interlocked.Exchange(ref enCours, 0); }
            });
        }

        void Afficher()
        {
            int n = lignes.Count(x => x.Gravite > 0);
            resume.Text = !lu ? L.T("Lecture en cours…") : n == 0 ? L.T("Rien à vérifier.") : string.Format(L.T("{0} point(s) à vérifier."), n);
            resume.Foreground = Jetons.Pinceau(lu && n > 0 ? Jetons.Attention : Jetons.TexteSecondaire);
            var x0 = lignes.FirstOrDefault(x => x.Sujet == choisi) ?? lignes.FirstOrDefault(x => x.Gravite > 0) ?? lignes.FirstOrDefault();
            choisi = x0 == null ? null : x0.Sujet;
            string signature = string.Join(";", lignes.Select(x => x.Sujet + "|" + x.Etat + "|" + x.Date + "|" + x.Detail)) + "#" + choisi + "#" + lu;
            if (signature == vu) return;
            vu = signature;
            liste.Children.Clear();
            if (!lu) liste.Children.Add(new TextBlock { Text = L.T("Lecture en cours…"), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire) });
            foreach (var x in lignes)
            {
                string sujet = x.Sujet;
                liste.Children.Add(Briques.Ligne(x.Sujet, x.Etat, string.Join("  ·  ", new[] { x.Date, x.Source }.Where(y => !string.IsNullOrEmpty(y))), x.Gravite, sujet == choisi, false, () => { choisi = sujet; Afficher(); }));
            }
            Detailler(x0);
        }

        void Detailler(LigneSante x)
        {
            if (x == null) { detail.Content = new TextBlock { Text = L.T("Sélectionnez une ligne pour lire son détail en entier."), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap }; return; }
            var pile = new StackPanel();
            pile.Children.Add(new TextBlock { Text = x.Sujet, FontSize = 18, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            pile.Children.Add(new TextBlock { Text = x.Etat, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Briques.Couleur(x.Gravite)), Margin = new Thickness(0, 2, 0, 8) });
            foreach (var l in new[] { new LigneDetail { Titre = L.T("Vérifié"), Texte = x.Date }, new LigneDetail { Titre = L.T("Détail"), Texte = x.Detail }, new LigneDetail { Titre = L.T("Source"), Texte = x.Source } })
            {
                if (string.IsNullOrEmpty(l.Texte)) continue;
                pile.Children.Add(Briques.Titre(l.Titre, 10));
                pile.Children.Add(new TextBlock { Text = l.Texte, TextWrapping = TextWrapping.Wrap });
            }
            detail.Content = pile;
        }
    }

    // Page Détection en WPF (U3a) : mêmes fichiers (ids.json, dpi.json, config.json) que la page d'aujourd'hui ; vues en
    // boutons ; l'IPS se règle par la même commande et la même confirmation élevée (VueDetection.ChangerIps)
    class PageDetectionFluent : Grid
    {
        readonly TextBlock resume = new TextBlock();
        readonly StackPanel outils = new StackPanel();
        readonly StackPanel liste = new StackPanel();
        readonly ContentControl detail = new ContentControl();
        readonly System.Windows.Threading.DispatcherTimer minuteur = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        EtatIds ids; EtatDpi dpi; bool? ips; bool lu;
        int vue, choisie, enCours, chargement;
        string vu;

        public PageDetectionFluent()
        {
            Briques.Disposer(this, resume, outils, liste, detail);
            minuteur.Tick += (s, e) => Charger();
            Loaded += (s, e) => { minuteur.Start(); Charger(); };
            Unloaded += (s, e) => minuteur.Stop();
            Afficher();
        }

        internal void Charger()
        {
            if (System.Threading.Interlocked.CompareExchange(ref enCours, 1, 0) != 0) return;
            int numero = ++chargement;
            System.Threading.ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    var i = Commun.Lire<EtatIds>("ids.json"); var d = Commun.Lire<EtatDpi>("dpi.json"); var c = Commun.Lire<Config>("config.json");
                    Dispatcher.BeginInvoke((Action)(() => { if (numero == chargement) { ids = i; dpi = d; ips = c == null ? (bool?)null : c.Ips; lu = true; Afficher(); } }));
                }
                finally { System.Threading.Interlocked.Exchange(ref enCours, 0); }
            });
        }

        void Afficher()
        {
            resume.Text = !lu ? L.T("Lecture en cours…") : VueDetection.Info(ids, dpi, ips) + (ids == null ? "\n" + L.T("ids.json absent ou illisible : rien n'est conclu.") : "");
            resume.Foreground = Jetons.Pinceau(lu && (ids == null || !ips.HasValue) ? Jetons.Attention : Jetons.TexteSecondaire);
            var lignes = VueDetectionFluent.Lignes(ids, dpi, vue);
            if (choisie >= lignes.Count) choisie = 0;
            string signature = vue + "#" + choisie + "#" + lu + "#" + ips + "#" + string.Join(";", lignes.Take(VueDetectionFluent.Maximum).Select(x => x.Titre + "|" + x.Sous));
            if (signature == vu) return;
            vu = signature;
            outils.Children.Clear();
            var vues = new WrapPanel { Margin = new Thickness(0, 0, 0, 8) };
            for (int k = 0; k < VueDetectionFluent.Vues.Length; k++)
            {
                int n = k;
                bool actif = n == vue;
                var b = new Button
                {
                    Content = L.T(VueDetectionFluent.Vues[k]), Padding = new Thickness(12, 4, 12, 4), Margin = new Thickness(0, 0, 8, 6), Cursor = Cursors.Hand,
                    Background = Jetons.Pinceau(actif ? Jetons.Surface : Jetons.Fond), BorderBrush = Jetons.Pinceau(actif ? Jetons.Accent : Jetons.Separateur),
                    BorderThickness = new Thickness(1), Foreground = Jetons.Pinceau(Jetons.Texte)
                };
                b.Template = Coquille.ModeleBouton();
                b.Click += (s, e) => { vue = n; choisie = 0; Afficher(); };
                vues.Children.Add(b);
            }
            outils.Children.Add(vues);
            var bas = new WrapPanel { Margin = new Thickness(0, 0, 0, 12) };
            bool ipsActif = ips == true;
            var bIps = Briques.Action(ipsActif ? L.T("Désactiver l'IPS") : L.T("Activer l'IPS : bloquer au pare-feu l'adresse distante des règles « drop » ou de priorité 1"), !ipsActif, (s, e) => { VueDetection.ChangerIps(!ipsActif); Charger(); });
            bIps.HorizontalAlignment = HorizontalAlignment.Left; bIps.Margin = new Thickness(0, 0, 8, 0);
            // État de l'IPS inconnu avant la première lecture : aucun bouton qui prétendrait le connaître
            // config.json illisible : état inconnu, aucun bouton (audit de #138, S138-01)
            bIps.Visibility = lu && ips.HasValue ? Visibility.Visible : Visibility.Collapsed;
            var bRegles = Briques.Action(L.T("Dossier des règles"), false, (s, e) => VueDetection.OuvrirDossierRegles());
            bRegles.HorizontalAlignment = HorizontalAlignment.Left;
            bas.Children.Add(bIps); bas.Children.Add(bRegles);
            outils.Children.Add(bas);
            liste.Children.Clear();
            if (!lu) liste.Children.Add(new TextBlock { Text = L.T("Lecture en cours…"), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire) });
            else if (lignes.Count == 0) liste.Children.Add(new TextBlock { Text = L.T("Rien d'enregistré pour cette vue."), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap });
            for (int k = 0; k < Math.Min(lignes.Count, VueDetectionFluent.Maximum); k++)
            {
                int n = k; var x = lignes[k];
                liste.Children.Add(Briques.Ligne(x.Titre, x.Etiquette, x.Sous, x.Gravite, n == choisie, false, () => { choisie = n; Afficher(); }));
            }
            if (lignes.Count > VueDetectionFluent.Maximum)
                liste.Children.Add(new TextBlock { Text = string.Format(L.T("Les {0} plus récentes sont affichées."), VueDetectionFluent.Maximum), FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire) });
            Detailler(lignes.Count > 0 ? lignes[choisie] : null);
        }

        void Detailler(LigneEtatFluent x)
        {
            if (x == null) { detail.Content = new TextBlock { Text = L.T("Sélectionnez une ligne pour lire son détail en entier."), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap }; return; }
            var pile = new StackPanel();
            pile.Children.Add(new TextBlock { Text = x.Titre, FontSize = 16, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            if (!string.IsNullOrEmpty(x.Etiquette)) pile.Children.Add(new TextBlock { Text = x.Etiquette, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Briques.Couleur(x.Gravite)), Margin = new Thickness(0, 2, 0, 4), TextWrapping = TextWrapping.Wrap });
            foreach (var l in x.Detail)
            {
                pile.Children.Add(Briques.Titre(l.Titre, 10));
                var t = new TextBlock { Text = l.Texte, TextWrapping = TextWrapping.Wrap };
                if (l.Chasse) { t.FontFamily = Briques.Chasse; t.FontSize = 12; }
                pile.Children.Add(t);
            }
            detail.Content = pile;
        }
    }

    // Décisions pures de la page Événements de la coquille (U3b), testées par tests\rendu-pilote.ps1. Les événements et les
    // incidents de corrélation décrivent le poste : un programme peut y avoir mis ce qu'il veut, tout passe par Visible
    public static class VueEvenementsFluent
    {
        public const int Maximum = 500;
        public static readonly string[] Sources = { "Toutes les sources", "alerte", "connexion", "processus", "securite", "parefeu", "systeme" };
        public static readonly string[] Niveaux = { "Tous niveaux", "Alerte", "Critique" };
        public static readonly string[] Periodes = { "1 heure", "24 heures", "7 jours", "30 jours" };

        static int Gravite(string niveau) { return niveau == "Critique" ? 2 : niveau == "Alerte" ? 1 : 0; }

        static LigneDetail D(string titre, string texte, bool chasse = false) { return new LigneDetail { Titre = L.T(titre), Texte = Canal.Visible(texte ?? ""), Chasse = chasse }; }

        public static LigneEtatFluent Ligne(Evenement e)
        {
            Func<string, string> v = x => Canal.Visible(x ?? "");
            string qui = string.Join("  ·  ", new[] { v(e.Utilisateur), v(e.Processus), v(e.Ip) }.Where(x => x != ""));
            return new LigneEtatFluent
            {
                Titre = v(e.Message), Etiquette = v(e.Source) + (string.IsNullOrEmpty(e.Type) ? "" : " / " + v(e.Type)),
                Sous = v(e.Heure) + (qui == "" ? "" : "  ·  " + qui), Gravite = Gravite(e.Niveau),
                Detail = new[]
                {
                    D("Heure", e.Heure), D("Niveau", L.T(e.Niveau ?? "")), D("Source", e.Source), D("Type", e.Type), D("MITRE", e.Mitre),
                    D("Utilisateur", e.Utilisateur), D("Programme", e.Processus + (e.Pid.HasValue ? " (PID " + e.Pid + ")" : "")),
                    D("IP", string.IsNullOrEmpty(e.Ip) ? "" : e.Ip + (e.Port > 0 ? ":" + e.Port : ""), true), D("Destination", e.Destination, true), D("Message", e.Message)
                }.Where(x => x.Texte != "").ToList()
            };
        }

        public static LigneEtatFluent Ligne(Incident i)
        {
            Func<string, string> v = x => Canal.Visible(x ?? "");
            var d = new List<LigneDetail> { D("Heure", i.Heure), D("Règle", i.Regle + (string.IsNullOrEmpty(i.Mitre) ? "" : " · " + i.Mitre)), D("Résumé", i.Resume) };
            var evts = (i.Evenements ?? new List<string>()).Take(5).Select(v).ToList();
            if (evts.Count > 0) d.Add(new LigneDetail { Titre = L.T("Événements"), Texte = string.Join("\n", evts), Chasse = true });
            return new LigneEtatFluent
            {
                Titre = v(i.Titre), Etiquette = v(L.T(i.Niveau ?? "")), Sous = v(i.Heure) + "  ·  " + v(i.Regle) + (string.IsNullOrEmpty(i.Mitre) ? "" : "  ·  " + v(i.Mitre)),
                Gravite = Gravite(i.Niveau), Detail = d.Where(x => x.Texte != "").ToList()
            };
        }

        public static string Resume(ResultatSiem r, DateTime? fDebut, DateTime? fFin)
        {
            if (r == null) return L.T("Recherche…");
            string tranche = fDebut.HasValue ? string.Format(L.En ? " · slice {0:HH:mm}–{1:HH:mm} (click it again to clear)" : " · tranche {0:HH:mm}–{1:HH:mm} (recliquer pour l'enlever)", fDebut, fFin) : "";
            return string.Format(L.En ? "{0} event(s){1}, {2} correlation incident(s){3}" : "{0} événement(s){1}, {2} incident(s) de corrélation{3}",
                r.Total, r.Total > Maximum ? (L.En ? " (latest " + Maximum + " shown)" : " (les " + Maximum + " plus récents affichés)") : "", r.Incidents.Count, tranche);
        }
    }

    // Chronologie de la page Événements : barres empilées par niveau (racine carrée, comme aujourd'hui), clic pour garder
    // une tranche, nouveau clic pour l'enlever
    class ChronologieFluent : FrameworkElement
    {
        ResultatSiem r;
        DateTime? choixDebut;
        public event Action<DateTime?, DateTime?> TrancheChoisie;

        public ChronologieFluent() { Height = 104; Cursor = Cursors.Hand; Margin = new Thickness(0, 0, 0, 12); }

        public void Definir(ResultatSiem resultat, DateTime? debut) { r = resultat; choixDebut = debut; InvalidateVisual(); }

        int Tranches { get { return r == null || r.Compteurs == null ? 0 : r.Compteurs.GetLength(0); } }

        // Repères (relecture de #139, constat 6) : sur une échelle en racine carrée, une barre à mi-hauteur vaut le quart du
        // maximum ; le maximum par tranche et les heures de début, de milieu et de fin sont donc écrits
        FormattedText Texte(string t)
        {
            return new FormattedText(t, System.Globalization.CultureInfo.CurrentUICulture, FlowDirection.LeftToRight, new Typeface(Jetons.Police, FontStyles.Normal, FontWeights.Normal, FontStretches.Normal),
                11, Jetons.Pinceau(Jetons.TexteSecondaire), VisualTreeHelper.GetDpi(this).PixelsPerDip);
        }

        internal const double Gauche = 12, Haut = 20, Bas = 18;

        protected override void OnRender(DrawingContext g)
        {
            g.DrawRoundedRectangle(Jetons.Pinceau(Jetons.Carte), null, new Rect(0, 0, ActualWidth, ActualHeight), 8, 8);
            int n = Tranches;
            if (n == 0) return;
            double l = ActualWidth - 2 * Gauche, h = Math.Max(1, ActualHeight - Haut - Bas), pas = l / n;
            int max = 1;
            for (int t = 0; t < n; t++) max = Math.Max(max, r.Compteurs[t, 0] + r.Compteurs[t, 1] + r.Compteurs[t, 2]);
            g.DrawText(Texte(string.Format(L.T("max {0} par tranche, hauteur en racine carrée"), max)), new Point(Gauche, 3));
            string format = (r.Fin - r.Debut).TotalHours > 24 ? "dd/MM HH:mm" : "HH:mm";
            var debut = Texte(r.Debut.ToString(format)); var milieu = Texte(r.Debut.AddTicks((r.Fin - r.Debut).Ticks / 2).ToString(format)); var fin = Texte(r.Fin.ToString(format));
            double yt = ActualHeight - Bas + 2;
            g.DrawText(debut, new Point(Gauche, yt));
            g.DrawText(milieu, new Point(Gauche + l / 2 - milieu.Width / 2, yt));
            g.DrawText(fin, new Point(Gauche + l - fin.Width, yt));
            var couleurs = new[] { Jetons.Accent, Jetons.Attention, Jetons.Danger };
            for (int t = 0; t < n; t++)
            {
                DateTime d, f;
                RechercheSiem.Tranche(r.Debut, r.Fin, n, t, out d, out f);
                bool choisie = choixDebut.HasValue && Math.Abs((choixDebut.Value - d).TotalSeconds) < 1;
                if (choisie) g.DrawRectangle(Jetons.Pinceau(Jetons.Surface), null, new Rect(Gauche + t * pas, Haut - 2, pas, h + 4));
                int total = r.Compteurs[t, 0] + r.Compteurs[t, 1] + r.Compteurs[t, 2];
                if (total <= 0) continue;
                double hauteur = Math.Max(2, Math.Sqrt(total) / Math.Sqrt(max) * h);
                // Alerte et Critique jamais sous 2 px : quelques critiques restent visibles parmi des milliers d'infos (constat 6b)
                double[] segments = new double[3];
                for (int niv = 1; niv < 3; niv++) if (r.Compteurs[t, niv] > 0) segments[niv] = Math.Max(2, hauteur * r.Compteurs[t, niv] / total);
                segments[0] = r.Compteurs[t, 0] > 0 ? Math.Max(1, hauteur - segments[1] - segments[2]) : 0;
                double y = Haut + h;
                for (int niv = 0; niv < 3; niv++)
                {
                    if (segments[niv] <= 0) continue;
                    y -= segments[niv];
                    g.DrawRectangle(Jetons.Pinceau(couleurs[niv]), null, new Rect(Gauche + t * pas + 1, y, Math.Max(1, pas - 2), segments[niv]));
                }
            }
        }

        // Hauteurs des segments d'une tranche (Info, Alerte, Critique), pour les tests : même calcul que le rendu
        internal static double[] Segments(int info, int alerte, int critique, int max, double h)
        {
            int total = info + alerte + critique;
            var seg = new double[3];
            if (total <= 0) return seg;
            double hauteur = Math.Max(2, Math.Sqrt(total) / Math.Sqrt(Math.Max(1, max)) * h);
            int[] c = { info, alerte, critique };
            for (int niv = 1; niv < 3; niv++) if (c[niv] > 0) seg[niv] = Math.Max(2, hauteur * c[niv] / total);
            seg[0] = info > 0 ? Math.Max(1, hauteur - seg[1] - seg[2]) : 0;
            return seg;
        }

        protected override void OnMouseLeftButtonUp(MouseButtonEventArgs e)
        {
            base.OnMouseLeftButtonUp(e);
            int n = Tranches;
            if (n == 0 || TrancheChoisie == null) return;
            double x = e.GetPosition(this).X - Gauche, l = ActualWidth - 2 * Gauche;
            if (x < 0 || x >= l) return;
            int t = Math.Min(n - 1, (int)(x / (l / n)));
            DateTime d, f;
            RechercheSiem.Tranche(r.Debut, r.Fin, n, t, out d, out f);
            if (choixDebut.HasValue && Math.Abs((choixDebut.Value - d).TotalSeconds) < 1) TrancheChoisie(null, null);
            else TrancheChoisie(d, f);
        }
    }

    // Page Événements en WPF (U3b) : même recherche que la page d'aujourd'hui (RechercheSiem, lecture seule, hors du fil de
    // l'interface), mêmes filtres et même chronologie ; incidents de corrélation puis événements, panneau de détails
    class PageEvenementsFluent : Grid
    {
        readonly TextBlock resume = new TextBlock();
        readonly StackPanel outils = new StackPanel();
        readonly StackPanel liste = new StackPanel();
        readonly ContentControl detail = new ContentControl();
        readonly TextBox recherche = new TextBox();
        readonly ChronologieFluent chrono = new ChronologieFluent();
        readonly WrapPanel filtres = new WrapPanel { Margin = new Thickness(0, 0, 0, 8) };
        int source, niveau, periode = 1, numero, choisie;
        DateTime? trancheDebut, trancheFin;
        ResultatSiem resultat;
        List<LigneEtatFluent> lignes = new List<LigneEtatFluent>();

        public PageEvenementsFluent()
        {
            Briques.Disposer(this, resume, outils, liste, detail);
            var ligneRecherche = new DockPanel { Margin = new Thickness(0, 0, 0, 8) };
            var bouton = Briques.Action(L.T("Rechercher"), true, (s, e) => { trancheDebut = trancheFin = null; Charger(); });
            bouton.HorizontalAlignment = HorizontalAlignment.Left; bouton.Margin = new Thickness(8, 0, 0, 0);
            DockPanel.SetDock(bouton, Dock.Right);
            ligneRecherche.Children.Add(bouton);
            recherche.Background = Jetons.Pinceau(Jetons.Surface); recherche.Foreground = Jetons.Pinceau(Jetons.Texte); recherche.CaretBrush = Jetons.Pinceau(Jetons.Texte);
            recherche.BorderBrush = Jetons.Pinceau(Jetons.Separateur); recherche.Padding = new Thickness(8, 5, 8, 5); recherche.VerticalContentAlignment = VerticalAlignment.Center;
            recherche.ToolTip = L.T("Texte cherché dans les événements (utilisateur, IP, programme, message…)");
            recherche.KeyDown += (s, e) => { if (e.Key == Key.Enter) { trancheDebut = trancheFin = null; Charger(); } };
            ligneRecherche.Children.Add(recherche);
            outils.Children.Add(ligneRecherche);
            outils.Children.Add(filtres);
            outils.Children.Add(chrono);
            chrono.TrancheChoisie += (d, f) => { trancheDebut = d; trancheFin = f; Charger(); };
            Loaded += (s, e) => Charger();
            Filtres();
            Afficher();
        }

        void Filtres()
        {
            filtres.Children.Clear();
            Action<string[], int, Action<int>> groupe = (valeurs, actif, choisir) =>
            {
                for (int k = 0; k < valeurs.Length; k++)
                {
                    int n = k;
                    var b = new Button
                    {
                        Content = L.T(valeurs[k]), Padding = new Thickness(10, 3, 10, 3), Margin = new Thickness(0, 0, 6, 6), Cursor = Cursors.Hand, FontSize = 12,
                        Background = Jetons.Pinceau(n == actif ? Jetons.Surface : Jetons.Fond), BorderBrush = Jetons.Pinceau(n == actif ? Jetons.Accent : Jetons.Separateur),
                        BorderThickness = new Thickness(1), Foreground = Jetons.Pinceau(Jetons.Texte)
                    };
                    b.Template = Coquille.ModeleBouton();
                    b.Click += (s, e) => { choisir(n); trancheDebut = trancheFin = null; Filtres(); Charger(); };
                    filtres.Children.Add(b);
                }
                filtres.Children.Add(new Border { Width = 12 });
            };
            groupe(VueEvenementsFluent.Periodes, periode, n => periode = n);
            groupe(VueEvenementsFluent.Niveaux, niveau, n => niveau = n);
            groupe(VueEvenementsFluent.Sources, source, n => source = n);
        }

        internal void Charger()
        {
            string texte = recherche.Text.Trim(), src = RechercheSiem.Sources[source];
            int niv = niveau;
            DateTime fin = DateTime.Now, debut = fin - RechercheSiem.Periodes[periode];
            DateTime? fd = trancheDebut, ff = trancheFin;
            int n = ++numero;
            resume.Text = L.T("Recherche…");
            System.Threading.ThreadPool.QueueUserWorkItem(_ =>
            {
                var r = RechercheSiem.ChercherSur(texte, src, niv, debut, fin, fd, ff);
                Dispatcher.BeginInvoke((Action)(() => { if (n == numero) { resultat = r; choisie = 0; Afficher(); } }));
            });
        }

        void Afficher()
        {
            resume.Text = VueEvenementsFluent.Resume(resultat, trancheDebut, trancheFin);
            resume.Foreground = Jetons.Pinceau(Jetons.TexteSecondaire);
            chrono.Definir(resultat, trancheDebut);
            liste.Children.Clear();
            lignes = new List<LigneEtatFluent>();
            if (resultat == null) { liste.Children.Add(new TextBlock { Text = L.T("Recherche…"), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire) }); Detailler(null); return; }
            if (resultat.Incidents.Count > 0) liste.Children.Add(Briques.Titre(L.T("Incidents de corrélation"), 0));
            foreach (var i in resultat.Incidents.Take(VueEvenementsFluent.Maximum)) Ajouter(VueEvenementsFluent.Ligne(i));
            if (resultat.Evenements.Count > 0) liste.Children.Add(Briques.Titre(L.T("Événements"), 8));
            foreach (var e in resultat.Evenements.Take(VueEvenementsFluent.Maximum)) Ajouter(VueEvenementsFluent.Ligne(e));
            if (lignes.Count == 0) liste.Children.Add(new TextBlock { Text = L.T("Aucun événement pour cette recherche."), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap });
            Detailler(lignes.Count > 0 ? lignes[Math.Min(choisie, lignes.Count - 1)] : null);
        }

        void Ajouter(LigneEtatFluent x)
        {
            int n = lignes.Count;
            lignes.Add(x);
            var b = Briques.Ligne(x.Titre, x.Etiquette, x.Sous, x.Gravite, n == choisie, false, () => { choisie = n; Afficher(); });
            liste.Children.Add(b);
        }

        void Detailler(LigneEtatFluent x)
        {
            if (x == null) { detail.Content = new TextBlock { Text = L.T("Sélectionnez un incident ou un événement pour voir le détail."), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap }; return; }
            var pile = new StackPanel();
            pile.Children.Add(new TextBlock { Text = x.Titre, FontSize = 16, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            if (!string.IsNullOrEmpty(x.Etiquette)) pile.Children.Add(new TextBlock { Text = x.Etiquette, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Briques.Couleur(x.Gravite)), Margin = new Thickness(0, 2, 0, 4) });
            foreach (var l in x.Detail)
            {
                pile.Children.Add(Briques.Titre(l.Titre, 10));
                var t = new TextBlock { Text = l.Texte, TextWrapping = TextWrapping.Wrap };
                if (l.Chasse) { t.FontFamily = Briques.Chasse; t.FontSize = 12; }
                pile.Children.Add(t);
            }
            detail.Content = pile;
        }
    }
    // Actions de réponse que les pages Connexions et Chaînes de la coquille (U4a) demandent à la fenêtre d'aujourd'hui :
    // mêmes méthodes, mêmes contrôles et mêmes questions que les menus de ses listes
    public interface ISourceReponses
    {
        void AgirElement(object element, string action);
        void BloquerConnexion(FluxInfo f, bool ipSeulement);
        void OuvrirEmplacement(string chemin);
    }

    // Décisions pures communes aux pages Connexions et Chaînes de la coquille (U4a), testées par tests\rendu-pilote.ps1
    public static class VueReseauFluent
    {
        public static string Libelle(string action)
        {
            switch (action)
            {
                case "bloquer": return L.T("Bloquer (nom dans le fichier hosts, sinon IP au pare-feu)");
                case "bloquerIp": return L.T("Bloquer l'IP au pare-feu");
                case "isolerProgramme": return L.T("Isoler ce programme du réseau");
                case "suspendre": return L.T("Suspendre le processus");
                case "reprendre": return L.T("Reprendre le processus");
                case "tuer": return L.T("Tuer le processus");
                case "tuerChaine": return L.T("Tuer ce processus et toute sa descendance");
                case "quarantaine": return L.T("Mettre le programme en quarantaine");
                case "emplacement": return L.T("Ouvrir l'emplacement du programme");
                case "copier": return L.T("Copier");
            }
            return action;
        }

        // Collecte en panne qui rend la liste incomplète : dite, jamais une liste vide qui rassure (null si elle tourne)
        public static string Panne(Etat e, string collecte)
        {
            var c = Couverture.EnPannes(e).FirstOrDefault(x => x.Id == collecte);
            return c == null ? null : Canal.Visible(Couverture.Decrire(c));
        }

        // Début du résumé selon la lecture d'etat.json : null quand l'état est lu et à jour
        public static string Lecture(bool lu, bool illisible, bool dejaAffiche)
        {
            bool en = L.En;
            if (!lu) return L.T("Lecture en cours…");
            if (!illisible) return null;
            return dejaAffiche
                ? (en ? "Service state unreadable or missing (etat.json): the last display is kept; it may be out of date." : "État du service illisible ou absent (etat.json) : dernier affichage gardé, peut-être dépassé.")
                : (en ? "Service state unreadable or missing (etat.json): nothing is concluded." : "État du service illisible ou absent (etat.json) : rien n'est conclu.");
        }

        // Valeurs copiées, séparées par des tabulations : d'origine, échappées (audit de #139, S139-01)
        public static string Copie(params string[] valeurs)
        {
            return string.Join("\t", valeurs.Select(Canal.Echappe));
        }

        internal static void Copier(string texte)
        {
            try { Clipboard.SetText(texte); } catch { }
        }
    }

    // Décisions pures de la page Connexions de la coquille (U4a). Tout ce qui vient d'etat.json (noms de programmes,
    // destinations, signataires, lignes de commande, raisons) peut avoir été choisi par un programme : neutralisé
    public static class VueConnexionsFluent
    {
        public const int Maximum = 500;
        public static readonly string[] Filtres = { "Toutes", "Suspectes", "Menaces" };

        // 2 : menace connue ; 1 : score au seuil d'alerte (3) ; 0 : le reste. Le score est toujours écrit
        public static int Gravite(FluxInfo f)
        {
            if (f == null) return 0;
            if ((f.Raisons ?? "").Contains("MENACE")) return 2;
            return f.Score >= Commun.SeuilAlerte ? 1 : 0;
        }

        public static bool Bloquee(FluxInfo f) { return f != null && (f.Raisons ?? "").Contains("BLOQUÉ"); }

        public static string Cle(FluxInfo f) { return f.Cle ?? (f.Pid + "|" + f.Ip + "|" + f.Port); }

        // Filtre 0 : toutes ; 1 : suspectes (score de 1 au moins, ou menace) ; 2 : menaces. Plus graves d'abord, puis score
        public static List<FluxInfo> Filtrer(IList<FluxInfo> flux, int filtre)
        {
            return (flux ?? new List<FluxInfo>()).Where(f => f != null && (filtre == 0 || (filtre == 1 && (f.Score >= 1 || Gravite(f) == 2)) || (filtre == 2 && Gravite(f) == 2)))
                .OrderByDescending(Gravite).ThenByDescending(f => f.Score).ThenBy(f => f.Processus ?? "", StringComparer.OrdinalIgnoreCase).ThenBy(Cle, StringComparer.Ordinal).ToList();
        }

        static string DestinationBrute(FluxInfo f) { return string.IsNullOrEmpty(f.NomDns) ? f.Ip : f.NomDns + " (" + f.Ip + ")"; }

        public static string Destination(FluxInfo f) { return Canal.Visible(DestinationBrute(f)); }

        // Actions offertes, dans l'ordre des boutons : celles du menu d'aujourd'hui, selon ce que la ligne permet
        public static List<string> Actions(FluxInfo f)
        {
            var l = new List<string>();
            if (f == null) return l;
            bool ip = !string.IsNullOrEmpty(f.Ip), nom = !string.IsNullOrEmpty(f.NomDns), chemin = !string.IsNullOrEmpty(f.Chemin), pid = f.Pid > 4;
            if (ip || nom) l.Add("bloquer");
            if (ip && nom) l.Add("bloquerIp");
            if (chemin) l.Add("isolerProgramme");
            if (pid) { l.Add("suspendre"); l.Add("reprendre"); l.Add("tuer"); }
            if (chemin) { l.Add("quarantaine"); l.Add("emplacement"); }
            l.Add("copier");
            return l;
        }

        public static string Sous(FluxInfo f)
        {
            bool en = L.En;
            return "PID " + f.Pid + "  ·  port " + f.Port + "  ·  " + Canal.Visible(string.IsNullOrEmpty(f.Signataire) ? (en ? "unsigned" : "non signé") : f.Signataire)
                + (string.IsNullOrEmpty(f.PremiereVue) ? "" : "  ·  " + (en ? "seen since " : "vu depuis ") + Canal.Visible(f.PremiereVue));
        }

        public static List<LigneDetail> Detail(FluxInfo f)
        {
            bool en = L.En;
            var l = new List<LigneDetail>();
            if (f == null) return l;
            Action<string, string, bool> ajout = (t, v, chasse) => { if (!string.IsNullOrEmpty(v)) l.Add(new LigneDetail { Titre = t, Texte = Canal.Visible(v), Chasse = chasse }); };
            ajout(en ? "Destination" : "Destination", DestinationBrute(f), true);
            ajout(en ? "Port" : "Port", f.Port.ToString(), false);
            ajout("PID", f.Pid.ToString(), false);
            ajout(en ? "Launched by" : "Lancé par", f.Parent, false);
            ajout(en ? "Connections" : "Connexions", f.Connexions > 0 ? f.Connexions.ToString() : null, false);
            ajout(en ? "Program signer" : "Signataire du programme", string.IsNullOrEmpty(f.Signataire) ? (en ? "unsigned" : "non signé") : f.Signataire, false);
            ajout(en ? "Seen since" : "Vu depuis", f.PremiereVue, false);
            ajout(en ? "Reasons" : "Raisons", f.Raisons, false);
            ajout(en ? "Path" : "Chemin", f.Chemin, true);
            ajout(en ? "Command line" : "Ligne de commande", f.LigneCommande, true);
            ajout(en ? "File origin" : "Origine du fichier", f.Origine, false);
            return l;
        }

        // Mêmes colonnes que la liste d'aujourd'hui
        public static string Copie(FluxInfo f)
        {
            return VueReseauFluent.Copie(f.Score.ToString(), f.Processus, f.Parent ?? "", f.Pid.ToString(), DestinationBrute(f), f.Port.ToString(), f.Signataire, f.PremiereVue, f.Raisons);
        }

        public static string Resume(IList<FluxInfo> flux, bool lu, bool illisible, string misAJour, string panne)
        {
            bool en = L.En;
            string lecture = VueReseauFluent.Lecture(lu, illisible, flux != null && flux.Count > 0);
            if (lecture != null && (!lu || flux == null || flux.Count == 0)) return lecture;
            var l = flux ?? new List<FluxInfo>();
            int suspectes = l.Count(f => f.Score >= 1 || Gravite(f) == 2), menaces = l.Count(f => Gravite(f) == 2);
            string texte = string.Format(en ? "{0} live outbound connection(s), {1} suspicious, {2} to a known threat." : "{0} connexion(s) sortante(s) en direct, dont {1} suspecte(s) et {2} vers une menace connue.", l.Count, suspectes, menaces);
            if (!string.IsNullOrEmpty(misAJour)) texte += " " + (en ? "State of " : "État du ") + Canal.Visible(misAJour) + ".";
            if (panne != null) texte += "\n" + (en ? "Incomplete list: " : "Liste incomplète : ") + panne;
            return lecture != null ? lecture + "\n" + texte : texte;
        }
    }

    // Décisions pures de la page Chaînes de la coquille (U4a) : mêmes seuils que la page d'aujourd'hui (alerte au-delà de
    // 12 sur toute la chaîne) ; noms et lignes de commande neutralisés
    public static class VueChainesFluent
    {
        public const int SeuilChaine = 12;

        public static int Gravite(Chaine c) { return c == null ? 0 : c.Score >= SeuilChaine ? 2 : c.Score >= Commun.SeuilAlerte ? 1 : 0; }

        // Même couleur que la liste d'aujourd'hui : un nœud qui compte dans une chaîne au-delà du seuil est critique
        public static int GraviteNoeud(Chaine c, NoeudChaine n)
        {
            if (n == null || n.Score <= 0) return 0;
            return c != null && c.Score >= SeuilChaine ? 2 : n.Score >= Commun.SeuilAlerte ? 1 : 0;
        }

        public static string Cle(Chaine c) { return (c.Racine ?? "") + "|" + (c.Depuis ?? ""); }

        // Chaînes au score positif, comme la page d'aujourd'hui ; les plus lourdes d'abord
        public static List<Chaine> Suspectes(IList<Chaine> chaines)
        {
            return (chaines ?? new List<Chaine>()).Where(c => c != null && c.Score > 0).OrderByDescending(c => c.Score).ThenBy(Cle, StringComparer.Ordinal).ToList();
        }

        public static List<string> Actions(NoeudChaine n)
        {
            var l = new List<string>();
            if (n == null) return l;
            if (n.Pid > 4) { l.Add("tuerChaine"); l.Add("suspendre"); }
            if (!string.IsNullOrEmpty(n.Chemin)) { l.Add("quarantaine"); l.Add("isolerProgramme"); l.Add("emplacement"); }
            l.Add("copier");
            return l;
        }

        public static List<LigneDetail> Detail(NoeudChaine n)
        {
            bool en = L.En;
            var l = new List<LigneDetail>();
            if (n == null) return l;
            Action<string, string, bool> ajout = (t, v, chasse) => { if (!string.IsNullOrEmpty(v)) l.Add(new LigneDetail { Titre = t, Texte = Canal.Visible(v), Chasse = chasse }); };
            ajout("PID", n.Pid.ToString(), false);
            ajout("Score", n.Score > 0 ? n.Score.ToString() : null, false);
            ajout(en ? "Reasons" : "Raisons", n.Raisons, false);
            ajout(en ? "Path" : "Chemin", n.Chemin, true);
            ajout(en ? "Command line" : "Ligne de commande", n.LigneCommande, true);
            return l;
        }

        // Mêmes colonnes que la liste d'aujourd'hui, sans le retrait de l'arbre
        public static string Copie(NoeudChaine n)
        {
            return VueReseauFluent.Copie(n.Nom, n.Pid.ToString(), n.Score > 0 ? n.Score.ToString() : "", n.Raisons, n.LigneCommande);
        }

        public static string Sous(Chaine c)
        {
            bool en = L.En;
            int n = (c.Noeuds ?? new List<NoeudChaine>()).Count;
            return (en ? "since " : "depuis ") + Canal.Visible(c.Depuis) + "  ·  " + n + " " + (en ? "process(es)" : "processus");
        }

        public static string Resume(IList<Chaine> suspectes, bool lu, bool illisible, string misAJour, string panne)
        {
            bool en = L.En;
            string lecture = VueReseauFluent.Lecture(lu, illisible, suspectes != null && suspectes.Count > 0);
            if (lecture != null && (!lu || suspectes == null || suspectes.Count == 0)) return lecture;
            var l = suspectes ?? new List<Chaine>();
            string texte = l.Count == 0 ? (en ? "No suspicious chain right now." : "Aucune chaîne suspecte en ce moment.")
                : string.Format(en ? "{0} suspicious chain(s), {1} above the alert threshold (12)." : "{0} chaîne(s) suspecte(s), dont {1} au-delà du seuil d'alerte (12).", l.Count, l.Count(c => c.Score >= SeuilChaine));
            texte += " " + (en ? "The score adds up over the whole chain: a series of actions that are harmless one by one becomes visible." : "Le score s'additionne sur toute la chaîne : une suite d'actions banales une à une devient visible.");
            if (!string.IsNullOrEmpty(misAJour)) texte += " " + (en ? "State of " : "État du ") + Canal.Visible(misAJour) + ".";
            if (panne != null) texte += "\n" + (en ? "Incomplete list: " : "Liste incomplète : ") + panne;
            return lecture != null ? lecture + "\n" + texte : texte;
        }
    }

    // Lecture d'etat.json hors du fil de l'interface, une à la fois, commune aux pages Connexions et Chaînes (U4a)
    abstract class PageEtatServiceFluent : Grid
    {
        protected readonly ISourceReponses source;
        protected readonly TextBlock resume = new TextBlock();
        protected readonly StackPanel outils = new StackPanel();
        protected readonly StackPanel liste = new StackPanel();
        protected readonly ContentControl detail = new ContentControl();
        readonly System.Windows.Threading.DispatcherTimer minuteur = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        protected bool lu, illisible;   // rien n'est dit « vide » avant la première lecture
        protected string misAJour, panne;
        protected string vu;
        int enCours, chargement;
        readonly string collecte;

        protected PageEtatServiceFluent(ISourceReponses source, string collecte, bool avecOutils)
        {
            this.source = source;
            this.collecte = collecte;
            Briques.Disposer(this, resume, avecOutils ? outils : null, liste, detail);
            minuteur.Tick += (s, e) => Charger();
            Loaded += (s, e) => { minuteur.Start(); Charger(); };
            Unloaded += (s, e) => minuteur.Stop();
        }

        internal void Charger()
        {
            if (System.Threading.Interlocked.CompareExchange(ref enCours, 1, 0) != 0) return;
            int numero = ++chargement;
            System.Threading.ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    var e = Commun.Lire<Etat>("etat.json");
                    string p = e == null ? null : VueReseauFluent.Panne(e, collecte);
                    Dispatcher.BeginInvoke((Action)(() => { if (numero == chargement) { lu = true; illisible = e == null; if (e != null) { misAJour = e.MisAJour; panne = p; Recevoir(e); } Afficher(); } }));
                }
                finally { System.Threading.Interlocked.Exchange(ref enCours, 0); }
            });
        }

        // Illisible : la dernière liste reste, plutôt qu'un vide qui rassure
        protected abstract void Recevoir(Etat e);
        protected abstract void Afficher();

        protected void Actions(StackPanel pile, List<string> actions, Action<string> agir)
        {
            pile.Children.Add(Briques.Titre(L.T("Agir"), 12));
            foreach (var a in actions)
            {
                string act = a;
                // Sans la fenêtre d'aujourd'hui (rendu hors écran), seule la copie reste : rien d'autre ne serait demandé
                if (source == null && act != "copier") continue;
                pile.Children.Add(Briques.Action(VueReseauFluent.Libelle(act), act == "bloquer" || act == "tuerChaine", (s, e) => agir(act)));
            }
        }

        protected static void Lignes(StackPanel pile, List<LigneDetail> lignes)
        {
            foreach (var l in lignes)
            {
                pile.Children.Add(Briques.Titre(l.Titre, 10));
                var t = new TextBlock { Text = l.Texte, TextWrapping = TextWrapping.Wrap };
                if (l.Chasse) { t.FontFamily = Briques.Chasse; t.FontSize = 12; }
                pile.Children.Add(t);
            }
        }

        protected void Vide(string texte)
        {
            liste.Children.Add(new TextBlock { Text = texte, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap });
        }
    }

    // Page Connexions en WPF (U4a) : flux sortants en direct lus dans etat.json, filtres, panneau de détails ; mêmes
    // actions et mêmes questions que le menu de la liste d'aujourd'hui (ISourceReponses)
    class PageConnexionsFluent : PageEtatServiceFluent
    {
        List<FluxInfo> flux = new List<FluxInfo>();
        int filtre;
        string choisie;

        public PageConnexionsFluent(ISourceReponses source) : base(source, "Connexions", true) { Afficher(); }

        protected override void Recevoir(Etat e) { flux = e.Flux ?? new List<FluxInfo>(); }

        protected override void Afficher()
        {
            resume.Text = VueConnexionsFluent.Resume(flux, lu, illisible, misAJour, panne);
            resume.Foreground = Jetons.Pinceau(illisible || panne != null ? Jetons.Attention : flux.Any(f => VueConnexionsFluent.Gravite(f) == 2) ? Jetons.Danger : Jetons.TexteSecondaire);
            var lignes = VueConnexionsFluent.Filtrer(flux, filtre);
            var x0 = lignes.FirstOrDefault(f => VueConnexionsFluent.Cle(f) == choisie) ?? lignes.FirstOrDefault();
            choisie = x0 == null ? null : VueConnexionsFluent.Cle(x0);
            string signature = filtre + "#" + choisie + "#" + resume.Text + "#" + string.Join(";", flux.Select(f => VueConnexionsFluent.Cle(f) + "|" + f.Score + "|" + f.Raisons + "|" + f.Connexions));
            if (signature == vu) return;
            vu = signature;
            outils.Children.Clear();
            var filtres = new WrapPanel { Margin = new Thickness(0, 0, 0, 12) };
            for (int k = 0; k < VueConnexionsFluent.Filtres.Length; k++)
            {
                int n = k;
                bool actif = n == filtre;
                var b = new Button
                {
                    // Avant la première lecture, aucun compteur : « 0 » ferait croire à une liste vide
                    Content = L.T(VueConnexionsFluent.Filtres[k]) + (lu ? "  " + VueConnexionsFluent.Filtrer(flux, n).Count : ""), Padding = new Thickness(12, 4, 12, 4), Margin = new Thickness(0, 0, 8, 0), Cursor = Cursors.Hand,
                    Background = Jetons.Pinceau(actif ? Jetons.Surface : Jetons.Fond), BorderBrush = Jetons.Pinceau(actif ? Jetons.Accent : Jetons.Separateur),
                    BorderThickness = new Thickness(1), Foreground = Jetons.Pinceau(Jetons.Texte)
                };
                b.Template = Coquille.ModeleBouton();
                b.Click += (s, e) => { filtre = n; choisie = null; Afficher(); };
                filtres.Children.Add(b);
            }
            outils.Children.Add(filtres);
            liste.Children.Clear();
            // Avant la première lecture, le résumé dit « Lecture en cours… » ; liste vide après lecture : le résumé dit pourquoi
            if (lu && lignes.Count == 0 && flux.Count > 0) Vide(L.En ? "Nothing for this filter." : "Rien pour ce filtre.");
            foreach (var f in lignes.Take(VueConnexionsFluent.Maximum))
            {
                string cle = VueConnexionsFluent.Cle(f);
                liste.Children.Add(Briques.Ligne(Canal.Visible(f.Processus) + "  →  " + VueConnexionsFluent.Destination(f), "score " + f.Score, VueConnexionsFluent.Sous(f),
                    VueConnexionsFluent.Gravite(f), cle == choisie, VueConnexionsFluent.Bloquee(f), () => { choisie = cle; Afficher(); }));
            }
            if (lignes.Count > VueConnexionsFluent.Maximum)
                liste.Children.Add(new TextBlock { Text = string.Format(L.En ? "The {0} most suspicious are shown." : "Les {0} plus suspectes sont affichées.", VueConnexionsFluent.Maximum), FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire) });
            Detailler(x0);
        }

        void Detailler(FluxInfo f)
        {
            if (f == null) { detail.Content = new TextBlock { Text = L.En ? "Select a connection to read its detail and act on it." : "Sélectionnez une connexion pour lire son détail et agir.", Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap }; return; }
            var pile = new StackPanel();
            int g = VueConnexionsFluent.Gravite(f);
            pile.Children.Add(new TextBlock { Text = Canal.Visible(f.Processus), FontSize = 18, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            pile.Children.Add(new TextBlock { Text = "score " + f.Score + (VueConnexionsFluent.Bloquee(f) ? (L.En ? "  ·  blocked" : "  ·  bloquée") : ""), FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Briques.Couleur(g)), Margin = new Thickness(0, 2, 0, 4) });
            Lignes(pile, VueConnexionsFluent.Detail(f));
            Actions(pile, VueConnexionsFluent.Actions(f), a => Agir(f, a));
            detail.Content = pile;
        }

        void Agir(FluxInfo f, string action)
        {
            if (action == "copier") { VueReseauFluent.Copier(VueConnexionsFluent.Copie(f)); return; }
            if (source == null) return;
            if (action == "bloquer") source.BloquerConnexion(f, false);
            else if (action == "bloquerIp") source.BloquerConnexion(f, true);
            else if (action == "emplacement") source.OuvrirEmplacement(f.Chemin);
            else source.AgirElement(f, action);
            Charger();
        }
    }

    // Page Chaînes en WPF (U4a) : chaînes de processus lues dans etat.json, arbre dans le panneau de détails ; mêmes
    // actions et mêmes questions que le menu de la liste d'aujourd'hui (ISourceReponses)
    class PageChainesFluent : PageEtatServiceFluent
    {
        List<Chaine> chaines = new List<Chaine>();
        string choisie;
        int? noeud;             // PID du processus choisi dans l'arbre

        public PageChainesFluent(ISourceReponses source) : base(source, "Processus", false) { Afficher(); }

        protected override void Recevoir(Etat e) { chaines = VueChainesFluent.Suspectes(e.Chaines); }

        protected override void Afficher()
        {
            resume.Text = VueChainesFluent.Resume(chaines, lu, illisible, misAJour, panne);
            resume.Foreground = Jetons.Pinceau(illisible || panne != null ? Jetons.Attention : chaines.Any(c => c.Score >= VueChainesFluent.SeuilChaine) ? Jetons.Danger : Jetons.TexteSecondaire);
            var c0 = chaines.FirstOrDefault(c => VueChainesFluent.Cle(c) == choisie) ?? chaines.FirstOrDefault();
            choisie = c0 == null ? null : VueChainesFluent.Cle(c0);
            var noeuds = c0 == null ? new List<NoeudChaine>() : (c0.Noeuds ?? new List<NoeudChaine>());
            var n0 = noeuds.FirstOrDefault(n => n.Pid == noeud) ?? noeuds.OrderByDescending(n => n.Score).FirstOrDefault();
            noeud = n0 == null ? (int?)null : n0.Pid;
            string signature = choisie + "#" + noeud + "#" + resume.Text + "#" + string.Join(";", chaines.Select(c => VueChainesFluent.Cle(c) + "|" + c.Score + "|" + string.Join(",", (c.Noeuds ?? new List<NoeudChaine>()).Select(n => n.Pid + ":" + n.Score))));
            if (signature == vu) return;
            vu = signature;
            liste.Children.Clear();
            // Avant la première lecture, le résumé dit « Lecture en cours… » ; liste vide après lecture : le résumé le dit
            foreach (var c in chaines)
            {
                string cle = VueChainesFluent.Cle(c);
                liste.Children.Add(Briques.Ligne(Canal.Visible(c.Resume), "score " + c.Score, VueChainesFluent.Sous(c), VueChainesFluent.Gravite(c), cle == choisie, false, () => { choisie = cle; noeud = null; Afficher(); }));
            }
            Detailler(c0, n0);
        }

        void Detailler(Chaine c, NoeudChaine n0)
        {
            bool en = L.En;
            if (c == null) { detail.Content = new TextBlock { Text = en ? "Select a chain to read who launched what." : "Sélectionnez une chaîne pour lire qui a lancé quoi.", Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap }; return; }
            var pile = new StackPanel();
            pile.Children.Add(new TextBlock { Text = Canal.Visible(c.Resume), FontSize = 16, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            pile.Children.Add(new TextBlock { Text = "score " + c.Score + "  ·  " + (en ? "alert above 12" : "alerte au-delà de 12"), FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Briques.Couleur(VueChainesFluent.Gravite(c))), Margin = new Thickness(0, 2, 0, 4) });
            pile.Children.Add(Briques.Titre(en ? "Who launched what" : "Qui a lancé quoi", 10));
            foreach (var n in c.Noeuds ?? new List<NoeudChaine>())
            {
                int pid = n.Pid;
                int g = VueChainesFluent.GraviteNoeud(c, n);
                var ligne = new Border
                {
                    Background = Jetons.Pinceau(n == n0 ? Jetons.Surface : Jetons.Carte), CornerRadius = new CornerRadius(4), Padding = new Thickness(8, 3, 8, 3),
                    Margin = new Thickness(Math.Min(Math.Max(n.Profondeur, 0), 8) * 14, 0, 0, 2), Cursor = Cursors.Hand
                };
                var texte = new TextBlock { TextTrimming = TextTrimming.CharacterEllipsis };
                texte.Inlines.Add(new System.Windows.Documents.Run((n.Profondeur > 0 ? "└ " : "") + Canal.Visible(n.Nom)) { Foreground = Jetons.Pinceau(n.Score > 0 ? Jetons.Texte : Jetons.TexteSecondaire) });
                texte.Inlines.Add(new System.Windows.Documents.Run("  " + pid + (n.Score > 0 ? "  ·  +" + n.Score : "")) { Foreground = Jetons.Pinceau(n.Score > 0 ? Briques.Couleur(g) : Jetons.TexteSecondaire), FontSize = 12 });
                ligne.Child = texte;
                ligne.MouseLeftButtonUp += (s, e) => { noeud = pid; Afficher(); };
                pile.Children.Add(ligne);
            }
            if (n0 != null)
            {
                pile.Children.Add(new TextBlock { Text = Canal.Visible(n0.Nom), FontSize = 14, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 14, 0, 0), TextWrapping = TextWrapping.Wrap });
                Lignes(pile, VueChainesFluent.Detail(n0));
                Actions(pile, VueChainesFluent.Actions(n0), a => Agir(n0, a));
            }
            detail.Content = pile;
        }

        void Agir(NoeudChaine n, string action)
        {
            if (action == "copier") { VueReseauFluent.Copier(VueChainesFluent.Copie(n)); return; }
            if (source == null) return;
            if (action == "emplacement") source.OuvrirEmplacement(n.Chemin);
            else source.AgirElement(n, action);
            Charger();
        }
    }
    // Décisions pures de la page Trafic de la coquille (U4b), testées par tests\rendu-pilote.ps1. Noms de programmes, noms
    // de destinations et nom d'interface : un programme choisit son nom, un serveur DNS le nom qu'il renvoie ; neutralisés
    public static class VueTraficFluent
    {
        public static readonly string[] Vues = { "Programmes", "Pays", "Destinations" };
        public const int Maximum = 500;

        // Intensité d'un pays sur la carte (0 à 1) : échelle logarithmique, quelques Ko restent visibles à côté de plusieurs Go
        public static double Intensite(long v, long max)
        {
            if (v <= 0) return 0;
            return Math.Log(1 + (double)v) / Math.Log(1 + (double)Math.Max(v, Math.Max(1, max)));
        }

        internal static Color Melange(Color a, Color b, double t)
        {
            t = Math.Max(0, Math.Min(1, t));
            return Color.FromRgb((byte)(a.R + (b.R - a.R) * t), (byte)(a.G + (b.G - a.G) * t), (byte)(a.B + (b.B - a.B) * t));
        }

        public static string Resume(EtatTrafic t, bool lu, bool illisible)
        {
            bool en = L.En;
            if (!lu) return L.T("Lecture en cours…");
            if (t == null)
                return en ? "No traffic data (trafic.json missing or unreadable): nothing is concluded. The service captures packets once it has started."
                          : "Aucune donnée de trafic (trafic.json absent ou illisible) : rien n'est conclu. Le service capture les paquets dès son démarrage.";
            string depuis = (t.Depuis ?? "").Length >= 16 ? t.Depuis.Substring(11, 5) : t.Depuis;
            string s = string.Format(en ? "Now: ↓ {0}  ↑ {1}   ·   since {2}: ↓ {3}  ↑ {4}   ·   {5:N0} packets   ·   interface {6}"
                                        : "En ce moment : ↓ {0}  ↑ {1}   ·   depuis {2} : ↓ {3}  ↑ {4}   ·   {5:N0} paquets   ·   interface {6}",
                Format.Debit(t.DebitEntrant), Format.Debit(t.DebitSortant), Canal.Visible(depuis), Format.Octets(t.TotalEntrant), Format.Octets(t.TotalSortant), t.Paquets, Canal.Visible(t.Interface));
            if (!string.IsNullOrEmpty(t.MisAJour)) s += (en ? "   ·   state of " : "   ·   état du ") + Canal.Visible(t.MisAJour);
            if (illisible) s = (en ? "trafic.json unreadable: the last display is kept; it may be out of date." : "trafic.json illisible : dernier affichage gardé, peut-être dépassé.") + "\n" + s;
            return s;
        }

        static string Programmes(List<string> l) { return string.Join(", ", (l ?? new List<string>()).Select(Canal.Visible)); }

        public static string NomPays(string code) { return Canal.Visible(PaysCarte.NomDe(code)) + " (" + Canal.Visible(code) + ")"; }

        // Bulle d'un pays de la carte (null : pays sans échange)
        public static string Bulle(string code, TraficPays p)
        {
            if (code == null) return null;
            string nom = NomPays(code);
            if (p == null) return nom;
            return nom + "\n" + Format.Octets(p.Entrant + p.Sortant) + " · " + p.Destinations + " destination(s)" + (p.Programmes != null && p.Programmes.Count > 0 ? "\n" + Programmes(p.Programmes) : "");
        }

        // Lignes de la vue choisie, plus gros volume d'abord ; « en ce moment » pour un échange des 10 dernières secondes
        public static List<LigneEtatFluent> Lignes(EtatTrafic t, int vue)
        {
            bool en = L.En;
            var l = new List<LigneEtatFluent>();
            if (t == null) return l;
            string maintenant = en ? "  ·  now" : "  ·  en ce moment";
            Func<string, string, LigneDetail> d = (titre, texte) => new LigneDetail { Titre = titre, Texte = texte };
            if (vue == 0)
                foreach (var a in (t.Applications ?? new List<TraficApplication>()).Where(x => x != null).OrderByDescending(x => x.Entrant + x.Sortant).ThenBy(x => x.Nom ?? "", StringComparer.OrdinalIgnoreCase))
                    l.Add(new LigneEtatFluent
                    {
                        Titre = Canal.Visible(a.Nom), Etiquette = Format.Octets(a.Entrant + a.Sortant),
                        Sous = "↓ " + Format.Octets(a.Entrant) + "  ↑ " + Format.Octets(a.Sortant) + "  ·  " + a.Destinations + " destination(s)",
                        Detail = new List<LigneDetail> { d(en ? "Received" : "Reçu", Format.Octets(a.Entrant)), d(en ? "Sent" : "Envoyé", Format.Octets(a.Sortant)), d("Destinations", a.Destinations.ToString()) }
                    });
            else if (vue == 1)
                foreach (var p in (t.Pays ?? new List<TraficPays>()).Where(x => x != null).OrderByDescending(x => x.Entrant + x.Sortant).ThenBy(x => x.Code ?? "", StringComparer.Ordinal))
                    l.Add(new LigneEtatFluent
                    {
                        Titre = NomPays(p.Code), Etiquette = Format.Octets(p.Entrant + p.Sortant),
                        Sous = p.Destinations + " destination(s)  ·  " + Programmes(p.Programmes) + (p.Active ? maintenant : ""),
                        Detail = new List<LigneDetail> { d(en ? "Received" : "Reçu", Format.Octets(p.Entrant)), d(en ? "Sent" : "Envoyé", Format.Octets(p.Sortant)), d("Destinations", p.Destinations.ToString()),
                                                         d(en ? "Programs" : "Programmes", string.Join("\n", (p.Programmes ?? new List<string>()).Select(Canal.Visible))) }
                    });
            else
                foreach (var x in (t.Destinations ?? new List<TraficDestination>()).Where(x => x != null).OrderByDescending(x => x.Entrant + x.Sortant).ThenBy(x => x.Ip ?? "", StringComparer.Ordinal))
                {
                    var det = new List<LigneDetail> { new LigneDetail { Titre = en ? "IP address" : "Adresse IP", Texte = Canal.Visible(x.Ip), Chasse = true } };
                    if (!string.IsNullOrEmpty(x.Nom)) det.Add(new LigneDetail { Titre = en ? "Name" : "Nom", Texte = Canal.Visible(x.Nom), Chasse = true });
                    det.Add(d(en ? "Country" : "Pays", NomPays(x.Pays)));
                    det.Add(d(en ? "Program" : "Programme", Canal.Visible(x.Programme)));
                    det.Add(d("Port", x.Port.ToString()));
                    det.Add(d(en ? "Received" : "Reçu", Format.Octets(x.Entrant)));
                    det.Add(d(en ? "Sent" : "Envoyé", Format.Octets(x.Sortant)));
                    l.Add(new LigneEtatFluent
                    {
                        Titre = Canal.Visible(string.IsNullOrEmpty(x.Nom) ? x.Ip : x.Nom + " (" + x.Ip + ")"), Etiquette = Format.Octets(x.Entrant + x.Sortant),
                        Sous = Canal.Visible(x.Pays) + "  ·  " + Canal.Visible(x.Programme) + "  ·  port " + x.Port + (x.Active ? maintenant : ""), Detail = det
                    });
                }
            foreach (var x in l) foreach (var y in x.Detail) if (string.IsNullOrEmpty(y.Texte)) y.Texte = "—";
            return l;
        }
    }

    // Carte du monde de la page Trafic (U4b) : contours Natural Earth intégrés à l'exécutable (aucun fond chargé d'Internet),
    // pays colorés selon le volume depuis minuit, arcs fixes vers les pays des 10 dernières secondes ; aucune animation
    // continue (la page reste légère quand elle est ouverte longtemps)
    class CarteFluent : FrameworkElement
    {
        List<TraficPays> pays = new List<TraficPays>();
        List<KeyValuePair<string, Geometry>> formes;
        Size tailleFormes;
        string survol;
        readonly string origine;

        public CarteFluent()
        {
            ClipToBounds = true;
            try { origine = System.Globalization.RegionInfo.CurrentRegion.TwoLetterISORegionName; } catch { origine = null; }
            ToolTipService.SetInitialShowDelay(this, 150);
        }

        public void Definir(List<TraficPays> p) { pays = p ?? new List<TraficPays>(); InvalidateVisual(); }

        internal const double Haut = 22;

        Rect Zone()
        {
            // Longitude -180..180, latitude -58..84 (sans l'Antarctique), proportions conservées
            double l = Math.Max(1, ActualWidth - 16), h = Math.Max(1, ActualHeight - Haut - 8);
            double echelle = Math.Min(l / 360, h / 142);
            double lw = 360 * echelle, lh = 142 * echelle;
            return new Rect((ActualWidth - lw) / 2, Haut + (h - lh) / 2, lw, lh);
        }

        static Point Projeter(System.Drawing.PointF ll, Rect z) { return new Point(z.X + (ll.X + 180) / 360 * z.Width, z.Y + (84 - ll.Y) / 142 * z.Height); }

        // Contours projetés, reconstruits seulement quand la taille change
        List<KeyValuePair<string, Geometry>> Formes()
        {
            var taille = new Size(ActualWidth, ActualHeight);
            if (formes != null && taille == tailleFormes) return formes;
            tailleFormes = taille;
            var z = Zone();
            formes = new List<KeyValuePair<string, Geometry>>();
            foreach (var p in PaysCarte.Tous.Values)
            {
                var g = new StreamGeometry();
                using (var c = g.Open())
                    foreach (var a in p.Anneaux)
                    {
                        if (a.Length < 3) continue;
                        c.BeginFigure(Projeter(a[0], z), true, true);
                        c.PolyLineTo(a.Skip(1).Select(q => Projeter(q, z)).ToList(), true, false);
                    }
                g.Freeze();
                formes.Add(new KeyValuePair<string, Geometry>(p.Code, g));
            }
            return formes;
        }

        FormattedText Texte(string t)
        {
            return new FormattedText(t, System.Globalization.CultureInfo.CurrentUICulture, FlowDirection.LeftToRight, new Typeface(Jetons.Police, FontStyles.Normal, FontWeights.Normal, FontStretches.Normal),
                11, Jetons.Pinceau(Jetons.TexteSecondaire), VisualTreeHelper.GetDpi(this).PixelsPerDip);
        }

        protected override void OnRender(DrawingContext g)
        {
            g.DrawRoundedRectangle(Jetons.Pinceau(Jetons.Carte), null, new Rect(0, 0, ActualWidth, ActualHeight), 8, 8);
            if (ActualWidth < 40 || ActualHeight < 40) return;
            // Légende coupée par des points de suspension quand la carte est étroite, jamais tronquée en plein mot (captures de #141)
            var legende = Texte(L.En ? "Volume since midnight (log scale) · arcs: last 10 seconds" : "Volume depuis minuit (échelle log.) · arcs : 10 dernières secondes");
            legende.MaxTextWidth = Math.Max(1, ActualWidth - 24); legende.MaxLineCount = 1; legende.Trimming = TextTrimming.CharacterEllipsis;
            g.DrawText(legende, new Point(12, 4));
            var volumes = new Dictionary<string, long>();
            foreach (var p in pays) if (p != null && p.Code != null) volumes[p.Code] = p.Entrant + p.Sortant;
            long max = volumes.Count == 0 ? 1 : volumes.Values.Max();
            var trait = new Pen(Jetons.Pinceau(Jetons.Separateur), 0.6); trait.Freeze();
            foreach (var f in Formes())
            {
                long v;
                var fond = Jetons.Surface;
                if (volumes.TryGetValue(f.Key, out v) && v > 0) fond = VueTraficFluent.Melange(Jetons.Surface, Jetons.Accent, 0.25 + 0.75 * VueTraficFluent.Intensite(v, max));
                if (f.Key == survol) fond = VueTraficFluent.Melange(fond, Colors.White, 0.2);
                g.DrawGeometry(Jetons.Pinceau(fond), trait, f.Value);
            }
            PaysCarte depart;
            if (origine == null || !PaysCarte.Tous.TryGetValue(origine, out depart)) return;
            var z = Zone();
            var a0 = Projeter(depart.Centre, z);
            var arc = new Pen(new SolidColorBrush(Color.FromArgb(170, Jetons.Accent.R, Jetons.Accent.G, Jetons.Accent.B)), 1.4); arc.Freeze();
            foreach (var p in pays.Where(x => x != null && x.Active))
            {
                PaysCarte arrivee;
                if (p.Code == null || !PaysCarte.Tous.TryGetValue(p.Code, out arrivee) || arrivee == depart) continue;
                var a1 = Projeter(arrivee.Centre, z);
                double dx = a1.X - a0.X, dy = a1.Y - a0.Y;
                var milieu = new Point((a0.X + a1.X) / 2 - dy * 0.25, (a0.Y + a1.Y) / 2 - Math.Abs(dx) * 0.25 - 10);
                var courbe = new StreamGeometry();
                using (var c = courbe.Open()) { c.BeginFigure(a0, false, false); c.QuadraticBezierTo(milieu, a1, true, false); }
                courbe.Freeze();
                g.DrawGeometry(null, arc, courbe);
                g.DrawEllipse(Jetons.Pinceau(Jetons.Accent), null, a1, 3.5, 3.5);
            }
            g.DrawEllipse(Jetons.Pinceau(Jetons.Texte), null, a0, 3.5, 3.5);
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            var pt = e.GetPosition(this);
            string trouve = null;
            foreach (var f in Formes()) if (f.Value.FillContains(pt)) { trouve = f.Key; break; }
            if (trouve == survol) return;
            survol = trouve;
            ToolTip = VueTraficFluent.Bulle(trouve, pays.FirstOrDefault(x => x != null && x.Code == trouve));
            InvalidateVisual();
        }

        protected override void OnMouseLeave(MouseEventArgs e)
        {
            base.OnMouseLeave(e);
            if (survol == null) return;
            survol = null; ToolTip = null; InvalidateVisual();
        }
    }

    // Courbe du débit (entrant et sortant) sur les 10 dernières minutes, maximum et légende écrits
    class CourbeFluent : FrameworkElement
    {
        List<PointTrafic> serie = new List<PointTrafic>();

        public void Definir(List<PointTrafic> s) { serie = s ?? new List<PointTrafic>(); InvalidateVisual(); }

        FormattedText Texte(string t, Color c)
        {
            return new FormattedText(t, System.Globalization.CultureInfo.CurrentUICulture, FlowDirection.LeftToRight, new Typeface(Jetons.Police, FontStyles.Normal, FontWeights.Normal, FontStretches.Normal),
                11, Jetons.Pinceau(c), VisualTreeHelper.GetDpi(this).PixelsPerDip);
        }

        protected override void OnRender(DrawingContext g)
        {
            bool en = L.En;
            g.DrawRoundedRectangle(Jetons.Pinceau(Jetons.Carte), null, new Rect(0, 0, ActualWidth, ActualHeight), 8, 8);
            if (ActualWidth < 60 || ActualHeight < 60) return;
            var points = serie.Where(p => p != null).ToList();
            long max = Math.Max(1024, points.Select(p => Math.Max(p.Entrant, p.Sortant)).DefaultIfEmpty(0).Max());
            // Sans deux mesures, aucun maximum : « max 1 Ko/s » laisserait croire à un débit mesuré
            g.DrawText(Texte(points.Count < 2 ? (en ? "no measurement yet" : "pas encore de mesure") : "max " + Format.Debit(max), Jetons.TexteSecondaire), new Point(12, 4));
            var sortant = Texte(en ? "▬ out" : "▬ sortant", Jetons.Succes);
            var entrant = Texte(en ? "▬ in" : "▬ entrant", Jetons.Accent);
            g.DrawText(sortant, new Point(ActualWidth - 12 - sortant.Width, 4));
            g.DrawText(entrant, new Point(ActualWidth - 24 - sortant.Width - entrant.Width, 4));
            g.DrawText(Texte(en ? "last 10 minutes" : "10 dernières minutes", Jetons.TexteSecondaire), new Point(12, ActualHeight - 18));
            if (points.Count < 2) return;
            var z = new Rect(12, 24, ActualWidth - 24, Math.Max(1, ActualHeight - 46));
            int n = Math.Max(points.Count, 120);
            Func<int, long, Point> pt = (i, v) => new Point(z.Left + i * z.Width / (n - 1), z.Bottom - v / (double)max * z.Height);
            foreach (var s in new[] { new { Couleur = Jetons.Accent, Entrant = true }, new { Couleur = Jetons.Succes, Entrant = false } })
            {
                var geo = new StreamGeometry();
                bool entr = s.Entrant;
                using (var c = geo.Open())
                {
                    c.BeginFigure(pt(0, entr ? points[0].Entrant : points[0].Sortant), false, false);
                    c.PolyLineTo(points.Skip(1).Select((p, i) => pt(i + 1, entr ? p.Entrant : p.Sortant)).ToList(), true, true);
                }
                geo.Freeze();
                var stylo = new Pen(Jetons.Pinceau(s.Couleur), 1.6); stylo.Freeze();
                g.DrawGeometry(null, stylo, geo);
            }
        }
    }

    // Page Trafic en WPF (U4b) : même fichier que la page d'aujourd'hui (trafic.json, lecture seule hors du fil de
    // l'interface, relu seulement quand il change), carte, courbe, puis programmes, pays ou destinations avec leur détail
    class PageTraficFluent : Grid
    {
        readonly TextBlock resume = new TextBlock();
        readonly StackPanel outils = new StackPanel();
        readonly WrapPanel vues = new WrapPanel { Margin = new Thickness(0, 0, 0, 12) };
        readonly StackPanel liste = new StackPanel();
        readonly ContentControl detail = new ContentControl();
        readonly CarteFluent carte = new CarteFluent();
        readonly CourbeFluent courbe = new CourbeFluent();
        readonly System.Windows.Threading.DispatcherTimer minuteur = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        EtatTrafic t;
        bool lu, illisible;
        long vuFichier;         // date du fichier lu (ticks) : rien n'est relu tant qu'il ne change pas
        int vue, choisie, enCours, chargement;
        string vu;

        public PageTraficFluent()
        {
            var haut = new Grid { Height = 250, Margin = new Thickness(0, 0, 0, 12) };
            haut.ColumnDefinitions.Add(new ColumnDefinition());
            haut.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(300) });
            courbe.Margin = new Thickness(12, 0, 0, 0);
            Grid.SetColumn(courbe, 1);
            haut.Children.Add(carte); haut.Children.Add(courbe);
            outils.Children.Add(haut);
            outils.Children.Add(vues);
            Briques.Disposer(this, resume, outils, liste, detail);
            minuteur.Tick += (s, e) => Charger();
            Loaded += (s, e) => { minuteur.Start(); Charger(); };
            Unloaded += (s, e) => minuteur.Stop();
            Afficher();
        }

        internal void Charger()
        {
            if (System.Threading.Interlocked.CompareExchange(ref enCours, 1, 0) != 0) return;
            int numero = ++chargement;
            long deja = lu && !illisible ? vuFichier : -1;
            System.Threading.ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    long date;
                    try { date = System.IO.File.GetLastWriteTimeUtc(System.IO.Path.Combine(Commun.Dossier, "trafic.json")).Ticks; } catch { date = 0; }
                    if (date == deja) return;
                    var x = Commun.Lire<EtatTrafic>("trafic.json");
                    Dispatcher.BeginInvoke((Action)(() =>
                    {
                        if (numero != chargement) return;
                        lu = true;
                        // Illisible après une lecture : la dernière carte et les dernières listes restent, et c'est dit
                        if (x == null) illisible = t != null;
                        else { t = x; illisible = false; vuFichier = date; }
                        Afficher();
                    }));
                }
                finally { System.Threading.Interlocked.Exchange(ref enCours, 0); }
            });
        }

        void Afficher()
        {
            resume.Text = VueTraficFluent.Resume(t, lu, illisible);
            resume.Foreground = Jetons.Pinceau(lu && (t == null || illisible) ? Jetons.Attention : Jetons.TexteSecondaire);
            carte.Definir(t == null ? null : t.Pays);
            courbe.Definir(t == null ? null : t.Serie);
            var lignes = VueTraficFluent.Lignes(t, vue);
            if (choisie >= lignes.Count) choisie = 0;
            string signature = vue + "#" + choisie + "#" + resume.Text + "#" + string.Join(";", lignes.Take(VueTraficFluent.Maximum).Select(x => x.Titre + "|" + x.Etiquette + "|" + x.Sous));
            if (signature == vu) return;
            vu = signature;
            vues.Children.Clear();
            for (int k = 0; k < VueTraficFluent.Vues.Length; k++)
            {
                int n = k;
                bool actif = n == vue;
                var b = new Button
                {
                    Content = L.T(VueTraficFluent.Vues[k]), Padding = new Thickness(12, 4, 12, 4), Margin = new Thickness(0, 0, 8, 0), Cursor = Cursors.Hand,
                    Background = Jetons.Pinceau(actif ? Jetons.Surface : Jetons.Fond), BorderBrush = Jetons.Pinceau(actif ? Jetons.Accent : Jetons.Separateur),
                    BorderThickness = new Thickness(1), Foreground = Jetons.Pinceau(Jetons.Texte)
                };
                b.Template = Coquille.ModeleBouton();
                b.Click += (s, e) => { vue = n; choisie = 0; Afficher(); };
                vues.Children.Add(b);
            }
            liste.Children.Clear();
            // Avant la première lecture, ou sans données, le résumé le dit ; rien n'est conclu ici
            if (lu && t != null && lignes.Count == 0)
                liste.Children.Add(new TextBlock { Text = L.T("Rien d'enregistré pour cette vue."), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap });
            for (int k = 0; k < Math.Min(lignes.Count, VueTraficFluent.Maximum); k++)
            {
                int n = k; var x = lignes[k];
                liste.Children.Add(Briques.Ligne(x.Titre, x.Etiquette, x.Sous, 0, n == choisie, false, () => { choisie = n; Afficher(); }));
            }
            if (lignes.Count > VueTraficFluent.Maximum)
                liste.Children.Add(new TextBlock { Text = string.Format(L.En ? "The {0} largest are shown." : "Les {0} plus gros volumes sont affichés.", VueTraficFluent.Maximum), FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire) });
            Detailler(lignes.Count > 0 ? lignes[choisie] : null);
        }

        void Detailler(LigneEtatFluent x)
        {
            if (x == null) { detail.Content = new TextBlock { Text = L.T("Sélectionnez une ligne pour lire son détail en entier."), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap }; return; }
            var pile = new StackPanel();
            pile.Children.Add(new TextBlock { Text = x.Titre, FontSize = 16, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            pile.Children.Add(new TextBlock { Text = x.Etiquette, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, 2, 0, 4) });
            foreach (var l in x.Detail)
            {
                pile.Children.Add(Briques.Titre(l.Titre, 10));
                var tb = new TextBlock { Text = l.Texte, TextWrapping = TextWrapping.Wrap };
                if (l.Chasse) { tb.FontFamily = Briques.Chasse; tb.FontSize = 12; }
                pile.Children.Add(tb);
            }
            detail.Content = pile;
        }
    }
    // Lecture d'un fichier du service : absent n'est pas illisible (absent : rien d'enregistré ; illisible : rien de conclu)
    static class LectureFluent
    {
        public static T Lire<T>(string nom, out bool absent) where T : class
        {
            // Accès refusé n'est pas absent (audit de #142, S142-01) : même règle que config.json
            absent = ActionsProtection.Absent(nom);
            return absent ? null : Commun.Lire<T>(nom);
        }
    }

    // Décisions pures de la page Blocages de la coquille (U5a), testées par tests\rendu-pilote.ps1. Cible et raison
    // reprennent un nom de domaine ou de programme vu sur le réseau : neutralisés
    public static class VueBlocagesFluent
    {
        public static string Type(Blocage b)
        {
            bool en = L.En;
            return b.Type == "hosts" ? (en ? "hosts file" : "fichier hosts") : b.Type == "programme" ? (en ? "isolated program" : "programme isolé") : (en ? "firewall" : "pare-feu");
        }

        public static string Resume(IList<Blocage> l, bool lu, bool illisible)
        {
            bool en = L.En;
            if (!lu) return L.T("Lecture en cours…");
            bool garde = l != null && l.Count > 0;
            string avant = !illisible ? "" : garde
                ? (en ? "blocages.json unreadable: the last display is kept; it may be out of date.\n" : "blocages.json illisible : dernier affichage gardé, peut-être dépassé.\n")
                : (en ? "blocages.json unreadable: nothing is concluded." : "blocages.json illisible : rien n'est conclu.");
            if (illisible && !garde) return avant;
            var x = l ?? new List<Blocage>();
            if (x.Count == 0) return en ? "No block." : "Aucun blocage.";
            return avant + string.Format(en ? "{0} block(s): {1} name(s) redirected to 127.0.0.1 in the hosts file, {2} IP address(es) blocked at the firewall, {3} program(s) isolated from the network."
                                            : "{0} blocage(s) : {1} nom(s) redirigé(s) vers 127.0.0.1 dans le fichier hosts, {2} IP bloquée(s) au pare-feu, {3} programme(s) isolé(s) du réseau.",
                x.Count, x.Count(b => b.Type == "hosts"), x.Count(b => b.Type != "hosts" && b.Type != "programme"), x.Count(b => b.Type == "programme"));
        }

        public static List<LigneDetail> Detail(Blocage b)
        {
            bool en = L.En;
            return new List<LigneDetail>
            {
                new LigneDetail { Titre = "Type", Texte = Type(b) },
                new LigneDetail { Titre = en ? "Target" : "Cible", Texte = Canal.Visible(b.Cible), Chasse = true },
                new LigneDetail { Titre = en ? "Reason" : "Raison", Texte = string.IsNullOrEmpty(b.Raison) ? "—" : Canal.Visible(b.Raison) },
                new LigneDetail { Titre = "Date", Texte = string.IsNullOrEmpty(b.Date) ? "—" : Canal.Visible(b.Date) }
            };
        }
    }

    // Décisions pures de la page Quarantaine de la coquille (U5a). Le chemin d'origine est un nom de fichier choisi par un
    // programme : neutralisé, à l'écran comme dans la question de restauration
    public static class VueQuarantaineFluent
    {
        // Plus récents d'abord, comme la page d'aujourd'hui
        public static List<ElementQuarantaine> Trier(IList<ElementQuarantaine> l) { return Enumerable.Reverse(l ?? new List<ElementQuarantaine>()).Where(q => q != null).ToList(); }

        public static string Nom(ElementQuarantaine q)
        {
            string c = q.CheminOrigine ?? "";
            int k = Math.Max(c.LastIndexOf('\\'), c.LastIndexOf('/'));
            return Canal.Visible(k >= 0 && k < c.Length - 1 ? c.Substring(k + 1) : c);
        }

        public static string Taille(long octets) { return (octets / 1024).ToString("N0") + (L.En ? " KB" : " Ko"); }

        public static string Resume(IList<ElementQuarantaine> l, bool lu, bool illisible)
        {
            bool en = L.En;
            if (!lu) return L.T("Lecture en cours…");
            bool garde = l != null && l.Count > 0;
            if (illisible && !garde) return en ? "quarantaine.json unreadable: nothing is concluded." : "quarantaine.json illisible : rien n'est conclu.";
            string avant = illisible ? (en ? "quarantaine.json unreadable: the last display is kept; it may be out of date.\n" : "quarantaine.json illisible : dernier affichage gardé, peut-être dépassé.\n") : "";
            var x = l ?? new List<ElementQuarantaine>();
            if (x.Count == 0) return en ? "No file in quarantine." : "Aucun fichier en quarantaine.";
            return avant + string.Format(en ? "{0} file(s) removed from their location and made non-executable; they can be restored." : "{0} fichier(s) retiré(s) de leur emplacement et rendu(s) inexécutable(s) ; ils peuvent être restaurés.", x.Count);
        }

        public static List<LigneDetail> Detail(ElementQuarantaine q)
        {
            bool en = L.En;
            return new List<LigneDetail>
            {
                new LigneDetail { Titre = en ? "Original location" : "Emplacement d'origine", Texte = Canal.Visible(q.CheminOrigine), Chasse = true },
                new LigneDetail { Titre = "Date", Texte = string.IsNullOrEmpty(q.Date) ? "—" : Canal.Visible(q.Date) },
                new LigneDetail { Titre = en ? "Reason" : "Raison", Texte = string.IsNullOrEmpty(q.Raison) ? "—" : Canal.Visible(q.Raison) },
                new LigneDetail { Titre = en ? "Size" : "Taille", Texte = Taille(q.Taille) }
            };
        }
    }

    // Décisions pures de la page Menaces de la coquille (U5a)
    public static class VueMenacesFluent
    {
        public static string ConfigIllisible()
        {
            return L.En ? "config.json unreadable: the automatic responses' settings are unknown; none is offered until it can be read."
                        : "config.json illisible : réglages des réponses automatiques inconnus ; aucun n'est proposé tant qu'il n'est pas lu.";
        }

        // 1 : liste en échec (des menaces connues ne sont pas reconnues) ; 0 : à jour ou désactivée par choix
        public static int Gravite(SourceMenace s) { string st = s.Statut ?? ""; return st == "ok" || st.StartsWith("désactivée") ? 0 : 1; }

        // Étiquette courte de la liste : un long statut écrasait le nom de la source (captures de #142) ; le statut entier est
        // dans le détail
        public static string Etiquette(SourceMenace s)
        {
            bool en = L.En;
            string st = s.Statut ?? "";
            return st == "ok" ? "ok" : st.StartsWith("désactivée") ? (en ? "disabled" : "désactivée") : (en ? "failed" : "en échec");
        }

        // Texte d'un réglage : l'état d'abord, pour qu'il reste lisible quelle que soit la largeur (captures de #142)
        public static string TexteReglage(string reglage, bool actif)
        {
            bool en = L.En;
            return (en ? (actif ? "On" : "Off") : (actif ? "Activé" : "Désactivé")) + "  ·  " + Libelle(reglage) + "  " + (en ? (actif ? "(click to turn off)" : "(click to turn on)") : (actif ? "(cliquer pour désactiver)" : "(cliquer pour activer)"));
        }

        public static string Resume(InfosMenaces m, bool lu, bool illisible)
        {
            bool en = L.En;
            if (!lu) return L.T("Lecture en cours…");
            if (m == null) return illisible ? (en ? "menaces.json unreadable: nothing is concluded." : "menaces.json illisible : rien n'est conclu.") : (en ? "Lists not loaded yet." : "Listes pas encore chargées.");
            string s = string.Format(en ? "{0:N0} IP addresses, {1:N0} networks and {2:N0} malicious domains known · reloaded on {3} · downloaded every 12 h by the service."
                                        : "{0:N0} IP, {1:N0} réseaux et {2:N0} domaines malveillants connus · rechargées le {3} · téléchargées toutes les 12 h par le service.",
                m.TotalIp, m.TotalReseaux, m.TotalDomaines, Canal.Visible(m.MisAJour));
            int ko = (m.Sources ?? new List<SourceMenace>()).Count(x => x != null && Gravite(x) == 1);
            if (ko > 0) s += "\n" + string.Format(en ? "{0} list(s) failed: the threats they contain are not recognised." : "{0} liste(s) en échec : les menaces qu'elles contiennent ne sont pas reconnues.", ko);
            if (illisible) s = (en ? "menaces.json unreadable: the last display is kept; it may be out of date.\n" : "menaces.json illisible : dernier affichage gardé, peut-être dépassé.\n") + s;
            return s;
        }

        public static string Libelle(string reglage)
        {
            switch (reglage)
            {
                case "BlocageAutoMenaces": return L.T("Bloquer automatiquement au pare-feu les IP de Spamhaus DROP et de Feodo Tracker");
                case "ReponseAutoRancongiciel": return L.T("Suspendre automatiquement un programme qui touche aux fichiers leurres (rançongiciel)");
                case "ListesRestreintes": return L.T("Utiliser aussi les listes non commerciales ou aux conditions non vérifiées (usage personnel uniquement)");
            }
            return reglage;
        }

        public static bool Valeur(Config c, string reglage)
        {
            return reglage == "BlocageAutoMenaces" ? c.BlocageAutoMenaces : reglage == "ReponseAutoRancongiciel" ? c.ReponseAutoRancongiciel : c.ListesRestreintes;
        }

        public static List<LigneDetail> Detail(SourceMenace s)
        {
            bool en = L.En;
            Func<string, string> v = x => string.IsNullOrEmpty(x) ? "—" : Canal.Visible(x);
            return new List<LigneDetail>
            {
                new LigneDetail { Titre = "Type", Texte = v(s.Type) },
                new LigneDetail { Titre = en ? "Confidence" : "Confiance", Texte = v(s.Confiance) },
                new LigneDetail { Titre = en ? "Entries" : "Entrées", Texte = s.Entrees.ToString("N0") },
                new LigneDetail { Titre = en ? "Updated" : "Mise à jour", Texte = v(s.MisAJour) },
                new LigneDetail { Titre = en ? "Licence" : "Licence", Texte = v(s.Licence) },
                new LigneDetail { Titre = en ? "Status" : "Statut", Texte = v(s.Statut) }
            };
        }
    }

    // Base des pages de protection (U5a) : un fichier lu hors du fil de l'interface, une lecture à la fois ; résumé,
    // outils, liste et panneau de détails
    abstract class PageProtectionFluent : Grid
    {
        protected readonly TextBlock resume = new TextBlock();
        protected readonly StackPanel outils = new StackPanel();
        protected readonly StackPanel liste = new StackPanel();
        protected readonly ContentControl detail = new ContentControl();
        readonly System.Windows.Threading.DispatcherTimer minuteur = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        protected bool lu;
        protected string vu;
        protected int choisie;
        int enCours, chargement;

        protected PageProtectionFluent()
        {
            Briques.Disposer(this, resume, outils, liste, detail);
            minuteur.Tick += (s, e) => Charger();
            Loaded += (s, e) => { minuteur.Start(); Charger(); };
            Unloaded += (s, e) => minuteur.Stop();
        }

        internal void Charger()
        {
            if (System.Threading.Interlocked.CompareExchange(ref enCours, 1, 0) != 0) return;
            int numero = ++chargement;
            System.Threading.ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    var r = LireFichiers();
                    Dispatcher.BeginInvoke((Action)(() => { if (numero == chargement) { lu = true; Recevoir(r); Afficher(); } }));
                }
                finally { System.Threading.Interlocked.Exchange(ref enCours, 0); }
            });
        }

        // Sur le fil de fond : lecture seule des fichiers ; sur le fil de l'interface : réception puis affichage
        protected abstract object LireFichiers();
        protected abstract void Recevoir(object lecture);
        protected abstract void Afficher();

        protected void Liste(List<LigneEtatFluent> lignes)
        {
            liste.Children.Clear();
            if (choisie >= lignes.Count) choisie = 0;
            for (int k = 0; k < lignes.Count; k++)
            {
                int n = k; var x = lignes[k];
                liste.Children.Add(Briques.Ligne(x.Titre, x.Etiquette, x.Sous, x.Gravite, n == choisie, false, () => { choisie = n; vu = null; Afficher(); }));
            }
        }

        protected StackPanel Panneau(LigneEtatFluent x, string vide)
        {
            if (x == null) { detail.Content = new TextBlock { Text = vide, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap }; return null; }
            var pile = new StackPanel();
            pile.Children.Add(new TextBlock { Text = x.Titre, FontSize = 16, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            if (!string.IsNullOrEmpty(x.Etiquette)) pile.Children.Add(new TextBlock { Text = x.Etiquette, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Briques.Couleur(x.Gravite)), Margin = new Thickness(0, 2, 0, 4), TextWrapping = TextWrapping.Wrap });
            foreach (var l in x.Detail)
            {
                pile.Children.Add(Briques.Titre(l.Titre, 10));
                var t = new TextBlock { Text = l.Texte, TextWrapping = TextWrapping.Wrap };
                if (l.Chasse) { t.FontFamily = Briques.Chasse; t.FontSize = 12; }
                pile.Children.Add(t);
            }
            detail.Content = pile;
            return pile;
        }

        protected static Button Outil(string texte, bool fort, RoutedEventHandler clic)
        {
            var b = Briques.Action(texte, fort, clic);
            b.HorizontalAlignment = HorizontalAlignment.Left; b.Margin = new Thickness(0, 0, 8, 8);
            return b;
        }
    }

    // Page Blocages en WPF (U5a) : blocages.json, mêmes commandes que la page d'aujourd'hui (ActionsProtection)
    class PageBlocagesFluent : PageProtectionFluent
    {
        List<Blocage> blocages = new List<Blocage>();
        bool illisible;

        public PageBlocagesFluent() { Afficher(); }

        protected override object LireFichiers() { bool absent; var l = LectureFluent.Lire<List<Blocage>>("blocages.json", out absent); return absent ? new List<Blocage>() : l; }

        protected override void Recevoir(object lecture)
        {
            var l = lecture as List<Blocage>;
            illisible = l == null;
            if (l != null) blocages = l.Where(b => b != null).ToList();
        }

        protected override void Afficher()
        {
            resume.Text = VueBlocagesFluent.Resume(blocages, lu, illisible);
            resume.Foreground = Jetons.Pinceau(illisible ? Jetons.Attention : Jetons.TexteSecondaire);
            var lignes = blocages.Select(b => new LigneEtatFluent { Titre = Canal.Visible(b.Cible), Etiquette = VueBlocagesFluent.Type(b), Sous = (string.IsNullOrEmpty(b.Raison) ? "" : Canal.Visible(b.Raison) + "  ·  ") + Canal.Visible(b.Date), Detail = VueBlocagesFluent.Detail(b) }).ToList();
            string signature = choisie + "#" + resume.Text + "#" + string.Join(";", blocages.Select(b => b.Type + "|" + b.Cible + "|" + b.Date));
            if (signature == vu) return;
            vu = signature;
            outils.Children.Clear();
            if (lu && blocages.Count > 0)
            {
                var barre = new WrapPanel();
                barre.Children.Add(Outil(L.T("Tout débloquer"), false, (s, e) => { if (ActionsProtection.ToutDebloquer()) Charger(); }));
                outils.Children.Add(barre);
            }
            Liste(lignes);
            var choix = lignes.Count > 0 ? blocages[Math.Min(choisie, blocages.Count - 1)] : null;
            var pile = Panneau(lignes.Count > 0 ? lignes[Math.Min(choisie, lignes.Count - 1)] : null, L.En ? "Select a block to read it and lift it." : "Sélectionnez un blocage pour le lire et le lever.");
            if (pile != null && choix != null)
            {
                pile.Children.Add(Briques.Titre(L.T("Agir"), 12));
                pile.Children.Add(Briques.Action(L.En ? "Unblock" : "Débloquer", true, (s, e) => { ActionsProtection.Debloquer(choix); Charger(); }));
            }
        }
    }

    // Page Quarantaine en WPF (U5a) : quarantaine.json, mêmes restaurations et mêmes questions que la page d'aujourd'hui
    class PageQuarantaineFluent : PageProtectionFluent
    {
        List<ElementQuarantaine> elements = new List<ElementQuarantaine>();
        bool illisible;

        public PageQuarantaineFluent() { Afficher(); }

        protected override object LireFichiers() { bool absent; var l = LectureFluent.Lire<List<ElementQuarantaine>>("quarantaine.json", out absent); return absent ? new List<ElementQuarantaine>() : l; }

        protected override void Recevoir(object lecture)
        {
            var l = lecture as List<ElementQuarantaine>;
            illisible = l == null;
            if (l != null) elements = VueQuarantaineFluent.Trier(l);
        }

        protected override void Afficher()
        {
            resume.Text = VueQuarantaineFluent.Resume(elements, lu, illisible);
            resume.Foreground = Jetons.Pinceau(illisible ? Jetons.Attention : Jetons.TexteSecondaire);
            var lignes = elements.Select(q => new LigneEtatFluent { Titre = VueQuarantaineFluent.Nom(q), Etiquette = VueQuarantaineFluent.Taille(q.Taille), Sous = Canal.Visible(q.Date) + (string.IsNullOrEmpty(q.Raison) ? "" : "  ·  " + Canal.Visible(q.Raison)), Detail = VueQuarantaineFluent.Detail(q) }).ToList();
            string signature = choisie + "#" + resume.Text + "#" + string.Join(";", elements.Select(q => q.Id));
            if (signature == vu) return;
            vu = signature;
            Liste(lignes);
            var choix = elements.Count > 0 ? elements[Math.Min(choisie, elements.Count - 1)] : null;
            var pile = Panneau(lignes.Count > 0 ? lignes[Math.Min(choisie, lignes.Count - 1)] : null, L.En ? "Select a file to read it and restore it." : "Sélectionnez un fichier pour le lire et le restaurer.");
            if (pile != null && choix != null)
            {
                pile.Children.Add(Briques.Titre(L.T("Agir"), 12));
                pile.Children.Add(Briques.Action(L.En ? "Restore to its original location" : "Restaurer à son emplacement d'origine", true, (s, e) => { if (ActionsProtection.Restaurer(choix, false)) Charger(); }));
                pile.Children.Add(Briques.Action(L.T("Restaurer dans le dossier de deR4Tizer"), false, (s, e) => { if (ActionsProtection.Restaurer(choix, true)) Charger(); }));
            }
        }
    }

    // Page Menaces en WPF (U5a) : menaces.json et config.json ; réglages des réponses automatiques par la même commande
    // que la page d'aujourd'hui, cachés quand config.json est illisible (S139-02)
    class PageMenacesFluent : PageProtectionFluent
    {
        InfosMenaces menaces;
        Config config;
        bool menacesIllisible, configIllisible;

        public PageMenacesFluent() { Afficher(); }

        protected override object LireFichiers()
        {
            bool absent, ci;
            var m = LectureFluent.Lire<InfosMenaces>("menaces.json", out absent);
            var c = ActionsProtection.LireConfig(out ci);
            return new object[] { m, !absent && m == null, c, ci };
        }

        protected override void Recevoir(object lecture)
        {
            var r = (object[])lecture;
            menacesIllisible = (bool)r[1];
            if (r[0] != null || !menacesIllisible) menaces = r[0] as InfosMenaces;
            configIllisible = (bool)r[3];
            config = r[2] as Config;
        }

        protected override void Afficher()
        {
            resume.Text = VueMenacesFluent.Resume(menaces, lu, menacesIllisible) + (lu && configIllisible ? "\n" + VueMenacesFluent.ConfigIllisible() : "");
            var sources = menaces == null ? new List<SourceMenace>() : (menaces.Sources ?? new List<SourceMenace>()).Where(x => x != null).ToList();
            resume.Foreground = Jetons.Pinceau(lu && (menacesIllisible || configIllisible || sources.Any(x => VueMenacesFluent.Gravite(x) == 1)) ? Jetons.Attention : Jetons.TexteSecondaire);
            var lignes = sources.Select(x => new LigneEtatFluent
            {
                Titre = Canal.Visible(x.Nom), Etiquette = VueMenacesFluent.Etiquette(x),
                Sous = Canal.Visible(x.Type) + "  ·  " + Canal.Visible(x.Confiance) + "  ·  " + x.Entrees.ToString("N0") + (L.En ? " entries" : " entrées") + (string.IsNullOrEmpty(x.MisAJour) ? "" : "  ·  " + Canal.Visible(x.MisAJour)),
                Gravite = VueMenacesFluent.Gravite(x), Detail = VueMenacesFluent.Detail(x)
            }).ToList();
            string reglages = config == null ? "?" : string.Join(",", ActionsProtection.Reglages.Select(g => VueMenacesFluent.Valeur(config, g)));
            string signature = choisie + "#" + resume.Text + "#" + lu + "#" + configIllisible + "#" + reglages + "#" + string.Join(";", lignes.Select(x => x.Titre + "|" + x.Etiquette + "|" + x.Sous));
            if (signature == vu) return;
            vu = signature;
            outils.Children.Clear();
            var barre = new WrapPanel();
            barre.Children.Add(Outil(L.T("Mettre à jour maintenant"), false, (s, e) => { ActionsProtection.MajMenaces(); Charger(); }));
            outils.Children.Add(barre);
            // Réglages : seulement quand leur état est lu ; illisible, le résumé le dit et rien n'est proposé
            if (lu && config != null && !configIllisible)
            {
                outils.Children.Add(Briques.Titre(L.En ? "Automatic responses" : "Réponses automatiques", 0));
                foreach (var g in ActionsProtection.Reglages)
                {
                    string nom = g;
                    bool actif = VueMenacesFluent.Valeur(config, nom);
                    var b = Outil("", actif, (s, e) => { ActionsProtection.ChangerReglage(nom, !actif); Charger(); });
                    // Texte renvoyé à la ligne : l'état n'est jamais coupé
                    b.Content = new TextBlock { Text = VueMenacesFluent.TexteReglage(nom, actif), TextWrapping = TextWrapping.Wrap };
                    b.HorizontalAlignment = HorizontalAlignment.Stretch; b.HorizontalContentAlignment = HorizontalAlignment.Stretch;
                    b.Margin = new Thickness(0, 0, 0, 6);
                    outils.Children.Add(b);
                }
                outils.Children.Add(new Border { Height = 6 });
            }
            Liste(lignes);
            Panneau(lignes.Count > 0 ? lignes[Math.Min(choisie, lignes.Count - 1)] : null, L.En ? "Select a list to read its detail." : "Sélectionnez une liste pour lire son détail.");
        }
    }
    // Décisions pures de la page Baseline de la coquille (U5b), testées par tests\rendu-pilote.ps1
    public static class VueBaselineFluent
    {
        public static readonly string[] Profils = { "journalisation", "recommandé", "renforcé" };

        public static string NomProfil(string p)
        {
            bool en = L.En;
            return p == "journalisation" ? (en ? "Logging (applied automatically)" : "Journalisation (appliquée automatiquement)")
                 : p == "recommandé" ? (en ? "Recommended" : "Recommandé") : (en ? "Hardened (may hinder some software)" : "Renforcé (peut gêner certains logiciels)");
        }

        public static int Score(EtatBaseline b, string profil) { int s = 0; if (b != null && b.Scores != null) b.Scores.TryGetValue(profil, out s); return s; }

        // 1 : règle non conforme d'un profil attendu (journalisation, recommandé) ; le renforcé reste un choix, pas un défaut
        public static int Gravite(EtatRegle r) { return r.Etat == "non conforme" && r.Profil != "renforcé" ? 1 : 0; }

        public static List<EtatRegle> Regles(EtatBaseline b, string profil)
        {
            if (b == null || b.Regles == null) return new List<EtatRegle>();
            return b.Regles.Where(x => x != null && x.Profil == profil).OrderBy(x => x.Categorie ?? "", StringComparer.CurrentCulture).ThenBy(x => x.Titre ?? "", StringComparer.CurrentCulture).ToList();
        }

        public static string Resume(EtatBaseline b, bool lu, bool illisible)
        {
            bool en = L.En;
            if (!lu) return L.T("Lecture en cours…");
            if (b == null || b.Regles == null)
                return illisible ? (en ? "baseline.json unreadable: nothing is concluded." : "baseline.json illisible : rien n'est conclu.")
                                 : (en ? "The service has not evaluated the baseline yet (every 10 minutes)." : "Le service n'a pas encore évalué la baseline (toutes les 10 minutes).");
            string s = string.Format(en ? "Recommended: {0} % compliant · logging {1} % · hardened {2} %. Applied through local group policy; every rule can be reverted."
                                        : "Recommandé : {0} % conforme · journalisation {1} % · renforcé {2} %. Appliquée par la stratégie de groupe locale ; chaque règle est réversible.",
                Score(b, "recommandé"), Score(b, "journalisation"), Score(b, "renforcé"));
            if (!string.IsNullOrEmpty(b.Message)) s += "\n" + (en ? "Last operation: " : "Dernière opération : ") + Canal.Visible(b.Message);
            if (illisible) s = (en ? "baseline.json unreadable: the last display is kept; it may be out of date.\n" : "baseline.json illisible : dernier affichage gardé, peut-être dépassé.\n") + s;
            return s;
        }

        public static List<LigneDetail> Detail(EtatRegle r)
        {
            bool en = L.En;
            Func<string, string> v = x => string.IsNullOrEmpty(x) ? "—" : Canal.Visible(x);
            var l = new List<LigneDetail>
            {
                new LigneDetail { Titre = en ? "Why" : "Pourquoi", Texte = v(r.Pourquoi) },
                new LigneDetail { Titre = en ? "Current" : "Actuel", Texte = v(r.Actuel), Chasse = true },
                new LigneDetail { Titre = en ? "Expected" : "Attendu", Texte = v(r.Attendu), Chasse = true },
                new LigneDetail { Titre = en ? "Compatibility" : "Compatibilité", Texte = v(r.Compat) }
            };
            if (r.Appliquee) l.Add(new LigneDetail { Titre = "deR4Tizer", Texte = en ? "Applied by deR4Tizer (reversible)." : "Appliquée par deR4Tizer (réversible)." });
            return l;
        }
    }

    // Décisions pures de la page Pare-feu de la coquille (U5b). Noms de règles, programmes visés et auteurs sont choisis par
    // le programme qui crée la règle ; adresses et programmes des paquets entrants viennent du réseau : neutralisés
    public static class VueParefeuFluent
    {
        public const int Maximum = 200;

        public static string Fichier(string chemin)
        {
            string c = chemin ?? "";
            int k = Math.Max(c.LastIndexOf('\\'), c.LastIndexOf('/'));
            return k >= 0 && k < c.Length - 1 ? c.Substring(k + 1) : c;
        }

        public static string Description(EvenementRegle r)
        {
            return Canal.Visible(r.Sens) + ", " + Canal.Visible(r.Action) + (string.IsNullOrEmpty(r.Ports) ? "" : ", ports " + Canal.Visible(r.Ports))
                + (string.IsNullOrEmpty(r.ProgrammeCible) ? "" : (L.En ? ", for " : ", pour ") + Canal.Visible(r.ProgrammeCible));
        }

        // 2 : toutes les règles supprimées ; 1 : entrée autorisée ajoutée ou modifiée ; 0 : le reste
        public static int Gravite(EvenementRegle r)
        {
            if (r.Operation == "toutes supprimées") return 2;
            return r.Sens == "entrant" && (r.Action ?? "").StartsWith("autoriser") && r.Operation != "supprimée" ? 1 : 0;
        }

        public static int Gravite(EntreeExposee e) { return e.Action == "ACCEPTÉ" ? 2 : 1; }

        public static string Resume(Exposition x, bool etatLu, bool etatIllisible, int changements)
        {
            bool en = L.En;
            if (!etatLu) return L.T("Lecture en cours…");
            string s;
            if (x == null)
                s = etatIllisible ? (en ? "Service state unreadable (etat.json): exposure unknown, nothing is concluded." : "État du service illisible (etat.json) : exposition inconnue, rien n'est conclu.")
                                  : (en ? "Exposure not published by the service yet." : "Exposition pas encore publiée par le service.");
            else if (x.Exposee)
                s = (en ? "COMPUTER EXPOSED TO THE INTERNET: " : "PC EXPOSÉ À INTERNET : ") + string.Join(" ; ", (x.Raisons ?? new List<string>()).Select(Canal.Visible));
            else
                s = Constat(x);
            if (x != null && x.Exposee && !x.JournalPaquets) s += "\n" + (en ? "Firewall packet log off: incoming packets are not seen." : "Journal des paquets du pare-feu inactif : les paquets entrants ne sont pas vus.");
            // Ce sur quoi repose le verdict, tel que le service le publie (Base, neutralisée)
            if (x != null && !string.IsNullOrEmpty(x.Base)) s += "\n" + (en ? "Based on: " : "Repose sur : ") + Canal.Visible(x.Base);
            return s + "\n" + string.Format(en ? "{0} firewall rule change(s) recorded." : "{0} changement(s) de règle du pare-feu enregistré(s).", changements);
        }

        // UPnP vérifié seulement si le service a publié le résultat d'une vérification (« N redirection(s) sur la box, dont M
        // vers ce PC ») ; « pas encore vérifiées » ou un message d'erreur : non vérifié (dossier U5c, constat C1)
        public static bool UpnpVerifie(string base_)
        {
            return base_ != null && System.Text.RegularExpressions.Regex.IsMatch(base_, @"\(UPnP\) : \d+ redirection\(s\) sur la box");
        }

        // Contrôles complets : journal des paquets actif et UPnP vérifié. Sinon, rien n'est relevé mais tout n'a pas été vu
        public static bool Complet(Exposition x) { return x != null && x.JournalPaquets && UpnpVerifie(x.Base); }

        // Constat quand le service ne dit pas « exposé » : chaque contrôle est dit vu ou non vérifié ; jamais « aucune
        // exposition » si un contrôle manque, jamais « protégé » (dossier U5c, constat C1)
        public static string Constat(Exposition x)
        {
            bool en = L.En;
            var vus = new List<string>();
            var nonVus = new List<string>();
            if (x.JournalPaquets) vus.Add(en ? "no packet from the Internet in the last 24 h" : "aucun paquet venu d'Internet ces dernières 24 h");
            else nonVus.Add(en ? "packets from the Internet (firewall packet log off)" : "paquets venus d'Internet (journal des paquets du pare-feu inactif)");
            vus.Add(en ? "no public address on this computer" : "aucune adresse publique sur ce PC");
            if (UpnpVerifie(x.Base)) vus.Add(en ? "no UPnP redirection from the router to this computer" : "aucune redirection UPnP de la box vers ce PC");
            else nonVus.Add(en ? "UPnP redirections of the router (not checked)" : "redirections UPnP de la box (non vérifiées)");
            string s = nonVus.Count == 0
                ? (en ? "Nothing found by the available checks: " : "Rien relevé par les contrôles disponibles : ") + string.Join(", ", vus) + "."
                : (en ? "Nothing found, checks incomplete: " : "Rien relevé, contrôles incomplets : ") + string.Join(", ", vus) + ". "
                  + (en ? "Not checked: " : "Non vérifié : ") + string.Join(" ; ", nonVus) + ".";
            return s + " " + (en ? "A router in DMZ or a manual redirection is not visible from this computer." : "Une box en DMZ ou une redirection manuelle ne se voit pas depuis le PC.");
        }

        public static LigneEtatFluent Ligne(EntreeExposee e)
        {
            bool en = L.En;
            return new LigneEtatFluent
            {
                Titre = (en ? "Incoming " : "Entrant ") + Canal.Visible(e.Action) + (en ? ": port " : " : port ") + e.PortLocal + " (" + Canal.Visible(e.Protocole) + ")",
                Etiquette = e.Nombre + (en ? " packet(s)" : " paquet(s)"), Sous = (en ? "from " : "depuis ") + Canal.Visible(e.Source) + (string.IsNullOrEmpty(e.Programme) ? "" : "  ·  " + Canal.Visible(e.Programme)),
                Gravite = Gravite(e),
                Detail = new List<LigneDetail>
                {
                    new LigneDetail { Titre = en ? "Source" : "Source", Texte = Canal.Visible(e.Source), Chasse = true },
                    new LigneDetail { Titre = en ? "Program" : "Programme", Texte = string.IsNullOrEmpty(e.Programme) ? "—" : Canal.Visible(e.Programme), Chasse = true },
                    new LigneDetail { Titre = en ? "First" : "Premier", Texte = Canal.Visible(e.Premiere) },
                    new LigneDetail { Titre = en ? "Last" : "Dernier", Texte = Canal.Visible(e.Derniere) }
                }
            };
        }

        public static LigneEtatFluent Ligne(EvenementRegle r)
        {
            bool en = L.En;
            return new LigneEtatFluent
            {
                Titre = Canal.Visible(r.Regle), Etiquette = Canal.Visible(r.Operation), Sous = Description(r) + "  ·  " + Canal.Visible(r.Heure), Gravite = Gravite(r),
                Detail = new List<LigneDetail>
                {
                    new LigneDetail { Titre = en ? "Rule" : "Règle", Texte = Canal.Visible(r.Regle) },
                    new LigneDetail { Titre = en ? "Change" : "Changement", Texte = Description(r) },
                    new LigneDetail { Titre = en ? "Made by" : "Fait par", Texte = string.IsNullOrEmpty(r.Auteur) ? "—" : Canal.Visible(r.Auteur), Chasse = true },
                    new LigneDetail { Titre = en ? "Time" : "Heure", Texte = Canal.Visible(r.Heure) }
                }
            };
        }
    }

    // Page Baseline en WPF (U5b) : baseline.json ; mêmes opérations et mêmes questions que la page d'aujourd'hui
    class PageBaselineFluent : PageProtectionFluent
    {
        EtatBaseline b;
        bool illisible;
        int profil = 1;         // recommandé par défaut

        public PageBaselineFluent() { Afficher(); }

        protected override object LireFichiers() { bool absent; var x = LectureFluent.Lire<EtatBaseline>("baseline.json", out absent); return new object[] { x, !absent && x == null }; }

        protected override void Recevoir(object lecture)
        {
            var r = (object[])lecture;
            illisible = (bool)r[1];
            if (r[0] != null || !illisible) b = r[0] as EtatBaseline;
        }

        protected override void Afficher()
        {
            resume.Text = VueBaselineFluent.Resume(b, lu, illisible);
            int rec = VueBaselineFluent.Score(b, "recommandé");
            resume.Foreground = Jetons.Pinceau(lu && (illisible || b == null) ? Jetons.Attention : b != null && b.Regles != null && rec < 50 ? Jetons.Danger : b != null && b.Regles != null && rec < 90 ? Jetons.Attention : Jetons.TexteSecondaire);
            string nomProfil = VueBaselineFluent.Profils[profil];
            var regles = VueBaselineFluent.Regles(b, nomProfil);
            var lignes = regles.Select(x => new LigneEtatFluent
            {
                Titre = Canal.Visible((x.Categorie ?? "") + " : " + (x.Titre ?? "")), Etiquette = Canal.Visible(x.Etat) + (x.Appliquee ? " ✓" : ""),
                Sous = Canal.Visible(x.Actuel) + "  →  " + Canal.Visible(x.Attendu), Gravite = VueBaselineFluent.Gravite(x), Detail = VueBaselineFluent.Detail(x)
            }).ToList();
            string signature = profil + "#" + choisie + "#" + resume.Text + "#" + string.Join(";", regles.Select(x => x.Id + "|" + x.Etat + "|" + x.Appliquee + "|" + x.Actuel));
            if (signature == vu) return;
            vu = signature;
            outils.Children.Clear();
            var profils = new WrapPanel { Margin = new Thickness(0, 0, 0, 8) };
            for (int k = 0; k < VueBaselineFluent.Profils.Length; k++)
            {
                int n = k; bool actif = n == profil;
                var bt = new Button
                {
                    Content = VueBaselineFluent.NomProfil(VueBaselineFluent.Profils[k]) + (b != null && b.Regles != null ? "  " + VueBaselineFluent.Score(b, VueBaselineFluent.Profils[k]) + " %" : ""),
                    Padding = new Thickness(12, 4, 12, 4), Margin = new Thickness(0, 0, 8, 0), Cursor = Cursors.Hand,
                    Background = Jetons.Pinceau(actif ? Jetons.Surface : Jetons.Fond), BorderBrush = Jetons.Pinceau(actif ? Jetons.Accent : Jetons.Separateur), BorderThickness = new Thickness(1), Foreground = Jetons.Pinceau(Jetons.Texte)
                };
                bt.Template = Coquille.ModeleBouton();
                bt.Click += (s, e) => { profil = n; choisie = 0; Afficher(); };
                profils.Children.Add(bt);
            }
            outils.Children.Add(profils);
            var barre = new WrapPanel();
            barre.Children.Add(Outil(L.T("Appliquer le profil recommandé"), true, (s, e) => { if (ActionsProtection.Baseline("appliquer", "recommandé", ActionsProtection.QuestionRecommande)) Charger(); }));
            barre.Children.Add(Outil(L.T("Appliquer le profil renforcé…"), false, (s, e) => { if (ActionsProtection.Baseline("appliquer", "renforcé", ActionsProtection.QuestionRenforce)) Charger(); }));
            barre.Children.Add(Outil(L.T("Tout annuler"), false, (s, e) => { if (ActionsProtection.Baseline("annuler", "recommandé,renforcé", ActionsProtection.QuestionToutAnnuler)) Charger(); }));
            barre.Children.Add(Outil(L.T("Réévaluer"), false, (s, e) => { if (ActionsProtection.Baseline("evaluer", "", null)) Charger(); }));
            outils.Children.Add(barre);
            Liste(lignes);
            var choix = regles.Count > 0 ? regles[Math.Min(choisie, regles.Count - 1)] : null;
            var pile = Panneau(lignes.Count > 0 ? lignes[Math.Min(choisie, lignes.Count - 1)] : null, L.En ? "Select a rule to read why it matters." : "Sélectionnez une règle pour lire pourquoi elle compte.");
            if (pile != null && choix != null && !string.IsNullOrEmpty(choix.Id))
            {
                pile.Children.Add(Briques.Titre(L.T("Agir"), 12));
                string id = choix.Id;
                if (choix.Etat != "conforme") pile.Children.Add(Briques.Action(L.En ? "Apply this rule" : "Appliquer cette règle", true, (s, e) => { if (ActionsProtection.Baseline("appliquer", id, null)) Charger(); }));
                if (choix.Appliquee) pile.Children.Add(Briques.Action(L.En ? "Revert this rule" : "Annuler cette règle", false, (s, e) => { if (ActionsProtection.Baseline("annuler", id, ActionsProtection.QuestionAnnulerRegles)) Charger(); }));
            }
        }
    }

    // Page Pare-feu en WPF (U5b) : exposition (etat.json) et changements de règles (parefeu.json), lecture seule
    class PageParefeuFluent : PageProtectionFluent
    {
        Exposition exposition;
        List<EvenementRegle> regles = new List<EvenementRegle>();
        bool etatIllisible, reglesIllisible;
        int vue;
        static readonly string[] Vues = { "Exposition à Internet", "Changements de règles" };

        public PageParefeuFluent() { Afficher(); }

        protected override object LireFichiers()
        {
            bool absentEtat, absentRegles;
            var e = LectureFluent.Lire<Etat>("etat.json", out absentEtat);
            var r = LectureFluent.Lire<List<EvenementRegle>>("parefeu.json", out absentRegles);
            return new object[] { e, !absentEtat && e == null, absentRegles ? new List<EvenementRegle>() : r, !absentRegles && r == null };
        }

        protected override void Recevoir(object lecture)
        {
            var x = (object[])lecture;
            etatIllisible = (bool)x[1];
            var e = x[0] as Etat;
            if (e != null) exposition = e.Exposition;
            reglesIllisible = (bool)x[3];
            var r = x[2] as List<EvenementRegle>;
            if (r != null) regles = r.Where(y => y != null).ToList();
        }

        protected override void Afficher()
        {
            bool en = L.En;
            resume.Text = VueParefeuFluent.Resume(exposition, lu, etatIllisible && exposition == null, regles.Count)
                + (lu && reglesIllisible ? "\n" + (en ? "parefeu.json unreadable: the last list is kept; it may be out of date." : "parefeu.json illisible : dernière liste gardée, peut-être dépassée.") : "");
            resume.Foreground = Jetons.Pinceau(exposition != null && exposition.Exposee ? Jetons.Danger : lu && (etatIllisible || reglesIllisible || (exposition != null && !VueParefeuFluent.Complet(exposition))) ? Jetons.Attention : Jetons.TexteSecondaire);
            var lignes = vue == 0
                ? (exposition == null ? new List<LigneEtatFluent>() : (exposition.Entrees ?? new List<EntreeExposee>()).Where(y => y != null).Select(VueParefeuFluent.Ligne).ToList())
                : Enumerable.Reverse(regles).Take(VueParefeuFluent.Maximum).Select(VueParefeuFluent.Ligne).ToList();
            string signature = vue + "#" + choisie + "#" + resume.Text + "#" + string.Join(";", lignes.Select(y => y.Titre + "|" + y.Etiquette + "|" + y.Sous));
            if (signature == vu) return;
            vu = signature;
            outils.Children.Clear();
            var vues = new WrapPanel { Margin = new Thickness(0, 0, 0, 12) };
            for (int k = 0; k < Vues.Length; k++)
            {
                int n = k; bool actif = n == vue;
                var bt = new Button
                {
                    Content = L.T(Vues[k]), Padding = new Thickness(12, 4, 12, 4), Margin = new Thickness(0, 0, 8, 0), Cursor = Cursors.Hand,
                    Background = Jetons.Pinceau(actif ? Jetons.Surface : Jetons.Fond), BorderBrush = Jetons.Pinceau(actif ? Jetons.Accent : Jetons.Separateur), BorderThickness = new Thickness(1), Foreground = Jetons.Pinceau(Jetons.Texte)
                };
                bt.Template = Coquille.ModeleBouton();
                bt.Click += (s, e) => { vue = n; choisie = 0; Afficher(); };
                vues.Children.Add(bt);
            }
            outils.Children.Add(vues);
            Liste(lignes);
            if (lu && lignes.Count == 0)
                liste.Children.Add(new TextBlock { Text = vue == 0 ? (en ? "No incoming packet from the Internet recorded." : "Aucun paquet entrant venu d'Internet enregistré.") : (en ? "No rule change since this version was installed." : "Aucun changement de règle depuis l'installation de cette version."), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap });
            var x0 = lignes.Count > 0 ? lignes[Math.Min(choisie, lignes.Count - 1)] : null;
            var pile = Panneau(x0, en ? "Select a line to read its detail." : "Sélectionnez une ligne pour lire son détail.");
            if (pile != null)
            {
                pile.Children.Add(Briques.Titre(L.T("Agir"), 12));
                string copie = VueReseauFluent.Copie(new[] { x0.Titre, x0.Etiquette }.Concat(x0.Detail.Select(d => d.Texte)).ToArray());
                pile.Children.Add(Briques.Action(L.T("Copier"), false, (s, e) => VueReseauFluent.Copier(copie)));
            }
        }
    }
}
