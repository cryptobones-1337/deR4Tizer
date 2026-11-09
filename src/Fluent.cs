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
        public static void Disposer(Grid g, TextBlock resume, StackPanel liste, ContentControl detail)
        {
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition());
            g.ColumnDefinitions.Add(new ColumnDefinition());
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(380) });
            resume.TextWrapping = TextWrapping.Wrap; resume.FontSize = 12; resume.Margin = new Thickness(0, 0, 0, 12);
            Grid.SetColumnSpan(resume, 2); g.Children.Add(resume);
            var defile = new ScrollViewer { Content = liste, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(0, 0, 16, 0) };
            Grid.SetRow(defile, 1); g.Children.Add(defile);
            var panneau = new Border { Background = Jetons.Pinceau(Jetons.Carte), CornerRadius = new CornerRadius(8), Padding = new Thickness(20) };
            panneau.Child = new ScrollViewer { Content = detail, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            Grid.SetRow(panneau, 1); Grid.SetColumn(panneau, 1); g.Children.Add(panneau);
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
            // Liste vide : le résumé dit pourquoi (collectes en panne, suivi illisible) ; avant la première lecture, rien n'est conclu
            if (incidents.Count == 0) liste.Children.Add(new TextBlock { Text = lu ? resume.Text : L.T("Lecture en cours…"), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap });
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
            if (lignes.Count == 0) liste.Children.Add(new TextBlock { Text = !lu ? L.T("Lecture en cours…") : en ? "No ongoing response." : "Aucune réponse en cours.", Foreground = Jetons.Pinceau(Jetons.TexteSecondaire) });
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
}
