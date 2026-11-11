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
        readonly ContentControl zone = new ContentControl();
        readonly TextBlock titrePage = new TextBlock();
        readonly List<Button> boutons = new List<Button>();

        // Toutes les pages sont natives (U6c) : plus de pages WinForms prêtées par la fenêtre d'aujourd'hui (relecture de #147)
        public Coquille() : this(null) { }

        public Coquille(ISourceEtat source)
        {
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
            bool connue = demandee != null && (demandee == VueAssistantFluent.Cle || NavigationFluent.Groupes().SelectMany(x => x.Entrees).Any(x => x.Cle == demandee));
            // Premiers réglages (U7a) : proposés au premier lancement, jamais en administrateur, sans source, avec --page ou caché
            bool proposer = VueAssistantFluent.DoitProposer(VueAssistantFluent.RepereExiste(VueAssistantFluent.CheminRepere()), Canal.EstAdmin(), source != null, demandee != null,
                Environment.GetCommandLineArgs().Contains("--cache"));
            Ouvrir(connue ? demandee : proposer ? VueAssistantFluent.Cle : NavigationFluent.VueEnsemble);
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
            // Démarrage auto, Extensions et Vie privée en WPF (U6a)
            if (cle == "Démarrage auto") { zone.Content = new PageDemarrageFluent(source as ISourceReponses); return; }
            if (cle == "Extensions") { zone.Content = new PageExtensionsFluent(); return; }
            if (cle == "Vie privée") { zone.Content = new PageVieFluent(source as ISourceReponses); return; }
            // Réseau local en WPF (U6b), lecture seule
            if (cle == "Réseau local") { zone.Content = new PageReseauLocalFluent(); return; }
            // Réglages en WPF (U6c) : la dernière page hébergée ; plus aucune page WinForms dans la coquille
            if (cle == "Réglages") { var pr = new PageReglagesFluent(); pr.Revoir = () => Ouvrir(VueAssistantFluent.Cle); zone.Content = pr; return; }
            // Premiers réglages (U7a), hors de la navigation : lecture seule, renvois vers les pages
            if (cle == VueAssistantFluent.Cle) { zone.Content = new PageAssistantFluent(source, Ouvrir, VueAssistantFluent.CheminRepere()); return; }
            zone.Content = new TextBlock { Text = L.T("Page introuvable."), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire) };
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

            if (source != null && !Canal.EstAdmin() && !VueAssistantFluent.RepereExiste(VueAssistantFluent.CheminRepere()))
            {
                bool en = L.En;
                var carte = new Border { Background = Jetons.Pinceau(Jetons.Carte), CornerRadius = new CornerRadius(8), Padding = new Thickness(20, 16, 20, 16), Margin = new Thickness(0, 0, 0, 12) };
                var c = new StackPanel();
                c.Children.Add(new TextBlock { Text = en ? "First-run setup: not seen yet" : "Premiers réglages : pas encore vus", FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 6) });
                c.Children.Add(new TextBlock { Text = en ? "Six steps that show what deR4Tizer sees and the settings that matter; nothing changes without you." : "Six étapes qui montrent ce que deR4Tizer voit et les réglages qui comptent ; rien ne change sans vous.", TextWrapping = TextWrapping.Wrap, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, 0, 0, 8) });
                var ouvre = Briques.Action(en ? "Open the first-run setup" : "Ouvrir les premiers réglages", true, (s, a) => Ouvrir(VueAssistantFluent.Cle));
                ouvre.HorizontalAlignment = HorizontalAlignment.Left;
                c.Children.Add(ouvre);
                carte.Child = c;
                pile.Children.Add(carte);
            }

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
        public string Chemin;   // programme de la ligne, pour « Ouvrir l'emplacement » (U6a) ; jamais affiché tel quel
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
            else if (Verdict(x) != "")
                // Verdict du diagnostic du service (U5c-2)
                s = TitreVerdict(x) + " : " + DetailVerdict(x);
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

        // Contrôles complets : avec le diagnostic du service (U5c-1), « rien relevé » ou un verdict établi ; avec un service
        // plus ancien, journal des paquets actif et UPnP vérifié
        public static bool Complet(Exposition x)
        {
            if (x == null) return false;
            string v = Verdict(x);
            if (v != "") return v != "rien_releve_incomplet";
            return x.JournalPaquets && UpnpVerifie(x.Base);
        }

        static readonly string[] Verdicts = { "expose", "a_surveiller", "rien_releve", "rien_releve_incomplet" };

        // Verdict du diagnostic du service ; vide avec un service plus ancien, et pour toute valeur inconnue (service plus
        // récent, état abîmé) : alors l'ancien constat de U5c-0, jamais la phrase la plus rassurante (audit de #149, S149-01)
        public static string Verdict(Exposition x)
        {
            string v = x == null || x.Diagnostic == null ? null : x.Diagnostic.Verdict;
            return v != null && Array.IndexOf(Verdicts, v) >= 0 ? v : "";
        }

        public static bool ASurveiller(Exposition x) { return Verdict(x) == "a_surveiller"; }

        static IEnumerable<ConstatExposition> Constats(Exposition x, string etat)
        {
            return (x.Diagnostic == null || x.Diagnostic.Constats == null ? new List<ConstatExposition>() : x.Diagnostic.Constats).Where(c => c != null && c.Etat == etat);
        }

        // Titre du bilan selon le verdict (U5c-2)
        public static string TitreVerdict(Exposition x)
        {
            switch (Verdict(x))
            {
                case "expose": return L.T("PC EXPOSÉ À INTERNET");
                case "a_surveiller": return L.T("EXPOSITION À SURVEILLER");
                case "rien_releve": return L.T("Rien relevé par les contrôles disponibles");
                case "rien_releve_incomplet": return L.T("Rien relevé, contrôles incomplets");
            }
            return x != null && x.Exposee ? L.T("PC EXPOSÉ À INTERNET") : Complet(x) ? L.T("Rien relevé par les contrôles disponibles") : L.T("Rien relevé, contrôles incomplets");
        }

        // Détail du bilan selon le verdict : ce qui a été constaté, ou ce qui n'a pas pu être vérifié ; jamais « protégé »
        public static string DetailVerdict(Exposition x)
        {
            bool en = L.En;
            string v = Verdict(x);
            if (v == "") return x.Exposee ? string.Join(" ; ", (x.Raisons ?? new List<string>()).Select(Canal.Visible)) : Constat(x);
            string limite = en ? "A router in DMZ or a manual redirection is not visible from this computer." : "Une box en DMZ ou une redirection manuelle ne se voit pas depuis le PC.";
            string vus = string.Join(" ; ", Constats(x, "constate").Select(c => Canal.Visible(c.Texte)));
            string nonVus = string.Join(" ; ", Constats(x, "non_verifie").Select(c => Canal.Visible(c.Texte)));
            if (v == "expose" || v == "a_surveiller") return vus + (nonVus == "" ? "" : "\n" + (en ? "Not checked: " : "Non vérifié : ") + nonVus);
            if (v == "rien_releve_incomplet") return (en ? "Not checked: " : "Non vérifié : ") + nonVus + ". " + limite;
            return (en ? "Every available check ran and found nothing. " : "Tous les contrôles disponibles ont été faits, sans rien relever. ") + limite;
        }

        public static string NomPiste(string piste)
        {
            bool en = L.En;
            switch (piste)
            {
                case "adresse_ipv4": return en ? "Public IPv4 address" : "Adresse IPv4 publique";
                case "adresse_ipv6": return en ? "Global IPv6 address" : "Adresse IPv6 globale";
                case "paquets_acceptes": return en ? "Incoming connections accepted" : "Connexions entrantes acceptées";
                case "paquets_bloques": return en ? "Incoming sources blocked" : "Sources entrantes bloquées";
                case "upnp": return en ? "Router UPnP redirections" : "Redirections UPnP de la box";
                case "parefeu": return en ? "Windows Firewall" : "Pare-feu de Windows";
            }
            return Canal.Visible(piste);
        }

        // Que faire, phrase fixe par piste ; jamais un bouton qui modifie le pare-feu ou la box
        public static string QueFaire(ConstatExposition c)
        {
            bool en = L.En;
            if (c.Etat == "non_verifie") return en ? "This check could not run: nothing is concluded." : "Ce contrôle n'a pas pu être fait : rien n'est conclu.";
            if (c.Etat != "constate") return en ? "Nothing to do for this check." : "Rien à faire pour ce contrôle.";
            switch (c.Piste)
            {
                case "adresse_ipv4": return en ? "Check the router: this computer should not get a public address directly (bridge mode, DMZ)." : "Vérifiez la box : le PC ne doit pas recevoir directement une adresse publique (mode pont, DMZ).";
                case "adresse_ipv6": return en ? "Check that the router's IPv6 firewall blocks incoming connections." : "Vérifiez que le pare-feu IPv6 de la box bloque les connexions entrantes.";
                case "paquets_acceptes": return en ? "Open the « Internet exposure » view: which port, which program; close the rule or redirection that allows it." : "Ouvrez la vue « Exposition à Internet » : quel port, quel programme ; fermez la règle ou la redirection qui le permet.";
                case "paquets_bloques": return en ? "The computer's firewall blocked them; check that no router redirection points to this computer." : "Le pare-feu du PC les a bloquées ; vérifiez qu'aucune redirection de la box ne pointe vers ce PC.";
                case "upnp": return en ? "Turn UPnP off on the router, or remove the redirection if nobody wanted it." : "Désactivez UPnP sur la box, ou supprimez la redirection si personne ne l'a voulue.";
                case "parefeu": return en ? "Turn the Windows Firewall back on and block incoming connections by default on this profile." : "Réactivez le pare-feu de Windows et bloquez les connexions entrantes par défaut sur ce profil.";
            }
            return "";
        }

        // 2 : exposition prouvée ; 1 : à surveiller ou non vérifié ; 0 : rien constaté
        public static int Gravite(ConstatExposition c)
        {
            if (c.Etat == "non_verifie") return 1;
            if (c.Etat != "constate") return 0;
            return c.Piste == "adresse_ipv4" || c.Piste == "paquets_acceptes" || c.Piste == "upnp" ? 2 : 1;
        }

        public static string Etat(ConstatExposition c)
        {
            bool en = L.En;
            return c.Etat == "constate" ? (en ? "found" : "constaté") : c.Etat == "non_verifie" ? (en ? "not checked" : "non vérifié") : (en ? "not found" : "pas constaté");
        }

        public static List<LigneEtatFluent> LignesPourquoi(Exposition x)
        {
            bool en = L.En;
            var l = new List<LigneEtatFluent>();
            if (x == null || x.Diagnostic == null || x.Diagnostic.Constats == null) return l;
            foreach (var c in x.Diagnostic.Constats.Where(y => y != null))
                l.Add(new LigneEtatFluent
                {
                    Titre = NomPiste(c.Piste), Etiquette = Etat(c), Sous = Canal.Visible(c.Texte), Gravite = Gravite(c),
                    Detail = new List<LigneDetail> { new LigneDetail { Titre = en ? "Finding" : "Constat", Texte = Canal.Visible(c.Texte) }, new LigneDetail { Titre = en ? "What to do" : "Que faire", Texte = QueFaire(c) } }
                });
            return l;
        }

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
        static readonly string[] Vues = { "Pourquoi", "Exposition à Internet", "Changements de règles" };

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
            resume.Foreground = Jetons.Pinceau(exposition != null && exposition.Exposee ? Jetons.Danger : lu && (etatIllisible || reglesIllisible || VueParefeuFluent.ASurveiller(exposition) || (exposition != null && !VueParefeuFluent.Complet(exposition))) ? Jetons.Attention : Jetons.TexteSecondaire);
            var lignes = vue == 0 ? VueParefeuFluent.LignesPourquoi(exposition)
                : vue == 1 ? (exposition == null ? new List<LigneEtatFluent>() : (exposition.Entrees ?? new List<EntreeExposee>()).Where(y => y != null).Select(VueParefeuFluent.Ligne).ToList())
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
                liste.Children.Add(new TextBlock { Text = vue == 0 ? (en ? "Diagnostic not published by the service yet: nothing is concluded." : "Diagnostic pas encore publié par le service : rien n'est conclu.") : vue == 1 ? (en ? "No incoming packet from the Internet recorded." : "Aucun paquet entrant venu d'Internet enregistré.") : (en ? "No rule change since this version was installed." : "Aucun changement de règle depuis l'installation de cette version."), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap });
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
    // Décisions pures de la page Démarrage auto de la coquille (U6a). Nom, commande et cible sont choisis par le programme
    // qui s'inscrit au démarrage : neutralisés
    public static class VueDemarrageFluent
    {
        public static bool Microsoft(EntreeDemarrage e) { return e.Signataire == "Windows (catalogue)" || (e.Signataire ?? "").StartsWith("Microsoft"); }

        // Même filtre que la case d'aujourd'hui : une entrée Microsoft ou Windows reste visible si elle porte une remarque
        public static List<EntreeDemarrage> Filtrer(IList<EntreeDemarrage> l, bool masquerWindows)
        {
            return (l ?? new List<EntreeDemarrage>()).Where(e => e != null && (!masquerWindows || !string.IsNullOrEmpty(e.Remarque) || !Microsoft(e)))
                .OrderByDescending(e => !string.IsNullOrEmpty(e.Remarque)).ThenBy(e => e.Categorie ?? "", StringComparer.CurrentCulture).ThenBy(e => e.Nom ?? "", StringComparer.CurrentCulture).ToList();
        }

        public static int Gravite(EntreeDemarrage e) { return string.IsNullOrEmpty(e.Remarque) ? 0 : 1; }

        public static string Signataire(EntreeDemarrage e) { return string.IsNullOrEmpty(e.Signataire) ? (L.En ? "unsigned" : "non signé") : Canal.Visible(e.Signataire); }

        public static string Resume(IList<EntreeDemarrage> toutes, int affichees, bool lu, bool illisible)
        {
            bool en = L.En;
            if (!lu) return L.T("Lecture en cours…");
            bool garde = toutes != null && toutes.Count > 0;
            if (illisible && !garde) return en ? "demarrage.json unreadable: nothing is concluded." : "demarrage.json illisible : rien n'est conclu.";
            var l = toutes ?? new List<EntreeDemarrage>();
            string s = l.Count == 0 ? (en ? "No autostart entry recorded yet." : "Aucune entrée de démarrage enregistrée pour l'instant.")
                : string.Format(en ? "{0} autostart entr(ies), {1} new or changed (alert raised), {2} shown." : "{0} entrée(s) de démarrage, dont {1} nouvelle(s) ou modifiée(s) (alerte levée) ; {2} affichée(s).", l.Count, l.Count(x => x != null && !string.IsNullOrEmpty(x.Remarque)), affichees);
            if (illisible) s = (en ? "demarrage.json unreadable: the last display is kept; it may be out of date.\n" : "demarrage.json illisible : dernier affichage gardé, peut-être dépassé.\n") + s;
            return s;
        }

        public static List<LigneDetail> Detail(EntreeDemarrage e)
        {
            bool en = L.En;
            Func<string, string> v = x => string.IsNullOrEmpty(x) ? "—" : Canal.Visible(x);
            return new List<LigneDetail>
            {
                new LigneDetail { Titre = en ? "Category" : "Catégorie", Texte = v(e.Categorie) },
                new LigneDetail { Titre = en ? "Command" : "Commande", Texte = v(e.Commande), Chasse = true },
                new LigneDetail { Titre = en ? "Target" : "Cible", Texte = v(e.Cible), Chasse = true },
                new LigneDetail { Titre = en ? "Signer" : "Signataire", Texte = Signataire(e) },
                new LigneDetail { Titre = en ? "Note" : "Remarque", Texte = v(e.Remarque) },
                new LigneDetail { Titre = en ? "Seen since" : "Vu depuis", Texte = v(e.Depuis) }
            };
        }

        public static string Copie(EntreeDemarrage e) { return VueReseauFluent.Copie(e.Categorie, e.Nom, e.Commande, string.IsNullOrEmpty(e.Signataire) ? "NON SIGNÉ" : e.Signataire, e.Remarque, e.Depuis); }
    }

    // Décisions pures de la page Extensions de la coquille (U6a) : nom, version et permissions écrits par l'auteur de
    // l'extension, neutralisés
    public static class VueExtensionsFluent
    {
        public static string Resume(IList<Extension> l, bool lu, bool illisible)
        {
            bool en = L.En;
            if (!lu) return L.T("Lecture en cours…");
            bool garde = l != null && l.Count > 0;
            if (illisible && !garde) return en ? "extensions.json unreadable: nothing is concluded." : "extensions.json illisible : rien n'est conclu.";
            var x = l ?? new List<Extension>();
            string s = x.Count == 0 ? (en ? "No browser extension recorded yet." : "Aucune extension de navigateur enregistrée pour l'instant.")
                : string.Format(en ? "{0} extension(s), {1} with sensitive permissions (pages, cookies or typing). A new extension raises an alert." : "{0} extension(s), dont {1} avec des permissions sensibles (pages, cookies ou saisies). Une nouvelle extension déclenche une alerte.", x.Count, x.Count(e => e != null && e.Dangereuse));
            if (illisible) s = (en ? "extensions.json unreadable: the last display is kept; it may be out of date.\n" : "extensions.json illisible : dernier affichage gardé, peut-être dépassé.\n") + s;
            return s;
        }

        public static List<Extension> Trier(IList<Extension> l)
        {
            return (l ?? new List<Extension>()).Where(e => e != null).OrderByDescending(e => e.Dangereuse).ThenBy(e => e.Navigateur ?? "", StringComparer.CurrentCulture).ThenBy(e => e.Nom ?? "", StringComparer.CurrentCulture).ToList();
        }

        public static List<LigneDetail> Detail(Extension e)
        {
            bool en = L.En;
            Func<string, string> v = x => string.IsNullOrEmpty(x) ? "—" : Canal.Visible(x);
            return new List<LigneDetail>
            {
                new LigneDetail { Titre = en ? "Browser" : "Navigateur", Texte = v(e.Navigateur) },
                new LigneDetail { Titre = "Id", Texte = v(e.Id), Chasse = true },
                new LigneDetail { Titre = "Version", Texte = v(e.Version) },
                new LigneDetail { Titre = "Permissions", Texte = v(e.Permissions) },
                new LigneDetail { Titre = en ? "Seen since" : "Vue depuis", Texte = v(e.Depuis) }
            };
        }

        public static string Copie(Extension e) { return VueReseauFluent.Copie(e.Navigateur, e.Nom, e.Version, e.Permissions, e.Depuis, e.Id); }
    }

    // Décisions pures de la page Vie privée de la coquille (U6a) : caméra et micro, prise en main à distance, ports ouverts
    public static class VueVieFluent
    {
        public static readonly string[] Vues = { "Caméra et micro", "Prise en main à distance", "Ports ouverts" };

        // Une ligne par programme et par périphérique : l'utilisation en cours, sinon la plus récente (comme aujourd'hui)
        public static List<UsagePeripherique> Usages(Etat e)
        {
            return (e == null || e.Peripheriques == null ? new List<UsagePeripherique>() : e.Peripheriques).Where(u => u != null)
                .GroupBy(u => (u.Peripherique ?? "") + "|" + (u.Programme ?? "").ToLowerInvariant())
                .Select(g => g.OrderByDescending(u => u.EnCours).ThenByDescending(u => u.DernierDebut).First())
                .OrderByDescending(u => u.EnCours).ThenByDescending(u => u.DernierDebut).ToList();
        }

        public static string Resume(Etat e, bool lu, bool illisible, string panne)
        {
            bool en = L.En;
            string lecture = VueReseauFluent.Lecture(lu, illisible, e != null);
            if (lecture != null && (!lu || e == null)) return lecture;
            var usages = Usages(e);
            int outils = (e.OutilsDistants ?? new List<OutilDistant>()).Count, ports = (e.Ecoutes ?? new List<Ecoute>()).Count;
            string s = string.Format(en ? "Camera or microphone in use now: {0}. Remote Desktop: {1}. Remote control tools running: {2}. Open ports waiting for incoming connections: {3}."
                                        : "Caméra ou micro utilisés en ce moment : {0}. Bureau à distance : {1}. Outils de prise en main en cours : {2}. Ports ouverts en attente de connexions entrantes : {3}.",
                usages.Count(u => u.EnCours), e.BureauADistance ? (en ? "ON" : "ACTIVÉ") : (en ? "off" : "désactivé"), outils, ports);
            if (!string.IsNullOrEmpty(e.MisAJour)) s += " " + (en ? "State of " : "État du ") + Canal.Visible(e.MisAJour) + ".";
            if (panne != null) s += "\n" + (en ? "Incomplete: " : "Incomplet : ") + panne;
            return lecture != null ? lecture + "\n" + s : s;
        }

        public static List<LigneEtatFluent> Lignes(Etat e, int vue)
        {
            bool en = L.En;
            var l = new List<LigneEtatFluent>();
            if (e == null) return l;
            Func<string, string> v = x => string.IsNullOrEmpty(x) ? "—" : Canal.Visible(x);
            if (vue == 0)
                foreach (var u in Usages(e))
                    l.Add(new LigneEtatFluent
                    {
                        Titre = v(u.Programme), Etiquette = Canal.Visible(u.Peripherique) + (u.EnCours ? (en ? " · IN USE" : " · EN COURS") : ""),
                        Sous = u.EnCours ? (en ? "since " : "depuis ") + v(u.DernierDebut) : v(u.DernierDebut) + " → " + v(u.DerniereFin), Gravite = u.EnCours ? 2 : 0,
                        Detail = new List<LigneDetail> { new LigneDetail { Titre = en ? "Path" : "Chemin", Texte = v(u.Chemin), Chasse = true }, new LigneDetail { Titre = en ? "Last use" : "Dernière utilisation", Texte = v(u.DernierDebut) + " → " + v(u.DerniereFin) } },
                        Chemin = u.Chemin
                    });
            else if (vue == 1)
            {
                l.Add(new LigneEtatFluent
                {
                    Titre = en ? "Remote Desktop (RDP)" : "Bureau à distance (RDP)", Etiquette = e.BureauADistance ? (en ? "ON" : "ACTIVÉ") : (en ? "off" : "désactivé"),
                    Sous = e.BureauADistance ? (en ? "this computer accepts Remote Desktop connections" : "ce PC accepte les connexions Bureau à distance") : "", Gravite = e.BureauADistance ? 2 : 0,
                    Detail = new List<LigneDetail> { new LigneDetail { Titre = "Windows", Texte = e.BureauADistance ? (en ? "Remote Desktop is on." : "Le Bureau à distance est activé.") : (en ? "Remote Desktop is off." : "Le Bureau à distance est désactivé.") } }
                });
                foreach (var o in e.OutilsDistants ?? new List<OutilDistant>())
                    if (o != null) l.Add(new LigneEtatFluent
                    {
                        Titre = v(o.Nom), Etiquette = en ? "RUNNING" : "EN COURS", Sous = (en ? "since " : "depuis ") + v(o.Depuis) + "  ·  PID " + o.Pid, Gravite = 2,
                        Detail = new List<LigneDetail> { new LigneDetail { Titre = en ? "Path" : "Chemin", Texte = v(o.Chemin), Chasse = true }, new LigneDetail { Titre = en ? "Signer" : "Signataire", Texte = v(o.Signataire) } },
                        Chemin = o.Chemin
                    });
            }
            else
                foreach (var c in e.Ecoutes ?? new List<Ecoute>())
                    if (c != null) l.Add(new LigneEtatFluent
                    {
                        Titre = "Port " + c.Port + "  ·  " + v(c.Programme), Etiquette = c.Signataire == "-" ? (en ? "unsigned" : "non signé") : v(c.Signataire),
                        Sous = v(c.Adresse) + ":" + c.Port + "  ·  " + (en ? "since " : "depuis ") + v(c.Depuis), Gravite = c.Signataire == "-" ? 1 : 0,
                        Detail = new List<LigneDetail> { new LigneDetail { Titre = en ? "Address" : "Adresse", Texte = v(c.Adresse) + ":" + c.Port, Chasse = true }, new LigneDetail { Titre = en ? "Path" : "Chemin", Texte = v(c.Chemin), Chasse = true }, new LigneDetail { Titre = "PID", Texte = c.Pid.ToString() } },
                        Chemin = c.Chemin
                    });
            return l;
        }
    }

    // Page Démarrage auto en WPF (U6a) : demarrage.json, même filtre et même quarantaine que la page d'aujourd'hui
    class PageDemarrageFluent : PageProtectionFluent
    {
        readonly ISourceReponses source;
        List<EntreeDemarrage> entrees = new List<EntreeDemarrage>();
        bool illisible, masquer = true;

        public PageDemarrageFluent(ISourceReponses source) { this.source = source; Afficher(); }

        protected override object LireFichiers() { bool absent; var l = LectureFluent.Lire<List<EntreeDemarrage>>("demarrage.json", out absent); return absent ? new List<EntreeDemarrage>() : l; }

        protected override void Recevoir(object lecture)
        {
            var l = lecture as List<EntreeDemarrage>;
            illisible = l == null;
            if (l != null) entrees = l;
        }

        protected override void Afficher()
        {
            var vues = VueDemarrageFluent.Filtrer(entrees, masquer);
            resume.Text = VueDemarrageFluent.Resume(entrees, vues.Count, lu, illisible);
            resume.Foreground = Jetons.Pinceau(illisible ? Jetons.Attention : vues.Any(x => VueDemarrageFluent.Gravite(x) == 1) ? Jetons.Attention : Jetons.TexteSecondaire);
            var lignes = vues.Select(x => new LigneEtatFluent { Titre = Canal.Visible(x.Nom), Etiquette = VueDemarrageFluent.Signataire(x), Sous = Canal.Visible(x.Categorie) + "  ·  " + Canal.Visible(x.Commande), Gravite = VueDemarrageFluent.Gravite(x), Detail = VueDemarrageFluent.Detail(x) }).ToList();
            string signature = masquer + "#" + choisie + "#" + resume.Text + "#" + string.Join(";", vues.Select(x => x.Cle + "|" + x.Remarque + "|" + x.Commande));
            if (signature == vu) return;
            vu = signature;
            outils.Children.Clear();
            var barre = new WrapPanel();
            barre.Children.Add(Outil((masquer ? "✓  " : "○  ") + L.T("Masquer les entrées signées Microsoft / Windows (sauf commande suspecte)"), masquer, (s, e) => { masquer = !masquer; choisie = 0; vu = null; Afficher(); }));
            outils.Children.Add(barre);
            Liste(lignes);
            var choix = vues.Count > 0 ? vues[Math.Min(choisie, vues.Count - 1)] : null;
            var pile = Panneau(lignes.Count > 0 ? lignes[Math.Min(choisie, lignes.Count - 1)] : null, L.En ? "Select an entry to read it and act on it." : "Sélectionnez une entrée pour la lire et agir.");
            if (pile != null && choix != null)
            {
                pile.Children.Add(Briques.Titre(L.T("Agir"), 12));
                if (source != null && !string.IsNullOrEmpty(choix.Cible))
                {
                    pile.Children.Add(Briques.Action(L.T("Mettre la cible en quarantaine"), true, (s, e) => { source.AgirElement(choix, "quarantaine"); Charger(); }));
                    pile.Children.Add(Briques.Action(L.T("Ouvrir l'emplacement du fichier"), false, (s, e) => source.OuvrirEmplacement(choix.Cible)));
                }
                pile.Children.Add(Briques.Action(L.T("Copier"), false, (s, e) => VueReseauFluent.Copier(VueDemarrageFluent.Copie(choix))));
            }
        }
    }

    // Page Extensions en WPF (U6a) : extensions.json, lecture seule
    class PageExtensionsFluent : PageProtectionFluent
    {
        List<Extension> extensions = new List<Extension>();
        bool illisible;

        public PageExtensionsFluent() { Afficher(); }

        protected override object LireFichiers() { bool absent; var l = LectureFluent.Lire<List<Extension>>("extensions.json", out absent); return absent ? new List<Extension>() : l; }

        protected override void Recevoir(object lecture)
        {
            var l = lecture as List<Extension>;
            illisible = l == null;
            if (l != null) extensions = VueExtensionsFluent.Trier(l);
        }

        protected override void Afficher()
        {
            resume.Text = VueExtensionsFluent.Resume(extensions, lu, illisible);
            resume.Foreground = Jetons.Pinceau(illisible ? Jetons.Attention : Jetons.TexteSecondaire);
            var lignes = extensions.Select(x => new LigneEtatFluent { Titre = Canal.Visible(x.Nom), Etiquette = Canal.Visible(x.Navigateur), Sous = (string.IsNullOrEmpty(x.Version) ? "" : "v" + Canal.Visible(x.Version) + "  ·  ") + (x.Dangereuse ? (L.En ? "sensitive permissions" : "permissions sensibles") : Canal.Visible(x.Depuis)), Gravite = x.Dangereuse ? 1 : 0, Detail = VueExtensionsFluent.Detail(x) }).ToList();
            string signature = choisie + "#" + resume.Text + "#" + string.Join(";", extensions.Select(x => x.Navigateur + "|" + x.Id + "|" + x.Version));
            if (signature == vu) return;
            vu = signature;
            Liste(lignes);
            var choix = extensions.Count > 0 ? extensions[Math.Min(choisie, extensions.Count - 1)] : null;
            var pile = Panneau(lignes.Count > 0 ? lignes[Math.Min(choisie, lignes.Count - 1)] : null, L.En ? "Select an extension to read its permissions." : "Sélectionnez une extension pour lire ses permissions.");
            if (pile != null && choix != null)
            {
                pile.Children.Add(Briques.Titre(L.T("Agir"), 12));
                pile.Children.Add(Briques.Action(L.T("Copier"), false, (s, e) => VueReseauFluent.Copier(VueExtensionsFluent.Copie(choix))));
            }
        }
    }

    // Page Vie privée en WPF (U6a) : etat.json comme la page d'aujourd'hui ; ouvrir l'emplacement et copier
    class PageVieFluent : PageEtatServiceFluent
    {
        Etat etat;
        int vue, choisie;

        public PageVieFluent(ISourceReponses source) : base(source, "Peripheriques", true) { Afficher(); }

        protected override void Recevoir(Etat e) { etat = e; }

        protected override void Afficher()
        {
            resume.Text = VueVieFluent.Resume(etat, lu, illisible, panne);
            bool actif = etat != null && (etat.BureauADistance || (etat.OutilsDistants ?? new List<OutilDistant>()).Count > 0 || VueVieFluent.Usages(etat).Any(u => u.EnCours));
            resume.Foreground = Jetons.Pinceau(actif ? Jetons.Danger : illisible || panne != null ? Jetons.Attention : Jetons.TexteSecondaire);
            var lignes = VueVieFluent.Lignes(etat, vue);
            if (choisie >= lignes.Count) choisie = 0;
            string signature = vue + "#" + choisie + "#" + resume.Text + "#" + string.Join(";", lignes.Select(x => x.Titre + "|" + x.Etiquette + "|" + x.Sous));
            if (signature == vu) return;
            vu = signature;
            outils.Children.Clear();
            var vues = new WrapPanel { Margin = new Thickness(0, 0, 0, 12) };
            for (int k = 0; k < VueVieFluent.Vues.Length; k++)
            {
                int n = k; bool ouverte = n == vue;
                var bt = new Button
                {
                    Content = L.T(VueVieFluent.Vues[k]), Padding = new Thickness(12, 4, 12, 4), Margin = new Thickness(0, 0, 8, 0), Cursor = Cursors.Hand,
                    Background = Jetons.Pinceau(ouverte ? Jetons.Surface : Jetons.Fond), BorderBrush = Jetons.Pinceau(ouverte ? Jetons.Accent : Jetons.Separateur), BorderThickness = new Thickness(1), Foreground = Jetons.Pinceau(Jetons.Texte)
                };
                bt.Template = Coquille.ModeleBouton();
                bt.Click += (s, e) => { vue = n; choisie = 0; Afficher(); };
                vues.Children.Add(bt);
            }
            outils.Children.Add(vues);
            liste.Children.Clear();
            if (lu && etat != null && lignes.Count == 0)
                Vide(vue == 0 ? (L.En ? "No camera or microphone use recorded by Windows." : "Aucune utilisation de la caméra ou du micro enregistrée par Windows.") : (L.En ? "No open port outside the local loopback." : "Aucun port ouvert hors de la boucle locale."));
            for (int k = 0; k < lignes.Count; k++)
            {
                int n = k; var x = lignes[k];
                liste.Children.Add(Briques.Ligne(x.Titre, x.Etiquette, x.Sous, x.Gravite, n == choisie, false, () => { choisie = n; Afficher(); }));
            }
            var x0 = lignes.Count > 0 ? lignes[choisie] : null;
            if (x0 == null) { detail.Content = new TextBlock { Text = L.En ? "Select a line to read its detail." : "Sélectionnez une ligne pour lire son détail.", Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap }; return; }
            var pile = new StackPanel();
            pile.Children.Add(new TextBlock { Text = x0.Titre, FontSize = 16, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            pile.Children.Add(new TextBlock { Text = x0.Etiquette, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Briques.Couleur(x0.Gravite)), Margin = new Thickness(0, 2, 0, 4), TextWrapping = TextWrapping.Wrap });
            Lignes(pile, x0.Detail);
            var actions = new List<string>();
            if (!string.IsNullOrEmpty(x0.Chemin)) actions.Add("emplacement");
            actions.Add("copier");
            string chemin = x0.Chemin;
            string copie = VueReseauFluent.Copie(new[] { x0.Titre, x0.Etiquette, x0.Sous }.Concat(x0.Detail.Select(d => d.Texte)).ToArray());
            Actions(pile, actions, a => { if (a == "copier") VueReseauFluent.Copier(copie); else if (source != null) source.OuvrirEmplacement(chemin); });
            detail.Content = pile;
        }
    }
    // Décisions pures de la page Réseau local de la coquille (U6b) : reseau.json, écrit par le service à partir de ce qu'il
    // voit sur le réseau (noms annoncés, descriptions UPnP, adresses) ; tout est neutralisé
    public static class VueReseauLocalFluent
    {
        public static readonly string[] Vues = { "Appareils", "Serveurs DHCP", "Redirections UPnP", "Répondeurs" };

        public static bool LeurreRepondu(EtatReseau r) { return r != null && (r.ResultatLeurre ?? "").StartsWith("RÉPONSE"); }

        public static long Ordre(string ip)
        {
            long v = 0;
            foreach (var o in (ip ?? "").Split('.')) { int n; int.TryParse(o, out n); v = v * 256 + n; }
            return v;
        }

        public static string Resume(EtatReseau r, bool lu, bool illisible)
        {
            bool en = L.En;
            if (!lu) return L.T("Lecture en cours…");
            if (r == null)
                return illisible ? (en ? "reseau.json unreadable: nothing is concluded." : "reseau.json illisible : rien n'est conclu.")
                                 : (en ? "No data yet (the service analyses the network when it starts)." : "Pas encore de données (le service analyse le réseau au démarrage).");
            Func<string, string> v = x => string.IsNullOrEmpty(x) ? "?" : Canal.Visible(x);
            string s = string.Format(en ? "Interface {0} / {1} · gateway {2} ({3}) · DHCP server {4}\nDecoy ({5}): {6}" : "Interface {0} / {1} · passerelle {2} ({3}) · serveur DHCP {4}\nLeurre ({5}) : {6}",
                v(r.Interface), v(r.Masque), v(r.Passerelle), v(r.MacPasserelle), string.IsNullOrEmpty(r.DhcpInterface) ? (en ? "none (static address)" : "aucun (adresse fixe)") : Canal.Visible(r.DhcpInterface), v(r.DernierLeurre), v(r.ResultatLeurre));
            int pirates = (r.ServeursDhcp ?? new List<ServeurDhcp>()).Count(d => d != null && !d.Legitime);
            if (pirates > 0) s += "\n" + string.Format(en ? "{0} rogue DHCP server(s) seen." : "{0} serveur(s) DHCP pirate(s) vu(s).", pirates);
            if (!string.IsNullOrEmpty(r.MisAJour)) s += "\n" + (en ? "State of " : "État du ") + Canal.Visible(r.MisAJour) + ".";
            if (illisible) s = (en ? "reseau.json unreadable: the last display is kept; it may be out of date.\n" : "reseau.json illisible : dernier affichage gardé, peut-être dépassé.\n") + s;
            return s;
        }

        public static int Gravite(EtatReseau r) { return r == null ? 0 : LeurreRepondu(r) || (r.ServeursDhcp ?? new List<ServeurDhcp>()).Any(d => d != null && !d.Legitime) ? 2 : 0; }

        public static List<LigneEtatFluent> Lignes(EtatReseau r, int vue)
        {
            bool en = L.En;
            var l = new List<LigneEtatFluent>();
            if (r == null) return l;
            Func<string, string> v = x => string.IsNullOrEmpty(x) ? "—" : Canal.Visible(x);
            if (vue == 0)
                foreach (var a in (r.Appareils ?? new List<Appareil>()).Where(x => x != null).OrderByDescending(x => x.Passerelle).ThenBy(x => Ordre(x.Ip)))
                    l.Add(new LigneEtatFluent
                    {
                        Titre = v(a.Ip), Etiquette = a.Passerelle ? (en ? "gateway (router)" : "passerelle (box)") : (en ? "device" : "appareil"), Sous = "MAC " + v(a.Mac) + "  ·  " + (en ? "last seen " : "vu le ") + v(a.DerniereVue),
                        Detail = new List<LigneDetail> { new LigneDetail { Titre = "MAC", Texte = v(a.Mac), Chasse = true }, new LigneDetail { Titre = en ? "First seen" : "Première vue", Texte = v(a.PremiereVue) }, new LigneDetail { Titre = en ? "Last seen" : "Dernière vue", Texte = v(a.DerniereVue) } }
                    });
            else if (vue == 1)
                foreach (var d in (r.ServeursDhcp ?? new List<ServeurDhcp>()).Where(x => x != null))
                    l.Add(new LigneEtatFluent
                    {
                        Titre = v(d.Ip), Etiquette = d.Legitime ? (en ? "DHCP server" : "serveur DHCP") : (en ? "ROGUE DHCP server" : "serveur DHCP PIRATE"), Gravite = d.Legitime ? 0 : 2,
                        Sous = d.Legitime ? (en ? "server of this interface" : "serveur de cette interface") : (en ? "not the server of this interface" : "n'est pas le serveur de cette interface"),
                        Detail = new List<LigneDetail> { new LigneDetail { Titre = en ? "Seen" : "Vu", Texte = v(d.Vu) } }
                    });
            else if (vue == 2)
                foreach (var x in (r.Redirections ?? new List<RedirectionUpnp>()).Where(y => y != null))
                {
                    bool versPc = x.Client == r.Interface;
                    l.Add(new LigneEtatFluent
                    {
                        Titre = (versPc ? (en ? "TO THIS COMPUTER " : "VERS CE PC ") : "") + x.PortExterne + "/" + v(x.Protocole), Etiquette = x.Active ? (en ? "active" : "active") : (en ? "inactive" : "inactive"),
                        Sous = v(x.Client) + "  ·  " + (en ? "internal port " : "port interne ") + x.PortInterne, Gravite = versPc && x.Active ? 1 : 0,
                        Detail = new List<LigneDetail> { new LigneDetail { Titre = en ? "Client" : "Client", Texte = v(x.Client), Chasse = true }, new LigneDetail { Titre = "Description", Texte = v(x.Description) } }
                    });
                }
            else
                foreach (var x in (r.Repondeurs ?? new List<Repondeur>()).Where(y => y != null))
                {
                    var noms = x.Noms ?? new List<string>();
                    l.Add(new LigneEtatFluent
                    {
                        Titre = v(x.Ip), Etiquette = v(x.Protocole), Sous = noms.Count + (en ? " name(s) answered" : " nom(s) répondu(s)") + "  ·  " + v(x.Derniere),
                        Gravite = noms.Count >= (x.Protocole == "mDNS" ? 15 : 3) ? 1 : 0,
                        Detail = new List<LigneDetail> { new LigneDetail { Titre = en ? "Names" : "Noms", Texte = noms.Count == 0 ? "—" : string.Join("\n", noms.Select(Canal.Visible)) }, new LigneDetail { Titre = en ? "Last" : "Dernière", Texte = v(x.Derniere) } }
                    });
                }
            return l;
        }
    }

    // Page Réseau local en WPF (U6b) : reseau.json, lecture seule ; copie de la ligne
    class PageReseauLocalFluent : PageProtectionFluent
    {
        EtatReseau reseau;
        bool illisible;
        int vue;

        public PageReseauLocalFluent() { Afficher(); }

        protected override object LireFichiers() { bool absent; var r = LectureFluent.Lire<EtatReseau>("reseau.json", out absent); return new object[] { r, !absent && r == null }; }

        protected override void Recevoir(object lecture)
        {
            var x = (object[])lecture;
            illisible = (bool)x[1];
            if (x[0] != null || !illisible) reseau = x[0] as EtatReseau;
        }

        protected override void Afficher()
        {
            bool en = L.En;
            resume.Text = VueReseauLocalFluent.Resume(reseau, lu, illisible);
            resume.Foreground = Jetons.Pinceau(VueReseauLocalFluent.Gravite(reseau) == 2 ? Jetons.Danger : lu && (illisible || reseau == null) ? Jetons.Attention : Jetons.TexteSecondaire);
            var lignes = VueReseauLocalFluent.Lignes(reseau, vue);
            string signature = vue + "#" + choisie + "#" + resume.Text + "#" + string.Join(";", lignes.Select(x => x.Titre + "|" + x.Etiquette + "|" + x.Sous));
            if (signature == vu) return;
            vu = signature;
            outils.Children.Clear();
            var vues = new WrapPanel { Margin = new Thickness(0, 0, 0, 12) };
            for (int k = 0; k < VueReseauLocalFluent.Vues.Length; k++)
            {
                int n = k; bool ouverte = n == vue;
                var bt = new Button
                {
                    Content = L.T(VueReseauLocalFluent.Vues[k]), Padding = new Thickness(12, 4, 12, 4), Margin = new Thickness(0, 0, 8, 0), Cursor = Cursors.Hand,
                    Background = Jetons.Pinceau(ouverte ? Jetons.Surface : Jetons.Fond), BorderBrush = Jetons.Pinceau(ouverte ? Jetons.Accent : Jetons.Separateur), BorderThickness = new Thickness(1), Foreground = Jetons.Pinceau(Jetons.Texte)
                };
                bt.Template = Coquille.ModeleBouton();
                bt.Click += (s, e) => { vue = n; choisie = 0; Afficher(); };
                vues.Children.Add(bt);
            }
            outils.Children.Add(vues);
            Liste(lignes);
            if (lu && reseau != null && lignes.Count == 0)
                liste.Children.Add(new TextBlock { Text = vue == 2 && reseau != null ? (en ? "No redirection read. UPnP: " : "Aucune redirection lue. UPnP : ") + (string.IsNullOrEmpty(reseau.Upnp) ? (en ? "not checked yet" : "pas encore vérifié") : Canal.Visible(reseau.Upnp)) : L.T("Rien d'enregistré pour cette vue."), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap });
            var x0 = lignes.Count > 0 ? lignes[Math.Min(choisie, lignes.Count - 1)] : null;
            var pile = Panneau(x0, en ? "Select a line to read its detail." : "Sélectionnez une ligne pour lire son détail.");
            if (pile != null)
            {
                pile.Children.Add(Briques.Titre(L.T("Agir"), 12));
                string copie = VueReseauFluent.Copie(new[] { x0.Titre, x0.Etiquette, x0.Sous }.Concat(x0.Detail.Select(d => d.Texte)).ToArray());
                pile.Children.Add(Briques.Action(L.T("Copier"), false, (s, e) => VueReseauFluent.Copier(copie)));
            }
        }
    }
    // Choix parmi quelques valeurs fixes (protocole, format, niveau…) : boutons, sans liste déroulante claire dans le thème sombre
    class ChoixFluent : WrapPanel
    {
        readonly string[] valeurs;
        public string Valeur { get; private set; }

        public ChoixFluent(string[] valeurs, string[] libelles)
        {
            this.valeurs = valeurs;
            Margin = new Thickness(0, 0, 12, 0);
            for (int k = 0; k < valeurs.Length; k++)
            {
                string v = valeurs[k];
                var b = new Button { Content = libelles == null ? L.T(v) : libelles[k], Padding = new Thickness(10, 3, 10, 3), Margin = new Thickness(0, 0, 4, 0), Cursor = Cursors.Hand, BorderThickness = new Thickness(1), Foreground = Jetons.Pinceau(Jetons.Texte), Tag = v };
                b.Template = Coquille.ModeleBouton();
                b.Click += (s, e) => Definir(v);
                Children.Add(b);
            }
            Definir(valeurs[0]);
        }

        public void Definir(string v)
        {
            Valeur = Array.IndexOf(valeurs, v) >= 0 ? v : valeurs[0];
            foreach (Button b in Children)
            {
                bool actif = (string)b.Tag == Valeur;
                b.Background = Jetons.Pinceau(actif ? Jetons.Surface : Jetons.Fond);
                b.BorderBrush = Jetons.Pinceau(actif ? Jetons.Accent : Jetons.Separateur);
            }
        }
    }

    // Page Réglages en WPF (U6c) : mêmes réglages, mêmes contrôles et mêmes commandes que la page d'aujourd'hui
    // (ActionsReglages) ; lue à l'ouverture et après chaque action, jamais pendant la saisie ; config.json illisible : dit, et
    // rien n'est enregistré
    class PageReglagesFluent : ScrollViewer
    {
        readonly StackPanel pile = new StackPanel { MaxWidth = 900, HorizontalAlignment = HorizontalAlignment.Left };
        readonly TextBlock config = Texte(true), apprentissage = Texte(false), notifEtat = Texte(true), maj = Texte(false), lecteurs = Texte(true);
        readonly ChoixFluent langue = new ChoixFluent(new[] { "fr", "en" }, new[] { "Français", "English" });
        readonly CheckBox syslog = Case("Envoyer les alertes à un serveur syslog / SIEM"), api = Case("Activer l'API d'export"), reseau = Case("Accessible depuis le réseau local (sinon cet ordinateur seulement)"),
            majAuto = Case("Installer automatiquement une version signée par la clé épinglée dans deR4Tizer (révocation vérifiée)"),
            ntfy = Case("ntfy (application mobile ou de bureau, serveur public ou auto-hébergé)"), teams = Case("Microsoft Teams (webhook d'un flux de travail « publier dans un canal »)"), smtp = Case("E-mail (SMTP chiffré)");
        readonly TextBox hote = Saisie(220), portSyslog = Saisie(70), portApi = Saisie(70), adresses = Saisie(300), majUrl = Saisie(520), maxHeure = Saisie(60),
            smtpServeur = Saisie(220), smtpPort = Saisie(60), smtpUtilisateur = Saisie(220), expediteur = Saisie(220), destinataires = Saisie(360), compte = Saisie(300);
        // Adresse ntfy masquée comme les autres secrets (audit de #147, S147-02)
        readonly PasswordBox ntfyUrl = Secret(360), ntfyJeton = Secret(220), teamsUrl = Secret(520), smtpMdp = Secret(160);
        readonly ChoixFluent protocole = new ChoixFluent(ActionsReglages.Protocoles, null), format = new ChoixFluent(ActionsReglages.Formats, null), niveau = new ChoixFluent(ActionsReglages.Niveaux, null),
            niveauNotif = new ChoixFluent(ActionsReglages.Niveaux, null), securite = new ChoixFluent(ActionsReglages.Securites, null);
        int enCours, chargement;
        bool rempli;            // aucune action avant la première lecture : des champs vides ne partent jamais comme réglages
        public Action Revoir;   // ouvre « Premiers réglages » (donné par la coquille)

        public PageReglagesFluent()
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto;
            Content = pile;
            pile.Children.Add(Note("Langue, envoi des alertes à un SIEM (syslog), API d'export et export des journaux."));
            pile.Children.Add(config);
            Section("LANGUE");
            pile.Children.Add(Ligne(Etiquette("Langue de l'interface"), langue));
            pile.Children.Add(Note("La langue s'applique au prochain lancement de l'interface."));

            Section("MODE APPRENTISSAGE ET EXCEPTIONS");
            pile.Children.Add(Note("Les premiers jours, les alertes non critiques sont notées en information et leur comportement est mémorisé (logiciel de caisse, outils du prestataire, scripts…). Ensuite, seul un comportement nouveau alerte. Les alertes critiques ne sont jamais adoucies. Clic droit sur une alerte : « Ne plus alerter pour ce comportement »."));
            pile.Children.Add(apprentissage);
            pile.Children.Add(Ligne(Bouton("Terminer l'apprentissage", false, () => ActionsReglages.Apprentissage("terminer")),
                Bouton("Recommencer (7 jours)", false, () => ActionsReglages.Apprentissage("recommencer")), Bouton("Supprimer les exceptions", false, () => ActionsReglages.Apprentissage("oublier"))));

            Section("REMONTÉE DES ALERTES (PRESTATAIRE, RÉFÉRENT)");
            pile.Children.Add(Note("Envoie les alertes de ce poste à la personne qui s'en occupe, avec le « quoi faire ». Les alertes d'un quart de minute sont regroupées en un seul message, et un plafond par heure évite l'inondation."));
            pile.Children.Add(Ligne(Etiquette("Niveau minimal"), niveauNotif, Etiquette("Messages par heure au plus"), maxHeure));
            pile.Children.Add(ntfy);
            pile.Children.Add(Note("Conseil : un serveur ntfy auto-hébergé plutôt que ntfy.sh, que des malwares utilisent aussi pour faire sortir des données (il reste joignable en mode panique)."));
            pile.Children.Add(Ligne(Etiquette("Adresse du sujet"), ntfyUrl, Etiquette("Jeton (facultatif)"), ntfyJeton));
            pile.Children.Add(teams);
            pile.Children.Add(Ligne(Etiquette("Adresse du webhook"), teamsUrl));
            pile.Children.Add(smtp);
            pile.Children.Add(Ligne(Etiquette("Serveur"), smtpServeur, Etiquette("Port"), smtpPort, Etiquette("Sécurité"), securite));
            pile.Children.Add(Ligne(Etiquette("Utilisateur"), smtpUtilisateur, Etiquette("Mot de passe"), smtpMdp));
            pile.Children.Add(Ligne(Etiquette("Expéditeur"), expediteur, Etiquette("Destinataires"), destinataires));
            pile.Children.Add(Note("Les adresses ntfy et Teams, le jeton et le mot de passe sont gardés à part, lisibles par les administrateurs seulement : laissez le champ vide pour conserver la valeur enregistrée, tapez « - » pour l'effacer."));
            pile.Children.Add(notifEtat);
            pile.Children.Add(Ligne(Bouton("Enregistrer les notifications", true, () => Notifications("notifications")), Bouton("Envoyer un message de test", false, () => Notifications("testerNotifications"))));

            Section("ENVOI DES ALERTES (SYSLOG)");
            pile.Children.Add(syslog);
            pile.Children.Add(Ligne(Etiquette("Serveur"), hote, Etiquette("Port"), portSyslog, Etiquette("Protocole"), protocole));
            pile.Children.Add(Ligne(Etiquette("Format"), format, Etiquette("Niveau minimal"), niveau));
            pile.Children.Add(Note("JSON : en-tête RFC 5424 et détail en JSON. CEF : reconnu par la plupart des SIEM (Splunk, QRadar, Sentinel, Wazuh, Graylog…)."));
            pile.Children.Add(Ligne(Bouton("Tester l'envoi", false, () => { var x = Saisis(); if (x != null) ActionsReglages.TesterSyslog(x.Item1); })));

            Section("API D'EXPORT (HTTP, LECTURE SEULE)");
            pile.Children.Add(api);
            pile.Children.Add(Ligne(Etiquette("Port"), portApi));
            pile.Children.Add(reseau);
            pile.Children.Add(Ligne(Etiquette("Adresses autorisées (SIEM)"), adresses));
            pile.Children.Add(Note("Chaque requête doit porter l'en-tête « Authorization: Bearer <jeton> ». Routes : /api/v1/alertes, /connexions, /exposition, /baseline, /regles-parefeu, /blocages, /journal."));
            pile.Children.Add(Ligne(Bouton("Afficher le jeton", false, ActionsReglages.AfficherJeton), Bouton("Nouveau jeton", false, () => ActionsReglages.NouveauJeton())));
            pile.Children.Add(Ligne(Bouton("Enregistrer", true, Enregistrer)));

            Section("MISE À JOUR");
            pile.Children.Add(maj);
            pile.Children.Add(majAuto);
            pile.Children.Add(Ligne(Etiquette("Manifeste"), majUrl));
            pile.Children.Add(Ligne(Bouton("Enregistrer", true, () => ActionsReglages.MajConfig(majAuto.IsChecked == true, majUrl.Text)), Bouton("Rechercher maintenant", false, ActionsReglages.MajVerifier)));

            Section("ACCÈS AUX DONNÉES");
            pile.Children.Add(lecteurs);
            pile.Children.Add(Ligne(Etiquette("Nom du compte (par exemple : PC-ACCUEIL\\marie)"), compte, Bouton("Autoriser", false, Autoriser)));

            Section("EXPORT DES JOURNAUX");
            pile.Children.Add(Ligne(Bouton("Exporter les alertes…", true, ExporterAlertes), Bouton("Exporter le journal du service…", false, ExporterJournal)));

            // Premiers réglages (U7a) : rejouables à tout moment, sans commande
            Section("PREMIERS RÉGLAGES");
            var revoir = Briques.Action(L.En ? "See the first-run setup again" : "Revoir les premiers réglages", false, (s, e) => { if (Revoir != null) Revoir(); });
            revoir.HorizontalAlignment = HorizontalAlignment.Left;
            pile.Children.Add(revoir);
            Loaded += (s, e) => Charger();
        }

        // Lecture hors du fil de l'interface ; les champs ne sont remplis qu'à l'ouverture et après une action
        internal void Charger()
        {
            if (System.Threading.Interlocked.CompareExchange(ref enCours, 1, 0) != 0) return;
            int numero = ++chargement;
            System.Threading.ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    bool illisible;
                    var c = ActionsProtection.LireConfig(out illisible);
                    var app = Commun.Lire<EtatApprentissage>("apprentissage.json");
                    var em = Commun.Lire<EtatMaj>("maj.json");
                    var en = Commun.Lire<EtatNotifications>("notifications.json");
                    var lect = Commun.Lire<List<Lecteur>>("lecteurs.json");
                    Dispatcher.BeginInvoke((Action)(() => { if (numero == chargement) Remplir(c, illisible, app, em, en, lect); }));
                }
                finally { System.Threading.Interlocked.Exchange(ref enCours, 0); }
            });
        }

        void Remplir(Config c, bool illisible, EtatApprentissage app, EtatMaj em, EtatNotifications en, List<Lecteur> lect)
        {
            config.Text = illisible ? ActionsReglages.ConfigIllisible() : "";
            config.Visibility = illisible ? Visibility.Visible : Visibility.Collapsed;
            var x = c ?? new Config();
            var sl = x.Syslog ?? new ConfigSyslog(); var a = x.Api ?? new ConfigApi(); var n = x.Notifications ?? new ConfigNotifications(); var m = x.Maj ?? new ConfigMaj();
            langue.Definir(x.Langue == "en" ? "en" : "fr");
            syslog.IsChecked = sl.Actif; hote.Text = sl.Hote ?? ""; portSyslog.Text = sl.Port.ToString(); protocole.Definir(sl.Protocole); format.Definir(sl.Format); niveau.Definir(sl.NiveauMin);
            api.IsChecked = a.Actif; portApi.Text = a.Port.ToString(); reseau.IsChecked = a.Reseau; adresses.Text = a.Adresses ?? "";
            majAuto.IsChecked = m.Auto; majUrl.Text = m.Url ?? "";
            niveauNotif.Definir(n.NiveauMin); maxHeure.Text = n.MaxParHeure.ToString(); ntfy.IsChecked = n.Ntfy; teams.IsChecked = n.Teams; smtp.IsChecked = n.Smtp;
            smtpServeur.Text = n.SmtpServeur ?? ""; smtpPort.Text = n.SmtpPort.ToString(); securite.Definir(n.SmtpSecurite); smtpUtilisateur.Text = n.SmtpUtilisateur ?? ""; expediteur.Text = n.Expediteur ?? ""; destinataires.Text = n.Destinataires ?? "";
            // Secrets jamais relus ni réaffichés : vide garde la valeur enregistrée
            ntfyUrl.Password = ""; ntfyJeton.Password = ""; teamsUrl.Password = ""; smtpMdp.Password = "";
            apprentissage.Text = ActionsReglages.TexteApprentissage(app);
            maj.Text = ActionsReglages.TexteMaj(em);
            notifEtat.Text = ActionsReglages.TexteNotifications(en);
            lecteurs.Text = ActionsReglages.TexteLecteurs(lect);
            rempli = true;
        }

        Tuple<ConfigSyslog, ConfigApi> Saisis()
        {
            int ps, pa;
            string erreur = ActionsReglages.PortsInvalides(portSyslog.Text, portApi.Text, out ps, out pa);
            if (erreur != null) { WinForms.MessageBox.Show(erreur, "deR4Tizer", WinForms.MessageBoxButtons.OK, WinForms.MessageBoxIcon.Warning); return null; }
            return Tuple.Create(new ConfigSyslog { Actif = syslog.IsChecked == true, Hote = hote.Text.Trim(), Port = ps, Protocole = protocole.Valeur, Format = format.Valeur, NiveauMin = niveau.Valeur },
                new ConfigApi { Actif = api.IsChecked == true, Port = pa, Reseau = reseau.IsChecked == true, Adresses = adresses.Text.Trim() });
        }

        // config.json relu au moment d'enregistrer : illisible, rien n'est écrit (S139-02 étendu)
        void Enregistrer()
        {
            var s = Saisis();
            if (s == null) return;
            bool illisible;
            var lue = ActionsProtection.LireConfig(out illisible);
            ActionsReglages.Enregistrer(ActionsReglages.Composer(illisible ? null : lue, langue.Valeur == "en", s.Item1, s.Item2));
        }

        void Notifications(string action)
        {
            int max, port;
            string erreur = ActionsReglages.NotificationsInvalides(maxHeure.Text, smtpPort.Text, out max, out port);
            if (erreur != null) { WinForms.MessageBox.Show(erreur, "deR4Tizer", WinForms.MessageBoxButtons.OK, WinForms.MessageBoxIcon.Warning); return; }
            ActionsReglages.Notifications(action, new ConfigNotifications
            {
                NiveauMin = niveauNotif.Valeur, MaxParHeure = max, Ntfy = ntfy.IsChecked == true, Teams = teams.IsChecked == true, Smtp = smtp.IsChecked == true,
                SmtpServeur = smtpServeur.Text.Trim(), SmtpPort = port, SmtpSecurite = securite.Valeur, SmtpUtilisateur = smtpUtilisateur.Text.Trim(), Expediteur = expediteur.Text.Trim(), Destinataires = destinataires.Text.Trim()
            }, ntfyUrl.Password, ntfyJeton.Password, teamsUrl.Password, smtpMdp.Password);
        }

        void Autoriser()
        {
            if (string.IsNullOrWhiteSpace(compte.Text)) return;
            string sid = ActionsReglages.Sid(compte.Text);
            if (sid == null) { WinForms.MessageBox.Show(L.T("Compte introuvable."), "deR4Tizer", WinForms.MessageBoxButtons.OK, WinForms.MessageBoxIcon.Warning); return; }
            ActionsReglages.AutoriserLecteur(sid);
            compte.Text = "";
        }

        void ExporterAlertes()
        {
            var d = new Microsoft.Win32.SaveFileDialog { Filter = "JSON (*.json)|*.json|CSV (*.csv)|*.csv", FileName = ActionsReglages.NomExport("alertes") };
            if (d.ShowDialog() != true) return;
            try { ActionsReglages.ExporterAlertes(d.FileName, d.FilterIndex == 2); }
            catch (Exception e) { WinForms.MessageBox.Show(e.Message, "deR4Tizer", WinForms.MessageBoxButtons.OK, WinForms.MessageBoxIcon.Error); }
        }

        void ExporterJournal()
        {
            var d = new Microsoft.Win32.SaveFileDialog { Filter = "Texte (*.txt)|*.txt", FileName = ActionsReglages.NomExport("journal") };
            if (d.ShowDialog() != true) return;
            string erreur = ActionsReglages.ExporterJournal(d.FileName);
            if (erreur != null) WinForms.MessageBox.Show(erreur, "deR4Tizer", WinForms.MessageBoxButtons.OK, WinForms.MessageBoxIcon.Error);
        }

        // ------------------------------------------------------------ construction

        void Section(string titre)
        {
            pile.Children.Add(new TextBlock { Text = L.T(titre), FontSize = 13, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Jetons.Accent), Margin = new Thickness(0, 20, 0, 6) });
        }

        static TextBlock Texte(bool secondaire)
        {
            return new TextBlock { TextWrapping = TextWrapping.Wrap, FontSize = 12, Foreground = Jetons.Pinceau(secondaire ? Jetons.TexteSecondaire : Jetons.Texte), Margin = new Thickness(0, 2, 0, 6) };
        }

        static TextBlock Note(string texte)
        {
            var t = Texte(true); t.Text = L.T(texte); return t;
        }

        static TextBlock Etiquette(string texte)
        {
            return new TextBlock { Text = L.T(texte), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) };
        }

        static CheckBox Case(string texte)
        {
            return new CheckBox { Content = new TextBlock { Text = L.T(texte), TextWrapping = TextWrapping.Wrap }, Foreground = Jetons.Pinceau(Jetons.Texte), Margin = new Thickness(0, 6, 0, 4), Cursor = Cursors.Hand };
        }

        static TextBox Saisie(double largeur)
        {
            return new TextBox { Width = largeur, Background = Jetons.Pinceau(Jetons.Surface), Foreground = Jetons.Pinceau(Jetons.Texte), BorderBrush = Jetons.Pinceau(Jetons.Separateur), CaretBrush = Jetons.Pinceau(Jetons.Texte), Padding = new Thickness(6, 3, 6, 3), FontFamily = Briques.Chasse, FontSize = 12, Margin = new Thickness(0, 0, 12, 0), VerticalContentAlignment = VerticalAlignment.Center };
        }

        static PasswordBox Secret(double largeur)
        {
            return new PasswordBox { Width = largeur, Background = Jetons.Pinceau(Jetons.Surface), Foreground = Jetons.Pinceau(Jetons.Texte), BorderBrush = Jetons.Pinceau(Jetons.Separateur), CaretBrush = Jetons.Pinceau(Jetons.Texte), Padding = new Thickness(6, 3, 6, 3), FontSize = 12, Margin = new Thickness(0, 0, 12, 0), VerticalContentAlignment = VerticalAlignment.Center };
        }

        static WrapPanel Ligne(params UIElement[] elements)
        {
            var l = new WrapPanel { Margin = new Thickness(0, 4, 0, 4) };
            foreach (var e in elements) l.Children.Add(e);
            return l;
        }

        Button Bouton(string texte, bool fort, Action action)
        {
            var b = Briques.Action(L.T(texte), fort, (s, e) => { if (!rempli) return; action(); Charger(); });
            b.HorizontalAlignment = HorizontalAlignment.Left; b.Margin = new Thickness(0, 4, 8, 4);
            return b;
        }
    }
    // Décisions pures de « Premiers réglages » (U7a, dossier de conception U7), testées par tests\rendu-pilote.ps1. L'assistant
    // n'est jamais élevé ; dans cette étape il ne fait que lire et renvoyer vers les pages ; fermer ne change rien
    public static class VueAssistantFluent
    {
        public const string Cle = "Premiers réglages";
        public static readonly string[] Etapes = { "Bienvenue", "Vérification", "Apprentissage", "Qui prévenir", "Réponses automatiques", "Résumé" };

        // Repère par utilisateur, écrit par l'interface non élevée : « assistant déjà proposé », jamais une donnée de sécurité
        public static string CheminRepere()
        {
            return System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "deR4Tizer", "premiers-reglages.txt");
        }

        public static bool RepereExiste(string chemin) { try { return System.IO.File.Exists(chemin); } catch { return false; } }

        // « termine » ou « plus_tard » seulement ; échec d'écriture : l'assistant sera reproposé, sans autre effet. Jamais en
        // administrateur : ce dossier est contrôlé par les programmes non élevés du compte (jonction, lien), et l'assistant ne
        // s'y ouvre jamais d'office (relecture et audit de #151, constat 4, S151-01)
        public static bool EcrireRepere(string chemin, string sortie, bool administrateur)
        {
            if (administrateur || (sortie != "termine" && sortie != "plus_tard")) return false;
            try
            {
                System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(chemin));
                System.IO.File.WriteAllText(chemin, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture) + " " + sortie);
                return true;
            }
            catch { return false; }
        }

        // Ouverture automatique : pas si déjà proposé, si l'interface tourne en administrateur, sans source (rendu de test),
        // si une page est demandée, ou au démarrage caché
        public static bool DoitProposer(bool repere, bool administrateur, bool source, bool pageDemandee, bool cache)
        {
            return !repere && !administrateur && source && !pageDemandee && !cache;
        }

        // Trois cas : en cours, terminé, et « pas d'apprentissage automatique » (début égal à la fin : le poste avait déjà des
        // alertes), que l'écran d'aujourd'hui affichait « terminé » (dossier U7, constat). Textes fidèles à apprentissage.rs
        // (decider, filtrer) : pendant l'apprentissage, toute alerte non critique sans signal fort est notée en information et
        // mémorisée, comportement nouveau compris (relecture de #151, constat 1)
        public static string TexteApprentissage(EtatApprentissage app, bool illisible, DateTime maintenant)
        {
            bool en = L.En;
            if (app == null && illisible) return en ? "apprentissage.json unreadable: the learning state is unknown." : "apprentissage.json illisible : l'état de l'apprentissage est inconnu.";
            if (app == null) return en ? "Learning state not published by the service yet: nothing is concluded." : "État de l'apprentissage pas encore publié par le service : rien n'est conclu.";
            int appris = (app.Appris ?? new List<string>()).Count;
            if (!string.IsNullOrEmpty(app.Fin) && app.Debut == app.Fin)
                return en ? "No automatic learning: this computer already had alerts when deR4Tizer was installed; every non-critical alert is reported as is."
                          : "Pas d'apprentissage automatique : ce poste avait déjà des alertes à l'installation ; toute alerte non critique est dite telle quelle.";
            if (string.CompareOrdinal(maintenant.ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture), app.Fin ?? "") < 0)
                return string.Format(en ? "Learning until {0}: {1} behaviour(s) learned. Until then, every non-critical alert is recorded as information and its behaviour learned, new behaviours included, except strong signals (downloaded code, LOLBin, backup deletion…); critical alerts are never softened."
                                        : "Apprentissage en cours jusqu'au {0} : {1} comportement(s) appris. D'ici là, toute alerte non critique est notée en information et son comportement mémorisé, comportement nouveau compris, sauf les signaux forts (code téléchargé, LOLBin, suppression des sauvegardes…) ; les alertes critiques ne sont jamais adoucies.", Canal.Visible(app.Fin), appris);
            return string.Format(en ? "Learning finished on {0}: {1} behaviour(s) learned. A non-critical alert for a learned behaviour is recorded as information, unless it is a strong signal; any other alert, and every critical alert, remains an alert."
                                    : "Apprentissage terminé le {0} : {1} comportement(s) appris. Une alerte non critique d'un comportement appris est notée en information, sauf signal fort ; toute autre alerte, et toute alerte critique, reste une alerte.", Canal.Visible(app.Fin), appris);
        }

        static List<string> Canaux(Config c)
        {
            var n = c == null ? null : c.Notifications;
            var l = new List<string>();
            if (n == null) return l;
            if (n.Ntfy) l.Add("ntfy");
            if (n.Teams) l.Add("Teams");
            if (n.Smtp) l.Add(L.En ? "e-mail" : "e-mail");
            return l;
        }

        public static bool PersonnePrevenu(Config c, bool illisible) { return !illisible && c != null && Canaux(c).Count == 0; }

        // Jamais « le prestataire sera prévenu » : ce qui est activé et ce que le service a réellement envoyé
        public static string TexteQuiPrevenir(Config c, bool illisible, EtatNotifications e, bool envoisIllisibles)
        {
            bool en = L.En;
            if (illisible || c == null) return en ? "config.json unreadable: who is notified is unknown." : "config.json illisible : on ne sait pas qui est prévenu.";
            var canaux = Canaux(c);
            // Syslog n'est pas une personne prévenue, mais il est dit (relecture de #151, remarque R1)
            string siem = c.Syslog != null && c.Syslog.Actif ? " " + (en ? "Alerts are forwarded to a SIEM (syslog): someone must be watching it." : "Les alertes partent vers un SIEM (syslog) : quelqu'un doit le surveiller.") : "";
            if (canaux.Count == 0) return (en ? "Nobody is notified of alerts: no channel is turned on (ntfy, Teams or e-mail)." : "Personne n'est prévenu des alertes : aucun canal n'est activé (ntfy, Teams ou e-mail).") + siem;
            string niveau = c.Notifications.NiveauMin ?? "Critique";
            string s = string.Format(en ? "Channels turned on: {0}, from level {1}." : "Canaux activés : {0}, à partir du niveau {1}.", string.Join(", ", canaux), Canal.Visible(L.T(niveau))) + siem;
            // notifications.json illisible : jamais « aucun message envoyé » (relecture de #151, constat 3)
            if (e == null && envoisIllisibles)
                return s + " " + (en ? "notifications.json unreadable: whether a message was sent is unknown." : "notifications.json illisible : on ne sait pas si un message est parti.");
            if (e == null || e.Envoyes == 0)
                return s + " " + (en ? "No message sent yet: send a test message from Settings." : "Aucun message envoyé pour l'instant : envoyez un message de test depuis Réglages.");
            return s + " " + ActionsReglages.TexteNotifications(e);
        }

        // Réponses qui agissent seules : les deux de niveau 3 et l'IPS (niveau 2, désactivé par défaut, bloque 24 h sans
        // confirmation), état lu et durées de docs/reponse/politique.md ; illisible : inconnu (relecture de #151, constat 2)
        public static List<string> TexteReponses(Config c, bool illisible)
        {
            bool en = L.En;
            if (illisible || c == null) return new List<string> { ActionsReglages.ConfigIllisible() };
            Func<bool, string> etat = b => b ? (en ? "on" : "activé") : (en ? "off" : "désactivé");
            return new List<string>
            {
                string.Format(en ? "Automatic firewall block of Spamhaus DROP and Feodo Tracker addresses: {0} (lifted after 7 days, or earlier if the address leaves the list)."
                                 : "Blocage automatique au pare-feu des adresses Spamhaus DROP et Feodo Tracker : {0} (levé après 7 jours, ou plus tôt si l'adresse sort de la liste).", etat(c.BlocageAutoMenaces)),
                string.Format(en ? "Automatic suspension of a program that touches the decoy files: {0} (never resumed automatically; the critical alert is repeated after 2 h, then every 24 h)."
                                 : "Suspension automatique d'un programme qui touche aux fichiers leurres : {0} (jamais reprise automatiquement ; l'alerte critique est relancée au bout de 2 h, puis toutes les 24 h).", etat(c.ReponseAutoRancongiciel)),
                string.Format(en ? "Intrusion prevention (IPS), blocking at the firewall without confirmation: {0} (block lifted after 24 h; off by default, set on the Detection page)."
                                 : "Prévention d'intrusion (IPS), blocage au pare-feu sans confirmation : {0} (blocage levé après 24 h ; désactivée par défaut, se règle dans la page Détection).", etat(c.Ips))
            };
        }

        // Vérification : collectes en panne dites avec leur conséquence ; état illisible : rien ne prouve que la surveillance tourne
        public static List<string> Verification(Etat e, bool lu, bool illisible)
        {
            bool en = L.En;
            var l = new List<string>();
            if (!lu) { l.Add(L.T("Lecture en cours…")); return l; }
            if (e == null)
            {
                l.Add(illisible ? (en ? "Service state unreadable: nothing proves that monitoring is running." : "État du service illisible : rien ne prouve que la surveillance fonctionne.")
                                : (en ? "Service state not published yet: is the service running? (Health page)" : "État du service pas encore publié : le service tourne-t-il ? (page Santé)"));
                return l;
            }
            var pannes = Couverture.EnPannes(e);
            if (pannes.Count == 0) l.Add(en ? "No data collection reported as unavailable." : "Aucune collecte signalée indisponible.");
            foreach (var p in pannes) l.Add(Canal.Visible(Couverture.Decrire(p)));
            return l;
        }

        // Ce qui reste à faire ; jamais « tout est en ordre »
        public static List<string> ResteAFaire(Etat e, bool etatLu, bool etatIllisible, Config c, bool configIllisible)
        {
            bool en = L.En;
            var l = new List<string>();
            if (etatLu && e == null) l.Add(en ? "The service state cannot be read: check that the service is running (Health page)." : "L'état du service ne se lit pas : vérifiez que le service tourne (page Santé).");
            int pannes = e == null ? 0 : Couverture.EnPannes(e).Count;
            if (pannes > 0) l.Add(string.Format(en ? "{0} data collection(s) unavailable: some detections cannot fire (Health page)." : "{0} collecte(s) indisponible(s) : des détections ne peuvent pas se déclencher (page Santé).", pannes));
            if (PersonnePrevenu(c, configIllisible)) l.Add(en ? "Nobody is notified of alerts: set up alert forwarding (Settings)." : "Personne n'est prévenu des alertes : configurez la remontée des alertes (Réglages).");
            if (configIllisible) l.Add(ActionsReglages.ConfigIllisible());
            return l;
        }

        // Action offerte à l'étape Apprentissage (U7b) : terminer, seulement s'il est en cours ; jamais recommencer, qui note en
        // information pendant 7 jours toute alerte non critique sans signal fort et apprendrait un programme malveillant actif à
        // ce moment (relecture de #152, constat 1) : il reste dans Réglages, avec l'avertissement ci-dessous ; rien quand le
        // service l'a écarté (début égal à la fin), ni sans état lu
        public static string OperationApprentissage(EtatApprentissage app, bool illisible, DateTime maintenant)
        {
            if (app == null || illisible || string.IsNullOrEmpty(app.Fin) || app.Debut == app.Fin) return null;
            bool enCours = string.CompareOrdinal(maintenant.ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture), app.Fin) < 0;
            return enCours ? "terminer" : null;
        }

        public static string AvertissementRecommencer()
        {
            return L.En ? "Restarting learning (Settings) forgets learned behaviours and, for 7 days, records every non-critical alert without a strong signal as information and learns it, including a malicious program active at that time: only do it on a computer known to be clean."
                        : "Recommencer l'apprentissage (Réglages) oublie les comportements appris et, pendant 7 jours, note en information et mémorise toute alerte non critique sans signal fort, y compris celle d'un programme malveillant actif à ce moment : à faire seulement sur un poste que l'on sait sain.";
        }

        // Réglages des réponses automatiques que l'assistant peut changer : les deux de niveau 3, par la commande de la page
        // Menaces ; l'IPS reste dans la page Détection
        public static readonly string[] ReglagesReponses = { "BlocageAutoMenaces", "ReponseAutoRancongiciel" };

        // Commandes que l'assistant montre dans la confirmation : construites par les fonctions mêmes qui les envoient (pages
        // Réglages et Menaces, listes fermées), elles ne peuvent pas diverger (audit de #152, S152-01)
        public static Commande CommandeApprentissage(string operation) { return ActionsReglages.CommandeApprentissage(operation); }
        public static Commande CommandeReglage(string reglage, bool valeur) { return ActionsProtection.CommandeReglage(reglage, valeur); }

        // Après un bouton : « demandé », jamais « fait » ; l'état affiché est relu dans les fichiers du service
        public static string Demande(string quoi)
        {
            return string.Format(L.En ? "Requested, if you confirmed it: {0}. The state shown is read again from the service files and may take a few seconds to change." : "Demandé, si vous l'avez confirmé : {0}. L'état affiché est relu dans les fichiers du service et peut mettre quelques secondes à changer.", quoi);
        }

        public static string Avertissement()
        {
            return L.En ? "These steps say what deR4Tizer sees, not that the computer is healthy: the Overview and the alerts remain the reference."
                        : "Ces étapes disent ce que deR4Tizer voit, pas que le poste est sain : la Vue d'ensemble et les alertes restent la référence.";
        }
    }

    // Page « Premiers réglages » (U7a, U7b) : six étapes ; « Suivant » et « Retour » n'envoient rien ; « Plus tard » et
    // « Terminer » n'écrivent que le repère ; fermer ou cliquer ailleurs ne change rien (l'assistant reste proposé). Seuls
    // boutons d'action (U7b) : terminer ou recommencer l'apprentissage, activer ou désactiver les deux réponses automatiques
    // de niveau 3, par les commandes des pages Réglages et Menaces, chacune confirmée
    class PageAssistantFluent : Grid
    {
        readonly ISourceEtat source;
        readonly Action<string> ouvrir;
        readonly string repere;
        readonly TextBlock entete = new TextBlock { FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, 0, 0, 4) };
        readonly TextBlock titre = new TextBlock { FontSize = 18, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 12) };
        readonly StackPanel contenu = new StackPanel { MaxWidth = 760, HorizontalAlignment = HorizontalAlignment.Left };
        readonly WrapPanel boutons = new WrapPanel { Margin = new Thickness(0, 12, 0, 0) };
        int etape, enCours, chargement;
        bool lu, etatIllisible, configIllisible, apprentissageIllisible, notificationsIllisibles;
        Etat etat; Config config; EtatApprentissage apprentissage; EtatNotifications notifications;

        public PageAssistantFluent(ISourceEtat source, Action<string> ouvrir, string repere)
        {
            this.source = source; this.ouvrir = ouvrir; this.repere = repere;
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            RowDefinitions.Add(new RowDefinition());
            RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Children.Add(entete);
            Grid.SetRow(titre, 1); Children.Add(titre);
            var defile = new ScrollViewer { Content = contenu, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            Grid.SetRow(defile, 2); Children.Add(defile);
            Grid.SetRow(boutons, 3); Children.Add(boutons);
            Loaded += (s, e) => Charger();
            Afficher();
        }

        // Lecture des fichiers du service hors du fil de l'interface ; aucune écriture
        internal void Charger()
        {
            if (System.Threading.Interlocked.CompareExchange(ref enCours, 1, 0) != 0) return;
            int numero = ++chargement;
            System.Threading.ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    bool absentEtat, ci;
                    var e = LectureFluent.Lire<Etat>("etat.json", out absentEtat);
                    var c = ActionsProtection.LireConfig(out ci);
                    // Accès refusé ou contenu illisible n'est pas absent (S142-01, relecture de #151, constat 3)
                    bool absentApp, absentNotif;
                    var a = LectureFluent.Lire<EtatApprentissage>("apprentissage.json", out absentApp);
                    var n = LectureFluent.Lire<EtatNotifications>("notifications.json", out absentNotif);
                    Dispatcher.BeginInvoke((Action)(() =>
                    {
                        if (numero != chargement) return;
                        lu = true; etat = e; etatIllisible = !absentEtat && e == null; config = c; configIllisible = ci; apprentissage = a; notifications = n;
                        apprentissageIllisible = !absentApp && a == null; notificationsIllisibles = !absentNotif && n == null;
                        Afficher();
                    }));
                }
                finally { System.Threading.Interlocked.Exchange(ref enCours, 0); }
            });
        }

        TextBlock Texte(string t, bool secondaire = false)
        {
            return new TextBlock { Text = t, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8), Foreground = Jetons.Pinceau(secondaire ? Jetons.TexteSecondaire : Jetons.Texte) };
        }

        Button Lien(string texte, string page)
        {
            var b = Briques.Action(texte, false, (s, e) => { if (ouvrir != null) ouvrir(page); });
            b.HorizontalAlignment = HorizontalAlignment.Left; b.Margin = new Thickness(0, 4, 8, 4);
            return b;
        }

        internal void Afficher()
        {
            bool en = L.En;
            entete.Text = string.Format(en ? "Step {0} of {1} · nothing changes without you" : "Étape {0} sur {1} · rien ne change sans vous", etape + 1, VueAssistantFluent.Etapes.Length);
            titre.Text = L.T(VueAssistantFluent.Etapes[etape]);
            contenu.Children.Clear();
            if (!string.IsNullOrEmpty(demande) && demandeEtape == etape) contenu.Children.Add(Texte(demande, true));
            switch (etape)
            {
                case 0:
                    contenu.Children.Add(Texte(en ? "deR4Tizer watches this computer alongside Microsoft Defender: connections, programs, autostart, firewall, local network. It is neither an antivirus nor a replacement for Defender."
                                                  : "deR4Tizer surveille ce poste aux côtés de Microsoft Defender : connexions, programmes, démarrage automatique, pare-feu, réseau local. Ce n'est ni un antivirus ni un remplaçant de Defender."));
                    contenu.Children.Add(Texte(en ? "These six steps show what deR4Tizer sees and the settings that matter. The Learning and Automatic responses steps also have their buttons; every change asks for an administrator's confirmation (Windows UAC, or deR4Tizer's own confirmation when the interface already runs as administrator)."
                                                  : "Ces six étapes montrent ce que deR4Tizer voit et les réglages qui comptent. Les étapes Apprentissage et Réponses automatiques ont aussi leurs boutons ; chaque changement demande la confirmation d'un administrateur (contrôle de compte de Windows, ou confirmation de deR4Tizer quand l'interface tourne déjà en administrateur)."));
                    contenu.Children.Add(Texte(en ? "« Later » closes them; they can be opened again from Settings." : "« Plus tard » les referme ; elles se rouvrent depuis Réglages.", true));
                    break;
                case 1:
                    if (source != null)
                    {
                        int g;
                        var points = VueEnsembleFluent.AvecCompteurs(source.Points(), source.Badges());
                        contenu.Children.Add(Texte(VueEnsembleFluent.Resume(points, out g)));
                        foreach (var p in points.Where(x => x.Gravite > 0)) contenu.Children.Add(Texte("· " + p.Texte));
                    }
                    contenu.Children.Add(Briques.Titre(en ? "Data collections" : "Collectes", 8));
                    foreach (var l in VueAssistantFluent.Verification(etat, lu, etatIllisible)) contenu.Children.Add(Texte(l));
                    contenu.Children.Add(Texte(VueAssistantFluent.Avertissement(), true));
                    contenu.Children.Add(Lien(en ? "Open the Health page" : "Ouvrir la page Santé", "Santé"));
                    break;
                case 2:
                    contenu.Children.Add(Texte(!lu ? L.T("Lecture en cours…") : VueAssistantFluent.TexteApprentissage(apprentissage, apprentissageIllisible, DateTime.Now)));
                    string op = lu ? VueAssistantFluent.OperationApprentissage(apprentissage, apprentissageIllisible, DateTime.Now) : null;
                    if (op == "terminer")
                        contenu.Children.Add(Agir(en ? "End learning now" : "Terminer l'apprentissage maintenant", VueAssistantFluent.CommandeApprentissage(op),
                            () => ActionsReglages.Apprentissage(op), en ? "end of learning" : "fin de l'apprentissage"));
                    contenu.Children.Add(Texte(VueAssistantFluent.AvertissementRecommencer(), true));
                    contenu.Children.Add(Texte(en ? "Learned exceptions are managed in Settings." : "Les exceptions apprises se gèrent dans Réglages.", true));
                    contenu.Children.Add(Lien(en ? "Open Settings" : "Ouvrir Réglages", "Réglages"));
                    break;
                case 3:
                    contenu.Children.Add(Texte(!lu ? L.T("Lecture en cours…") : VueAssistantFluent.TexteQuiPrevenir(config, configIllisible, notifications, notificationsIllisibles)));
                    contenu.Children.Add(Lien(en ? "Set up alert forwarding in Settings" : "Configurer la remontée dans Réglages", "Réglages"));
                    break;
                case 4:
                    if (!lu) contenu.Children.Add(Texte(L.T("Lecture en cours…")));
                    else foreach (var l in VueAssistantFluent.TexteReponses(config, configIllisible)) contenu.Children.Add(Texte(l));
                    contenu.Children.Add(Texte(en ? "Only these three responses act on their own; every other response waits for a human decision." : "Seules ces trois réponses agissent seules ; toute autre réponse attend une décision humaine.", true));
                    if (lu && !configIllisible && config != null)
                        foreach (var r in VueAssistantFluent.ReglagesReponses)
                        {
                            bool actif = r == "BlocageAutoMenaces" ? config.BlocageAutoMenaces : config.ReponseAutoRancongiciel;
                            string nom = r == "BlocageAutoMenaces" ? (en ? "automatic block of listed addresses" : "blocage automatique des adresses listées") : (en ? "automatic suspension by decoy files" : "suspension automatique par les leurres");
                            string reglage = r;
                            contenu.Children.Add(Agir((actif ? (en ? "Turn off: " : "Désactiver : ") : (en ? "Turn on: " : "Activer : ")) + nom, VueAssistantFluent.CommandeReglage(reglage, !actif),
                                () => ActionsProtection.ChangerReglage(reglage, !actif), (actif ? (en ? "turn off " : "désactiver ") : (en ? "turn on " : "activer ")) + nom));
                        }
                    contenu.Children.Add(Lien(en ? "See them on the Threats page" : "Les voir dans la page Menaces", "Menaces"));
                    contenu.Children.Add(Lien(en ? "Change the IPS on the Detection page" : "Changer l'IPS dans la page Détection", "Détection"));
                    break;
                default:
                    if (!lu) { contenu.Children.Add(Texte(L.T("Lecture en cours…"))); break; }
                    var reste = VueAssistantFluent.ResteAFaire(etat, lu, etatIllisible, config, configIllisible);
                    contenu.Children.Add(Briques.Titre(en ? "Still to do" : "Reste à faire", 0));
                    if (reste.Count == 0) contenu.Children.Add(Texte(en ? "Nothing reported by these steps." : "Rien de signalé par ces étapes."));
                    foreach (var l in reste) contenu.Children.Add(Texte("· " + l));
                    contenu.Children.Add(Texte(VueAssistantFluent.Avertissement(), true));
                    break;
            }
            boutons.Children.Clear();
            Func<string, bool, Action, Button> bouton = (t, fort, a) => { var b = Briques.Action(t, fort, (s, e) => a()); b.HorizontalAlignment = HorizontalAlignment.Left; b.Margin = new Thickness(0, 0, 8, 0); return b; };
            if (etape > 0) boutons.Children.Add(bouton(en ? "Back" : "Retour", false, () => { etape--; Afficher(); }));
            if (etape < VueAssistantFluent.Etapes.Length - 1) boutons.Children.Add(bouton(en ? "Next" : "Suivant", true, () => { etape++; Afficher(); }));
            else boutons.Children.Add(bouton(en ? "Finish" : "Terminer", true, () => Sortir("termine")));
            boutons.Children.Add(bouton(en ? "Later" : "Plus tard", false, () => Sortir("plus_tard")));
        }

        // Seul effet : le repère par utilisateur ; aucune commande au service
        void Sortir(string sortie)
        {
            VueAssistantFluent.EcrireRepere(repere, sortie, Canal.EstAdmin());
            if (ouvrir != null) ouvrir(NavigationFluent.VueEnsemble);
        }

        // Bouton d'action (U7b) : interface élevée, l'assistant montre lui-même la confirmation détaillée, que l'envoi direct au
        // canal ne montre pas pour ces commandes ; non élevée, la confirmation passe par la copie élevée (UAC) comme partout. Le résultat
        // est dit « demandé » et l'état relu
        Button Agir(string texte, Commande commande, Action action, string quoi)
        {
            var b = Briques.Action(texte, true, (s, e) =>
            {
                if (commande == null) return;
                if (Canal.EstAdmin())
                    using (var fenetre = Canal.FenetreConfirmation(Canal.Decrire(commande), L.En))
                        if (fenetre.ShowDialog() != System.Windows.Forms.DialogResult.Yes) return;
                action();
                demande = VueAssistantFluent.Demande(quoi); demandeEtape = etape;
                Afficher(); Charger();
            });
            b.HorizontalAlignment = HorizontalAlignment.Left; b.Margin = new Thickness(0, 4, 8, 4);
            return b;
        }

        string demande; int demandeEtape = -1;

        internal int Etape { get { return etape; } }
    }
}
