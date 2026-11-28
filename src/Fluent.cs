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
        // Accessibilité : en contraste élevé de Windows, la palette suit les couleurs système ; sinon le thème sombre.
        public static readonly bool ContrasteEleve = SystemParameters.HighContrast;
        public static readonly Color Fond, Carte, Surface, Texte, TexteSecondaire, Accent, TexteSurAccent, Danger, Attention, Succes, Separateur;
        static Jetons()
        {
            if (ContrasteEleve)
            {
                Fond = SystemColors.WindowColor; Carte = SystemColors.ControlColor; Surface = SystemColors.ControlColor;
                Texte = SystemColors.WindowTextColor; TexteSecondaire = SystemColors.GrayTextColor;
                Accent = SystemColors.HighlightColor; TexteSurAccent = SystemColors.HighlightTextColor;
                Separateur = SystemColors.WindowTextColor;
                Danger = SystemColors.WindowTextColor; Attention = SystemColors.WindowTextColor; Succes = SystemColors.WindowTextColor;
            }
            else
            {
                Fond = Hex("#141518"); Carte = Hex("#1E2024"); Surface = Hex("#262A30");
                Texte = Hex("#E6E8EB"); TexteSecondaire = Hex("#9AA3AF"); Accent = Hex("#3BA7F0"); TexteSurAccent = Hex("#0B1220");
                Danger = Hex("#F0605A"); Attention = Hex("#F2A93B"); Succes = Hex("#2FBF71"); Separateur = Hex("#2E3238");
            }
        }
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

        // Indicateur de focus clavier partagé (accessibilité) : un cadre accent — ou la surbrillance système en contraste
        // élevé — autour de l'élément focalisé au clavier. Ne s'affiche pas à la souris (comportement natif de FocusVisualStyle).
        static Style styleFocus;
        public static Style StyleFocus()
        {
            if (styleFocus != null) return styleFocus;
            var modele = new ControlTemplate();
            var rect = new FrameworkElementFactory(typeof(System.Windows.Shapes.Rectangle));
            rect.SetValue(System.Windows.Shapes.Shape.StrokeProperty, Pinceau(Accent));
            rect.SetValue(System.Windows.Shapes.Shape.StrokeThicknessProperty, 2.0);
            rect.SetValue(System.Windows.Shapes.Rectangle.RadiusXProperty, Rayon);
            rect.SetValue(System.Windows.Shapes.Rectangle.RadiusYProperty, Rayon);
            rect.SetValue(FrameworkElement.MarginProperty, new Thickness(-2));
            rect.SetValue(UIElement.SnapsToDevicePixelsProperty, true);
            modele.VisualTree = rect;
            var s = new Style();
            s.Setters.Add(new Setter(Control.TemplateProperty, modele));
            s.Seal();
            styleFocus = s;
            return s;
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
                g("Protection", new[] { "Blocages", "", "Quarantaine", "", "Menaces", "", "Baseline", "", "Pare-feu", "", "Navigation", "" }),
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
        // Vert dans l'en-tête (service en ligne, Defender OK) : seul fait qui a droit à la puce verte d'« En ordre » ;
        // une information (cyan, gris) n'est pas un état sain (relecture de la refonte, défaut 3)
        public bool Sain;
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
        // État du service pour le pied du rail : 0 en ligne et état frais, 1 à vérifier (état ancien ou illisible),
        // 2 arrêté ou non installé (relecture de la refonte, défaut 2 : le point vert ne suivait que la présence d'un texte)
        int SanteService();
        // La zone de notification montre la coquille (page demandée, ou celle ouverte si null)
        void Rattacher(Action<string> montrer);
        // Panneau « Protections » (T-18) : fichiers d'état relus par la fenêtre d'aujourd'hui (lecture seule) ; null : rien
        EntreesProtections Protections();
        // Comptes de la Vue d'ensemble (T-4) : alertes critiques non lues, incidents non clos ; null : rien de compté
        ComptesVue Comptes();
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
            ajouter("Règle", string.IsNullOrEmpty(a.Regle) ? null : a.Regle + (string.IsNullOrEmpty(a.Collecte) ? "" : " (" + L.T("collecte présumée") + VueEnsembleFluent.DeuxPoints + Couverture.Nom(a.Collecte) + ")"), false);
            // Technique et conseil : textes fixes du service (mitre.rs), traduits par la table (point 3 de la revue)
            ajouter("Technique", L.Mitre(a.Mitre), false);
            ajouter("Que faire", L.T(a.Conseil), false);
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
        // d'un compteur rouge (capture en VM d'U2). Alertes et incidents sont comptés à part (ComptesVue, T-4) : une alerte
        // critique non lue et un incident critique non clos sont « à traiter », avec le même nombre que leurs tuiles
        public static List<PointEtat> AvecCompteurs(IList<PointEtat> points, IDictionary<string, PointEtat> badges, ComptesVue comptes)
        {
            var r = new List<PointEtat>(points ?? new List<PointEtat>());
            foreach (var t in TuilesComptes(comptes)) r.Add(new PointEtat { Texte = t.Nombre ? t.Libelle + DeuxPoints + t.Valeur : t.Libelle, Gravite = t.Gravite });
            if (badges == null) return r;
            foreach (var g in NavigationFluent.Groupes())
                foreach (var e in g.Entrees)
                {
                    PointEtat b;
                    if (!Comptees.Contains(e.Cle) && badges.TryGetValue(e.Cle, out b) && b.Gravite >= 1)
                    {
                        // « Baseline : 12% » est illisible : phrase claire (le détail reste la page Baseline).
                        string t = e.Cle == "Baseline"
                            ? string.Format(L.T("Réglages de sécurité recommandés : {0} appliqués"), b.Texte)
                            : L.T(e.Cle) + DeuxPoints + b.Texte;
                        r.Add(new PointEtat { Texte = t, Gravite = 1 });
                    }
                }
            return r;
        }

        // Une tuile : un compteur de la navigation (« à surveiller »), ou un compte d'alertes ou d'incidents (T-4, « à traiter »
        // s'il est critique), qui ouvre sa page
        public class TuileVue { public string Cle; public string Icone; public string Valeur; public string Libelle; public bool Nombre; public int Gravite = 1; public int Section = -1; }

        // Contrôle de mise à jour en échec (maquette t18-2) : maj.json dit un contrôle en échec (Controle « EchecRecent » ou
        // « EchecProlonge »), une issue d'échec (StatutCode) ou une installation précédente en échec. Jamais retenu si l'état
        // du service est ancien ou absent (même règle que le panneau « Protections », prérelecture de #310, D1)
        public static bool MajEnEchec(EtatMaj m, Etat etat, DateTime maintenant, out string depuis)
        {
            depuis = "";
            if (m == null || etat == null || VueSante.EtatAncien(etat, maintenant)) return false;
            bool echec = m.EchecInstallationPrecedente || m.Controle == "EchecRecent" || m.Controle == "EchecProlonge" || VueProtectionsFluent.EchecsMaj.Contains(m.StatutCode ?? "");
            if (!echec) return false;
            depuis = Canal.Visible(!string.IsNullOrEmpty(m.EchecDepuis) ? m.EchecDepuis : m.VerifieLe ?? "");
            return true;
        }

        // Pages dont la tuile vient de ComptesVue, jamais du compteur de la navigation (plafonné à « à surveiller »)
        static readonly string[] Comptees = { "Alertes", "Incidents" };

        static string IconeDe(string cle)
        {
            return NavigationFluent.Groupes().SelectMany(g => g.Entrees).Where(e => e.Cle == cle).Select(e => e.Icone).FirstOrDefault() ?? "";
        }

        static string Nombre(int n) { return n > 999 ? "999+" : n.ToString(); }

        // Tuiles des comptes (T-4) : incidents critiques non clos (risque confirmé, comme la page Incidents) à traiter, sinon
        // incidents non clos à surveiller ; alertes critiques non lues à traiter (une alerte non critique non lue reste comme
        // aujourd'hui hors des tuiles). Le libellé dit aussi le total, pour que le nombre de la tuile ne passe pas pour lui
        public static List<TuileVue> TuilesComptes(ComptesVue c)
        {
            var l = new List<TuileVue>();
            if (c == null) return l;
            bool en = L.En;
            if (c.IncidentsIllisibles)
                l.Add(new TuileVue { Cle = "Incidents", Icone = IconeDe("Incidents"), Valeur = "?", Nombre = false, Gravite = 1,
                    Libelle = en ? "Incidents: suivi-incidents.json unreadable, nothing is concluded" : "Incidents : suivi-incidents.json illisible, rien n'est conclu" });
            else if (c.IncidentsCritiques > 0)
                l.Add(new TuileVue { Cle = "Incidents", Icone = IconeDe("Incidents"), Valeur = Nombre(c.IncidentsCritiques), Nombre = true, Gravite = 2,
                    Libelle = string.Format(en ? "Critical incidents open ({0} open in all)" : "Incidents critiques ouverts ({0} ouverts en tout)", Nombre(c.IncidentsOuverts)) });
            else if (c.IncidentsOuverts > 0)
                l.Add(new TuileVue { Cle = "Incidents", Icone = IconeDe("Incidents"), Valeur = Nombre(c.IncidentsOuverts), Nombre = true, Gravite = 1,
                    Libelle = en ? "Incidents open (none critical)" : "Incidents ouverts (aucun critique)" });
            if (c.AlertesCritiquesNonLues > 0)
                l.Add(new TuileVue { Cle = "Alertes", Icone = IconeDe("Alertes"), Valeur = Nombre(c.AlertesCritiquesNonLues), Nombre = true, Gravite = 2,
                    Libelle = string.Format(en ? "Critical alerts not yet read ({0} unread in all)" : "Alertes critiques non lues ({0} non lues en tout)", Nombre(Math.Max(c.AlertesNonLues, c.AlertesCritiquesNonLues))) });
            // Contrôle de mise à jour en échec (maquette t18-2) : à surveiller, ouvre Réglages, section « Mises à jour »
            if (c.MajEnEchec)
                l.Add(new TuileVue { Cle = "Réglages", Icone = IconeDe("Réglages"), Valeur = "!", Nombre = false, Gravite = 1, Section = Array.IndexOf(VueReglagesFluent.Sections, "Mises à jour"),
                    Libelle = string.IsNullOrEmpty(c.MajDepuis) ? (en ? "Update check failed" : "Contrôle de mise à jour en échec")
                                                                : string.Format(en ? "Update check failed since {0}" : "Contrôle de mise à jour en échec depuis le {0}", c.MajDepuis) });
            return l;
        }

        // Ce que la Vue d'ensemble affiche, rangé : chaque fait de l'en-tête dans la section de sa gravité (aucun n'est
        // perdu), plus les compteurs de la navigation en tuiles. Resume(AvecCompteurs) compte exactement ces éléments : la
        // refonte avait remplacé la liste « à surveiller » par les seules tuiles et perdu les faits orange de l'en-tête
        // (Defender sans protection contre la falsification, exposition, journal DNS inactif…) que la tête comptait encore
        // (relecture de la refonte, défaut 1)
        public class SectionsVue
        {
            public List<PointEtat> ATraiter = new List<PointEtat>(), ASurveiller = new List<PointEtat>(), EnOrdre = new List<PointEtat>();
            public List<TuileVue> Tuiles = new List<TuileVue>();
            // Tuiles « à traiter » (T-4) : incidents critiques non clos, alertes critiques non lues
            public List<TuileVue> TuilesATraiter = new List<TuileVue>();
        }

        public static SectionsVue Sections(IList<PointEtat> points, IDictionary<string, PointEtat> badges, ComptesVue comptes)
        {
            var s = new SectionsVue();
            foreach (var p in points ?? new List<PointEtat>())
                (p.Gravite >= 2 ? s.ATraiter : p.Gravite == 1 ? s.ASurveiller : s.EnOrdre).Add(p);
            foreach (var t in TuilesComptes(comptes)) (t.Gravite >= 2 ? s.TuilesATraiter : s.Tuiles).Add(t);
            if (badges == null) return s;
            foreach (var g in NavigationFluent.Groupes())
                foreach (var e in g.Entrees)
                {
                    PointEtat b;
                    if (!Comptees.Contains(e.Cle) && badges.TryGetValue(e.Cle, out b) && b.Gravite >= 1)
                        s.Tuiles.Add(new TuileVue { Cle = e.Cle, Icone = e.Icone, Valeur = b.Texte ?? "", Libelle = e.Cle == "Baseline" ? L.T("Réglages de sécurité appliqués") : L.T(e.Cle), Nombre = EstNombre(b.Texte) });
                }
            return s;
        }

        // Compteur chiffré (« 3 », « 12% », « 999+ ») : en grand ; un mot (« LIVE », « EXPOSÉ ») reste à la taille du texte
        public static bool EstNombre(string t) { return !string.IsNullOrEmpty(t) && char.IsDigit(t[0]); }

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

    // Ce que lit le panneau « Protections » de la Vue d'ensemble (T-18) : fichiers publiés par le service, relus par la
    // fenêtre d'aujourd'hui ; null : absent ou illisible. Lecture seule : aucune commande, aucun réglage
    public class EntreesProtections
    {
        public Etat Etat;
        public Config Config;
        public bool ConfigIllisible;
        public EtatMaj Maj;
        public EtatFiltrage Filtrage;
        public EtatIds Ids;
        public EtatBaseline Baseline;
        public EtatRemontee Remontee;
        public EtatApprentissage Apprentissage;
        public DateTime Maintenant;
    }

    // Comptes de la Vue d'ensemble (T-4) : alertes non lues (comme le compteur de la page Alertes) et incidents non clos
    // (suivi-incidents.json ; critiques : risque confirmé, comme la page Incidents)
    public class ComptesVue
    {
        public int AlertesNonLues, AlertesCritiquesNonLues, IncidentsOuverts, IncidentsCritiques;
        // suivi-incidents.json présent mais illisible : rien n'est compté, et c'est dit (prérelecture de #310, D4)
        public bool IncidentsIllisibles;
        // Contrôle de mise à jour en échec et sa date (VueEnsembleFluent.MajEnEchec), maquette t18-2
        public bool MajEnEchec;
        public string MajDepuis;
    }

    // Une ligne du panneau « Protections » : état publié par le service, traduit ; un lien vers la page de la fonction
    public class LigneProtection
    {
        public string Cle;          // identifiant stable de la ligne
        public string Titre;
        public string Detail;
        public string Etat;         // libellé d'état, à droite
        public int Visuel;          // VueProtectionsFluent.Verifie, Eteint, Attention, Information, NonVerifiable
        public string Page;         // clé de navigation de la page où la fonction se règle
        public bool Experimental;
        public bool Recommande;
    }

    // Décisions pures du panneau « Protections » (T-18, maquettes validées le 2026-11-23) : l'état effectif publié par le
    // service, jamais un verdict global ; un champ absent (service plus ancien, fichier absent ou illisible) vaut « non
    // vérifiable », jamais « actif » ; éteinte, une fonction recommandée est orange, une autre grise ; une fonction
    // expérimentale n'est jamais recommandée (jamais orange parce qu'éteinte). Aucun bouton d'activation : un lien par ligne
    // vers la page de la fonction, où la même commande et la même confirmation s'appliquent
    public static class VueProtectionsFluent
    {
        public const int Verifie = 0, Eteint = 1, Attention = 2, Information = 3, NonVerifiable = 4;
        // Décision du mainteneur du 2026-11-23 : recommandées ; non recommandées : mise à jour automatique, syslog, API
        public static readonly string[] Recommandees = { "Rancongiciel", "BlocageListes", "Baseline", "Remontee" };
        public static readonly string[] Experimentales = { "Ips" };
        internal static readonly string[] EchecsMaj = { "AdresseRefusee", "ManifesteNonObtenu", "ManifesteInvalide", "ManifesteAncien", "SansCleEpinglee", "InstallationRefusee", "InstallationImpossible" };

        static string T(string fr, string en) { return L.En ? en : fr; }

        public static Color Couleur(int visuel)
        {
            return visuel == Verifie ? Jetons.Succes : visuel == Attention ? Jetons.Attention : visuel == Information ? Jetons.Accent : Jetons.TexteSecondaire;
        }

        // Légende, dans l'ordre des états
        public static string Legende(int visuel)
        {
            switch (visuel)
            {
                case Verifie: return T("actif et vérifié", "active and verified");
                case Eteint: return T("éteint par choix", "off by choice");
                case Attention: return T("activé sans effet, ou recommandé et éteint", "on without effect, or recommended and off");
                case Information: return T("information", "information");
                default: return T("non vérifiable (état non publié)", "not verifiable (state not published)");
            }
        }

        public static string Pied()
        {
            return T("Chaque fonction s'active depuis sa page, avec la même confirmation. Cette liste montre ce que publie le service, pas un verdict global.",
                     "Each feature is turned on from its page, with the same confirmation. This list shows what the service reports, not a global verdict.");
        }

        public static string Lien(string page) { return string.Format(T("Ouvrir {0}", "Open {0}"), L.T(page)); }

        static LigneProtection Nouvelle(string cle, string titre, string page)
        {
            return new LigneProtection { Cle = cle, Titre = titre, Page = page, Recommande = Recommandees.Contains(cle) && !Experimentales.Contains(cle), Experimental = Experimentales.Contains(cle) };
        }

        static LigneProtection Poser(LigneProtection l, int visuel, string etat, string detail)
        {
            l.Visuel = visuel; l.Etat = etat; l.Detail = detail ?? "";
            return l;
        }

        // Éteinte : orange si recommandée (jamais pour une expérimentale), grise sinon
        static LigneProtection Eteinte(LigneProtection l, string detail)
        {
            return l.Recommande && !l.Experimental
                ? Poser(l, Attention, T("Recommandé · désactivé", "Recommended · off"), detail)
                : Poser(l, Eteint, T("Désactivé", "Off"), detail);
        }

        static string NonPublieTexte() { return T("Le service ne publie pas cet état (version plus ancienne, ou fichier absent ou illisible) : rien n'est conclu.", "The service does not publish this state (older version, or file missing or unreadable): nothing is concluded."); }

        static LigneProtection NonPublie(LigneProtection l, bool reglageActif, string detail)
        {
            return Poser(l, NonVerifiable, reglageActif ? T("Activé · non vérifié", "On · not verified") : T("Non vérifiable", "Not verifiable"), detail ?? NonPublieTexte());
        }

        static string Ancien() { return T("État du service ancien (plus de 2 min) : ce qui suit peut ne plus être vrai ; service à vérifier (page Santé).", "Service state is old (over 2 min): this may no longer be true; check the service (Health page)."); }

        static string Absent() { return T("État du service absent ou illisible (etat.json) : le service tourne-t-il ? Rien n'est vérifié (page Santé).", "Service state missing or unreadable (etat.json): is the service running? Nothing is verified (Health page)."); }

        // Fichier publié souvent par le service (ids.json toutes les quelques secondes, filtrage-etat.json au moins toutes
        // les 5 min) : au-delà de 10 min, ou date illisible, il n'est plus tenu pour à jour (prérelecture de #310, D1)
        public const int DelaiFichierMinutes = 10;
        public static bool Frais(string misAJour, DateTime maintenant)
        {
            DateTime d;
            return DateTime.TryParseExact(misAJour ?? "", "yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out d)
                && Math.Abs((maintenant - d).TotalMinutes) <= DelaiFichierMinutes;
        }

        static string FichierAncien(string fichier) { return string.Format(T("{0} ancien (plus de 10 min) ou sans date : rien n'est conclu.", "{0} is old (over 10 min) or undated: nothing is concluded."), fichier); }

        // Réponse automatique, d'après le code publié (politique::etat_rancongiciel, etat_blocage_listes)
        static LigneProtection Reponse(LigneProtection l, string code, string actif, string partiel, string sansEffet, string eteinte)
        {
            switch (code ?? "")
            {
                case "Actif": return Poser(l, Verifie, T("Actif", "Active"), actif);
                case "Desactive": return Eteinte(l, eteinte);
                case "Partiel": return Poser(l, Attention, T("Actif en partie", "Partly active"), partiel);
                case "SansEffet": return Poser(l, Attention, T("Activé, sans effet", "On, no effect"), sansEffet);
                case "NonVerifiable": return NonPublie(l, true, T("Une source n'a pas encore été lue par le service : rien n'est conclu.", "A source has not been read by the service yet: nothing is concluded."));
                default: return NonPublie(l, false, null);
            }
        }

        static string NomCategorie(string libelle)
        {
            return libelle == "sécurité" ? VueNavigationFluent.NomCategorie("securite") : libelle == "publicité et pistage" ? VueNavigationFluent.NomCategorie("publicite") : Canal.Visible(libelle);
        }

        public static List<LigneProtection> Lignes(EntreesProtections e)
        {
            e = e ?? new EntreesProtections();
            var etat = e.Etat;
            bool ancien = etat != null && VueSante.EtatAncien(etat, e.Maintenant);
            var c = e.ConfigIllisible ? null : e.Config;
            var l = new List<LigneProtection>();
            Func<string, string> v = x => Canal.Visible(x ?? "");

            // Réponses automatiques (etat.json, ReponsesAuto)
            var ra = etat == null ? null : etat.ReponsesAuto;
            var ran = Nouvelle("Rancongiciel", T("Réponse automatique au rançongiciel", "Ransomware auto-response"), "Menaces");
            l.Add(ancien ? NonPublie(ran, false, Ancien()) : Reponse(ran, ra == null ? null : ra.Rancongiciel,
                T("Suspend un programme qui modifie les fichiers leurres ; leurres surveillés.", "Suspends a program that modifies the decoy files; decoys watched."),
                T("Leurres ou journal Sécurité lus en partie : un programme qui touche un leurre peut ne pas être vu.", "Decoys or Security log only partly read: a program touching a decoy may go unseen."),
                T("Leurres non surveillés (collecte indisponible, audit « Système de fichiers » coupé, ou registre des réponses illisible) : rien ne serait suspendu.", "Decoys not watched (collection unavailable, \"File System\" audit off, or responses register unreadable): nothing would be suspended."),
                T("Un programme qui touche aux fichiers leurres est seulement signalé, pas suspendu.", "A program touching the decoy files is only reported, not suspended.")));
            var bl = Nouvelle("BlocageListes", T("Blocage automatique par les listes de menaces", "Automatic block from threat lists"), "Menaces");
            l.Add(ancien ? NonPublie(bl, false, Ancien()) : Reponse(bl, ra == null ? null : ra.BlocageListes,
                T("Les adresses Spamhaus DROP et Feodo Tracker sont bloquées au pare-feu ; listes chargées.", "Spamhaus DROP and Feodo Tracker addresses are blocked at the firewall; lists loaded."),
                T("Une partie des listes est chargée : certaines adresses connues ne seraient pas bloquées.", "Only some lists are loaded: some known addresses would not be blocked."),
                T("Listes non chargées, connexions non vues, protection du dossier de données en échec, ou registre des réponses illisible : rien ne serait bloqué.", "Lists not loaded, connections not seen, data folder protection failing, or responses register unreadable: nothing would be blocked."),
                T("Les adresses malveillantes connues sont seulement signalées, pas bloquées.", "Known malicious addresses are only reported, not blocked.")));

            // IPS, expérimental (ids.json à jour, sinon le réglage pour le seul « désactivé »)
            var ips = Nouvelle("Ips", T("Prévention d'intrusion (IPS)", "Intrusion prevention (IPS)"), "Détection");
            string eteintIps = T("Bloquerait au pare-feu sans confirmation pendant 24 h ; jamais recommandé tant qu'il est expérimental.", "Would block at the firewall without confirmation for 24 h; never recommended while experimental.");
            bool idsAncien = e.Ids != null && !Frais(e.Ids.MisAJour, e.Maintenant);
            if (idsAncien && (c == null || c.Ips)) l.Add(NonPublie(ips, c != null && c.Ips, FichierAncien("ids.json")));
            else if (idsAncien) l.Add(Eteinte(ips, eteintIps));
            else if (e.Ids != null)
            {
                if (!e.Ids.Ips) l.Add(Eteinte(ips, eteintIps));
                else if (e.Ids.Regles > 0) l.Add(Poser(ips, Verifie, T("Actif", "Active"), string.Format(T("{0} règle(s) chargée(s), paquets analysés ; bloque au pare-feu pendant 24 h.", "{0} rule(s) loaded, packets analysed; blocks at the firewall for 24 h."), e.Ids.Regles)));
                else l.Add(Poser(ips, Attention, T("Activé, sans effet", "On, no effect"), T("Aucune règle chargée : rien n'est bloqué.", "No rule loaded: nothing is blocked.")));
            }
            else if (c != null && !c.Ips) l.Add(Eteinte(ips, eteintIps));
            else l.Add(NonPublie(ips, c != null && c.Ips, null));

            // Filtrage par nom de domaine (filtrage-etat.json, EtatCode)
            var fi = Nouvelle("Filtrage", T("Filtrage par nom de domaine", "Domain filtering"), "Navigation");
            string code = e.Filtrage == null ? null : e.Filtrage.EtatCode;
            string suspendu = T("Activé, suspendu", "On, suspended");
            if (e.Filtrage != null && !string.IsNullOrEmpty(code) && !Frais(e.Filtrage.MisAJour, e.Maintenant)) { l.Add(NonPublie(fi, false, FichierAncien("filtrage-etat.json"))); code = null; }
            else switch (code ?? "")
            {
                case "Actif":
                    var cats = (e.Filtrage.Categories ?? new List<string>()).Where(x => !string.IsNullOrEmpty(x)).ToList();
                    l.Add(Poser(fi, Verifie, string.Format(T("Actif · {0} catégorie(s)", "Active · {0} category(ies)"), cats.Count), string.Join(", ", cats.Select(NomCategorie)) + T(" ; noms bloqués par le résolveur local.", "; names blocked by the local resolver.")));
                    break;
                case "ActifSansCategorie": l.Add(Poser(fi, Attention, T("Activé, sans effet", "On, no effect"), T("Le résolveur tourne mais aucune catégorie n'est choisie : rien n'est bloqué.", "The resolver runs but no category is selected: nothing is blocked."))); break;
                case "Inactif": l.Add(Eteinte(fi, T("Aucun nom de domaine n'est filtré.", "No domain name is filtered."))); break;
                case "RemiseEnAttente": l.Add(Poser(fi, Attention, suspendu, T("Remise des cartes réseau en attente : rien n'est filtré pour l'instant.", "Network card restore pending: nothing is filtered for now."))); break;
                case "SuspenduResolveur": l.Add(Poser(fi, Attention, suspendu, T("Résolveur local non lancé : rien n'est filtré.", "Local resolver not running: nothing is filtered."))); break;
                case "SuspenduAmont": l.Add(Poser(fi, Attention, suspendu, T("Résolveur d'amont injoignable : rien n'est filtré.", "Upstream resolver unreachable: nothing is filtered."))); break;
                case "Contourne": l.Add(Poser(fi, Attention, T("Activé, contourné", "On, bypassed"), VueNavigationFluent.EtatTexte(e.Filtrage.Etat) + T(" : le trafic de cette carte n'est pas filtré.", ": this card's traffic is not filtered."))); break;
                default: l.Add(NonPublie(fi, false, null)); break;
            }

            // Baseline (baseline.json) : même seuil que le compteur de la navigation (90 %)
            var ba = Nouvelle("Baseline", T("Baseline de sécurité", "Security baseline"), "Baseline");
            if (e.Baseline == null || e.Baseline.Regles == null)
                l.Add(NonPublie(ba, false, T("Le service n'a pas encore évalué la baseline (toutes les 10 minutes), ou baseline.json est illisible : rien n'est conclu.", "The service has not evaluated the baseline yet (every 10 minutes), or baseline.json is unreadable: nothing is concluded.")));
            else
            {
                int rec = VueBaselineFluent.Score(e.Baseline, "recommandé");
                var regles = VueBaselineFluent.Regles(e.Baseline, "recommandé");
                string d = string.Format(T("{0} des {1} réglages Windows recommandés sont appliqués.", "{0} of {1} recommended Windows settings are applied."), regles.Count(x => x.Etat == "conforme"), regles.Count);
                l.Add(rec >= 90 ? Poser(ba, Verifie, string.Format(T("{0} % appliqués", "{0}% applied"), rec), d)
                                : Poser(ba, Attention, string.Format(T("Recommandé · {0} % appliqués", "Recommended · {0}% applied"), rec), d));
            }

            // Remontée des alertes (config.json pour les canaux, notifications.json pour les envois)
            var re = Nouvelle("Remontee", T("Remontée des alertes", "Alert forwarding"), "Réglages");
            if (c == null) l.Add(NonPublie(re, false, T("config.json illisible : on ne sait pas qui est prévenu.", "config.json unreadable: who is notified is unknown.")));
            else
            {
                var canaux = VueReglagesFluent.Canaux(c.Notifications);
                string noms = string.Join(", ", canaux);
                var r = e.Remontee;
                if (canaux.Count == 0) l.Add(Eteinte(re, T("Personne n'est prévenu des alertes : aucun canal n'est activé (ntfy, Teams ou e-mail).", "Nobody is notified of alerts: no channel is turned on (ntfy, Teams or e-mail).")));
                else if (r == null) l.Add(NonPublie(re, true, noms + T(" : notifications.json absent ou illisible, on ne sait pas si un message est parti.", ": notifications.json missing or unreadable, whether a message was sent is unknown.")));
                else if (!string.IsNullOrEmpty(r.EchecDepuis)) l.Add(Poser(re, Attention, T("Activé, en échec", "On, failing"), string.Format(T("{0} : envois en échec depuis {1} ; {2} alerte(s) en attente.", "{0}: sending fails since {1}; {2} alert(s) waiting."), noms, v(r.EchecDepuis), r.EnAttente)));
                else if (r.Envoyes == 0) l.Add(NonPublie(re, true, noms + T(" : aucun message envoyé pour l'instant ; envoyez un message de test (Réglages).", ": no message sent yet; send a test message (Settings).")));
                else l.Add(Poser(re, Verifie, T("Actif", "Active"), string.Format(T("{0} ; dernier message envoyé le {1}.", "{0}; last message sent on {1}."), noms, v(r.DernierEnvoi))));
            }

            // Mise à jour automatique (config.json pour le réglage, maj.json pour l'issue)
            var mj = Nouvelle("MajAuto", T("Mises à jour automatiques", "Automatic updates"), "Réglages");
            var m = e.Maj;
            bool majEchec = m != null && (m.EchecInstallationPrecedente || EchecsMaj.Contains(m.StatutCode ?? ""));
            if (c == null || c.Maj == null) l.Add(NonPublie(mj, false, T("config.json illisible : le réglage n'est pas connu.", "config.json unreadable: the setting is unknown.")));
            else if (!c.Maj.Auto)
                l.Add(Eteinte(mj, T("Les mises à jour sont contrôlées chaque jour et seulement signalées.", "Updates are checked daily and only reported.") + (majEchec ? T(" Dernier contrôle en échec (page Santé).", " Last check failed (Health page).") : "")));
            else if (m == null) l.Add(NonPublie(mj, true, T("maj.json absent ou illisible : premier contrôle 10 min après le démarrage du service.", "maj.json missing or unreadable: first check 10 min after the service starts.")));
            else if (m.EchecInstallationPrecedente) l.Add(Poser(mj, Attention, T("Activé, en échec", "On, failing"), T("L'installation précédente a échoué (paquet modifié ou retour arrière) : voir la page Santé.", "The previous installation failed (modified package or rollback): see the Health page.")));
            else if (EchecsMaj.Contains(m.StatutCode ?? "")) l.Add(Poser(mj, Attention, T("Activé, en échec", "On, failing"), string.Format(T("Dernier contrôle le {0} en échec ; rien n'est installé.", "Last check on {0} failed; nothing installed."), v(m.VerifieLe))));
            else if (m.StatutCode == "AJour") l.Add(Poser(mj, Verifie, T("Actif", "Active"), string.Format(T("Dernier contrôle le {0} : à jour.", "Last check on {0}: up to date."), v(m.VerifieLe))));
            else if (m.StatutCode == "InstallationLancee") l.Add(Poser(mj, Verifie, T("Actif", "Active"), string.Format(T("Installation lancée par le contrôle du {0}.", "Installation started by the check on {0}."), v(m.VerifieLe))));
            else if (m.StatutCode == "Disponible") l.Add(Poser(mj, Attention, T("Activé, non installée", "On, not installed"), string.Format(T("Version {0} disponible, non installée automatiquement (page Santé).", "Version {0} available, not installed automatically (Health page)."), v(m.VersionDisponible))));
            else l.Add(NonPublie(mj, true, null));

            // Source de collecte des processus (etat.json)
            var sp = Nouvelle("SourceProcessus", T("Source de collecte des processus", "Process collection source"), "Santé");
            string src = etat == null ? null : etat.SourceProcessus;
            if (ancien) l.Add(NonPublie(sp, false, Ancien()));
            else if (src == "Sysmon") l.Add(Poser(sp, Verifie, T("Sysmon · actif", "Sysmon · active"), T("Créations de programmes avec ligne de commande et empreintes.", "Program creations with command lines and hashes.")));
            else if (src == "Audit 4688") l.Add(Poser(sp, Verifie, T("Audit 4688 · actif", "Audit 4688 · active"), T("Créations de programmes lues dans le journal Sécurité (Sysmon non installé).", "Program creations come from the Security log (Sysmon not installed).")));
            else if (src == "WMI") l.Add(Poser(sp, Information, "WMI", T("Créations de programmes vues par WMI, moins complètes (Sysmon et audit 4688 indisponibles).", "Program creations seen through WMI, less complete (Sysmon and audit 4688 unavailable).")));
            else if (src == "aucune") l.Add(Poser(sp, Attention, T("Aucune", "None"), T("Aucune création de programme n'est vue : les détections sur les processus ne peuvent pas se déclencher.", "No program creation is seen: process detections cannot fire.")));
            else l.Add(NonPublie(sp, false, null));

            // Apprentissage (apprentissage.json)
            var ap = Nouvelle("Apprentissage", T("Apprentissage", "Learning"), "Réglages");
            var app = e.Apprentissage;
            int jour, total;
            if (app == null || string.IsNullOrEmpty(app.Fin)) l.Add(NonPublie(ap, false, T("apprentissage.json absent ou illisible : rien n'est conclu.", "apprentissage.json missing or unreadable: nothing is concluded.")));
            else if (app.Debut == app.Fin) l.Add(Poser(ap, Information, T("Écarté", "Skipped"), T("Pas d'apprentissage automatique : ce poste avait déjà des alertes à l'installation.", "No automatic learning: this computer already had alerts when deR4Tizer was installed.")));
            else if (VueReglagesFluent.JourApprentissage(app, e.Maintenant, out jour, out total))
                l.Add(Poser(ap, Information, string.Format(T("Jour {0} sur {1}", "Day {0} of {1}"), jour, total), string.Format(T("Les alertes non critiques sont notées en information jusqu'au {0}.", "Non-critical alerts are recorded as information until {0}."), v(app.Fin))));
            else l.Add(Poser(ap, Verifie, T("Terminé", "Finished"), string.Format(T("Depuis le {0} ; {1} comportement(s) appris, {2} exception(s).", "Since {0}; {1} learned behaviour(s), {2} exception(s)."), v(app.Fin), (app.Appris ?? new List<string>()).Count, (app.Exceptions ?? new List<ExceptionApprise>()).Count)));

            // Syslog et API (etat.json, Syslog et Api) ; l'hôte et le port viennent des réglages locaux
            var sy = Nouvelle("Syslog", T("Export syslog", "Syslog export"), "Réglages");
            var ss = etat == null ? null : etat.Syslog;
            bool syReglage = c != null && c.Syslog != null && c.Syslog.Actif;
            string dest = c != null && c.Syslog != null && !string.IsNullOrEmpty(c.Syslog.Hote) ? v(c.Syslog.Hote) + ":" + c.Syslog.Port : T("le SIEM", "the SIEM");
            switch (ancien || ss == null ? "" : ss.Etat ?? "")
            {
                case "Desactive": l.Add(Eteinte(sy, T("Les alertes ne partent vers aucun SIEM.", "Alerts are not sent to a SIEM."))); break;
                case "Joignable": l.Add(Poser(sy, Verifie, T("Actif", "Active"), string.Format(T("Alertes envoyées vers {0} en TCP ; dernier envoi accepté par Windows, pas une preuve de réception.", "Alerts go to {0} over TCP; last send accepted by Windows, not a proof of receipt."), dest))); break;
                case "EnEchec": l.Add(Poser(sy, Attention, T("Activé, en échec", "On, failing"), string.Format(T("Le dernier envoi vers {0} a échoué.", "The last send to {0} failed."), dest))); break;
                case "NonVerifiable": l.Add(NonPublie(sy, true, string.Format(T("Alertes vers {0} ; aucun envoi encore, ou UDP (jamais confirmé) : rien n'est conclu.", "Alerts go to {0}; nothing sent yet, or UDP (never confirmed): nothing is concluded."), dest))); break;
                default: l.Add(NonPublie(sy, syReglage, ancien ? Ancien() : syReglage ? string.Format(T("Alertes vers {0} ; le service ne publie pas si l'envoi fonctionne.", "Alerts go to {0}; the service does not publish whether sending works."), dest) : null)); break;
            }
            var api = Nouvelle("Api", T("API d'export", "Export API"), "Réglages");
            var sa = etat == null ? null : etat.Api;
            bool apiReglage = c != null && c.Api != null && c.Api.Actif;
            string port = c != null && c.Api != null ? c.Api.Port.ToString() : "?";
            switch (ancien || sa == null ? "" : sa.Etat ?? "")
            {
                case "Desactive": l.Add(Eteinte(api, T("Export HTTP en lecture seule pour un SIEM.", "Read-only HTTP export for a SIEM."))); break;
                case "Joignable": l.Add(Poser(api, Verifie, T("Port ouvert", "Port open"), string.Format(T("Port {0} ouvert par le service ; l'accès depuis le SIEM n'est pas vérifié.", "Port {0} opened by the service; access from the SIEM is not verified."), port))); break;
                case "EnEchec": l.Add(Poser(api, Attention, T("Activé, en échec", "On, failing"), T("Jeton, port ou écoute en échec : l'API ne répond pas.", "Token, port or listener failing: the API does not answer."))); break;
                case "NonVerifiable": l.Add(NonPublie(api, true, T("Ouverture de l'écoute en cours.", "Listener opening in progress."))); break;
                default: l.Add(NonPublie(api, apiReglage, ancien ? Ancien() : apiReglage ? string.Format(T("Port {0} ; le service ne publie pas s'il écoute.", "Port {0}; the service does not publish whether it listens."), port) : null)); break;
            }
            // État du service ancien ou absent (service arrêté, fichiers restés sur le disque) : aucune ligne n'est dite
            // « actif et vérifié », quel que soit le fichier qui la porte (IPS, filtrage, mise à jour, remontée, baseline,
            // apprentissage) ; les lignes éteintes, orange ou d'information restent (prérelecture de #310, D1)
            if (etat == null || ancien)
                foreach (var x in l.Where(x => x.Visuel == Verifie))
                    Poser(x, NonVerifiable, T("Non vérifiable", "Not verifiable"), (etat == null ? Absent() : Ancien()) + " " + x.Detail);
            return l;
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
        System.Windows.Shapes.Ellipse piedPoint;   // pied daté du rail : état du service
        TextBlock piedTexte;
        Button boutonPanique;                        // panique dans l'en-tête (haut à droite), état suivi au rafraîchissement
        // Tuiles de la Vue d'ensemble par clé de page : le focus clavier posé sur une tuile la suit à la reconstruction
        readonly Dictionary<string, Button> tuilesVue = new Dictionary<string, Button>();

        // Vue d'ensemble reconstruite à chaque état publié (2 s) : une tuile focalisée au clavier le reste (relecture de la
        // refonte, défaut 6 ; prérelecture de #205, D1)
        void ReconstruireVueEnsemble()
        {
            string cle = tuilesVue.Where(kv => kv.Value.IsKeyboardFocused).Select(kv => kv.Key).FirstOrDefault();
            zone.Content = VueEnsemble();
            Button b;
            if (cle != null && tuilesVue.TryGetValue(cle, out b)) b.Dispatcher.BeginInvoke(new Action(() => b.Focus()), System.Windows.Threading.DispatcherPriority.Input);
        }
        readonly ContentControl zone = new ContentControl();
        readonly TextBlock titrePage = new TextBlock();
        readonly List<Button> boutons = new List<Button>();

        // Toutes les pages sont natives (U6c) : plus de pages WinForms prêtées par la fenêtre d'aujourd'hui (relecture de #147)
        public Coquille() : this(null) { }

        // Bascule (B1) : vrai quand la coquille est construite au premier geste après un démarrage caché ; ce geste est celui
        // de l'utilisateur, donc « Premiers réglages » peuvent se proposer (dossier de la bascule, constat 4)
        internal static bool OuvertureDifferee;

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
            Resources.Add(typeof(System.Windows.Controls.Primitives.ScrollBar), StyleDefilement());
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
            titrePage.VerticalAlignment = VerticalAlignment.Center;
            // En-tête : titre à gauche, bouton Panique à droite (action globale, toujours accessible)
            var entete = new DockPanel { Margin = new Thickness(0, 0, 0, 16) };
            DockPanel.SetDock(entete, Dock.Top);
            if (source != null)
            {
                boutonPanique = new Button { Padding = new Thickness(16, 7, 16, 7), Cursor = Cursors.Hand, FontWeight = FontWeights.SemiBold, BorderThickness = new Thickness(1), VerticalAlignment = VerticalAlignment.Center };
                boutonPanique.Template = ModeleSimple();
                boutonPanique.Click += (s, a) => source.DemanderPanique();
                MettreAJourPanique();
                DockPanel.SetDock(boutonPanique, Dock.Right);
                entete.Children.Add(boutonPanique);
            }
            entete.Children.Add(titrePage);
            droite.Children.Add(entete);
            droite.Children.Add(zone);
            Grid.SetColumn(droite, 1);
            grille.Children.Add(droite);
            Content = grille;

            int iPage = Array.IndexOf(Environment.GetCommandLineArgs(), "--page");
            string demandee = iPage > 0 && iPage + 1 < Environment.GetCommandLineArgs().Length ? Environment.GetCommandLineArgs()[iPage + 1] : null;
            bool connue = demandee != null && (demandee == VueAssistantFluent.Cle || NavigationFluent.Groupes().SelectMany(x => x.Entrees).Any(x => x.Cle == demandee));
            // Premiers réglages (U7a) : proposés au premier lancement, jamais en administrateur, sans source, avec --page ou caché
            // Repère jamais consulté sous jeton administrateur (audit de #304, A304-2)
            bool proposer = VueAssistantFluent.DoitProposer(VueAssistantFluent.RepereVu(Canal.EstAdmin(), VueAssistantFluent.CheminRepere, VueAssistantFluent.RepereExiste), Canal.EstAdmin(), source != null, demandee != null,
                Environment.GetCommandLineArgs().Contains("--cache") && !OuvertureDifferee);
            Ouvrir(connue ? demandee : proposer ? VueAssistantFluent.Cle : NavigationFluent.VueEnsemble);
            if (source != null)
            {
                Action suivre = () =>
                {
                    MettreAJourPastillesNav();
                    // Cachée (zone de notification) : rien n'est reconstruit (dossier de la bascule, constat 5)
                    if (!IsVisible) return;
                    if (ouverte == NavigationFluent.VueEnsemble) ReconstruireVueEnsemble();
                    else if (ouverte == "Alertes" && pageAlertes != null) { pageAlertes.Rafraichir(); if (IsVisible) ((ISourceAlertes)source).MarquerAlertesLues(); }
                };
                // Pastilles d'abord, abonnement à l'état en dernier : si la construction échoue (repli au premier geste), aucun
                // abonnement ne reste attaché (audit de #156, S156-02)
                MettreAJourPastillesNav();
                source.Rattacher(cle =>
                {
                    Show();
                    if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
                    Activate();
                    if (cle != null) Ouvrir(cle);
                });
                Closed += (s, a) => { source.Change -= suivre; source.Rattacher(null); };
                // Cachée : la page est déchargée (ses minuteurs ne tournent plus) ; remontrée, elle est reconstruite
                IsVisibleChanged += (s, a) =>
                {
                    if (!IsVisible) zone.Content = null;
                    else if (zone.Content == null) Ouvrir(ouverte ?? NavigationFluent.VueEnsemble);
                };
                source.Change += suivre;
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

        [System.Runtime.InteropServices.DefaultDllImportSearchPaths(System.Runtime.InteropServices.DllImportSearchPath.System32)]
        [System.Runtime.InteropServices.DllImport("dwmapi.dll")]
        static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int val, int size);
        // Barre de titre sombre (accessibilité/finition) : DWMWA_USE_IMMERSIVE_DARK_MODE (20, repli 19 sur Windows ancien).
        // Laissée au système en contraste élevé. Sans effet si l'API est absente.
        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);
            if (Jetons.ContrasteEleve) return;
            try
            {
                var h = new System.Windows.Interop.WindowInteropHelper(this).Handle;
                int oui = 1;
                if (DwmSetWindowAttribute(h, 20, ref oui, 4) != 0) DwmSetWindowAttribute(h, 19, ref oui, 4);
            }
            catch { }
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
            MettreAJourPied();
            MettreAJourPanique();
        }

        // Pied du rail : pastille selon l'état réel du service (vert seulement en ligne avec un état frais, orange à vérifier,
        // rouge arrêté) et statut « · »-séparé (mise à jour, démarrage, version). Service arrêté : l'ancien statut n'est plus
        // montré, il daterait d'avant l'arrêt (relecture de la refonte, défaut 2)
        void MettreAJourPied()
        {
            if (piedTexte == null) return;
            if (source == null) { piedTexte.Text = "v" + Commun.Version; piedPoint.Fill = Jetons.Pinceau(Jetons.TexteSecondaire); return; }
            int sante = source.SanteService();
            string statut = (source.Statut() ?? "").Replace("▸", "·").Trim(' ', '·');
            piedTexte.Text = TextePied(sante, statut);
            piedPoint.Fill = Jetons.Pinceau(sante == 0 ? Jetons.Succes : sante == 1 ? Jetons.Attention : Jetons.Danger);
        }

        internal static string TextePied(int sante, string statut)
        {
            if (sante >= 2) return L.T("Service hors ligne : rien n'est surveillé") + " · v" + Commun.Version;
            if (sante == 1) return L.T("Service à vérifier") + (statut != "" ? " · " + statut : " · v" + Commun.Version);
            return statut != "" ? statut : "v" + Commun.Version;
        }

        // Bouton Panique de l'en-tête : texte et couleurs selon l'état (actif = fond accent, sinon contour rouge)
        void MettreAJourPanique()
        {
            if (boutonPanique == null || source == null) return;
            bool active = source.PaniqueActive();
            boutonPanique.Content = source.TextePanique();
            boutonPanique.Foreground = Jetons.Pinceau(active ? Jetons.TexteSurAccent : Jetons.Danger);
            boutonPanique.Background = Jetons.Pinceau(active ? Jetons.Accent : Jetons.Carte);
            boutonPanique.BorderBrush = Jetons.Pinceau(active ? Jetons.Accent : Jetons.Danger);
            // Phrase selon l'état (audit de #134, S134-01), retirée de la Vue d'ensemble avec l'ancien bouton : gardée en
            // infobulle et en aide du lecteur d'écran (relecture de la refonte, défaut 7)
            string aide = L.T(active ? "Rétablit Internet sur ce poste ; ce qui sera fait est dit avant d'agir."
                                     : "Coupe Internet sur ce poste ; la portée et le retour arrière sont dits avant d'agir.");
            boutonPanique.ToolTip = aide;
            System.Windows.Automation.AutomationProperties.SetHelpText(boutonPanique, aide);
        }

        // Tuile de compteur (Vue d'ensemble) : barre orange à gauche (un compteur est « à surveiller » au plus, comme dans
        // Resume), rouge pour un compte « à traiter » (T-4 : incidents critiques, alertes critiques non lues), icône et
        // valeur, libellé ; bouton focalisable qui ouvre la page du compteur (relecture de la refonte, défaut 6). Un mot
        // (« LIVE ») garde la taille du texte, seul un chiffre est mis en grand
        Button Tuile(VueEnsembleFluent.TuileVue t)
        {
            var teinte = t.Gravite >= 2 ? Jetons.Danger : Jetons.Attention;
            var b = new Button { Template = ModeleSimple(), Cursor = Cursors.Hand, Background = Jetons.Pinceau(Jetons.Carte), BorderBrush = Jetons.Pinceau(teinte), BorderThickness = new Thickness(3, 0, 0, 0), Padding = new Thickness(16, 14, 16, 14), Margin = new Thickness(0, 0, 12, 12), Width = 190, HorizontalContentAlignment = HorizontalAlignment.Stretch, Foreground = Jetons.Pinceau(Jetons.Texte) };
            b.FocusVisualStyle = Jetons.StyleFocus();
            string valeur = Canal.Visible(t.Nombre ? t.Valeur : VueEnsembleFluent.Phrase(t.Valeur));
            System.Windows.Automation.AutomationProperties.SetName(b, t.Libelle + VueEnsembleFluent.DeuxPoints + valeur);
            b.ToolTip = string.Format(L.T("Ouvrir la page {0}"), L.T(t.Cle));
            var c = new StackPanel();
            var haut = new DockPanel();
            if (!string.IsNullOrEmpty(t.Icone))
            {
                var ic = new TextBlock { Text = t.Icone, FontFamily = Jetons.Icones, FontSize = 16, Foreground = Jetons.Pinceau(teinte), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0) };
                DockPanel.SetDock(ic, Dock.Left);
                haut.Children.Add(ic);
            }
            haut.Children.Add(new TextBlock { Text = valeur, FontSize = t.Nombre ? 26 : 15, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis });
            c.Children.Add(haut);
            c.Children.Add(new TextBlock { Text = t.Libelle, FontSize = 12.5, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 0) });
            b.Content = c;
            string cle = t.Cle;
            tuilesVue[cle] = b;
            int sectionT = t.Section;
            b.Click += (s, a) =>
            {
                Ouvrir(cle);
                // Tuile de mise à jour : la page Réglages ouverte sur sa section « Mises à jour »
                var pr = zone.Content as PageReglagesFluent;
                if (sectionT >= 0 && pr != null) pr.Afficher(sectionT);
            };
            return b;
        }

        // Logo de la barre latérale : l'image de l'icône de l'application elle-même (icone.ps1 → deR4Tizer.ico, source unique
        // du dessin, constat T-14), jamais un second dessin. Affiché à 32 px depuis l'image de 64 px (ou plus grande sur un
        // écran à plus de 200 %) : nette à 200 %, réduite en haute qualité à 100 %. Sans la ressource (tests compilés sans
        // l'icône), le logo reste vide.
        internal const int TailleLogo = 32;
        internal static System.Windows.Controls.Image LogoApplication()
        {
            var image = new System.Windows.Controls.Image { Width = TailleLogo, Height = TailleLogo, VerticalAlignment = VerticalAlignment.Center, Stretch = Stretch.Uniform };
            RenderOptions.SetBitmapScalingMode(image, BitmapScalingMode.HighQuality);
            var png = Theme.OctetsImageApplication(Math.Max(2 * TailleLogo, Theme.TailleImage(TailleLogo)));
            if (png != null)
            {
                var source = System.Windows.Media.Imaging.BitmapFrame.Create(new System.IO.MemoryStream(png), System.Windows.Media.Imaging.BitmapCreateOptions.None, System.Windows.Media.Imaging.BitmapCacheOption.OnLoad);
                source.Freeze();
                image.Source = source;
            }
            return image;
        }
        UIElement Navigation()
        {
            var fond = new Border { Background = Jetons.Pinceau(Jetons.Carte) };
            var dock = new DockPanel { Margin = new Thickness(12, 16, 12, 16) };
            var marque = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(8, 0, 0, 20) };
            marque.Children.Add(LogoApplication());
            marque.Children.Add(new TextBlock { Text = "deR4Tizer", FontFamily = Jetons.PoliceTitre, FontSize = 20, FontWeight = FontWeights.SemiBold, Margin = new Thickness(10, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center });
            DockPanel.SetDock(marque, Dock.Top);
            dock.Children.Add(marque);

            var groupes = NavigationFluent.Groupes();
            var bas = new StackPanel { Margin = new Thickness(0, 8, 0, 0) };
            bas.Children.Add(new Border { Height = 1, Background = Jetons.Pinceau(Jetons.Separateur), Margin = new Thickness(8, 0, 8, 8) });
            foreach (var e in groupes.Last().Entrees) bas.Children.Add(Bouton(e));
            // Pied daté : pastille d'état + statut du service (dernière mise à jour, version)
            bas.Children.Add(new Border { Height = 1, Background = Jetons.Pinceau(Jetons.Separateur), Margin = new Thickness(8, 8, 8, 0) });
            piedPoint = new System.Windows.Shapes.Ellipse { Width = 7, Height = 7, VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 4, 7, 0), Fill = Jetons.Pinceau(Jetons.Succes) };
            piedTexte = new TextBlock { FontSize = 11, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap };
            // DockPanel : le texte prend la largeur restante et passe à la ligne (un StackPanel horizontal lui donnait une
            // largeur infinie, relecture de la refonte, défaut 5)
            var piedBloc = new DockPanel { Margin = new Thickness(12, 10, 10, 2) };
            DockPanel.SetDock(piedPoint, Dock.Left);
            piedBloc.Children.Add(piedPoint);
            piedBloc.Children.Add(piedTexte);
            bas.Children.Add(piedBloc);
            MettreAJourPied();
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
            contenu.Children.Add(new TextBlock { Text = L.T(e.Cle), VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis, ToolTip = L.T(e.Cle) });
            // Couleur donnée au bouton : sans elle, WPF écrit le libellé et l'icône en noir (vu sur le rendu : noir sur gris)
            var b = new Button { Content = contenu, Foreground = Jetons.Pinceau(Jetons.Texte), HorizontalContentAlignment = HorizontalAlignment.Stretch, Padding = new Thickness(12, 6, 12, 6), Margin = new Thickness(0, 1, 0, 1), Cursor = Cursors.Hand };
            b.Template = Modele();
            System.Windows.Automation.AutomationProperties.SetName(b, L.T(e.Cle));
            b.FocusVisualStyle = Jetons.StyleFocus();
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
            // Chaînes (T-20) : « Ouvrir l'alerte liée » ouvre la page Alertes sur cette alerte
            if (cle == "Chaînes") { zone.Content = new PageChainesFluent(source as ISourceReponses, alertes == null ? null : (Action<string>)(id => { Ouvrir("Alertes"); if (pageAlertes != null) pageAlertes.Montrer(id); })); return; }
            // Trafic en WPF (U4b) : lecture seule, aucune action ; un pays signalé ouvre Connexions sur l'onglet Suspectes (T-19)
            if (cle == "Trafic")
            {
                zone.Content = new PageTraficFluent(() => { Ouvrir("Connexions"); var pc = zone.Content as PageConnexionsFluent; if (pc != null) pc.Filtrer(1); });
                return;
            }
            // Blocages, Quarantaine et Menaces en WPF (U5a) : mêmes commandes et mêmes questions (ActionsProtection)
            if (cle == "Blocages") { zone.Content = new PageBlocagesFluent(); return; }
            if (cle == "Quarantaine") { zone.Content = new PageQuarantaineFluent(); return; }
            if (cle == "Menaces") { zone.Content = new PageMenacesFluent(); return; }
            // Baseline et Pare-feu en WPF (U5b)
            if (cle == "Baseline") { zone.Content = new PageBaselineFluent(); return; }
            if (cle == "Pare-feu") { zone.Content = new PageParefeuFluent(); return; }
            // Navigation (phase 7, PR 7.5b) : filtrage par nom de domaine
            if (cle == "Navigation") { zone.Content = new PageNavigationFluent(); return; }
            // Démarrage auto, Extensions et Vie privée en WPF (U6a)
            if (cle == "Démarrage auto") { zone.Content = new PageDemarrageFluent(source as ISourceReponses); return; }
            if (cle == "Extensions") { zone.Content = new PageExtensionsFluent(); return; }
            if (cle == "Vie privée") { zone.Content = new PageVieFluent(source as ISourceReponses); return; }
            // Réseau local en WPF (U6b), lecture seule
            if (cle == "Réseau local") { zone.Content = new PageReseauLocalFluent(); return; }
            // Réglages en WPF (U6c) : la dernière page hébergée ; plus aucune page WinForms dans la coquille
            if (cle == "Réglages") { var pr = new PageReglagesFluent(); pr.Revoir = () => Ouvrir(VueAssistantFluent.Cle); zone.Content = pr; return; }
            // Premiers réglages (U7a), hors de la navigation : lecture seule, renvois vers les pages
            // Chemin du repère jamais calculé sous jeton administrateur (S307-01) : EcrireRepere refuse alors d'écrire
            if (cle == VueAssistantFluent.Cle) { zone.Content = new PageAssistantFluent(source, Ouvrir, Canal.EstAdmin() ? null : VueAssistantFluent.CheminRepere()); return; }
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
            var pile = new StackPanel { MaxWidth = 880, HorizontalAlignment = HorizontalAlignment.Left };
            // Comptes des alertes et des incidents (T-4) : dans la phrase de tête et dans les tuiles, le même nombre
            var comptes = source == null ? null : source.Comptes();
            var points = source == null ? new List<PointEtat>() : VueEnsembleFluent.AvecCompteurs(source.Points(), source.Badges(), comptes);
            var sections = source == null ? new VueEnsembleFluent.SectionsVue() : VueEnsembleFluent.Sections(source.Points(), source.Badges(), comptes);
            tuilesVue.Clear();
            int gravite;
            string resume = VueEnsembleFluent.Resume(points, out gravite);
            var couleurTete = gravite == 2 ? Jetons.Danger : gravite == 1 ? Jetons.Attention : Jetons.Succes;
            // Bandeau d'état dominant : carte teintée par la gravité, tuile d'icône, résumé en grand
            var bandeau = new Border { Background = new LinearGradientBrush(VueTraficFluent.Melange(Jetons.Carte, couleurTete, 0.16), Jetons.Carte, 0), BorderBrush = Jetons.Pinceau(VueTraficFluent.Melange(Jetons.Separateur, couleurTete, 0.35)), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(10), Padding = new Thickness(20, 18, 20, 18), Margin = new Thickness(0, 0, 0, 20) };
            var ligneBandeau = new StackPanel { Orientation = Orientation.Horizontal };
            var tuileIcone = new Border { Width = 46, Height = 46, CornerRadius = new CornerRadius(10), Background = Jetons.Pinceau(VueTraficFluent.Melange(Jetons.Carte, couleurTete, 0.28)), VerticalAlignment = VerticalAlignment.Center };
            tuileIcone.Child = new TextBlock { Text = gravite == 2 ? "" : gravite == 1 ? "" : "", FontFamily = Jetons.Icones, FontSize = 24, Foreground = Jetons.Pinceau(couleurTete), HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
            ligneBandeau.Children.Add(tuileIcone);
            ligneBandeau.Children.Add(new TextBlock { Text = resume, FontSize = 23, FontWeight = FontWeights.SemiBold, Margin = new Thickness(16, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center, TextWrapping = TextWrapping.Wrap, MaxWidth = 620 });
            bandeau.Child = ligneBandeau;
            pile.Children.Add(bandeau);

            Action<string, List<PointEtat>, Color> section = (titre, faits, couleur) =>
            {
                if (faits.Count == 0) return;
                var carte = new Border { Background = Jetons.Pinceau(Jetons.Carte), CornerRadius = new CornerRadius(8), Padding = new Thickness(20, 16, 20, 16), Margin = new Thickness(0, 0, 0, 12) };
                var contenu = new StackPanel();
                if (titre != null) contenu.Children.Add(new TextBlock { Text = L.T(titre), FontSize = 13, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(couleur), Margin = new Thickness(0, 0, 0, 8) });
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
            // « À traiter » : les faits rouges de l'en-tête, puis les comptes critiques en tuiles (T-4 : incidents critiques non
            // clos, alertes critiques non lues), comptés par la phrase de tête
            if (sections.ATraiter.Count > 0 || sections.TuilesATraiter.Count > 0)
            {
                pile.Children.Add(new TextBlock { Text = L.T("À traiter"), FontSize = 13, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Jetons.Danger), Margin = new Thickness(0, 0, 0, 10) });
                section(null, sections.ATraiter, Jetons.Danger);
                var wrapR = new WrapPanel { Margin = new Thickness(0, 0, 0, 4) };
                foreach (var tv in sections.TuilesATraiter) wrapR.Children.Add(Tuile(tv));
                if (wrapR.Children.Count > 0) pile.Children.Add(wrapR);
            }
            // « À surveiller » : les faits orange de l'en-tête en liste (jamais perdus, défaut 1), puis les compteurs de la
            // navigation en tuiles cliquables
            if (sections.ASurveiller.Count > 0 || sections.Tuiles.Count > 0)
            {
                pile.Children.Add(new TextBlock { Text = L.T("À surveiller"), FontSize = 13, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Jetons.Attention), Margin = new Thickness(0, 0, 0, 10) });
                section(null, sections.ASurveiller, Jetons.Attention);
                var wrap = new WrapPanel { Margin = new Thickness(0, 0, 0, 4) };
                foreach (var tv in sections.Tuiles) wrap.Children.Add(Tuile(tv));
                if (wrap.Children.Count > 0) pile.Children.Add(wrap);
            }
            // Panneau « Protections » (T-18) : état effectif publié par le service, un lien par ligne ; pas compté dans la
            // phrase de tête, aucun bouton d'activation
            var protections = source == null ? null : source.Protections();
            if (protections != null) pile.Children.Add(PanneauProtections(VueProtectionsFluent.Lignes(protections)));
            // « En ordre » : un seul conteneur, lignes séparées, libellé à gauche et état à droite (séparé sur « : ») ; puce
            // verte pour un fait sain seulement, grise pour une information (défaut 3)
            var enOrdre = sections.EnOrdre;
            if (enOrdre.Count > 0)
            {
                pile.Children.Add(new TextBlock { Text = L.T("En ordre et informations"), FontSize = 13, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, 0, 0, 10) });
                var carte = new Border { Background = Jetons.Pinceau(Jetons.Carte), CornerRadius = new CornerRadius(8), Padding = new Thickness(6, 4, 6, 4), Margin = new Thickness(0, 0, 0, 12) };
                var col = new StackPanel();
                for (int i = 0; i < enOrdre.Count; i++)
                {
                    if (i > 0) col.Children.Add(new Border { Height = 1, Background = Jetons.Pinceau(Jetons.Separateur), Margin = new Thickness(14, 0, 14, 0) });
                    string t = enOrdre[i].Texte ?? ""; int sep = t.IndexOf(" : ", StringComparison.Ordinal);
                    string libelle = sep >= 0 ? t.Substring(0, sep) : t;
                    string etat = sep >= 0 ? t.Substring(sep + 3) : "";
                    var dock = new DockPanel { Margin = new Thickness(14, 11, 14, 11) };
                    var puce = new Border { Width = 7, Height = 7, CornerRadius = new CornerRadius(3.5), Background = Jetons.Pinceau(enOrdre[i].Sain ? Jetons.Succes : Jetons.TexteSecondaire), Margin = new Thickness(0, 0, 10, 0), VerticalAlignment = VerticalAlignment.Center };
                    DockPanel.SetDock(puce, Dock.Left);
                    dock.Children.Add(puce);
                    var droite = new TextBlock { Text = etat, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(12, 0, 0, 0) };
                    DockPanel.SetDock(droite, Dock.Right);
                    dock.Children.Add(droite);
                    dock.Children.Add(new TextBlock { Text = libelle, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis });
                    col.Children.Add(dock);
                }
                carte.Child = col;
                pile.Children.Add(carte);
            }

            if (source != null && !VueAssistantFluent.RepereVu(Canal.EstAdmin(), VueAssistantFluent.CheminRepere, VueAssistantFluent.RepereExiste))
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

            return new ScrollViewer { Content = pile, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        }

        // Puce d'état du panneau « Protections » : pleine (vérifié, attention, information), anneau (éteint par choix),
        // anneau pointillé (non vérifiable) ; la forme distingue les états aussi en contraste élevé, où les couleurs se confondent
        internal static System.Windows.Shapes.Ellipse PuceProtection(int visuel)
        {
            var c = Jetons.Pinceau(VueProtectionsFluent.Couleur(visuel));
            var e = new System.Windows.Shapes.Ellipse { Width = 9, Height = 9, VerticalAlignment = VerticalAlignment.Center };
            if (visuel == VueProtectionsFluent.Eteint) { e.Stroke = c; e.StrokeThickness = 1.5; }
            else if (visuel == VueProtectionsFluent.NonVerifiable) { e.Stroke = c; e.StrokeThickness = 1.5; e.StrokeDashArray = new DoubleCollection { 1, 1.2 }; }
            else e.Fill = c;
            return e;
        }

        // Panneau « Protections » (T-18) : légende, une ligne par fonction (titre, détail, état à droite, lien vers sa page),
        // phrase de pied. Les liens ouvrent la page de la fonction et rien d'autre : l'activation reste sur cette page
        UIElement PanneauProtections(List<LigneProtection> lignes)
        {
            bool en = L.En;
            var bloc = new StackPanel { Margin = new Thickness(0, 8, 0, 12) };
            bloc.Children.Add(new TextBlock { Text = "Protections", FontSize = 13, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 6) });
            var legende = new WrapPanel { Margin = new Thickness(0, 0, 0, 10) };
            foreach (int x in new[] { VueProtectionsFluent.Verifie, VueProtectionsFluent.Eteint, VueProtectionsFluent.Attention, VueProtectionsFluent.Information, VueProtectionsFluent.NonVerifiable })
            {
                var item = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 16, 2) };
                var p = PuceProtection(x); p.Width = p.Height = 8; p.Margin = new Thickness(0, 0, 6, 0);
                item.Children.Add(p);
                item.Children.Add(new TextBlock { Text = VueProtectionsFluent.Legende(x), FontSize = 11.5, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire) });
                legende.Children.Add(item);
            }
            bloc.Children.Add(legende);
            var carte = new Border { Background = Jetons.Pinceau(Jetons.Carte), CornerRadius = new CornerRadius(8), Padding = new Thickness(6, 4, 6, 10) };
            var col = new StackPanel();
            for (int i = 0; i < lignes.Count; i++)
            {
                var lp = lignes[i];
                if (i > 0) col.Children.Add(new Border { Height = 1, Background = Jetons.Pinceau(Jetons.Separateur), Margin = new Thickness(16, 0, 16, 0) });
                var dock = new DockPanel { Margin = new Thickness(16, 11, 16, 11) };
                var puce = PuceProtection(lp.Visuel);
                puce.Margin = new Thickness(0, 5, 14, 0); puce.VerticalAlignment = VerticalAlignment.Top;
                DockPanel.SetDock(puce, Dock.Left);
                dock.Children.Add(puce);
                var droite = new StackPanel { Margin = new Thickness(16, 0, 0, 0), HorizontalAlignment = HorizontalAlignment.Right };
                droite.Children.Add(new TextBlock { Text = lp.Etat, Foreground = Jetons.Pinceau(VueProtectionsFluent.Couleur(lp.Visuel)), HorizontalAlignment = HorizontalAlignment.Right });
                string page = lp.Page;
                var lien = new Button { Template = ModeleSimple(), Cursor = Cursors.Hand, Background = Brushes.Transparent, BorderThickness = new Thickness(0), Padding = new Thickness(0, 3, 0, 0), HorizontalAlignment = HorizontalAlignment.Right, Foreground = Jetons.Pinceau(Jetons.Accent), Tag = page };
                lien.FocusVisualStyle = Jetons.StyleFocus();
                lien.Content = new TextBlock { Text = VueProtectionsFluent.Lien(page) + "  \u203A", FontSize = 12.5 };
                System.Windows.Automation.AutomationProperties.SetName(lien, VueProtectionsFluent.Lien(page) + VueEnsembleFluent.DeuxPoints + lp.Titre);
                lien.Click += (s, a) => Ouvrir(page);
                droite.Children.Add(lien);
                DockPanel.SetDock(droite, Dock.Right);
                dock.Children.Add(droite);
                var gauche = new StackPanel();
                var titre = new WrapPanel();
                titre.Children.Add(new TextBlock { Text = lp.Titre, FontSize = 14, VerticalAlignment = VerticalAlignment.Center });
                if (lp.Experimental)
                {
                    var etiquette = new Border { BorderBrush = Jetons.Pinceau(Jetons.TexteSecondaire), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(3), Padding = new Thickness(5, 0, 5, 1), Margin = new Thickness(10, 1, 0, 0), VerticalAlignment = VerticalAlignment.Center };
                    etiquette.Child = new TextBlock { Text = en ? "Experimental" : "Expérimental", FontSize = 11, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire) };
                    titre.Children.Add(etiquette);
                }
                gauche.Children.Add(titre);
                if (!string.IsNullOrEmpty(lp.Detail))
                    gauche.Children.Add(new TextBlock { Text = lp.Detail, FontSize = 12.5, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 3, 0, 0) });
                dock.Children.Add(gauche);
                col.Children.Add(dock);
            }
            col.Children.Add(new TextBlock { Text = VueProtectionsFluent.Pied(), FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(16, 6, 16, 0) });
            carte.Child = col;
            bloc.Children.Add(carte);
            return bloc;
        }

        // Barre de défilement sombre : fine, pouce arrondi teinté, pas de boutons fléchés (chrome de Windows retiré)
        static Style StyleDefilement()
        {
            Func<Color, string> hex = c => string.Format("#{0:X2}{1:X2}{2:X2}", c.R, c.G, c.B);
            string n = hex(VueTraficFluent.Melange(Jetons.Separateur, Jetons.TexteSecondaire, 0.45));
            string h = hex(VueTraficFluent.Melange(Jetons.Separateur, Jetons.TexteSecondaire, 0.8));
            string x =
                "<Style xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml' TargetType='ScrollBar'>" +
                "<Setter Property='Background' Value='Transparent'/><Setter Property='Width' Value='10'/><Setter Property='MinWidth' Value='10'/>" +
                "<Setter Property='Template'><Setter.Value><ControlTemplate TargetType='ScrollBar'>" +
                "<Grid Background='Transparent'><Track Name='PART_Track' IsDirectionReversed='True'>" +
                "<Track.Thumb><Thumb x:Name='pouce' MinHeight='24'><Thumb.Template><ControlTemplate TargetType='Thumb'>" +
                "<Border x:Name='t' Background='" + n + "' CornerRadius='4' Margin='2,1,2,1'/>" +
                "<ControlTemplate.Triggers><Trigger Property='IsMouseOver' Value='True'><Setter TargetName='t' Property='Background' Value='" + h + "'/></Trigger></ControlTemplate.Triggers>" +
                "</ControlTemplate></Thumb.Template></Thumb></Track.Thumb>" +
                "<Track.IncreaseRepeatButton><RepeatButton x:Name='plus' Command='ScrollBar.PageDownCommand' Opacity='0' Focusable='False'/></Track.IncreaseRepeatButton>" +
                "<Track.DecreaseRepeatButton><RepeatButton x:Name='moins' Command='ScrollBar.PageUpCommand' Opacity='0' Focusable='False'/></Track.DecreaseRepeatButton>" +
                "</Track></Grid>" +
                // Sens inversé pour la seule barre verticale (haut = début) ; l'horizontale garde gauche = début et pages
                // gauche/droite (relecture de la refonte, défaut 8 : elle défilait à l'envers)
                "<ControlTemplate.Triggers><Trigger Property='Orientation' Value='Horizontal'>" +
                "<Setter TargetName='PART_Track' Property='IsDirectionReversed' Value='False'/><Setter TargetName='pouce' Property='MinHeight' Value='0'/><Setter TargetName='pouce' Property='MinWidth' Value='24'/>" +
                "<Setter TargetName='plus' Property='Command' Value='ScrollBar.PageRightCommand'/><Setter TargetName='moins' Property='Command' Value='ScrollBar.PageLeftCommand'/>" +
                "</Trigger></ControlTemplate.Triggers>" +
                "</ControlTemplate></Setter.Value></Setter>" +
                "<Style.Triggers><Trigger Property='Orientation' Value='Horizontal'><Setter Property='Width' Value='Auto'/><Setter Property='MinWidth' Value='0'/><Setter Property='Height' Value='10'/><Setter Property='MinHeight' Value='10'/></Trigger></Style.Triggers>" +
                "</Style>";
            return (Style)System.Windows.Markup.XamlReader.Parse(x);
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
        // Modèle des entrées de navigation, repris par la navigation des sections de la page Réglages (T-15)
        internal static ControlTemplate ModeleNavigation() { return Modele(); }
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
            // Accessibilité : comme les autres listes (Briques.Disposer), Tab entre une fois, les flèches déplacent le focus.
            KeyboardNavigation.SetTabNavigation(liste, KeyboardNavigationMode.Once);
            KeyboardNavigation.SetDirectionalNavigation(liste, KeyboardNavigationMode.Contained);
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

        // Ouverte depuis une autre page sur une alerte (page Chaînes, « Ouvrir l'alerte liée », T-20) : tous les niveaux
        internal void Montrer(string id) { niveau = null; choisie = id; Rafraichir(); }

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

            bool rendreFocus = liste.IsKeyboardFocusWithin;
            // Clé de la ligne focalisée, lue avant la reconstruction (relecture de #205, défaut A : parcourir aux flèches
            // sans ouvrir ne doit pas être ramené à la ligne choisie à chaque rafraîchissement)
            string idFocus = null;
            foreach (UIElement c in liste.Children) { var fe = c as FrameworkElement; if (fe != null && fe.IsKeyboardFocusWithin) idFocus = fe.Tag as string; }
            liste.Children.Clear();
            var visibles = VueAlertesFluent.Filtrer(toutes, niveau);
            if (visibles.Count == 0)
                liste.Children.Add(new TextBlock
                {
                    Text = niveau == null ? source.AucuneAlerte() : L.T("Aucune alerte de ce niveau."), TextWrapping = TextWrapping.Wrap,
                    Foreground = Jetons.Pinceau(niveau == null && source.CollectesEnAlarme() ? Jetons.Attention : Jetons.TexteSecondaire)
                });
            string lue = source.DerniereLue();
            UIElement premiereLigne = null, ligneChoisie = null, ligneFocus = null;
            foreach (var a in visibles)
            {
                var l = Ligne(a, VueAlertesFluent.NonLue(a, lue));
                var fl = l as FrameworkElement; if (fl != null) fl.Tag = a.Id;
                if (premiereLigne == null) premiereLigne = l;
                if (a.Id == choisie) ligneChoisie = l;
                if (idFocus != null && a.Id == idFocus) ligneFocus = l;
                liste.Children.Add(l);
            }
            if (toutes.Count(a => niveau == null || a.Niveau == niveau) > VueAlertesFluent.Maximum)
                liste.Children.Add(new TextBlock { Text = string.Format(L.T("Les {0} plus récentes sont affichées."), VueAlertesFluent.Maximum), FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, 8, 0, 0) });
            Afficher(visibles.FirstOrDefault(a => a.Id == choisie) ?? visibles.FirstOrDefault());
            // Accessibilité (défaut 1) : le rafraîchissement reconstruit la liste et détruit la ligne qui avait le focus.
            // Si le focus clavier était dans la liste, le rendre à la ligne ouverte (ou à la première), après la mise en page.
            if (rendreFocus) { var cible = ligneFocus ?? ligneChoisie ?? premiereLigne; if (cible != null) cible.Dispatcher.BeginInvoke(new Action(() => cible.Focus()), System.Windows.Threading.DispatcherPriority.Input); }
        }

        UIElement Ligne(Alerte a, bool nonLue)
        {
            int g = VueAlertesFluent.Gravite(a.Niveau);
            var couleur = g == 2 ? Jetons.Danger : g == 1 ? Jetons.Attention : Jetons.TexteSecondaire;
            bool ouverte = a.Id == choisie;
            var cadre = new LigneBord
            {
                Background = Jetons.Pinceau(ouverte ? Jetons.Surface : Jetons.Carte), CornerRadius = new CornerRadius(6), Padding = new Thickness(14, 8, 14, 8),
                Margin = new Thickness(0, 0, 0, 6), BorderThickness = new Thickness(3, 0, 0, 0), BorderBrush = Jetons.Pinceau(couleur), Cursor = Cursors.Hand
            };
            if (ouverte && Jetons.ContrasteEleve) { cadre.BorderThickness = new Thickness(2); cadre.BorderBrush = Jetons.Pinceau(Jetons.Accent); }
            var pile = new StackPanel();
            var haut = new DockPanel();
            var niveauTexte = new TextBlock { Text = Canal.Visible(L.T(a.Niveau ?? "")), FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(couleur), Margin = new Thickness(8, 0, 0, 0) };
            DockPanel.SetDock(niveauTexte, Dock.Right);
            haut.Children.Add(niveauTexte);
            haut.Children.Add(new TextBlock { Text = (nonLue ? "• " : "") + Canal.Visible(a.Processus), FontWeight = nonLue ? FontWeights.SemiBold : FontWeights.Normal, TextTrimming = TextTrimming.CharacterEllipsis, ToolTip = Canal.Visible(a.Processus) });
            pile.Children.Add(haut);
            string sous = Canal.Visible(a.Heure) + (string.IsNullOrEmpty(a.Destination) ? "" : "  ·  " + Canal.Visible(a.Destination));
            pile.Children.Add(new TextBlock { Text = sous, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextTrimming = TextTrimming.CharacterEllipsis, ToolTip = sous });
            cadre.Child = pile;
            // Accessibilité : focus clavier (Tab + flèches), activation Entrée/Espace, nom lu par les lecteurs d'écran, survol.
            cadre.Focusable = true;
            cadre.FocusVisualStyle = Jetons.StyleFocus();
            System.Windows.Automation.AutomationProperties.SetName(cadre, string.Join(", ", new[] { Canal.Visible(a.Processus), Canal.Visible(L.T(a.Niveau ?? "")), sous }.Where(x => !string.IsNullOrEmpty(x))));
            Action activer = () => { choisie = a.Id; Rafraichir(); };
            cadre.MouseLeftButtonUp += (s, e) => activer();
            cadre.KeyDown += (s, e) => { if (e.Key == Key.Enter || e.Key == Key.Space) { activer(); e.Handled = true; } };
            cadre.MouseEnter += (s, e) => { if (!ouverte) cadre.Background = Jetons.Pinceau(Jetons.Surface); };
            cadre.MouseLeave += (s, e) => { if (!ouverte) cadre.Background = Jetons.Pinceau(Jetons.Carte); };
            cadre.GotFocus += (s, e) => { if (!ouverte) cadre.Background = Jetons.Pinceau(Jetons.Surface); };
            cadre.LostFocus += (s, e) => { if (!ouverte) cadre.Background = Jetons.Pinceau(Jetons.Carte); };
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

    // Ligne de liste accessible : un Border nu n'a pas d'AutomationPeer en WPF, donc AutomationProperties.Name n'est pas lu
    // par le Narrateur. Cette sous-classe s'annonce comme « élément de liste » et porte son nom.
    class LigneBord : Border
    {
        public bool EstOuverte;   // ligne sélectionnée : cible du focus rendu après un rafraîchissement (défaut A)
        protected override System.Windows.Automation.Peers.AutomationPeer OnCreateAutomationPeer() { return new LignePeer(this); }
    }
    class LignePeer : System.Windows.Automation.Peers.FrameworkElementAutomationPeer
    {
        public LignePeer(FrameworkElement proprietaire) : base(proprietaire) { }
        protected override System.Windows.Automation.Peers.AutomationControlType GetAutomationControlTypeCore() { return System.Windows.Automation.Peers.AutomationControlType.ListItem; }
        protected override string GetClassNameCore() { return "Ligne"; }
        protected override bool IsControlElementCore() { return true; }
    }

    // Briques communes aux pages natives de la coquille : ligne de liste, titre de section, bouton d'action, disposition
    static class Briques
    {
        public static readonly FontFamily Chasse = new FontFamily("Cascadia Mono, Consolas");

        public static Color Couleur(int gravite) { return gravite == 2 ? Jetons.Danger : gravite == 1 ? Jetons.Attention : Jetons.TexteSecondaire; }

        // « score N » est illisible pour un non-informaticien : on montre le mot du produit (le chiffre reste au panneau de
        // détail). Gravité 0 = rien à signaler, aucune étiquette. Vocabulaire du service : Suspecte, Menace.
        public static string NiveauRisque(int gravite) { return gravite == 2 ? L.T("Menace") : gravite == 1 ? L.T("Suspecte") : ""; }
        // Chaînes : gravité 2 = score au-delà du seuil d'alerte (12), pas une menace avérée → « Alerte », pas « Menace »
        public static string NiveauChaine(int gravite) { return gravite == 2 ? L.T("Alerte") : gravite == 1 ? L.T("Suspecte") : ""; }

        // Carte de liste : barre de couleur à gauche, titre et étiquette d'état à droite, sous-ligne secondaire
        public static Border Ligne(string titre, string etiquette, string sous, int gravite, bool ouverte, bool estompee, Action choisir)
        {
            var couleur = Couleur(gravite);
            var cadre = new LigneBord
            {
                Background = Jetons.Pinceau(ouverte ? Jetons.Surface : Jetons.Carte), CornerRadius = new CornerRadius(6), Padding = new Thickness(14, 8, 14, 8),
                Margin = new Thickness(0, 0, 0, 6), BorderThickness = new Thickness(3, 0, 0, 0), BorderBrush = Jetons.Pinceau(couleur), Cursor = Cursors.Hand
            };
            // Contraste élevé : Carte == Surface, donc la sélection ne se voit pas par le fond ; on la marque par une bordure accent.
            if (ouverte && Jetons.ContrasteEleve) { cadre.BorderThickness = new Thickness(2); cadre.BorderBrush = Jetons.Pinceau(Jetons.Accent); }
            cadre.EstOuverte = ouverte;
            // Accessibilité : la ligne prend le focus (Tab puis flèches), s'active au clavier (Entrée/Espace) et porte un
            // nom lu par les lecteurs d'écran ; anneau de focus partagé ; fond en surface au survol et au focus clavier.
            cadre.Focusable = true;
            cadre.FocusVisualStyle = Jetons.StyleFocus();
            System.Windows.Automation.AutomationProperties.SetName(cadre, string.Join(", ", new[] { titre, etiquette, sous }.Where(x => !string.IsNullOrEmpty(x))));
            // Accessibilité (défaut A) : activer au clavier reconstruit la liste et détruit cette ligne ; on rend le focus
            // à la ligne ouverte de la liste reconstruite (sa référence change, mais le conteneur parent reste le même)
            cadre.KeyDown += (s, e) =>
            {
                if (e.Key == Key.Enter || e.Key == Key.Space)
                {
                    var parent = cadre.Parent as Panel;
                    choisir();
                    if (parent != null)
                        foreach (UIElement enfant in parent.Children)
                        {
                            var lb = enfant as LigneBord;
                            if (lb != null && lb.EstOuverte) { lb.Dispatcher.BeginInvoke(new Action(() => lb.Focus()), System.Windows.Threading.DispatcherPriority.Input); break; }
                        }
                    e.Handled = true;
                }
            };
            cadre.MouseEnter += (s, e) => { if (!ouverte) cadre.Background = Jetons.Pinceau(Jetons.Surface); };
            cadre.MouseLeave += (s, e) => { if (!ouverte) cadre.Background = Jetons.Pinceau(Jetons.Carte); };
            cadre.GotFocus += (s, e) => { if (!ouverte) cadre.Background = Jetons.Pinceau(Jetons.Surface); };
            cadre.LostFocus += (s, e) => { if (!ouverte) cadre.Background = Jetons.Pinceau(Jetons.Carte); };
            var pile = new StackPanel();
            var haut = new DockPanel();
            var et = new TextBlock { Text = etiquette, FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(estompee ? Jetons.TexteSecondaire : couleur), Margin = new Thickness(8, 0, 0, 0) };
            DockPanel.SetDock(et, Dock.Right);
            haut.Children.Add(et);
            haut.Children.Add(new TextBlock { Text = titre, Foreground = Jetons.Pinceau(estompee ? Jetons.TexteSecondaire : Jetons.Texte), TextTrimming = TextTrimming.CharacterEllipsis, ToolTip = titre });
            pile.Children.Add(haut);
            if (!string.IsNullOrEmpty(sous)) pile.Children.Add(new TextBlock { Text = sous, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextTrimming = TextTrimming.CharacterEllipsis, ToolTip = sous });
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
            System.Windows.Automation.AutomationProperties.SetName(b, texte);
            b.FocusVisualStyle = Jetons.StyleFocus();
            b.Click += clic;
            return b;
        }

        // Accessibilité (défaut A ; relecture de la refonte, défaut 4) : commun à toutes les pages qui reconstruisent une
        // liste au rafraîchissement périodique. Si le focus clavier était dans un des panneaux et que la reconstruction l'a
        // détruit, il est rendu à la ligne ouverte, sinon au contrôle de même rang, sinon (liste seulement, premier panneau)
        // à la première ligne : dans une barre d'outils, jamais à un bouton que l'utilisateur n'a pas choisi (prérelecture
        // de #205, D2)
        public static void GarderFocus(Action afficher, params Panel[] panneaux)
        {
            var avant = new int[panneaux.Length];
            for (int i = 0; i < panneaux.Length; i++) avant[i] = panneaux[i] != null && panneaux[i].IsKeyboardFocusWithin ? RangFocus(panneaux[i]) : -2;
            afficher();
            for (int i = 0; i < panneaux.Length; i++)
                if (avant[i] != -2 && !FocusEncoreDans(panneaux[i], Keyboard.FocusedElement as DependencyObject)) { RendreFocus(panneaux[i], avant[i], i == 0); break; }
        }

        // Juste après la reconstruction, IsKeyboardFocusWithin reste vrai : WPF ne retire le focus d'une ligne détruite
        // qu'un peu plus tard, puis le donne à la fenêtre (essai clavier en VM de #205). On regarde donc si l'élément
        // focalisé est encore dans le panneau
        public static bool FocusEncoreDans(Panel p, DependencyObject f)
        {
            return f != null && f is Visual && (f == p || p.IsAncestorOf(f));
        }

        static int RangFocus(Panel p)
        {
            for (int i = 0; i < p.Children.Count; i++) if (p.Children[i].IsKeyboardFocusWithin) return i;
            return -1;
        }

        public static void RendreFocus(Panel p, int rang, bool premierSinon)
        {
            var cible = CibleFocus(p, rang, premierSinon);
            if (cible != null) cible.Dispatcher.BeginInvoke(new Action(() => cible.Focus()), System.Windows.Threading.DispatcherPriority.Input);
        }

        // Le rang où était le focus d'abord : parcourir la liste aux flèches sans ouvrir de ligne ne doit pas être ramené à
        // la ligne ouverte à chaque rafraîchissement (relecture de #205, défaut A) ; la ligne ouverte seulement si ce rang
        // n'existe plus, puis la première ligne (liste seulement)
        public static UIElement CibleFocus(Panel p, int rang, bool premierSinon)
        {
            if (rang >= 0 && rang < p.Children.Count && p.Children[rang].Focusable) return p.Children[rang];
            foreach (UIElement c in p.Children) { var lb = c as LigneBord; if (lb != null && lb.EstOuverte) return lb; }
            if (premierSinon) foreach (UIElement c in p.Children) if (c.Focusable) return c;
            return null;
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
            // Accessibilité : Tab entre une fois dans la liste, les flèches déplacent le focus d'une ligne à l'autre.
            KeyboardNavigation.SetTabNavigation(liste, KeyboardNavigationMode.Once);
            KeyboardNavigation.SetDirectionalNavigation(liste, KeyboardNavigationMode.Contained);
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
                    Dispatcher.BeginInvoke((Action)(() => { if (numero == chargement) Briques.GarderFocus(() => Recevoir(lu, absent, pannes), liste); }));
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
                string sous = Canal.Visible(L.T(x.Niveau)) + "  ·  " + string.Join(", ", (x.Regles ?? new List<string>()).Select(Canal.Visible)) + "  ·  " + x.NombreAlertes + " " + L.T("alertes") + "  ·  " + Canal.Visible(x.DerniereActiviteUtc);
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
                    Dispatcher.BeginInvoke((Action)(() => { if (numero == chargement) Briques.GarderFocus(() => Recevoir(l, illisible), liste); }));
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
        public string Pays;     // code pays de la ligne (page Trafic, onglet Pays) : pilote la carte (T-19)
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
                    VueSante.AjouterMaj(l, Commun.Lire<EtatMaj>("maj.json"));
                    Dispatcher.BeginInvoke((Action)(() => { if (numero == chargement) { lignes = l; lu = true; vu = null; Briques.GarderFocus(Afficher, liste); } }));
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
                    Dispatcher.BeginInvoke((Action)(() => { if (numero == chargement) { ids = i; dpi = d; ips = c == null ? (bool?)null : c.Ips; lu = true; Briques.GarderFocus(Afficher, liste, outils); } }));
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
        int curseur = -1;   // tranche sous le curseur clavier (défaut 4) ; -1 = aucune
        public event Action<DateTime?, DateTime?> TrancheChoisie;

        public ChronologieFluent()
        {
            Height = 104; Cursor = Cursors.Hand; Margin = new Thickness(0, 0, 0, 12);
            // Accessibilité (défaut 4) : focus clavier et flèches, en plus du clic ; le contour de la tranche n'est tracé
            // que si la chronologie a le focus clavier, donc on redessine quand le focus entre ou sort
            Focusable = true; FocusVisualStyle = Jetons.StyleFocus();
            GotKeyboardFocus += (s, e) => InvalidateVisual();
            LostKeyboardFocus += (s, e) => InvalidateVisual();
        }

        public void Definir(ResultatSiem resultat, DateTime? debut) { r = resultat; choixDebut = debut; int n = Tranches; if (curseur >= n) curseur = n - 1; InvalidateVisual(); }

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
            // Accessibilité (défaut 4) : contour de la tranche sous le curseur clavier
            if (IsKeyboardFocused && curseur >= 0 && curseur < n)
                g.DrawRectangle(null, new Pen(Jetons.Pinceau(Jetons.Accent), 2), new Rect(Gauche + curseur * pas + 1, Haut - 2, Math.Max(1, pas - 2), h + 4));
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
            curseur = t; Focus(); InvalidateVisual();
            ChoisirTranche(t);
        }

        void ChoisirTranche(int t)
        {
            int n = Tranches;
            if (n == 0 || TrancheChoisie == null || t < 0 || t >= n) return;
            DateTime d, f;
            RechercheSiem.Tranche(r.Debut, r.Fin, n, t, out d, out f);
            if (choixDebut.HasValue && Math.Abs((choixDebut.Value - d).TotalSeconds) < 1) TrancheChoisie(null, null);
            else TrancheChoisie(d, f);
        }

        int IndexChoisi()
        {
            int n = Tranches;
            if (!choixDebut.HasValue) return -1;
            for (int t = 0; t < n; t++) { DateTime d, f; RechercheSiem.Tranche(r.Debut, r.Fin, n, t, out d, out f); if (Math.Abs((choixDebut.Value - d).TotalSeconds) < 1) return t; }
            return -1;
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            int n = Tranches;
            if (n > 0)
            {
                if (e.Key == Key.Home) { curseur = 0; InvalidateVisual(); e.Handled = true; }
                else if (e.Key == Key.End) { curseur = n - 1; InvalidateVisual(); e.Handled = true; }
                else if (e.Key == Key.Left || e.Key == Key.Right)
                {
                    if (curseur < 0) curseur = Math.Max(0, IndexChoisi());
                    else curseur = e.Key == Key.Left ? Math.Max(0, curseur - 1) : Math.Min(n - 1, curseur + 1);
                    InvalidateVisual(); e.Handled = true;
                }
                else if ((e.Key == Key.Enter || e.Key == Key.Space) && curseur >= 0) { ChoisirTranche(curseur); e.Handled = true; }
            }
            base.OnKeyDown(e);
        }

        string DescriptionGenerale() { return L.T("Chronologie des événements. Flèches gauche et droite pour parcourir les tranches, Entrée pour filtrer."); }

        string DescriptionCurseur()
        {
            int n = Tranches;
            if (curseur < 0 || curseur >= n) return DescriptionGenerale();
            DateTime d, f;
            RechercheSiem.Tranche(r.Debut, r.Fin, n, curseur, out d, out f);
            string format = (r.Fin - r.Debut).TotalHours > 24 ? "dd/MM HH:mm" : "HH:mm";
            return string.Format(L.T("{0} à {1} : {2} infos, {3} alertes, {4} critiques"), d.ToString(format), f.ToString(format), r.Compteurs[curseur, 0], r.Compteurs[curseur, 1], r.Compteurs[curseur, 2]);
        }

        internal string NomAccessible() { return curseur >= 0 ? DescriptionCurseur() : DescriptionGenerale(); }

        protected override System.Windows.Automation.Peers.AutomationPeer OnCreateAutomationPeer() { return new ChronologiePeer(this); }
    }

    // Accessibilité (défaut 4) : expose la chronologie aux lecteurs d'écran ; le nom décrit la tranche sous le curseur
    class ChronologiePeer : System.Windows.Automation.Peers.FrameworkElementAutomationPeer
    {
        public ChronologiePeer(ChronologieFluent o) : base(o) { }
        protected override System.Windows.Automation.Peers.AutomationControlType GetAutomationControlTypeCore() { return System.Windows.Automation.Peers.AutomationControlType.Custom; }
        protected override string GetClassNameCore() { return "Chronologie"; }
        protected override bool IsControlElementCore() { return true; }
        protected override string GetNameCore() { return ((ChronologieFluent)Owner).NomAccessible(); }
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

        // Filtre 0 : toutes ; 1 : suspectes (même seuil que la pastille : gravité >= 1, soit score au seuil d'alerte ou menace) ; 2 : menaces. Plus graves d'abord, puis score
        public static List<FluxInfo> Filtrer(IList<FluxInfo> flux, int filtre)
        {
            return (flux ?? new List<FluxInfo>()).Where(f => f != null && (filtre == 0 || (filtre == 1 && Gravite(f) >= 1) || (filtre == 2 && Gravite(f) == 2)))
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
            // Même seuil que l'onglet « Suspectes » et la pastille (gravité >= 1 : score au seuil d'alerte ou menace connue) ;
            // un score de 1 sous le seuil est compté à part, jamais dit suspect (T-4 : le sous-titre comptait score >= 1)
            int suspectes = l.Count(f => Gravite(f) >= 1), menaces = l.Count(f => Gravite(f) == 2);
            int faibles = l.Count(f => Gravite(f) == 0 && f.Score >= 1);
            string texte = string.Format(en ? "{0} live outbound connection(s), {1} suspicious, {2} to a known threat." : "{0} connexion(s) sortante(s) en direct, dont {1} suspecte(s) et {2} vers une menace connue.", l.Count, suspectes, menaces);
            if (faibles > 0)
                texte += " " + string.Format(en ? "{0} with a low score (1 to {1}), not counted as suspicious." : "{0} avec un score faible (1 à {1}), non comptée(s) comme suspecte(s).", faibles, Commun.SeuilAlerte - 1);
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

        // Identité publiée par l'étape 1 de T-20 (tête, PID, heure de création) : stable quand le plus vieux signal expire ;
        // service plus ancien : racine et heure du premier signal, comme avant
        public static string Cle(Chaine c) { return !string.IsNullOrEmpty(c.Identite) ? "i:" + c.Identite : (c.Racine ?? "") + "|" + (c.Depuis ?? ""); }

        // Chaînes au score positif, comme la page d'aujourd'hui ; les plus lourdes d'abord
        public static List<Chaine> Suspectes(IList<Chaine> chaines)
        {
            return (chaines ?? new List<Chaine>()).Where(c => c != null && c.Score > 0).OrderByDescending(c => c.Score).ThenBy(Cle, StringComparer.Ordinal).ToList();
        }

        public static List<string> Actions(NoeudChaine n)
        {
            var l = new List<string>();
            if (n == null) return l;
            // Processus vu terminé (T-20) : son PID a pu être repris par un autre programme, tuer et suspendre ne sont pas proposés
            if (n.Pid > 4 && !Termine(n)) { l.Add("tuerChaine"); l.Add("suspendre"); }
            // Chemin coupé par le service (« … ») : il ne désigne plus le programme, aucune action sur le fichier (T-20)
            if (!string.IsNullOrEmpty(n.Chemin) && !CheminCoupe(n.Chemin)) { l.Add("quarantaine"); l.Add("isolerProgramme"); l.Add("emplacement"); }
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

        // ---- T-20, étape 2 : dossier d'analyse (bandeau, résumé, que faire, graphe). Tout vient des champs publiés par
        // l'étape 1 (#323) ; avec un service plus ancien (champs absents), rien n'est affirmé de ce qu'il ne publie pas ----

        // Au-delà de 40 cases dans une couche du graphe, le reste est replié dans une case « +N de plus »
        public const int MaxParCouche = 40;
        public const double LargeurCase = 128, HauteurCase = 50, PasX = 158, PasY = 60, Marge = 10;
        public static readonly string[] Filtres = { "Tous", "Avec signaux", "Sans signal", "En cours", "Terminés", "Lien incertain" };
        static readonly string[] FiltresEn = { "All", "With signals", "Without signal", "Running", "Exited", "Uncertain link" };

        public static string NomFiltre(int k) { return k < 0 || k >= Filtres.Length ? "" : L.En ? FiltresEn[k] : Filtres[k]; }

        // Champs de l'étape 1 présents : le service écrit toujours Lien (code fermé, jamais vide) ; absent = service plus ancien
        public static bool Publie(NoeudChaine n) { return n != null && !string.IsNullOrEmpty(n.Lien); }
        public static bool NouveauFormat(Chaine c) { return c != null && c.Noeuds != null && c.Noeuds.Count > 0 && c.Noeuds.All(Publie); }
        // Tête de chaîne : son parent n'est pas suivi (raison dans Lien) ; « suivi » et « suivi-approche » ont un parent dans la chaîne
        public static bool EstTete(NoeudChaine n) { return Publie(n) && n.Lien != "suivi" && n.Lien != "suivi-approche"; }
        // Lien incertain : parent suivi à heure approchée, ou parent non suivi (sauf racine reconnue par chemin exact)
        public static bool LienIncertain(NoeudChaine n) { return Publie(n) && n.Lien != "suivi" && n.Lien != "racine-systeme"; }
        public static bool EnCours(NoeudChaine n) { return Publie(n) && n.Vivant == true; }
        public static bool Termine(NoeudChaine n) { return Publie(n) && n.Vivant == false; }

        // Chemin coupé par le service (au-delà de 1 024 caractères, « … » à la fin) : il ne désigne plus un fichier
        public static bool CheminCoupe(string chemin) { return !string.IsNullOrEmpty(chemin) && chemin.EndsWith("…", StringComparison.Ordinal); }

        public static bool Garde(NoeudChaine n, int filtre)
        {
            if (n == null) return false;
            switch (filtre)
            {
                case 1: return n.Score > 0;
                case 2: return n.Score <= 0;
                case 3: return EnCours(n);
                case 4: return Termine(n);
                case 5: return LienIncertain(n);
                default: return true;
            }
        }

        // Filtres 3 à 5 : faits publiés par l'étape 1 seulement ; avec un service plus ancien ils ne sont pas proposés (« 0 » serait faux)
        public static bool FiltrePropose(Chaine c, int filtre) { return filtre >= 0 && filtre < Filtres.Length && (filtre < 3 || NouveauFormat(c)); }
        public static int Compter(Chaine c, int filtre) { return c == null || c.Noeuds == null ? 0 : c.Noeuds.Count(n => Garde(n, filtre)); }

        // « AAAA-MM-JJ HH:MM:SS[.mmm] » → « HH:MM:SS » ; autre forme : le texte neutralisé tel quel
        public static string HeureCourte(string h)
        {
            if (string.IsNullOrEmpty(h)) return "";
            return h.Length >= 19 && h[10] == ' ' ? Canal.Visible(h.Substring(11, 8)) : Canal.Visible(h);
        }

        // Libellés anglais par règle (titres de docs/detection/regles.md) ; en français, la raison du service telle quelle
        static readonly Dictionary<string, string> LibellesEn = new Dictionary<string, string>
        {
            { "RES-001", "Connection to an address or a domain from the threat lists" }, { "RES-002", "Network: new connection with a suspicious score" },
            { "RES-003", "First Internet connection of a program" }, { "RES-004", "Public address directly on the PC" },
            { "RES-005", "Incoming packet from the Internet" }, { "RES-006", "New port open and listening on the network" },
            { "RES-007", "Incoming connection from the Internet" }, { "DNS-001", "DNS query to a known malicious domain" },
            { "DNS-002", "DNS server changed on an adapter" }, { "DNS-003", "DNS port of the loopback held by another program" },
            { "PRC-001", "Office document that launches an interpreter" }, { "PRC-002", "Obfuscated PowerShell or PowerShell that downloads code" },
            { "PRC-003", "Abuse of a Windows tool (LOLBin)" }, { "PRC-004", "Browser launched in remote debugging mode" },
            { "PRC-005", "Deletion of backups" }, { "CHA-001", "Process chain with a cumulative score" },
            { "PER-001", "New autostart" }, { "PER-002", "Modified autostart" },
            { "LEU-001", "Decoy modified, deleted, renamed or replaced by a link" }, { "LEU-002", "Decoy touched" },
            { "VOL-001", "Access to the secrets of a software by another program" }, { "SYS-001", "Hosts file modified by another program" },
            { "SYS-002", "Firewall rule added or modified" }, { "SYS-003", "All firewall rules deleted" },
            { "PIL-001", "Known vulnerable driver present" }, { "EXT-001", "New browser extension" }, { "BAS-001", "Baseline security setting undone" },
        };

        public static string Regle(string code)
        {
            if (string.IsNullOrEmpty(code)) return "";
            int i = code.IndexOf('#');
            return Canal.Visible(i < 0 ? code : code.Substring(0, i));
        }

        public static string LibelleSignal(SignalChaine s)
        {
            if (s == null) return "";
            string raison = Canal.Visible(s.Raison), l;
            if (!L.En) return raison.Length > 0 ? raison : Regle(s.Code);
            if (s.Code == "CHA-001#parent-service") return "Parent is the deR4Tizer service, but this is not one of its programs (spoofed parent?)";
            if (s.Code != null && LibellesEn.TryGetValue(Regle(s.Code), out l)) return l;
            return raison.Length > 0 ? raison : Regle(s.Code);
        }

        public static List<SignalChaine> Signaux(NoeudChaine n) { return n == null || n.Signaux == null ? new List<SignalChaine>() : n.Signaux.Where(s => s != null).ToList(); }

        public class LigneChrono { public string Heure, Derniere, Nom, Libelle, Regle; public int Score, Pid, Fois = 1; }

        // Chronologie des signaux, dans l'ordre de leur heure de rattachement (puis de publication) ; signaux identiques
        // (même programme, même libellé, même règle, même score) sur une seule ligne « ×N » à l'heure du premier ; service
        // plus ancien : les processus qui ont un score, sans heure, avec leurs raisons
        public static List<LigneChrono> Chronologie(Chaine c)
        {
            var noeuds = c == null || c.Noeuds == null ? new List<NoeudChaine>() : c.Noeuds.Where(n => n != null).ToList();
            var l = new List<KeyValuePair<string, LigneChrono>>();
            if (!NouveauFormat(c))
            {
                foreach (var n in noeuds.Where(n => n.Score > 0))
                    l.Add(new KeyValuePair<string, LigneChrono>("", new LigneChrono { Heure = "", Nom = Canal.Visible(n.Nom), Libelle = Canal.Visible(n.Raisons), Regle = "", Score = n.Score, Pid = n.Pid }));
                return l.Select(x => x.Value).ToList();
            }
            foreach (var n in noeuds)
                foreach (var s in Signaux(n))
                    l.Add(new KeyValuePair<string, LigneChrono>(s.Heure ?? "", new LigneChrono { Heure = HeureCourte(s.Heure), Nom = Canal.Visible(n.Nom), Libelle = LibelleSignal(s), Regle = Regle(s.Code), Score = s.Score, Pid = n.Pid }));
            var tries = l.Select((x, i) => new { x, i }).OrderBy(y => y.x.Key, StringComparer.Ordinal).ThenBy(y => y.i).Select(y => y.x.Value).ToList();
            var r = new List<LigneChrono>();
            var vues = new Dictionary<string, LigneChrono>();
            foreach (var x in tries)
            {
                string cle = x.Nom + "\u0001" + x.Libelle + "\u0001" + x.Regle + "\u0001" + x.Score;
                LigneChrono deja;
                if (vues.TryGetValue(cle, out deja)) { deja.Fois++; deja.Derniere = x.Heure; continue; }
                x.Derniere = x.Heure;
                vues[cle] = x; r.Add(x);
            }
            return r;
        }

        public static List<string> Techniques(Chaine c)
        {
            var vues = new List<string>();
            if (c == null || c.Noeuds == null) return vues;
            foreach (var n in c.Noeuds)
                foreach (var s in Signaux(n))
                    foreach (var t in s.Techniques ?? new List<string>())
                    {
                        string v = Canal.Visible(t);
                        if (v.Length > 0 && !vues.Contains(v)) vues.Add(v);
                    }
            return vues;
        }

        public static int NombreSignaux(Chaine c) { return c == null || c.Noeuds == null ? 0 : c.Noeuds.Where(n => n != null).Sum(n => Signaux(n).Count + Math.Max(0, n.SignauxTronques)); }
        public static int SignauxNonPublies(Chaine c) { return c == null || c.Noeuds == null ? 0 : c.Noeuds.Where(n => n != null).Sum(n => Math.Max(0, n.SignauxTronques)); }

        // Phrase de tête du résumé : faits publiés seulement (aucune interprétation de ce que la chaîne « a fait »)
        public static string Phrase(Chaine c)
        {
            bool en = L.En;
            var n = c == null || c.Noeuds == null ? new List<NoeudChaine>() : c.Noeuds.Where(x => x != null).ToList();
            if (c == null || n.Count == 0) return en ? "No process published for this chain." : "Aucun processus publié pour cette chaîne.";
            var tete = n[0];
            string seuil = c.Score >= SeuilChaine ? (en ? "above the alert threshold (12)" : "au-delà du seuil d'alerte (12)") : (en ? "below the alert threshold (12)" : "sous le seuil d'alerte (12)");
            string texte = string.Format(en ? "{0} (PID {1}) heads a chain of {2} published process(es)." : "{0} (PID {1}) est en tête d'une chaîne de {2} processus publié(s).", Canal.Visible(tete.Nom), tete.Pid, n.Count);
            int avec = n.Count(x => x.Score > 0);
            if (NouveauFormat(c)) texte += " " + string.Format(en ? "{0} signal(s) on {1} of them; chain score {2}, {3}." : "{0} signal(s) sur {1} d'entre eux ; score de la chaîne {2}, {3}.", NombreSignaux(c), n.Count(x => Signaux(x).Count > 0 || x.SignauxTronques > 0), c.Score, seuil);
            else texte += " " + string.Format(en ? "{0} of them carry a score; chain score {1}, {2}." : "{0} d'entre eux portent un score ; score de la chaîne {1}, {2}.", avec, c.Score, seuil);
            return texte;
        }

        public class CaseBandeau { public string Titre, Valeur, Sous; public int Gravite; }

        // Alerte liée : la dernière alerte CHA-001 dont l'entité est celle de la chaîne (comparée sans casse, comme la page
        // Incidents) ; jamais devinée par le PID ou le texte « chaîne : … » (service plus ancien : aucune)
        public static Alerte AlerteLiee(Chaine c, IList<Alerte> alertes)
        {
            if (c == null || alertes == null || string.IsNullOrWhiteSpace(c.Entite)) return null;
            string e = c.Entite.Trim();
            Alerte r = null;
            foreach (var a in alertes)
                if (a != null && a.Regle == "CHA-001" && string.Equals((a.Entite ?? "").Trim(), e, StringComparison.OrdinalIgnoreCase)) r = a;
            return r;
        }

        // Incident de même entité : un incident non clos d'abord, puis le plus récent
        public static IncidentSuivi IncidentLie(Chaine c, IList<IncidentSuivi> incidents)
        {
            if (c == null || incidents == null || string.IsNullOrWhiteSpace(c.Entite)) return null;
            string e = c.Entite.Trim();
            return incidents.Where(i => i != null && string.Equals((i.Entite ?? "").Trim(), e, StringComparison.OrdinalIgnoreCase))
                .OrderBy(i => i.Etat == "Clos" ? 1 : 0).ThenByDescending(i => i.DerniereActiviteUtc ?? "", StringComparer.Ordinal).FirstOrDefault();
        }

        public static string EtatIncident(IncidentSuivi i)
        {
            bool en = L.En;
            if (i == null) return "";
            return i.Etat == "Clos" ? (en ? "incident closed" : "incident clos") : i.Etat == "PrisEnCharge" ? (en ? "incident taken in charge" : "incident pris en charge") : (en ? "incident open" : "incident ouvert");
        }

        // Bandeau de 5 cases : niveau, processus, signaux, premier signal, alerte liée. alertes : null = alertes.json illisible
        public static List<CaseBandeau> Bandeau(Chaine c, IList<Alerte> alertes, IList<IncidentSuivi> incidents)
        {
            bool en = L.En;
            var r = new List<CaseBandeau>();
            if (c == null) return r;
            var n = c.Noeuds == null ? new List<NoeudChaine>() : c.Noeuds.Where(x => x != null).ToList();
            bool nouveau = NouveauFormat(c);
            int g = Gravite(c);
            r.Add(new CaseBandeau { Titre = en ? "Level" : "Niveau", Valeur = g > 0 ? Briques.NiveauChaine(g) : (en ? "Low score" : "Score faible"), Sous = "score " + c.Score + "  ·  " + (en ? "alert above 12" : "alerte au-delà de 12"), Gravite = g });
            string sousP = !nouveau ? (en ? "running state not published (older service)" : "état non publié (service plus ancien)")
                : string.Format(en ? "{0} running  ·  {1} exited" : "{0} en cours  ·  {1} terminé(s)", n.Count(EnCours), n.Count(Termine));
            if (c.NoeudsTronques > 0) sousP += "  ·  " + string.Format(en ? "{0} more not published" : "{0} de plus non publié(s)", c.NoeudsTronques);
            r.Add(new CaseBandeau { Titre = en ? "Processes" : "Processus", Valeur = n.Count.ToString(), Sous = sousP });
            if (nouveau)
            {
                int techniques = Techniques(c).Count, non = SignauxNonPublies(c);
                string sousS = string.Format(en ? "on {0} process(es)  ·  {1} technique(s)" : "sur {0} processus  ·  {1} technique(s)", n.Count(x => Signaux(x).Count > 0 || x.SignauxTronques > 0), techniques);
                if (non > 0) sousS += "  ·  " + string.Format(en ? "{0} not published" : "{0} non publié(s)", non);
                r.Add(new CaseBandeau { Titre = en ? "Signals" : "Signaux", Valeur = NombreSignaux(c).ToString(), Sous = sousS });
                var heures = n.SelectMany(x => Signaux(x)).Select(s => s.Heure ?? "").Where(h => h.Length > 0).OrderBy(h => h, StringComparer.Ordinal).ToList();
                var tete = n.FirstOrDefault();
                string sousT = tete == null || string.IsNullOrEmpty(tete.Creation) ? "" : string.Format(en ? "head started {0} ({1})" : "tête lancée à {0} ({1})", HeureCourte(tete.Creation),
                    tete.CreationExacte == true ? (en ? "exact" : "exacte") : (en ? "approx." : "approchée"));
                r.Add(new CaseBandeau { Titre = en ? "First signal" : "Premier signal", Valeur = heures.Count > 0 ? HeureCourte(heures[0]) : "?", Sous = sousT });
            }
            else
            {
                r.Add(new CaseBandeau { Titre = en ? "Signals" : "Signaux", Valeur = n.Count(x => x.Score > 0).ToString(), Sous = en ? "processes with a score (signals not published by this service version)" : "processus avec un score (signaux non publiés par cette version du service)" });
                r.Add(new CaseBandeau { Titre = en ? "First signal" : "Premier signal", Valeur = HeureCourte(c.Depuis), Sous = (en ? "since " : "depuis ") + Canal.Visible(c.Depuis) });
            }
            var titreA = en ? "Linked alert" : "Alerte liée";
            if (string.IsNullOrWhiteSpace(c.Entite))
                r.Add(new CaseBandeau { Titre = titreA, Valeur = en ? "Not linked" : "Non liée", Sous = en ? "chain entity not published" : "entité de la chaîne non publiée" });
            else if (alertes == null)
                r.Add(new CaseBandeau { Titre = titreA, Valeur = "?", Sous = en ? "alertes.json unreadable: nothing is concluded" : "alertes.json illisible : rien n'est conclu" });
            else
            {
                var al = AlerteLiee(c, alertes);
                if (al == null) r.Add(new CaseBandeau { Titre = titreA, Valeur = en ? "None found" : "Aucune trouvée", Sous = en ? "no CHA-001 alert with this entity in alertes.json" : "aucune alerte CHA-001 de cette entité dans alertes.json" });
                else
                {
                    var inc = IncidentLie(c, incidents);
                    string sousA = "CHA-001  ·  " + HeureCourte(al.Heure) + (inc != null ? "  ·  " + EtatIncident(inc) : "");
                    r.Add(new CaseBandeau { Titre = titreA, Valeur = Canal.Visible(L.T(al.Niveau)), Sous = sousA, Gravite = al.Niveau == "Critique" ? 2 : al.Niveau == "Alerte" ? 1 : 0 });
                }
            }
            return r;
        }

        // Processus encore en cours (PID utilisable) ; cible proposée par « Que faire » : le plus lourd, le plus profond à égalité
        public static List<NoeudChaine> Vivants(Chaine c) { return c == null || c.Noeuds == null ? new List<NoeudChaine>() : c.Noeuds.Where(n => EnCours(n) && n.Pid > 4).ToList(); }
        public static NoeudChaine Cible(Chaine c)
        {
            NoeudChaine r = null;
            foreach (var n in Vivants(c)) if (r == null || n.Score >= r.Score) r = n;
            return r;
        }

        public static string TexteLien(string lien)
        {
            bool en = L.En;
            switch (lien ?? "")
            {
                case "suivi": return en ? "followed: parent alive when this process started" : "suivi : parent vivant au lancement de ce processus";
                case "suivi-approche": return en ? "followed, parent time approximated (±10 s): its 4688 event is missing" : "suivi, heure du parent approchée (±10 s) : son événement 4688 manque";
                case "racine-systeme": return en ? "system root (recognised by its exact path, or PID 1 to 4)" : "racine du système (reconnue par son chemin exact, ou PID 1 à 4)";
                case "parent-inconnu": return en ? "parent not followed: unknown parent (absent from the tree, older than one hour or never seen)" : "parent non suivi : parent inconnu (absent de l'arbre, plus vieux d'une heure ou jamais vu)";
                case "pid-reutilise": return en ? "parent not followed: PID reused (now held by a process started after this one)" : "parent non suivi : PID repris (tenu par un processus lancé après celui-ci)";
                case "parent-termine": return en ? "parent not followed: the parent was seen gone before this process started" : "parent non suivi : le parent a été vu terminé avant le lancement de ce processus";
                case "parent-service": return en ? "parent not followed: the deR4Tizer service, but this is not one of its programs (spoofed parent?)" : "parent non suivi : le service de deR4Tizer, mais ce n'est pas un de ses programmes (parent usurpé ?)";
                case "profondeur-max": return en ? "parent not followed: walk up stopped at 32 processes" : "parent non suivi : remontée arrêtée à 32 processus";
                case "": return en ? "nature of the link not published (older service)" : "nature du lien non publiée (service plus ancien)";
            }
            return Canal.Visible(lien);
        }

        // Trait vers une case : 0 plein (parent suivi, ou service plus ancien : nature non publiée), 1 pointillé (heure du
        // parent approchée), 2 tirets (parent non suivi, vers la case fantôme), 3 plein discret (racine du système)
        public static int StyleLien(string lien, bool nouveau)
        {
            if (!nouveau) return 0;
            switch (lien ?? "")
            {
                case "suivi": return 0;
                case "suivi-approche": return 1;
                case "racine-systeme": return 3;
            }
            return 2;
        }

        // Sous-titre court de la case fantôme (parent non suivi de la tête)
        public static string SousFantome(string lien)
        {
            bool en = L.En;
            switch (lien ?? "")
            {
                case "racine-systeme": return en ? "system root" : "racine du système";
                case "parent-inconnu": return en ? "unknown parent" : "parent inconnu";
                case "pid-reutilise": return en ? "PID reused" : "PID repris";
                case "parent-termine": return en ? "parent ended before" : "parent terminé avant";
                case "parent-service": return en ? "spoofed parent?" : "parent usurpé ?";
                case "profondeur-max": return en ? "depth limit (32)" : "limite de 32";
            }
            return en ? "parent not published" : "parent non publié";
        }

        public static string EtatProcessus(NoeudChaine n)
        {
            bool en = L.En;
            if (n == null) return "";
            if (!Publie(n)) return "PID " + n.Pid + "  ·  " + (en ? "running state not published (older service)" : "état non publié (service plus ancien)");
            if (n.Vivant == true) return "PID " + n.Pid + "  ·  " + (en ? "running" : "en cours");
            return "PID " + n.Pid + "  ·  " + (en ? "exited" : "terminé") + (string.IsNullOrEmpty(n.Fin) ? "" : ", " + (en ? "seen gone at " : "vu disparu à ") + HeureCourte(n.Fin));
        }

        public static string Naissance(NoeudChaine n)
        {
            bool en = L.En;
            if (!Publie(n) || string.IsNullOrEmpty(n.Creation)) return null;
            return (en ? "started " : "lancé le ") + Canal.Visible(n.Creation) + " (" + (n.CreationExacte == true ? (en ? "exact, audit 4688" : "exacte, audit 4688") : (en ? "approx., first process list that showed it" : "approchée, première liste des processus qui l'a montré")) + ")";
        }

        // « Lancé par » : parent dans la chaîne (nom, PID, lien) ; tête : nom publié du parent ou son PID, et pourquoi il n'est pas suivi
        public static string LancePar(Chaine c, NoeudChaine n)
        {
            bool en = L.En;
            if (n == null || !Publie(n)) return null;
            if (!EstTete(n))
            {
                var p = c == null || c.Noeuds == null ? null : c.Noeuds.FirstOrDefault(x => x != null && x.Pid == n.ParentPid);
                return (p != null ? Canal.Visible(p.Nom) + "  ·  " : "") + "PID " + n.ParentPid;
            }
            string nom = Canal.Visible(n.ParentNom);
            return (nom.Length > 0 ? nom + "  ·  " : "") + (n.ParentPid > 0 ? "PID " + n.ParentPid : (en ? "no parent PID" : "aucun PID parent")) + "  ·  " + (en ? "not in the chain" : "hors de la chaîne");
        }

        public static string Limites(bool nouveau)
        {
            bool en = L.En;
            string t = en ? "Limits: a chain lists only the ancestors of the flagged processes (their siblings without a signal are never in it); the time of a signal is when it was attached to the chain (3 s cycle), not the time of the original event; an end time is an upper bound (“seen gone at”)."
                          : "Limites : une chaîne ne contient que les ancêtres des processus signalés (leurs frères sans signal n'y sont jamais) ; l'heure d'un signal est celle de son rattachement à la chaîne (cycle de 3 s), pas celle de l'événement d'origine ; une heure de fin est une borne haute (« vu disparu à »).";
            if (!nouveau) t += " " + (en ? "This service version does not publish parents, states or signals: the graph follows the indentation of the text view and says nothing of the nature of the links."
                                         : "Cette version du service ne publie ni parents, ni états, ni signaux : le graphe suit le retrait de la vue texte et ne dit rien de la nature des liens.");
            return t;
        }

        // ---- Graphe en couches : parents à gauche, enfants à droite ; répétitions regroupées ; repli au-delà de 40 par couche ----

        // Clé des répétitions : même parent, même programme, même ligne de commande publiée (300 premiers caractères), mêmes codes
        public static string CleRepetition(NoeudChaine n)
        {
            var codes = Signaux(n).Select(s => s.Code ?? "").Distinct().OrderBy(x => x, StringComparer.Ordinal);
            return n.ParentPid + "\u0001" + (n.Nom ?? "") + "\u0001" + (n.Chemin ?? "") + "\u0001" + (n.LigneCommande ?? "") + "\u0001" + string.Join(",", codes) + "\u0001" + (n.Lien ?? "");
        }

        // Clé stable d'une case (sélection et focus) : processus ou groupe (PID du premier), fantôme (PID de la tête), repli (couche)
        public static string CleCase(CaseChaine c)
        {
            if (c == null) return null;
            if (c.Repli) return "r" + c.Couche;
            if (c.Fantome) return "f" + (c.Enfants.Count > 0 && c.Enfants[0].Premier != null ? c.Enfants[0].Premier.Pid : 0);
            return (c.Membres.Count > 1 ? "g" : "p") + (c.Premier != null ? c.Premier.Pid : 0);
        }

        public static GrapheChaine Graphe(Chaine c, bool regrouper, int? choisi)
        {
            var g = new GrapheChaine();
            var noeuds = c == null || c.Noeuds == null ? new List<NoeudChaine>() : c.Noeuds.Where(n => n != null).ToList();
            bool nouveau = NouveauFormat(c);
            int k = noeuds.Count;
            g.Processus = k;
            var parent = new int[k];
            var parPid = new Dictionary<long, int>();
            var pile = new List<int>();
            for (int i = 0; i < k; i++)
            {
                var n = noeuds[i];
                int p = -1;
                if (nouveau)
                {
                    int j;
                    // Le service publie un parent avant ses enfants (chaines::chaine_publiee) : seul un nœud déjà vu peut être parent
                    if (!EstTete(n) && parPid.TryGetValue(n.ParentPid, out j)) p = j;
                }
                else
                {
                    // Service plus ancien : parent déduit du retrait (dernier nœud de la profondeur au-dessus), comme la vue texte
                    int prof = Math.Max(0, n.Profondeur);
                    if (prof > 0 && prof - 1 < pile.Count) p = pile[prof - 1];
                    if (pile.Count > prof) pile.RemoveRange(prof, pile.Count - prof);
                    while (pile.Count < prof) pile.Add(p);
                    pile.Add(i);
                }
                if (!parPid.ContainsKey(n.Pid)) parPid[n.Pid] = i;
                parent[i] = p;
            }
            var enfants = new List<int>[k];
            var racines = new List<int>();
            for (int i = 0; i < k; i++) enfants[i] = new List<int>();
            for (int i = 0; i < k; i++) { if (parent[i] >= 0) enfants[parent[i]].Add(i); else racines.Add(i); }

            // Cases dans l'ordre de publication, couche par couche (file) ; fantôme à gauche de chaque tête (étape 1 seulement)
            var toutes = new List<CaseChaine>();
            var file = new Queue<KeyValuePair<CaseChaine, List<int>>>();
            Func<List<int>, CaseChaine, int, CaseChaine> creer = (membres, pere, couche) =>
            {
                var cs = new CaseChaine { Id = toutes.Count, Parent = pere, Couche = couche };
                foreach (int m in membres) cs.Membres.Add(noeuds[m]);
                cs.Lien = cs.Premier.Lien ?? "";
                if (pere != null) pere.Enfants.Add(cs);
                toutes.Add(cs);
                file.Enqueue(new KeyValuePair<CaseChaine, List<int>>(cs, membres));
                return cs;
            };
            Action<List<int>, CaseChaine, int> regrouperEnfants = (indices, pere, couche) =>
            {
                if (!regrouper || !nouveau) { foreach (int i in indices) creer(new List<int> { i }, pere, couche); return; }
                var ordre = new List<string>();
                var paquets = new Dictionary<string, List<int>>();
                foreach (int i in indices)
                {
                    string cle = CleRepetition(noeuds[i]);
                    List<int> l;
                    if (!paquets.TryGetValue(cle, out l)) { l = new List<int>(); paquets[cle] = l; ordre.Add(cle); }
                    l.Add(i);
                }
                foreach (var cle in ordre) creer(paquets[cle], pere, couche);
            };
            foreach (int r in racines)
            {
                if (nouveau)
                {
                    var n = noeuds[r];
                    var f = new CaseChaine { Id = toutes.Count, Couche = 0, Fantome = true, Lien = n.Lien ?? "" };
                    string nom = Canal.Visible(n.ParentNom);
                    f.Titre = nom.Length > 0 ? nom : n.ParentPid > 0 ? "PID " + n.ParentPid : (L.En ? "no parent" : "aucun parent");
                    f.Sous = SousFantome(EstTete(n) ? n.Lien : null);
                    toutes.Add(f);
                    creer(new List<int> { r }, f, 1);
                }
                else creer(new List<int> { r }, null, 0);
            }
            while (file.Count > 0)
            {
                var x = file.Dequeue();
                var fils = x.Value.SelectMany(m => enfants[m]).Distinct().OrderBy(m => m).ToList();
                if (fils.Count > 0) regrouperEnfants(fils, x.Key, x.Key.Couche + 1);
            }

            // Poids du sous-arbre (somme des scores) : priorité pour rester visible quand une couche dépasse 40 cases
            for (int i = toutes.Count - 1; i >= 0; i--)
            {
                var cs = toutes[i];
                cs.Poids += cs.Membres.Sum(m => (double)Math.Max(0, m.Score));
                if (cs.Parent != null) cs.Parent.Poids += cs.Poids;
            }
            var chemin = new HashSet<CaseChaine>();
            if (choisi.HasValue)
                for (var cs = toutes.FirstOrDefault(x => x.Membres.Any(m => m.Pid == choisi.Value)); cs != null; cs = cs.Parent) chemin.Add(cs);
            int couches = toutes.Count == 0 ? 0 : toutes.Max(x => x.Couche) + 1;
            var replis = new List<CaseChaine>();
            for (int co = 0; co < couches; co++)
            {
                var dans = toutes.Where(x => x.Couche == co).ToList();
                var masquees = dans.Where(x => x.Parent != null && x.Parent.Masquee).ToList();
                var candidates = dans.Where(x => !(x.Parent != null && x.Parent.Masquee)).ToList();
                if (candidates.Count > MaxParCouche)
                {
                    var gardees = new HashSet<CaseChaine>(candidates.OrderBy(x => chemin.Contains(x) ? 0 : 1).ThenByDescending(x => x.Poids).ThenBy(x => x.Id).Take(MaxParCouche));
                    masquees.AddRange(candidates.Where(x => !gardees.Contains(x)));
                }
                foreach (var m in masquees) m.Masquee = true;
                if (masquees.Count > 0)
                {
                    var rp = new CaseChaine { Id = toutes.Count + replis.Count, Couche = co, Repli = true };
                    foreach (var m in masquees.OrderBy(x => x.Id)) rp.Replies.AddRange(m.Membres);
                    rp.Titre = "+" + rp.Replies.Count + " " + (L.En ? "more" : "de plus");
                    rp.Sous = L.En ? "open the list" : "ouvrir la liste";
                    replis.Add(rp);
                }
            }
            g.CasesAvantRepli = toutes.Count;

            // Placement en O(n) : une colonne par couche ; feuilles l'une sous l'autre dans l'ordre publié, parent centré sur ses enfants
            var visibles = toutes.Where(x => !x.Masquee).ToList();
            double rang = 0;
            var pileDfs = new Stack<KeyValuePair<CaseChaine, bool>>();
            foreach (var r in visibles.Where(x => x.Parent == null).Reverse()) pileDfs.Push(new KeyValuePair<CaseChaine, bool>(r, false));
            while (pileDfs.Count > 0)
            {
                var e = pileDfs.Pop();
                var cs = e.Key;
                var fils = cs.Enfants.Where(x => !x.Masquee).ToList();
                if (!e.Value && fils.Count > 0)
                {
                    pileDfs.Push(new KeyValuePair<CaseChaine, bool>(cs, true));
                    for (int i = fils.Count - 1; i >= 0; i--) pileDfs.Push(new KeyValuePair<CaseChaine, bool>(fils[i], false));
                    continue;
                }
                if (fils.Count == 0) { cs.Y = Marge + rang * PasY; rang++; }
                else cs.Y = (fils[0].Y + fils[fils.Count - 1].Y) / 2;
                cs.X = Marge + cs.Couche * PasX;
            }
            foreach (var rp in replis)
            {
                var memes = visibles.Where(x => x.Couche == rp.Couche).ToList();
                rp.X = Marge + rp.Couche * PasX;
                rp.Y = memes.Count == 0 ? Marge : memes.Max(x => x.Y) + PasY;
            }
            g.Cases = visibles.Concat(replis).ToList();
            g.Largeur = g.Cases.Count == 0 ? 0 : g.Cases.Max(x => x.X) + LargeurCase + Marge + 8;
            g.Hauteur = g.Cases.Count == 0 ? 0 : g.Cases.Max(x => x.Y) + HauteurCase + Marge;
            return g;
        }

        // Clavier du graphe : Gauche = parent, Droite = premier enfant, Haut/Bas = case voisine de la même couche, Début = première
        public static CaseChaine Voisin(GrapheChaine g, CaseChaine c, string touche)
        {
            if (g == null || g.Cases.Count == 0) return null;
            if (c == null || touche == "Debut") return g.Cases.OrderBy(x => x.Couche).ThenBy(x => x.Y).First();
            switch (touche)
            {
                case "Gauche": return c.Parent != null && g.Cases.Contains(c.Parent) ? c.Parent : c;
                case "Droite": var f = c.Enfants.Where(x => g.Cases.Contains(x)).OrderBy(x => x.Y).FirstOrDefault(); return f ?? c;
                case "Haut": var h = g.Cases.Where(x => x.Couche == c.Couche && x.Y < c.Y).OrderByDescending(x => x.Y).FirstOrDefault(); return h ?? c;
                case "Bas": var b = g.Cases.Where(x => x.Couche == c.Couche && x.Y > c.Y).OrderBy(x => x.Y).FirstOrDefault(); return b ?? c;
            }
            return c;
        }

        // Nom lu par le Narrateur pour une case (la couleur ne porte jamais le sens seule)
        public static string NomCase(CaseChaine c)
        {
            bool en = L.En;
            if (c == null) return "";
            if (c.Repli) return c.Titre + ", " + (en ? "folded boxes" : "cases repliées");
            if (c.Fantome) return c.Titre + ", " + c.Sous + ", " + (en ? "parent not in the chain" : "parent hors de la chaîne");
            var n = c.Premier;
            string t = Canal.Visible(n.Nom) + (c.Membres.Count > 1 ? ", ×" + c.Membres.Count : ", PID " + n.Pid);
            if (c.Score > 0) t += ", +" + c.Score;
            if (c.Membres.Count == 1 && Publie(n)) t += ", " + (n.Vivant == true ? (en ? "running" : "en cours") : (en ? "exited" : "terminé"));
            if (c.Membres.Count > 1) t += ", " + string.Format(en ? "{0} running" : "{0} en cours", c.Membres.Count(EnCours));
            return t;
        }

        // Copie du dossier : en-tête de la chaîne puis une ligne par processus (valeurs d'origine échappées, comme Copie)
        public static string CopieDossier(Chaine c, Alerte a)
        {
            if (c == null) return "";
            var l = new List<string> { VueReseauFluent.Copie(c.Resume, "score " + c.Score, c.Depuis, a == null ? "" : a.Regle + " " + a.Niveau + " " + a.Heure) };
            foreach (var n in c.Noeuds ?? new List<NoeudChaine>())
                if (n != null) l.Add(VueReseauFluent.Copie(new string(' ', Math.Min(Math.Max(n.Profondeur, 0), 32) * 2) + (n.Nom ?? ""), n.Pid.ToString(), n.Score > 0 ? n.Score.ToString() : "", n.Raisons, n.LigneCommande, n.Chemin));
            return string.Join("\r\n", l);
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
                    object annexes = Annexes();
                    Dispatcher.BeginInvoke((Action)(() => { if (numero == chargement) { lu = true; illisible = e == null; RecevoirAnnexes(annexes); if (e != null) { misAJour = e.MisAJour; panne = p; Recevoir(e); } Briques.GarderFocus(Afficher, liste); } }));
                }
                finally { System.Threading.Interlocked.Exchange(ref enCours, 0); }
            });
        }

        // Illisible : la dernière liste reste, plutôt qu'un vide qui rassure
        protected abstract void Recevoir(Etat e);
        protected abstract void Afficher();
        // Autres fichiers lus hors du fil de l'interface avec etat.json (page Chaînes : alertes et incidents, T-20)
        protected virtual object Annexes() { return null; }
        protected virtual void RecevoirAnnexes(object annexes) { }

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

        // Filtre choisi par une autre page (Trafic, pays signalé : 1, Suspectes)
        internal void Filtrer(int f) { filtre = f; choisie = null; vu = null; Afficher(); }
        internal int FiltreActuel { get { return filtre; } }

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
                liste.Children.Add(Briques.Ligne(Canal.Visible(f.Processus) + "  →  " + VueConnexionsFluent.Destination(f), Briques.NiveauRisque(VueConnexionsFluent.Gravite(f)), VueConnexionsFluent.Sous(f),
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

    // Case du graphe d'une chaîne (T-20) : un processus, un groupe de répétitions (×N), une case fantôme (parent non suivi de
    // la tête, hors de la chaîne) ou un repli « +N de plus » (au-delà de 40 cases dans une couche)
    public class CaseChaine
    {
        public int Id, Couche;
        public readonly List<NoeudChaine> Membres = new List<NoeudChaine>();
        public CaseChaine Parent;
        public readonly List<CaseChaine> Enfants = new List<CaseChaine>();
        public bool Fantome, Repli, Masquee;
        public string Titre, Sous, Lien;
        public readonly List<NoeudChaine> Replies = new List<NoeudChaine>();
        public double X, Y, Poids;
        public NoeudChaine Premier { get { return Membres.Count > 0 ? Membres[0] : null; } }
        public int Score { get { return Membres.Count == 0 ? 0 : Membres.Max(m => m.Score); } }
    }

    public class GrapheChaine
    {
        public List<CaseChaine> Cases = new List<CaseChaine>();
        public int Processus, CasesAvantRepli;
        public double Largeur, Hauteur;
    }

    // Page Chaînes en WPF (U4a ; T-20, étape 2) : chaînes de processus lues dans etat.json. Deux vues : « Graphe » (dossier
    // d'analyse : bandeau, résumé, que faire, filtres, graphe en couches, panneau de détail) et « Texte » (la liste et l'arbre
    // en retrait d'avant T-20). Mêmes actions et mêmes questions que le menu de la liste d'aujourd'hui (ISourceReponses) ;
    // aucune commande ni réglage nouveau
    class PageChainesFluent : PageEtatServiceFluent
    {
        List<Chaine> chaines = new List<Chaine>();
        string choisie;
        int? noeud;             // vue texte : PID du processus choisi dans l'arbre
        // Vue retenue pour la session de l'interface (aucun réglage écrit)
        static bool vueTexte;
        // Vue graphe : case choisie (CleCase, ou « p<PID> » pour un membre d'un groupe), case du focus clavier, filtre, regroupement
        string choixCase, courant;
        int filtre;
        bool regrouper = true, tousMembres, resumeOuvert = true, faireOuvert = true, tronquees, tousSelecteur;
        double zoom = 1;
        bool zoomAuto = true;
        bool amener;            // la prochaine reconstruction amène la case choisie à la vue (choix de l'utilisateur)   // ajusté à la largeur (entre 60 et 100 %) tant que l'utilisateur n'a pas choisi un zoom
        List<Alerte> alertes = new List<Alerte>();      // null : alertes.json illisible
        List<IncidentSuivi> incidents = new List<IncidentSuivi>();
        DateTime dateAlertes = DateTime.MinValue, dateIncidents = DateTime.MinValue;
        readonly Action<string> ouvrirAlerte;
        // Vue graphe : conteneurs gardés d'un rafraîchissement à l'autre (le focus clavier reste sur le graphe)
        readonly ContentControl hoteSelecteur = new ContentControl(), hoteBandeau = new ContentControl(), hoteResume = new ContentControl(), hoteFiltres = new ContentControl(), hoteDetail = new ContentControl(), hoteEntete = new ContentControl(), hoteBas = new ContentControl();
        readonly Border hoteGraphe = new Border { Focusable = true, CornerRadius = new CornerRadius(6), Padding = new Thickness(4) };
        readonly ScrollViewer defileGraphe = new ScrollViewer { HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Focusable = false, MaxHeight = 460 };
        readonly ScaleTransform echelle = new ScaleTransform(1, 1);
        GrapheChaine graphe;
        readonly Dictionary<string, FrameworkElement> elementsCases = new Dictionary<string, FrameworkElement>();
        System.Windows.Shapes.Rectangle anneau;
        readonly StackPanel bascule = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        ScrollViewer defileListe;
        Border panneauDetail;
        bool grapheConstruit;
        Grid grilleGraphe;

        public PageChainesFluent(ISourceReponses source) : this(source, null) { }

        public PageChainesFluent(ISourceReponses source, Action<string> ouvrirAlerte) : base(source, "Processus", true)
        {
            this.ouvrirAlerte = ouvrirAlerte;
            foreach (UIElement e in Children)
            {
                var sv = e as ScrollViewer;
                if (sv != null && sv.Content == liste) defileListe = sv;
                var b = e as Border;
                if (b != null && Grid.GetColumn(b) == 1) panneauDetail = b;
            }
            hoteGraphe.FocusVisualStyle = Jetons.StyleFocus();
            hoteGraphe.Background = Jetons.Pinceau(Jetons.Fond);
            hoteGraphe.Child = defileGraphe;
            hoteGraphe.KeyDown += ToucheGraphe;
            hoteGraphe.GotKeyboardFocus += (s, e) => PlacerAnneau();
            hoteGraphe.LostKeyboardFocus += (s, e) => PlacerAnneau();
            hoteGraphe.MouseLeftButtonDown += (s, e) => hoteGraphe.Focus();
            hoteGraphe.SizeChanged += (s, e) => { if (zoomAuto) AjusterLargeur(); };
            outils.Children.Add(bascule);
            Afficher();
        }

        protected override void Recevoir(Etat e) { chaines = VueChainesFluent.Suspectes(e.Chaines); tronquees = e.ChainesTronquees; }

        // alertes.json et suivi-incidents.json : relus seulement quand ils changent (alerte liée par l'entité de la chaîne)
        protected override object Annexes()
        {
            var r = new object[4];
            var da = DateFichier("alertes.json");
            // Lecture manquée (fichier illisible ou en cours d'écriture) : « ? » affiché, relu au prochain tour (date oubliée)
            if (da != dateAlertes) { bool absent; var a = LectureFluent.Lire<List<Alerte>>("alertes.json", out absent); r[0] = absent ? new List<Alerte>() : a; r[1] = r[0] == null ? DateTime.MinValue : da; }
            var di = DateFichier("suivi-incidents.json");
            if (di != dateIncidents) { bool absent; var i = LectureFluent.Lire<List<IncidentSuivi>>("suivi-incidents.json", out absent); r[2] = absent ? new List<IncidentSuivi>() : i; r[3] = r[2] == null ? DateTime.MinValue : di; }
            return r;
        }

        protected override void RecevoirAnnexes(object o)
        {
            var r = o as object[];
            if (r == null) return;
            if (r[1] is DateTime) { alertes = r[0] as List<Alerte>; dateAlertes = (DateTime)r[1]; }
            if (r[3] is DateTime) { incidents = r[2] as List<IncidentSuivi> ?? new List<IncidentSuivi>(); dateIncidents = (DateTime)r[3]; }
        }

        static DateTime DateFichier(string nom)
        {
            try { var f = System.IO.Path.Combine(Commun.Dossier, nom); return System.IO.File.Exists(f) ? System.IO.File.GetLastWriteTimeUtc(f) : DateTime.MinValue.AddTicks(1); } catch { return DateTime.MinValue.AddTicks(2); }
        }

        string Resume()
        {
            string t = VueChainesFluent.Resume(chaines, lu, illisible, misAJour, panne);
            if (lu && tronquees) t += "\n" + (L.En ? "Some chains, processes or signals were left out of etat.json by the service (size budget): the list is incomplete." : "Des chaînes, processus ou signaux ont été laissés hors d'etat.json par le service (budget de taille) : la liste est incomplète.");
            return t;
        }

        protected override void Afficher()
        {
            resume.Text = Resume();
            resume.Foreground = Jetons.Pinceau(illisible || panne != null || tronquees ? Jetons.Attention : chaines.Any(c => c.Score >= VueChainesFluent.SeuilChaine) ? Jetons.Danger : Jetons.TexteSecondaire);
            Basculer();
            if (vueTexte) AfficherTexte(); else AfficherGraphe();
        }

        // Bascule Graphe / Texte, en haut à droite ; le choix est retenu pour la session
        void Basculer()
        {
            bascule.Children.Clear();
            foreach (var texte in new[] { false, true })
            {
                bool t = texte, actif = vueTexte == t;
                var b = new Button
                {
                    Content = t ? (L.En ? "Text" : "Texte") : (L.En ? "Graph" : "Graphe"), Padding = new Thickness(14, 4, 14, 4), Margin = new Thickness(6, 0, 0, 10), Cursor = Cursors.Hand,
                    Background = Jetons.Pinceau(actif ? Jetons.Surface : Jetons.Fond), BorderBrush = Jetons.Pinceau(actif ? Jetons.Accent : Jetons.Separateur), BorderThickness = new Thickness(1), Foreground = Jetons.Pinceau(Jetons.Texte)
                };
                b.Template = Coquille.ModeleBouton();
                b.FocusVisualStyle = Jetons.StyleFocus();
                System.Windows.Automation.AutomationProperties.SetName(b, (L.En ? "View: " : "Vue : ") + b.Content + (actif ? (L.En ? ", selected" : ", choisie") : ""));
                b.Click += (s, e) =>
                {
                    if (vueTexte == t) return;
                    // La sélection suit d'une vue à l'autre
                    if (t) { int pid; if (choixCase != null && choixCase.Length > 1 && (choixCase[0] == 'p' || choixCase[0] == 'g') && int.TryParse(choixCase.Substring(1), out pid)) noeud = pid; }
                    else if (noeud.HasValue) choixCase = "p" + noeud.Value;
                    vueTexte = t; vu = null; grapheConstruit = false;
                    Afficher();
                    var cible = bascule.Children.Count > (t ? 1 : 0) ? bascule.Children[t ? 1 : 0] : null;
                    if (cible != null) cible.Dispatcher.BeginInvoke(new Action(() => cible.Focus()), System.Windows.Threading.DispatcherPriority.Input);
                };
                bascule.Children.Add(b);
            }
        }

        // ---------------- Vue texte : la page d'avant T-20 ----------------

        void AfficherTexte()
        {
            if (grapheConstruit || panneauDetail.Visibility != Visibility.Visible)
            {
                grapheConstruit = false;
                panneauDetail.Visibility = Visibility.Visible;
                Grid.SetColumnSpan(defileListe, 1);
                KeyboardNavigation.SetTabNavigation(liste, KeyboardNavigationMode.Once);
                KeyboardNavigation.SetDirectionalNavigation(liste, KeyboardNavigationMode.Contained);
                vu = null;
            }
            var c0 = chaines.FirstOrDefault(c => VueChainesFluent.Cle(c) == choisie) ?? chaines.FirstOrDefault();
            choisie = c0 == null ? null : VueChainesFluent.Cle(c0);
            var noeuds = c0 == null ? new List<NoeudChaine>() : (c0.Noeuds ?? new List<NoeudChaine>());
            var n0 = noeuds.FirstOrDefault(n => n.Pid == noeud) ?? noeuds.OrderByDescending(n => n.Score).FirstOrDefault();
            noeud = n0 == null ? (int?)null : n0.Pid;
            string signature = "T#" + choisie + "#" + noeud + "#" + resume.Text + "#" + string.Join(";", chaines.Select(c => VueChainesFluent.Cle(c) + "|" + c.Score + "|" + string.Join(",", (c.Noeuds ?? new List<NoeudChaine>()).Select(n => n.Pid + ":" + n.Score + ":" + n.Vivant + ":" + n.Chemin))));
            if (signature == vu) return;
            vu = signature;
            liste.Children.Clear();
            // Avant la première lecture, le résumé dit « Lecture en cours… » ; liste vide après lecture : le résumé le dit
            foreach (var c in chaines)
            {
                string cle = VueChainesFluent.Cle(c);
                liste.Children.Add(Briques.Ligne(Canal.Visible(c.Resume), Briques.NiveauChaine(VueChainesFluent.Gravite(c)), VueChainesFluent.Sous(c), VueChainesFluent.Gravite(c), cle == choisie, false, () => { choisie = cle; noeud = null; Afficher(); }));
            }
            Detailler(c0, n0);
        }

        void Detailler(Chaine c, NoeudChaine n0)
        {
            bool en = L.En;
            bool rendreFocus = detail.IsKeyboardFocusWithin;
            var noeudFocalise = Keyboard.FocusedElement as LigneBord;
            object pidFocus = rendreFocus && noeudFocalise != null ? noeudFocalise.Tag : null;
            if (c == null) { detail.Content = new TextBlock { Text = en ? "Select a chain to read who launched what." : "Sélectionnez une chaîne pour lire qui a lancé quoi.", Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap }; return; }
            var pile = new StackPanel();
            pile.Children.Add(new TextBlock { Text = Canal.Visible(c.Resume), FontSize = 16, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            pile.Children.Add(new TextBlock { Text = "score " + c.Score + "  ·  " + (en ? "alert above 12" : "alerte au-delà de 12"), FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Briques.Couleur(VueChainesFluent.Gravite(c))), Margin = new Thickness(0, 2, 0, 4) });
            pile.Children.Add(Briques.Titre(en ? "Who launched what" : "Qui a lancé quoi", 10));
            UIElement noeudChoisi = null, noeudFocus = null;
            foreach (var n in c.Noeuds ?? new List<NoeudChaine>())
            {
                int pid = n.Pid;
                int g = VueChainesFluent.GraviteNoeud(c, n);
                bool ouvert = n == n0;
                var ligne = new LigneBord
                {
                    Background = Jetons.Pinceau(ouvert ? Jetons.Surface : Jetons.Carte), CornerRadius = new CornerRadius(4), Padding = new Thickness(8, 3, 8, 3),
                    Margin = new Thickness(Math.Min(Math.Max(n.Profondeur, 0), 8) * 14, 0, 0, 2), Cursor = Cursors.Hand, Tag = pid
                };
                var texte = new TextBlock { TextTrimming = TextTrimming.CharacterEllipsis };
                texte.Inlines.Add(new System.Windows.Documents.Run((n.Profondeur > 0 ? "└ " : "") + Canal.Visible(n.Nom)) { Foreground = Jetons.Pinceau(n.Score > 0 ? Jetons.Texte : Jetons.TexteSecondaire) });
                texte.Inlines.Add(new System.Windows.Documents.Run("  " + pid + (n.Score > 0 ? "  ·  +" + n.Score : "")) { Foreground = Jetons.Pinceau(n.Score > 0 ? Briques.Couleur(g) : Jetons.TexteSecondaire), FontSize = 12 });
                ligne.Child = texte;
                // Accessibilité (défaut 4) : focus clavier, activation Entrée/Espace, nom lu par les lecteurs d'écran
                ligne.Focusable = true;
                ligne.FocusVisualStyle = Jetons.StyleFocus();
                System.Windows.Automation.AutomationProperties.SetName(ligne, Canal.Visible(n.Nom) + ", PID " + pid + (n.Score > 0 ? ", +" + n.Score : ""));
                Action activer = () => { noeud = pid; Afficher(); };
                ligne.MouseLeftButtonUp += (s, e) => activer();
                ligne.KeyDown += (s, e) => { if (e.Key == Key.Enter || e.Key == Key.Space) { activer(); e.Handled = true; } };
                ligne.MouseEnter += (s, e) => { if (!ouvert) ligne.Background = Jetons.Pinceau(Jetons.Surface); };
                ligne.MouseLeave += (s, e) => { if (!ouvert) ligne.Background = Jetons.Pinceau(Jetons.Carte); };
                ligne.GotFocus += (s, e) => { if (!ouvert) ligne.Background = Jetons.Pinceau(Jetons.Surface); };
                ligne.LostFocus += (s, e) => { if (!ouvert) ligne.Background = Jetons.Pinceau(Jetons.Carte); };
                if (ouvert && noeudChoisi == null) noeudChoisi = ligne;
                if (pidFocus is int && (int)pidFocus == pid) noeudFocus = ligne;
                pile.Children.Add(ligne);
            }
            if (n0 != null)
            {
                pile.Children.Add(new TextBlock { Text = Canal.Visible(n0.Nom), FontSize = 14, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 14, 0, 0), TextWrapping = TextWrapping.Wrap });
                Lignes(pile, VueChainesFluent.Detail(n0));
                NotesActions(pile, n0);
                Actions(pile, VueChainesFluent.Actions(n0), a => Agir(n0, a));
            }
            detail.Content = pile;
            // Accessibilité (défaut 4) : si le focus clavier était dans le détail, le rendre au nœud ouvert après reconstruction
            var cibleNoeud = noeudFocus ?? noeudChoisi;
            if (rendreFocus && cibleNoeud != null) cibleNoeud.Dispatcher.BeginInvoke(new Action(() => cibleNoeud.Focus()), System.Windows.Threading.DispatcherPriority.Input);
        }

        // Pourquoi une action manque (processus terminé, chemin coupé) : dit au lieu de cacher
        static void NotesActions(StackPanel pile, NoeudChaine n)
        {
            bool en = L.En;
            if (VueChainesFluent.Termine(n) && n.Pid > 4)
                pile.Children.Add(Note(en ? "This process has exited: kill and suspend are not offered (its PID may now belong to another program)." : "Ce processus est terminé : tuer et suspendre ne sont pas proposés (son PID peut désigner aujourd'hui un autre programme)."));
            if (VueChainesFluent.CheminCoupe(n.Chemin))
                pile.Children.Add(Note(en ? "Path cut by the service (too long): no action on the program file is offered." : "Chemin coupé par le service (trop long) : aucune action sur le fichier du programme n'est proposée."));
        }

        static TextBlock Note(string texte, double haut = 8)
        {
            return new TextBlock { Text = texte, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, haut, 0, 4) };
        }

        void Agir(NoeudChaine n, string action)
        {
            if (action == "copier") { VueReseauFluent.Copier(VueChainesFluent.Copie(n)); return; }
            if (source == null) return;
            if (action == "emplacement") source.OuvrirEmplacement(n.Chemin);
            else source.AgirElement(n, action);
            Charger();
        }

        // ---------------- Vue graphe : dossier d'analyse ----------------

        void ConstruireGraphe()
        {
            grapheConstruit = true;
            panneauDetail.Visibility = Visibility.Collapsed;
            Grid.SetColumnSpan(defileListe, 2);
            // Toute la page défile ; Tab parcourt les contrôles et entre une fois dans le graphe (ses flèches lui appartiennent)
            KeyboardNavigation.SetTabNavigation(liste, KeyboardNavigationMode.Continue);
            KeyboardNavigation.SetDirectionalNavigation(liste, KeyboardNavigationMode.None);
            liste.Children.Clear();
            liste.Children.Add(hoteSelecteur);
            liste.Children.Add(hoteBandeau);
            liste.Children.Add(hoteResume);
            liste.Children.Add(hoteFiltres);
            // Graphe et détail construits une seule fois : leurs conteneurs gardent leur parent d'une bascule à l'autre
            if (grilleGraphe == null)
            {
                var gauche = new StackPanel();
                gauche.Children.Add(hoteEntete);
                gauche.Children.Add(hoteGraphe);
                gauche.Children.Add(hoteBas);
                var carteD = Carte(hoteDetail, 20);
                carteD.VerticalAlignment = VerticalAlignment.Top;
                grilleGraphe = DeuxColonnes(Carte(gauche, 16), carteD, 380);
            }
            liste.Children.Add(grilleGraphe);
            vu = null;
        }

        static Border Carte(UIElement contenu, double pad)
        {
            return new Border { Background = Jetons.Pinceau(Jetons.Carte), CornerRadius = new CornerRadius(8), Padding = new Thickness(pad, pad - 2, pad, pad), Child = contenu };
        }

        static Grid DeuxColonnes(UIElement g, UIElement d, double droite)
        {
            var grille = new Grid();
            grille.ColumnDefinitions.Add(new ColumnDefinition());
            grille.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(14) });
            grille.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(droite) });
            grille.Children.Add(g); Grid.SetColumn(d, 2); grille.Children.Add(d);
            return grille;
        }

        Chaine ChaineChoisie()
        {
            var c0 = chaines.FirstOrDefault(c => VueChainesFluent.Cle(c) == choisie) ?? chaines.FirstOrDefault();
            choisie = c0 == null ? null : VueChainesFluent.Cle(c0);
            return c0;
        }

        // Case de la sélection : « g »/« p » + PID (groupe ou processus), « f » fantôme, « r » repli
        CaseChaine CaseDe(string cle)
        {
            if (graphe == null || cle == null || cle.Length < 2) return null;
            var exacte = graphe.Cases.FirstOrDefault(x => VueChainesFluent.CleCase(x) == cle);
            if (exacte != null) return exacte;
            int pid;
            if ((cle[0] == 'p' || cle[0] == 'g') && int.TryParse(cle.Substring(1), out pid)) return graphe.Cases.FirstOrDefault(x => x.Membres.Any(m => m.Pid == pid));
            return null;
        }

        int? PidChoisi()
        {
            int pid;
            if (choixCase != null && choixCase.Length > 1 && (choixCase[0] == 'p' || choixCase[0] == 'g') && int.TryParse(choixCase.Substring(1), out pid)) return pid;
            return null;
        }

        void AfficherGraphe()
        {
            if (!grapheConstruit) ConstruireGraphe();
            var c0 = ChaineChoisie();
            if (c0 != null && choixCase == null)
            {
                var plus = (c0.Noeuds ?? new List<NoeudChaine>()).Where(n => n != null).OrderByDescending(n => n.Score).FirstOrDefault();
                if (plus != null) choixCase = "g" + plus.Pid;
            }
            if (c0 != null && !VueChainesFluent.FiltrePropose(c0, filtre)) filtre = 0;
            var lien = VueChainesFluent.AlerteLiee(c0, alertes);
            var inc = VueChainesFluent.IncidentLie(c0, incidents);
            string signature = "G#" + choisie + "#" + choixCase + "#" + courant + "#" + filtre + "#" + regrouper + "#" + tousMembres + "#" + resumeOuvert + "#" + faireOuvert + "#" + resume.Text + "#" + (alertes == null ? "?" : lien == null ? "-" : lien.Id + lien.Niveau) + "#" + (inc == null ? "-" : inc.Id + inc.Etat) + "#"
                + string.Join(";", chaines.Select(c => VueChainesFluent.Cle(c) + "|" + c.Score + "|" + c.NoeudsTronques + "|" + (c == c0 ? string.Join(",", (c.Noeuds ?? new List<NoeudChaine>()).Where(n => n != null).Select(n => n.Pid + ":" + n.Score + ":" + n.Vivant + ":" + n.Fin + ":" + n.Lien + ":" + VueChainesFluent.Signaux(n).Count + ":" + n.SignauxTronques + ":" + n.Chemin)) : (c.Noeuds == null ? 0 : c.Noeuds.Count).ToString())));
            if (signature == vu) return;
            vu = signature;
            bool focusFiltres = hoteFiltres.IsKeyboardFocusWithin;
            hoteSelecteur.Content = Selecteur();
            if (c0 == null)
            {
                hoteBandeau.Content = hoteResume.Content = hoteFiltres.Content = hoteEntete.Content = hoteBas.Content = null;
                defileGraphe.Content = null; graphe = null;
                hoteDetail.Content = new TextBlock { Text = L.En ? "Select a chain to read who launched what." : "Sélectionnez une chaîne pour lire qui a lancé quoi.", Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap };
                ((FrameworkElement)liste.Children[liste.Children.Count - 1]).Visibility = lu ? Visibility.Collapsed : Visibility.Visible;
                return;
            }
            ((FrameworkElement)liste.Children[liste.Children.Count - 1]).Visibility = Visibility.Visible;
            hoteBandeau.Content = Bandeau(c0);
            hoteResume.Content = ResumeEtFaire(c0, lien, inc);
            hoteFiltres.Content = BarreFiltres(c0);
            if (focusFiltres) RendreFocusFiltres();
            graphe = VueChainesFluent.Graphe(c0, regrouper, PidChoisi());
            var choix = CaseDe(choixCase);
            if (choix == null && graphe.Cases.Count > 0) { choix = graphe.Cases.FirstOrDefault(x => !x.Fantome && !x.Repli) ?? graphe.Cases[0]; choixCase = VueChainesFluent.CleCase(choix); }
            if (CaseDe(courant) == null) courant = choix == null ? null : VueChainesFluent.CleCase(choix);
            hoteEntete.Content = EnteteGraphe(c0);
            DessinerGraphe(c0, choix);
            hoteBas.Content = BasGraphe(c0);
            hoteDetail.Content = DetailCase(c0, choix, lien);
        }

        // Sélecteur : une pastille par chaîne suspecte (niveau en mots) ; Tab y entre une fois, les flèches passent de l'une à l'autre
        UIElement Selecteur()
        {
            var w = new WrapPanel { Margin = new Thickness(0, 0, 0, 8) };
            KeyboardNavigation.SetTabNavigation(w, KeyboardNavigationMode.Once);
            KeyboardNavigation.SetDirectionalNavigation(w, KeyboardNavigationMode.Contained);
            // Au plus 10 pastilles (plus la chaîne choisie) tant que la liste n'est pas dépliée ; la vue texte les liste toutes
            var montrees = tousSelecteur || chaines.Count <= 12 ? chaines : chaines.Where((c, i) => i < 10 || VueChainesFluent.Cle(c) == choisie).ToList();
            foreach (var c in montrees)
            {
                string cle = VueChainesFluent.Cle(c);
                int g = VueChainesFluent.Gravite(c);
                int n = c.Noeuds == null ? 0 : c.Noeuds.Count;
                var ligne = Briques.Ligne(Canal.Visible(c.Resume), Briques.NiveauChaine(g), "score " + c.Score + "  ·  " + n + " " + (L.En ? "process(es)" : "processus"), g, cle == choisie, false,
                    () => { if (choisie == cle) return; choisie = cle; choixCase = null; courant = null; tousMembres = false; zoomAuto = true; Afficher(); });
                ligne.MaxWidth = 380; ligne.Margin = new Thickness(0, 0, 8, 6);
                w.Children.Add(ligne);
            }
            if (montrees.Count < chaines.Count)
                w.Children.Add(Bouton(string.Format(L.En ? "Show the {0} other chains" : "Montrer les {0} autres chaînes", chaines.Count - montrees.Count), false, () => { tousSelecteur = true; vu = null; Afficher(); }));
            return w;
        }

        UIElement Bandeau(Chaine c)
        {
            var cases = VueChainesFluent.Bandeau(c, alertes, incidents);
            var g = new Grid { Margin = new Thickness(0, 4, 0, 12) };
            for (int i = 0; i < cases.Count; i++)
            {
                if (i > 0) g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(10) });
                g.ColumnDefinitions.Add(new ColumnDefinition());
            }
            for (int i = 0; i < cases.Count; i++)
            {
                var x = cases[i];
                var couleur = Briques.Couleur(x.Gravite);
                var b = new Border { Background = Jetons.Pinceau(Jetons.Carte), BorderBrush = Jetons.Pinceau(couleur), BorderThickness = new Thickness(3, 0, 0, 0), CornerRadius = new CornerRadius(Jetons.Rayon), Padding = new Thickness(12, 9, 10, 10) };
                var p = new StackPanel();
                p.Children.Add(new TextBlock { Text = x.Titre, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire) });
                p.Children.Add(new TextBlock { Text = x.Valeur, FontSize = 20, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(x.Gravite > 0 ? couleur : Jetons.Texte), Margin = new Thickness(0, 3, 0, 0), TextTrimming = TextTrimming.CharacterEllipsis });
                p.Children.Add(new TextBlock { Text = x.Sous, FontSize = 11.5, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 0) });
                b.Child = p;
                System.Windows.Automation.AutomationProperties.SetName(b, x.Titre + " : " + x.Valeur + ", " + x.Sous);
                Grid.SetColumn(b, i * 2); g.Children.Add(b);
            }
            return g;
        }

        // Titre de section repliable (Résumé, Que faire) : bouton, état dit par le chevron et lu par le Narrateur
        Button TitreSection(string texte, string droite, bool ouvert, Action basculer)
        {
            // Titre à gauche, toujours entier ; précision à droite, coupée si la place manque
            var d = new Grid();
            d.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            d.ColumnDefinitions.Add(new ColumnDefinition());
            if (!string.IsNullOrEmpty(droite)) { var t = new TextBlock { Text = droite, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Right, TextTrimming = TextTrimming.CharacterEllipsis, Margin = new Thickness(12, 0, 0, 0), ToolTip = droite }; Grid.SetColumn(t, 1); d.Children.Add(t); }
            var titre = new TextBlock { FontSize = 15, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Jetons.Texte) };
            titre.Inlines.Add(new System.Windows.Documents.Run(ouvert ? "  " : "  ") { FontFamily = Jetons.Icones, FontSize = 11, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire) });
            titre.Inlines.Add(new System.Windows.Documents.Run(texte));
            d.Children.Add(titre);
            var b = new Button { Content = d, HorizontalContentAlignment = HorizontalAlignment.Stretch, Background = Brushes.Transparent, BorderThickness = new Thickness(0), Padding = new Thickness(0, 0, 0, ouvert ? 8 : 0), Cursor = Cursors.Hand, Foreground = Jetons.Pinceau(Jetons.Texte) };
            b.Template = Coquille.ModeleBouton();
            b.FocusVisualStyle = Jetons.StyleFocus();
            System.Windows.Automation.AutomationProperties.SetName(b, texte + ", " + (ouvert ? (L.En ? "expanded" : "ouvert") : (L.En ? "collapsed" : "replié")));
            b.Click += (s, e) => { basculer(); Afficher(); };
            return b;
        }

        UIElement ResumeEtFaire(Chaine c, Alerte lien, IncidentSuivi inc)
        {
            bool en = L.En;
            bool nouveau = VueChainesFluent.NouveauFormat(c);
            var chrono = VueChainesFluent.Chronologie(c);
            // Résumé : une phrase de faits, puis la chronologie des signaux par code ; jamais une interprétation
            var res = new StackPanel();
            res.Children.Add(TitreSection(en ? "Summary" : "Résumé", resumeOuvert ? (en ? "built from the signals, nothing guessed" : "construit à partir des signaux, rien de deviné") : VueChainesFluent.Phrase(c), resumeOuvert, () => resumeOuvert = !resumeOuvert));
            if (resumeOuvert)
            {
                res.Children.Add(new TextBlock { Text = VueChainesFluent.Phrase(c), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 10) });
                foreach (var l in chrono.Take(60))
                {
                    var g = new Grid { Margin = new Thickness(0, 0, 0, 4) };
                    g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(nouveau ? 64 : 0) });
                    g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(104) });
                    g.ColumnDefinitions.Add(new ColumnDefinition());
                    g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(34) });
                    g.Children.Add(new TextBlock { Text = l.Heure, FontFamily = Briques.Chasse, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, 1, 0, 0) });
                    var nom = new TextBlock { Text = l.Nom + (l.Fois > 1 ? " ×" + l.Fois : ""), FontWeight = FontWeights.SemiBold, TextTrimming = TextTrimming.CharacterEllipsis, ToolTip = l.Fois > 1 ? string.Format(en ? "{0} times, {1} to {2}" : "{0} fois, de {1} à {2}", l.Fois, l.Heure, l.Derniere) : l.Nom + "  ·  PID " + l.Pid }; Grid.SetColumn(nom, 1); g.Children.Add(nom);
                    var lib = new TextBlock { Text = l.Libelle + (l.Regle.Length > 0 ? " (" + l.Regle + ")" : ""), TextWrapping = TextWrapping.Wrap, FontSize = 13 }; Grid.SetColumn(lib, 2); g.Children.Add(lib);
                    var sc = new TextBlock { Text = "+" + l.Score, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Briques.Couleur(c.Score >= VueChainesFluent.SeuilChaine ? 2 : l.Score >= Commun.SeuilAlerte ? 1 : 0)), HorizontalAlignment = HorizontalAlignment.Right }; Grid.SetColumn(sc, 3); g.Children.Add(sc);
                    res.Children.Add(g);
                }
                if (chrono.Count > 60) res.Children.Add(Note(string.Format(en ? "{0} more signal(s): see each process in the graph or the text view." : "{0} signal(s) de plus : voir chaque processus dans le graphe ou la vue texte.", chrono.Count - 60), 2));
                int non = VueChainesFluent.SignauxNonPublies(c);
                if (non > 0) res.Children.Add(Note(string.Format(en ? "{0} signal(s) not published by the service (limit of 20 per process or size budget); they still count in the score." : "{0} signal(s) non publié(s) par le service (20 par processus au plus, ou budget de taille) ; ils comptent toujours dans le score.", non), 2));
                var tech = VueChainesFluent.Techniques(c);
                if (tech.Count > 0) res.Children.Add(Note((en ? "Techniques: " : "Techniques : ") + string.Join(", ", tech), 6));
            }
            // Que faire : conseils de l'alerte liée ; tuer et suspendre seulement sur un processus encore en cours
            var faire = new StackPanel();
            var vivants = VueChainesFluent.Vivants(c);
            string droiteF = !nouveau ? "" : string.Format(en ? "{0} process(es) still run" : "{0} processus encore en cours", vivants.Count);
            faire.Children.Add(TitreSection(en ? "What to do" : "Que faire", faireOuvert ? (lien != null ? (en ? "from the linked alert" : "d'après l'alerte liée") : "") : droiteF, faireOuvert, () => faireOuvert = !faireOuvert));
            if (faireOuvert)
            {
                int k = 1;
                if (!nouveau) faire.Children.Add(Etape(k++, en ? "This service version does not say which processes still run: act on a process from the graph or the text view." : "Cette version du service ne dit pas quels processus tournent encore : agissez sur un processus depuis le graphe ou la vue texte.", null));
                else if (vivants.Count == 0) faire.Children.Add(Etape(k++, en ? "No process of this chain is still running: there is nothing to kill or suspend." : "Aucun processus de cette chaîne ne tourne encore : rien à tuer ni à suspendre.", null));
                else
                {
                    var cible = VueChainesFluent.Cible(c);
                    string noms = string.Join(", ", vivants.Take(4).Select(n => Canal.Visible(n.Nom) + " " + n.Pid)) + (vivants.Count > 4 ? ", …" : "");
                    var boutons = new List<UIElement>();
                    if (source != null && cible != null)
                    {
                        boutons.Add(Bouton(string.Format(en ? "Kill {0} (PID {1}) and its descendants" : "Tuer {0} (PID {1}) et sa descendance", Canal.Visible(cible.Nom), cible.Pid), true, () => Agir(cible, "tuerChaine")));
                        boutons.Add(Bouton(string.Format(en ? "Suspend (PID {0})" : "Suspendre (PID {0})", cible.Pid), false, () => Agir(cible, "suspendre")));
                    }
                    faire.Children.Add(Etape(k++, string.Format(en ? "Kill the chain: {0} process(es) still run ({1})." : "Tuer la chaîne : {0} processus tournent encore ({1}).", vivants.Count, noms),
                        en ? "state read in etat.json; the same confirmation as everywhere else" : "état lu dans etat.json ; même confirmation que partout ailleurs", boutons.ToArray()));
                }
                if (lien != null && !string.IsNullOrWhiteSpace(lien.Conseil))
                    faire.Children.Add(Etape(k++, Canal.Visible(L.T(lien.Conseil)), string.Format(en ? "advice of the linked alert {0} (service text)" : "conseil de l'alerte liée {0} (texte du service)", Canal.Visible(lien.Regle))));
                if (inc != null) faire.Children.Add(Etape(k++, string.Format(en ? "Follow the response in the incident ({0})." : "Suivez la réponse dans l'incident ({0}).", VueChainesFluent.EtatIncident(inc)), Canal.Visible(inc.Id)));
                var fin = new List<UIElement>();
                if (lien != null && ouvrirAlerte != null) { string id = lien.Id; fin.Add(Bouton(en ? "Open the linked alert" : "Ouvrir l'alerte liée", false, () => ouvrirAlerte(id))); }
                fin.Add(Bouton(en ? "Copy the dossier" : "Copier le dossier", false, () => VueReseauFluent.Copier(VueChainesFluent.CopieDossier(c, lien))));
                faire.Children.Add(Etape(k++, null, null, fin.ToArray()));
            }
            var gauche = Carte(res, 16);
            var droite = Carte(faire, 16);
            var grille = new Grid { Margin = new Thickness(0, 0, 0, 12) };
            grille.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(11, GridUnitType.Star) });
            grille.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(14) });
            grille.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(9, GridUnitType.Star) });
            grille.Children.Add(gauche); Grid.SetColumn(droite, 2); grille.Children.Add(droite);
            return grille;
        }

        static UIElement Etape(int n, string texte, string source, params UIElement[] boutons)
        {
            var d = new DockPanel { Margin = new Thickness(0, 0, 0, 10) };
            if (texte != null)
            {
                var rond = new Border { Width = 22, Height = 22, CornerRadius = new CornerRadius(11), Background = Jetons.Pinceau(Jetons.Surface), VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 0, 10, 0) };
                rond.Child = new TextBlock { Text = n.ToString(), FontSize = 12, FontWeight = FontWeights.SemiBold, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
                DockPanel.SetDock(rond, Dock.Left); d.Children.Add(rond);
            }
            var p = new StackPanel();
            if (texte != null) p.Children.Add(new TextBlock { Text = texte, TextWrapping = TextWrapping.Wrap });
            if (source != null) p.Children.Add(new TextBlock { Text = source, FontSize = 11.5, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 0) });
            if (boutons.Length > 0) { var w = new WrapPanel { Margin = new Thickness(0, 6, 0, -6) }; foreach (var b in boutons) w.Children.Add(b); p.Children.Add(w); }
            d.Children.Add(p);
            return d;
        }

        // Action au libellé long (PID dans le texte) : il passe à la ligne au lieu d'être coupé
        static Button ActionLongue(string texte, bool fort, Action clic)
        {
            var b = Briques.Action(texte, fort, (s, e) => clic());
            b.Content = new TextBlock { Text = texte, TextWrapping = TextWrapping.Wrap };
            return b;
        }

        static Button Bouton(string texte, bool fort, Action clic)
        {
            var b = Briques.Action(texte, fort, (s, e) => clic());
            b.HorizontalAlignment = HorizontalAlignment.Left;
            b.Margin = new Thickness(0, 0, 8, 6);
            return b;
        }

        // Filtres par type de nœud avec compteurs, puis « Regrouper les répétitions » (bouton dont l'état est écrit)
        UIElement BarreFiltres(Chaine c)
        {
            bool en = L.En;
            var w = new WrapPanel { Margin = new Thickness(0, 0, 0, 10) };
            for (int k = 0; k < VueChainesFluent.Filtres.Length; k++)
            {
                if (!VueChainesFluent.FiltrePropose(c, k)) continue;
                int n = k;
                bool actif = n == filtre;
                var b = new Button
                {
                    Content = VueChainesFluent.NomFiltre(k) + "  " + VueChainesFluent.Compter(c, k), Padding = new Thickness(12, 4, 12, 4), Margin = new Thickness(0, 0, 8, 6), Cursor = Cursors.Hand,
                    Background = Jetons.Pinceau(actif ? Jetons.Surface : Jetons.Fond), BorderBrush = Jetons.Pinceau(actif ? Jetons.Accent : Jetons.Separateur), BorderThickness = new Thickness(1), Foreground = Jetons.Pinceau(Jetons.Texte), Tag = "f" + k
                };
                b.Template = Coquille.ModeleBouton();
                b.FocusVisualStyle = Jetons.StyleFocus();
                System.Windows.Automation.AutomationProperties.SetName(b, b.Content + (actif ? (en ? ", selected" : ", choisi") : ""));
                b.Click += (s, e) => { filtre = n; Afficher(); };
                w.Children.Add(b);
            }
            if (VueChainesFluent.NouveauFormat(c))
            {
                var r = new Button
                {
                    Content = (en ? "Group repeats: " : "Regrouper les répétitions : ") + (regrouper ? (en ? "On" : "Oui") : (en ? "Off" : "Non")), Padding = new Thickness(12, 4, 12, 4), Margin = new Thickness(16, 0, 8, 6), Cursor = Cursors.Hand,
                    Background = Jetons.Pinceau(regrouper ? Jetons.Surface : Jetons.Fond), BorderBrush = Jetons.Pinceau(regrouper ? Jetons.Accent : Jetons.Separateur), BorderThickness = new Thickness(1), Foreground = Jetons.Pinceau(Jetons.Texte), Tag = "regrouper"
                };
                r.Template = Coquille.ModeleBouton();
                r.FocusVisualStyle = Jetons.StyleFocus();
                System.Windows.Automation.AutomationProperties.SetName(r, r.Content.ToString());
                r.Click += (s, e) => { regrouper = !regrouper; Afficher(); };
                w.Children.Add(r);
            }
            return w;
        }

        // Les filtres sont reconstruits au clic : le focus revient au bouton actif (ou au regroupement s'il venait de là)
        void RendreFocusFiltres()
        {
            var w = hoteFiltres.Content as WrapPanel;
            if (w == null) return;
            foreach (UIElement e in w.Children)
            {
                var b = e as Button;
                if (b != null && (string.Equals(b.Tag as string, "f" + filtre) || (string.Equals(b.Tag as string, "regrouper") && filtreFocusRegrouper)))
                { b.Dispatcher.BeginInvoke(new Action(() => b.Focus()), System.Windows.Threading.DispatcherPriority.Input); return; }
            }
        }
        bool filtreFocusRegrouper { get { var f = Keyboard.FocusedElement as Button; return f != null && string.Equals(f.Tag as string, "regrouper"); } }

        UIElement EnteteGraphe(Chaine c)
        {
            bool en = L.En;
            var d = new DockPanel { Margin = new Thickness(0, 0, 0, 8) };
            var z = new StackPanel { Orientation = Orientation.Horizontal };
            Action<string, string, Action> zb = (texte, nom, agir) =>
            {
                var b = new Button { Content = texte, Padding = new Thickness(9, 2, 9, 3), Margin = new Thickness(4, 0, 0, 0), Cursor = Cursors.Hand, Background = Jetons.Pinceau(Jetons.Fond), BorderBrush = Jetons.Pinceau(Jetons.Separateur), BorderThickness = new Thickness(1), Foreground = Jetons.Pinceau(Jetons.Texte) };
                b.Template = Coquille.ModeleBouton();
                b.FocusVisualStyle = Jetons.StyleFocus();
                System.Windows.Automation.AutomationProperties.SetName(b, nom);
                b.Click += (s, e) => agir();
                z.Children.Add(b);
            };
            zb("−", en ? "Zoom out" : "Dézoomer", () => { zoomAuto = false; Zoomer(Math.Max(0.25, zoom - 0.25)); });
            zb(Math.Round(zoom * 100) + " %", en ? "Zoom 100 %" : "Zoom 100 %", () => { zoomAuto = false; Zoomer(1); });
            zb("+", en ? "Zoom in" : "Zoomer", () => { zoomAuto = false; Zoomer(Math.Min(2, zoom + 0.25)); });
            zb(en ? "Fit" : "Ajuster", en ? "Fit the graph" : "Ajuster le graphe", () => { zoomAuto = false; Ajuster(); });
            DockPanel.SetDock(z, Dock.Right); d.Children.Add(z);
            var t = new TextBlock { TextWrapping = TextWrapping.Wrap };
            t.Inlines.Add(new System.Windows.Documents.Run(en ? "Who launched what" : "Qui a lancé quoi") { FontSize = 15, FontWeight = FontWeights.SemiBold });
            string sous = en ? "parents left, children right" : "parents à gauche, enfants à droite";
            int nCases = graphe.Cases.Count(x => !x.Fantome && !x.Repli);
            if (nCases != graphe.Processus) sous += "  ·  " + string.Format(en ? "{0} processes, {1} boxes" : "{0} processus, {1} cases", graphe.Processus, nCases);
            if (c.NoeudsTronques > 0) sous += "  ·  " + string.Format(en ? "{0} of {1} processes published" : "{0} processus publiés sur {1}", graphe.Processus, graphe.Processus + c.NoeudsTronques);
            if (filtre > 0) sous += "  ·  " + string.Format(en ? "{0}: {1} matching, the others dimmed" : "{0} : {1} correspondant(s), les autres estompés", VueChainesFluent.NomFiltre(filtre), VueChainesFluent.Compter(c, filtre));
            t.Inlines.Add(new System.Windows.Documents.Run("   " + sous) { FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire) });
            d.Children.Add(t);
            return d;
        }

        void Zoomer(double z)
        {
            zoom = z;
            echelle.ScaleX = echelle.ScaleY = zoom;
            var d = hoteEntete.Content as DockPanel;
            var boutons = d == null ? null : d.Children[0] as StackPanel;
            if (boutons != null && boutons.Children.Count > 1) ((Button)boutons.Children[1]).Content = Math.Round(zoom * 100) + " %";
        }

        // Zoom automatique : le graphe tient dans la largeur de la carte, sans descendre sous 60 % (au-delà, défilement)
        void AjusterLargeur()
        {
            if (graphe == null || graphe.Largeur <= 0 || hoteGraphe.ActualWidth <= 40) return;
            double z = Math.Max(0.6, Math.Min(1, (hoteGraphe.ActualWidth - 12) / graphe.Largeur));
            if (Math.Abs(z - zoom) > 0.005) Zoomer(z);
        }

        void Ajuster()
        {
            if (graphe == null || graphe.Largeur <= 0) return;
            double l = hoteGraphe.ActualWidth > 40 ? hoteGraphe.ActualWidth - 30 : 600;
            Zoomer(Math.Max(0.25, Math.Min(1, Math.Min(l / graphe.Largeur, (defileGraphe.MaxHeight - 20) / graphe.Hauteur))));
        }

        void DessinerGraphe(Chaine c, CaseChaine choix)
        {
            elementsCases.Clear();
            var toile = new Canvas { Width = Math.Max(graphe.Largeur, 10), Height = Math.Max(graphe.Hauteur, 10), LayoutTransform = echelle, Background = Brushes.Transparent };
            echelle.ScaleX = echelle.ScaleY = zoom;
            bool nouveau = VueChainesFluent.NouveauFormat(c);
            foreach (var cs in graphe.Cases)
                foreach (var e in cs.Enfants)
                    if (!e.Masquee) Lien(toile, cs, e, nouveau);
            foreach (var cs in graphe.Cases) DessinerCase(toile, c, cs, cs == choix);
            anneau = new System.Windows.Shapes.Rectangle { StrokeThickness = 2, Stroke = Jetons.Pinceau(Jetons.Accent), RadiusX = 9, RadiusY = 9, IsHitTestVisible = false, Visibility = Visibility.Collapsed };
            toile.Children.Add(anneau);
            defileGraphe.Content = toile;
            if (zoomAuto) AjusterLargeur();
            PlacerAnneau();
            // Case choisie par l'utilisateur (clic, liste repliée, membre d'un groupe) : amenée à la vue ; jamais à un simple
            // rafraîchissement, pour ne pas faire défiler la page sous ses yeux
            FrameworkElement vise;
            if (amener && choix != null && elementsCases.TryGetValue(VueChainesFluent.CleCase(choix), out vise))
                vise.Dispatcher.BeginInvoke(new Action(() => vise.BringIntoView()), System.Windows.Threading.DispatcherPriority.Loaded);
            amener = false;
        }

        // Trait plein : parent suivi ; pointillé orange : parent suivi à heure approchée (±10 s) ; tirets : parent non suivi
        // (vers la case fantôme) ; plein discret : racine du système. Service plus ancien : trait plein, nature non publiée
        static void Lien(Canvas toile, CaseChaine a, CaseChaine b, bool nouveau)
        {
            double w = VueChainesFluent.LargeurCase, h = VueChainesFluent.HauteurCase;
            var p0 = new Point(a.X + w, a.Y + h / 2);
            var p1 = new Point(b.X - 6, b.Y + h / 2);
            double mx = (p0.X + p1.X) / 2;
            var geo = new PathGeometry();
            var f = new PathFigure { StartPoint = p0 };
            f.Segments.Add(new BezierSegment(new Point(mx, p0.Y), new Point(mx, p1.Y), p1, true));
            geo.Figures.Add(f);
            geo.Freeze();
            int style = VueChainesFluent.StyleLien(b.Lien, nouveau);
            var couleur = style == 1 ? Jetons.Attention : style == 3 ? Jetons.Separateur : Jetons.TexteSecondaire;
            var trait = new System.Windows.Shapes.Path { Data = geo, Stroke = Jetons.Pinceau(couleur), StrokeThickness = style == 1 ? 2.2 : 1.6, StrokeDashCap = PenLineCap.Round, IsHitTestVisible = false };
            if (style == 1) trait.StrokeDashArray = new DoubleCollection { 0.1, 3 };
            if (style == 2) trait.StrokeDashArray = new DoubleCollection { 4, 3 };
            toile.Children.Add(trait);
            toile.Children.Add(new System.Windows.Shapes.Polygon { Points = new PointCollection { new Point(p1.X, p1.Y - 4.5), new Point(p1.X + 6, p1.Y), new Point(p1.X, p1.Y + 4.5) }, Fill = Jetons.Pinceau(couleur), IsHitTestVisible = false });
            if (style == 1)
            {
                var t = new TextBlock { Text = "±10 s", FontSize = 10.5, Foreground = Jetons.Pinceau(Jetons.Attention), FontStyle = FontStyles.Italic, Background = Jetons.Pinceau(Jetons.Fond), IsHitTestVisible = false };
                Canvas.SetLeft(t, mx - 14); Canvas.SetTop(t, (p0.Y + p1.Y) / 2 - (Math.Abs(p0.Y - p1.Y) < 2 ? 20 : 8));
                toile.Children.Add(t);
            }
        }

        void DessinerCase(Canvas toile, Chaine c, CaseChaine cs, bool choisie)
        {
            double w = VueChainesFluent.LargeurCase, h = VueChainesFluent.HauteurCase;
            string cle = VueChainesFluent.CleCase(cs);
            int g = cs.Fantome || cs.Repli ? 0 : cs.Membres.Max(m => VueChainesFluent.GraviteNoeud(c, m));
            var couleur = Briques.Couleur(g);
            bool estompee = filtre > 0 && !cs.Fantome && !(cs.Repli ? cs.Replies.Any(m => VueChainesFluent.Garde(m, filtre)) : cs.Membres.Any(m => VueChainesFluent.Garde(m, filtre)));
            if (cs.Membres.Count > 1)
                for (int k = 2; k >= 1; k--)
                {
                    var ar = new Border { Width = w, Height = h, CornerRadius = new CornerRadius(6), Background = Jetons.Pinceau(Jetons.Surface), BorderBrush = Jetons.Pinceau(Jetons.Separateur), BorderThickness = new Thickness(1), IsHitTestVisible = false, Opacity = estompee ? 0.35 : 1 };
                    Canvas.SetLeft(ar, cs.X + 4 * k); Canvas.SetTop(ar, cs.Y + 4 * k); toile.Children.Add(ar);
                }
            var b = new Border { Width = w, Height = h, CornerRadius = new CornerRadius(6), Padding = new Thickness(10, 5, 8, 5), Cursor = Cursors.Hand, Opacity = estompee ? 0.35 : 1 };
            if (cs.Fantome || cs.Repli)
            {
                b.Background = Jetons.Pinceau(Jetons.Fond);
                b.BorderThickness = new Thickness(0);
                var cadre = new System.Windows.Shapes.Rectangle { Width = w, Height = h, RadiusX = 6, RadiusY = 6, Stroke = Jetons.Pinceau(choisie ? Jetons.Accent : Jetons.TexteSecondaire), StrokeThickness = choisie ? 1.6 : 1, StrokeDashArray = new DoubleCollection { 3, 3 }, IsHitTestVisible = false };
                Canvas.SetLeft(cadre, cs.X); Canvas.SetTop(cadre, cs.Y);
                toile.Children.Add(b); Canvas.SetLeft(b, cs.X); Canvas.SetTop(b, cs.Y);
                toile.Children.Add(cadre);
            }
            else
            {
                b.Background = Jetons.Pinceau(choisie ? Jetons.Surface : Jetons.Carte);
                b.BorderBrush = Jetons.Pinceau(choisie ? Jetons.Accent : Jetons.Separateur);
                b.BorderThickness = new Thickness(choisie ? 1.6 : 1);
                toile.Children.Add(b); Canvas.SetLeft(b, cs.X); Canvas.SetTop(b, cs.Y);
                var barre = new Border { Width = 3, Height = h - 14, CornerRadius = new CornerRadius(2), Background = Jetons.Pinceau(couleur), IsHitTestVisible = false, Opacity = estompee ? 0.35 : 1 };
                Canvas.SetLeft(barre, cs.X + 1); Canvas.SetTop(barre, cs.Y + 7);
                toile.Children.Add(barre);
            }
            var p = new StackPanel();
            var haut = new DockPanel();
            if (cs.Score > 0 && !cs.Fantome && !cs.Repli) { var sc = new TextBlock { Text = "+" + cs.Score, FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(couleur), Margin = new Thickness(4, 0, 0, 0) }; DockPanel.SetDock(sc, Dock.Right); haut.Children.Add(sc); }
            string titre = cs.Fantome || cs.Repli ? cs.Titre : Canal.Visible(cs.Premier.Nom);
            haut.Children.Add(new TextBlock { Text = titre, FontSize = 12.5, FontWeight = cs.Fantome ? FontWeights.Normal : FontWeights.SemiBold, FontStyle = cs.Fantome ? FontStyles.Italic : FontStyles.Normal, Foreground = Jetons.Pinceau(cs.Fantome ? Jetons.TexteSecondaire : Jetons.Texte), TextTrimming = TextTrimming.CharacterEllipsis });
            p.Children.Add(haut);
            var bas = new DockPanel { Margin = new Thickness(0, 3, 0, 0) };
            string sous;
            if (cs.Fantome || cs.Repli) sous = cs.Sous;
            else if (cs.Membres.Count > 1)
            {
                var badge = new Border { Background = Jetons.Pinceau(Color.FromArgb(0x30, Jetons.Accent.R, Jetons.Accent.G, Jetons.Accent.B)), CornerRadius = new CornerRadius(8), Padding = new Thickness(5, 0, 5, 1), Margin = new Thickness(0, 0, 5, 0), VerticalAlignment = VerticalAlignment.Center };
                badge.Child = new TextBlock { Text = "×" + cs.Membres.Count, FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Jetons.Accent) };
                DockPanel.SetDock(badge, Dock.Left); bas.Children.Add(badge);
                sous = string.Format(L.En ? "{0} running" : "{0} en cours", cs.Membres.Count(VueChainesFluent.EnCours));
            }
            else
            {
                var n = cs.Premier;
                bool publie = VueChainesFluent.Publie(n);
                if (publie)
                {
                    var pt = new System.Windows.Shapes.Ellipse { Width = 7, Height = 7, Margin = new Thickness(0, 1, 6, 0), VerticalAlignment = VerticalAlignment.Center, Stroke = Jetons.Pinceau(n.Vivant == true ? Jetons.Succes : Jetons.TexteSecondaire), StrokeThickness = 1.3, Fill = n.Vivant == true ? Jetons.Pinceau(Jetons.Succes) : Brushes.Transparent };
                    DockPanel.SetDock(pt, Dock.Left); bas.Children.Add(pt);
                }
                sous = n.Pid + (publie ? "  ·  " + (n.Vivant == true ? (L.En ? "running" : "en cours") : (L.En ? "exited" : "terminé")) : "");
            }
            bas.Children.Add(new TextBlock { Text = sous, FontSize = 11.5, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center });
            p.Children.Add(bas);
            b.Child = p;
            b.ToolTip = VueChainesFluent.NomCase(cs);
            b.MouseLeftButtonUp += (s, e) => { courant = cle; Choisir(cs); };
            elementsCases[cle] = b;
        }

        void Choisir(CaseChaine cs)
        {
            amener = true;
            choixCase = VueChainesFluent.CleCase(cs);
            courant = choixCase;
            tousMembres = false;
            Afficher();
        }

        // Anneau de focus clavier autour de la case courante, seulement quand le graphe a le focus ; nom lu par le Narrateur
        void PlacerAnneau()
        {
            if (anneau == null || graphe == null) return;
            var cs = CaseDe(courant);
            System.Windows.Automation.AutomationProperties.SetName(hoteGraphe, (L.En ? "Process graph" : "Graphe des processus") + (cs == null ? "" : ": " + VueChainesFluent.NomCase(cs)));
            if (cs == null || !hoteGraphe.IsKeyboardFocused) { anneau.Visibility = Visibility.Collapsed; return; }
            anneau.Width = VueChainesFluent.LargeurCase + 8; anneau.Height = VueChainesFluent.HauteurCase + 8;
            Canvas.SetLeft(anneau, cs.X - 4); Canvas.SetTop(anneau, cs.Y - 4);
            anneau.Visibility = Visibility.Visible;
            FrameworkElement el;
            if (elementsCases.TryGetValue(VueChainesFluent.CleCase(cs), out el)) el.BringIntoView();
        }

        // Clavier : flèches parent / enfant / case voisine de la couche, Début : première case, Entrée ou Espace : ouvrir le détail
        void ToucheGraphe(object s, KeyEventArgs e)
        {
            if (graphe == null) return;
            string t = e.Key == Key.Left ? "Gauche" : e.Key == Key.Right ? "Droite" : e.Key == Key.Up ? "Haut" : e.Key == Key.Down ? "Bas" : e.Key == Key.Home ? "Debut" : null;
            var cs = CaseDe(courant);
            if (t != null)
            {
                var v = VueChainesFluent.Voisin(graphe, cs, t);
                if (v != null) courant = VueChainesFluent.CleCase(v);
                PlacerAnneau();
                e.Handled = true;
            }
            else if ((e.Key == Key.Enter || e.Key == Key.Space) && cs != null) { Choisir(cs); e.Handled = true; }
        }

        UIElement BasGraphe(Chaine c)
        {
            bool en = L.En;
            bool nouveau = VueChainesFluent.NouveauFormat(c);
            var p = new StackPanel { Margin = new Thickness(0, 10, 0, 0) };
            var w = new WrapPanel();
            Action<int, string> trait = (style, texte) =>
            {
                var sp = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 16, 6) };
                var l = new System.Windows.Shapes.Line { X1 = 0, Y1 = 6, X2 = 28, Y2 = 6, Stroke = Jetons.Pinceau(style == 1 ? Jetons.Attention : Jetons.TexteSecondaire), StrokeThickness = style == 1 ? 2.2 : 1.6, StrokeDashCap = PenLineCap.Round, Width = 30, Height = 12, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) };
                if (style == 1) l.StrokeDashArray = new DoubleCollection { 0.1, 3 };
                if (style == 2) l.StrokeDashArray = new DoubleCollection { 4, 3 };
                sp.Children.Add(l);
                sp.Children.Add(new TextBlock { Text = texte, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire) });
                w.Children.Add(sp);
            };
            if (nouveau)
            {
                trait(0, en ? "parent followed (alive when the child started)" : "parent suivi (vivant au lancement de l'enfant)");
                trait(1, en ? "parent time approximated (±10 s)" : "heure du parent approchée (±10 s)");
                trait(2, en ? "parent not followed" : "parent non suivi");
                Action<bool, string> point = (vivant, texte) =>
                {
                    var sp = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 16, 6) };
                    sp.Children.Add(new System.Windows.Shapes.Ellipse { Width = 8, Height = 8, Stroke = Jetons.Pinceau(vivant ? Jetons.Succes : Jetons.TexteSecondaire), StrokeThickness = 1.3, Fill = vivant ? Jetons.Pinceau(Jetons.Succes) : Brushes.Transparent, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) });
                    sp.Children.Add(new TextBlock { Text = texte, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire) });
                    w.Children.Add(sp);
                };
                point(true, en ? "running" : "en cours");
                point(false, en ? "exited" : "terminé");
                w.Children.Add(new TextBlock { Text = (en ? "×N: repeats grouped" : "×N : répétitions regroupées"), FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, 0, 16, 6) });
            }
            else trait(0, en ? "launched by (nature of the link not published)" : "lancé par (nature du lien non publiée)");
            p.Children.Add(w);
            p.Children.Add(new Border { Height = 1, Background = Jetons.Pinceau(Jetons.Separateur), Margin = new Thickness(0, 4, 0, 8) });
            p.Children.Add(Note(VueChainesFluent.Limites(nouveau), 0));
            p.Children.Add(Note(en ? "Keyboard: Tab enters the graph, arrow keys move parent / child / sibling, Enter opens the detail. A layer of more than 40 boxes is folded into “+N more” (opens the list); the text view always lists everything."
                                   : "Clavier : Tab entre dans le graphe, les flèches vont au parent, à l'enfant, à la case voisine, Entrée ouvre le détail. Au-delà de 40 cases, une couche est repliée en « +N de plus » (ouvre la liste) ; la vue texte liste toujours tout.", 4));
            return p;
        }

        UIElement DetailCase(Chaine c, CaseChaine cs, Alerte lien)
        {
            bool en = L.En;
            var pile = new StackPanel();
            if (cs == null) { pile.Children.Add(Note(en ? "Select a box of the graph to read its detail and act on it." : "Sélectionnez une case du graphe pour lire son détail et agir.", 0)); return pile; }
            if (cs.Repli)
            {
                pile.Children.Add(new TextBlock { Text = cs.Titre, FontSize = 18, FontWeight = FontWeights.SemiBold });
                pile.Children.Add(Note(string.Format(en ? "{0} processes of this layer are folded (more than 40 boxes). Choose one to show it in the graph." : "{0} processus de cette couche sont repliés (plus de 40 cases). Choisissez-en un pour le montrer dans le graphe.", cs.Replies.Count), 4));
                var l = new StackPanel();
                KeyboardNavigation.SetTabNavigation(l, KeyboardNavigationMode.Once);
                KeyboardNavigation.SetDirectionalNavigation(l, KeyboardNavigationMode.Contained);
                foreach (var n in cs.Replies.Take(500))
                {
                    int pid = n.Pid;
                    l.Children.Add(Briques.Ligne(Canal.Visible(n.Nom), n.Score > 0 ? "+" + n.Score : "", VueChainesFluent.EtatProcessus(n), VueChainesFluent.GraviteNoeud(c, n), false, false, () => { choixCase = "p" + pid; courant = choixCase; amener = true; Afficher(); }));
                }
                pile.Children.Add(l);
                return pile;
            }
            if (cs.Fantome)
            {
                var tete = cs.Enfants.Count > 0 ? cs.Enfants[0].Premier : null;
                pile.Children.Add(new TextBlock { Text = cs.Titre, FontSize = 18, FontWeight = FontWeights.SemiBold, FontStyle = FontStyles.Italic, TextWrapping = TextWrapping.Wrap });
                pile.Children.Add(new TextBlock { Text = en ? "Parent of the head, not in the chain" : "Parent de la tête, hors de la chaîne", Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, 2, 0, 0) });
                if (tete != null)
                {
                    Ligne(pile, en ? "Why it is not followed" : "Pourquoi il n'est pas suivi", VueChainesFluent.TexteLien(VueChainesFluent.EstTete(tete) ? tete.Lien : null), false);
                    if (tete.ParentPid > 0) Ligne(pile, en ? "Parent PID (as Windows gave it)" : "PID du parent (donné par Windows)", tete.ParentPid.ToString(), false);
                    Ligne(pile, en ? "Head of the chain" : "Tête de la chaîne", Canal.Visible(tete.Nom) + "  ·  PID " + tete.Pid, false);
                }
                pile.Children.Add(Note(en ? "No action: this process is not part of the chain, deR4Tizer does not know it is the same program." : "Aucune action : ce processus ne fait pas partie de la chaîne, deR4Tizer ne sait pas si c'est le même programme.", 12));
                return pile;
            }
            var membres = cs.Membres;
            int pidVu;
            NoeudChaine n0 = membres.Count == 1 ? membres[0] : (choixCase != null && choixCase.StartsWith("p", StringComparison.Ordinal) && int.TryParse(choixCase.Substring(1), out pidVu) ? membres.FirstOrDefault(m => m.Pid == pidVu) : null);
            if (n0 == null) return DetailGroupe(c, cs);
            if (membres.Count > 1)
                pile.Children.Add(Bouton(string.Format(en ? "Back to the group of {0}" : "Revenir au groupe de {0}", membres.Count), false, () => { choixCase = "g" + membres[0].Pid; Afficher(); }));
            DetailNoeud(pile, c, n0);
            return pile;
        }

        void DetailNoeud(StackPanel pile, Chaine c, NoeudChaine n)
        {
            bool en = L.En;
            int g = VueChainesFluent.GraviteNoeud(c, n);
            pile.Children.Add(new TextBlock { Text = Canal.Visible(n.Nom), FontSize = 18, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            if (n.Score > 0) pile.Children.Add(new TextBlock { Text = "+" + n.Score + (c.Score >= VueChainesFluent.SeuilChaine ? "  ·  " + (en ? "counts in an alert chain" : "compte dans une chaîne en alerte") : ""), FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Briques.Couleur(g)), Margin = new Thickness(0, 2, 0, 0) });
            Ligne(pile, en ? "Process" : "Processus", VueChainesFluent.EtatProcessus(n), false, VueChainesFluent.Naissance(n));
            string lance = VueChainesFluent.LancePar(c, n);
            if (lance != null) Ligne(pile, en ? "Launched by" : "Lancé par", lance, false, VueChainesFluent.TexteLien(n.Lien));
            if (!string.IsNullOrEmpty(n.Chemin)) Ligne(pile, en ? "Path" : "Chemin", Canal.Visible(n.Chemin), true);
            if (!string.IsNullOrEmpty(n.LigneCommande)) Ligne(pile, en ? "Command line (first 300 characters, secrets masked)" : "Ligne de commande (300 premiers caractères, secrets masqués)", Canal.Visible(n.LigneCommande), true);
            var signaux = VueChainesFluent.Signaux(n);
            if (VueChainesFluent.Publie(n))
            {
                if (signaux.Count > 0 || n.SignauxTronques > 0) pile.Children.Add(Briques.Titre(en ? "Signals" : "Signaux", 12));
                foreach (var s in signaux) pile.Children.Add(CarteSignal(s, Briques.Couleur(g > 0 ? g : 1)));
                if (n.SignauxTronques > 0) pile.Children.Add(Note(string.Format(en ? "{0} more signal(s) not published (they still count in the score)." : "{0} signal(s) de plus non publié(s) (ils comptent toujours dans le score).", n.SignauxTronques), 0));
            }
            else if (!string.IsNullOrEmpty(n.Raisons)) Ligne(pile, en ? "Reasons" : "Raisons", Canal.Visible(n.Raisons), false);
            NotesActions(pile, n);
            Actions(pile, VueChainesFluent.Actions(n), a => Agir(n, a));
        }

        static UIElement CarteSignal(SignalChaine s, Color couleur)
        {
            bool en = L.En;
            var b = new Border { Background = Jetons.Pinceau(Jetons.Fond), CornerRadius = new CornerRadius(5), Padding = new Thickness(10, 7, 10, 8), Margin = new Thickness(0, 0, 0, 6) };
            var p = new StackPanel();
            var h = new DockPanel();
            var hr = new TextBlock { Text = VueChainesFluent.HeureCourte(s.Heure), FontFamily = Briques.Chasse, FontSize = 11.5, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), ToolTip = en ? "time the signal was attached to the chain" : "heure de rattachement du signal à la chaîne" };
            DockPanel.SetDock(hr, Dock.Right); h.Children.Add(hr);
            var t = new TextBlock { FontSize = 12.5 };
            t.Inlines.Add(new System.Windows.Documents.Run("+" + s.Score + "  ") { Foreground = Jetons.Pinceau(couleur), FontWeight = FontWeights.SemiBold });
            t.Inlines.Add(new System.Windows.Documents.Run(Canal.Visible(s.Code)) { Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), FontFamily = Briques.Chasse });
            h.Children.Add(t);
            p.Children.Add(h);
            string lib = VueChainesFluent.LibelleSignal(s);
            p.Children.Add(new TextBlock { Text = lib, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 3, 0, 0) });
            string raison = Canal.Visible(s.Raison);
            if (raison.Length > 0 && raison != lib) p.Children.Add(new TextBlock { Text = (en ? "Service text: " : "Texte du service : ") + raison, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 0) });
            if (s.Techniques != null && s.Techniques.Count > 0) p.Children.Add(new TextBlock { Text = string.Join("  ·  ", s.Techniques.Select(Canal.Visible)), FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, 2, 0, 0) });
            b.Child = p;
            return b;
        }

        UIElement DetailGroupe(Chaine c, CaseChaine cs)
        {
            bool en = L.En;
            var pile = new StackPanel();
            var n = cs.Premier;
            var membres = cs.Membres;
            var hd = new StackPanel { Orientation = Orientation.Horizontal };
            hd.Children.Add(new TextBlock { Text = Canal.Visible(n.Nom), FontSize = 18, FontWeight = FontWeights.SemiBold });
            var badge = new Border { Background = Jetons.Pinceau(Color.FromArgb(0x30, Jetons.Accent.R, Jetons.Accent.G, Jetons.Accent.B)), CornerRadius = new CornerRadius(9), Padding = new Thickness(8, 1, 8, 2), Margin = new Thickness(10, 2, 0, 0), VerticalAlignment = VerticalAlignment.Center };
            badge.Child = new TextBlock { Text = "×" + membres.Count, FontSize = 13, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Jetons.Accent) };
            hd.Children.Add(badge);
            pile.Children.Add(hd);
            pile.Children.Add(Note(string.Format(en ? "{0} processes: same parent, same program, same command line (identical, first 300 characters), same signal codes." : "{0} processus : même parent, même programme, même ligne de commande (identique sur les 300 premiers caractères), mêmes codes de signaux.", membres.Count), 4));
            int min = membres.Min(m => m.Score), max = membres.Max(m => m.Score);
            if (max > 0) pile.Children.Add(new TextBlock { Text = (min == max ? string.Format(en ? "+{0} each" : "+{0} chacun", max) : string.Format(en ? "+{0} to +{1}" : "+{0} à +{1}", min, max)) + (en ? " (process scores; the chain score is computed by the service)" : " (scores des processus ; le score de la chaîne est calculé par le service)"), TextWrapping = TextWrapping.Wrap, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Briques.Couleur(membres.Max(m => VueChainesFluent.GraviteNoeud(c, m)))), Margin = new Thickness(0, 4, 0, 0) });
            string lance = VueChainesFluent.LancePar(c, n);
            var heures = membres.Select(m => m.Creation ?? "").Where(x => x.Length > 0).OrderBy(x => x, StringComparer.Ordinal).ToList();
            if (lance != null) Ligne(pile, en ? "Launched by" : "Lancé par", lance, false, heures.Count > 1 ? string.Format(en ? "started from {0} to {1}" : "lancés de {0} à {1}", VueChainesFluent.HeureCourte(heures[0]), VueChainesFluent.HeureCourte(heures[heures.Count - 1])) : VueChainesFluent.TexteLien(n.Lien));
            if (!string.IsNullOrEmpty(n.Chemin)) Ligne(pile, en ? "Path" : "Chemin", Canal.Visible(n.Chemin), true);
            if (!string.IsNullOrEmpty(n.LigneCommande)) Ligne(pile, en ? "Command line (identical, first 300 characters)" : "Ligne de commande (identique sur les 300 premiers caractères)", Canal.Visible(n.LigneCommande), true);
            pile.Children.Add(Briques.Titre(en ? "Processes in this group" : "Processus de ce groupe", 12));
            var tab = new StackPanel();
            KeyboardNavigation.SetTabNavigation(tab, KeyboardNavigationMode.Once);
            KeyboardNavigation.SetDirectionalNavigation(tab, KeyboardNavigationMode.Contained);
            // Plus récents d'abord ; les 5 premiers, puis « Montrer les N autres »
            var ordre = membres.Select((m, i) => new { m, i }).OrderByDescending(x => x.m.Creation ?? "", StringComparer.Ordinal).ThenByDescending(x => x.i).Select(x => x.m).ToList();
            foreach (var m in tousMembres ? ordre : ordre.Take(5))
            {
                int pid = m.Pid;
                string etat = m.Vivant == true ? (en ? "running" : "en cours") : (en ? "exited" : "terminé");
                if (m.Signaux != null && m.Signaux.Count > 0 && m.Score > 0) etat += "  ·  +" + m.Score;
                tab.Children.Add(Briques.Ligne("PID " + pid, VueChainesFluent.HeureCourte(m.Creation), etat, 0, false, m.Vivant != true, () => { choixCase = "p" + pid; Afficher(); }));
            }
            pile.Children.Add(tab);
            if (!tousMembres && ordre.Count > 5) pile.Children.Add(Bouton(string.Format(en ? "Show the {0} others" : "Montrer les {0} autres", ordre.Count - 5), false, () => { tousMembres = true; Afficher(); }));
            // Agir : sur le plus récent encore en cours (même commande et même question que pour un processus seul)
            pile.Children.Add(Briques.Titre(L.T("Agir"), 12));
            var vivant = ordre.FirstOrDefault(m => VueChainesFluent.EnCours(m) && m.Pid > 4);
            if (vivant == null) pile.Children.Add(Note(en ? "No process of this group is still running: kill and suspend are not offered." : "Aucun processus de ce groupe ne tourne encore : tuer et suspendre ne sont pas proposés.", 0));
            else if (source != null)
            {
                pile.Children.Add(ActionLongue(string.Format(en ? "Kill the running one (PID {0}) and all its descendants" : "Tuer celui qui tourne (PID {0}) et toute sa descendance", vivant.Pid), true, () => Agir(vivant, "tuerChaine")));
                pile.Children.Add(ActionLongue(string.Format(en ? "Suspend the process (PID {0})" : "Suspendre le processus (PID {0})", vivant.Pid), false, () => Agir(vivant, "suspendre")));
            }
            pile.Children.Add(Briques.Action(string.Format(en ? "Ungroup these {0} processes" : "Dégrouper ces {0} processus", membres.Count), false, (s, e) => { regrouper = false; choixCase = "p" + n.Pid; Afficher(); }));
            pile.Children.Add(Briques.Action(L.T("Copier"), false, (s, e) => VueReseauFluent.Copier(string.Join("\r\n", membres.Select(VueChainesFluent.Copie)))));
            return pile;
        }

        static void Ligne(StackPanel pile, string titre, string valeur, bool chasse, string precision = null)
        {
            pile.Children.Add(Briques.Titre(titre, 10));
            var t = new TextBlock { Text = valeur, TextWrapping = TextWrapping.Wrap };
            if (chasse) { t.FontFamily = Briques.Chasse; t.FontSize = 12; }
            pile.Children.Add(t);
            if (!string.IsNullOrEmpty(precision)) pile.Children.Add(new TextBlock { Text = precision, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 2, 0, 0) });
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

        static string Programmes(List<string> l) { return string.Join(", ", (l ?? new List<string>()).Select(NomProgramme)); }

        // « ? » : nom posé par le service pour un trafic sans programme nommé (T-4) ; affiché « Programme non identifié »,
        // avec les raisons publiées (trafic.json, NonAttribue). Tout autre nom est neutralisé tel quel
        public const string SansProgramme = "?";
        public static string NomProgramme(string nom) { return nom == SansProgramme ? (L.En ? "Unidentified program" : "Programme non identifié") : Canal.Visible(nom); }

        // Raisons de la ligne « ? » (capture::attribuer) ; « ProcessusTermine » est la somme des lignes « PID n », pas de cette
        // ligne. « Connexion fermée avant la relecture » et « aucun programme du poste » (machine virtuelle, partage de
        // connexion) ne se distinguent pas sans collecte nouvelle : un seul libellé (PR #308)
        public static readonly string[] RaisonsSansProgramme = { "SansProprietaire", "HorsTcpUdp", "SansPort" };

        public static string LibelleRaison(string r)
        {
            bool en = L.En;
            switch (r)
            {
                case "SansProprietaire": return en ? "Port owned by no program" : "Port sans programme";
                case "HorsTcpUdp": return en ? "Not TCP or UDP" : "Ni TCP ni UDP";
                case "SansPort": return en ? "No local port" : "Sans port local";
                default: return Canal.Visible(r);
            }
        }

        public static string ExplicationRaison(string r)
        {
            bool en = L.En;
            switch (r)
            {
                case "SansProprietaire": return en ? "Connection closed before the port tables were read again, virtual machine or Windows Sandbox, connection sharing, unsolicited incoming packet (scans included) or a reply from Windows itself: these cases cannot be told apart."
                                                   : "Connexion fermée avant la relecture des tables de ports, machine virtuelle ou Windows Sandbox, partage de connexion, paquet entrant non sollicité (balayage compris) ou réponse de Windows lui-même : ces cas ne se distinguent pas.";
                case "HorsTcpUdp": return en ? "ICMP, IPsec (VPN) and other protocols have no port." : "ICMP, IPsec (VPN) et les autres protocoles n'ont pas de port.";
                case "SansPort": return en ? "IP fragment other than the first, truncated header, or port 0." : "Fragment IP qui n'est pas le premier, en-tête tronqué, ou port 0.";
                default: return "";
            }
        }

        // Détail de la ligne « Programme non identifié » : ce que c'est, puis chaque raison publiée avec son volume, la plus
        // grosse d'abord ; service plus ancien (NonAttribue absent) : dit non publié, rien n'est conclu
        public static List<LigneDetail> DetailSansProgramme(EtatTrafic t)
        {
            bool en = L.En;
            var l = new List<LigneDetail> { new LigneDetail { Titre = en ? "What it is" : "Ce que c'est", Texte = en ? "Packets whose local port belonged to no program when they were seen." : "Paquets dont le port local n'appartenait à aucun programme au moment où ils ont été vus." } };
            var raisons = (t == null || t.NonAttribue == null ? new List<TraficNonAttribue>() : t.NonAttribue)
                .Where(x => x != null && RaisonsSansProgramme.Contains(x.Raison) && x.Entrant + x.Sortant > 0).OrderByDescending(x => x.Entrant + x.Sortant).ToList();
            // Champ absent : service plus ancien ; champ publié sans raison pour ce volume (relevé remis à zéro à minuit
            // entre deux écritures, par exemple) : dit tel quel, jamais « version plus ancienne » (prérelecture de #310, D3)
            if (raisons.Count == 0 && (t == null || t.NonAttribue == null))
                l.Add(new LigneDetail { Titre = en ? "Reasons" : "Raisons", Texte = en ? "Breakdown by reason not published by this service (older version): nothing is concluded." : "Détail par raison non publié par ce service (version plus ancienne) : rien n'est conclu." });
            else if (raisons.Count == 0)
                l.Add(new LigneDetail { Titre = en ? "Reasons" : "Raisons", Texte = en ? "The service publishes no reason for this volume (count reset at midnight, or not written yet): nothing is concluded." : "Le service ne publie aucune raison pour ce volume (relevé remis à zéro à minuit, ou pas encore écrit) : rien n'est conclu." });
            foreach (var x in raisons)
                l.Add(new LigneDetail { Titre = LibelleRaison(x.Raison) + " · " + Format.Octets(x.Entrant + x.Sortant), Texte = ExplicationRaison(x.Raison) });
            return l;
        }

        // Nom localisé du pays (colonnes française et anglaise des contours de la carte) ; pays absent de la carte : nom anglais
        // de Windows en anglais, code seul en français ; code vide : « pays inconnu ». Le code vient de trafic.json : neutralisé
        public static string NomPays(string code)
        {
            if (string.IsNullOrEmpty(code)) return L.En ? "unknown country" : "pays inconnu";
            string nom = NomCourt(code);
            return nom == null ? Canal.Visible(code) : Canal.Visible(nom) + " (" + Canal.Visible(code) + ")";
        }

        // Nom seul, sans le code (null si inconnu)
        static string NomCourt(string code)
        {
            PaysCarte p;
            if (string.IsNullOrEmpty(code)) return null;
            if (PaysCarte.Tous.TryGetValue(code, out p)) return p.Nom;
            if (L.En && code.Length == 2 && code.All(c => c >= 'A' && c <= 'Z'))
                try { return new System.Globalization.RegionInfo(code).EnglishName; } catch { }
            return null;
        }

        static string NomSeul(string code) { return Canal.Visible(NomCourt(code) ?? code); }

        // Carte interactive (T-19, décisions du mainteneur du 2026-11-23) : 20 arcs au plus, zoom de 1 à 12
        public const int MaxArcs = 20;
        public const double ZoomMin = 1, ZoomMax = 12;

        // Zoom borné, jamais remis à 1 tout seul
        public static double BornerZoom(double z) { return double.IsNaN(z) ? ZoomMin : Math.Max(ZoomMin, Math.Min(ZoomMax, z)); }

        // Centre de la vue en fraction de la carte (0 à 1) : la partie visible reste sur la carte ; au zoom 1, carte entière
        public static double BornerCentre(double c, double zoom)
        {
            double m = 0.5 / BornerZoom(zoom);
            return double.IsNaN(c) ? 0.5 : Math.Max(m, Math.Min(1 - m, c));
        }

        // Champs T-19 absents : service plus ancien (un service à jour écrit toujours PaysSignales, liste vide comprise)
        public static bool Ancien(EtatTrafic t) { return t == null || t.PaysSignales == null; }

        public static bool Signale(EtatTrafic t, string code) { return t != null && t.PaysSignales != null && !string.IsNullOrEmpty(code) && t.PaysSignales.Contains(code); }

        public static TraficPays Pays(EtatTrafic t, string code)
        {
            return t == null || t.Pays == null || string.IsNullOrEmpty(code) ? null : t.Pays.FirstOrDefault(x => x != null && x.Code == code);
        }

        // Volume sans pays : total capturé moins la somme des pays (réseau local, adresse sans pays connu)
        public static long VolumeSansPays(EtatTrafic t)
        {
            if (t == null) return 0;
            // Calcul en double : Sum sur des long lève une exception au dépassement, des valeurs aberrantes ne doivent rien casser
            double pays = (t.Pays ?? new List<TraficPays>()).Where(x => x != null).Sum(x => (double)Math.Max(0, x.Entrant) + Math.Max(0, x.Sortant));
            double reste = (double)t.TotalEntrant + t.TotalSortant - pays;
            return reste <= 0 ? 0 : reste >= long.MaxValue ? long.MaxValue : (long)reste;
        }

        public class ArcCarte { public string Code; public long Debit; public double Epaisseur; public bool Signale; }

        // Arcs depuis le pays du réglage régional vers les pays dont le débit récent (10 s environ) n'est pas nul, connus de
        // la carte, hors pays d'origine : les 20 plus forts, épaisseur de 1 à 5 px en racine carrée du débit. Service plus
        // ancien (débit récent absent) : aucun arc
        public static List<ArcCarte> Arcs(EtatTrafic t, string origine)
        {
            var l = new List<ArcCarte>();
            if (t == null || t.Pays == null || string.IsNullOrEmpty(origine) || !PaysCarte.Tous.ContainsKey(origine)) return l;
            var choisis = t.Pays.Where(p => p != null && p.Code != null && p.Code != origine && PaysCarte.Tous.ContainsKey(p.Code))
                .GroupBy(p => p.Code).Select(g => g.First())
                .Select(p => new { p.Code, Debit = Math.Max(0, p.DebitEntrantRecent) + Math.Max(0, p.DebitSortantRecent) })
                .Where(x => x.Debit > 0).OrderByDescending(x => x.Debit).ThenBy(x => x.Code, StringComparer.Ordinal).Take(MaxArcs).ToList();
            long max = choisis.Count == 0 ? 1 : choisis.Max(x => x.Debit);
            foreach (var x in choisis) l.Add(new ArcCarte { Code = x.Code, Debit = x.Debit, Epaisseur = 1 + 4 * Math.Sqrt(x.Debit / (double)max), Signale = Signale(t, x.Code) });
            return l;
        }

        // Ordre du clavier sur la carte : pays avec trafic connus de la carte, plus gros volume d'abord
        public static List<string> PaysClavier(EtatTrafic t)
        {
            return (t == null || t.Pays == null ? new List<TraficPays>() : t.Pays)
                .Where(p => p != null && p.Code != null && p.Entrant + p.Sortant > 0 && PaysCarte.Tous.ContainsKey(p.Code))
                .GroupBy(p => p.Code).Select(g => g.First())
                .OrderByDescending(p => p.Entrant + p.Sortant).ThenBy(p => p.Code, StringComparer.Ordinal).Select(p => p.Code).ToList();
        }

        // Pays suivant (sens 1) ou précédent (-1), en boucle ; sans pays courant : le premier (ou le dernier)
        public static string Voisin(List<string> l, string courant, int sens)
        {
            if (l == null || l.Count == 0) return null;
            int i = courant == null ? -1 : l.IndexOf(courant);
            if (i < 0) return sens < 0 ? l[l.Count - 1] : l[0];
            return l[((i + sens) % l.Count + l.Count) % l.Count];
        }

        // Lignes de l'infobulle d'un pays : 0 titre, 1 texte, 2 secondaire, 3 danger, 4 accent (ce que fait le clic).
        // Programmes : les trois plus gros (ProgrammesVolumes), sinon les noms déjà publiés (pays au-delà des 30 détaillés,
        // service plus ancien)
        public static List<KeyValuePair<int, string>> LignesBulle(EtatTrafic t, string code, bool filtre)
        {
            bool en = L.En;
            var l = new List<KeyValuePair<int, string>>();
            if (string.IsNullOrEmpty(code)) return l;
            Action<int, string> a = (k, s) => l.Add(new KeyValuePair<int, string>(k, s));
            a(0, NomPays(code));
            var p = Pays(t, code);
            // Pays absent de la liste : « aucun échange » seulement si l'état est lu et les plages d'adresses chargées ;
            // sinon rien n'est conclu (prérelecture de #322, D1)
            if (p == null && t == null) a(2, en ? "Traffic not read yet: nothing is concluded" : "Trafic pas encore lu : rien n'est conclu");
            else if (p == null && t.PlagesGeoip <= 0) a(2, en ? "Address ranges not loaded: no country can be attributed yet, nothing is concluded" : "Plages d'adresses non chargées : aucun pays attribuable pour l'instant, rien n'est conclu");
            else if (p == null) a(2, en ? "No traffic since midnight" : "Aucun échange depuis minuit");
            else
            {
                a(1, "↓ " + Format.Octets(p.Entrant) + (en ? " received" : " reçus") + "  ·  ↑ " + Format.Octets(p.Sortant) + (en ? " sent" : " envoyés"));
                a(2, p.Destinations + " destination(s)");
                if (p.DebitEntrantRecent + p.DebitSortantRecent > 0) a(2, (en ? "Now: ↓ " : "En ce moment : ↓ ") + Format.Debit(p.DebitEntrantRecent) + "  ↑ " + Format.Debit(p.DebitSortantRecent));
                var noms = TroisProgrammes(p);
                if (noms.Count > 0) a(2, (en ? "Top programs: " : "Principaux programmes : ") + string.Join(", ", noms));
            }
            if (Signale(t, code)) a(3, en ? "Flagged connection to this country: click, then “Open in Connections”" : "Connexion signalée vers ce pays : cliquer, puis « Ouvrir dans Connexions »");
            if (p != null) a(4, filtre ? (en ? "Click again or press Esc to clear the filter" : "Cliquer à nouveau ou Échap pour retirer le filtre") : (en ? "Click to filter the lists on this country" : "Cliquer pour filtrer les listes sur ce pays"));
            return l;
        }

        static List<string> TroisProgrammes(TraficPays p)
        {
            var v = (p.ProgrammesVolumes ?? new List<TraficProgrammePays>()).Where(x => x != null && x.Nom != null).OrderByDescending(x => x.Entrant + x.Sortant).Select(x => x.Nom).ToList();
            if (v.Count == 0) v = (p.Programmes ?? new List<string>()).Where(x => x != null).ToList();
            return v.Take(3).Select(NomProgramme).ToList();
        }

        // Bulle d'un pays en texte (null : aucun pays)
        public static string Bulle(string code, TraficPays p)
        {
            if (code == null) return null;
            if (p == null) return NomPays(code);
            var t = new EtatTrafic { Pays = new List<TraficPays> { p }, PlagesGeoip = 1 };
            return string.Join("\n", LignesBulle(t, code, false).Select(x => x.Value));
        }

        // Légende des arcs : pays d'origine (réglage régional), ou pourquoi il n'y a pas d'arc
        public static string TexteArcs(EtatTrafic t, string origine)
        {
            bool en = L.En;
            if (t != null && Ancien(t)) return en ? "no arcs: recent rate not published by this service (older version)" : "pas d'arc : débit récent non publié par ce service (version plus ancienne)";
            if (origine == null || !PaysCarte.Tous.ContainsKey(origine)) return en ? "no arcs: country of the regional setting unknown" : "pas d'arc : pays du réglage régional inconnu";
            return string.Format(en ? "arcs from {0} ({1}, regional setting): last 10 s, width = √ rate, 20 at most" : "arcs depuis {0} ({1}, réglage régional) : 10 dernières s, épaisseur = √ débit, 20 au plus", NomSeul(origine), Canal.Visible(origine));
        }

        // Molette : la carte la garde pour zoomer, sauf au zoom minimal en descente et au zoom maximal en montée, où la page
        // défile (prérelecture de #322)
        public static bool MoletteGardee(double zoom, int delta)
        {
            if (delta < 0 && zoom <= ZoomMin) return false;
            if (delta > 0 && zoom >= ZoomMax) return false;
            return delta != 0;
        }

        // Filtre de pays écrit au-dessus des listes
        public static string TexteFiltre(string code) { return (L.En ? "Country: " : "Pays : ") + NomPays(code); }

        public static string AideFiltre(string code)
        {
            return string.Format(L.En ? "Click {0} again or press Esc to clear." : "Cliquer à nouveau sur {0} ou Échap pour retirer le filtre.", NomSeul(code));
        }

        public static string TitreFiltre(int vue, string code)
        {
            bool en = L.En;
            string nom = NomSeul(code);
            return vue == 0 ? string.Format(en ? "Programs with traffic to {0}" : "Programmes qui échangent avec {0}", nom)
                 : vue == 1 ? string.Format(en ? "{0} only" : "{0} seulement", nom)
                 : string.Format(en ? "Destinations in {0}" : "Destinations dans {0}", nom);
        }

        // Pourquoi un pays n'a pas de détail : service plus ancien, ou pays au-delà des 30 détaillés
        static string SansDetail(EtatTrafic t)
        {
            bool en = L.En;
            return Ancien(t) ? (en ? "Not published by this service (older version): nothing is concluded." : "Non publié par ce service (version plus ancienne) : rien n'est conclu.")
                             : (en ? "Not published for this country: the service details only the 30 largest countries." : "Non publié pour ce pays : le service ne détaille que les 30 plus gros pays.");
        }

        // Panneau d'un pays : ses destinations principales (30 plus gros pays), sinon dit pourquoi il n'y en a pas
        public static List<LigneDetail> DetailPays(EtatTrafic t, string code)
        {
            bool en = L.En;
            var l = new List<LigneDetail>();
            var p = Pays(t, code);
            if (p == null) return l;
            string titre = en ? "Top destinations in this country" : "Destinations principales dans ce pays";
            var dests = (p.DestinationsPrincipales ?? new List<TraficDestinationPays>()).Where(x => x != null)
                .OrderByDescending(x => x.Entrant + x.Sortant).ThenBy(x => x.Ip ?? "", StringComparer.Ordinal).ToList();
            if (dests.Count == 0) { l.Add(new LigneDetail { Titre = titre, Texte = SansDetail(t) }); return l; }
            l.Add(new LigneDetail { Titre = titre, Texte = en ? "The largest first, 10 at most." : "Les plus grosses d'abord, 10 au plus." });
            foreach (var x in dests)
                l.Add(new LigneDetail
                {
                    Titre = NomProgramme(x.Programme) + "  ·  " + Format.Octets(x.Entrant + x.Sortant),
                    Texte = Canal.Visible(string.IsNullOrEmpty(x.Nom) ? x.Ip : x.Nom + " (" + x.Ip + ")"), Chasse = true
                });
            return l;
        }

        public static List<LigneEtatFluent> Lignes(EtatTrafic t, int vue) { return LignesFiltrees(t, vue, null); }

        // Lignes de la vue choisie, plus gros volume d'abord ; « en ce moment » pour un échange des 10 dernières secondes.
        // Filtre de pays (clic sur la carte, T-19) : programmes du pays avec leur volume dans ce pays, ce pays seul, ou ses
        // destinations (liste Destinations, puis destinations principales du pays) ; pays qui n'a plus de trafic : rien
        public static List<LigneEtatFluent> LignesFiltrees(EtatTrafic t, int vue, string pays)
        {
            bool en = L.En;
            var l = new List<LigneEtatFluent>();
            if (t == null) return l;
            var pf = Pays(t, pays);
            if (pays != null && pf == null) return l;
            string maintenant = en ? "  ·  now" : "  ·  en ce moment";
            Func<string, string, LigneDetail> d = (titre, texte) => new LigneDetail { Titre = titre, Texte = texte };
            if (vue == 0 && pf != null)
            {
                string vers = (en ? "with " : "avec ") + NomPays(pays);
                var vols = (pf.ProgrammesVolumes ?? new List<TraficProgrammePays>()).Where(x => x != null).OrderByDescending(x => x.Entrant + x.Sortant).ThenBy(x => x.Nom ?? "", StringComparer.OrdinalIgnoreCase).ToList();
                foreach (var a in vols)
                    l.Add(new LigneEtatFluent
                    {
                        Titre = NomProgramme(a.Nom), Etiquette = Format.Octets(a.Entrant + a.Sortant),
                        Sous = "↓ " + Format.Octets(a.Entrant) + "  ↑ " + Format.Octets(a.Sortant) + "  ·  " + vers,
                        Detail = new List<LigneDetail> { d(en ? "Received from this country" : "Reçu de ce pays", Format.Octets(a.Entrant)), d(en ? "Sent to this country" : "Envoyé vers ce pays", Format.Octets(a.Sortant)), d(en ? "Country" : "Pays", NomPays(pays)) }
                    });
                if (vols.Count == 0)
                    foreach (var nom in (pf.Programmes ?? new List<string>()).Where(x => x != null))
                        l.Add(new LigneEtatFluent
                        {
                            Titre = NomProgramme(nom), Etiquette = "", Sous = vers + "  ·  " + (en ? "volume not published" : "volume non publié"),
                            Detail = new List<LigneDetail> { d(en ? "Country" : "Pays", NomPays(pays)), d(en ? "Volume with this country" : "Volume avec ce pays", SansDetail(t)) }
                        });
            }
            else if (vue == 0)
                foreach (var a in (t.Applications ?? new List<TraficApplication>()).Where(x => x != null).OrderByDescending(x => x.Entrant + x.Sortant).ThenBy(x => x.Nom ?? "", StringComparer.OrdinalIgnoreCase))
                    l.Add(new LigneEtatFluent
                    {
                        Titre = NomProgramme(a.Nom), Etiquette = Format.Octets(a.Entrant + a.Sortant),
                        Sous = "↓ " + Format.Octets(a.Entrant) + "  ↑ " + Format.Octets(a.Sortant) + "  ·  " + a.Destinations + " destination(s)",
                        Detail = new List<LigneDetail> { d(en ? "Received" : "Reçu", Format.Octets(a.Entrant)), d(en ? "Sent" : "Envoyé", Format.Octets(a.Sortant)), d("Destinations", a.Destinations.ToString()) }
                            .Concat(a.Nom == SansProgramme ? DetailSansProgramme(t) : new List<LigneDetail>()).ToList()
                    });
            else if (vue == 1)
                foreach (var p in (t.Pays ?? new List<TraficPays>()).Where(x => x != null && (pays == null || x.Code == pays)).OrderByDescending(x => x.Entrant + x.Sortant).ThenBy(x => x.Code ?? "", StringComparer.Ordinal))
                {
                    bool signale = Signale(t, p.Code);
                    l.Add(new LigneEtatFluent
                    {
                        Titre = NomPays(p.Code), Etiquette = Format.Octets(p.Entrant + p.Sortant), Pays = p.Code, Gravite = signale ? 2 : 0,
                        Sous = p.Destinations + " destination(s)  ·  " + Programmes(p.Programmes) + (p.Active ? maintenant : "") + (signale ? (en ? "  ·  flagged" : "  ·  signalé") : ""),
                        Detail = new List<LigneDetail> { d(en ? "Received" : "Reçu", Format.Octets(p.Entrant)), d(en ? "Sent" : "Envoyé", Format.Octets(p.Sortant)), d("Destinations", p.Destinations.ToString()),
                                                         d(en ? "Programs" : "Programmes", string.Join("\n", (p.Programmes ?? new List<string>()).Select(NomProgramme))) }
                            .Concat(signale ? new List<LigneDetail> { d(en ? "Flagged connection" : "Connexion signalée", en ? "At least one connection to this country is at the threshold of the Suspicious tab of Connections." : "Au moins une connexion vers ce pays est au seuil de l'onglet Suspectes de Connexions.") } : new List<LigneDetail>())
                            .Concat(DetailPays(t, p.Code)).ToList()
                    });
                }
            else
            {
                var dests = (t.Destinations ?? new List<TraficDestination>()).Where(x => x != null && (pays == null || x.Pays == pays)).ToList();
                // Filtre : destinations principales du pays absentes de la liste Destinations (100 lignes), sans port publié
                if (pf != null)
                    foreach (var x in (pf.DestinationsPrincipales ?? new List<TraficDestinationPays>()).Where(x => x != null && !dests.Any(y => y.Ip == x.Ip)))
                        dests.Add(new TraficDestination { Ip = x.Ip, Nom = x.Nom, Pays = pays, Programme = x.Programme, Entrant = x.Entrant, Sortant = x.Sortant });
                foreach (var x in dests.OrderByDescending(x => x.Entrant + x.Sortant).ThenBy(x => x.Ip ?? "", StringComparer.Ordinal))
                {
                    var det = new List<LigneDetail> { new LigneDetail { Titre = en ? "IP address" : "Adresse IP", Texte = Canal.Visible(x.Ip), Chasse = true } };
                    if (!string.IsNullOrEmpty(x.Nom)) det.Add(new LigneDetail { Titre = en ? "Name" : "Nom", Texte = Canal.Visible(x.Nom), Chasse = true });
                    det.Add(d(en ? "Country" : "Pays", NomPays(x.Pays)));
                    det.Add(d(en ? "Program" : "Programme", NomProgramme(x.Programme)));
                    det.Add(d("Port", x.Port > 0 ? x.Port.ToString() : (en ? "not published for this line" : "non publié pour cette ligne")));
                    det.Add(d(en ? "Received" : "Reçu", Format.Octets(x.Entrant)));
                    det.Add(d(en ? "Sent" : "Envoyé", Format.Octets(x.Sortant)));
                    l.Add(new LigneEtatFluent
                    {
                        Titre = Canal.Visible(string.IsNullOrEmpty(x.Nom) ? x.Ip : x.Nom + " (" + x.Ip + ")"), Etiquette = Format.Octets(x.Entrant + x.Sortant),
                        // Nom localisé du pays, jamais le code brut seul (défaut relevé pour T-19)
                        Sous = NomPays(x.Pays) + "  ·  " + NomProgramme(x.Programme) + (x.Port > 0 ? "  ·  port " + x.Port : "") + (x.Active ? maintenant : ""), Detail = det
                    });
                }
            }
            foreach (var x in l) foreach (var y in x.Detail) if (string.IsNullOrEmpty(y.Texte)) y.Texte = "—";
            return l;
        }
    }

    // Carte du monde de la page Trafic (U4b, interactive depuis T-19) : contours Natural Earth intégrés à l'exécutable (aucun
    // fond chargé d'Internet), pays colorés selon le volume depuis minuit (échelle logarithmique), arcs fixes depuis le pays
    // du réglage régional vers les 20 pays au plus fort débit récent. Zoom de 1 à 12 (molette au curseur, boutons, + et -),
    // glisser, double-clic qui centre, clic qui filtre les listes, clavier sur les pays avec trafic. Aucune animation
    // continue : un rendu seulement quand l'état, la vue, le survol ou le focus change ; les contours sont projetés une fois
    // par taille, le zoom est une transformation
    class CarteFluent : FrameworkElement
    {
        class Forme { public string Code; public Geometry G; public Rect Bornes; }

        EtatTrafic t;
        List<Forme> formes;
        Dictionary<string, Forme> index;
        Size tailleFormes;
        string survol, filtre, clavier, marque;
        internal string Origine;
        double zoom = 1;
        Point centre = new Point(0.5, 0.5);
        Point? appui;
        Point centreAppui;
        bool glisse;
        readonly ToolTip bulle = new ToolTip();
        public Action<string> Choisi;   // clic, Entrée : pays (la page bascule le filtre) ; Échap : null
        public Action VueChange;        // zoom ou centre changé : bornes écrites sous la carte

        internal const double Haut = 56, Bas = 34;

        public CarteFluent()
        {
            ClipToBounds = true;
            Focusable = true;
            FocusVisualStyle = null;    // focus dessiné sur le pays parcouru
            try { Origine = System.Globalization.RegionInfo.CurrentRegion.TwoLetterISORegionName; } catch { Origine = null; }
            ToolTipService.SetInitialShowDelay(this, 150);
            System.Windows.Automation.AutomationProperties.SetName(this, L.En ? "Traffic map: arrows go through the countries with traffic, Enter filters the lists, Esc clears the filter, + and - zoom"
                                                                              : "Carte du trafic : flèches pour parcourir les pays avec trafic, Entrée pour filtrer les listes, Échap pour retirer le filtre, + et - pour zoomer");
            // Infobulle ouverte au clavier fermée en quittant la page, quand la carte est cachée ou la fenêtre réduite
            // (prérelecture de #322)
            Loaded += (s, e) => { fenetre = Window.GetWindow(this); if (fenetre != null) fenetre.StateChanged += FenetreChangee; };
            Unloaded += (s, e) => { if (fenetre != null) fenetre.StateChanged -= FenetreChangee; fenetre = null; Fermer(); };
            IsVisibleChanged += (s, e) => { if (!IsVisible) Fermer(); };
        }

        Window fenetre;

        void FenetreChangee(object s, EventArgs e) { if (fenetre != null && fenetre.WindowState == WindowState.Minimized) Fermer(); }

        // Ferme l'infobulle (survol oublié aussi) ; appelée au départ de la page et à la réduction de la fenêtre
        internal void Fermer() { survol = null; ToolTip = null; bulle.IsOpen = false; }

        public void Definir(EtatTrafic e) { t = e; if (clavier != null && VueTraficFluent.Pays(t, clavier) == null) clavier = null; Bulle(); InvalidateVisual(); }

        internal string Filtre { get { return filtre; } set { if (filtre == value) return; filtre = value; Bulle(); InvalidateVisual(); } }

        // Pays choisi dans l'onglet Pays : contour accent, vue déplacée vers lui s'il est hors champ (l'onglet pilote la carte)
        internal string Marque { get { return marque; } set { if (marque == value) return; marque = value; Montrer(value); InvalidateVisual(); } }

        internal string Clavier { get { return clavier; } }
        internal double Zoom { get { return zoom; } }
        internal Point Centre { get { return centre; } }

        Rect Vue() { return new Rect(8, Haut, Math.Max(1, ActualWidth - 16), Math.Max(1, ActualHeight - Haut - Bas)); }

        Rect Zone()
        {
            // Longitude -180..180, latitude -58..84 (sans l'Antarctique), proportions conservées, centrée dans la vue
            var v = Vue();
            double echelle = Math.Max(1e-6, Math.Min(v.Width / 360, v.Height / 142));
            double lw = 360 * echelle, lh = 142 * echelle;
            return new Rect(v.X + (v.Width - lw) / 2, v.Y + (v.Height - lh) / 2, lw, lh);
        }

        static Point Projeter(System.Drawing.PointF ll, Rect z) { return new Point(z.X + (ll.X + 180) / 360 * z.Width, z.Y + (84 - ll.Y) / 142 * z.Height); }

        // Vue : le point de la carte au centre choisi va au centre de la vue, agrandi par le zoom (identité au zoom 1)
        Matrix Transformation()
        {
            var z = Zone(); var v = Vue();
            var m = Matrix.Identity;
            m.Translate(-(z.X + centre.X * z.Width), -(z.Y + centre.Y * z.Height));
            m.Scale(zoom, zoom);
            m.Translate(v.X + v.Width / 2, v.Y + v.Height / 2);
            return m;
        }

        // Contours projetés, reconstruits seulement quand la taille change
        List<Forme> Formes()
        {
            var taille = new Size(ActualWidth, ActualHeight);
            if (formes != null && taille == tailleFormes) return formes;
            tailleFormes = taille;
            var z = Zone();
            formes = new List<Forme>();
            index = new Dictionary<string, Forme>();
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
                var f = new Forme { Code = p.Code, G = g, Bornes = g.Bounds };
                formes.Add(f); index[p.Code] = f;
            }
            return formes;
        }

        Point CentrePays(string code)
        {
            PaysCarte p;
            return code != null && PaysCarte.Tous.TryGetValue(code, out p) ? Transformation().Transform(Projeter(p.Centre, Zone())) : new Point(double.NaN, double.NaN);
        }

        // Pays sous un point de l'écran (null : mer, hors de la vue)
        internal string PaysEn(Point ecran)
        {
            if (!Vue().Contains(ecran)) return null;
            var inv = Transformation();
            if (!inv.HasInverse) return null;
            inv.Invert();
            var b = inv.Transform(ecran);
            foreach (var f in Formes()) if (f.Bornes.Contains(b) && f.G.FillContains(b)) return f.Code;
            return null;
        }

        void Placer(double z, Point c)
        {
            z = VueTraficFluent.BornerZoom(z);
            var n = new Point(VueTraficFluent.BornerCentre(c.X, z), VueTraficFluent.BornerCentre(c.Y, z));
            if (z == zoom && n == centre) return;
            zoom = z; centre = n;
            InvalidateVisual();
            if (VueChange != null) VueChange();
        }

        // Zoom autour d'un point de l'écran (centre de la vue si null) : ce point reste en place
        internal void Zoomer(double facteur, Point? ecran)
        {
            double nz = VueTraficFluent.BornerZoom(zoom * facteur);
            var v = Vue(); var z = Zone();
            var p = ecran ?? new Point(v.X + v.Width / 2, v.Y + v.Height / 2);
            var inv = Transformation(); inv.Invert();
            var b = inv.Transform(p);
            double cx = b.X - (p.X - (v.X + v.Width / 2)) / nz, cy = b.Y - (p.Y - (v.Y + v.Height / 2)) / nz;
            Placer(nz, new Point((cx - z.X) / z.Width, (cy - z.Y) / z.Height));
        }

        internal void VueMonde() { Placer(1, new Point(0.5, 0.5)); }

        // Pays hors champ quand la carte est agrandie : la vue se déplace vers lui (le zoom ne change pas)
        void Montrer(string code)
        {
            PaysCarte p;
            if (zoom <= 1 || code == null || !PaysCarte.Tous.TryGetValue(code, out p)) return;
            var e = CentrePays(code);
            if (Vue().Contains(e)) return;
            var z = Zone(); var b = Projeter(p.Centre, z);
            Placer(zoom, new Point((b.X - z.X) / z.Width, (b.Y - z.Y) / z.Height));
        }

        // Infobulle du pays survolé, ou du pays parcouru au clavier (ouverte à côté de lui, seulement dans une vraie fenêtre)
        void Bulle()
        {
            string code = survol ?? (IsKeyboardFocused ? clavier : null);
            if (code == null) { ToolTip = null; bulle.IsOpen = false; return; }
            var pile = new StackPanel { MaxWidth = 380 };
            foreach (var x in VueTraficFluent.LignesBulle(t, code, code == filtre))
                pile.Children.Add(new TextBlock
                {
                    Text = x.Value, TextWrapping = TextWrapping.Wrap, FontSize = x.Key == 0 ? 13 : 12, FontWeight = x.Key == 0 ? FontWeights.SemiBold : FontWeights.Normal,
                    Foreground = Jetons.Pinceau(x.Key == 3 ? Jetons.Danger : x.Key == 4 ? Jetons.Accent : x.Key == 2 ? Jetons.TexteSecondaire : Jetons.Texte),
                    Margin = new Thickness(0, x.Key == 0 ? 0 : x.Key == 4 ? 6 : 2, 0, 0)
                });
            bulle.Content = pile;
            bulle.Background = Jetons.Pinceau(Jetons.Carte); bulle.BorderBrush = Jetons.Pinceau(Jetons.Separateur); bulle.Padding = new Thickness(10, 7, 10, 8);
            if (survol != null) { bulle.Placement = System.Windows.Controls.Primitives.PlacementMode.Mouse; ToolTip = bulle; return; }
            ToolTip = null;
            var c = CentrePays(code);
            if (PresentationSource.FromVisual(this) == null || double.IsNaN(c.X)) return;
            bulle.PlacementTarget = this; bulle.Placement = System.Windows.Controls.Primitives.PlacementMode.Relative;
            bulle.HorizontalOffset = c.X + 14; bulle.VerticalOffset = c.Y + 14;
            bulle.IsOpen = true;
        }

        void Survoler(string code)
        {
            if (code == survol) return;
            survol = code;
            Cursor = code != null && VueTraficFluent.Pays(t, code) != null ? Cursors.Hand : null;
            Bulle();
            InvalidateVisual();
        }

        protected override void OnMouseWheel(MouseWheelEventArgs e)
        {
            base.OnMouseWheel(e);
            if (!VueTraficFluent.MoletteGardee(zoom, e.Delta)) return;
            Zoomer(Math.Pow(1.25, e.Delta / 120.0), e.GetPosition(this));
            e.Handled = true;
        }

        protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
        {
            base.OnMouseLeftButtonDown(e);
            Focus();
            var p = e.GetPosition(this);
            if (e.ClickCount == 2)
            {
                // Double-clic : vue centrée sur le point, zoom ×2 ; le pays reste filtré (le premier clic l'a basculé)
                appui = null;
                string code = PaysEn(p);
                var inv = Transformation(); inv.Invert();
                var b = inv.Transform(p); var z = Zone();
                Placer(zoom * 2, new Point((b.X - z.X) / z.Width, (b.Y - z.Y) / z.Height));
                if (code != null && code != filtre && VueTraficFluent.Pays(t, code) != null && Choisi != null) Choisi(code);
                e.Handled = true;
                return;
            }
            appui = p; centreAppui = centre; glisse = false;
            CaptureMouse();
            e.Handled = true;
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            var p = e.GetPosition(this);
            if (appui.HasValue && IsMouseCaptured)
            {
                double dx = p.X - appui.Value.X, dy = p.Y - appui.Value.Y;
                if (!glisse && Math.Abs(dx) + Math.Abs(dy) > 4) { glisse = true; Survoler(null); Cursor = Cursors.SizeAll; }
                if (glisse)
                {
                    var z = Zone();
                    Placer(zoom, new Point(centreAppui.X - dx / (z.Width * zoom), centreAppui.Y - dy / (z.Height * zoom)));
                    return;
                }
            }
            Survoler(PaysEn(p));
        }

        protected override void OnMouseLeftButtonUp(MouseButtonEventArgs e)
        {
            base.OnMouseLeftButtonUp(e);
            if (!appui.HasValue) return;
            bool clic = !glisse;
            appui = null; glisse = false;
            ReleaseMouseCapture();
            Cursor = null;
            if (clic)
            {
                string code = PaysEn(e.GetPosition(this));
                if (code != null && VueTraficFluent.Pays(t, code) != null && Choisi != null) Choisi(code);
            }
            e.Handled = true;
        }

        protected override void OnMouseLeave(MouseEventArgs e)
        {
            base.OnMouseLeave(e);
            Survoler(null);
        }

        protected override void OnGotKeyboardFocus(KeyboardFocusChangedEventArgs e)
        {
            base.OnGotKeyboardFocus(e);
            if (clavier == null) clavier = filtre ?? marque ?? VueTraficFluent.Voisin(VueTraficFluent.PaysClavier(t), null, 1);
            Montrer(clavier); Bulle(); InvalidateVisual();
        }

        protected override void OnLostKeyboardFocus(KeyboardFocusChangedEventArgs e)
        {
            base.OnLostKeyboardFocus(e);
            bulle.IsOpen = false; Bulle(); InvalidateVisual();
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            base.OnKeyDown(e);
            if (Touche(e.Key)) e.Handled = true;
        }

        // Clavier (essayé sans fenêtre par les tests) : flèches, pays avec trafic par volume ; Entrée ou Espace, filtre ;
        // Échap, filtre retiré ; + et -, zoom au centre ; Origine, vue monde
        internal bool Touche(Key k)
        {
            switch (k)
            {
                case Key.Right: case Key.Down: Parcourir(1); return true;
                case Key.Left: case Key.Up: Parcourir(-1); return true;
                case Key.Enter: case Key.Space:
                    if (clavier == null || Choisi == null) return false;
                    Choisi(clavier); return true;
                case Key.Escape:
                    if (filtre == null || Choisi == null) return false;
                    Choisi(null); return true;
                case Key.Add: case Key.OemPlus: Zoomer(1.5, null); return true;
                case Key.Subtract: case Key.OemMinus: Zoomer(1 / 1.5, null); return true;
                case Key.Home: VueMonde(); return true;
            }
            return false;
        }

        void Parcourir(int sens)
        {
            clavier = VueTraficFluent.Voisin(VueTraficFluent.PaysClavier(t), clavier, sens);
            Montrer(clavier); Bulle(); InvalidateVisual();
        }

        FormattedText Texte(string s, Color c)
        {
            return new FormattedText(s, System.Globalization.CultureInfo.CurrentUICulture, FlowDirection.LeftToRight, new Typeface(Jetons.Police, FontStyles.Normal, FontWeights.Normal, FontStretches.Normal),
                11, Jetons.Pinceau(c), VisualTreeHelper.GetDpi(this).PixelsPerDip);
        }

        // Ligne de légende coupée par des points de suspension quand la carte est étroite, jamais tronquée en plein mot
        // (captures de #141) ; rend la largeur écrite
        double Ecrire(DrawingContext g, string s, double x, double y, double largeur, Color c)
        {
            var legende = Texte(s, c);
            legende.MaxTextWidth = Math.Max(1, largeur); legende.MaxLineCount = 1; legende.Trimming = TextTrimming.CharacterEllipsis;
            g.DrawText(legende, new Point(x, y));
            return Math.Min(legende.WidthIncludingTrailingWhitespace, largeur);
        }

        // Légende : échelle logarithmique (aucun, 1 Ko, 1 Mo, maximum), origine et épaisseur des arcs, pays signalé, volume sans pays
        void Legende(DrawingContext g, long max)
        {
            bool en = L.En;
            double barre = Math.Max(80, Math.Min(180, ActualWidth * 0.26));
            double xb = ActualWidth - 16 - barre, gauche = Math.Max(1, xb - 48 - 12);
            Ecrire(g, en ? "Volume since midnight (log scale)" : "Volume depuis minuit (échelle log.)", 12, 4, gauche, Jetons.TexteSecondaire);
            var gris = Jetons.Pinceau(Jetons.TexteSecondaire);
            g.DrawRoundedRectangle(Jetons.Pinceau(Jetons.Surface), new Pen(Jetons.Pinceau(Jetons.Separateur), 0.6), new Rect(xb - 30, 8, 18, 8), 2, 2);
            var degrade = new LinearGradientBrush(VueTraficFluent.Melange(Jetons.Surface, Jetons.Accent, 0.25), Jetons.Accent, 0); degrade.Freeze();
            g.DrawRoundedRectangle(degrade, null, new Rect(xb, 8, barre, 8), 2, 2);
            var aucun = Texte(en ? "none" : "aucun", Jetons.TexteSecondaire);
            g.DrawText(aucun, new Point(xb - 21 - aucun.Width / 2, 17));
            double fin = double.NegativeInfinity;
            var reperes = new List<KeyValuePair<long, string>>();
            if (max > 1024) reperes.Add(new KeyValuePair<long, string>(1024, en ? "1 KB" : "1 Ko"));
            if (max > 1L << 20) reperes.Add(new KeyValuePair<long, string>(1L << 20, en ? "1 MB" : "1 Mo"));
            reperes.Add(new KeyValuePair<long, string>(max, Format.Octets(max)));
            for (int i = 0; i < reperes.Count; i++)
            {
                double x = xb + VueTraficFluent.Intensite(reperes[i].Key, max) * barre;
                var ft = Texte(reperes[i].Value, Jetons.TexteSecondaire);
                double xt = Math.Max(xb - 4, Math.Min(x - ft.Width / 2, ActualWidth - 8 - ft.Width));
                if (xt < fin + 4 && i < reperes.Count - 1) continue;
                g.DrawLine(new Pen(gris, 1), new Point(x, 16), new Point(x, 19));
                g.DrawText(ft, new Point(xt, 18)); fin = xt + ft.Width;
            }
            // Arcs : pays d'origine (réglage régional), 10 dernières secondes, épaisseur en racine carrée du débit
            string arcs = VueTraficFluent.TexteArcs(t, Origine);
            var trait = new Pen(new SolidColorBrush(Color.FromArgb(0xB0, Jetons.Accent.R, Jetons.Accent.G, Jetons.Accent.B)), 1); trait.Freeze();
            var epais = new Pen(trait.Brush, 4); epais.Freeze();
            g.DrawLine(trait, new Point(14, 26), new Point(28, 26)); g.DrawLine(epais, new Point(34, 26), new Point(48, 26));
            Ecrire(g, arcs, 56, 19, Math.Max(1, ActualWidth - 56 - 12), Jetons.TexteSecondaire);
            // Pays signalé, puis volume sans pays (réseau local, adresse sans pays connu)
            g.DrawRoundedRectangle(null, new Pen(Jetons.Pinceau(Jetons.Danger), 1.6), new Rect(14, 38, 14, 9), 2, 2);
            string sansPays = t == null ? "" : t.PlagesGeoip <= 0 ? (en ? "  ·  no country yet: address ranges not loaded" : "  ·  aucun pays encore : plages d'adresses non chargées")
                : string.Format(en ? "  ·  without country: {0} (local network or unknown address)" : "  ·  sans pays : {0} (réseau local ou adresse inconnue)", Format.Octets(VueTraficFluent.VolumeSansPays(t)));
            Ecrire(g, (en ? "flagged connection" : "connexion signalée") + sansPays, 34, 35, Math.Max(1, ActualWidth - 34 - 12), Jetons.TexteSecondaire);
        }

        protected override void OnRender(DrawingContext g)
        {
            g.DrawRoundedRectangle(Jetons.Pinceau(Jetons.Carte), null, new Rect(0, 0, ActualWidth, ActualHeight), 8, 8);
            if (ActualWidth < 40 || ActualHeight < Haut + Bas + 20) return;
            var volumes = new Dictionary<string, long>();
            foreach (var p in t == null || t.Pays == null ? new List<TraficPays>() : t.Pays) if (p != null && p.Code != null) volumes[p.Code] = p.Entrant + p.Sortant;
            long max = volumes.Count == 0 ? 1 : Math.Max(1, volumes.Values.Max());
            Legende(g, max);
            var v = Vue(); var m = Transformation();
            g.PushClip(new RectangleGeometry(v, 6, 6));
            g.PushTransform(new MatrixTransform(m));
            var trait = new Pen(Jetons.Pinceau(Jetons.Separateur), 0.6 / zoom); trait.Freeze();
            foreach (var f in Formes())
            {
                long x;
                var fond = Jetons.Surface;
                if (volumes.TryGetValue(f.Code, out x) && x > 0) fond = VueTraficFluent.Melange(Jetons.Surface, Jetons.Accent, 0.25 + 0.75 * VueTraficFluent.Intensite(x, max));
                if (filtre != null && f.Code != filtre) fond = VueTraficFluent.Melange(fond, Jetons.Carte, 0.45);
                if (f.Code == survol || f.Code == filtre) fond = VueTraficFluent.Melange(fond, Colors.White, 0.18);
                g.DrawGeometry(Jetons.Pinceau(fond), trait, f.G);
            }
            // Contours : pays signalés (rouge), survol, pays de l'onglet Pays et pays filtré (accent), focus clavier (pointillé)
            Forme h;
            foreach (var code in t == null || t.PaysSignales == null ? new List<string>() : t.PaysSignales)
                if (code != null && index.TryGetValue(code, out h)) g.DrawGeometry(null, new Pen(Jetons.Pinceau(Jetons.Danger), 1.8 / zoom), h.G);
            if (survol != null && index.TryGetValue(survol, out h)) g.DrawGeometry(null, new Pen(Jetons.Pinceau(Jetons.Texte), 1.2 / zoom), h.G);
            if (marque != null && marque != filtre && index.TryGetValue(marque, out h)) g.DrawGeometry(null, new Pen(Jetons.Pinceau(Jetons.Accent), 1.6 / zoom), h.G);
            if (filtre != null && index.TryGetValue(filtre, out h)) g.DrawGeometry(null, new Pen(Jetons.Pinceau(Jetons.Accent), 2.4 / zoom), h.G);
            if (IsKeyboardFocused && clavier != null && index.TryGetValue(clavier, out h))
                g.DrawGeometry(null, new Pen(Jetons.Pinceau(Jetons.Texte), 1.2 / zoom) { DashStyle = new DashStyle(new double[] { 2, 2 }, 0) }, h.G);
            g.Pop();
            // Arcs en coordonnées de l'écran : leur épaisseur ne grossit pas avec le zoom
            PaysCarte depart;
            if (Origine != null && PaysCarte.Tous.TryGetValue(Origine, out depart))
            {
                var z = Zone();
                var a0 = m.Transform(Projeter(depart.Centre, z));
                var arcs = VueTraficFluent.Arcs(t, Origine);
                foreach (var a in Enumerable.Reverse(arcs))
                {
                    var a1 = m.Transform(Projeter(PaysCarte.Tous[a.Code].Centre, z));
                    double dx = a1.X - a0.X, dy = a1.Y - a0.Y;
                    var milieu = new Point((a0.X + a1.X) / 2 - dy * 0.25, (a0.Y + a1.Y) / 2 - Math.Abs(dx) * 0.25 - 10);
                    var courbe = new StreamGeometry();
                    using (var c = courbe.Open()) { c.BeginFigure(a0, false, false); c.QuadraticBezierTo(milieu, a1, true, false); }
                    courbe.Freeze();
                    var couleur = a.Signale ? Jetons.Danger : Jetons.Accent;
                    byte alpha = (byte)(filtre == null || filtre == a.Code ? 0xC0 : 0x40);
                    var stylo = new Pen(new SolidColorBrush(Color.FromArgb(alpha, couleur.R, couleur.G, couleur.B)), a.Epaisseur) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
                    stylo.Freeze();
                    g.DrawGeometry(null, stylo, courbe);
                    g.DrawEllipse(Jetons.Pinceau(couleur), null, a1, 3.5, 3.5);
                }
                g.DrawEllipse(Jetons.Pinceau(Jetons.Texte), null, a0, 4, 4);
            }
            g.Pop();
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
    // l'interface, relu seulement quand il change), carte, courbe, puis programmes, pays ou destinations avec leur détail.
    // T-19 : clic sur un pays de la carte (ou Entrée) = filtre des listes, écrit au-dessus d'elles avec sa croix, appliqué au
    // panneau de détail, remis à zéro en quittant la page ; aucune commande, aucun réglage
    class PageTraficFluent : Grid
    {
        readonly TextBlock resume = new TextBlock();
        readonly StackPanel outils = new StackPanel();
        readonly WrapPanel vues = new WrapPanel { Margin = new Thickness(0, 0, 0, 12) };
        readonly StackPanel barreFiltre = new StackPanel { Margin = new Thickness(0, 0, 0, 10) };
        readonly StackPanel liste = new StackPanel();
        readonly ContentControl detail = new ContentControl();
        readonly CarteFluent carte = new CarteFluent();
        readonly CourbeFluent courbe = new CourbeFluent();
        readonly TextBlock bornes = new TextBlock();
        readonly Button monde;
        readonly Action ouvrirConnexions;
        readonly System.Windows.Threading.DispatcherTimer minuteur = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        EtatTrafic t;
        bool lu, illisible;
        long vuFichier;         // date du fichier lu (ticks) : rien n'est relu tant qu'il ne change pas
        int vue, choisie, enCours, chargement;
        string vu, filtre;

        public PageTraficFluent() : this(null) { }

        public PageTraficFluent(Action ouvrirConnexions)
        {
            this.ouvrirConnexions = ouvrirConnexions;
            bool en = L.En;
            var haut = new Grid { Height = 400, Margin = new Thickness(0, 0, 0, 12) };
            haut.ColumnDefinitions.Add(new ColumnDefinition());
            haut.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(300) });
            // Commandes de vue sous la carte : zoom, vue monde, bornes écrites, rappel des gestes
            var cadre = new Grid();
            cadre.Children.Add(carte);
            var bas = new DockPanel { VerticalAlignment = VerticalAlignment.Bottom, Margin = new Thickness(12, 0, 12, 7), LastChildFill = true };
            Func<string, string, RoutedEventHandler, Button> outil = (texte, nom, clic) =>
            {
                var b = new Button
                {
                    Content = texte, Padding = new Thickness(9, 1, 9, 2), Margin = new Thickness(0, 0, 6, 0), FontSize = 12, Cursor = Cursors.Hand, Background = Jetons.Pinceau(Jetons.Carte),
                    BorderBrush = Jetons.Pinceau(Jetons.Separateur), BorderThickness = new Thickness(1), Foreground = Jetons.Pinceau(Jetons.Texte), FocusVisualStyle = Jetons.StyleFocus()
                };
                b.Template = Coquille.ModeleBouton();
                System.Windows.Automation.AutomationProperties.SetName(b, nom);
                b.Click += clic;
                DockPanel.SetDock(b, Dock.Left);
                bas.Children.Add(b);
                return b;
            };
            outil("−", en ? "Zoom out" : "Dézoomer", (s, e) => carte.Zoomer(1 / 1.5, null));
            outil("+", en ? "Zoom in" : "Zoomer", (s, e) => carte.Zoomer(1.5, null));
            monde = outil(en ? "World view" : "Vue monde", en ? "World view" : "Vue monde", (s, e) => carte.VueMonde());
            bornes.FontSize = 11.5; bornes.Foreground = Jetons.Pinceau(Jetons.TexteSecondaire); bornes.VerticalAlignment = VerticalAlignment.Center; bornes.Margin = new Thickness(4, 0, 12, 0);
            DockPanel.SetDock(bornes, Dock.Left); bas.Children.Add(bornes);
            string gestes = en ? "Wheel: zoom at the cursor · drag: move · double-click: centre · click: filter · Esc: clear"
                               : "Molette : zoom au curseur · glisser : déplacer · double-clic : centrer · clic : filtrer · Échap : retirer";
            bas.Children.Add(new TextBlock { Text = gestes, ToolTip = gestes, FontSize = 11.5, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextTrimming = TextTrimming.CharacterEllipsis, TextAlignment = TextAlignment.Right, VerticalAlignment = VerticalAlignment.Center });
            cadre.Children.Add(bas);
            carte.VueChange = Bornes;
            carte.Choisi = code => Basculer(code);
            Bornes();
            courbe.Margin = new Thickness(12, 0, 0, 0);
            Grid.SetColumn(courbe, 1);
            haut.Children.Add(cadre); haut.Children.Add(courbe);
            outils.Children.Add(haut);
            outils.Children.Add(barreFiltre);
            outils.Children.Add(vues);
            Briques.Disposer(this, resume, outils, liste, detail);
            minuteur.Tick += (s, e) => Charger();
            Loaded += (s, e) => { minuteur.Start(); Charger(); };
            // Filtre remis à zéro en quittant la page (décision T-19)
            Unloaded += (s, e) => { minuteur.Stop(); FiltrerPays(null); };
            KeyDown += (s, e) => { if (e.Key == Key.Escape && filtre != null) { FiltrerPays(null); e.Handled = true; } };
            Afficher();
        }

        internal string Filtre { get { return filtre; } }

        void Bornes()
        {
            bornes.Text = "×" + carte.Zoom.ToString("0.#", System.Globalization.CultureInfo.CurrentUICulture) + (L.En ? "  (1 to 12)" : "  (1 à 12)");
            monde.BorderBrush = Jetons.Pinceau(carte.Zoom > 1 ? Jetons.Accent : Jetons.Separateur);
        }

        // Clic ou Entrée sur un pays : filtre posé, ou retiré s'il était déjà posé ; null retire le filtre
        internal void Basculer(string code) { FiltrerPays(code != null && code == filtre ? null : code); }

        internal void FiltrerPays(string code)
        {
            if (code == filtre) return;
            filtre = code; choisie = 0; vu = null;
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
                        Briques.GarderFocus(Afficher, liste, vues, barreFiltre);
                    }));
                }
                finally { System.Threading.Interlocked.Exchange(ref enCours, 0); }
            });
        }

        void Afficher()
        {
            bool en = L.En;
            resume.Text = VueTraficFluent.Resume(t, lu, illisible);
            resume.Foreground = Jetons.Pinceau(lu && (t == null || illisible) ? Jetons.Attention : Jetons.TexteSecondaire);
            carte.Definir(t);
            carte.Filtre = filtre;
            courbe.Definir(t == null ? null : t.Serie);
            var lignes = VueTraficFluent.LignesFiltrees(t, vue, filtre);
            if (choisie >= lignes.Count) choisie = 0;
            // Onglet Pays : la ligne choisie est marquée sur la carte
            carte.Marque = vue == 1 && lignes.Count > 0 ? lignes[choisie].Pays : null;
            bool signale = VueTraficFluent.Signale(t, filtre);
            string signature = vue + "#" + choisie + "#" + filtre + "#" + signale + "#" + resume.Text + "#" + string.Join(";", lignes.Take(VueTraficFluent.Maximum).Select(x => x.Titre + "|" + x.Etiquette + "|" + x.Sous));
            if (signature == vu) return;
            vu = signature;
            Filtrer(signale);
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
            if (filtre != null) liste.Children.Add(new TextBlock { Text = VueTraficFluent.TitreFiltre(vue, filtre), FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, 0, 0, 6) });
            // Avant la première lecture, ou sans données, le résumé le dit ; rien n'est conclu ici
            if (lu && t != null && lignes.Count == 0)
                liste.Children.Add(new TextBlock { Text = L.T("Rien d'enregistré pour cette vue."), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap });
            for (int k = 0; k < Math.Min(lignes.Count, VueTraficFluent.Maximum); k++)
            {
                int n = k; var x = lignes[k];
                liste.Children.Add(Briques.Ligne(x.Titre, x.Etiquette, x.Sous, x.Gravite, n == choisie, false, () => { choisie = n; Afficher(); }));
            }
            if (lignes.Count > VueTraficFluent.Maximum)
                liste.Children.Add(new TextBlock { Text = string.Format(en ? "The {0} largest are shown." : "Les {0} plus gros volumes sont affichés.", VueTraficFluent.Maximum), FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire) });
            Detailler(lignes.Count > 0 ? lignes[choisie] : null);
        }

        // Filtre écrit au-dessus des listes : pays avec sa croix, rappel pour le retirer, lien vers Connexions s'il est signalé
        void Filtrer(bool signale)
        {
            bool en = L.En;
            barreFiltre.Children.Clear();
            barreFiltre.Visibility = filtre == null ? Visibility.Collapsed : Visibility.Visible;
            if (filtre == null) return;
            var ligne = new WrapPanel();
            var puce = new Button
            {
                Content = VueTraficFluent.TexteFiltre(filtre) + "   ✕", Padding = new Thickness(12, 3, 10, 4), Margin = new Thickness(0, 0, 12, 0), Cursor = Cursors.Hand,
                Background = Jetons.Pinceau(VueTraficFluent.Melange(Jetons.Fond, Jetons.Accent, 0.14)), BorderBrush = Jetons.Pinceau(Jetons.Accent), BorderThickness = new Thickness(1),
                Foreground = Jetons.Pinceau(Jetons.Texte), FocusVisualStyle = Jetons.StyleFocus()
            };
            puce.Template = Coquille.ModeleBouton();
            System.Windows.Automation.AutomationProperties.SetName(puce, (en ? "Clear the filter, " : "Retirer le filtre, ") + VueTraficFluent.TexteFiltre(filtre));
            puce.Click += (s, e) => { FiltrerPays(null); carte.Focus(); };
            ligne.Children.Add(puce);
            ligne.Children.Add(new TextBlock { Text = VueTraficFluent.AideFiltre(filtre), FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 12, 0) });
            if (signale) ligne.Children.Add(LienConnexions());
            barreFiltre.Children.Add(ligne);
        }

        Button LienConnexions()
        {
            var b = new Button
            {
                Content = L.En ? "Open in Connections ›" : "Ouvrir dans Connexions ›", Padding = new Thickness(10, 3, 10, 4), Cursor = Cursors.Hand, Background = Jetons.Pinceau(Jetons.Carte),
                BorderBrush = Jetons.Pinceau(Jetons.Danger), BorderThickness = new Thickness(1), Foreground = Jetons.Pinceau(Jetons.Texte), FocusVisualStyle = Jetons.StyleFocus(),
                HorizontalAlignment = HorizontalAlignment.Left
            };
            b.Template = Coquille.ModeleBouton();
            b.Click += (s, e) => OuvrirConnexions();
            return b;
        }

        // Onglet Suspectes de Connexions : même seuil que les pays signalés (PaysSignales)
        internal void OuvrirConnexions() { if (ouvrirConnexions != null) ouvrirConnexions(); }

        void Detailler(LigneEtatFluent x)
        {
            bool en = L.En;
            if (x == null) { detail.Content = new TextBlock { Text = L.T("Sélectionnez une ligne pour lire son détail en entier."), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap }; return; }
            var pile = new StackPanel();
            pile.Children.Add(new TextBlock { Text = x.Titre, FontSize = 16, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            pile.Children.Add(new TextBlock { Text = x.Etiquette, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, 2, 0, 4) });
            var lignes = x.Detail.ToList();
            // Filtre appliqué au panneau : les destinations principales du pays filtré suivent le détail de la ligne
            if (filtre != null && vue != 1) lignes.AddRange(VueTraficFluent.DetailPays(t, filtre));
            foreach (var l in lignes)
            {
                pile.Children.Add(Briques.Titre(l.Titre, 10));
                var tb = new TextBlock { Text = l.Texte, TextWrapping = TextWrapping.Wrap };
                if (l.Chasse) { tb.FontFamily = Briques.Chasse; tb.FontSize = 12; }
                pile.Children.Add(tb);
            }
            // Onglet Pays, équivalent clavier complet de la carte : filtrer sur ce pays, ou retirer le filtre
            if (vue == 1 && x.Pays != null)
            {
                var b = Briques.Action(x.Pays == filtre ? (en ? "Clear the country filter" : "Retirer le filtre de pays") : (en ? "Filter the lists on this country" : "Filtrer les listes sur ce pays"), false, (s, e) => Basculer(x.Pays));
                b.Margin = new Thickness(0, 14, 0, 6);
                pile.Children.Add(b);
                if (VueTraficFluent.Signale(t, x.Pays)) pile.Children.Add(LienConnexions());
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
                    Dispatcher.BeginInvoke((Action)(() => { if (numero == chargement) { lu = true; Recevoir(r); Briques.GarderFocus(Afficher, liste, outils); } }));
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
    // Décisions pures de la page « Navigation » (phase 7, PR 7.5b), testées par tests\rendu-pilote.ps1. Tout ce qui vient
    // de filtrage-etat.json (noms bloqués : écrits par les sites et les programmes du poste) passe par Canal.Visible
    public static class VueNavigationFluent
    {
        public static readonly string[] Categories = { "securite", "publicite" };

        public static string NomCategorie(string cle)
        {
            bool en = L.En;
            return cle == "securite" ? (en ? "Safe browsing" : "Navigation sécurisée") : cle == "publicite" ? (en ? "Ads and tracking" : "Publicités et pistage") : Canal.Visible(cle);
        }

        // Libellé publié par le service pour une catégorie (filtrage.rs, Categorie::libelle)
        public static string LibelleService(string cle) { return cle == "securite" ? "sécurité" : cle == "publicite" ? "publicité et pistage" : cle; }

        public static bool Actif(EtatFiltrage e) { return e != null && !string.IsNullOrEmpty(e.Etat) && e.Etat != "inactif"; }

        public static bool CategorieActive(EtatFiltrage e, string cle)
        {
            return e != null && e.Categories != null && e.Categories.Contains(LibelleService(cle));
        }

        // Valeur de la commande filtrageCategories après un basculement (pure, testée)
        public static string ValeurApres(EtatFiltrage e, string cle, bool activer)
        {
            var l = Categories.Where(c => c == cle ? activer : CategorieActive(e, c)).ToList();
            return string.Join(",", l);
        }

        // État publié, traduit en anglais pour les libellés connus ; inconnu : neutralisé tel quel
        public static string EtatTexte(string etat)
        {
            string s = etat ?? "";
            if (!L.En) return Canal.Visible(s);
            if (s == "inactif") return "off";
            if (s == "actif") return "on";
            if (s == "suspendu : amont injoignable") return "suspended: upstream unreachable";
            if (s == "suspendu : résolveur local non lancé") return "suspended: local resolver not running";
            if (s == "remise des cartes en attente") return "card restore pending";
            if (s.StartsWith("contourné sur la carte ")) return "bypassed on card " + Canal.Visible(s.Substring("contourné sur la carte ".Length));
            return Canal.Visible(s);
        }

        // Gravité : 1 si le filtrage activé ne filtre pas (suspendu, contourné, remise en attente), 0 sinon
        public static int Gravite(EtatFiltrage e)
        {
            if (!Actif(e)) return 0;
            return e.Etat == "actif" ? 0 : 1;
        }

        // Aucune liste publiée de catégorie « sécurité » (D7-2 : aucune n'est compilée aujourd'hui) : la catégorie ne bloque
        // rien, et la page le dit au lieu d'afficher « Activé » seul (relecture de #166, constat 1)
        // Décisions partagées avec Canal.Decrire, gardées dans Commun.cs (TextesFiltrage) : l'assistant élevé ne doit jamais
        // dépendre d'une classe de Fluent.cs (audit de #166, S166-01)
        public static bool SansListeSecurite(EtatFiltrage e) { return TextesFiltrage.SansListeSecurite(e); }
        public static string RienBloqueSecurite(EtatFiltrage e) { return TextesFiltrage.RienBloqueSecurite(e); }

        public static string Honnete()
        {
            return L.En ? "Filtering does not protect against a program that uses its own DNS or encrypted DNS."
                        : "Le filtrage ne protège pas contre un programme qui utilise son propre DNS ou un DNS chiffré.";
        }

        public static string Lecteurs()
        {
            return L.En ? "Blocked names cover every user of this computer: an account allowed to read deR4Tizer data sees them."
                        : "Les noms bloqués concernent tous les utilisateurs du poste : un compte autorisé à lire les données de deR4Tizer les voit.";
        }

        public static string Resume(EtatFiltrage e, bool lu, bool illisible)
        {
            bool en = L.En;
            if (!lu) return en ? "Reading…" : "Lecture en cours…";
            if (illisible) return en ? "Filtering state unreadable (filtrage-etat.json)." : "État du filtrage illisible (filtrage-etat.json).";
            if (e == null) return (en ? "Domain-name filtering: off (no state published by the service yet)." : "Filtrage par nom de domaine : inactif (aucun état publié par le service pour l'instant).") + "\n" + Honnete();
            var cats = Categories.Where(c => CategorieActive(e, c)).Select(NomCategorie).ToList();
            var amonts = (e.Amonts ?? new List<string>()).Select(Canal.Visible).ToList();
            return (en ? "Filtering: " : "Filtrage : ") + EtatTexte(e.Etat)
                + (en ? "  ·  categories: " : "  ·  catégories : ") + (cats.Count == 0 ? (en ? "none" : "aucune") : string.Join(", ", cats))
                + (amonts.Count == 0 ? "" : (en ? "  ·  upstream: " : "  ·  amont : ") + string.Join(", ", amonts))
                + (CategorieActive(e, "securite") && SansListeSecurite(e) ? "\n" + NomCategorie("securite") + " : " + RienBloqueSecurite(e) : "")
                + "\n" + TexteAmont(e)
                + "\n" + Honnete() + "\n" + Lecteurs();
        }

        // Résolveur d'amont (PR 7.6) : celui du réseau, ou le tiers nommé, avec l'envoi des requêtes dit, et le repli
        public static string TexteAmont(EtatFiltrage e)
        {
            bool en = L.En;
            string t = e == null ? null : TextesFiltrage.NomTiers(e.AmontChoisi);
            if (t == null) return en ? "Upstream resolver: your network's." : "Résolveur d'amont : celui de votre réseau.";
            return (en ? "Upstream resolver: " : "Résolveur d'amont : ") + t + " (" + TextesFiltrage.PresentationTiers(e.AmontChoisi) + ")"
                + (en ? "; your DNS queries that are not blocked are sent to " : " ; vos requêtes DNS non bloquées sont envoyées à ") + t + "."
                + (e.RepliTiers ? (en ? " Not answering (captive portal?): your network's DNS is used for now." : " Injoignable (portail captif ?) : le DNS de votre réseau est utilisé pour l'instant.") : "");
        }

        public static string TexteChoixAmont(string cle, bool choisi)
        {
            string nom = cle == "reseau" ? (L.En ? "Your network's resolver" : "Résolveur de votre réseau") : TextesFiltrage.NomTiers(cle) + "  ·  " + TextesFiltrage.PresentationTiers(cle);
            return (choisi ? (L.En ? "Chosen" : "Choisi") + "  ·  " : "") + nom;
        }

        public static string TexteActivation(bool actif)
        {
            return actif ? (L.En ? "Turn filtering off" : "Désactiver le filtrage") : (L.En ? "Turn filtering on" : "Activer le filtrage");
        }

        public static string TexteCategorie(string cle, bool actif, bool sansListe, EtatFiltrage e)
        {
            return (actif ? (L.En ? "On" : "Activé") : (L.En ? "Off" : "Désactivé")) + "  ·  " + NomCategorie(cle)
                + (cle == "securite" && sansListe ? "  ·  " + RienBloqueSecurite(e) : "");
        }

        // Lignes de la page, et pour chacune : « b » (blocage), « a » (autorisation) ou « l » (liste), avec le nom
        public static List<KeyValuePair<string, LigneEtatFluent>> Lignes(EtatFiltrage e)
        {
            bool en = L.En;
            var r = new List<KeyValuePair<string, LigneEtatFluent>>();
            if (e == null) return r;
            foreach (var b in (e.Derniers ?? new List<BlocageFiltrage>()).Where(x => x != null))
            {
                var l = new LigneEtatFluent { Titre = Canal.Visible(b.Nom), Etiquette = en ? "blocked" : "bloqué", Sous = Canal.Visible(b.Liste) + "  ·  " + Canal.Visible(b.Heure), Gravite = 0 };
                l.Detail.Add(new LigneDetail { Titre = en ? "Name" : "Nom", Texte = Canal.Visible(b.Nom), Chasse = true });
                l.Detail.Add(new LigneDetail { Titre = en ? "List" : "Liste", Texte = Canal.Visible(b.Liste) + " (" + Canal.Visible(b.Categorie) + ")" });
                l.Detail.Add(new LigneDetail { Titre = en ? "Time" : "Heure", Texte = Canal.Visible(b.Heure) });
                r.Add(new KeyValuePair<string, LigneEtatFluent>("b" + (b.Nom ?? ""), l));
            }
            foreach (var a in (e.Autorises ?? new List<string>()).Where(x => !string.IsNullOrEmpty(x)))
            {
                var l = new LigneEtatFluent { Titre = Canal.Visible(a), Etiquette = en ? "allowed" : "autorisé", Sous = en ? "never blocked, subdomains included" : "jamais bloqué, sous-domaines compris" };
                r.Add(new KeyValuePair<string, LigneEtatFluent>("a" + a, l));
            }
            foreach (var x in (e.Listes ?? new List<ListeFiltrage>()).Where(y => y != null))
            {
                var l = new LigneEtatFluent
                {
                    Titre = Canal.Visible(x.Nom), Etiquette = Canal.Visible(x.Categorie),
                    Sous = x.Entrees.ToString("N0") + (en ? " domains" : " domaines") + (string.IsNullOrEmpty(x.MiseAJour) ? "" : "  ·  " + Canal.Visible(x.MiseAJour))
                };
                l.Detail.Add(new LigneDetail { Titre = en ? "License" : "Licence", Texte = Canal.Visible(x.Licence) });
                l.Detail.Add(new LigneDetail { Titre = en ? "Entries" : "Entrées", Texte = x.Entrees.ToString("N0") + (en ? " domains, " : " domaines, ") + x.Exceptions.ToString("N0") + (en ? " exceptions" : " exceptions") });
                l.Detail.Add(new LigneDetail { Titre = en ? "Skipped" : "Écartées", Texte = x.Ecartees.ToString("N0") + (en ? " rules (other syntax), " : " règles (autre syntaxe), ") + x.ProtegesIgnores.ToString("N0") + (en ? " never-blocked domains (built-in list) ignored" : " domaines jamais bloqués (liste intégrée) ignorés") });
                r.Add(new KeyValuePair<string, LigneEtatFluent>("l" + (x.Nom ?? ""), l));
            }
            return r;
        }
    }

    // Page « Navigation » en WPF (phase 7, PR 7.5b) : filtrage-etat.json ; activation, catégories et autorisations par les
    // mêmes commandes que le service (ActionsProtection, confirmées par Canal dans une interface élevée)
    class PageNavigationFluent : PageProtectionFluent
    {
        EtatFiltrage etat;
        bool illisible;

        public PageNavigationFluent() { Afficher(); }

        protected override object LireFichiers()
        {
            bool absent;
            var e = LectureFluent.Lire<EtatFiltrage>("filtrage-etat.json", out absent);
            return new object[] { e, absent };
        }

        protected override void Recevoir(object lecture)
        {
            var r = (object[])lecture;
            bool absent = (bool)r[1];
            illisible = !absent && r[0] == null;
            if (r[0] != null || absent) etat = r[0] as EtatFiltrage;
        }

        protected override void Afficher()
        {
            resume.Text = VueNavigationFluent.Resume(etat, lu, illisible);
            resume.Foreground = Jetons.Pinceau(lu && (illisible || VueNavigationFluent.Gravite(etat) > 0) ? Jetons.Attention : Jetons.TexteSecondaire);
            var paires = VueNavigationFluent.Lignes(etat);
            var lignes = paires.Select(p => p.Value).ToList();
            bool actif = VueNavigationFluent.Actif(etat);
            string cats = string.Join(",", VueNavigationFluent.Categories.Where(c => VueNavigationFluent.CategorieActive(etat, c)));
            string signature = choisie + "#" + resume.Text + "#" + lu + "#" + actif + "#" + cats + "#" + (etat == null ? "" : etat.AmontChoisi + etat.RepliTiers) + "#" + string.Join(";", paires.Select(p => p.Key + "|" + p.Value.Sous));
            if (signature == vu) return;
            vu = signature;
            outils.Children.Clear();
            if (lu && !illisible)
            {
                var barre = new WrapPanel();
                barre.Children.Add(Outil(VueNavigationFluent.TexteActivation(actif), !actif, (s, e) => { if (ActionsProtection.Filtrage(!actif)) Charger(); }));
                outils.Children.Add(barre);
                outils.Children.Add(Briques.Titre(L.En ? "Categories" : "Catégories", 0));
                foreach (var c in VueNavigationFluent.Categories)
                {
                    string cle = c;
                    bool on = VueNavigationFluent.CategorieActive(etat, cle);
                    var b = Outil("", on, (s, e) => { ActionsProtection.FiltrageCategories(VueNavigationFluent.ValeurApres(etat, cle, !on)); Charger(); });
                    b.Content = new TextBlock { Text = VueNavigationFluent.TexteCategorie(cle, on, VueNavigationFluent.SansListeSecurite(etat), etat), TextWrapping = TextWrapping.Wrap };
                    b.HorizontalAlignment = HorizontalAlignment.Stretch; b.HorizontalContentAlignment = HorizontalAlignment.Stretch;
                    b.Margin = new Thickness(0, 0, 0, 6);
                    outils.Children.Add(b);
                }
                // Résolveur d'amont (PR 7.6) : deux choix, jamais le tiers par défaut
                outils.Children.Add(Briques.Titre(L.En ? "Upstream resolver" : "Résolveur d'amont", 0));
                string courant = etat == null || TextesFiltrage.NomTiers(etat.AmontChoisi) == null ? "reseau" : etat.AmontChoisi;
                foreach (var a in new[] { "reseau", "quad9" })
                {
                    string cleA = a;
                    bool choisi = cleA == courant;
                    var b = Outil("", choisi, (s, e) => { if (!choisi && ActionsProtection.FiltrageAmont(cleA)) Charger(); });
                    b.Content = new TextBlock { Text = VueNavigationFluent.TexteChoixAmont(cleA, choisi), TextWrapping = TextWrapping.Wrap };
                    b.HorizontalAlignment = HorizontalAlignment.Stretch; b.HorizontalContentAlignment = HorizontalAlignment.Stretch;
                    b.Margin = new Thickness(0, 0, 0, 6);
                    outils.Children.Add(b);
                }
                outils.Children.Add(new Border { Height = 6 });
            }
            Liste(lignes);
            int i = Math.Min(choisie, Math.Max(0, lignes.Count - 1));
            var pile = Panneau(lignes.Count > 0 ? lignes[i] : null, L.En ? "Select a blocked name, an allowed domain or a list." : "Sélectionnez un nom bloqué, un domaine autorisé ou une liste.");
            if (pile != null && lignes.Count > 0)
            {
                string cle = paires[i].Key, nom = cle.Substring(1);
                if (cle[0] == 'b' && nom.Length > 0)
                {
                    pile.Children.Add(Briques.Titre(L.T("Agir"), 12));
                    pile.Children.Add(new TextBlock { Text = L.En ? "Allows this exact name and its subdomains, not the whole domain of the list rule." : "Autorise ce nom exact et ses sous-domaines, pas tout le domaine de la règle de la liste.", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 6), Foreground = Jetons.Pinceau(Jetons.TexteSecondaire) });
                    pile.Children.Add(Briques.Action(L.En ? "Allow this domain" : "Autoriser ce domaine", true, (s, e) => { ActionsProtection.FiltrageAutoriser(nom); Charger(); }));
                }
                else if (cle[0] == 'a' && nom.Length > 0)
                {
                    pile.Children.Add(Briques.Titre(L.T("Agir"), 12));
                    pile.Children.Add(Briques.Action(L.En ? "Remove the authorization" : "Retirer l'autorisation", false, (s, e) => { ActionsProtection.FiltrageRetirer(nom); Charger(); }));
                }
            }
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
        // « sans effet » (B4 de la relecture de la baseline du 2026-11-20) : posé mais pas appliqué par Defender, à signaler
        // quel que soit le profil, puisque la protection affichée n'existe pas
        public static int Gravite(EtatRegle r) { return r.Etat == "sans effet" || (r.Etat == "non conforme" && r.Profil != "renforcé") ? 1 : 0; }

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

        // Résultat du contrôle, pas l'objet contrôlé : « not found » à côté de « Windows Firewall » se lisait « pare-feu
        // introuvable » quand le service disait le pare-feu actif (« pas_constate » : aucun problème relevé ; constat T-17)
        public static string Etat(ConstatExposition c)
        {
            bool en = L.En;
            return c.Etat == "constate" ? (en ? "issue found" : "constaté") : c.Etat == "non_verifie" ? (en ? "not checked" : "non vérifié") : (en ? "no issue found" : "rien relevé");
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
                // « sans effet » : le réglage est déjà posé, le réappliquer ne changerait rien tant que Defender n'est pas
                // l'antivirus actif ou applique une autre valeur ; on le dit au lieu de proposer le bouton (prérelecture de #217)
                if (choix.Etat == "sans effet") pile.Children.Add(new TextBlock { Text = L.En ? "Already set: reapplying would change nothing while Microsoft Defender does not apply it (another antivirus is active, or Defender applies another value)." : "Déjà posé : le réappliquer ne changerait rien tant que Microsoft Defender ne l'applique pas (autre antivirus actif, ou Defender applique une autre valeur).", TextWrapping = TextWrapping.Wrap, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, 0, 0, 6) });
                else if (choix.Etat != "conforme") pile.Children.Add(Briques.Action(L.En ? "Apply this rule" : "Appliquer cette règle", true, (s, e) => { if (ActionsProtection.Baseline("appliquer", id, null)) Charger(); }));
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
        // Donné : un clic appelle Choisi au lieu de changer la valeur active (choix de la langue, qui ne vaut qu'au prochain
        // lancement : le bouton actif reste la langue affichée, constat T-17)
        public Action<string> Choisi;

        public ChoixFluent(string[] valeurs, string[] libelles)
        {
            this.valeurs = valeurs;
            Margin = new Thickness(0, 0, 12, 0);
            for (int k = 0; k < valeurs.Length; k++)
            {
                string v = valeurs[k];
                var b = new Button { Content = libelles == null ? L.T(v) : libelles[k], Padding = new Thickness(10, 3, 10, 3), Margin = new Thickness(0, 0, 4, 0), Cursor = Cursors.Hand, BorderThickness = new Thickness(1), Foreground = Jetons.Pinceau(Jetons.Texte), Tag = v };
                b.Template = Coquille.ModeleBouton();
                b.Click += (s, e) => { if (Choisi != null) Choisi(v); else Definir(v); };
                Children.Add(b);
            }
            Definir(valeurs[0]);
        }

        // enAttente : valeur enregistrée qui ne vaut qu'au prochain lancement, bordée en gris clair (dite aussi en texte à part)
        public void Definir(string v, string enAttente = null)
        {
            Valeur = Array.IndexOf(valeurs, v) >= 0 ? v : valeurs[0];
            foreach (Button b in Children)
            {
                bool actif = (string)b.Tag == Valeur, attente = !actif && (string)b.Tag == enAttente;
                b.Background = Jetons.Pinceau(actif ? Jetons.Surface : Jetons.Fond);
                b.BorderBrush = Jetons.Pinceau(actif ? Jetons.Accent : attente ? Jetons.TexteSecondaire : Jetons.Separateur);
            }
        }
    }

    // Bandeau d'état d'une section de la page Réglages (T-15) : gravité 2 à traiter (rouge), 1 à surveiller (orange), 0 en
    // ordre (vert), -1 information (accent), -2 neutre (gris) ; titre et détail déjà neutralisés
    public class BandeauReglages
    {
        public int Gravite;
        public string Titre;
        public string Detail;
    }

    // Décisions pures de la page Réglages (constat T-15), testées par tests\rendu-pilote.ps1 : sections, états de la
    // navigation des sections, bandeaux, champs en défaut. Aucune ne décide d'un envoi : les commandes restent celles
    // d'ActionsReglages, construites et validées comme avant
    public static class VueReglagesFluent
    {
        // Navigation des sections, dans cet ordre (clés françaises) ; les premiers réglages sont dans « Langue »
        public static readonly string[] Sections = { "Langue", "Apprentissage", "Remontée des alertes", "Syslog", "API d'export", "Mises à jour", "Comptes et données" };
        static readonly string[] SectionsEn = { "Language", "Learning", "Alert forwarding", "Syslog", "Export API", "Updates", "Accounts and data" };
        public static readonly string[] Icones = { "", "", "", "", "", "", "" };

        public static string Nom(int section) { return section < 0 || section >= Sections.Length ? "" : L.En ? SectionsEn[section] : Sections[section]; }

        static string T(string fr, string en) { return L.En ? en : fr; }

        static bool Date(string s, out DateTime d)
        {
            return DateTime.TryParseExact(s ?? "", "yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out d);
        }

        // Jour de l'apprentissage en cours (1 à total) ; faux s'il est terminé ou si ses dates sont illisibles
        public static bool JourApprentissage(EtatApprentissage app, DateTime maintenant, out int jour, out int total)
        {
            jour = 0; total = 0;
            DateTime debut, fin;
            if (app == null || !Date(app.Debut, out debut) || !Date(app.Fin, out fin) || fin <= debut || maintenant >= fin) return false;
            total = Math.Max(1, (int)Math.Round((fin - debut).TotalDays));
            jour = Math.Min(total, Math.Max(1, (int)Math.Floor((maintenant - debut).TotalDays) + 1));
            return true;
        }

        // Canaux de remontée activés dans config.json (pas les secrets enregistrés : notifications.json le dit à part)
        public static List<string> Canaux(ConfigNotifications n)
        {
            var l = new List<string>();
            if (n == null) return l;
            if (n.Ntfy) l.Add("ntfy");
            if (n.Teams) l.Add("Teams");
            if (n.Smtp) l.Add(T("e-mail", "e-mail"));
            return l;
        }

        // Gravité de l'état de mise à jour, d'après le code publié par le service dans maj.json (maj.rs, code_controle,
        // #294) : contrôle en échec depuis plus de 24 h, manifeste plus ancien (gel possible) ou code inconnu (service plus
        // récent) : à traiter ; dernier contrôle en échec, essai rapproché : à surveiller ; lu : en ordre ; pas encore : neutre
        public static int GraviteMaj(EtatMaj m)
        {
            if (m == null) return -2;
            string c = m.Controle;
            if (string.IsNullOrEmpty(c)) return 0;
            if (c == "EchecRecent") return 1;
            return 2;
        }

        public static string EtatMajCourt(EtatMaj m)
        {
            if (m == null) return T("pas vérifiée", "not checked");
            string c = m.Controle;
            if (string.IsNullOrEmpty(c)) return T("contrôlée", "checked");
            if (c == "ManifesteAncien") return T("à vérifier", "to check");
            return T("en échec", "failed");
        }

        // État court affiché à droite de chaque section de la navigation ; configuration illisible : « ? » à surveiller,
        // jamais une valeur par défaut présentée comme réglée
        public static PointEtat EtatSection(int section, Config c, bool illisible, EtatApprentissage app, EtatMaj em, EtatRemontee r, List<Lecteur> lecteurs, DateTime maintenant)
        {
            var x = new PointEtat { Texte = "", Gravite = 0 };
            int jour, total;
            switch (section)
            {
                case 0: x = EtatLangue(L.Reglage, null); break;
                case 1:
                    if (app == null) x.Texte = "";
                    else if (JourApprentissage(app, maintenant, out jour, out total)) x.Texte = string.Format(T("Jour {0}/{1}", "Day {0}/{1}"), jour, total);
                    else x.Texte = T("terminé", "finished");
                    break;
                case 2:
                    {
                        if (illisible || c == null) { x.Texte = "?"; x.Gravite = 1; break; }
                        var canaux = Canaux(c.Notifications);
                        if (canaux.Count == 0) { x.Texte = T("Aucun", "None"); x.Gravite = 1; }
                        else if (r != null && !string.IsNullOrEmpty(r.EchecDepuis)) { x.Texte = T("en échec", "failed"); x.Gravite = 2; }
                        else x.Texte = canaux.Count == 1 ? canaux[0] : string.Format(T("{0} canaux", "{0} channels"), canaux.Count);
                        break;
                    }
                case 3:
                    if (illisible || c == null) { x.Texte = "?"; x.Gravite = 1; }
                    else x.Texte = c.Syslog != null && c.Syslog.Actif ? T("Activé", "On") : T("Désactivé", "Off");
                    break;
                case 4:
                    if (illisible || c == null) { x.Texte = "?"; x.Gravite = 1; }
                    else x.Texte = c.Api != null && c.Api.Actif ? T("Activée", "On") : T("Désactivée", "Off");
                    break;
                case 5: x.Texte = EtatMajCourt(em); x.Gravite = Math.Max(0, GraviteMaj(em)); break;
                case 6: x.Texte = string.Format(T("{0} lecteur(s)", "{0} reader(s)"), (lecteurs ?? new List<Lecteur>()).Count(l => l != null)); break;
            }
            return x;
        }

        // État « Langue » de la navigation : le réglage en vigueur (automatique, français, anglais), ou « en attente » si un
        // autre choix est enregistré pour le prochain lancement (prérelecture de #305, N2)
        public static PointEtat EtatLangue(string reglage, string enregistre)
        {
            if (enregistre != null && enregistre != reglage) return new PointEtat { Texte = T("en attente", "pending"), Gravite = 0 };
            return new PointEtat { Texte = reglage == "fr" ? "Français" : reglage == "en" ? "English" : T("Automatique", "Automatic"), Gravite = 0 };
        }

        // Bandeau de la remontée : aucun canal (personne n'est prévenu), canal sans adresse enregistrée, envois en échec, ou
        // canaux activés avec le compte des envois ; textes du service et d'un serveur neutralisés
        public static BandeauReglages BandeauRemontee(ConfigNotifications n, bool illisible, EtatRemontee r)
        {
            Func<string, string> v = Canal.Visible;
            if (illisible || n == null)
                return new BandeauReglages { Gravite = 1, Titre = T("Réglages de remontée inconnus", "Alert forwarding settings unknown"), Detail = ActionsReglages.ConfigIllisible() };
            var canaux = Canaux(n);
            if (canaux.Count == 0)
                return new BandeauReglages { Gravite = 1, Titre = T("Aucun canal activé", "No channel turned on"), Detail = T("Personne n'est prévenu des alertes : activez ntfy, Teams ou l'e-mail ci-dessous.", "Nobody is notified of alerts: turn on ntfy, Teams or e-mail below.") };
            string envois = r == null ? T("notifications.json absent ou illisible : envois inconnus.", "notifications.json missing or unreadable: sending unknown.")
                : string.Format(T("{0} message(s) envoyé(s)", "{0} message(s) sent"), r.Envoyes)
                    + (string.IsNullOrEmpty(r.DernierEnvoi) ? "" : T(", dernier le ", ", last on ") + v(r.DernierEnvoi))
                    + " · " + (string.IsNullOrEmpty(r.DerniereErreur) ? T("aucune erreur signalée", "no error reported") : T("dernière erreur : ", "last error: ") + v(r.DerniereErreur));
            if (r != null && !string.IsNullOrEmpty(r.EchecDepuis))
                return new BandeauReglages { Gravite = 2, Titre = string.Format(T("Remontée en échec depuis le {0}", "Alert forwarding failing since {0}"), v(r.EchecDepuis)), Detail = envois };
            var sansAdresse = new List<string>();
            if (r != null && n.Ntfy && !r.NtfyConfigure) sansAdresse.Add("ntfy");
            if (r != null && n.Teams && !r.TeamsConfigure) sansAdresse.Add("Teams");
            if (sansAdresse.Count > 0)
                return new BandeauReglages { Gravite = 1, Titre = string.Format(T("Activé sans adresse enregistrée : {0}", "On without a saved address: {0}"), string.Join(", ", sansAdresse)), Detail = envois };
            return new BandeauReglages { Gravite = 0, Titre = string.Format(T("{0} canal(aux) activé(s) : {1}, à partir du niveau {2}", "{0} channel(s) on: {1}, from level {2}"), canaux.Count, string.Join(", ", canaux), v(L.T(n.NiveauMin ?? ""))), Detail = envois };
        }

        public static BandeauReglages BandeauApprentissage(EtatApprentissage app, DateTime maintenant, out double avancement)
        {
            avancement = -1;
            if (app == null)
                return new BandeauReglages { Gravite = -2, Titre = T("Apprentissage : état inconnu", "Learning: state unknown"), Detail = T("apprentissage.json absent ou illisible.", "apprentissage.json missing or unreadable.") };
            int jour, total;
            if (JourApprentissage(app, maintenant, out jour, out total))
            {
                avancement = (double)jour / total;
                return new BandeauReglages { Gravite = -1, Titre = string.Format(T("Apprentissage : jour {0} sur {1}", "Learning: day {0} of {1}"), jour, total), Detail = ActionsReglages.TexteApprentissage(app) };
            }
            return new BandeauReglages { Gravite = 0, Titre = T("Apprentissage terminé : seul un comportement nouveau alerte", "Learning finished: only new behaviour raises an alert"), Detail = ActionsReglages.TexteApprentissage(app) };
        }

        // Bandeau des mises à jour : état de la ligne « Mise à jour » de la page Santé (même code, même texte), détail
        // d'aujourd'hui (version installée, clé épinglée, date et statut du service)
        public static BandeauReglages BandeauMaj(EtatMaj m)
        {
            var ligne = VueSante.LigneMaj(m);
            return new BandeauReglages
            {
                Gravite = GraviteMaj(m),
                Titre = L.T("Mise à jour") + " : " + ligne.Etat,
                Detail = ActionsReglages.TexteMaj(m) + (m != null && !string.IsNullOrEmpty(m.Controle) && !string.IsNullOrEmpty(ligne.Detail) ? "\n" + ligne.Detail : "")
            };
        }

        // Exceptions apprises : en vigueur (apprentissage.json) et d'une version précédente (compteur d'etat.json)
        public static string TexteExceptions(EtatApprentissage app, Etat e)
        {
            int n = app == null || app.Exceptions == null ? 0 : app.Exceptions.Count;
            int p = e == null ? 0 : e.ExceptionsPerimees;
            return (app == null ? T("Exceptions en vigueur : inconnues (apprentissage.json illisible)", "Exceptions in force: unknown (apprentissage.json unreadable)") : string.Format(T("{0} exception(s) en vigueur", "{0} exception(s) in force"), n))
                + (p > 0 ? " · " + string.Format(T("{0} d'une version précédente, qui ne s'appliquent plus", "{0} from a previous version, no longer applied"), p) : "");
        }

        // Champs en défaut, par la validation même qui décide de l'envoi (ActionsReglages), l'autre champ mis à une valeur
        // valide : [port syslog, port de l'API] et [messages par heure, port SMTP]
        public static bool[] PortsEnDefaut(string syslog, string api)
        {
            int a, b;
            return new[] { ActionsReglages.PortsInvalides(syslog, "8642", out a, out b) != null, ActionsReglages.PortsInvalides("514", api, out a, out b) != null };
        }

        public static bool[] NotificationsEnDefaut(string maxHeure, string port)
        {
            int a, b;
            return new[] { ActionsReglages.NotificationsInvalides(maxHeure, "465", out a, out b) != null, ActionsReglages.NotificationsInvalides("10", port, out a, out b) != null };
        }

        // Adresse du manifeste : vide ou égale à l'adresse par défaut (le service applique alors l'adresse par défaut, S68b-02)
        public static bool ManifesteParDefaut(string url)
        {
            string u = (url ?? "").Trim();
            return u.Length == 0 || u == new ConfigMaj().Url;
        }
    }

    // Page Réglages en WPF (U6c, refaite au constat T-15 sur les maquettes validées le 2026-11-23) : navigation des sections
    // à gauche, une section affichée à la fois, une carte par bloc. Mêmes réglages, mêmes contrôles et mêmes commandes que
    // la page d'aujourd'hui (ActionsReglages) : aucune commande ni aucun réglage ajouté ou retiré ; lue à l'ouverture et
    // après chaque action, jamais pendant la saisie ; config.json illisible : dit, et rien n'est enregistré ; secrets jamais
    // relus ni réaffichés (le champ vide dit seulement « enregistré » ou « non renseigné », d'après notifications.json)
    class PageReglagesFluent : Grid
    {
        readonly StackPanel contenu = new StackPanel { MaxWidth = 820, HorizontalAlignment = HorizontalAlignment.Left };
        readonly TextBlock titreSection = new TextBlock { FontSize = 20, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 2, 0, 14) };
        readonly StackPanel[] panneaux = new StackPanel[VueReglagesFluent.Sections.Length];
        readonly Button[] entrees = new Button[VueReglagesFluent.Sections.Length];
        readonly TextBlock[] etatsEntrees = new TextBlock[VueReglagesFluent.Sections.Length];
        int section;
        readonly TextBlock config = Texte(true);
        readonly Border configBandeau;
        // Trois valeurs (constat T-17) : automatique (langue de Windows), français, anglais ; bouton actif = réglage en vigueur
        readonly ChoixFluent langue = new ChoixFluent(L.Reglages, L.Reglages.Select(r => L.Libelle(r, System.Globalization.CultureInfo.CurrentUICulture)).ToArray());
        readonly TextBlock langueEtat = Texte(true);
        readonly CheckBox syslog = Interrupteur("Syslog / SIEM"), api = Interrupteur(VueReglagesFluent.Nom(4)), majAuto = Interrupteur(T("Installation automatique", "Automatic installation")),
            ntfy = Interrupteur("ntfy"), teams = Interrupteur("Microsoft Teams"), smtp = Interrupteur("E-mail"),
            reseau = Case("Accessible depuis le réseau local (sinon cet ordinateur seulement)");
        readonly TextBox hote = Saisie(), portSyslog = Saisie(), portApi = Saisie(), adresses = Saisie(), majUrl = Saisie(), maxHeure = Saisie(),
            smtpServeur = Saisie(), smtpPort = Saisie(), smtpUtilisateur = Saisie(), expediteur = Saisie(), destinataires = Saisie(), compte = Saisie();
        // Adresse ntfy masquée comme les autres secrets (audit de #147, S147-02)
        readonly PasswordBox ntfyUrl = Secret(360), ntfyJeton = Secret(220), teamsUrl = Secret(520), smtpMdp = Secret(160);
        readonly TextBlock indiceNtfyUrl = Indice(), indiceNtfyJeton = Indice(), indiceTeamsUrl = Indice(), indiceSmtpMdp = Indice();
        readonly ChoixFluent protocole = new ChoixFluent(ActionsReglages.Protocoles, null), format = new ChoixFluent(ActionsReglages.Formats, null), niveau = new ChoixFluent(ActionsReglages.Niveaux, null),
            niveauNotif = new ChoixFluent(ActionsReglages.Niveaux, null), securite = new ChoixFluent(ActionsReglages.Securites, null);
        // Erreurs de saisie, sous le champ ; message de la validation d'aujourd'hui sous les boutons de la carte
        readonly TextBlock errPortSyslog = Erreur(), errPortApi = Erreur(), errMaxHeure = Erreur(), errSmtpPort = Erreur(), errCompte = Erreur(),
            errSyslog = Erreur(), errApi = Erreur(), errNotif = Erreur();
        readonly TextBlock bandeauRemonteeTitre = new TextBlock(), bandeauRemonteeDetail = new TextBlock(), bandeauAppTitre = new TextBlock(), bandeauAppDetail = new TextBlock(),
            bandeauMajTitre = new TextBlock(), bandeauMajDetail = new TextBlock();
        readonly Border bandeauRemontee, bandeauApp, bandeauMaj;
        readonly Grid avancementApp = new Grid { Height = 6, Width = 420, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 12, 0, 0) };
        readonly TextBlock notifEtat = Texte(true), exceptions = new TextBlock { TextWrapping = TextWrapping.Wrap }, aideManifeste = Texte(true);
        readonly WrapPanel lecteurs = new WrapPanel();
        readonly Grid champsSmtp;
        int enCours, chargement;
        bool rempli;            // aucune action avant la première lecture : des champs vides ne partent jamais comme réglages
        public Action Revoir;   // ouvre « Premiers réglages » (donné par la coquille)

        public PageReglagesFluent()
        {
            ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            ColumnDefinitions.Add(new ColumnDefinition());
            var nav = new StackPanel { Width = 256, Margin = new Thickness(0, 0, 24, 0) };
            for (int i = 0; i < panneaux.Length; i++) { nav.Children.Add(Entree(i)); panneaux[i] = new StackPanel(); }
            Children.Add(nav);
            var defile = new ScrollViewer { Content = contenu, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            Grid.SetColumn(defile, 1);
            Children.Add(defile);
            contenu.Children.Add(titreSection);
            configBandeau = Bandeau(new TextBlock { Text = T("Configuration illisible", "Configuration unreadable") }, config, null);
            Teinter(configBandeau, 1);
            configBandeau.Visibility = Visibility.Collapsed;
            contenu.Children.Add(configBandeau);
            foreach (var p in panneaux) contenu.Children.Add(p);

            // ---------------- Langue (choix écrit pour cet utilisateur, sans commande ni élévation, constat T-17) et premiers réglages
            panneaux[0].Children.Add(Carte(L.T("Langue de l'interface"), T("S'applique au prochain lancement de l'interface ; propre à votre compte, sans droits d'administrateur.", "Applies the next time the interface starts; for your account only, without administrator rights."), null,
                Pile(langue, langueEtat), null));
            langue.Choisi = v => { ActionsReglages.ChoisirLangue(v); AfficherLangue(); };
            AfficherLangue();
            // Premiers réglages (U7a) : rejouables à tout moment, sans commande
            var revoir = Briques.Action(L.En ? "See the first-run setup again" : "Revoir les premiers réglages", false, (s, e) => { if (Revoir != null) Revoir(); });
            revoir.HorizontalAlignment = HorizontalAlignment.Left; revoir.Margin = new Thickness(0, 4, 8, 4);
            panneaux[0].Children.Add(Carte(T("Premiers réglages", "First-run setup"), T("Rejoue les étapes des premiers réglages ; ne change rien par lui-même.", "Replays the first-run steps; changes nothing by itself."), null, null, new UIElement[] { revoir }));

            // ---------------- Apprentissage et exceptions
            avancementApp.ColumnDefinitions.Add(new ColumnDefinition()); avancementApp.ColumnDefinitions.Add(new ColumnDefinition());
            var plein = new Border { Background = Jetons.Pinceau(Jetons.Accent), CornerRadius = new CornerRadius(3, 0, 0, 3) };
            var vide = new Border { Background = Jetons.Pinceau(Jetons.Surface), CornerRadius = new CornerRadius(0, 3, 3, 0) };
            Grid.SetColumn(vide, 1); avancementApp.Children.Add(plein); avancementApp.Children.Add(vide);
            bandeauApp = Bandeau(bandeauAppTitre, bandeauAppDetail, avancementApp);
            panneaux[1].Children.Add(bandeauApp);
            panneaux[1].Children.Add(Carte(T("Mode apprentissage", "Learning mode"), L.T("Les premiers jours, les alertes non critiques sont notées en information et leur comportement est mémorisé (logiciel de caisse, outils du prestataire, scripts…). Ensuite, seul un comportement nouveau alerte. Les alertes critiques ne sont jamais adoucies. Clic droit sur une alerte : « Ne plus alerter pour ce comportement »."), null, null,
                new UIElement[] { Bouton("Terminer l'apprentissage", true, () => ActionsReglages.Apprentissage("terminer")) },
                new UIElement[] { Destructif(L.T("Recommencer (7 jours)"), () => ActionsReglages.Apprentissage("recommencer")) },
                T("Recommencer oublie les comportements appris et réapprend pendant 7 jours, y compris ce que ferait un programme malveillant actif à ce moment : seulement sur un poste que l'on sait sain.",
                  "Restarting forgets learned behaviours and learns again for 7 days, including what a malicious program active at that time would do: only on a computer known to be clean.")));
            // Exceptions d'une version précédente seulement (ligne « Exceptions » de la page Santé ; prérelecture de #255, R1)
            panneaux[1].Children.Add(Carte(T("Exceptions apprises", "Learned exceptions"), T("Clic droit sur une alerte, « Ne plus alerter pour ce comportement », pour en ajouter une.", "Right-click an alert, \"No longer alert for this behaviour\", to add one."), null,
                exceptions, null,
                new UIElement[] { Destructif(T("Effacer les exceptions d'une version précédente", "Clear exceptions from a previous version"), () => ActionsReglages.Apprentissage("oublier-perimees")),
                    Destructif(L.T("Supprimer les exceptions"), () => ActionsReglages.Apprentissage("oublier")) },
                T("Irréversible. « Supprimer les exceptions » retire aussi celles d'une version précédente.", "Cannot be undone. \"Delete exceptions\" also removes those from a previous version.")));

            // ---------------- Remontée des alertes
            bandeauRemontee = Bandeau(bandeauRemonteeTitre, bandeauRemonteeDetail, null);
            panneaux[2].Children.Add(bandeauRemontee);
            panneaux[2].Children.Add(Carte(T("Règles", "Rules"), T("Envoie les alertes de ce poste à la personne qui s'en occupe, avec le « quoi faire » ; les alertes d'un quart de minute sont regroupées en un seul message, et un plafond par heure évite l'inondation.", "Sends this computer's alerts to the person in charge, with what to do; alerts within 15 seconds are grouped into one message, and an hourly cap prevents flooding."), null,
                Grille(Champ(L.T("Niveau minimal"), niveauNotif), Champ(L.T("Messages par heure au plus"), maxHeure, errMaxHeure, T("1 à 1000.", "1 to 1000."))), null));
            panneaux[2].Children.Add(CarteCanal(ntfy, T("Application mobile ou de bureau, serveur public ou auto-hébergé.", "Mobile or desktop app, public or self-hosted server."),
                Grille(Champ(L.T("Adresse du sujet"), Masque(ntfyUrl, indiceNtfyUrl)), Champ(L.T("Jeton (facultatif)"), Masque(ntfyJeton, indiceNtfyJeton)),
                    Large(Note(L.T("Conseil : un serveur ntfy auto-hébergé plutôt que ntfy.sh, que des malwares utilisent aussi pour faire sortir des données (il reste joignable en mode panique).")), Jetons.Attention))));
            panneaux[2].Children.Add(CarteCanal(teams, T("Webhook d'un flux de travail « publier dans un canal ».", "\"Post to a channel\" workflow webhook."),
                Grille(Large(Champ(L.T("Adresse du webhook"), Masque(teamsUrl, indiceTeamsUrl))))));
            champsSmtp = Grille(Champ(L.T("Serveur"), smtpServeur), Champ(L.T("Port"), smtpPort, errSmtpPort, T("1 à 65535.", "1 to 65535.")),
                    Champ(L.T("Sécurité"), securite), Champ(L.T("Utilisateur"), smtpUtilisateur),
                    Champ(L.T("Mot de passe"), Masque(smtpMdp, indiceSmtpMdp)), Champ(L.T("Expéditeur"), expediteur),
                    Large(Champ(L.T("Destinataires"), destinataires)));
            panneaux[2].Children.Add(CarteCanal(smtp, T("SMTP chiffré.", "Encrypted SMTP."), champsSmtp));
            panneaux[2].Children.Add(Carte(T("Enregistrer et tester", "Save and test"), L.T("Les adresses ntfy et Teams, le jeton et le mot de passe sont gardés à part, lisibles par les administrateurs seulement : laissez le champ vide pour conserver la valeur enregistrée, tapez « - » pour l'effacer."), null,
                Pile(notifEtat), new UIElement[] { BoutonValide("Enregistrer les notifications", true, () => Notifications("notifications")), BoutonValide("Envoyer un message de test", false, () => Notifications("testerNotifications")) },
                null, null, errNotif));

            // ---------------- Syslog ; « Enregistrer » envoie le syslog et l'API ensemble (une seule commande « reglages »)
            var ensemble = T("« Enregistrer » envoie ensemble le syslog et l'API d'export, avec la langue gardée dans config.json : une seule confirmation, qui montre les trois.",
                "\"Save\" sends syslog and the export API together, with the language kept in config.json: one confirmation, which shows all three.");
            panneaux[3].Children.Add(Carte("Syslog / SIEM", L.T("JSON : en-tête RFC 5424 et détail en JSON. CEF : reconnu par la plupart des SIEM (Splunk, QRadar, Sentinel, Wazuh, Graylog…)."), syslog,
                Grille(Champ(L.T("Serveur"), hote), Champ(L.T("Port"), portSyslog, errPortSyslog, T("1 à 65535.", "1 to 65535.")),
                    Champ(L.T("Protocole"), protocole), Champ(L.T("Format"), format), Champ(L.T("Niveau minimal"), niveau)),
                new UIElement[] { BoutonValide("Enregistrer", true, Enregistrer), BoutonValide("Tester l'envoi", false, () => { var x = Saisis(); if (x == null) return false; ActionsReglages.TesterSyslog(x.Item1); return true; }) },
                null, null, Pile(errSyslog, Note(ensemble))));

            // ---------------- API d'export
            var routes = new WrapPanel { Margin = new Thickness(0, 0, 0, 10) };
            foreach (var route in new[] { "/api/v1/alertes", "/connexions", "/exposition", "/baseline", "/regles-parefeu", "/blocages", "/journal" })
                routes.Children.Add(new TextBlock { Text = route, FontFamily = Briques.Chasse, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, 0, 14, 2) });
            panneaux[4].Children.Add(Carte(VueReglagesFluent.Nom(4), T("HTTP en lecture seule ; chaque requête doit porter l'en-tête « Authorization: Bearer <jeton> ».", "Read-only HTTP; every request must carry the \"Authorization: Bearer <token>\" header."), api,
                Grille(Champ(L.T("Port"), portApi, errPortApi, T("1024 à 65535.", "1024 to 65535.")), Large(reseau), Large(Champ(L.T("Adresses autorisées (SIEM)"), adresses)), Large(routes)),
                new UIElement[] { BoutonValide("Enregistrer", true, Enregistrer) }, null, null, Pile(errApi, Note(ensemble))));
            panneaux[4].Children.Add(Carte(T("Jeton d'accès", "Access token"), T("Les outils qui lisent l'API utilisent ce jeton.", "Tools that read the API use this token."), null, null,
                new UIElement[] { Bouton("Afficher le jeton", false, ActionsReglages.AfficherJeton) },
                new UIElement[] { Destructif(L.T("Nouveau jeton"), () => ActionsReglages.NouveauJeton()) },
                T("Remplacer le jeton coupe les outils qui utilisent l'ancien.", "Replacing the token breaks the tools that use the old one.")));

            // ---------------- Mises à jour
            bandeauMaj = Bandeau(bandeauMajTitre, bandeauMajDetail, null);
            panneaux[5].Children.Add(bandeauMaj);
            majUrl.TextChanged += (s, e) => AideManifeste();
            panneaux[5].Children.Add(Carte(T("Installation automatique", "Automatic installation"), L.T("Installer automatiquement une version signée par la clé épinglée dans deR4Tizer (révocation vérifiée)"), majAuto,
                Grille(Large(Champ(L.T("Manifeste"), majUrl, null, null, aideManifeste))),
                new UIElement[] { Bouton("Enregistrer", true, () => ActionsReglages.MajConfig(majAuto.IsChecked == true, majUrl.Text)), Bouton("Rechercher maintenant", false, ActionsReglages.MajVerifier) }));

            // ---------------- Comptes et données
            panneaux[6].Children.Add(Carte(T("Accès aux données", "Data access"), L.T("Les événements, sessions, alertes et appareils du réseau ne sont lisibles que par SYSTEM, les administrateurs et ces comptes :").TrimEnd(' ', ':') + ".", null,
                Pile(new TextBlock { Text = T("Lecteurs en plus de SYSTEM et des administrateurs", "Readers besides SYSTEM and administrators"), FontSize = 13, Margin = new Thickness(0, 0, 0, 8) }, lecteurs,
                    Couleur(Note(L.T("Ces comptes peuvent lire l'historique de tous les comptes (alertes, événements, lignes de commande masquées).")), Jetons.Attention),
                    Champ(L.T("Nom du compte (par exemple : PC-ACCUEIL\\marie)"), compte, errCompte)),
                new UIElement[] { BoutonValide("Autoriser", true, Autoriser) }));
            panneaux[6].Children.Add(Carte(T("Export des journaux", "Log export"), T("Alertes en JSON ou en CSV (sans formule pour le tableur), journal du service en texte.", "Alerts as JSON or CSV (no spreadsheet formulas), service log as text."), null, null,
                new UIElement[] { Bouton("Exporter les alertes…", true, ExporterAlertes), Bouton("Exporter le journal du service…", false, ExporterJournal) }));

            Afficher(0);
            Loaded += (s, e) => Charger();
        }

        // Une section affichée à la fois ; l'entrée ouverte est marquée comme dans la navigation de la coquille
        internal void Afficher(int i)
        {
            if (i < 0 || i >= panneaux.Length) return;
            section = i;
            for (int k = 0; k < panneaux.Length; k++)
            {
                panneaux[k].Visibility = k == i ? Visibility.Visible : Visibility.Collapsed;
                entrees[k].Tag = k == i ? "ouverte" : null;
            }
            titreSection.Text = VueReglagesFluent.Nom(i);
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
                    var r = Commun.Lire<EtatRemontee>("notifications.json");
                    var lect = Commun.Lire<List<Lecteur>>("lecteurs.json");
                    var etat = Commun.Lire<Etat>("etat.json");
                    Dispatcher.BeginInvoke((Action)(() => { if (numero == chargement) Remplir(c, illisible, app, em, en, r, lect, etat); }));
                }
                finally { System.Threading.Interlocked.Exchange(ref enCours, 0); }
            });
        }

        void Remplir(Config c, bool illisible, EtatApprentissage app, EtatMaj em, EtatNotifications en, EtatRemontee r, List<Lecteur> lect, Etat etat)
        {
            config.Text = illisible ? ActionsReglages.ConfigIllisible() : "";
            configBandeau.Visibility = illisible ? Visibility.Visible : Visibility.Collapsed;
            var x = c ?? new Config();
            var sl = x.Syslog ?? new ConfigSyslog(); var a = x.Api ?? new ConfigApi(); var n = x.Notifications ?? new ConfigNotifications(); var m = x.Maj ?? new ConfigMaj();
            AfficherLangue();
            syslog.IsChecked = sl.Actif; hote.Text = sl.Hote ?? ""; portSyslog.Text = sl.Port.ToString(); protocole.Definir(sl.Protocole); format.Definir(sl.Format); niveau.Definir(sl.NiveauMin);
            api.IsChecked = a.Actif; portApi.Text = a.Port.ToString(); reseau.IsChecked = a.Reseau; adresses.Text = a.Adresses ?? "";
            majAuto.IsChecked = m.Auto; majUrl.Text = m.Url ?? "";
            niveauNotif.Definir(n.NiveauMin); maxHeure.Text = n.MaxParHeure.ToString(); ntfy.IsChecked = n.Ntfy; teams.IsChecked = n.Teams; smtp.IsChecked = n.Smtp;
            smtpServeur.Text = n.SmtpServeur ?? ""; smtpPort.Text = n.SmtpPort.ToString(); securite.Definir(n.SmtpSecurite); smtpUtilisateur.Text = n.SmtpUtilisateur ?? ""; expediteur.Text = n.Expediteur ?? ""; destinataires.Text = n.Destinataires ?? "";
            // Secrets jamais relus ni réaffichés : vide garde la valeur enregistrée ; le champ vide dit seulement s'il y en a une
            ntfyUrl.Password = ""; ntfyJeton.Password = ""; teamsUrl.Password = ""; smtpMdp.Password = "";
            indiceNtfyUrl.Text = Enregistre(en == null ? (bool?)null : en.NtfyConfigure);
            indiceTeamsUrl.Text = Enregistre(en == null ? (bool?)null : en.TeamsConfigure);
            indiceSmtpMdp.Text = Enregistre(en == null ? (bool?)null : en.SmtpMotDePasse);
            // Le service ne dit pas si un jeton ntfy est enregistré : rien n'est affirmé
            indiceNtfyJeton.Text = T("Jamais réaffiché", "Never shown again");
            foreach (var e in new[] { errPortSyslog, errPortApi, errMaxHeure, errSmtpPort, errCompte, errSyslog, errApi, errNotif }) DireErreur(e, null);
            notifEtat.Text = ActionsReglages.TexteNotifications(en);
            exceptions.Text = VueReglagesFluent.TexteExceptions(app, etat);
            lecteurs.Children.Clear();
            var l = (lect ?? new List<Lecteur>()).Where(y => y != null).ToList();
            foreach (var y in l) lecteurs.Children.Add(Pastille(Canal.Visible(ActionsReglages.NomLecteur(y))));
            if (l.Count == 0) lecteurs.Children.Add(Pastille(T("aucun", "none")));
            AideManifeste();
            var maintenant = DateTime.Now;
            var br = VueReglagesFluent.BandeauRemontee(illisible ? null : n, illisible, r);
            bandeauRemonteeTitre.Text = br.Titre; bandeauRemonteeDetail.Text = br.Detail; Teinter(bandeauRemontee, br.Gravite);
            double av;
            var ba = VueReglagesFluent.BandeauApprentissage(app, maintenant, out av);
            bandeauAppTitre.Text = ba.Titre; bandeauAppDetail.Text = ba.Detail; Teinter(bandeauApp, ba.Gravite);
            avancementApp.Visibility = av < 0 ? Visibility.Collapsed : Visibility.Visible;
            if (av >= 0) { avancementApp.ColumnDefinitions[0].Width = new GridLength(av, GridUnitType.Star); avancementApp.ColumnDefinitions[1].Width = new GridLength(1 - av, GridUnitType.Star); }
            var bm = VueReglagesFluent.BandeauMaj(em);
            bandeauMajTitre.Text = bm.Titre; bandeauMajDetail.Text = bm.Detail; Teinter(bandeauMaj, bm.Gravite);
            for (int i = 1; i < etatsEntrees.Length; i++)
            {
                var p = VueReglagesFluent.EtatSection(i, illisible ? null : x, illisible, app, em, r, lect, maintenant);
                etatsEntrees[i].Text = p.Texte;
                etatsEntrees[i].Foreground = Jetons.Pinceau(p.Gravite == 2 ? Jetons.Danger : p.Gravite == 1 ? Jetons.Attention : Jetons.TexteSecondaire);
                System.Windows.Automation.AutomationProperties.SetName(entrees[i], VueReglagesFluent.Nom(i) + (string.IsNullOrEmpty(p.Texte) ? "" : ", " + p.Texte));
            }
            rempli = true;
        }

        static string T(string fr, string en) { return L.En ? en : fr; }

        static string Enregistre(bool? b) { return b == null ? T("État inconnu", "Unknown") : b.Value ? T("Enregistré", "Saved") : T("Non renseigné", "Not set"); }

        void AideManifeste()
        {
            aideManifeste.Text = VueReglagesFluent.ManifesteParDefaut(majUrl.Text) ? T("Adresse par défaut.", "Default address.")
                : T("Adresse modifiée : ce n'est pas l'adresse par défaut du projet.", "Modified address: not the project's default address.");
        }

        // Bouton actif = réglage en vigueur dans ce processus, jamais la valeur par défaut de config.json (constat T-13)
        void AfficherLangue()
        {
            langue.Definir(L.Reglage, ActionsReglages.LangueEnregistree());
            langueEtat.Text = ActionsReglages.TexteLangue();
            var p = VueReglagesFluent.EtatLangue(L.Reglage, ActionsReglages.LangueEnregistree());
            etatsEntrees[0].Text = p.Texte;
            System.Windows.Automation.AutomationProperties.SetName(entrees[0], VueReglagesFluent.Nom(0) + ", " + p.Texte);
        }

        static void DireErreur(TextBlock t, string texte)
        {
            t.Text = texte ?? "";
            t.Visibility = string.IsNullOrEmpty(texte) ? Visibility.Collapsed : Visibility.Visible;
        }

        // Syslog et API saisis, ou null si un port est invalide (même validation qu'avant, ActionsReglages.PortsInvalides) :
        // erreur dite sous le champ, et sous les boutons des deux cartes, puisque « Enregistrer » envoie les deux
        Tuple<ConfigSyslog, ConfigApi> Saisis()
        {
            int ps, pa;
            string erreur = ActionsReglages.PortsInvalides(portSyslog.Text, portApi.Text, out ps, out pa);
            var defaut = VueReglagesFluent.PortsEnDefaut(portSyslog.Text, portApi.Text);
            DireErreur(errPortSyslog, erreur != null && defaut[0] ? T("Port invalide.", "Invalid port.") : null);
            DireErreur(errPortApi, erreur != null && defaut[1] ? T("Port invalide.", "Invalid port.") : null);
            DireErreur(errSyslog, erreur == null ? null : erreur + (defaut[1] ? " " + T("Champ en défaut dans la section « API d'export ».", "Field in error in the \"Export API\" section.") : ""));
            DireErreur(errApi, erreur == null ? null : erreur + (defaut[0] ? " " + T("Champ en défaut dans la section « Syslog ».", "Field in error in the \"Syslog\" section.") : ""));
            if (erreur != null) return null;
            return Tuple.Create(new ConfigSyslog { Actif = syslog.IsChecked == true, Hote = hote.Text.Trim(), Port = ps, Protocole = protocole.Valeur, Format = format.Valeur, NiveauMin = niveau.Valeur },
                new ConfigApi { Actif = api.IsChecked == true, Port = pa, Reseau = reseau.IsChecked == true, Adresses = adresses.Text.Trim() });
        }

        // config.json relu au moment d'enregistrer : illisible, rien n'est écrit (S139-02 étendu)
        bool Enregistrer()
        {
            var s = Saisis();
            if (s == null) return false;
            bool illisible;
            var lue = ActionsProtection.LireConfig(out illisible);
            return ActionsReglages.Enregistrer(ActionsReglages.Composer(illisible ? null : lue, s.Item1, s.Item2));
        }

        // Réglages de remontée saisis, ou null si un nombre est invalide (même validation qu'avant,
        // ActionsReglages.NotificationsInvalides) : erreur sous le champ et sous les boutons
        ConfigNotifications SaisieNotifications()
        {
            int max, port;
            string erreur = ActionsReglages.NotificationsInvalides(maxHeure.Text, smtpPort.Text, out max, out port);
            var defaut = VueReglagesFluent.NotificationsEnDefaut(maxHeure.Text, smtpPort.Text);
            DireErreur(errMaxHeure, erreur != null && defaut[0] ? T("Nombre invalide.", "Invalid number.") : null);
            DireErreur(errSmtpPort, erreur != null && defaut[1] ? T("Port invalide.", "Invalid port.") : null);
            // Canal e-mail éteint : son port reste validé comme avant ; champs dépliés pour le corriger (prérelecture de #305, N5)
            bool deplier = erreur != null && defaut[1] && smtp.IsChecked != true;
            if (deplier) champsSmtp.Visibility = Visibility.Visible;
            DireErreur(errNotif, erreur == null ? null : erreur + (deplier ? " " + T("Port SMTP : carte « E-mail », champs dépliés.", "SMTP port: \"E-mail\" card, fields shown.") : ""));
            if (erreur != null) return null;
            return new ConfigNotifications
            {
                NiveauMin = niveauNotif.Valeur, MaxParHeure = max, Ntfy = ntfy.IsChecked == true, Teams = teams.IsChecked == true, Smtp = smtp.IsChecked == true,
                SmtpServeur = smtpServeur.Text.Trim(), SmtpPort = port, SmtpSecurite = securite.Valeur, SmtpUtilisateur = smtpUtilisateur.Text.Trim(), Expediteur = expediteur.Text.Trim(), Destinataires = destinataires.Text.Trim()
            };
        }

        bool Notifications(string action)
        {
            var c = SaisieNotifications();
            if (c == null) return false;
            ActionsReglages.Notifications(action, c, ntfyUrl.Password, ntfyJeton.Password, teamsUrl.Password, smtpMdp.Password);
            return true;
        }

        bool Autoriser()
        {
            DireErreur(errCompte, null);
            if (string.IsNullOrWhiteSpace(compte.Text)) return false;
            string sid = ActionsReglages.Sid(compte.Text);
            if (sid == null) { DireErreur(errCompte, L.T("Compte introuvable.")); return false; }
            ActionsReglages.AutoriserLecteur(sid);
            compte.Text = "";
            return true;
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

        // Entrée de la navigation des sections : icône, libellé, état court à droite ; modèle de la navigation de la coquille
        Button Entree(int i)
        {
            var d = new DockPanel { LastChildFill = true };
            var icone = new TextBlock { Text = VueReglagesFluent.Icones[i], FontFamily = Jetons.Icones, FontSize = 16, Width = 28, VerticalAlignment = VerticalAlignment.Center };
            DockPanel.SetDock(icone, Dock.Left); d.Children.Add(icone);
            var etat = new TextBlock { FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) };
            DockPanel.SetDock(etat, Dock.Right); d.Children.Add(etat);
            etatsEntrees[i] = etat;
            d.Children.Add(new TextBlock { Text = VueReglagesFluent.Nom(i), VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis, ToolTip = VueReglagesFluent.Nom(i) });
            var b = new Button { Content = d, Foreground = Jetons.Pinceau(Jetons.Texte), HorizontalContentAlignment = HorizontalAlignment.Stretch, Padding = new Thickness(12, 6, 12, 6), Margin = new Thickness(0, 1, 0, 1), Cursor = Cursors.Hand };
            b.Template = Coquille.ModeleNavigation();
            b.FocusVisualStyle = Jetons.StyleFocus();
            System.Windows.Automation.AutomationProperties.SetName(b, VueReglagesFluent.Nom(i));
            int k = i;
            b.Click += (s, e) => Afficher(k);
            entrees[i] = b;
            return b;
        }

        // Carte : titre (interrupteur à droite), phrase d'aide, contenu, boutons ; à part, sous un trait, les actions
        // destructives en rouge avec leur conséquence ; en dessous, les messages de la carte
        static Border Carte(string titre, string aide, UIElement droite, UIElement corps, UIElement[] actions, UIElement[] destructives = null, string consequence = null, UIElement pied = null)
        {
            var cadre = new Border { Background = Jetons.Pinceau(Jetons.Carte), CornerRadius = new CornerRadius(8), Padding = new Thickness(22, 18, 22, 18), Margin = new Thickness(0, 0, 0, 14) };
            if (Jetons.ContrasteEleve) { cadre.BorderBrush = Jetons.Pinceau(Jetons.Separateur); cadre.BorderThickness = new Thickness(1); }
            var pile = new StackPanel();
            var haut = new DockPanel();
            if (droite != null) { DockPanel.SetDock(droite, Dock.Right); haut.Children.Add(droite); }
            haut.Children.Add(new TextBlock { Text = titre, FontSize = 16, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center });
            pile.Children.Add(haut);
            var texteAide = new TextBlock { Text = aide ?? "", FontSize = 13, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 0), Tag = aide ?? "" };
            if (!string.IsNullOrEmpty(aide)) pile.Children.Add(texteAide);
            if (corps != null) { var fe = corps as FrameworkElement; if (fe != null) fe.Margin = new Thickness(0, 14, 0, 0); pile.Children.Add(corps); }
            if (actions != null && actions.Length > 0)
            {
                var l = new WrapPanel { Margin = new Thickness(0, corps == null ? 12 : 4, 0, 0) };
                foreach (var a in actions) l.Children.Add(a);
                pile.Children.Add(l);
            }
            if (pied != null) pile.Children.Add(pied);
            if (destructives != null && destructives.Length > 0)
            {
                pile.Children.Add(new Border { Height = 1, Background = Jetons.Pinceau(Jetons.Separateur), Margin = new Thickness(0, 16, 0, 12) });
                var l = new WrapPanel { HorizontalAlignment = HorizontalAlignment.Right };
                foreach (var a in destructives) l.Children.Add(a);
                var texte = new TextBlock { Text = consequence ?? "", FontSize = 12.5, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 12, 0) };
                if (destructives.Length == 1)
                {
                    var d = new DockPanel();
                    DockPanel.SetDock(l, Dock.Right);
                    d.Children.Add(l);
                    d.Children.Add(texte);
                    pile.Children.Add(d);
                }
                else { pile.Children.Add(texte); pile.Children.Add(l); }
            }
            cadre.Child = pile;
            return cadre;
        }

        // Carte d'un canal de remontée : interrupteur ; canal éteint, champs repliés (ils restent lus et envoyés comme avant)
        static Border CarteCanal(CheckBox interrupteur, string aide, UIElement champs)
        {
            var carte = Carte((string)System.Windows.Automation.AutomationProperties.GetName(interrupteur), aide, interrupteur, champs, null);
            var pile = (StackPanel)carte.Child;
            var texteAide = pile.Children.OfType<TextBlock>().FirstOrDefault(t => t.Tag as string == aide);
            Action suivre = () =>
            {
                bool actif = interrupteur.IsChecked == true;
                champs.Visibility = actif ? Visibility.Visible : Visibility.Collapsed;
                if (texteAide != null) texteAide.Text = aide + (actif ? "" : " " + T("Désactivé : champs masqués.", "Off: fields hidden."));
            };
            interrupteur.Checked += (s, e) => suivre();
            interrupteur.Unchecked += (s, e) => suivre();
            suivre();
            return carte;
        }

        // Bandeau d'état, même dessin que celui de la Vue d'ensemble : carte teintée, tuile d'icône, titre et détail
        static Border Bandeau(TextBlock titre, TextBlock detail, UIElement extra)
        {
            var b = new Border { BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(10), Padding = new Thickness(18, 14, 18, 14), Margin = new Thickness(0, 0, 0, 14) };
            var d = new DockPanel();
            var tuile = new Border { Width = 40, Height = 40, CornerRadius = new CornerRadius(8), VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 0, 14, 0) };
            tuile.Child = new TextBlock { FontFamily = Jetons.Icones, FontSize = 20, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
            DockPanel.SetDock(tuile, Dock.Left); d.Children.Add(tuile);
            var p = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            titre.FontSize = 16; titre.FontWeight = FontWeights.SemiBold; titre.TextWrapping = TextWrapping.Wrap;
            detail.FontSize = 13; detail.Foreground = Jetons.Pinceau(Jetons.TexteSecondaire); detail.TextWrapping = TextWrapping.Wrap; detail.Margin = new Thickness(0, 3, 0, 0);
            p.Children.Add(titre); p.Children.Add(detail);
            if (extra != null) p.Children.Add(extra);
            d.Children.Add(p);
            b.Child = d;
            Teinter(b, -2);
            return b;
        }

        static void Teinter(Border b, int gravite)
        {
            var couleur = gravite == 2 ? Jetons.Danger : gravite == 1 ? Jetons.Attention : gravite == 0 ? Jetons.Succes : gravite == -1 ? Jetons.Accent : Jetons.TexteSecondaire;
            b.Background = new LinearGradientBrush(VueTraficFluent.Melange(Jetons.Carte, couleur, 0.16), Jetons.Carte, 0);
            b.BorderBrush = Jetons.Pinceau(VueTraficFluent.Melange(Jetons.Separateur, couleur, 0.35));
            var tuile = (Border)((DockPanel)b.Child).Children[0];
            tuile.Background = Jetons.Pinceau(VueTraficFluent.Melange(Jetons.Carte, couleur, 0.28));
            var icone = (TextBlock)tuile.Child;
            icone.Foreground = Jetons.Pinceau(couleur);
            icone.Text = gravite == 2 ? "" : gravite == 1 ? "" : gravite == 0 ? "" : gravite == -1 ? "" : "";
        }

        // Grille à deux colonnes ; un élément marqué Large prend toute la largeur
        static Grid Grille(params UIElement[] cases)
        {
            var g = new Grid();
            g.ColumnDefinitions.Add(new ColumnDefinition());
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(20) });
            g.ColumnDefinitions.Add(new ColumnDefinition());
            int r = 0, c = 0;
            foreach (var e in cases)
            {
                var fe = e as FrameworkElement;
                bool large = fe != null && "large".Equals(fe.Tag);
                if (large && c != 0) { r++; c = 0; }
                if (g.RowDefinitions.Count <= r) g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                Grid.SetRow(e, r); Grid.SetColumn(e, c == 0 ? 0 : 2);
                if (large) Grid.SetColumnSpan(e, 3);
                g.Children.Add(e);
                if (large || c == 1) { r++; c = 0; } else c = 1;
            }
            return g;
        }

        static UIElement Large(FrameworkElement e, Color? couleur = null)
        {
            e.Tag = "large";
            var t = e as TextBlock;
            if (t != null && couleur != null) t.Foreground = Jetons.Pinceau(couleur.Value);
            return e;
        }

        // Champ : libellé au-dessus, saisie, aide, erreur de saisie sous le champ
        static StackPanel Champ(string libelle, UIElement saisie, TextBlock erreur = null, string aide = null, TextBlock aideVariable = null)
        {
            var p = new StackPanel { Margin = new Thickness(0, 0, 0, 12) };
            p.Children.Add(new TextBlock { Text = libelle, FontSize = 13, Margin = new Thickness(0, 0, 0, 6), TextWrapping = TextWrapping.Wrap });
            var fe = saisie as FrameworkElement;
            if (fe != null) fe.HorizontalAlignment = fe is ChoixFluent ? HorizontalAlignment.Left : HorizontalAlignment.Stretch;
            p.Children.Add(saisie);
            var nomChamp = saisie as Control ?? (saisie is Grid ? ((Grid)saisie).Children.OfType<PasswordBox>().FirstOrDefault() : null);
            if (nomChamp != null) System.Windows.Automation.AutomationProperties.SetName(nomChamp, libelle);
            if (aide != null) p.Children.Add(new TextBlock { Text = aide, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, 4, 0, 0), TextWrapping = TextWrapping.Wrap });
            if (aideVariable != null) { aideVariable.FontSize = 12; aideVariable.Margin = new Thickness(0, 4, 0, 0); p.Children.Add(aideVariable); }
            if (erreur != null) p.Children.Add(erreur);
            return p;
        }

        static StackPanel Pile(params UIElement[] elements)
        {
            var p = new StackPanel();
            foreach (var e in elements) p.Children.Add(e);
            return p;
        }

        static TextBlock Texte(bool secondaire)
        {
            return new TextBlock { TextWrapping = TextWrapping.Wrap, FontSize = 12, Foreground = Jetons.Pinceau(secondaire ? Jetons.TexteSecondaire : Jetons.Texte), Margin = new Thickness(0, 2, 0, 6) };
        }

        static TextBlock Note(string texte)
        {
            var t = Texte(true); t.Text = texte; return t;
        }

        static TextBlock Couleur(TextBlock t, Color c) { t.Foreground = Jetons.Pinceau(c); return t; }

        static TextBlock Erreur()
        {
            return new TextBlock { FontSize = 12, Foreground = Jetons.Pinceau(Jetons.Danger), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 0), Visibility = Visibility.Collapsed };
        }

        static TextBlock Indice()
        {
            return new TextBlock { FontSize = 13, FontStyle = FontStyles.Italic, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), VerticalAlignment = VerticalAlignment.Center };
        }

        static Border Pastille(string texte)
        {
            var b = new Border { Background = Jetons.Pinceau(Jetons.Surface), CornerRadius = new CornerRadius(12), Padding = new Thickness(10, 3, 10, 4), Margin = new Thickness(0, 0, 6, 6) };
            var p = new StackPanel { Orientation = Orientation.Horizontal };
            p.Children.Add(new TextBlock { Text = "", FontFamily = Jetons.Icones, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, 0, 6, 0), VerticalAlignment = VerticalAlignment.Center });
            p.Children.Add(new TextBlock { Text = texte, FontFamily = Briques.Chasse, FontSize = 12.5, VerticalAlignment = VerticalAlignment.Center });
            b.Child = p;
            return b;
        }

        static CheckBox Case(string texte)
        {
            return new CheckBox { Content = new TextBlock { Text = L.T(texte), TextWrapping = TextWrapping.Wrap }, Foreground = Jetons.Pinceau(Jetons.Texte), Margin = new Thickness(0, 2, 0, 12), Cursor = Cursors.Hand };
        }

        // Interrupteur : case à cocher dessinée en capsule, état dit en mots à côté (la couleur seule ne porte pas le sens) ;
        // nom lu par les lecteurs d'écran = titre de la carte
        static CheckBox Interrupteur(string nom)
        {
            var etat = new TextBlock { FontSize = 13, VerticalAlignment = VerticalAlignment.Center };
            var c = new CheckBox { Content = etat, Foreground = Jetons.Pinceau(Jetons.Texte), Cursor = Cursors.Hand, VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(12, 0, 0, 0) };
            c.Template = ModeleInterrupteur();
            c.FocusVisualStyle = Jetons.StyleFocus();
            System.Windows.Automation.AutomationProperties.SetName(c, nom);
            Action dire = () => { etat.Text = c.IsChecked == true ? T("Activé", "On") : T("Désactivé", "Off"); etat.Foreground = Jetons.Pinceau(c.IsChecked == true ? Jetons.Texte : Jetons.TexteSecondaire); };
            c.Checked += (s, e) => dire();
            c.Unchecked += (s, e) => dire();
            dire();
            return c;
        }

        static ControlTemplate modeleInterrupteur;
        static ControlTemplate ModeleInterrupteur()
        {
            if (modeleInterrupteur != null) return modeleInterrupteur;
            var t = new ControlTemplate(typeof(CheckBox));
            var pile = new FrameworkElementFactory(typeof(StackPanel));
            pile.SetValue(StackPanel.OrientationProperty, Orientation.Horizontal);
            pile.SetValue(Panel.BackgroundProperty, Brushes.Transparent);
            var texte = new FrameworkElementFactory(typeof(ContentPresenter));
            texte.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
            texte.SetValue(FrameworkElement.MarginProperty, new Thickness(0, 0, 10, 0));
            var capsule = new FrameworkElementFactory(typeof(Border), "capsule");
            capsule.SetValue(FrameworkElement.WidthProperty, 40.0);
            capsule.SetValue(FrameworkElement.HeightProperty, 20.0);
            capsule.SetValue(Border.CornerRadiusProperty, new CornerRadius(10));
            capsule.SetValue(Border.BorderThicknessProperty, new Thickness(1));
            capsule.SetValue(Border.BackgroundProperty, Jetons.Pinceau(Jetons.Fond));
            capsule.SetValue(Border.BorderBrushProperty, Jetons.Pinceau(Jetons.TexteSecondaire));
            capsule.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
            var bouton = new FrameworkElementFactory(typeof(System.Windows.Shapes.Ellipse), "bouton");
            bouton.SetValue(FrameworkElement.WidthProperty, 12.0);
            bouton.SetValue(FrameworkElement.HeightProperty, 12.0);
            bouton.SetValue(System.Windows.Shapes.Shape.FillProperty, Jetons.Pinceau(Jetons.TexteSecondaire));
            bouton.SetValue(FrameworkElement.HorizontalAlignmentProperty, HorizontalAlignment.Left);
            bouton.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
            bouton.SetValue(FrameworkElement.MarginProperty, new Thickness(4, 0, 0, 0));
            capsule.AppendChild(bouton);
            pile.AppendChild(texte);
            pile.AppendChild(capsule);
            t.VisualTree = pile;
            var coche = new Trigger { Property = System.Windows.Controls.Primitives.ToggleButton.IsCheckedProperty, Value = true };
            coche.Setters.Add(new Setter(Border.BackgroundProperty, Jetons.Pinceau(Jetons.Accent), "capsule"));
            coche.Setters.Add(new Setter(Border.BorderBrushProperty, Jetons.Pinceau(Jetons.Accent), "capsule"));
            coche.Setters.Add(new Setter(System.Windows.Shapes.Shape.FillProperty, Jetons.Pinceau(Jetons.TexteSurAccent), "bouton"));
            coche.Setters.Add(new Setter(FrameworkElement.HorizontalAlignmentProperty, HorizontalAlignment.Right, "bouton"));
            coche.Setters.Add(new Setter(FrameworkElement.MarginProperty, new Thickness(0, 0, 3, 0), "bouton"));
            coche.Setters.Add(new Setter(FrameworkElement.WidthProperty, 14.0, "bouton"));
            coche.Setters.Add(new Setter(FrameworkElement.HeightProperty, 14.0, "bouton"));
            t.Triggers.Add(coche);
            modeleInterrupteur = t;
            return t;
        }

        static TextBox Saisie()
        {
            return new TextBox { Background = Jetons.Pinceau(Jetons.Surface), Foreground = Jetons.Pinceau(Jetons.Texte), BorderBrush = Jetons.Pinceau(Jetons.Separateur), CaretBrush = Jetons.Pinceau(Jetons.Texte), Padding = new Thickness(8, 5, 8, 5), FontFamily = Briques.Chasse, FontSize = 12.5, VerticalContentAlignment = VerticalAlignment.Center };
        }

        static PasswordBox Secret(double largeur)
        {
            return new PasswordBox { MinWidth = Math.Min(largeur, 160), Background = Jetons.Pinceau(Jetons.Surface), Foreground = Jetons.Pinceau(Jetons.Texte), BorderBrush = Jetons.Pinceau(Jetons.Separateur), CaretBrush = Jetons.Pinceau(Jetons.Texte), Padding = new Thickness(8, 5, 8, 5), FontSize = 12.5, VerticalContentAlignment = VerticalAlignment.Center };
        }

        // Secret : le champ vide montre, par-dessus, un cadenas et l'indice (« enregistré », « non renseigné ») ; dès la première
        // lettre tapée, l'indice disparaît. La valeur enregistrée n'est jamais lue ni affichée
        static Grid Masque(PasswordBox p, TextBlock indice)
        {
            var g = new Grid();
            g.Children.Add(p);
            var d = new StackPanel { Orientation = Orientation.Horizontal, IsHitTestVisible = false, Margin = new Thickness(10, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
            d.Children.Add(new TextBlock { Text = "", FontFamily = Jetons.Icones, FontSize = 12, Foreground = Jetons.Pinceau(Jetons.TexteSecondaire), Margin = new Thickness(0, 0, 8, 0), VerticalAlignment = VerticalAlignment.Center });
            d.Children.Add(indice);
            g.Children.Add(d);
            p.PasswordChanged += (s, e) => d.Visibility = p.Password.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
            return g;
        }

        Button Bouton(string texte, bool fort, Action action) { return BoutonValide(texte, fort, () => { action(); return true; }); }

        // Action qui valide une saisie : faux = refusée, rien n'est parti ; pas de relecture alors, la saisie fautive et son
        // erreur restent à l'écran (prérelecture de #305, D1)
        Button BoutonValide(string texte, bool fort, Func<bool> action)
        {
            var b = Briques.Action(L.T(texte), fort, (s, e) => { if (!rempli) return; if (action()) Charger(); });
            b.HorizontalAlignment = HorizontalAlignment.Left; b.Margin = new Thickness(0, 4, 8, 4);
            return b;
        }

        // Action destructive : même bouton, bordure et texte rouges ; la conséquence est dite à côté, sur la carte
        Button Destructif(string texte, Action action)
        {
            var b = Bouton(texte, false, action);
            b.BorderBrush = Jetons.Pinceau(Jetons.Danger); b.Foreground = Jetons.Pinceau(Jetons.Danger);
            b.Margin = new Thickness(8, 4, 0, 4);
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

        // Repère « déjà proposés » consulté par l'interface non élevée seulement (audit de #304, A304-2) : sous jeton
        // administrateur, ni son chemin (GetFolderPath, qui vérifie le dossier) ni son existence (File.Exists) ne sont
        // demandés, car %LOCALAPPDATA% se redirige par HKCU sans élévation et la requête partirait vers un chemin choisi par
        // un programme non élevé du compte. Rend vrai (« déjà vu » : rien à proposer, aucune carte), comme le veut déjà
        // DoitProposer en administrateur. Décision pure, testée par tests\test-langue.ps1
        public static bool RepereVu(bool administrateur, Func<string> chemin, Func<string, bool> existe)
        {
            if (administrateur) return true;
            return existe(chemin());
        }

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

        // Message de test (U7c) : seulement si config.json est lu et qu'un canal est activé ; mêmes réglages, secrets vides
        // (le service garde les siens). Le service applique ces réglages avant le test : ils sont relus au clic (S154-01).
        // Commande construite par la fonction de la page Réglages
        public static bool PeutTester(Config c, bool illisible) { return !illisible && c != null && c.Notifications != null && Canaux(c).Count > 0; }

        public static Commande CommandeTest(Config c, bool illisible)
        {
            return PeutTester(c, illisible) ? ActionsReglages.CommandeNotifications("testerNotifications", c.Notifications, "", "", "", "") : null;
        }

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
                return s + " " + (en ? "No message sent yet: send a test message to check that it arrives." : "Aucun message envoyé pour l'instant : envoyez un message de test pour vérifier qu'il arrive.");
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

        public static string RienEnvoye()
        {
            return L.En ? "Nothing was sent: the settings read again are unreadable or no longer have a channel turned on." : "Rien n'a été envoyé : les réglages relus sont illisibles ou n'ont plus de canal activé.";
        }

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
        Etat etat; Config config; EtatApprentissage apprentissage; EtatNotifications notifications; List<Lecteur> lecteurs;

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
                    var lect = Commun.Lire<List<Lecteur>>("lecteurs.json");
                    Dispatcher.BeginInvoke((Action)(() =>
                    {
                        if (numero != chargement) return;
                        lu = true; etat = e; etatIllisible = !absentEtat && e == null; config = c; configIllisible = ci; apprentissage = a; notifications = n; lecteurs = lect;
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
                        var points = VueEnsembleFluent.AvecCompteurs(source.Points(), source.Badges(), source.Comptes());
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
                            () => { ActionsReglages.Apprentissage(op); return true; }, en ? "end of learning" : "fin de l'apprentissage"));
                    contenu.Children.Add(Texte(VueAssistantFluent.AvertissementRecommencer(), true));
                    contenu.Children.Add(Texte(en ? "Learned exceptions are managed in Settings." : "Les exceptions apprises se gèrent dans Réglages.", true));
                    contenu.Children.Add(Lien(en ? "Open Settings" : "Ouvrir Réglages", "Réglages"));
                    break;
                case 3:
                    contenu.Children.Add(Texte(!lu ? L.T("Lecture en cours…") : VueAssistantFluent.TexteQuiPrevenir(config, configIllisible, notifications, notificationsIllisibles)));
                    // Qui prévenir (U7c, option B du dossier) : test des canaux déjà réglés ; destinataires et secrets restent dans Réglages
                    if (lu && VueAssistantFluent.PeutTester(config, configIllisible))
                    {
                        // Le service applique les réglages envoyés avant le test : ils sont relus au clic, jamais ceux du chargement
                        // de l'étape (audit de #154, S154-01 ; relecture, R15)
                        contenu.Children.Add(Agir(en ? "Send a test message" : "Envoyer un message de test", VueAssistantFluent.CommandeTest(config, false),
                            () =>
                            {
                                bool illisibleAuClic;
                                var cfg = ActionsProtection.LireConfig(out illisibleAuClic);
                                if (VueAssistantFluent.CommandeTest(cfg, illisibleAuClic) == null) return false;
                                ActionsReglages.Notifications("testerNotifications", cfg.Notifications, "", "", "", "");
                                return true;
                            }, en ? "test message" : "message de test"));
                    }
                    contenu.Children.Add(Texte(en ? "Recipients, channels and their secrets are set in Settings; secrets are never shown again." : "Destinataires, canaux et secrets se règlent dans Réglages ; les secrets n'y sont jamais réaffichés.", true));
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
                                () => { ActionsProtection.ChangerReglage(reglage, !actif); return true; }, (actif ? (en ? "turn off " : "désactiver ") : (en ? "turn on " : "activer ")) + nom));
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
                    // Comptes lecteurs (audit du 2026-11-23, A-6-2) : le premier compte vu à la console l'est d'office
                    contenu.Children.Add(Briques.Titre(L.T("Comptes autorisés à lire les données"), 8));
                    contenu.Children.Add(Texte(ActionsReglages.TexteLecteurs(lecteurs)));
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

        // Bouton d'action (U7b) : la confirmation détaillée passe par Canal, élevé ou non (copie élevée pour un compte standard,
        // confirmation en administrateur pour config et apprentissage depuis S152-02) : l'assistant n'en montre pas une seconde.
        // Le résultat est dit « demandé » et l'état relu
        Button Agir(string texte, Commande commande, Func<bool> action, string quoi)
        {
            var b = Briques.Action(texte, true, (s, e) =>
            {
                if (commande == null) return;
                // false : rien n'est parti (réglages relus au clic devenus illisibles ou sans canal)
                demande = action() ? VueAssistantFluent.Demande(quoi) : VueAssistantFluent.RienEnvoye(); demandeEtape = etape;
                Afficher(); Charger();
            });
            b.HorizontalAlignment = HorizontalAlignment.Left; b.Margin = new Thickness(0, 4, 8, 4);
            return b;
        }

        string demande; int demandeEtape = -1;

        internal int Etape { get { return etape; } }
    }
}
