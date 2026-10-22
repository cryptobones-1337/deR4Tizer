// deR4Tizer.exe : interface qui affiche les connexions, les alertes, la vie privée, le démarrage
// automatique, les blocages et les listes de menaces du service.
// Tourne sans droits admin (lecture des fichiers d'état) ; chaque action de blocage relance
// l'exécutable en administrateur avec --commande, qui transmet la demande au service.
//   deR4Tizer.exe            ouvre la fenêtre
//   deR4Tizer.exe --cache    démarre directement dans la zone de notification (démarrage de session)
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace DeR4Tizer
{
    static class Canal
    {
        public static bool EstAdmin()
        {
            return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static Reponse Envoyer(Commande c)
        {
            try
            {
                using (var tube = new NamedPipeClientStream(".", Commun.NomPipe, PipeDirection.InOut))
                {
                    tube.Connect(3000);
                    var ecrivain = new StreamWriter(tube, new UTF8Encoding(false)) { AutoFlush = true };
                    ecrivain.WriteLine(Commun.Json().Serialize(c));
                    string ligne = new StreamReader(tube, Encoding.UTF8).ReadLine();
                    return Commun.Json().Deserialize<Reponse>(ligne);
                }
            }
            catch (System.TimeoutException) { return new Reponse { Ok = false, Message = "Le service deR4Tizer ne répond pas. Est-il démarré ?" }; }
            catch (UnauthorizedAccessException) { return new Reponse { Ok = false, Message = "Accès refusé : droits administrateur requis." }; }
            catch (Exception e) { return new Reponse { Ok = false, Message = e.Message }; }
        }

        // Envoie la commande, en passant par une copie de l'interface lancée en administrateur si besoin
        public static void Executer(Commande c)
        {
            if (EstAdmin())
            {
                Afficher(Envoyer(c));
                return;
            }
            string donnees = Convert.ToBase64String(Encoding.UTF8.GetBytes(Commun.Json().Serialize(c)));
            try
            {
                var p = Process.Start(new ProcessStartInfo(Application.ExecutablePath, "--commande " + donnees)
                {
                    Verb = "runas", UseShellExecute = true
                });
                if (p != null) p.WaitForExit();
            }
            catch (Win32Exception e)
            {
                if (e.NativeErrorCode != 1223) MessageBox.Show(e.Message, "deR4Tizer", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        public static void Afficher(Reponse r)
        {
            MessageBox.Show(L.T(r.Message), "deR4Tizer", MessageBoxButtons.OK, r.Ok ? MessageBoxIcon.Information : MessageBoxIcon.Error);
        }
    }

    // Bandeau du haut : logo, titre « glitch » et pastilles d'état
    class Entete : Control
    {
        public class Pastille
        {
            public string Texte;
            public Color Couleur;
            public bool Clignote;
        }

        readonly Image logo;
        public List<Pastille> Pastilles = new List<Pastille>();
        public bool Phase;

        public Entete()
        {
            Dock = DockStyle.Top;
            Height = 76;
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            logo = Theme.ImageApplication(48);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
            using (var fond = new LinearGradientBrush(ClientRectangle, Theme.Melange(Theme.Fond, Theme.Panneau2, 0.7f), Theme.Fond, 90f))
                g.FillRectangle(fond, ClientRectangle);
            // Fines lignes de balayage
            using (var ligne = new Pen(Color.FromArgb(10, Theme.Cyan)))
                for (int y = 0; y < Height; y += 3) g.DrawLine(ligne, 0, y, Width, y);

            g.DrawImage(logo, 16, 14, 48, 48);
            const string titre = "deR4Tizer";
            TextRenderer.DrawText(g, titre, Theme.Titre, new Point(76, 9), Color.FromArgb(200, Theme.Magenta));
            TextRenderer.DrawText(g, titre, Theme.Titre, new Point(74, 8), Theme.Cyan);
            TextRenderer.DrawText(g, "NETWORK THREAT MONITOR  //  v" + Commun.Version + "  //  SERVICE SYSTEM", Theme.PetitGras,
                new Point(77, 47), Theme.TexteDim);

            // Pastilles alignées à droite
            float x = Width - 16;
            foreach (var p in Enumerable.Reverse(Pastilles))
            {
                var taille = TextRenderer.MeasureText(p.Texte, Theme.PetitGras);
                float l = taille.Width + 30;
                x -= l;
                var r = new RectangleF(x, 26, l, 24);
                bool eteint = p.Clignote && !Phase;
                Color c = eteint ? Theme.Melange(p.Couleur, Theme.Fond, 0.55f) : p.Couleur;
                using (var chemin = Theme.Arrondi(r, 12))
                {
                    using (var b = new SolidBrush(Color.FromArgb(28, c))) g.FillPath(b, chemin);
                    using (var crayon = new Pen(Color.FromArgb(150, c))) g.DrawPath(crayon, chemin);
                }
                using (var b = new SolidBrush(c)) g.FillEllipse(b, x + 10, 34, 8, 8);
                TextRenderer.DrawText(g, p.Texte, Theme.PetitGras, new Rectangle((int)x + 22, 26, (int)l - 24, 24), c,
                    TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
                x -= 8;
            }

            // Trait néon dégradé cyan -> magenta
            using (var trait = new LinearGradientBrush(new Rectangle(0, Height - 2, Math.Max(1, Width), 2), Theme.Cyan, Theme.Magenta, 0f))
                g.FillRectangle(trait, 0, Height - 2, Width, 2);
        }
    }

    class Fenetre : Form
    {
        readonly string fichierLecture = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "deR4Tizer", "derniere-alerte-lue.txt");

        readonly Entete entete = new Entete();
        readonly Panel contenu = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Fond };
        readonly Label statut = new Label
        {
            Dock = DockStyle.Bottom, Height = 26, BackColor = Theme.Panneau, ForeColor = Theme.TexteDim, Font = Theme.Mono,
            TextAlign = ContentAlignment.MiddleLeft, Padding = new Padding(12, 0, 0, 0)
        };
        readonly List<BoutonNav> navigation = new List<BoutonNav>();
        readonly List<Control> pages = new List<Control>();
        BoutonNav navFlux, navAlertes, navChaines, navVie, navParefeu, navDemarrage, navBaseline, navExtensions, navBlocages, navQuarantaine, navMenaces;
        Control pageAlertes;
        readonly BoutonNeon btnService = new BoutonNeon("Démarrer le service", Theme.Vert);
        readonly BoutonNeon btnPanique = new BoutonNeon("◉ PANIQUE : couper Internet", Theme.Rouge);

        readonly Liste lvFlux = new Liste(), lvAlertes = new Liste(), lvBlocages = new Liste(), lvDemarrage = new Liste(), lvVie = new Liste(), lvMenaces = new Liste(),
                       lvChaines = new Liste(), lvBaseline = new Liste(), lvExtensions = new Liste(), lvQuarantaine = new Liste(), lvParefeu = new Liste();
        readonly CheckBox chkMasquerWindows = CaseNeon("Masquer les entrées signées Microsoft / Windows", true);
        readonly CheckBox chkBlocageAuto = CaseNeon("Bloquer automatiquement au pare-feu les IP des listes de confiance haute", false);
        readonly CheckBox chkRancongiciel = CaseNeon("Suspendre automatiquement un programme qui touche aux fichiers leurres (rançongiciel)", false);
        readonly Label lblMenaces = new Label { AutoSize = true, ForeColor = Theme.TexteDim, Font = Theme.Petit, Margin = new Padding(0, 8, 0, 0) };
        readonly Label lblBaseline = new Label { AutoSize = true, ForeColor = Theme.Texte, Font = Theme.PetitGras, Margin = new Padding(0, 8, 12, 0) };
        readonly Label detailAlerte = new Label
        {
            Dock = DockStyle.Bottom, Height = 92, BackColor = Theme.Panneau2, ForeColor = Theme.Texte, Font = Theme.Petit,
            Padding = new Padding(12, 8, 12, 8), Text = L.T("Sélectionnez une alerte pour voir la technique d'attaque et quoi faire.")
        };
        readonly Label detailBaseline = new Label
        {
            Dock = DockStyle.Bottom, Height = 64, BackColor = Theme.Panneau2, ForeColor = Theme.Texte, Font = Theme.Petit, Padding = new Padding(12, 8, 12, 8)
        };
        readonly NotifyIcon icone = new NotifyIcon();
        readonly Icon iconeNormale = Theme.IconeApplication(16);
        Icon iconeAlerte;
        readonly System.Windows.Forms.Timer minuteur = new System.Windows.Forms.Timer { Interval = 2000 };
        readonly System.Windows.Forms.Timer clignotement = new System.Windows.Forms.Timer { Interval = 600 };

        List<EntreeDemarrage> demarrage = new List<EntreeDemarrage>();
        DateTime demarrageVu, menacesVu, configVu, baselineVu, extensionsVu, quarantaineVu, parefeuVu;
        bool majCase, paniqueActive;
        string etatVu = "", alertesVues = "", blocagesVus = "";
        string derniereLue = "";
        HashSet<string> idsConnus;
        bool quitter, astuceMontree;
        readonly bool demarrerCache;

        public Fenetre(bool cache)
        {
            demarrerCache = cache;
            Text = "deR4Tizer " + Commun.Version;
            Icon = Theme.IconeApplication(32);
            Size = new Size(1360, 800);
            MinimumSize = new Size(960, 560);
            StartPosition = FormStartPosition.CenterScreen;
            Font = Theme.Petit;
            Theme.FenetreSombre(this);
            try { derniereLue = File.ReadAllText(fichierLecture).Trim(); } catch { }
            iconeAlerte = Theme.IconeAvecPastille(iconeNormale);
            var rendu = new RenduSombre();

            // ---------------- Connexions
            lvFlux.Colonnes("Score", 60, "Programme", 140, "Lancé par", 110, "PID", 60, "Destination", 280, "Port", 60,
                "Signataire", 170, "Vu depuis", 170, "Raisons", 420);
            lvFlux.ContextMenuStrip = MenuContextuel(rendu,
                new ToolStripMenuItem("Bloquer (nom dans le fichier hosts, sinon IP au pare-feu)", null, (s, e) => BloquerFlux(false)),
                new ToolStripMenuItem("Bloquer l'IP au pare-feu", null, (s, e) => BloquerFlux(true)),
                new ToolStripSeparator(),
                new ToolStripMenuItem("Isoler ce programme du réseau", null, (s, e) => Agir(lvFlux, "isolerProgramme")),
                new ToolStripMenuItem("Suspendre le processus", null, (s, e) => Agir(lvFlux, "suspendre")),
                new ToolStripMenuItem("Reprendre le processus", null, (s, e) => Agir(lvFlux, "reprendre")),
                new ToolStripMenuItem("Tuer le processus", null, (s, e) => Agir(lvFlux, "tuer")),
                new ToolStripMenuItem("Mettre le programme en quarantaine", null, (s, e) => Agir(lvFlux, "quarantaine")),
                new ToolStripSeparator(),
                new ToolStripMenuItem("Ouvrir l'emplacement du programme", null, (s, e) => Emplacement(lvFlux)),
                new ToolStripMenuItem("Copier", null, (s, e) => Copier(lvFlux)));
            var pageFlux = Page("Connexions", "Flux sortants en direct. Survolez une ligne pour le chemin, la ligne de commande et l'origine du fichier ; clic droit pour bloquer ou réagir.", lvFlux);

            // ---------------- Alertes
            lvAlertes.Colonnes("Heure", 170, "Niveau", 85, "Programme", 140, "Destination", 260, "Port", 60, "Raisons", 520, "Chemin", 320);
            lvAlertes.ContextMenuStrip = MenuContextuel(rendu,
                new ToolStripMenuItem("Bloquer cette destination", null, (s, e) => BloquerAlerte()),
                new ToolStripSeparator(),
                new ToolStripMenuItem("Isoler ce programme du réseau", null, (s, e) => Agir(lvAlertes, "isolerProgramme")),
                new ToolStripMenuItem("Suspendre le processus", null, (s, e) => Agir(lvAlertes, "suspendre")),
                new ToolStripMenuItem("Tuer le processus et ses enfants", null, (s, e) => Agir(lvAlertes, "tuerChaine")),
                new ToolStripMenuItem("Mettre le programme en quarantaine", null, (s, e) => Agir(lvAlertes, "quarantaine")),
                new ToolStripSeparator(),
                new ToolStripMenuItem("Ouvrir l'emplacement du programme", null, (s, e) => Emplacement(lvAlertes)),
                new ToolStripMenuItem("Copier", null, (s, e) => Copier(lvAlertes)));
            lvAlertes.SelectedIndexChanged += (s, e) => DetaillerAlerte();
            pageAlertes = Page("Alertes", "Critique : menace avérée. Alerte : comportement suspect. Info : première fois qu'un programme fait quelque chose.", lvAlertes);
            lvAlertes.Parent.Controls.Add(detailAlerte);

            // ---------------- Chaînes de processus
            lvChaines.Colonnes("Processus", 330, "PID", 70, "Score", 70, "Raisons", 560, "Ligne de commande", 520);
            lvChaines.ContextMenuStrip = MenuContextuel(rendu,
                new ToolStripMenuItem("Tuer ce processus et toute sa descendance", null, (s, e) => Agir(lvChaines, "tuerChaine")),
                new ToolStripMenuItem("Suspendre le processus", null, (s, e) => Agir(lvChaines, "suspendre")),
                new ToolStripMenuItem("Mettre le programme en quarantaine", null, (s, e) => Agir(lvChaines, "quarantaine")),
                new ToolStripMenuItem("Isoler ce programme du réseau", null, (s, e) => Agir(lvChaines, "isolerProgramme")),
                new ToolStripSeparator(),
                new ToolStripMenuItem("Ouvrir l'emplacement du programme", null, (s, e) => Emplacement(lvChaines)),
                new ToolStripMenuItem("Copier", null, (s, e) => Copier(lvChaines)));
            var pageChaines = Page("Chaînes de processus", "Qui a lancé quoi. Le score s'additionne sur toute la chaîne : une suite d'actions banales une à une devient visible. Alerte au-delà de 12.", lvChaines);

            // ---------------- Vie privée et accès
            lvVie.Colonnes("Élément", 220, "Programme", 170, "Détail", 420, "Depuis / dernière fois", 340, "Signataire", 180);
            lvVie.ContextMenuStrip = MenuContextuel(rendu,
                new ToolStripMenuItem("Ouvrir l'emplacement du programme", null, (s, e) => Emplacement(lvVie)),
                new ToolStripMenuItem("Copier", null, (s, e) => Copier(lvVie)));
            var pageVie = Page("Vie privée et accès", "Caméra, micro, prise en main à distance et ports ouverts sur le réseau.", lvVie);

            // ---------------- Pare-feu et exposition à Internet
            lvParefeu.Colonnes("Élément", 330, "Détail", 520, "Programme", 230, "Quand", 300);
            lvParefeu.ContextMenuStrip = MenuContextuel(rendu, new ToolStripMenuItem("Copier", null, (s, e) => Copier(lvParefeu)));
            var pageParefeu = Page("Pare-feu et exposition à Internet", "Paquets entrants venus d'Internet (journal du pare-feu) et changements de règles avec le programme qui les a faits.", lvParefeu);

            // ---------------- Démarrage automatique
            lvDemarrage.Colonnes("Catégorie", 160, "Nom", 260, "Commande", 420, "Signataire", 180, "Remarque", 220, "Vu depuis", 150);
            lvDemarrage.ContextMenuStrip = MenuContextuel(rendu,
                new ToolStripMenuItem("Mettre la cible en quarantaine", null, (s, e) => Agir(lvDemarrage, "quarantaine")),
                new ToolStripMenuItem("Ouvrir l'emplacement du fichier", null, (s, e) => Emplacement(lvDemarrage)),
                new ToolStripMenuItem("Copier", null, (s, e) => Copier(lvDemarrage)));
            chkMasquerWindows.CheckedChanged += (s, e) => RemplirDemarrage();
            var pageDemarrage = Page("Démarrage automatique", "Tout ce qui se lance avec Windows. Une entrée nouvelle ou modifiée déclenche une alerte.", lvDemarrage, chkMasquerWindows);

            // ---------------- Baseline de sécurité
            lvBaseline.Colonnes("Règle", 420, "État", 120, "Actuel", 170, "Attendu", 170, "Compatibilité", 420);
            lvBaseline.SelectedIndexChanged += (s, e) => DetaillerRegle();
            var btnRecommande = new BoutonNeon("Appliquer le profil recommandé", Theme.Cyan);
            btnRecommande.Click += (s, e) => OperationBaseline("appliquer", "recommandé",
                "Appliquer les règles du profil « recommandé » par la stratégie de groupe locale ?\n\nToutes sont réversibles (bouton Annuler).");
            var btnRenforce = new BoutonNeon("Appliquer le profil renforcé…", Theme.Magenta);
            btnRenforce.Click += (s, e) => OperationBaseline("appliquer", "renforcé",
                "Le profil « renforcé » peut gêner certains logiciels (voir la colonne Compatibilité).\n\nAppliquer quand même ?");
            var btnSelection = new BoutonNeon("Appliquer la sélection", Theme.Cyan);
            btnSelection.Click += (s, e) => OperationBaseline("appliquer", ReglesSelectionnees(), null);
            var btnAnnulerSel = new BoutonNeon("Annuler la sélection", Theme.TexteDim);
            btnAnnulerSel.Click += (s, e) => OperationBaseline("annuler", ReglesSelectionnees(), "Revenir aux valeurs d'origine pour les règles sélectionnées ?");
            var btnToutAnnuler = new BoutonNeon("Tout annuler", Theme.TexteDim);
            btnToutAnnuler.Click += (s, e) => OperationBaseline("annuler", "recommandé,renforcé",
                "Revenir aux valeurs d'origine pour toutes les règles « recommandé » et « renforcé » ?\n(La journalisation reste active.)");
            var btnReevaluer = new BoutonNeon("Réévaluer", Theme.TexteDim);
            btnReevaluer.Click += (s, e) => OperationBaseline("evaluer", "", null);
            var pageBaseline = Page("Baseline de sécurité", "Inspirée des baselines Intune et Microsoft, appliquée par la stratégie de groupe locale. La journalisation est appliquée automatiquement ; le reste à votre demande.",
                lvBaseline, lblBaseline, btnRecommande, btnRenforce, btnSelection, btnAnnulerSel, btnToutAnnuler, btnReevaluer);
            lvBaseline.Parent.Controls.Add(detailBaseline);

            // ---------------- Extensions de navigateur
            lvExtensions.Colonnes("Navigateur", 150, "Extension", 280, "Version", 120, "Permissions", 640, "Vue depuis", 150);
            lvExtensions.ContextMenuStrip = MenuContextuel(rendu, new ToolStripMenuItem("Copier", null, (s, e) => Copier(lvExtensions)));
            var pageExtensions = Page("Extensions de navigateur", "Une extension avec des permissions sensibles peut lire vos pages, vos cookies ou vos saisies. Une nouvelle extension déclenche une alerte.", lvExtensions);

            // ---------------- Blocages
            lvBlocages.Colonnes("Type", 140, "Cible", 380, "Raison", 420, "Date", 160);
            var btnDebloquer = new BoutonNeon("Débloquer la sélection", Theme.Cyan);
            btnDebloquer.Click += (s, e) => DebloquerSelection();
            var btnTout = new BoutonNeon("Tout débloquer", Theme.Magenta);
            btnTout.Click += (s, e) => ToutDebloquer();
            var btnTelemetrie = new BoutonNeon("Bloquer la télémétrie…", Theme.Cyan);
            btnTelemetrie.Click += (s, e) => DialogueTelemetrie();
            var pageBlocages = Page("Blocages", "Domaines redirigés vers 127.0.0.1 (fichier hosts), IP bloquées et programmes isolés au pare-feu.", lvBlocages,
                btnDebloquer, btnTelemetrie, btnTout);

            // ---------------- Quarantaine
            lvQuarantaine.Colonnes("Date", 160, "Fichier d'origine", 560, "Raison", 380, "Taille", 110);
            var btnRestaurer = new BoutonNeon("Restaurer la sélection", Theme.Cyan);
            btnRestaurer.Click += (s, e) =>
            {
                if (lvQuarantaine.SelectedItems.Count == 0) return;
                var q = (ElementQuarantaine)lvQuarantaine.SelectedItems[0].Tag;
                if (MessageBox.Show("Remettre ce fichier à son emplacement d'origine ?\n\n" + q.CheminOrigine, "deR4Tizer", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
                Canal.Executer(new Commande { Action = "restaurer", Cible = q.Id });
                quarantaineVu = DateTime.MinValue;
            };
            var pageQuarantaine = Page("Quarantaine", "Fichiers retirés de leur emplacement et rendus inexécutables. Ils peuvent être restaurés.", lvQuarantaine, btnRestaurer);

            // ---------------- Listes de menaces et réponses automatiques
            lvMenaces.Colonnes("Source", 300, "Type", 100, "Confiance", 110, "Entrées", 110, "Mise à jour", 160, "Statut", 420);
            var btnMaj = new BoutonNeon("Mettre à jour maintenant", Theme.Cyan);
            btnMaj.Click += (s, e) => Canal.Executer(new Commande { Action = "majMenaces" });
            chkBlocageAuto.CheckedChanged += (s, e) => ChangerReglage(chkBlocageAuto, "BlocageAutoMenaces");
            chkRancongiciel.CheckedChanged += (s, e) => ChangerReglage(chkRancongiciel, "ReponseAutoRancongiciel");
            var pageMenaces = Page("Menaces et réponses automatiques", "Listes open source téléchargées toutes les 12 h par le service, et réactions automatiques.",
                lvMenaces, btnMaj, chkBlocageAuto, chkRancongiciel, lblMenaces);

            // ---------------- Navigation
            const int largeurNav = 230;
            var nav = new Panel { Dock = DockStyle.Left, Width = largeurNav, BackColor = Theme.Fond };
            var liens = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(0, 14, 0, 0), AutoScroll = true };
            navFlux = Lien(liens, "Connexions", pageFlux, largeurNav);
            navAlertes = Lien(liens, "Alertes", pageAlertes, largeurNav);
            navChaines = Lien(liens, "Chaînes", pageChaines, largeurNav);
            navVie = Lien(liens, "Vie privée", pageVie, largeurNav);
            navParefeu = Lien(liens, "Pare-feu", pageParefeu, largeurNav);
            navDemarrage = Lien(liens, "Démarrage auto", pageDemarrage, largeurNav);
            navBaseline = Lien(liens, "Baseline", pageBaseline, largeurNav);
            navExtensions = Lien(liens, "Extensions", pageExtensions, largeurNav);
            navBlocages = Lien(liens, "Blocages", pageBlocages, largeurNav);
            navQuarantaine = Lien(liens, "Quarantaine", pageQuarantaine, largeurNav);
            navMenaces = Lien(liens, "Menaces", pageMenaces, largeurNav);
            var pageReglages = new PageReglages();
            contenu.Controls.Add(pageReglages);
            pages.Add(pageReglages);
            Lien(liens, "Réglages", pageReglages, largeurNav);
            navFlux.CouleurBadge = navBlocages.CouleurBadge = navMenaces.CouleurBadge = navQuarantaine.CouleurBadge = Theme.Cyan;

            var actions = new FlowLayoutPanel { Dock = DockStyle.Bottom, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Padding = new Padding(18, 8, 0, 14) };
            var btnJournal = new BoutonNeon("Journal du service", Theme.TexteDim);
            btnJournal.Click += (s, e) => Ouvrir(Path.Combine(Commun.Dossier, "journal.txt"));
            var btnDonnees = new BoutonNeon("Dossier des données", Theme.TexteDim);
            btnDonnees.Click += (s, e) => Ouvrir(Commun.Dossier);
            btnService.Click += (s, e) => DemarrerService();
            btnPanique.Click += (s, e) => Panique();
            btnPanique.Margin = new Padding(0, 0, 8, 14);
            actions.Controls.AddRange(new Control[] { btnPanique, btnService, btnJournal, btnDonnees });
            var separation = new Panel { Dock = DockStyle.Right, Width = 1, BackColor = Theme.Bordure };
            nav.Controls.Add(liens);
            nav.Controls.Add(actions);
            nav.Controls.Add(separation);

            Controls.Add(contenu);
            Controls.Add(nav);
            Controls.Add(statut);
            Controls.Add(entete);
            // Page d'ouverture : --page <nom> (ex. --page Alertes), sinon Connexions
            int iPage = Array.IndexOf(Environment.GetCommandLineArgs(), "--page");
            string pageDemandee = iPage > 0 && iPage + 1 < Environment.GetCommandLineArgs().Length ? Environment.GetCommandLineArgs()[iPage + 1] : null;
            var lienInitial = navigation.FirstOrDefault(b => pageDemandee != null && (b.Cle.StartsWith(pageDemandee, StringComparison.OrdinalIgnoreCase) || b.Text.StartsWith(pageDemandee, StringComparison.OrdinalIgnoreCase)));
            if (lienInitial != null) lienInitial.PerformClick(); else Afficher(navFlux, pageFlux);

            // Zone de notification
            icone.Icon = iconeNormale;
            icone.Text = "deR4Tizer";
            icone.Visible = true;
            icone.ContextMenuStrip = MenuContextuel(rendu,
                new ToolStripMenuItem("Ouvrir", null, (s, e) => Montrer(null, null)),
                new ToolStripMenuItem("Quitter", null, (s, e) => { quitter = true; Close(); }));
            icone.DoubleClick += (s, e) => Montrer(null, null);
            icone.BalloonTipClicked += (s, e) => Montrer(navAlertes, pageAlertes);

            minuteur.Tick += (s, e) => Rafraichir();
            minuteur.Start();
            clignotement.Tick += (s, e) =>
            {
                entete.Phase = !entete.Phase;
                if (entete.Pastilles.Any(p => p.Clignote)) entete.Invalidate();
            };
            clignotement.Start();
            Rafraichir();
        }

        // ------------------------------------------------------------ construction

        static CheckBox CaseNeon(string texte, bool coche)
        {
            return new CheckBox
            {
                Text = L.T(texte), Checked = coche, AutoSize = true, ForeColor = Theme.Texte, Font = Theme.Petit,
                FlatStyle = FlatStyle.Flat, Margin = new Padding(4, 6, 12, 0), Cursor = Cursors.Hand
            };
        }

        static ContextMenuStrip MenuContextuel(ToolStripRenderer rendu, params ToolStripItem[] items)
        {
            var m = new ContextMenuStrip { Renderer = rendu, Font = Theme.Petit };
            foreach (var item in items) item.Text = L.T(item.Text);
            m.Items.AddRange(items);
            return m;
        }

        // Page : titre, description, barre d'outils facultative et liste encadrée
        Control Page(string titre, string description, Liste liste, params Control[] outils)
        {
            var t = new TableLayoutPanel
            {
                Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, BackColor = Theme.Fond, Padding = new Padding(22, 14, 22, 16), Visible = false
            };
            t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            t.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            t.Controls.Add(new Label { Text = "// " + L.T(titre).ToUpperInvariant(), Font = Theme.TitrePage, ForeColor = Theme.Cyan, AutoSize = true, Margin = new Padding(0, 0, 0, 2) }, 0, 0);
            t.Controls.Add(new Label { Text = L.T(description), Font = Theme.Petit, ForeColor = Theme.TexteDim, AutoSize = true, Margin = new Padding(0, 0, 0, 10) }, 0, 1);
            var barre = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 0, 0, 6), WrapContents = true };
            barre.Controls.AddRange(outils);
            t.Controls.Add(barre, 0, 2);
            var cadre = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bordure, Padding = new Padding(1), Margin = Padding.Empty };
            cadre.Controls.Add(liste);
            t.Controls.Add(cadre, 0, 3);
            contenu.Controls.Add(t);
            pages.Add(t);
            return t;
        }

        BoutonNav Lien(FlowLayoutPanel liens, string texte, Control page, int largeur)
        {
            var b = new BoutonNav(texte, largeur - 1);
            b.Click += (s, e) => Afficher(b, page);
            liens.Controls.Add(b);
            navigation.Add(b);
            return b;
        }

        void Afficher(BoutonNav bouton, Control page)
        {
            foreach (var b in navigation) b.Actif = b == bouton;
            foreach (var p in pages) p.Visible = p == page;
            MarquerLues();
        }

        protected override void SetVisibleCore(bool value)
        {
            // Démarrage en arrière-plan : la fenêtre ne s'affiche pas tant qu'on ne l'ouvre pas
            if (demarrerCache && !IsHandleCreated) { CreateHandle(); value = false; }
            base.SetVisibleCore(value);
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (!quitter && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                Hide();
                if (!astuceMontree)
                {
                    icone.ShowBalloonTip(3000, "deR4Tizer", L.T("L'interface reste dans la zone de notification. Le service, lui, tourne en permanence."), ToolTipIcon.Info);
                    astuceMontree = true;
                }
                return;
            }
            icone.Visible = false;
            base.OnFormClosing(e);
        }

        void Montrer(BoutonNav bouton, Control page)
        {
            Show();
            if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
            Activate();
            if (bouton != null) Afficher(bouton, page);
            MarquerLues();
        }

        // ------------------------------------------------------------ rafraîchissement

        void Rafraichir()
        {
            ServiceControllerStatus? etatService = null;
            try { using (var sc = new ServiceController(Commun.NomService)) etatService = sc.Status; } catch { }
            btnService.Visible = etatService != null && etatService != ServiceControllerStatus.Running;
            var pastilles = new List<Entete.Pastille>();
            pastilles.Add(etatService == ServiceControllerStatus.Running
                ? new Entete.Pastille { Texte = "SERVICE EN LIGNE", Couleur = Theme.Vert }
                : new Entete.Pastille { Texte = etatService == null ? "SERVICE NON INSTALLÉ" : "SERVICE " + Traduire(etatService.Value).ToUpperInvariant(), Couleur = Theme.Rouge, Clignote = true });

            DateTime d0;
            var etat = Commun.Lire<Etat>("etat.json");
            if (etat != null)
            {
                pastilles.Add(etat.JournalDnsActif
                    ? new Entete.Pastille { Texte = "DNS " + etat.IpConnues.ToString("N0") + " IP", Couleur = Theme.Cyan }
                    : new Entete.Pastille { Texte = "DNS INACTIF", Couleur = Theme.Jaune });
                pastilles.Add(new Entete.Pastille
                {
                    Texte = etat.SourceProcessus == "Sysmon" ? "PROCESSUS : SYSMON" : etat.SourceProcessus == "WMI" ? "PROCESSUS : WMI" : "PROCESSUS : —",
                    Couleur = etat.SourceProcessus == "aucune" ? Theme.Jaune : Theme.Cyan
                });
                var actifs = (etat.Peripheriques ?? new List<UsagePeripherique>()).Where(u => u.EnCours).ToList();
                pastilles.Add(actifs.Count == 0
                    ? new Entete.Pastille { Texte = "CAM / MIC OFF", Couleur = Theme.TexteDim }
                    : new Entete.Pastille { Texte = string.Join(" + ", actifs.Select(u => u.Peripherique.ToUpperInvariant() + " : " + u.Programme)), Couleur = Theme.Rouge, Clignote = true });
                if (etat.Panique) pastilles.Insert(0, new Entete.Pastille { Texte = "MODE PANIQUE : INTERNET COUPÉ", Couleur = Theme.Rouge, Clignote = true });
                var def = etat.Defender;
                if (def != null && def.Disponible)
                    pastilles.Add(def.TempsReel && def.Antivirus
                        ? new Entete.Pastille { Texte = def.ProtectionFalsification ? "DEFENDER OK" : "DEFENDER (FALSIFICATION OFF)", Couleur = def.ProtectionFalsification ? Theme.Vert : Theme.Jaune }
                        : new Entete.Pastille { Texte = "DEFENDER DÉSACTIVÉ", Couleur = Theme.Rouge, Clignote = true });
                if (etat.Exposition != null && etat.Exposition.Exposee)
                    pastilles.Insert(1, new Entete.Pastille { Texte = "PC EXPOSÉ À INTERNET", Couleur = Theme.Rouge, Clignote = true });
                paniqueActive = etat.Panique;
                btnPanique.Text = paniqueActive ? "◉ RÉTABLIR INTERNET" : "◉ PANIQUE : COUPER INTERNET";
                if (etat.BureauADistance) pastilles.Add(new Entete.Pastille { Texte = "BUREAU À DISTANCE ACTIF", Couleur = Theme.Rouge, Clignote = true });
                if (etat.OutilsDistants != null && etat.OutilsDistants.Count > 0)
                    pastilles.Add(new Entete.Pastille { Texte = "PRISE EN MAIN : " + string.Join(", ", etat.OutilsDistants.Select(o => o.Nom).Distinct()), Couleur = Theme.Rouge, Clignote = true });

                statut.Text = "▸ mis à jour " + etat.MisAJour + "   ▸ service démarré le " + etat.Demarrage + "   ▸ v" + (etat.Version ?? "?")
                    + (etat.JournalDnsActif ? "" : "   ▸ journal DNS inactif : impossible de repérer les IP contactées directement");
                navVie.Badge = actifs.Count + (etat.OutilsDistants ?? new List<OutilDistant>()).Count + (etat.BureauADistance ? 1 : 0);
                navVie.CouleurBadge = Theme.Rouge;
                navVie.TexteBadge = navVie.Badge > 0 ? "LIVE" : null;
                if (etat.MisAJour != etatVu)
                {
                    etatVu = etat.MisAJour;
                    RemplirFlux(etat.Flux ?? new List<FluxInfo>());
                    RemplirVie(etat);
                    RemplirChaines(etat.Chaines ?? new List<Chaine>());
                    exposition = etat.Exposition;
                    parefeuVu = DateTime.MinValue;
                }
            }

            d0 = DateFichier("parefeu.json");
            if (d0 != parefeuVu)
            {
                parefeuVu = d0;
                RemplirParefeu(exposition, Commun.Lire<List<EvenementRegle>>("parefeu.json") ?? new List<EvenementRegle>());
            }

            d0 = DateFichier("baseline.json");
            if (d0 != baselineVu)
            {
                baselineVu = d0;
                RemplirBaseline(Commun.Lire<EtatBaseline>("baseline.json"));
            }
            d0 = DateFichier("extensions.json");
            if (d0 != extensionsVu)
            {
                extensionsVu = d0;
                RemplirExtensions(Commun.Lire<List<Extension>>("extensions.json") ?? new List<Extension>());
            }
            d0 = DateFichier("quarantaine.json");
            if (d0 != quarantaineVu)
            {
                quarantaineVu = d0;
                RemplirQuarantaine(Commun.Lire<List<ElementQuarantaine>>("quarantaine.json") ?? new List<ElementQuarantaine>());
            }

            DateTime d = DateFichier("menaces.json");
            if (d != menacesVu)
            {
                menacesVu = d;
                RemplirMenaces(Commun.Lire<InfosMenaces>("menaces.json"));
            }
            var infos = Commun.Lire<InfosMenaces>("menaces.json");
            if (infos != null)
                pastilles.Add(new Entete.Pastille { Texte = "INTEL " + (infos.TotalIp + infos.TotalReseaux).ToString("N0") + " IP · " + infos.TotalDomaines.ToString("N0") + " DOM.", Couleur = Theme.Magenta });
            entete.Pastilles = pastilles;
            entete.Invalidate();

            d = DateFichier("demarrage.json");
            if (d != demarrageVu)
            {
                demarrageVu = d;
                demarrage = Commun.Lire<List<EntreeDemarrage>>("demarrage.json") ?? new List<EntreeDemarrage>();
                RemplirDemarrage();
            }
            d = DateFichier("config.json");
            if (d != configVu)
            {
                configVu = d;
                var config = Commun.Lire<Config>("config.json") ?? new Config();
                majCase = true;
                chkBlocageAuto.Checked = config.BlocageAutoMenaces;
                chkRancongiciel.Checked = config.ReponseAutoRancongiciel;
                majCase = false;
            }

            var alertes = Commun.Lire<List<Alerte>>("alertes.json") ?? new List<Alerte>();
            string cleAlertes = alertes.Count + "|" + (alertes.Count > 0 ? alertes[alertes.Count - 1].Id : "");
            if (cleAlertes != alertesVues)
            {
                alertesVues = cleAlertes;
                NotifierNouvelles(alertes);
                RemplirAlertes(alertes);
            }

            var blocages = Commun.Lire<List<Blocage>>("blocages.json") ?? new List<Blocage>();
            string cleBlocages = string.Join("|", blocages.Select(b => b.Type + b.Cible));
            if (cleBlocages != blocagesVus)
            {
                blocagesVus = cleBlocages;
                RemplirBlocages(blocages);
            }
        }

        static string Traduire(ServiceControllerStatus s)
        {
            switch (s)
            {
                case ServiceControllerStatus.Running: return "en marche";
                case ServiceControllerStatus.Stopped: return "arrêté";
                case ServiceControllerStatus.StartPending: return "démarrage…";
                case ServiceControllerStatus.StopPending: return "arrêt…";
                default: return s.ToString();
            }
        }

        static DateTime DateFichier(string nom)
        {
            try { return File.GetLastWriteTime(Path.Combine(Commun.Dossier, nom)); } catch { return DateTime.MinValue; }
        }

        static void Colorer(ListViewItem item, Color fond, Color texte, bool gras)
        {
            item.BackColor = fond;
            item.ForeColor = texte;
            if (gras) item.Font = Theme.MonoGras;
        }

        void RemplirFlux(List<FluxInfo> flux)
        {
            string selection = lvFlux.SelectedItems.Count > 0 ? ((FluxInfo)lvFlux.SelectedItems[0].Tag).Cle : null;
            int haut = lvFlux.TopItem != null ? lvFlux.TopItem.Index : 0;
            lvFlux.BeginUpdate();
            lvFlux.Items.Clear();
            foreach (var f in flux)
            {
                var item = new ListViewItem(new[]
                {
                    f.Score.ToString(), f.Processus, f.Parent ?? "", f.Pid.ToString(), f.NomDns != null ? f.NomDns + "  (" + f.Ip + ")" : f.Ip,
                    f.Port.ToString(), f.Signataire, f.PremiereVue, f.Raisons
                }) { Tag = f, ToolTipText = f.Chemin + (string.IsNullOrEmpty(f.LigneCommande) ? "" : "\n" + f.LigneCommande)
                                            + (string.IsNullOrEmpty(f.Origine) ? "" : "\n" + f.Origine) };
                if (f.Raisons.Contains("MENACE")) Colorer(item, Theme.FondCritique, Theme.Rouge, true);
                else if (f.Raisons.Contains("BLOQUÉ")) item.ForeColor = Theme.TexteDim;
                else if (f.Score >= Commun.SeuilAlerte) Colorer(item, Theme.FondAlerte, Theme.Texte, false);
                else if (f.Score >= 1) Colorer(item, Theme.FondAttention, Theme.Texte, false);
                lvFlux.Items.Add(item);
                if (f.Cle == selection) item.Selected = true;
            }
            lvFlux.EndUpdate();
            if (haut > 0 && haut < lvFlux.Items.Count) lvFlux.TopItem = lvFlux.Items[haut];
            navFlux.Badge = flux.Count;
        }

        void RemplirAlertes(List<Alerte> alertes)
        {
            lvAlertes.BeginUpdate();
            lvAlertes.Items.Clear();
            foreach (var a in Enumerable.Reverse(alertes))
            {
                var item = new ListViewItem(new[]
                {
                    a.Heure, a.Niveau.ToUpperInvariant(), a.Processus, a.Destination, a.Port > 0 ? a.Port.ToString() : "", a.Raisons, a.Chemin
                }) { Tag = a, ToolTipText = a.Raisons };
                bool nonLue = string.CompareOrdinal(a.Heure, derniereLue) > 0;
                if (a.Niveau == "Critique") Colorer(item, Theme.FondCritique, Theme.Rouge, nonLue);
                else if (a.Niveau == "Alerte") Colorer(item, Theme.FondAlerte, Theme.Texte, nonLue);
                else Colorer(item, Theme.Panneau, Theme.TexteDim, nonLue);
                lvAlertes.Items.Add(item);
            }
            lvAlertes.EndUpdate();
            int nonLues = alertes.Count(a => string.CompareOrdinal(a.Heure, derniereLue) > 0);
            navAlertes.Badge = nonLues;
            navAlertes.CouleurBadge = alertes.Any(a => a.Niveau == "Critique" && string.CompareOrdinal(a.Heure, derniereLue) > 0) ? Theme.Rouge : Theme.Magenta;
            icone.Text = nonLues > 0 ? "deR4Tizer : " + nonLues + " alerte(s) non lue(s)" : "deR4Tizer";
            icone.Icon = nonLues > 0 ? iconeAlerte : iconeNormale;
        }

        void NotifierNouvelles(List<Alerte> alertes)
        {
            if (idsConnus == null) { idsConnus = new HashSet<string>(alertes.Select(a => a.Id)); return; }
            var nouvelles = alertes.Where(a => !idsConnus.Contains(a.Id)).ToList();
            foreach (var a in nouvelles) idsConnus.Add(a.Id);
            var graves = nouvelles.Where(a => a.Niveau == "Alerte" || a.Niveau == "Critique").ToList();
            var symbole = graves.Any(a => a.Niveau == "Critique") ? ToolTipIcon.Error : ToolTipIcon.Warning;
            if (graves.Count == 1)
                icone.ShowBalloonTip(8000, "deR4Tizer : " + graves[0].Processus, graves[0].Destination + " : " + graves[0].Raisons, symbole);
            else if (graves.Count > 1)
                icone.ShowBalloonTip(8000, "deR4Tizer", graves.Count + " nouvelles alertes", symbole);
        }

        void MarquerLues()
        {
            if (!Visible || !pageAlertes.Visible) return;
            var alertes = Commun.Lire<List<Alerte>>("alertes.json");
            if (alertes == null || alertes.Count == 0) return;
            string max = alertes.Max(a => a.Heure);
            if (string.CompareOrdinal(max, derniereLue) <= 0) return;
            derniereLue = max;
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(fichierLecture));
                File.WriteAllText(fichierLecture, derniereLue);
            }
            catch { }
            RemplirAlertes(alertes);
        }

        void RemplirBlocages(List<Blocage> blocages)
        {
            lvBlocages.BeginUpdate();
            lvBlocages.Items.Clear();
            foreach (var b in blocages)
                lvBlocages.Items.Add(new ListViewItem(new[] { b.Type == "hosts" ? "hosts" : b.Type == "programme" ? "programme isolé" : "pare-feu", b.Cible, b.Raison, b.Date }) { Tag = b });
            lvBlocages.EndUpdate();
            navBlocages.Badge = blocages.Count;
        }

        void RemplirDemarrage()
        {
            var liste = demarrage.Where(e => !chkMasquerWindows.Checked
                || !(e.Signataire == "Windows (catalogue)" || (e.Signataire ?? "").StartsWith("Microsoft"))).ToList();
            lvDemarrage.BeginUpdate();
            lvDemarrage.Items.Clear();
            foreach (var e in liste.OrderByDescending(x => x.Remarque != "").ThenBy(x => x.Categorie).ThenBy(x => x.Nom))
            {
                var item = new ListViewItem(new[]
                {
                    e.Categorie, e.Nom, e.Commande, e.Signataire == "" ? "NON SIGNÉ" : e.Signataire, e.Remarque, e.Depuis
                }) { Tag = e, ToolTipText = e.Cible };
                if (e.Remarque != "") Colorer(item, e.Signataire == "" ? Theme.FondAlerte : Theme.FondAttention, Theme.Texte, false);
                lvDemarrage.Items.Add(item);
            }
            lvDemarrage.EndUpdate();
            navDemarrage.Badge = liste.Count(e => e.Remarque != "");
            navDemarrage.CouleurBadge = Theme.Jaune;
        }

        void RemplirVie(Etat etat)
        {
            lvVie.BeginUpdate();
            lvVie.Items.Clear();

            lvVie.AjouterSection("Caméra et micro — dernier accès de chaque programme (historique de Windows)");
            // Une ligne par programme et par périphérique : l'utilisation en cours, sinon la plus récente
            var usages = (etat.Peripheriques ?? new List<UsagePeripherique>())
                .GroupBy(u => u.Peripherique + "|" + u.Programme.ToLowerInvariant())
                .Select(g => g.OrderByDescending(u => u.EnCours).ThenByDescending(u => u.DernierDebut).First())
                .OrderByDescending(u => u.EnCours).ThenByDescending(u => u.DernierDebut);
            foreach (var u in usages)
            {
                var item = new ListViewItem(new[]
                {
                    u.Peripherique + (u.EnCours ? "  ● EN COURS" : ""), u.Programme, u.Chemin,
                    u.EnCours ? "depuis " + u.DernierDebut : u.DernierDebut + " → " + u.DerniereFin, ""
                }) { Tag = new FluxInfo { Chemin = u.Chemin } };
                if (u.EnCours) Colorer(item, Theme.FondActif, Theme.Rouge, true);
                lvVie.Items.Add(item);
            }

            lvVie.AjouterSection("Prise en main à distance");
            var bureau = new ListViewItem(new[]
            {
                "Bureau à distance (RDP)", "Windows", etat.BureauADistance ? "ACTIVÉ : ce PC accepte les connexions Bureau à distance" : "désactivé", "", ""
            });
            if (etat.BureauADistance) Colorer(bureau, Theme.FondActif, Theme.Rouge, true);
            lvVie.Items.Add(bureau);
            var outils = etat.OutilsDistants ?? new List<OutilDistant>();
            foreach (var o in outils)
            {
                var item = new ListViewItem(new[] { o.Nom + "  ● EN COURS", Path.GetFileName(o.Chemin), o.Chemin, "depuis " + o.Depuis, o.Signataire })
                    { Tag = new FluxInfo { Chemin = o.Chemin } };
                Colorer(item, Theme.FondActif, Theme.Rouge, true);
                lvVie.Items.Add(item);
            }
            if (outils.Count == 0)
                lvVie.Items.Add(new ListViewItem(new[] { "Outils connus", "", "aucun en cours (AnyDesk, TeamViewer, RustDesk, ScreenConnect, VNC…)", "", "" })
                    { ForeColor = Theme.TexteDim });

            lvVie.AjouterSection("Ports ouverts sur le réseau — un programme attend des connexions entrantes");
            foreach (var e in etat.Ecoutes ?? new List<Ecoute>())
            {
                var item = new ListViewItem(new[]
                {
                    "Port " + e.Port, e.Programme, e.Adresse + ":" + e.Port + "   " + e.Chemin, "depuis " + e.Depuis, e.Signataire
                }) { Tag = new FluxInfo { Chemin = e.Chemin } };
                if (e.Signataire == "-") Colorer(item, Theme.FondAlerte, Theme.Texte, false);
                lvVie.Items.Add(item);
            }
            lvVie.EndUpdate();
        }

        Exposition exposition;

        void RemplirParefeu(Exposition exp, List<EvenementRegle> regles)
        {
            int haut = lvParefeu.TopItem != null ? lvParefeu.TopItem.Index : 0;
            lvParefeu.BeginUpdate();
            lvParefeu.Items.Clear();

            lvParefeu.AjouterSection("Exposition à Internet");
            if (exp == null)
                lvParefeu.Items.Add(new ListViewItem(new[] { "En attente du service", "", "", "" }) { ForeColor = Theme.TexteDim });
            else
            {
                var bilan = new ListViewItem(new[]
                {
                    exp.Exposee ? "PC EXPOSÉ À INTERNET" : "Non exposé",
                    exp.Exposee ? string.Join(" ; ", exp.Raisons ?? new List<string>()) : "aucun paquet venu d'Internet n'a atteint le PC ces dernières 24 h ; pas d'adresse publique sur le PC",
                    "", exp.JournalPaquets ? "journal des paquets actif" : "journal des paquets INACTIF (baseline « journalisation »)"
                });
                if (exp.Exposee) Colorer(bilan, Theme.FondActif, Theme.Rouge, true); else bilan.ForeColor = Theme.Vert;
                lvParefeu.Items.Add(bilan);
                foreach (var e in exp.Entrees ?? new List<EntreeExposee>())
                {
                    var item = new ListViewItem(new[]
                    {
                        "Entrant " + e.Action + " : port " + e.PortLocal + " (" + e.Protocole + ")",
                        "depuis " + e.Source + "  ·  " + e.Nombre + " paquet(s)", e.Programme ?? "", e.Premiere + " → " + e.Derniere
                    });
                    Colorer(item, e.Action == "ACCEPTÉ" ? Theme.FondCritique : Theme.FondAlerte, e.Action == "ACCEPTÉ" ? Theme.Rouge : Theme.Texte, e.Action == "ACCEPTÉ");
                    lvParefeu.Items.Add(item);
                }
            }

            lvParefeu.AjouterSection("Changements de règles du pare-feu (les plus récents d'abord)");
            foreach (var r in Enumerable.Reverse(regles).Take(200))
            {
                bool entrantAutorise = r.Sens == "entrant" && (r.Action ?? "").StartsWith("autoriser") && r.Operation != "supprimée";
                var item = new ListViewItem(new[]
                {
                    "Règle " + r.Operation + " : " + r.Regle,
                    r.Sens + ", " + r.Action + (string.IsNullOrEmpty(r.Ports) ? "" : ", ports " + r.Ports) + (string.IsNullOrEmpty(r.ProgrammeCible) ? "" : ", pour " + r.ProgrammeCible),
                    Path.GetFileName(r.Auteur ?? ""), r.Heure
                }) { ToolTipText = r.Auteur };
                if (r.Operation == "toutes supprimées") Colorer(item, Theme.FondCritique, Theme.Rouge, true);
                else if (entrantAutorise) Colorer(item, Theme.FondAttention, Theme.Texte, false);
                else item.ForeColor = Theme.TexteDim;
                lvParefeu.Items.Add(item);
            }
            if (regles.Count == 0)
                lvParefeu.Items.Add(new ListViewItem(new[] { "Aucun changement de règle depuis l'installation de cette version.", "", "", "" }) { ForeColor = Theme.TexteDim });
            lvParefeu.EndUpdate();
            if (haut > 0 && haut < lvParefeu.Items.Count) lvParefeu.TopItem = lvParefeu.Items[haut];
            navParefeu.TexteBadge = exp != null && exp.Exposee ? "EXPOSÉ" : null;
            navParefeu.CouleurBadge = Theme.Rouge;
            navParefeu.Invalidate();
        }

        void RemplirChaines(List<Chaine> chaines)
        {
            int haut = lvChaines.TopItem != null ? lvChaines.TopItem.Index : 0;
            lvChaines.BeginUpdate();
            lvChaines.Items.Clear();
            foreach (var c in chaines.Where(x => x.Score > 0))
            {
                lvChaines.AjouterSection("score " + c.Score + "  ·  " + c.Resume + "  ·  depuis " + c.Depuis);
                foreach (var n in c.Noeuds ?? new List<NoeudChaine>())
                {
                    string retrait = new string(' ', n.Profondeur * 3) + (n.Profondeur > 0 ? "└─ " : "");
                    var item = new ListViewItem(new[] { retrait + n.Nom, n.Pid.ToString(), n.Score > 0 ? n.Score.ToString() : "", n.Raisons, n.LigneCommande })
                        { Tag = n, ToolTipText = n.Chemin + (string.IsNullOrEmpty(n.LigneCommande) ? "" : "\n" + n.LigneCommande) };
                    if (c.Score >= 12 && n.Score > 0) Colorer(item, Theme.FondCritique, Theme.Rouge, true);
                    else if (n.Score >= 3) Colorer(item, Theme.FondAlerte, Theme.Texte, false);
                    else if (n.Score > 0) Colorer(item, Theme.FondAttention, Theme.Texte, false);
                    else item.ForeColor = Theme.TexteDim;
                    lvChaines.Items.Add(item);
                }
            }
            if (lvChaines.Items.Count == 0)
                lvChaines.Items.Add(new ListViewItem(new[] { "Aucune chaîne suspecte en ce moment.", "", "", "", "" }) { ForeColor = Theme.TexteDim });
            lvChaines.EndUpdate();
            if (haut > 0 && haut < lvChaines.Items.Count) lvChaines.TopItem = lvChaines.Items[haut];
            int max = chaines.Count > 0 ? chaines.Max(c => c.Score) : 0;
            navChaines.Badge = chaines.Count(c => c.Score >= 3);
            navChaines.CouleurBadge = max >= 12 ? Theme.Rouge : Theme.Jaune;
        }

        void RemplirBaseline(EtatBaseline b)
        {
            lvBaseline.BeginUpdate();
            lvBaseline.Items.Clear();
            if (b == null || b.Regles == null)
            {
                lvBaseline.Items.Add(new ListViewItem(new[] { "Le service n'a pas encore évalué la baseline (toutes les 10 minutes).", "", "", "", "" }) { ForeColor = Theme.TexteDim });
                lvBaseline.EndUpdate();
                return;
            }
            var noms = new Dictionary<string, string> { { "journalisation", "Journalisation (appliquée automatiquement)" }, { "recommandé", "Recommandé" }, { "renforcé", "Renforcé (peut gêner certains logiciels)" } };
            foreach (var profil in new[] { "journalisation", "recommandé", "renforcé" })
            {
                int score;
                b.Scores.TryGetValue(profil, out score);
                lvBaseline.AjouterSection(noms[profil] + "  ·  " + score + " % conforme");
                foreach (var r in b.Regles.Where(x => x.Profil == profil).OrderBy(x => x.Categorie))
                {
                    var item = new ListViewItem(new[] { r.Categorie + " : " + r.Titre, r.Etat + (r.Appliquee ? " ✓" : ""), r.Actuel, r.Attendu, r.Compat })
                        { Tag = r, ToolTipText = r.Pourquoi };
                    if (r.Etat == "conforme") item.ForeColor = Theme.Vert;
                    else if (r.Etat == "non conforme") Colorer(item, profil == "renforcé" ? Theme.Panneau : Theme.FondAttention, Theme.Texte, false);
                    else item.ForeColor = Theme.TexteDim;
                    lvBaseline.Items.Add(item);
                }
            }
            lvBaseline.EndUpdate();
            int rec;
            b.Scores.TryGetValue("recommandé", out rec);
            lblBaseline.Text = "Recommandé : " + rec + " %";
            lblBaseline.ForeColor = rec >= 90 ? Theme.Vert : rec >= 50 ? Theme.Jaune : Theme.Rouge;
            navBaseline.TexteBadge = rec + "%";
            navBaseline.CouleurBadge = rec >= 90 ? Theme.Vert : rec >= 50 ? Theme.Jaune : Theme.Rouge;
            navBaseline.Invalidate();
            if (!string.IsNullOrEmpty(b.Message)) detailBaseline.Text = "Dernière opération : " + b.Message;
        }

        void RemplirExtensions(List<Extension> extensions)
        {
            lvExtensions.BeginUpdate();
            lvExtensions.Items.Clear();
            foreach (var e in extensions)
            {
                var item = new ListViewItem(new[] { e.Navigateur, e.Nom, e.Version, e.Permissions, e.Depuis }) { Tag = e, ToolTipText = e.Id + "\n" + e.Permissions };
                if (e.Dangereuse) Colorer(item, Theme.FondAttention, Theme.Texte, false);
                lvExtensions.Items.Add(item);
            }
            lvExtensions.EndUpdate();
            navExtensions.Badge = extensions.Count;
            navExtensions.CouleurBadge = Theme.Cyan;
        }

        void RemplirQuarantaine(List<ElementQuarantaine> liste)
        {
            lvQuarantaine.BeginUpdate();
            lvQuarantaine.Items.Clear();
            foreach (var q in Enumerable.Reverse(liste))
                lvQuarantaine.Items.Add(new ListViewItem(new[] { q.Date, q.CheminOrigine, q.Raison, (q.Taille / 1024).ToString("N0") + " Ko" }) { Tag = q });
            lvQuarantaine.EndUpdate();
            navQuarantaine.Badge = liste.Count;
        }

        void DetaillerAlerte()
        {
            if (lvAlertes.SelectedItems.Count == 0) return;
            var a = lvAlertes.SelectedItems[0].Tag as Alerte;
            if (a == null) return;
            detailAlerte.Text = (string.IsNullOrEmpty(a.Mitre) ? "" : "TECHNIQUE : " + a.Mitre + "\n")
                + (string.IsNullOrEmpty(a.Conseil) ? "" : "QUE FAIRE : " + a.Conseil + "\n")
                + a.Raisons;
        }

        void DetaillerRegle()
        {
            if (lvBaseline.SelectedItems.Count == 0) return;
            var r = lvBaseline.SelectedItems[0].Tag as EtatRegle;
            if (r == null) return;
            detailBaseline.Text = r.Titre + " : " + r.Pourquoi + (string.IsNullOrEmpty(r.Compat) ? "" : "\nCompatibilité : " + r.Compat)
                + (r.Appliquee ? "\nAppliquée par deR4Tizer (réversible)." : "");
        }

        string ReglesSelectionnees()
        {
            return string.Join(",", lvBaseline.SelectedItems.Cast<ListViewItem>().Select(i => i.Tag as EtatRegle).Where(r => r != null).Select(r => r.Id));
        }

        void OperationBaseline(string operation, string cible, string question)
        {
            if (operation != "evaluer" && string.IsNullOrEmpty(cible))
            {
                MessageBox.Show("Sélectionnez d'abord une ou plusieurs règles (Ctrl+clic).", "deR4Tizer", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (question != null && MessageBox.Show(question, "deR4Tizer : baseline", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            detailBaseline.Text = "Opération en cours…";
            Canal.Executer(new Commande { Action = "baseline", Valeur = operation, Cible = cible });
        }

        void ChangerReglage(CheckBox c, string reglage)
        {
            if (majCase) return;
            Canal.Executer(new Commande { Action = "config", Cible = reglage, Valeur = c.Checked ? "true" : "false" });
            configVu = DateTime.MinValue;
            Rafraichir();
        }

        void Panique()
        {
            string question = paniqueActive
                ? "Rétablir l'accès à Internet pour tous les programmes ?"
                : "Couper Internet pour tous les programmes (sauf composants de Windows) et fermer les connexions en cours ?\n\nÀ utiliser si vous pensez qu'un attaquant ou un rançongiciel est actif.";
            if (MessageBox.Show(question, "deR4Tizer : PANIQUE", MessageBoxButtons.YesNo, paniqueActive ? MessageBoxIcon.Question : MessageBoxIcon.Warning) != DialogResult.Yes) return;
            Canal.Executer(new Commande { Action = "panique", Valeur = paniqueActive ? "off" : "on" });
            etatVu = "";
            Rafraichir();
        }

        // Action de réponse sur l'élément sélectionné d'une liste (flux, alerte, nœud de chaîne, entrée de démarrage)
        void Agir(ListView lv, string action)
        {
            if (lv.SelectedItems.Count == 0) return;
            var tag = lv.SelectedItems[0].Tag;
            int? pid = null;
            string chemin = null, nom = null;
            var f = tag as FluxInfo;
            var a = tag as Alerte;
            var n = tag as NoeudChaine;
            var d = tag as EntreeDemarrage;
            if (f != null) { pid = f.Pid; chemin = f.Chemin; nom = f.Processus; }
            else if (a != null) { pid = a.Pid; chemin = a.Chemin; nom = a.Processus; }
            else if (n != null) { pid = n.Pid; chemin = n.Chemin; nom = n.Nom; }
            else if (d != null) { chemin = d.Cible; nom = d.Nom; }
            bool besoinPid = action == "tuer" || action == "tuerChaine" || action == "suspendre" || action == "reprendre";
            if (besoinPid && (pid == null || pid <= 4)) { MessageBox.Show("Processus inconnu pour cet élément.", "deR4Tizer"); return; }
            if (!besoinPid && string.IsNullOrEmpty(chemin)) { MessageBox.Show("Chemin du programme inconnu pour cet élément.", "deR4Tizer"); return; }
            var libelles = new Dictionary<string, string>
            {
                { "tuer", "Tuer le processus " + nom + " (PID " + pid + ") ?" },
                { "tuerChaine", "Tuer " + nom + " (PID " + pid + ") et tous les processus qu'il a lancés ?" },
                { "suspendre", "Suspendre " + nom + " (PID " + pid + ") ? Il restera figé jusqu'à ce que vous le repreniez ou le tuiez." },
                { "reprendre", "Reprendre " + nom + " (PID " + pid + ") ?" },
                { "quarantaine", "Arrêter le programme et déplacer le fichier en quarantaine ?\n\n" + chemin },
                { "isolerProgramme", "Couper ce programme du réseau (entrant et sortant) ?\n\n" + chemin }
            };
            if (MessageBox.Show(libelles[action], "deR4Tizer : réponse", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            Canal.Executer(new Commande
            {
                Action = action, Cible = besoinPid ? pid.ToString() : chemin, Raison = "action manuelle sur " + nom
            });
            etatVu = "";
            Rafraichir();
        }

        void RemplirMenaces(InfosMenaces infos)
        {
            lvMenaces.BeginUpdate();
            lvMenaces.Items.Clear();
            if (infos != null)
                foreach (var s in infos.Sources ?? new List<SourceMenace>())
                {
                    var item = new ListViewItem(new[] { s.Nom, s.Type, s.Confiance, s.Entrees.ToString("N0"), s.MisAJour ?? "", s.Statut ?? "" });
                    if (s.Statut != "ok") item.ForeColor = Theme.Rouge;
                    else if (s.Confiance == "haute") item.ForeColor = Theme.Cyan;
                    lvMenaces.Items.Add(item);
                }
            lvMenaces.EndUpdate();
            lblMenaces.Text = infos == null ? "Listes pas encore chargées."
                : string.Format("{0:N0} IP, {1:N0} réseaux et {2:N0} domaines malveillants connus · rechargées le {3}",
                    infos.TotalIp, infos.TotalReseaux, infos.TotalDomaines, infos.MisAJour);
        }

        // ------------------------------------------------------------ actions

        void BloquerFlux(bool ipSeulement)
        {
            if (lvFlux.SelectedItems.Count == 0) return;
            var f = (FluxInfo)lvFlux.SelectedItems[0].Tag;
            Bloquer(f.Processus, f.Ip, ipSeulement ? null : f.NomDns);
        }

        void BloquerAlerte()
        {
            if (lvAlertes.SelectedItems.Count == 0) return;
            var a = (Alerte)lvAlertes.SelectedItems[0].Tag;
            if (string.IsNullOrEmpty(a.Ip) && string.IsNullOrEmpty(a.NomDns)) return;
            Bloquer(a.Processus, a.Ip, a.NomDns);
        }

        void Bloquer(string processus, string ip, string nomDns)
        {
            string question = !string.IsNullOrEmpty(nomDns)
                ? "Rediriger " + nomDns + " vers 127.0.0.1 dans le fichier hosts ?" + (ip != null ? "\nLes connexions en cours vers " + ip + " seront coupées." : "")
                : "Bloquer au pare-feu toutes les connexions sortantes vers " + ip + " ?\n\nAttention : une même IP peut servir à plusieurs sites (Cloudflare, Google…). La bloquer peut casser d'autres services.";
            if (MessageBox.Show(question, "deR4Tizer : " + processus, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            Canal.Executer(new Commande { Action = "bloquer", Ip = ip, NomDns = string.IsNullOrEmpty(nomDns) ? null : nomDns, Raison = "flux de " + processus });
            Rafraichir();
        }

        void DebloquerSelection()
        {
            if (lvBlocages.SelectedItems.Count == 0) return;
            var b = (Blocage)lvBlocages.SelectedItems[0].Tag;
            Canal.Executer(new Commande { Action = "debloquer", Type = b.Type, Cible = b.Cible });
            Rafraichir();
        }

        void ToutDebloquer()
        {
            if (MessageBox.Show("Retirer tous les blocages deR4Tizer (fichier hosts et pare-feu) ?", "deR4Tizer",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            Canal.Executer(new Commande { Action = "toutDebloquer" });
            Rafraichir();
        }

        void DialogueTelemetrie()
        {
            using (var d = new Form
            {
                Text = "Bloquer la télémétrie", Size = new Size(520, 380), FormBorderStyle = FormBorderStyle.FixedDialog,
                StartPosition = FormStartPosition.CenterParent, MinimizeBox = false, MaximizeBox = false, Font = Theme.Petit,
                Padding = new Padding(16), ShowIcon = false
            })
            {
                Theme.FenetreSombre(d);
                var liste = new CheckedListBox
                {
                    Dock = DockStyle.Top, Height = 120, CheckOnClick = true, BackColor = Theme.Panneau, ForeColor = Theme.Texte,
                    BorderStyle = BorderStyle.None, Font = Theme.Mono
                };
                foreach (var k in Commun.Telemetrie.Keys)
                    liste.Items.Add(k + " (" + Commun.Telemetrie[k].Length + " domaines)", !k.StartsWith("Microsoft"));
                var avertissement = new Label
                {
                    Dock = DockStyle.Top, Height = 100, ForeColor = Theme.TexteDim, Padding = new Padding(0, 10, 0, 0),
                    Text = "Les domaines cochés seront redirigés vers 127.0.0.1 dans le fichier hosts.\n\n" +
                           "Microsoft Defender considère le blocage des domaines Microsoft comme une modification " +
                           "suspecte (HostsFileHijack) et peut annuler ces lignes : c'est pourquoi ils ne sont pas cochés."
                };
                var ok = new BoutonNeon("Bloquer", Theme.Cyan) { DialogResult = DialogResult.OK, Dock = DockStyle.Bottom, AutoSize = false, Height = 34 };
                d.Controls.Add(avertissement);
                d.Controls.Add(liste);
                d.Controls.Add(ok);
                d.AcceptButton = ok;
                if (d.ShowDialog(this) != DialogResult.OK) return;
                var cles = Commun.Telemetrie.Keys.ToList();
                var choix = liste.CheckedIndices.Cast<int>().Select(i => cles[i]).ToList();
                if (choix.Count == 0) return;
                Canal.Executer(new Commande { Action = "telemetrie", Categories = choix });
                Rafraichir();
            }
        }

        void DemarrerService()
        {
            try
            {
                var p = Process.Start(new ProcessStartInfo("sc.exe", "start " + Commun.NomService)
                {
                    Verb = "runas", UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden
                });
                if (p != null) p.WaitForExit();
            }
            catch (Win32Exception) { }
            Rafraichir();
        }

        static void Emplacement(ListView lv)
        {
            if (lv.SelectedItems.Count == 0) return;
            var tag = lv.SelectedItems[0].Tag;
            var f = tag as FluxInfo;
            var a = tag as Alerte;
            var d = tag as EntreeDemarrage;
            var n = tag as NoeudChaine;
            string chemin = f != null ? f.Chemin : a != null ? a.Chemin : d != null ? d.Cible : n != null ? n.Chemin : null;
            if (!string.IsNullOrEmpty(chemin) && File.Exists(chemin)) Process.Start("explorer.exe", "/select,\"" + chemin + "\"");
        }

        static void Copier(ListView lv)
        {
            if (lv.SelectedItems.Count == 0) return;
            var item = lv.SelectedItems[0];
            Clipboard.SetText(string.Join("\t", item.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(s => s.Text)));
        }

        static void Ouvrir(string chemin)
        {
            if (File.Exists(chemin) || Directory.Exists(chemin)) Process.Start("explorer.exe", "\"" + chemin + "\"");
        }
    }

    static class Programme
    {
        [STAThread]
        static int Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            int i = Array.IndexOf(args, "--dossier");
            if (i >= 0 && i + 1 < args.Length) Commun.Dossier = args[i + 1];

            // Mode « assistant » : lancé en administrateur par l'interface pour transmettre une commande au service
            if (args.Length == 2 && args[0] == "--commande")
            {
                var c = Commun.Json().Deserialize<Commande>(Encoding.UTF8.GetString(Convert.FromBase64String(args[1])));
                var r = Canal.Envoyer(c);
                Canal.Afficher(r);
                return r.Ok ? 0 : 1;
            }

            var cfg = Commun.Lire<Config>("config.json");
            L.En = cfg != null && cfg.Langue == "en";

            bool premier;
            // Une seule interface à la fois, sauf pour un dossier de données de test
            using (new Mutex(true, i >= 0 ? "deR4Tizer.Interface." + Guid.NewGuid() : "deR4Tizer.Interface", out premier))
            {
                if (!premier) return 0;
                Application.Run(new Fenetre(args.Contains("--cache")));
            }
            return 0;
        }
    }
}
