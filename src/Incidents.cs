// Pages Incidents et Santé (phase 4, PR 4.6). L'interface lit suivi-incidents.json, chronologies\, etat.json et notifications.json,
// sans droit nouveau ; les transitions passent par le canal (assistant élevé). Décisions pures dans VueIncidents et VueSante,
// vérifiées par tests\test-incidents-interface.ps1.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace DeR4Tizer
{
    public class ResumeAlerteIncident
    {
        public string Heure { get; set; }
        public string Niveau { get; set; }
        public string Regle { get; set; }
        public string Processus { get; set; }
        public string Chemin { get; set; }
        public string Destination { get; set; }
        public string Raisons { get; set; }
    }

    public class TransitionIncident
    {
        public string Heure { get; set; }
        public string De { get; set; }
        public string Vers { get; set; }
        public string Motif { get; set; }
        public string Auteur { get; set; }
        public string Note { get; set; }
    }

    public class IncidentSuivi
    {
        public string Id { get; set; }
        public string Ouverture { get; set; }
        public string DerniereActiviteUtc { get; set; }
        public string Niveau { get; set; }
        public string Entite { get; set; }
        public List<string> Regles { get; set; }
        public string Etat { get; set; }
        public string MotifCloture { get; set; }
        public string Precedent { get; set; }
        public List<ResumeAlerteIncident> Alertes { get; set; }
        public int NombreAlertes { get; set; }
        public List<TransitionIncident> Transitions { get; set; }
    }

    public class ElementChronologie
    {
        public string Heure { get; set; }
        public string Source { get; set; }
        public string Type { get; set; }
        public string Niveau { get; set; }
        public string Texte { get; set; }
        public bool ParNom { get; set; }
    }

    public class ChronologieIncident
    {
        public string CalculeeUtc { get; set; }
        public List<ElementChronologie> Elements { get; set; }
        public bool Tronquee { get; set; }
        public int SansHeureUtc { get; set; }
        public long PertesSiem { get; set; }
        public bool FenetreSiemIncomplete { get; set; }
    }

    public class EtatRemontee
    {
        public bool NtfyConfigure { get; set; }
        public bool TeamsConfigure { get; set; }
        public bool SmtpMotDePasse { get; set; }
        public long Envoyes { get; set; }
        public string DernierEnvoi { get; set; }
        public string DerniereErreur { get; set; }
        public string EchecDepuis { get; set; }
        public int EnAttente { get; set; }
        public long Abandonnees { get; set; }
        public string DernierBattement { get; set; }
    }

    public static class VueIncidents
    {
        public const int MaxNote = 300;

        static string MotifTexte(string m)
        {
            return m == "Resolu" ? L.T("résolu") : m == "FauxPositif" ? L.T("faux positif") : m == "Accepte" ? L.T("risque accepté") : m ?? "";
        }

        public static string EtatEnTexte(string etat)
        {
            return etat == "PrisEnCharge" ? L.T("Pris en charge") : etat == "Clos" ? L.T("Clos") : L.T("Ouvert");
        }

        // L'état en texte, jamais la couleur seule
        public static string EtatComplet(IncidentSuivi i)
        {
            string e = EtatEnTexte(i.Etat);
            return i.Etat == "Clos" && !string.IsNullOrEmpty(i.MotifCloture) ? e + " : " + MotifTexte(i.MotifCloture) : e;
        }

        // Mêmes transitions que incidents.rs : le service reste seul juge
        public static bool Permise(string de, string vers)
        {
            de = de ?? "Ouvert";
            return (de == "Ouvert" && (vers == "PrisEnCharge" || vers == "Clos")) || (de == "PrisEnCharge" && vers == "Clos") || (de == "Clos" && vers == "Ouvert");
        }

        // Identifiant utilisable comme nom de fichier, comme validation.rs (le fichier appartient au service, mais rien n'est lu ailleurs)
        public static bool IdentifiantValide(string id)
        {
            return !string.IsNullOrEmpty(id) && id.Length <= 64 && id.All(c => (c < 128 && char.IsLetterOrDigit(c)) || c == '-');
        }

        // Non clos d'abord, puis la dernière activité la plus récente
        public static List<IncidentSuivi> Trier(IEnumerable<IncidentSuivi> l)
        {
            return l.OrderBy(i => i.Etat == "Clos" ? 1 : 0).ThenByDescending(i => i.DerniereActiviteUtc ?? "", StringComparer.Ordinal).ToList();
        }

        public static Commande Transition(string id, string vers, string motif, string note)
        {
            return new Commande { Action = "incident", Cible = id, Valeur = vers, Type = motif ?? "", Raison = note ?? "" };
        }

        // Une note refusée par le service l'est déjà ici (incidents.rs) : rend le texte d'erreur, ou vide
        public static string NoteRefusee(string note)
        {
            if (string.IsNullOrEmpty(note)) return "";
            if (note.Length > MaxNote) return string.Format(L.T("Note de {0} caractères au plus."), MaxNote);
            return note.Any(c => char.IsControl(c) || char.GetUnicodeCategory(c) == UnicodeCategory.Format) ? L.T("La note ne doit contenir ni retour à la ligne ni caractère de mise en forme.") : "";
        }

        // Panneau de détails : résumé, alertes, chronologie, transitions. Textes venus des fichiers passés par Canal.Visible : ils
        // décrivent le poste, un programme peut y avoir mis ce qu'il veut
        public static string Detail(IncidentSuivi i, ChronologieIncident c)
        {
            Func<string, string> v = Canal.Visible;
            var s = new StringBuilder();
            s.AppendLine(EtatComplet(i) + " — " + v(i.Niveau) + " — " + v(i.Entite));
            s.AppendLine(L.T("Ouvert le") + " " + v(i.Ouverture) + " ; " + L.T("règles") + " : " + string.Join(", ", (i.Regles ?? new List<string>()).Select(v)) + " ; " + L.T("alertes") + " : " + i.NombreAlertes);
            if (!string.IsNullOrEmpty(i.Precedent)) s.AppendLine(L.T("Récidive : incident clos précédent") + " " + v(i.Precedent));
            s.AppendLine();
            s.AppendLine("-- " + L.T("Alertes"));
            foreach (var a in i.Alertes ?? new List<ResumeAlerteIncident>())
                s.AppendLine(v(a.Heure) + "  " + v(a.Niveau) + "  " + v(a.Regle) + "  " + v(a.Processus) + "  " + v(a.Destination) + "  " + v(a.Raisons));
            if (i.NombreAlertes > (i.Alertes == null ? 0 : i.Alertes.Count))
                s.AppendLine(string.Format(L.T("(alertes gardées ici : {0} sur {1})"), i.Alertes == null ? 0 : i.Alertes.Count, i.NombreAlertes));
            s.AppendLine();
            s.AppendLine("-- " + L.T("Chronologie"));
            if (c == null) s.AppendLine(L.T("Pas encore calculée, ou illisible."));
            else
            {
                foreach (var e in c.Elements ?? new List<ElementChronologie>())
                    s.AppendLine(v(e.Heure) + "  " + v(e.Source) + "  " + v(e.Texte) + (e.ParNom ? "  " + L.T("[rattaché par le seul nom du fichier]") : ""));
                // Une chronologie incomplète le dit : des étapes peuvent manquer
                if (c.Tronquee) s.AppendLine(L.T("Tronquée : seuls les premiers et les derniers éléments sont gardés."));
                if (c.FenetreSiemIncomplete) s.AppendLine(L.T("Lecture des événements incomplète : des étapes peuvent manquer."));
                if (c.PertesSiem > 0) s.AppendLine(string.Format(L.T("{0} événement(s) perdus depuis le démarrage du service : des étapes peuvent manquer."), c.PertesSiem));
                if (c.SansHeureUtc > 0) s.AppendLine(string.Format(L.T("{0} événement(s) sans heure UTC, non placés."), c.SansHeureUtc));
                s.AppendLine(L.T("Calculée (UTC) :") + " " + v(c.CalculeeUtc));
            }
            s.AppendLine();
            s.AppendLine("-- " + L.T("Transitions"));
            if (i.Transitions == null || i.Transitions.Count == 0) s.AppendLine(L.T("Aucune."));
            foreach (var t in i.Transitions ?? new List<TransitionIncident>())
                s.AppendLine(v(t.Heure) + "  " + EtatEnTexte(t.De) + " → " + EtatEnTexte(t.Vers) + (string.IsNullOrEmpty(t.Motif) ? "" : " (" + MotifTexte(t.Motif) + ")") + "  " + v(t.Auteur) + (string.IsNullOrEmpty(t.Note) ? "" : "  « " + v(t.Note) + " »"));
            return s.ToString();
        }
    }

    public class LigneSante
    {
        public string Sujet { get; set; }
        public string Etat { get; set; }
        public string Date { get; set; }
        public string Detail { get; set; }
        public string Source { get; set; }
        public int Gravite { get; set; }       // 0 normal, 1 à vérifier, 2 risque confirmé
    }

    public static class VueSante
    {
        // Collectes critiques pour SAN-001 : mêmes que sante.rs
        static readonly string[] Critiques = { "JournalDefender", "EtatDefender", "JournalSecurite", "Connexions", "Processus", "ListesMenaces", "Persistance" };
        const int DelaiConstatMinutes = 30;
        const int DelaiEtatAncienMinutes = 2;

        static bool Date(string s, out DateTime d)
        {
            return DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out d);
        }

        static bool DepuisPlusDe(string depuis, int minutes, DateTime maintenant)
        {
            DateTime d;
            return Date(depuis, out d) && (maintenant - d).TotalMinutes > minutes;
        }

        // etat.json trop vieux : le service peut être arrêté, bloqué, ou n'écrit plus ce fichier (audit de #104, S104-14). Illisible vaut ancien
        public static bool EtatAncien(Etat e, DateTime maintenant)
        {
            DateTime d;
            return e != null && (!Date(e.MisAJour, out d) || (maintenant - d).TotalMinutes > DelaiEtatAncienMinutes);
        }

        static bool CritiqueEnPanne(EtatCollecte c, DateTime maintenant)
        {
            if (c == null || !Critiques.Contains(c.Id)) return false;
            // « Inconnue » au démarrage n'est pas une panne ; jamais lue après le délai du constat, si
            return c.Etat == "Indisponible" || (c.Etat == "Inconnue" && DepuisPlusDe(c.Depuis, DelaiConstatMinutes, maintenant));
        }

        // Pastille d'en-tête : 0 rien ; 1 à vérifier, en jaune ; 2 rouge, seulement si Defender est aveugle (SAN-003 : journal et état
        // illisibles depuis plus de 30 min). Le rouge est réservé aux risques confirmés
        public static int NiveauPastille(Etat e, DateTime maintenant)
        {
            if (e == null || e.Collectes == null) return 0;
            Func<string, bool> aveugle = id => e.Collectes.Any(c => c.Id == id && c.Etat == "Indisponible" && DepuisPlusDe(c.Depuis, DelaiConstatMinutes, maintenant));
            if (aveugle("JournalDefender") && aveugle("EtatDefender")) return 2;
            return e.Collectes.Any(c => CritiqueEnPanne(c, maintenant)) ? 1 : 0;
        }

        public static string TextePastille(int niveau)
        {
            return niveau == 2 ? L.T("SANTÉ : DEFENDER NON SURVEILLÉ") : niveau == 1 ? L.T("SANTÉ : À VÉRIFIER") : "";
        }

        static string EtatCollecteTexte(string etat)
        {
            return etat == "Active" ? L.T("active") : etat == "Partielle" ? L.T("partielle") : etat == "Indisponible" ? L.T("indisponible")
                : etat == "Desactivee" ? L.T("désactivée") : L.T("pas encore lue");
        }

        // Chaque ligne dit sa source et sa date de vérification
        public static List<LigneSante> Lignes(Etat e, EtatRemontee r, DateTime maintenant)
        {
            Func<string, string> v = Canal.Visible;
            var l = new List<LigneSante>();
            if (e == null)
            {
                l.Add(new LigneSante { Sujet = L.T("Service"), Etat = L.T("état illisible"), Date = "", Detail = L.T("etat.json absent ou illisible : le service est peut-être arrêté."), Source = "etat.json", Gravite = 1 });
                return l;
            }
            bool ancien = EtatAncien(e, maintenant);
            l.Add(new LigneSante
            {
                Sujet = L.T("Service"),
                Etat = ancien ? L.T("état ancien") : L.T("en marche"),
                Date = v(e.MisAJour),
                Detail = (ancien ? L.T("Cet état n'est plus à jour : tout ce qui suit peut être ancien ; service à vérifier.") + " " : "") + L.T("Version") + " " + v(e.Version) + ", " + L.T("démarré le") + " " + v(e.Demarrage),
                Source = "etat.json",
                Gravite = ancien ? 1 : 0
            });
            l.Add(new LigneSante
            {
                Sujet = L.T("Protection du dossier de données"),
                Etat = string.IsNullOrEmpty(e.ProtectionDonnees) ? L.T("vérifiée") : L.T("en échec"),
                Date = v(e.MisAJour),
                Detail = string.IsNullOrEmpty(e.ProtectionDonnees) ? "" : v(e.ProtectionDonnees),
                Source = "etat.json",
                Gravite = string.IsNullOrEmpty(e.ProtectionDonnees) ? 0 : 1
            });
            l.Add(new LigneSante
            {
                Sujet = L.T("Interface par session"),
                Etat = L.T("non publié"),
                Date = "",
                Detail = L.T("Le service ne publie pas cet état : une interface absente lève SAN-010 ou SAN-011, dans la page Alertes."),
                Source = L.T("aucune"),
                Gravite = 0
            });
            if (r == null)
                l.Add(new LigneSante { Sujet = L.T("Remontée"), Etat = L.T("état illisible"), Date = "", Detail = L.T("notifications.json absent ou illisible."), Source = "notifications.json", Gravite = 1 });
            else
            {
                bool configuree = r.NtfyConfigure || r.TeamsConfigure || r.SmtpMotDePasse;
                bool enEchec = !string.IsNullOrEmpty(r.EchecDepuis);
                l.Add(new LigneSante
                {
                    Sujet = L.T("Remontée"),
                    Etat = !configuree ? L.T("non configurée") : enEchec ? L.T("en échec") : L.T("active"),
                    Date = v(r.DernierEnvoi),
                    Detail = string.Format(L.T("{0} envoi(s), {1} en attente, {2} abandonnée(s)"), r.Envoyes, r.EnAttente, r.Abandonnees)
                        + (enEchec ? " ; " + L.T("échec depuis") + " " + v(r.EchecDepuis) + (string.IsNullOrEmpty(r.DerniereErreur) ? "" : " : " + v(r.DerniereErreur)) : ""),
                    Source = "notifications.json",
                    Gravite = enEchec ? 1 : 0
                });
            }
            foreach (var c in e.Collectes ?? new List<EtatCollecte>())
            {
                bool panne = c.Etat == "Indisponible" || (c.Etat == "Inconnue" && DepuisPlusDe(c.Depuis, DelaiConstatMinutes, maintenant));
                bool partielle = c.Etat == "Partielle";
                l.Add(new LigneSante
                {
                    Sujet = v(c.Id),
                    Etat = EtatCollecteTexte(c.Etat),
                    Date = string.IsNullOrEmpty(c.DernierSucces) ? "" : L.T("lue le") + " " + v(c.DernierSucces),
                    // La conséquence d'abord : c'est ce qui compte, et la colonne peut couper la fin
                    Detail = string.Join(" ; ", new[] { panne || partielle ? Couverture.Consequence(c.Id) : "", v(c.Raison), string.IsNullOrEmpty(c.Depuis) ? "" : L.T("depuis") + " " + v(c.Depuis) }.Where(x => x != "")),
                    Source = "etat.json",
                    Gravite = panne || partielle ? 1 : 0
                });
            }
            return l;
        }
    }

    class PageIncidents : TableLayoutPanel
    {
        readonly Liste liste = new Liste();
        readonly TextBox detail = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, BackColor = Theme.Panneau2, ForeColor = Theme.Texte, Font = Theme.Mono, BorderStyle = BorderStyle.None };
        readonly Label resume = new Label { AutoSize = true, ForeColor = Theme.TexteDim, Font = Theme.Petit, Margin = new Padding(12, 8, 0, 0) };
        readonly BoutonNeon btnPrendre = new BoutonNeon("Prendre en charge", Theme.Cyan), btnClore = new BoutonNeon("Clore…", Theme.Cyan), btnRouvrir = new BoutonNeon("Rouvrir", Theme.TexteDim);
        readonly System.Windows.Forms.Timer minuteur = new System.Windows.Forms.Timer { Interval = 15000 };
        List<IncidentSuivi> incidents = new List<IncidentSuivi>();
        int chargement;

        public PageIncidents()
        {
            Dock = DockStyle.Fill; ColumnCount = 1; RowCount = 5; BackColor = Theme.Fond; Padding = new Padding(22, 14, 22, 14);
            RowStyles.Add(new RowStyle(SizeType.AutoSize));
            RowStyles.Add(new RowStyle(SizeType.AutoSize));
            RowStyles.Add(new RowStyle(SizeType.AutoSize));
            RowStyles.Add(new RowStyle(SizeType.Percent, 45));
            RowStyles.Add(new RowStyle(SizeType.Percent, 55));
            Controls.Add(new Label { Text = "// " + L.T("Incidents").ToUpperInvariant(), Font = Theme.TitrePage, ForeColor = Theme.Cyan, AutoSize = true, Margin = new Padding(0, 0, 0, 4) }, 0, 0);
            Controls.Add(new Label { Text = L.T("Alertes regroupées par programme ou destination, à suivre jusqu'à leur clôture. Sélectionnez un incident pour voir ses alertes, sa chronologie et ses transitions."), Font = Theme.Petit, ForeColor = Theme.TexteDim, AutoSize = true, Margin = new Padding(0, 0, 0, 10) }, 0, 1);
            var barre = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 0, 0, 6), BackColor = Theme.Fond };
            barre.Controls.AddRange(new Control[] { btnPrendre, btnClore, btnRouvrir, resume });
            Controls.Add(barre, 0, 2);
            liste.Colonnes("État", 170, "Niveau", 80, "Entité", 340, "Règles", 170, "Alertes", 70, "Dernière activité (UTC)", 170);
            Controls.Add(liste, 0, 3);
            Controls.Add(detail, 0, 4);
            liste.SelectedIndexChanged += (s, e) => Selection();
            btnPrendre.Click += (s, e) => Passer("PrisEnCharge", "", "");
            btnClore.Click += (s, e) => Clore();
            btnRouvrir.Click += (s, e) => Passer("Ouvert", "", "");
            minuteur.Tick += (s, e) => Charger();
            VisibleChanged += (s, e) => { minuteur.Enabled = Visible; if (Visible) Charger(); };
            MajBoutons();
        }

        IncidentSuivi Choisi()
        {
            return liste.SelectedItems.Count == 1 ? liste.SelectedItems[0].Tag as IncidentSuivi : null;
        }

        void MajBoutons()
        {
            var i = Choisi();
            btnPrendre.Enabled = i != null && VueIncidents.Permise(i.Etat, "PrisEnCharge");
            btnClore.Enabled = i != null && VueIncidents.Permise(i.Etat, "Clos");
            btnRouvrir.Enabled = i != null && VueIncidents.Permise(i.Etat, "Ouvert");
        }

        // Lecture hors du fil de l'interface : un fichier verrouillé ne la fige pas
        public void Charger()
        {
            int numero = ++chargement;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                var l = VueIncidents.Trier(Commun.Lire<List<IncidentSuivi>>("suivi-incidents.json") ?? new List<IncidentSuivi>());
                if (!IsHandleCreated) return;
                try { BeginInvoke((Action)(() => { if (numero == chargement) Afficher(l); })); } catch (InvalidOperationException) { }
            });
        }

        void Afficher(List<IncidentSuivi> l)
        {
            var avant = Choisi();
            string idAvant = avant == null ? null : avant.Id;
            incidents = l;
            liste.BeginUpdate();
            liste.Items.Clear();
            foreach (var i in l)
            {
                var it = new ListViewItem(new[] { VueIncidents.EtatComplet(i), Canal.Visible(i.Niveau), Canal.Visible(i.Entite), string.Join(", ", (i.Regles ?? new List<string>()).Select(Canal.Visible)), i.NombreAlertes.ToString(), Canal.Visible(i.DerniereActiviteUtc) }) { Tag = i };
                it.ForeColor = i.Etat == "Clos" ? Theme.TexteDim : i.Niveau == "Critique" ? Theme.Rouge : Theme.Texte;
                liste.Items.Add(it);
                if (i.Id == idAvant) it.Selected = true;
            }
            liste.EndUpdate();
            resume.Text = string.Format(L.T("{0} incident(s), {1} non clos"), l.Count, l.Count(i => i.Etat != "Clos"));
            Selection();
        }

        void Selection()
        {
            MajBoutons();
            var i = Choisi();
            if (i == null) { detail.Text = L.T("Sélectionnez un incident."); return; }
            string id = i.Id;
            int numero = chargement;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                ChronologieIncident c = VueIncidents.IdentifiantValide(id) ? Commun.Lire<ChronologieIncident>(Path.Combine("chronologies", id + ".json")) : null;
                string texte = VueIncidents.Detail(i, c);
                if (!IsHandleCreated) return;
                try { BeginInvoke((Action)(() => { var ch = Choisi(); if (ch != null && ch.Id == id && detail.Text != texte) detail.Text = texte; })); } catch (InvalidOperationException) { }
            });
        }

        void Passer(string vers, string motif, string note)
        {
            var i = Choisi();
            if (i == null) return;
            Canal.Executer(VueIncidents.Transition(i.Id, vers, motif, note));
            Charger();
        }

        void Clore()
        {
            using (var f = new Form { Text = L.T("Clore l'incident"), FormBorderStyle = FormBorderStyle.FixedDialog, StartPosition = FormStartPosition.CenterParent, MinimizeBox = false, MaximizeBox = false, ClientSize = new Size(460, 190), BackColor = Theme.Fond, ForeColor = Theme.Texte })
            {
                var motifs = new[] { "Resolu", "FauxPositif", "Accepte" };
                var cb = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Left = 14, Top = 34, Width = 430 };
                cb.Items.AddRange(new object[] { L.T("Résolu"), L.T("Faux positif"), L.T("Risque accepté") });
                cb.SelectedIndex = 0;
                var note = new TextBox { Left = 14, Top = 88, Width = 430, MaxLength = VueIncidents.MaxNote };
                var ok = new Button { Text = L.T("Continuer"), Left = 268, Top = 146, Width = 84 };
                var annuler = new Button { Text = L.T("Annuler"), Left = 360, Top = 146, Width = 84, DialogResult = DialogResult.Cancel };
                ok.Click += (s, e) =>
                {
                    string refus = VueIncidents.NoteRefusee(note.Text);
                    if (refus != "") MessageBox.Show(f, refus, "deR4Tizer", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    else f.DialogResult = DialogResult.OK;
                };
                f.Controls.AddRange(new Control[] { new Label { Text = L.T("Motif"), Left = 14, Top = 12, AutoSize = true }, cb, new Label { Text = string.Format(L.T("Note (facultative, {0} caractères au plus)"), VueIncidents.MaxNote), Left = 14, Top = 66, AutoSize = true }, note, ok, annuler });
                f.AcceptButton = ok; f.CancelButton = annuler;
                if (f.ShowDialog(this) == DialogResult.OK) Passer("Clos", motifs[cb.SelectedIndex], note.Text);
            }
        }
    }

    class PageSante : TableLayoutPanel
    {
        readonly Liste liste = new Liste();
        readonly Label resume = new Label { AutoSize = true, ForeColor = Theme.TexteDim, Font = Theme.Petit, Margin = new Padding(0, 0, 0, 8) };
        // Le détail en entier : la colonne coupe les longues lignes
        readonly TextBox detail = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, BackColor = Theme.Panneau2, ForeColor = Theme.Texte, Font = Theme.Mono, BorderStyle = BorderStyle.None };
        readonly System.Windows.Forms.Timer minuteur = new System.Windows.Forms.Timer { Interval = 15000 };
        int chargement;

        public PageSante()
        {
            Dock = DockStyle.Fill; ColumnCount = 1; RowCount = 5; BackColor = Theme.Fond; Padding = new Padding(22, 14, 22, 14);
            RowStyles.Add(new RowStyle(SizeType.AutoSize));
            RowStyles.Add(new RowStyle(SizeType.AutoSize));
            RowStyles.Add(new RowStyle(SizeType.AutoSize));
            RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            RowStyles.Add(new RowStyle(SizeType.Absolute, 90));
            Controls.Add(new Label { Text = "// " + L.T("Santé").ToUpperInvariant(), Font = Theme.TitrePage, ForeColor = Theme.Cyan, AutoSize = true, Margin = new Padding(0, 0, 0, 4) }, 0, 0);
            Controls.Add(new Label { Text = L.T("Ce que deR4Tizer voit réellement : une collecte indisponible, c'est une détection qui ne peut pas se déclencher. Chaque ligne dit sa source et sa date."), Font = Theme.Petit, ForeColor = Theme.TexteDim, AutoSize = true, Margin = new Padding(0, 0, 0, 10) }, 0, 1);
            Controls.Add(resume, 0, 2);
            liste.Colonnes("Sujet", 240, "État", 130, "Vérifié", 180, "Détail", 460, "Source", 130);
            Controls.Add(liste, 0, 3);
            Controls.Add(detail, 0, 4);
            liste.SelectedIndexChanged += (s, e) => { detail.Text = liste.SelectedItems.Count == 1 ? liste.SelectedItems[0].SubItems[0].Text + " : " + liste.SelectedItems[0].ToolTipText : L.T("Sélectionnez une ligne pour lire son détail en entier."); };
            detail.Text = L.T("Sélectionnez une ligne pour lire son détail en entier.");
            minuteur.Tick += (s, e) => Charger();
            VisibleChanged += (s, e) => { minuteur.Enabled = Visible; if (Visible) Charger(); };
        }

        public void Charger()
        {
            int numero = ++chargement;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                var l = VueSante.Lignes(Commun.Lire<Etat>("etat.json"), Commun.Lire<EtatRemontee>("notifications.json"), DateTime.Now);
                if (!IsHandleCreated) return;
                try { BeginInvoke((Action)(() => { if (numero == chargement) Afficher(l); })); } catch (InvalidOperationException) { }
            });
        }

        void Afficher(List<LigneSante> l)
        {
            int indice = liste.TopItem == null ? 0 : liste.TopItem.Index;
            string sujet = liste.SelectedItems.Count == 1 ? liste.SelectedItems[0].SubItems[0].Text : null;
            liste.BeginUpdate();
            liste.Items.Clear();
            foreach (var x in l)
            {
                var it = new ListViewItem(new[] { x.Sujet, x.Etat, x.Date, x.Detail, x.Source }) { ToolTipText = x.Detail };
                it.ForeColor = x.Gravite > 0 ? Theme.Jaune : Theme.Texte;
                liste.Items.Add(it);
                if (x.Sujet == sujet) it.Selected = true;
            }
            liste.EndUpdate();
            if (indice > 0 && indice < liste.Items.Count) liste.TopItem = liste.Items[indice];
            int n = l.Count(x => x.Gravite > 0);
            resume.Text = n == 0 ? L.T("Rien à vérifier.") : string.Format(L.T("{0} point(s) à vérifier."), n);
            resume.ForeColor = n == 0 ? Theme.TexteDim : Theme.Jaune;
        }
    }
}
