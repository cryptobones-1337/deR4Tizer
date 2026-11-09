// Page « Réponses en cours » (phase 6, PR 6.7b) : actions de réponse qui durent, lues dans reponses.json tel que le
// service l'écrit (registre de politique.rs), avec leur échéance de relance et leur récupération. Une échéance n'est
// jamais une levée : chaque action attend une décision humaine, que le bouton de la ligne envoie par l'assistant élevé.

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Windows.Forms;

namespace DeR4Tizer
{
    // reponses.json, noms de politique.rs en PascalCase
    public class HistoriqueReponses
    {
        public List<ActionEnCours> Actions { get; set; }
    }

    public class ActionEnCours
    {
        public string Id { get; set; }
        public string Sorte { get; set; }
        public string Cible { get; set; }
        public int? Pid { get; set; }
        public long? Creation { get; set; }
        public long Debut { get; set; }
        public long Echeance { get; set; }
        public int Relances { get; set; }
        public long DerniereRelance { get; set; }
        public string Etat { get; set; }
        public string Declencheur { get; set; }
    }

    public class LigneReponse
    {
        public string Quoi, Cible, Declencheur, Depuis, Echeance, Etat, Recuperation, Bouton;
        // 2 : mode panique actif (rouge) ; 1 : relance en attente (jaune) ; 0 : en cours. Jamais la couleur seule : l'état
        // est aussi écrit
        public int Gravite;
        public ActionEnCours Action;
    }

    // Décisions pures, testées par tests\test-reponses-interface.ps1
    public static class VueReponses
    {
        public static string Libelle(string sorte)
        {
            bool en = L.En;
            switch (sorte)
            {
                case "SuspensionAuto": return en ? "Suspended automatically (canary)" : "Suspendu automatiquement (leurre)";
                case "Suspension": return en ? "Suspended by an administrator" : "Suspendu par un administrateur";
                case "Isolation": return en ? "Program cut off from the network" : "Programme coupé du réseau";
                case "Panique": return en ? "PANIC mode: Internet cut" : "Mode PANIQUE : Internet coupé";
                case "Quarantaine": return en ? "File in quarantine" : "Fichier en quarantaine";
                case "BlocageManuel": return en ? "Manual block" : "Blocage manuel";
                default: return sorte ?? "?";
            }
        }

        // Mêmes procédures que politique::recuperation : celle « service arrêté » est écrite, pas seulement le bouton
        public static string Recuperation(string sorte)
        {
            bool en = L.En;
            switch (sorte)
            {
                case "SuspensionAuto":
                case "Suspension":
                    return en ? "\"Resume\" or \"Kill\" here; service stopped: Resource Monitor (resmon), \"Resume process\", or end it in Task Manager"
                              : "« Reprendre » ou « Tuer » ici ; service arrêté : Moniteur de ressources (resmon), « Reprendre le processus », ou arrêt dans le Gestionnaire des tâches";
                case "Isolation":
                    return en ? "\"Release\" here; service stopped: delete the \"deR4Tizer - isole …\" rules from the firewall (deR4Tizer group)"
                              : "« Libérer » ici ; service arrêté : supprimer les règles « deR4Tizer - isole … » du pare-feu (groupe deR4Tizer)";
                case "Panique":
                    return en ? "\"Restore Internet\" here; service stopped: delete the \"deR4Tizer PANIQUE\" firewall rules, then the panique-active file in the data folder"
                              : "« Rétablir Internet » ici ; service arrêté : supprimer les règles « deR4Tizer PANIQUE » du pare-feu, puis le fichier panique-active du dossier de données";
                case "Quarantaine":
                    return en ? "\"Restore\" if the file is safe; otherwise leave it: it is never deleted"
                              : "« Restaurer » si le fichier est sûr ; sinon le laisser : il n'est jamais supprimé";
                case "BlocageManuel":
                    return en ? "\"Unblock\" if the block is no longer useful" : "« Débloquer » si le blocage n'est plus utile";
                default: return "";
            }
        }

        public static string Bouton(string sorte)
        {
            bool en = L.En;
            switch (sorte)
            {
                case "SuspensionAuto":
                case "Suspension": return en ? "Resume" : "Reprendre";
                case "Isolation": return en ? "Release" : "Libérer";
                case "Panique": return en ? "Restore Internet" : "Rétablir Internet";
                case "Quarantaine": return en ? "Restore" : "Restaurer";
                case "BlocageManuel": return en ? "Unblock" : "Débloquer";
                default: return "";
            }
        }

        public static string Heure(long secondes)
        {
            if (secondes <= 0) return "?";
            try { return DateTimeOffset.FromUnixTimeSeconds(secondes).LocalDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture); }
            catch { return "?"; }
        }

        // Actions encore actives, la plus grave puis la plus ancienne d'abord
        public static List<LigneReponse> Lignes(HistoriqueReponses h, long maintenant)
        {
            bool en = L.En;
            var l = new List<LigneReponse>();
            if (h == null || h.Actions == null) return l;
            foreach (var a in h.Actions.Where(x => x != null && x.Etat == "Active"))
            {
                bool due = maintenant >= a.Echeance;
                string etat = due
                    ? (en ? "reminder due: human decision awaited" : "relance en attente : décision humaine attendue")
                    : a.Relances > 0
                        ? string.Format(en ? "in progress, reminded {0} time(s)" : "en cours, relancé {0} fois", a.Relances)
                        : (en ? "in progress" : "en cours");
                l.Add(new LigneReponse
                {
                    Quoi = Libelle(a.Sorte),
                    Cible = Canal.Visible(a.Cible ?? "") + (a.Pid.HasValue ? " (PID " + a.Pid.Value + ")" : ""),
                    Declencheur = Canal.Visible(string.IsNullOrEmpty(a.Declencheur) ? "?" : a.Declencheur),
                    Depuis = Heure(a.Debut),
                    Echeance = Heure(a.Echeance),
                    Etat = etat,
                    Recuperation = Recuperation(a.Sorte),
                    Bouton = Bouton(a.Sorte),
                    Gravite = a.Sorte == "Panique" ? 2 : due ? 1 : 0,
                    Action = a,
                });
            }
            return l.OrderByDescending(x => x.Gravite).ThenBy(x => x.Action.Debut).ToList();
        }

        // Commande qui récupère cette action, ou null si son objet n'est plus retrouvé (blocage déjà levé, élément de
        // quarantaine restauré). Le registre garde la cible en minuscules : blocages.json et quarantaine.json donnent la
        // forme exacte attendue par le service
        public static Commande Recuperer(ActionEnCours a, List<Blocage> blocages, List<ElementQuarantaine> quarantaine)
        {
            if (a == null) return null;
            blocages = blocages ?? new List<Blocage>();
            quarantaine = quarantaine ?? new List<ElementQuarantaine>();
            Func<string, string, bool> egal = (x, y) => string.Equals(x, y, StringComparison.OrdinalIgnoreCase);
            switch (a.Sorte)
            {
                case "SuspensionAuto":
                case "Suspension":
                    // L'heure de création du registre voyage avec la commande : l'assistant refuse un PID réutilisé
                    return a.Pid.HasValue ? new Commande { Action = "reprendre", Cible = a.Pid.Value.ToString(CultureInfo.InvariantCulture), Creation = a.Creation } : null;
                case "Isolation":
                    {
                        var b = blocages.FirstOrDefault(x => x.Type == "programme" && egal(x.Cible, a.Cible));
                        return b == null ? null : new Commande { Action = "debloquer", Type = "programme", Cible = b.Cible };
                    }
                case "BlocageManuel":
                    {
                        var b = blocages.FirstOrDefault(x => (x.Type == "parefeu" || x.Type == "hosts") && egal(x.Cible, a.Cible));
                        return b == null ? null : new Commande { Action = "debloquer", Type = b.Type, Cible = b.Cible };
                    }
                case "Panique": return new Commande { Action = "panique", Valeur = "off" };
                case "Quarantaine":
                    {
                        // Même fichier mis deux fois en quarantaine : la plus récente (relecture de #120, R2)
                        var q = quarantaine.Where(x => egal(x.CheminOrigine, a.Cible)).OrderByDescending(x => x.Date ?? "", StringComparer.Ordinal).FirstOrDefault();
                        return q == null ? null : new Commande { Action = "restaurer", Cible = q.Id };
                    }
                default: return null;
            }
        }

        // La page peut-elle envoyer « Reprendre » ? Refus seulement si l'heure de création est lue ET différente (PID
        // réutilisé, audit de #120, S120-02). Illisible avec les droits de l'utilisateur (processus d'un autre compte) :
        // l'assistant élevé, qui fait autorité, tranche (relecture de #120, R4)
        public static bool MemeProcessus(long? attendue, long? lue)
        {
            return !attendue.HasValue || !lue.HasValue || lue.Value == attendue.Value;
        }

        // reponses.json : absent (aucune action enregistrée), illisible (verrou, fichier abîmé) ou lu (audit de #120, S120-04)
        public static string EtatLecture(bool present, bool lu)
        {
            return lu ? "lu" : present ? "illisible" : "absent";
        }

        // Portée du mode panique, dite avant de l'activer (conseil UX externe, P0 ; dossier de la phase 6, § 4.7)
        public static string ConfirmationPanique(bool activer)
        {
            bool en = L.En;
            if (!activer)
                return en ? "Restore Internet access for all programs?\n\nThe two \"deR4Tizer PANIQUE\" firewall rules are removed, then checked: if one remains, panic mode stays shown as uncertain."
                          : "Rétablir l'accès à Internet pour tous les programmes ?\n\nLes deux règles « deR4Tizer PANIQUE » du pare-feu sont retirées, puis vérifiées : s'il en reste une, le mode panique reste affiché « incertain ».";
            return en
                ? "Cut the Internet for all programs?\n\nScope: all of the Internet, incoming and outgoing, IPv4 and IPv6. Open IPv4 connections are closed; open IPv6 connections are NOT closed.\n\nStill reachable: the local network, this PC's DNS servers and the notification servers (ntfy, Teams, e-mail), for every program: malware could use them to send data out.\n\nPanic mode is never lifted automatically: a Critical reminder is sent after 4 hours, then every 24 hours.\n\nTo restore: \"Restore Internet\" here; service stopped: delete the \"deR4Tizer PANIQUE\" firewall rules."
                : "Couper Internet pour tous les programmes ?\n\nPortée : tout Internet, entrant et sortant, IPv4 et IPv6. Les connexions IPv4 ouvertes sont fermées ; les connexions IPv6 ouvertes ne le sont PAS.\n\nRestent joignables : le réseau local, les serveurs DNS de ce PC et les serveurs de notification (ntfy, Teams, e-mail), pour tous les programmes : un malware pourrait s'en servir pour faire sortir des données.\n\nLe mode panique n'est jamais levé automatiquement : une relance « Critique » part au bout de 4 h, puis toutes les 24 h.\n\nPour rétablir : « Rétablir Internet » ici ; service arrêté : supprimer les règles « deR4Tizer PANIQUE » du pare-feu.";
        }

        // Bouton et pastille d'après l'état EFFECTIF publié par le service (compté sur les règles du pare-feu)
        public static string TexteBoutonPanique(Etat e)
        {
            bool en = L.En;
            string etat = e == null ? null : e.PaniqueEtat;
            if (etat == "incertaine") return en ? "◉ PANIC UNCERTAIN: RESTORE" : "◉ PANIQUE INCERTAINE : RÉTABLIR";
            if (etat == "active" || (string.IsNullOrEmpty(etat) && e != null && e.Panique)) return en ? "◉ RESTORE INTERNET" : "◉ RÉTABLIR INTERNET";
            return en ? "◉ PANIC: CUT THE INTERNET" : "◉ PANIQUE : COUPER INTERNET";
        }

        // null : aucune pastille
        public static string PastillePanique(Etat e)
        {
            bool en = L.En;
            string etat = e == null ? null : e.PaniqueEtat;
            if (etat == "incertaine") return en ? "PANIC MODE: UNCERTAIN STATE" : "MODE PANIQUE : ÉTAT INCERTAIN";
            if (etat == "active" || (string.IsNullOrEmpty(etat) && e != null && e.Panique)) return en ? "PANIC MODE ACTIVE: NO INTERNET" : "MODE PANIQUE ACTIF : PAS D'INTERNET";
            return null;
        }
    }

    class PageReponses : TableLayoutPanel
    {
        readonly Liste liste = new Liste();
        readonly Label resume = new Label { AutoSize = true, ForeColor = Theme.TexteDim, Font = Theme.Petit, Margin = new Padding(0, 0, 0, 8) };
        readonly TextBox detail = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, BackColor = Theme.Panneau2, ForeColor = Theme.Texte, Font = Theme.Mono, BorderStyle = BorderStyle.None };
        readonly BoutonNeon recuperer = new BoutonNeon(L.En ? "Recover the selected action" : "Récupérer l'action sélectionnée", Theme.Cyan);
        readonly System.Windows.Forms.Timer minuteur = new System.Windows.Forms.Timer { Interval = 15000 };
        int chargement, enCours;

        public PageReponses()
        {
            bool en = L.En;
            Dock = DockStyle.Fill; ColumnCount = 1; RowCount = 6; BackColor = Theme.Fond; Padding = new Padding(22, 14, 22, 14);
            RowStyles.Add(new RowStyle(SizeType.AutoSize));
            RowStyles.Add(new RowStyle(SizeType.AutoSize));
            RowStyles.Add(new RowStyle(SizeType.AutoSize));
            RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            RowStyles.Add(new RowStyle(SizeType.Absolute, 96));
            RowStyles.Add(new RowStyle(SizeType.AutoSize));
            Controls.Add(Theme.TitreDePage((en ? "Ongoing responses" : "Réponses en cours"), new Padding(0, 0, 0, 4)), 0, 0);
            Controls.Add(new Label { Text = en ? "Response actions that last. None is ever lifted automatically: at its deadline, a reminder is sent and a human decision is awaited." : "Actions de réponse qui durent. Aucune n'est jamais levée automatiquement : à son échéance, une relance part et une décision humaine est attendue.", Font = Theme.Petit, ForeColor = Theme.TexteDim, AutoSize = true, Margin = new Padding(0, 0, 0, 10) }, 0, 1);
            Controls.Add(resume, 0, 2);
            liste.Colonnes(en ? "Action" : "Action", 230, en ? "Target" : "Cible", 360, en ? "Triggered by" : "Déclencheur", 170, en ? "Since" : "Depuis", 130, en ? "Reminder" : "Relance", 130, en ? "State" : "État", 300);
            Controls.Add(liste, 0, 3);
            Controls.Add(detail, 0, 4);
            Controls.Add(recuperer, 0, 5);
            liste.SelectedIndexChanged += (s, e) => Detailler();
            recuperer.Click += (s, e) => Recuperer();
            minuteur.Tick += (s, e) => Charger();
            VisibleChanged += (s, e) => { minuteur.Enabled = Visible; if (Visible) Charger(); };
            Detailler();
        }

        LigneReponse Choisie()
        {
            return liste.SelectedItems.Count == 1 ? liste.SelectedItems[0].Tag as LigneReponse : null;
        }

        void Detailler()
        {
            bool en = L.En;
            var x = Choisie();
            recuperer.Enabled = x != null;
            recuperer.Text = x == null ? (en ? "Recover the selected action" : "Récupérer l'action sélectionnée") : x.Bouton;
            detail.Text = x == null
                ? (en ? "Select a line to read how to recover it." : "Sélectionnez une ligne pour lire comment la récupérer.")
                : x.Quoi + " : " + x.Cible + "\r\n" + (en ? "Recovery: " : "Récupération : ") + x.Recuperation;
        }

        public void Charger()
        {
            if (Interlocked.CompareExchange(ref enCours, 1, 0) != 0) return;
            int numero = ++chargement;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    // Accès au dossier refusé : File.Exists rend faux ; présent par prudence, donc « illisible » (relecture de #121, R1)
                    bool present;
                    try { present = System.IO.File.Exists(System.IO.Path.Combine(Commun.Dossier, "reponses.json")) || (System.IO.Directory.Exists(Commun.Dossier) && !DossierLisible()); }
                    catch { present = true; }
                    var h = Commun.Lire<HistoriqueReponses>("reponses.json");
                    var l = VueReponses.Lignes(h, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                    // Illisible n'est pas « aucune réponse en cours » : le dernier affichage est gardé, et c'est dit
                    bool illisible = VueReponses.EtatLecture(present, h != null) == "illisible";
                    if (!IsHandleCreated) return;
                    try { BeginInvoke((Action)(() => { if (numero == chargement) { if (illisible) Illisible(); else Afficher(l); } })); } catch (InvalidOperationException) { }
                }
                finally { Interlocked.Exchange(ref enCours, 0); }
            });
        }

        void Afficher(List<LigneReponse> l)
        {
            bool en = L.En;
            string choisie = Choisie() == null ? null : Choisie().Action.Id;
            liste.BeginUpdate();
            liste.Items.Clear();
            foreach (var x in l)
            {
                var it = new ListViewItem(new[] { x.Quoi, x.Cible, x.Declencheur, x.Depuis, x.Echeance, x.Etat }) { Tag = x, ToolTipText = x.Recuperation };
                it.ForeColor = x.Gravite == 2 ? Theme.Rouge : x.Gravite == 1 ? Theme.Jaune : Theme.Texte;
                liste.Items.Add(it);
                if (x.Action.Id == choisie) it.Selected = true;
            }
            liste.EndUpdate();
            int dues = l.Count(x => x.Gravite == 1);
            resume.Text = l.Count == 0 ? (en ? "No ongoing response." : "Aucune réponse en cours.")
                : string.Format(en ? "{0} ongoing response(s), {1} awaiting a decision." : "{0} réponse(s) en cours, dont {1} en attente de décision.", l.Count, dues);
            resume.ForeColor = l.Any(x => x.Gravite == 2) ? Theme.Rouge : dues > 0 ? Theme.Jaune : Theme.TexteDim;
            Detailler();
        }

        // Le dossier de données se liste-t-il ? Sinon File.Exists ne peut pas répondre
        static bool DossierLisible()
        {
            try { System.IO.Directory.EnumerateFiles(Commun.Dossier, "reponses.json").Any(); return true; }
            catch { return false; }
        }

        void Illisible()
        {
            bool en = L.En;
            resume.Text = en ? "Response register unreadable (reponses.json): the last display is kept; it may be out of date." : "Registre des réponses illisible (reponses.json) : dernier affichage gardé, peut-être dépassé.";
            resume.ForeColor = Theme.Jaune;
        }

        void Recuperer()
        {
            bool en = L.En;
            var x = Choisie();
            if (x == null) return;
            var c = VueReponses.Recuperer(x.Action, Commun.Lire<List<Blocage>>("blocages.json"), Commun.Lire<List<ElementQuarantaine>>("quarantaine.json"));
            if (c == null)
            {
                MessageBox.Show(en ? "The object of this action is no longer found (already lifted or restored?). Recovery: " + x.Recuperation
                                   : "L'objet de cette action n'est plus retrouvé (déjà levé ou restauré ?). Récupération : " + x.Recuperation,
                    "deR4Tizer", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (c.Action == "reprendre" && !VueReponses.MemeProcessus(x.Action.Creation, Canal.CreationProcessus(x.Action.Pid ?? 0)))
            {
                MessageBox.Show(en ? "The suspended process no longer exists (its PID may now belong to another program). Nothing is sent."
                                   : "Le processus suspendu n'existe plus (son PID peut désigner un autre programme). Rien n'est envoyé.",
                    "deR4Tizer", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            string question = c.Action == "panique" ? VueReponses.ConfirmationPanique(false) : x.Bouton + " : " + x.Quoi + "\n\n" + x.Cible + " ?";
            if (c.Action == "restaurer")
            {
                var q = (Commun.Lire<List<ElementQuarantaine>>("quarantaine.json") ?? new List<ElementQuarantaine>()).FirstOrDefault(e => e.Id == c.Cible);
                if (q != null) question += "\n\n" + (en ? "Quarantined on " : "Mis en quarantaine le ") + Canal.Visible(q.Date ?? "?") + " (" + Canal.Visible(q.Id) + ")";
            }
            if (MessageBox.Show(question, "deR4Tizer", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            Canal.Executer(c);
            Charger();
        }
    }
}
