// Pages Réseau local (NDR : appareils, passerelle, DHCP, répondeurs LLMNR/NBNS/mDNS, leurre) et
// Détection (IDS/IPS et DPI : détections, sessions TLS avec SNI et JA3, requêtes HTTP et DNS).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace DeR4Tizer
{
    // Base commune : titre, description, ligne d'information, barre d'outils, liste ; relecture toutes les 3 s
    abstract class PageEtat : TableLayoutPanel
    {
        protected readonly Label Info = new Label { AutoSize = true, ForeColor = Theme.Texte, Font = Theme.PetitGras, Margin = new Padding(0, 0, 0, 6), MaximumSize = new Size(1400, 0) };
        protected readonly FlowLayoutPanel Outils = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 0, 0, 6), WrapContents = true };
        protected readonly Liste Lv = new Liste();
        readonly Timer minuteur = new Timer { Interval = 3000 };

        protected PageEtat(string titre, string description)
        {
            Dock = DockStyle.Fill; ColumnCount = 1; RowCount = 5; BackColor = Theme.Fond; Padding = new Padding(22, 14, 22, 16); Visible = false;
            for (int i = 0; i < 4; i++) RowStyles.Add(new RowStyle(SizeType.AutoSize));
            RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            Controls.Add(new Label { Text = "// " + L.T(titre).ToUpperInvariant(), Font = Theme.TitrePage, ForeColor = Theme.Cyan, AutoSize = true, Margin = new Padding(0, 0, 0, 2) }, 0, 0);
            Controls.Add(new Label { Text = L.T(description), Font = Theme.Petit, ForeColor = Theme.TexteDim, AutoSize = true, Margin = new Padding(0, 0, 0, 8), MaximumSize = new Size(1400, 0) }, 0, 1);
            Controls.Add(Info, 0, 2);
            Controls.Add(Outils, 0, 3);
            var cadre = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bordure, Padding = new Padding(1), Margin = Padding.Empty };
            cadre.Controls.Add(Lv);
            Controls.Add(cadre, 0, 4);
            var menu = new ContextMenuStrip { Renderer = new RenduSombre(), Font = Theme.Petit };
            menu.Items.Add(L.T("Copier"), null, (s, e) =>
            {
                var lignes = Lv.SelectedItems.Cast<ListViewItem>().Select(i => string.Join("\t", i.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(x => x.Text)));
                var texte = string.Join(Environment.NewLine, lignes);
                if (texte.Length > 0) Clipboard.SetText(texte);
            });
            Lv.ContextMenuStrip = menu;
            minuteur.Tick += (s, e) => Charger();
            VisibleChanged += (s, e) => { minuteur.Enabled = Visible; if (Visible) Charger(); };
        }

        protected abstract void Charger();

        protected void Ligne(string[] valeurs, string niveau, object tag = null)
        {
            var item = new ListViewItem(valeurs) { Tag = tag, ToolTipText = string.Join("  ", valeurs) };
            if (niveau == "Critique") { item.BackColor = Theme.FondCritique; item.ForeColor = Color.White; }
            else if (niveau == "Alerte") { item.BackColor = Theme.FondAlerte; item.ForeColor = Theme.Texte; }
            else { item.BackColor = Theme.Panneau; item.ForeColor = niveau == "Actif" ? Theme.Cyan : Theme.Texte; }
            Lv.Items.Add(item);
        }

        protected void Vider(params object[] colonnes)
        {
            Lv.BeginUpdate();
            Lv.Items.Clear();
            bool memes = colonnes.Length == Lv.Columns.Count * 2 && Lv.Columns.Count > 0 && Lv.Columns[0].Text == L.T((string)colonnes[0]);
            if (colonnes.Length > 0 && !memes)
            {
                Lv.Columns.Clear();
                Lv.Colonnes(colonnes);
            }
        }
    }

    class PageReseau : PageEtat
    {
        public PageReseau() : base("Réseau local",
            "Surveillance passive de la carte reliée à la box (même avec un VPN) : usurpation ARP, serveur DHCP pirate, empoisonnement LLMNR/NBNS (Responder). Un leurre interroge toutes les 10 minutes un nom qui n'existe pas : personne ne doit répondre.")
        {
            Lv.Colonnes("Élément", 190, "Adresse IP", 140, "Détail", 420, "Première vue", 160, "Dernière vue", 160);
        }

        protected override void Charger()
        {
            var r = Commun.Lire<EtatReseau>("reseau.json");
            if (r == null) { Info.Text = L.T("Pas encore de données (le service analyse le réseau au démarrage)."); return; }
            bool alerte = (r.ResultatLeurre ?? "").StartsWith("RÉPONSE");
            Info.ForeColor = alerte ? Theme.Rouge : Theme.Texte;
            Info.Text = string.Format(L.En
                ? "Interface {0} / {1} · gateway {2} ({3}) · DHCP server {4}\nDecoy ({5}): {6}"
                : "Interface {0} / {1} · passerelle {2} ({3}) · serveur DHCP {4}\nLeurre ({5}) : {6}",
                r.Interface, r.Masque, r.Passerelle, r.MacPasserelle, string.IsNullOrEmpty(r.DhcpInterface) ? (L.En ? "none (static address)" : "aucun (adresse fixe)") : r.DhcpInterface,
                r.DernierLeurre, r.ResultatLeurre);
            int haut = Lv.Items.Count > 0 ? Lv.TopItem.Index : 0;
            Vider();
            Lv.AjouterSection(L.T("Appareils du réseau local"));
            foreach (var a in (r.Appareils ?? new List<Appareil>()).OrderByDescending(a => a.Passerelle).ThenBy(a => Version(a.Ip)))
                Ligne(new[] { a.Passerelle ? L.T("Passerelle (box)") : L.T("Appareil"), a.Ip, "MAC " + a.Mac, a.PremiereVue, a.DerniereVue }, a.Passerelle ? "Actif" : "");
            Lv.AjouterSection(L.T("Serveurs DHCP vus"));
            foreach (var d in r.ServeursDhcp ?? new List<ServeurDhcp>())
                Ligne(new[] { d.Legitime ? L.T("Serveur DHCP") : L.T("Serveur DHCP PIRATE"), d.Ip, d.Legitime ? L.T("serveur de cette interface") : L.T("n'est pas le serveur de cette interface"), "", d.Vu }, d.Legitime ? "" : "Critique");
            Lv.AjouterSection(L.T("Répondeurs LLMNR / NBNS / mDNS"));
            foreach (var x in r.Repondeurs ?? new List<Repondeur>())
                Ligne(new[] { x.Protocole, x.Ip, string.Join(", ", x.Noms ?? new List<string>()), "", x.Derniere }, (x.Noms ?? new List<string>()).Count >= (x.Protocole == "mDNS" ? 15 : 3) ? "Alerte" : "");
            Lv.EndUpdate();
            if (haut > 0 && haut < Lv.Items.Count) Lv.TopItem = Lv.Items[haut];
        }

        static long Version(string ip)
        {
            long v = 0;
            foreach (var o in (ip ?? "").Split('.')) { int n; int.TryParse(o, out n); v = v * 256 + n; }
            return v;
        }
    }

    class PageDetection : PageEtat
    {
        readonly ComboBox cbVue = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, FlatStyle = FlatStyle.Flat, BackColor = Theme.Panneau2, ForeColor = Theme.Texte, Font = Theme.Petit, Width = 220, Margin = new Padding(0, 3, 10, 3) };
        readonly CheckBox chkIps = new CheckBox { AutoSize = true, ForeColor = Theme.Texte, Font = Theme.Petit, FlatStyle = FlatStyle.Flat, Margin = new Padding(4, 6, 12, 0), Cursor = Cursors.Hand };
        bool majCase;
        int vueAffichee = -1;

        public PageDetection() : base("Détection",
            "IDS/IPS : règles au format Suricata (intégrées + fichiers .rules du dossier des règles, par exemple Emerging Threats Open). DPI : nom des sites TLS (SNI), empreintes des clients TLS (JA3, liste SSLBL d'abuse.ch), requêtes HTTP en clair et DNS.")
        {
            cbVue.Items.AddRange(new object[] { L.T("Détections IDS"), L.T("Sessions TLS (SNI, JA3)"), L.T("Requêtes HTTP en clair"), L.T("Requêtes DNS"), L.T("Empreintes JA3") });
            cbVue.SelectedIndex = 0;
            cbVue.SelectedIndexChanged += (s, e) => Charger();
            chkIps.Text = L.T("IPS : bloquer au pare-feu l'adresse distante des règles « drop » ou de priorité 1");
            chkIps.CheckedChanged += (s, e) =>
            {
                if (majCase) return;
                Canal.Executer(new Commande { Action = "config", Cible = "Ips", Valeur = chkIps.Checked ? "true" : "false" });
            };
            var btnRegles = new BoutonNeon("Dossier des règles", Theme.TexteDim);
            btnRegles.Click += (s, e) =>
            {
                string d = Path.Combine(Commun.Dossier, "regles");
                try { Process.Start("explorer.exe", "\"" + d + "\""); } catch { }
            };
            Outils.Controls.AddRange(new Control[] { cbVue, chkIps, btnRegles });
        }

        protected override void Charger()
        {
            var ids = Commun.Lire<EtatIds>("ids.json") ?? new EtatIds();
            var dpi = Commun.Lire<EtatDpi>("dpi.json") ?? new EtatDpi();
            var config = Commun.Lire<Config>("config.json") ?? new Config();
            majCase = true;
            chkIps.Checked = config.Ips;
            majCase = false;
            Info.Text = string.Format(L.En
                ? "{0} rule(s) loaded, {1} ignored (unsupported options) · {2:N0} packets analysed · IPS {3}\nTLS {4:N0} · HTTP {5:N0} · DNS {6:N0} · {7:N0} known malicious JA3 fingerprints"
                : "{0} règle(s) chargée(s), {1} ignorée(s) (options non prises en charge) · {2:N0} paquets analysés · IPS {3}\nTLS {4:N0} · HTTP {5:N0} · DNS {6:N0} · {7:N0} empreintes JA3 malveillantes connues",
                ids.Regles, ids.Ignorees, ids.PaquetsAnalyses, config.Ips ? (L.En ? "ON" : "ACTIF") : (L.En ? "off" : "inactif"),
                dpi.SessionsTls, dpi.RequetesHttp, dpi.RequetesDns, dpi.EmpreintesJa3Connues);
            int vue = cbVue.SelectedIndex;
            int haut = vue == vueAffichee && Lv.Items.Count > 0 ? Lv.TopItem.Index : 0;
            vueAffichee = vue;
            switch (vue)
            {
                case 0:
                    Vider("Heure", 150, "Niveau", 80, "Règle", 70, "Message", 380, "Source", 170, "Destination", 170, "Programme", 130, "Bloqué", 70);
                    foreach (var d in ids.Detections ?? new List<DetectionIds>())
                        Ligne(new[] { d.Heure, d.Niveau, d.Sid.ToString(), d.Message, d.Source, d.Destination, d.Programme, d.Bloque ? L.T("oui") : "" }, d.Niveau);
                    break;
                case 1:
                    Vider("Heure", 150, "Programme", 130, "Site (SNI)", 300, "IP", 140, "Port", 55, "JA3", 250, "Remarque", 300);
                    foreach (var x in dpi.Tls ?? new List<SessionDpi>())
                        Ligne(new[] { x.Heure, x.Programme, x.Nom, x.Ip, x.Port.ToString(), x.Ja3, x.Remarque }, string.IsNullOrEmpty(x.Remarque) ? "" : "Critique");
                    break;
                case 2:
                    Vider("Heure", 150, "Programme", 130, "Hôte et chemin", 520, "IP", 140, "Port", 55, "Remarque", 260);
                    foreach (var x in dpi.Http ?? new List<SessionDpi>())
                        Ligne(new[] { x.Heure, x.Programme, x.Nom, x.Ip, x.Port.ToString(), x.Remarque }, string.IsNullOrEmpty(x.Remarque) ? "" : "Alerte");
                    break;
                case 3:
                    Vider("Heure", 150, "Programme", 130, "Nom demandé", 420, "Serveur DNS", 140);
                    foreach (var x in dpi.Dns ?? new List<SessionDpi>())
                        Ligne(new[] { x.Heure, x.Programme, x.Nom, x.Ip }, "");
                    break;
                default:
                    Vider("Empreinte JA3", 280, "Sessions", 90, "Programmes", 500);
                    foreach (var x in dpi.Empreintes ?? new List<EmpreinteJa3>())
                        Ligne(new[] { x.Ja3, x.Nombre.ToString(), string.Join(", ", x.Programmes ?? new List<string>()) }, "");
                    break;
            }
            Lv.EndUpdate();
            if (haut > 0 && haut < Lv.Items.Count) Lv.TopItem = Lv.Items[haut];
        }
    }
}
