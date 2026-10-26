// Code partagé entre le service (deR4TizerSvc.exe) et l'interface (deR4Tizer.exe).
// Compilé avec le csc de .NET Framework 4.8 fourni par Windows : C# 5 seulement.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace DeR4Tizer
{
    public class FluxInfo
    {
        public string Cle { get; set; }
        public int Score { get; set; }
        public string Processus { get; set; }
        public int Pid { get; set; }
        public string Chemin { get; set; }
        public string Signataire { get; set; }
        public string Ip { get; set; }
        public string NomDns { get; set; }
        public int Port { get; set; }
        public string Raisons { get; set; }
        public string PremiereVue { get; set; }
        public int Connexions { get; set; }
        public string Parent { get; set; }
        public string LigneCommande { get; set; }
        public string Origine { get; set; }
    }

    public class Etat
    {
        public string MisAJour { get; set; }
        public string Demarrage { get; set; }
        public string Version { get; set; }
        public bool JournalDnsActif { get; set; }
        public int IpConnues { get; set; }
        public string SourceProcessus { get; set; }     // "Sysmon", "WMI" ou "aucune"
        public bool BureauADistance { get; set; }
        public List<FluxInfo> Flux { get; set; }
        public List<UsagePeripherique> Peripheriques { get; set; }
        public List<OutilDistant> OutilsDistants { get; set; }
        public List<Ecoute> Ecoutes { get; set; }
        public EtatDefender Defender { get; set; }
        public List<Chaine> Chaines { get; set; }
        public bool Panique { get; set; }
        public Exposition Exposition { get; set; }
        public string ProtectionDonnees { get; set; }   // vide : droits du dossier de données vérifiés
        // État des collectes (phase 3.3) : null pour un service plus ancien
        public List<EtatCollecte> Collectes { get; set; }
        public List<string> ReglesSansCollecte { get; set; }
        public List<string> ReglesDegradees { get; set; }
        public List<CauseSansCollecte> CausesSansCollecte { get; set; }
    }

    // État d'une collecte publié par le service (etat.json, phase 3.3)
    public class EtatCollecte
    {
        public string Id { get; set; }
        public string Etat { get; set; }            // Inconnue, Active, Indisponible, Desactivee, Partielle
        public string Depuis { get; set; }
        public string DernierSucces { get; set; }
        public string Raison { get; set; }
    }

    // Règle sans collecte et les sources dont l'une au moins manque (etat.json, phase 3.3d)
    public class CauseSansCollecte
    {
        public string Regle { get; set; }
        public List<string> Collectes { get; set; }
    }

    // Textes de l'état des collectes pour l'interface (décisions pures, vérifiées par tests\test-collectes-interface.ps1) :
    // « aucune alerte » n'est jamais affiché seul quand une détection ne peut pas se déclencher
    public static class Couverture
    {
        static readonly Dictionary<string, string> Consequences = new Dictionary<string, string>
        {
            { "Connexions", "connexions réseau non vues" }, { "Processus", "programmes en cours non listés" },
            { "Sysmon", "créations de programmes non vues" }, { "WmiProcessus", "créations de programmes non vues" },
            { "JournalDns", "domaines contactés non vus" }, { "JournalDefender", "détections et réglages de Defender non vus" },
            { "EtatDefender", "état de Defender inconnu" }, { "JournalSecurite", "ouvertures de session et accès aux fichiers non vus" },
            { "AuditDonnees", "accès aux données sensibles non vus" }, { "JournalSysteme", "services et pilotes installés non vus" },
            { "JournalParefeu", "changements du pare-feu non vus" }, { "PaquetsParefeu", "paquets entrants non vus" },
            { "Persistance", "démarrages automatiques non vus" }, { "Baseline", "réglages de sécurité non vérifiés" },
            { "ListesMenaces", "adresses malveillantes connues non reconnues" }, { "ListesDomaines", "domaines malveillants connus non reconnus" },
            { "Loldrivers", "pilotes vulnérables non reconnus" }, { "Leurres", "chiffrement par un rançongiciel non repéré par les leurres" },
            { "Extensions", "extensions de navigateur non vues" }, { "Peripheriques", "usage de la caméra et du micro non vu" },
            { "CaptureTrafic", "trafic non analysé (modules expérimentaux)" }, { "CaptureReseauLocal", "réseau local non analysé (module expérimental)" },
        };

        public static string Consequence(string id)
        {
            string c;
            return id != null && Consequences.TryGetValue(id, out c) ? L.T(c) : L.T("conséquence inconnue");
        }

        static bool EnPanne(EtatCollecte c)
        {
            return c != null && (c.Etat == "Indisponible" || c.Etat == "Inconnue");
        }

        static EtatCollecte Trouver(Etat e, string id)
        {
            if (e == null || e.Collectes == null) return null;
            foreach (var c in e.Collectes) if (c != null && c.Id == id) return c;
            return null;
        }

        // Collectes en panne (indisponibles, ou jamais lues : échec fermé) ; les collectes désactivées par choix n'y sont pas
        public static List<EtatCollecte> EnPannes(Etat e)
        {
            var l = new List<EtatCollecte>();
            if (e == null || e.Collectes == null) return l;
            foreach (var c in e.Collectes) if (EnPanne(c)) l.Add(c);
            return l;
        }

        // Pastille d'en-tête : vide si aucune collecte n'est en panne
        public static string Pastille(Etat e)
        {
            int n = EnPannes(e).Count;
            if (n == 0) return "";
            return n == 1 ? L.T("1 COLLECTE INDISPONIBLE") : string.Format(L.T("{0} COLLECTES INDISPONIBLES"), n);
        }

        // Une collecte en mots : identifiant, état, raison et conséquence
        public static string Decrire(EtatCollecte c)
        {
            string etat = c.Etat == "Inconnue" ? L.T("pas encore lue") : c.Etat == "Desactivee" ? L.T("désactivée") : c.Etat == "Partielle" ? L.T("partielle") : L.T("indisponible");
            return c.Id + " " + etat + (string.IsNullOrEmpty(c.Raison) ? "" : " (" + c.Raison + ")") + " : " + Consequence(c.Id);
        }

        static List<string> SourcesDe(Etat e, string regle)
        {
            if (e != null && e.CausesSansCollecte != null)
                foreach (var c in e.CausesSansCollecte)
                    if (c != null && c.Regle == regle && c.Collectes != null && c.Collectes.Count > 0) return c.Collectes;
            return null;
        }

        // Règle muette par réglage : toutes ses sources manquantes sont désactivées par choix (listes de domaines coupées,
        // Sysmon absent…). Sans cause publiée, ou avec une source en panne ou introuvable : muette par panne (échec fermé)
        public static bool ParReglage(Etat e, string regle)
        {
            var s = SourcesDe(e, regle);
            if (s == null) return false;
            foreach (var id in s)
            {
                var c = Trouver(e, id);
                if (c == null || c.Etat != "Desactivee") return false;
            }
            return true;
        }

        static List<string> Regles(Etat e, bool parReglage)
        {
            var l = new List<string>();
            if (e == null || e.ReglesSansCollecte == null) return l;
            foreach (var r in e.ReglesSansCollecte) if (ParReglage(e, r) == parReglage) l.Add(r);
            return l;
        }

        // Détections qui ne peuvent pas se déclencher à cause d'une collecte en panne (pas d'un réglage)
        public static List<string> ReglesEnPanne(Etat e) { return Regles(e, false); }

        // Détections coupées par un réglage voulu (neutre, pas une alarme)
        public static List<string> ReglesParReglage(Etat e) { return Regles(e, true); }

        // « DNS-001 : domaines malveillants connus non reconnus (manque ListesDomaines) » : la conséquence en clair, la
        // source en second
        static string Expliquer(Etat e, List<string> regles)
        {
            var morceaux = new List<string>();
            foreach (var r in regles)
            {
                var s = SourcesDe(e, r);
                morceaux.Add(s == null ? r : r + " : " + Consequence(s[0]) + " (" + L.T("manque") + " " + string.Join(L.T(" ou "), s) + ")");
            }
            return string.Join(" ; ", morceaux);
        }

        // Le message doit-il alerter (jaune) ? Oui si une détection est muette par panne, ou si l'état est illisible
        public static bool Alarme(Etat e)
        {
            return e == null || ReglesEnPanne(e).Count > 0;
        }

        // Liste des alertes vide : « Aucune alerte. » seul seulement si chaque détection a sa collecte ; les détections
        // coupées par réglage sont dites en neutre, celles qui sont muettes par panne en premier
        public static string AucuneAlerte(Etat e)
        {
            if (e == null) return L.T("Aucune alerte, mais l'état du service est illisible : rien ne prouve que la surveillance fonctionne.");
            if (e.Collectes == null) return L.T("Aucune alerte (état des collectes non publié par ce service).");
            var panne = ReglesEnPanne(e);
            var reglage = ReglesParReglage(e);
            string suite = reglage.Count == 0 ? "" : " " + L.T("Désactivé par réglage") + " : " + Expliquer(e, reglage) + ".";
            if (panne.Count == 0) return L.T("Aucune alerte.") + suite;
            return string.Format(panne.Count == 1 ? L.T("Aucune alerte, mais {0} détection ne peut pas se déclencher : {1}.") : L.T("Aucune alerte, mais {0} détections ne peuvent pas se déclencher : {1}."),
                panne.Count, Expliquer(e, panne)) + suite;
        }

        // Bandeau de la page Alertes, toujours visible (même avec des alertes) : chaque collecte en panne expliquée,
        // puis les collectes désactivées par choix ; vide si tout est lu
        public static string Detail(Etat e)
        {
            if (e == null || e.Collectes == null) return "";
            var lignes = new List<string>();
            foreach (var c in EnPannes(e)) lignes.Add("▲ " + Decrire(c));
            foreach (var c in e.Collectes) if (c != null && c.Etat == "Desactivee") lignes.Add("○ " + Decrire(c));
            return string.Join("\n", lignes);
        }

        // Pastille caméra et micro : « OFF » seulement si le magasin des consentements est lu
        public static bool CamMicLue(Etat e)
        {
            if (e == null || e.Collectes == null) return true;
            var c = Trouver(e, "Peripheriques");
            return c != null && (c.Etat == "Active" || c.Etat == "Partielle");
        }

        // État de Defender pas encore lu (premier relevé au démarrage du PC) : « lecture en cours », pas « illisible »
        public static bool DefenderPasEncoreLu(Etat e)
        {
            var c = Trouver(e, "EtatDefender");
            return c != null && c.Etat == "Inconnue";
        }
    }

    // Exposition du PC à Internet (paquets entrants venus d'Internet, adresses publiques)
    public class Exposition
    {
        public bool Exposee { get; set; }
        public List<string> Raisons { get; set; }
        public List<string> AdressesPubliques { get; set; }
        public bool JournalPaquets { get; set; }
        public List<EntreeExposee> Entrees { get; set; }
        public string Base { get; set; }
    }

    public class EntreeExposee
    {
        public string Derniere { get; set; }
        public string Premiere { get; set; }
        public string Source { get; set; }
        public int PortLocal { get; set; }
        public string Protocole { get; set; }
        public string Action { get; set; }
        public int Nombre { get; set; }
        public string Programme { get; set; }
    }

    // Changement de règle du pare-feu (parefeu.json)
    public class EvenementRegle
    {
        public string Heure { get; set; }
        public string Operation { get; set; }
        public string Regle { get; set; }
        public string Sens { get; set; }
        public string Action { get; set; }
        public string Ports { get; set; }
        public string ProgrammeCible { get; set; }
        public string Auteur { get; set; }
    }

    public class EtatDefender
    {
        public bool Disponible { get; set; }
        public bool Antivirus { get; set; }
        public bool TempsReel { get; set; }
        public bool ProtectionFalsification { get; set; }
        public string Mode { get; set; }
        public string Signatures { get; set; }
        public string DerniereAnalyse { get; set; }
    }

    // Chaîne de processus et score cumulé (arbre des processus)
    public class Chaine
    {
        public string Racine { get; set; }
        public int Score { get; set; }
        public string Resume { get; set; }
        public string Depuis { get; set; }
        public List<NoeudChaine> Noeuds { get; set; }
    }

    public class NoeudChaine
    {
        public int Profondeur { get; set; }
        public int Pid { get; set; }
        public string Nom { get; set; }
        public string Chemin { get; set; }
        public string LigneCommande { get; set; }
        public int Score { get; set; }
        public string Raisons { get; set; }
    }

    // Baseline de sécurité (baseline.json)
    public class EtatBaseline
    {
        public string MisAJour { get; set; }
        public List<EtatRegle> Regles { get; set; }
        public Dictionary<string, int> Scores { get; set; }
        public string Message { get; set; }
    }

    public class EtatRegle
    {
        public string Id { get; set; }
        public string Profil { get; set; }
        public string Categorie { get; set; }
        public string Titre { get; set; }
        public string Pourquoi { get; set; }
        public string Compat { get; set; }
        public string Etat { get; set; }
        public string Actuel { get; set; }
        public string Attendu { get; set; }
        public bool Appliquee { get; set; }
    }

    public class Extension
    {
        public string Navigateur { get; set; }
        public string Id { get; set; }
        public string Nom { get; set; }
        public string Version { get; set; }
        public string Permissions { get; set; }
        public bool Dangereuse { get; set; }
        public string Depuis { get; set; }
    }

    public class ElementQuarantaine
    {
        public string Id { get; set; }
        public string CheminOrigine { get; set; }
        public string Date { get; set; }
        public string Raison { get; set; }
        public long Taille { get; set; }
    }

    // Entrée de démarrage automatique (clé Run, service, tâche planifiée, dossier Démarrage, WMI…)
    public class EntreeDemarrage
    {
        public string Cle { get; set; }
        public string Categorie { get; set; }
        public string Nom { get; set; }
        public string Commande { get; set; }
        public string Cible { get; set; }
        public string Signataire { get; set; }
        public string Remarque { get; set; }
        public string Depuis { get; set; }
    }

    public class UsagePeripherique
    {
        public string Peripherique { get; set; }        // "Caméra" ou "Micro"
        public string Programme { get; set; }
        public string Chemin { get; set; }
        public string DernierDebut { get; set; }
        public string DerniereFin { get; set; }
        public bool EnCours { get; set; }
    }

    public class OutilDistant
    {
        public string Nom { get; set; }
        public int Pid { get; set; }
        public string Chemin { get; set; }
        public string Signataire { get; set; }
        public string Depuis { get; set; }
    }

    public class Ecoute
    {
        public string Programme { get; set; }
        public string Chemin { get; set; }
        public int Pid { get; set; }
        public string Adresse { get; set; }
        public int Port { get; set; }
        public string Signataire { get; set; }
        public string Depuis { get; set; }
    }

    public class SourceMenace
    {
        public string Nom { get; set; }
        public string Type { get; set; }        // "IP" ou "Domaines"
        public string Confiance { get; set; }   // "haute" (serveurs de contrôle, réseaux criminels) ou "réputation"
        public int Entrees { get; set; }
        public string Statut { get; set; }
        public string MisAJour { get; set; }
        public string Licence { get; set; }
    }

    public class InfosMenaces
    {
        public string MisAJour { get; set; }
        public int TotalIp { get; set; }
        public int TotalReseaux { get; set; }
        public int TotalDomaines { get; set; }
        public List<SourceMenace> Sources { get; set; }
    }

    public class Config
    {
        // Tous les blocs créés : sans config.json (première installation), un bloc à null faisait refuser les réglages
        public Config() { BlocageAutoMenaces = true; ReponseAutoRancongiciel = true; Langue = "fr"; Syslog = new ConfigSyslog(); Api = new ConfigApi(); Notifications = new ConfigNotifications(); Maj = new ConfigMaj(); }
        public string Langue { get; set; }
        public ConfigSyslog Syslog { get; set; }
        public ConfigApi Api { get; set; }
        public bool Ips { get; set; }
        public bool ListesRestreintes { get; set; }
        public ConfigNotifications Notifications { get; set; }
        public ConfigMaj Maj { get; set; }
        // Bloque au pare-feu, dès qu'une connexion est vue, les IP des listes de confiance haute
        public bool BlocageAutoMenaces { get; set; }
        // Suspend aussitôt le programme qui modifie un fichier leurre
        public bool ReponseAutoRancongiciel { get; set; }
    }

    // Événement normalisé du mini-SIEM (siem\evenements-AAAAMMJJ.ndjson)
    public class Evenement
    {
        public string Heure { get; set; }
        public string Source { get; set; }
        public string Type { get; set; }
        public string Niveau { get; set; }
        public string Utilisateur { get; set; }
        public string Processus { get; set; }
        public int? Pid { get; set; }
        public string Ip { get; set; }
        public int Port { get; set; }
        public string Destination { get; set; }
        public string Message { get; set; }
        public string Mitre { get; set; }
    }

    // Incident levé par une règle de corrélation (incidents.json)
    public class Incident
    {
        public string Id { get; set; }
        public string Heure { get; set; }
        public string Regle { get; set; }
        public string Titre { get; set; }
        public string Niveau { get; set; }
        public string Mitre { get; set; }
        public string Resume { get; set; }
        public List<string> Evenements { get; set; }
    }

    // ------------------------------------------------------------ trafic (trafic.json)
    public class PointTrafic { public string Heure { get; set; } public long Entrant { get; set; } public long Sortant { get; set; } }
    public class TraficApplication { public string Nom { get; set; } public long Entrant { get; set; } public long Sortant { get; set; } public int Destinations { get; set; } }
    public class TraficDestination
    {
        public string Ip { get; set; } public string Nom { get; set; } public string Pays { get; set; } public string Programme { get; set; }
        public int Port { get; set; } public long Entrant { get; set; } public long Sortant { get; set; } public bool Active { get; set; }
    }
    public class TraficPays
    {
        public string Code { get; set; } public long Entrant { get; set; } public long Sortant { get; set; } public int Destinations { get; set; }
        public List<string> Programmes { get; set; } public bool Active { get; set; }
    }
    public class TraficPort { public string Port { get; set; } public long Octets { get; set; } }
    public class EtatTrafic
    {
        public string MisAJour { get; set; } public string Depuis { get; set; } public string Interface { get; set; }
        public long DebitEntrant { get; set; } public long DebitSortant { get; set; } public long TotalEntrant { get; set; } public long TotalSortant { get; set; }
        public long Paquets { get; set; } public int PlagesGeoip { get; set; }
        public List<PointTrafic> Serie { get; set; } public List<TraficApplication> Applications { get; set; }
        public List<TraficDestination> Destinations { get; set; } public List<TraficPays> Pays { get; set; } public List<TraficPort> Ports { get; set; }
    }

    // ------------------------------------------------------------ réseau local (reseau.json)
    public class Appareil { public string Ip { get; set; } public string Mac { get; set; } public string PremiereVue { get; set; } public string DerniereVue { get; set; } public bool Passerelle { get; set; } }
    public class Repondeur { public string Ip { get; set; } public string Protocole { get; set; } public List<string> Noms { get; set; } public string Derniere { get; set; } }
    public class ServeurDhcp { public string Ip { get; set; } public string Vu { get; set; } public bool Legitime { get; set; } }
    public class EtatReseau
    {
        public string MisAJour { get; set; } public string Interface { get; set; } public string Masque { get; set; } public string Passerelle { get; set; }
        public string MacPasserelle { get; set; } public string MacPasserelleConnue { get; set; } public string DhcpInterface { get; set; }
        public List<Appareil> Appareils { get; set; } public List<ServeurDhcp> ServeursDhcp { get; set; } public List<Repondeur> Repondeurs { get; set; }
        public string DernierLeurre { get; set; } public string ResultatLeurre { get; set; }
        public List<RedirectionUpnp> Redirections { get; set; } public string Upnp { get; set; }
    }
    public class RedirectionUpnp
    {
        public int PortExterne { get; set; } public string Protocole { get; set; } public string Client { get; set; }
        public int PortInterne { get; set; } public string Description { get; set; } public bool Active { get; set; }
    }

    // Mode apprentissage et exceptions (apprentissage.json), mise à jour (maj.json)
    public class ExceptionApprise { public string Signature { get; set; } public string Description { get; set; } public string Date { get; set; } }
    public class EtatApprentissage
    {
        public string Debut { get; set; } public string Fin { get; set; } public List<string> Appris { get; set; } public List<ExceptionApprise> Exceptions { get; set; }
    }
    public class EtatMaj { public string VerifieLe { get; set; } public string VersionInstallee { get; set; } public string VersionDisponible { get; set; } public string Statut { get; set; } public bool CleEpinglee { get; set; } }
    public class ConfigMaj
    {
        public ConfigMaj() { Auto = false; Url = "https://github.com/cryptobones-1337/deR4Tizer/releases/latest/download/manifeste.json"; }
        public bool Auto { get; set; } public string Url { get; set; }
    }

    // ------------------------------------------------------------ DPI (dpi.json) et IDS (ids.json)
    public class SessionDpi { public string Heure { get; set; } public string Programme { get; set; } public string Ip { get; set; } public int Port { get; set; } public string Nom { get; set; } public string Ja3 { get; set; } public string Remarque { get; set; } }
    public class EmpreinteJa3 { public string Ja3 { get; set; } public int Nombre { get; set; } public List<string> Programmes { get; set; } }
    public class EtatDpi
    {
        public string MisAJour { get; set; } public int SessionsTls { get; set; } public int RequetesHttp { get; set; } public int RequetesDns { get; set; }
        public int EmpreintesJa3Connues { get; set; } public List<SessionDpi> Tls { get; set; } public List<SessionDpi> Http { get; set; } public List<SessionDpi> Dns { get; set; }
        public List<EmpreinteJa3> Empreintes { get; set; }
    }
    public class DetectionIds
    {
        public string Heure { get; set; } public long Sid { get; set; } public string Message { get; set; } public string Classe { get; set; } public string Niveau { get; set; }
        public string Source { get; set; } public string Destination { get; set; } public string Programme { get; set; } public bool Bloque { get; set; }
    }
    public class EtatIds
    {
        public string MisAJour { get; set; } public int Regles { get; set; } public int Ignorees { get; set; } public List<string> Fichiers { get; set; }
        public bool Ips { get; set; } public long PaquetsAnalyses { get; set; } public List<DetectionIds> Detections { get; set; }
    }

    // Compte autorisé à lire les données (lecteurs.json)
    public class Lecteur { public string Sid { get; set; } public string Nom { get; set; } }

    public class ConfigNotifications
    {
        public ConfigNotifications() { NiveauMin = "Critique"; MaxParHeure = 10; SmtpPort = 465; SmtpSecurite = "SSL"; SmtpServeur = SmtpUtilisateur = Expediteur = Destinataires = ""; }
        public string NiveauMin { get; set; }
        public int MaxParHeure { get; set; }
        public bool Ntfy { get; set; }
        public bool Teams { get; set; }
        public bool Smtp { get; set; }
        public string SmtpServeur { get; set; }
        public int SmtpPort { get; set; }
        public string SmtpSecurite { get; set; }
        public string SmtpUtilisateur { get; set; }
        public string Expediteur { get; set; }
        public string Destinataires { get; set; }
    }

    // État des notifications (notifications.json, sans secret)
    public class EtatNotifications
    {
        public bool NtfyConfigure { get; set; }
        public bool TeamsConfigure { get; set; }
        public bool SmtpMotDePasse { get; set; }
        public long Envoyes { get; set; }
        public long Resumes { get; set; }
        public string DernierEnvoi { get; set; }
        public string DerniereErreur { get; set; }
    }

    public class ConfigSyslog
    {
        public ConfigSyslog() { Hote = ""; Port = 514; Protocole = "UDP"; Format = "JSON"; NiveauMin = "Alerte"; }
        public bool Actif { get; set; }
        public string Hote { get; set; }
        public int Port { get; set; }
        public string Protocole { get; set; }   // "UDP" ou "TCP"
        public string Format { get; set; }      // "JSON" ou "CEF"
        public string NiveauMin { get; set; }   // "Info", "Alerte" ou "Critique"
    }

    public class ConfigApi
    {
        public ConfigApi() { Port = 8642; Adresses = ""; }
        public bool Actif { get; set; }
        public int Port { get; set; }
        public bool Reseau { get; set; }
        public string Adresses { get; set; }
    }

    public class Alerte
    {
        public string Id { get; set; }
        public string Heure { get; set; }
        public string Niveau { get; set; }      // "Critique", "Alerte" ou "Info"
        public int Score { get; set; }
        public string Processus { get; set; }
        public string Chemin { get; set; }
        public string Destination { get; set; }
        public string Ip { get; set; }
        public string NomDns { get; set; }
        public int Port { get; set; }
        public string Raisons { get; set; }
        public int? Pid { get; set; }
        public string Mitre { get; set; }
        public string Conseil { get; set; }
        // Modèle d'événement (phase 3) : version, règle du registre, collecte présumée d'origine
        public int Modele { get; set; }
        public string Regle { get; set; }
        public string Collecte { get; set; }
    }

    public class Blocage
    {
        public string Type { get; set; }        // "hosts" ou "parefeu"
        public string Cible { get; set; }       // domaine ou IP
        public string Raison { get; set; }
        public string Date { get; set; }
    }

    public class Commande
    {
        // bloquer, bloquerIp, debloquer, toutDebloquer, config, majMenaces, reglages, notifications…
        public string Action { get; set; }
        public string Valeur { get; set; }
        public string Ip { get; set; }
        public string NomDns { get; set; }
        public string Type { get; set; }
        public string Cible { get; set; }
        public string Raison { get; set; }
        public List<string> Categories { get; set; }
    }

    public class Reponse
    {
        public bool Ok { get; set; }
        public string Message { get; set; }
    }

    public static class Commun
    {
        public const string Version = "4.3";
        public const string NomService = "deR4Tizer";
        public const string NomPipe = "deR4Tizer";
        public const int SeuilAlerte = 3;

        public static string Dossier = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "deR4Tizer");

        public static JavaScriptSerializer Json()
        {
            var j = new JavaScriptSerializer();
            j.MaxJsonLength = int.MaxValue;
            return j;
        }

        public static string Maintenant()
        {
            return DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        }

        public static T Lire<T>(string nom) where T : class
        {
            string f = Path.Combine(Dossier, nom);
            if (!File.Exists(f)) return null;
            for (int essai = 0; essai < 3; essai++)
            {
                try
                {
                    using (var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    using (var r = new StreamReader(fs, Encoding.UTF8))
                        return Json().Deserialize<T>(r.ReadToEnd());
                }
                catch (IOException) { Thread.Sleep(50); }
                catch (Exception) { return null; }
            }
            return null;
        }

        // Écriture atomique : fichier temporaire puis remplacement, pour que l'interface ne lise jamais un fichier à moitié écrit
        public static void Ecrire(string nom, object donnees)
        {
            string f = Path.Combine(Dossier, nom);
            string tmp = f + ".tmp";
            File.WriteAllText(tmp, Json().Serialize(donnees), Encoding.UTF8);
            for (int essai = 0; essai < 5; essai++)
            {
                try
                {
                    if (File.Exists(f)) File.Replace(tmp, f, null);
                    else File.Move(tmp, f);
                    return;
                }
                catch (IOException) { Thread.Sleep(50); }
                catch (UnauthorizedAccessException) { Thread.Sleep(50); }
            }
        }
    }
}
