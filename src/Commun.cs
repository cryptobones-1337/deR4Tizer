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
    }

    // Exposition du PC à Internet (paquets entrants venus d'Internet, adresses publiques)
    public class Exposition
    {
        public bool Exposee { get; set; }
        public List<string> Raisons { get; set; }
        public List<string> AdressesPubliques { get; set; }
        public bool JournalPaquets { get; set; }
        public List<EntreeExposee> Entrees { get; set; }
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
        public Config() { BlocageAutoMenaces = true; ReponseAutoRancongiciel = true; Langue = "fr"; Syslog = new ConfigSyslog(); Api = new ConfigApi(); }
        public string Langue { get; set; }
        public ConfigSyslog Syslog { get; set; }
        public ConfigApi Api { get; set; }
        // Bloque au pare-feu, dès qu'une connexion est vue, les IP des listes de confiance haute
        public bool BlocageAutoMenaces { get; set; }
        // Suspend aussitôt le programme qui modifie un fichier leurre
        public bool ReponseAutoRancongiciel { get; set; }
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
        public ConfigApi() { Port = 8642; }
        public bool Actif { get; set; }
        public int Port { get; set; }
        public bool Reseau { get; set; }
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
        // bloquer, bloquerIp, debloquer, toutDebloquer, telemetrie, config, majMenaces
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
        public const string Version = "3.1";
        public const string NomService = "deR4Tizer";
        public const string NomPipe = "deR4Tizer";
        public const int SeuilAlerte = 3;

        public static string Dossier = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "deR4Tizer");

        // Domaines de télémétrie connus, par éditeur
        public static readonly Dictionary<string, string[]> Telemetrie = new Dictionary<string, string[]>
        {
            { "Microsoft / Windows", new[] {
                "vortex.data.microsoft.com", "vortex-win.data.microsoft.com", "settings-win.data.microsoft.com",
                "v10.events.data.microsoft.com", "v20.events.data.microsoft.com", "self.events.data.microsoft.com",
                "mobile.events.data.microsoft.com", "umwatson.events.data.microsoft.com", "watson.events.data.microsoft.com",
                "watson.telemetry.microsoft.com", "telecommand.telemetry.microsoft.com", "oca.telemetry.microsoft.com",
                "sqm.telemetry.microsoft.com" } },
            { "NVIDIA", new[] { "telemetry.gfe.nvidia.com", "events.gfe.nvidia.com" } },
            { "Mozilla", new[] { "incoming.telemetry.mozilla.org" } },
            { "Adobe", new[] { "cc-api-data.adobe.io" } },
        };

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
