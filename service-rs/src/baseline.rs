//! Baseline de sécurité, inspirée des baselines Intune / Microsoft Security Baseline, adaptée à un PC personnel.
//! Trois profils :
//!   - « journalisation » : journaux nécessaires à la détection, appliqué automatiquement par le service ;
//!   - « recommandé »     : durcissement sans effet de bord notable, appliqué à la demande ;
//!   - « renforcé »       : durcissement plus strict, peut gêner certains logiciels (indiqué règle par règle).
//! Tout passe par la GPO locale (Registry.pol, audit.csv). Les valeurs précédentes sont sauvegardées
//! pour pouvoir revenir en arrière, règle par règle ou en bloc.

use crate::commun::{self, Alerte};
use crate::evenements;
use crate::gpo::{self, EntreePol};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use winreg::enums::*;
use winreg::RegKey;

#[derive(Clone, Copy, PartialEq)]
pub enum Valeur {
    Dword(u32),
    Texte(&'static str),
}

#[derive(Clone, Copy)]
pub enum Mecanisme {
    /// Valeur de registre HKLM posée par la GPO locale
    Registre { cle: &'static str, nom: &'static str, valeur: Valeur },
    /// Sous-catégorie de la stratégie d'audit avancée (1 succès, 2 échec, 3 les deux)
    Audit { guid: &'static str, nom: &'static str, reglage: u32 },
    /// Journal d'événements à activer
    Journal { canal: &'static str },
}

pub struct Regle {
    pub id: &'static str,
    pub profil: &'static str,
    pub categorie: &'static str,
    pub titre: &'static str,
    pub pourquoi: &'static str,
    pub compat: &'static str,
    pub mecanismes: &'static [Mecanisme],
}

use Mecanisme::*;
use Valeur::*;

const ASR: &str = r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";
const DEFENDER: &str = r"SOFTWARE\Policies\Microsoft\Windows Defender";

macro_rules! asr {
    ($id:literal, $guid:literal, $mode:literal, $profil:literal, $titre:literal, $compat:literal) => {
        Regle {
            id: $id, profil: $profil, categorie: "Defender : réduction de la surface d'attaque", titre: $titre,
            pourquoi: "Règle ASR de Microsoft Defender : bloque une technique d'attaque courante avant qu'elle n'aboutisse.",
            compat: $compat,
            mecanismes: &[
                Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR", nom: "ExploitGuard_ASR_Rules", valeur: Dword(1) },
                Registre { cle: ASR, nom: $guid, valeur: Texte($mode) },
            ],
        }
    };
}

macro_rules! audit {
    ($id:literal, $guid:literal, $nom:literal, $reglage:literal, $titre:literal, $pourquoi:literal) => {
        Regle {
            id: $id, profil: "journalisation", categorie: "Journalisation : audit", titre: $titre, pourquoi: $pourquoi, compat: "",
            mecanismes: &[Audit { guid: $guid, nom: $nom, reglage: $reglage }],
        }
    };
}

pub static REGLES: &[Regle] = &[
    // ---------------------------------------------------------------- journalisation
    audit!("audit.processus", "{0CCE922B-69AE-11D9-BED3-505054503030}", "Audit Process Creation", 1,
        "Audit de la création de processus (4688)", "Historique de chaque programme lancé, même ceux qui ne durent qu'une seconde."),
    audit!("audit.fichiers", "{0CCE921D-69AE-11D9-BED3-505054503030}", "Audit File System", 1,
        "Audit du système de fichiers (4663)", "Nécessaire à la détection des voleurs de mots de passe et de cookies (lecture des fichiers des navigateurs)."),
    audit!("audit.autres-objets", "{0CCE9227-69AE-11D9-BED3-505054503030}", "Audit Other Object Access Events", 1,
        "Audit des tâches planifiées (4698)", "Trace la création de tâches planifiées, méthode de persistance très courante."),
    audit!("audit.connexion", "{0CCE9215-69AE-11D9-BED3-505054503030}", "Audit Logon", 3,
        "Audit des ouvertures de session (4624, 4625)", "Détecte les connexions à distance et les tentatives de mot de passe."),
    audit!("audit.connexion-speciale", "{0CCE921B-69AE-11D9-BED3-505054503030}", "Audit Special Logon", 1,
        "Audit des ouvertures de session à privilèges (4672)", "Repère l'utilisation de comptes administrateurs."),
    audit!("audit.identifiants", "{0CCE923F-69AE-11D9-BED3-505054503030}", "Audit Credential Validation", 3,
        "Audit de la validation des identifiants", "Repère les essais de mots de passe."),
    audit!("audit.comptes", "{0CCE9235-69AE-11D9-BED3-505054503030}", "Audit User Account Management", 3,
        "Audit de la gestion des comptes (4720…)", "Un compte créé en cachette est un signe classique de compromission."),
    audit!("audit.groupes", "{0CCE9237-69AE-11D9-BED3-505054503030}", "Audit Security Group Management", 1,
        "Audit des groupes de sécurité (4732…)", "Ajout d'un compte au groupe Administrateurs."),
    audit!("audit.politique", "{0CCE922F-69AE-11D9-BED3-505054503030}", "Audit Audit Policy Change", 3,
        "Audit des changements de stratégie d'audit", "Un attaquant qui coupe la journalisation laisse cette trace."),
    audit!("audit.extensions", "{0CCE9211-69AE-11D9-BED3-505054503030}", "Audit Security System Extension", 1,
        "Audit des extensions de sécurité (4697)", "Installation de services et de pilotes."),
    audit!("audit.etat", "{0CCE9210-69AE-11D9-BED3-505054503030}", "Audit Security State Change", 1,
        "Audit des changements d'état de sécurité", "Démarrages et arrêts du système, changement d'heure."),
    audit!("audit.pnp", "{0CCE9248-69AE-11D9-BED3-505054503030}", "Audit PNP Activity", 1,
        "Audit des périphériques branchés (6416)", "Clés USB et périphériques ajoutés."),
    audit!("audit.amovibles", "{0CCE9245-69AE-11D9-BED3-505054503030}", "Audit Removable Storage", 3,
        "Audit des supports amovibles", "Fichiers copiés vers ou depuis une clé USB."),
    audit!("audit.regles-parefeu", "{0CCE9232-69AE-11D9-BED3-505054503030}", "Audit MPSSVC Rule-Level Policy Change", 3,
        "Audit des changements de règles du pare-feu (4946-4950)", "Un malware ouvre souvent un port entrant ou s'autorise dans le pare-feu."),
    Regle {
        id: "journal.parefeu", profil: "journalisation", categorie: "Journalisation : pare-feu", titre: "Journal des paquets du pare-feu (pfirewall.log)",
        pourquoi: "Garde la trace des connexions acceptées et bloquées ; deR4Tizer y repère tout paquet entrant venu d'Internet (PC exposé).",
        compat: "",
        mecanismes: &[
            Registre { cle: r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging", nom: "LogDroppedPackets", valeur: Dword(1) },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging", nom: "LogSuccessfulConnections", valeur: Dword(1) },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging", nom: "LogFileSize", valeur: Dword(32767) },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging", nom: "LogFilePath", valeur: Texte(r"%systemroot%\system32\LogFiles\Firewall\pfirewall.log") },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging", nom: "LogDroppedPackets", valeur: Dword(1) },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging", nom: "LogSuccessfulConnections", valeur: Dword(1) },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging", nom: "LogFileSize", valeur: Dword(32767) },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging", nom: "LogFilePath", valeur: Texte(r"%systemroot%\system32\LogFiles\Firewall\pfirewall.log") },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging", nom: "LogDroppedPackets", valeur: Dword(1) },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging", nom: "LogSuccessfulConnections", valeur: Dword(1) },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging", nom: "LogFileSize", valeur: Dword(32767) },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging", nom: "LogFilePath", valeur: Texte(r"%systemroot%\system32\LogFiles\Firewall\pfirewall.log") },
        ],
    },
    Regle {
        id: "journal.ligne-commande", profil: "journalisation", categorie: "Journalisation : contenu", titre: "Ligne de commande dans les événements 4688",
        pourquoi: "Sans elle, on sait qu'un PowerShell a été lancé, mais pas ce qu'il a exécuté.", compat: "",
        mecanismes: &[Registre { cle: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit", nom: "ProcessCreationIncludeCmdLine_Enabled", valeur: Dword(1) }],
    },
    Regle {
        id: "journal.sous-categories", profil: "journalisation", categorie: "Journalisation : contenu", titre: "Forcer l'audit avancé (sous-catégories)",
        pourquoi: "Empêche l'ancienne stratégie d'audit d'écraser la stratégie avancée.", compat: "",
        mecanismes: &[Registre { cle: r"SYSTEM\CurrentControlSet\Control\Lsa", nom: "SCENoApplyLegacyAuditPolicy", valeur: Dword(1) }],
    },
    Regle {
        id: "journal.powershell-blocs", profil: "journalisation", categorie: "Journalisation : contenu", titre: "Journal des blocs de script PowerShell (4104)",
        pourquoi: "Enregistre le code PowerShell réellement exécuté, même obscurci ou téléchargé en mémoire.", compat: "",
        mecanismes: &[Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", nom: "EnableScriptBlockLogging", valeur: Dword(1) }],
    },
    Regle {
        id: "journal.powershell-modules", profil: "journalisation", categorie: "Journalisation : contenu", titre: "Journal des modules PowerShell (4103)",
        pourquoi: "Trace les commandes PowerShell appelées.", compat: "",
        mecanismes: &[
            Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging", nom: "EnableModuleLogging", valeur: Dword(1) },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames", nom: "*", valeur: Texte("*") },
        ],
    },
    Regle {
        id: "journal.taille-securite", profil: "journalisation", categorie: "Journalisation : contenu", titre: "Journal Sécurité de 1 Go",
        pourquoi: "Par défaut 20 Mo : avec l'audit activé, l'historique ne durerait que quelques heures.", compat: "",
        mecanismes: &[Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows\EventLog\Security", nom: "MaxSize", valeur: Dword(1_048_576) }],
    },
    Regle {
        id: "journal.dns", profil: "journalisation", categorie: "Journalisation : journaux", titre: "Journal du client DNS",
        pourquoi: "Associe chaque IP contactée au nom demandé ; repère les IP contactées sans requête DNS.", compat: "",
        mecanismes: &[Journal { canal: "Microsoft-Windows-DNS-Client/Operational" }],
    },
    Regle {
        id: "journal.taches", profil: "journalisation", categorie: "Journalisation : journaux", titre: "Journal du planificateur de tâches",
        pourquoi: "Historique de l'exécution des tâches planifiées.", compat: "",
        mecanismes: &[Journal { canal: "Microsoft-Windows-TaskScheduler/Operational" }],
    },

    // ---------------------------------------------------------------- Defender
    Regle {
        id: "defender.pua", profil: "recommandé", categorie: "Defender", titre: "Blocage des applications potentiellement indésirables",
        pourquoi: "Adwares, mineurs de cryptomonnaie, faux optimiseurs.", compat: "",
        mecanismes: &[Registre { cle: DEFENDER, nom: "PUAProtection", valeur: Dword(1) }],
    },
    Regle {
        id: "defender.cloud", profil: "recommandé", categorie: "Defender", titre: "Protection cloud avancée et blocage renforcé",
        pourquoi: "Defender interroge le cloud Microsoft pour les fichiers inconnus et bloque plus tôt.",
        compat: "Envoie des métadonnées de fichiers à Microsoft (comme le réglage par défaut de Windows).",
        mecanismes: &[
            Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", nom: "SpynetReporting", valeur: Dword(2) },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", nom: "SubmitSamplesConsent", valeur: Dword(1) },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine", nom: "MpCloudBlockLevel", valeur: Dword(2) },
        ],
    },
    Regle {
        id: "defender.reseau", profil: "recommandé", categorie: "Defender", titre: "Protection réseau",
        pourquoi: "Bloque l'accès aux sites malveillants connus depuis n'importe quel programme, pas seulement Edge.", compat: "",
        mecanismes: &[Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection", nom: "EnableNetworkProtection", valeur: Dword(1) }],
    },
    Regle {
        id: "defender.usb", profil: "recommandé", categorie: "Defender", titre: "Analyse des supports amovibles",
        pourquoi: "Les clés USB sont analysées lors de l'analyse complète.", compat: "",
        mecanismes: &[Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows Defender\Scan", nom: "DisableRemovableDriveScanning", valeur: Dword(0) }],
    },
    Regle {
        id: "defender.dossiers-audit", profil: "recommandé", categorie: "Defender", titre: "Accès contrôlé aux dossiers (mode audit)",
        pourquoi: "Note les programmes qui modifieraient Documents, Images… sans rien bloquer. Prépare le mode bloquant.", compat: "",
        mecanismes: &[Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access", nom: "EnableControlledFolderAccess", valeur: Dword(2) }],
    },
    Regle {
        id: "defender.dossiers-blocage", profil: "renforcé", categorie: "Defender", titre: "Accès contrôlé aux dossiers (blocage)",
        pourquoi: "Protection forte contre les rançongiciels : seuls les programmes de confiance modifient vos dossiers personnels.",
        compat: "Certains jeux et logiciels de retouche devront être autorisés dans Sécurité Windows.",
        mecanismes: &[Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access", nom: "EnableControlledFolderAccess", valeur: Dword(1) }],
    },
    asr!("asr.courriel", "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", "1", "recommandé", "Bloquer les exécutables arrivant par courriel", ""),
    asr!("asr.office-enfants", "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "1", "recommandé", "Empêcher Office de lancer d'autres programmes", "Rares macros professionnelles légitimes."),
    asr!("asr.office-executables", "3B576869-A4EC-4529-8536-B80A7769E899", "1", "recommandé", "Empêcher Office de créer des exécutables", ""),
    asr!("asr.office-injection", "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", "1", "recommandé", "Empêcher Office d'injecter du code dans d'autres processus", ""),
    asr!("asr.scripts-telecharges", "D3E037E1-3EB8-44C8-A917-57927947596D", "1", "recommandé", "Empêcher JavaScript/VBScript de lancer du contenu téléchargé", ""),
    asr!("asr.scripts-obscurcis", "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", "1", "recommandé", "Bloquer les scripts obscurcis", ""),
    asr!("asr.macros-win32", "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", "1", "recommandé", "Bloquer les appels Win32 depuis les macros Office", ""),
    asr!("asr.lsass", "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", "1", "recommandé", "Bloquer le vol d'identifiants dans LSASS", ""),
    asr!("asr.wmi-persistance", "E6DB77E5-3DF2-4CF1-B95A-636979351E5B", "1", "recommandé", "Bloquer la persistance par abonnement WMI", ""),
    asr!("asr.usb", "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4", "1", "recommandé", "Bloquer les programmes non signés lancés depuis une clé USB", ""),
    asr!("asr.rancongiciel", "C1DB55AB-C21A-4637-BB3F-A12568109D35", "1", "recommandé", "Protection avancée contre les rançongiciels", ""),
    asr!("asr.pilotes", "56A863A9-875E-4185-98A7-B882C64B5CE5", "1", "recommandé", "Bloquer les pilotes signés mais vulnérables (BYOVD)", ""),
    asr!("asr.adobe", "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C", "1", "recommandé", "Empêcher Adobe Reader de lancer d'autres programmes", ""),
    asr!("asr.prevalence", "01443614-CD74-433A-B99E-2ECDC07BFC25", "2", "renforcé", "Exécutables rares ou récents (mode audit)",
        "Mode audit seulement : en blocage, gênerait les jeux et outils de développement récents."),
    asr!("asr.psexec-wmi", "D1E49AAC-8F56-4280-B9BA-993A6D77406C", "1", "renforcé", "Bloquer les processus créés par PsExec et WMI",
        "Peut gêner certains outils d'administration et installeurs."),

    // ---------------------------------------------------------------- réseau
    Regle {
        id: "reseau.llmnr", profil: "recommandé", categorie: "Réseau", titre: "Désactiver LLMNR",
        pourquoi: "Protocole de résolution de noms local détourné pour voler des empreintes de mots de passe sur un réseau partagé.", compat: "",
        mecanismes: &[Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", nom: "EnableMulticast", valeur: Dword(0) }],
    },
    Regle {
        id: "reseau.smb1", profil: "recommandé", categorie: "Réseau", titre: "Désactiver le serveur SMBv1",
        pourquoi: "Protocole obsolète exploité par WannaCry.", compat: "Très vieux NAS ou imprimantes réseau d'avant 2010.",
        mecanismes: &[Registre { cle: r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", nom: "SMB1", valeur: Dword(0) }],
    },
    Regle {
        id: "reseau.invite-smb", profil: "recommandé", categorie: "Réseau", titre: "Refuser les connexions SMB invité non sécurisées",
        pourquoi: "Empêche de se connecter à un faux partage réseau sans authentification.", compat: "Certains vieux NAS sans mot de passe.",
        mecanismes: &[Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation", nom: "AllowInsecureGuestAuth", valeur: Dword(0) }],
    },
    Regle {
        id: "reseau.signature-smb", profil: "renforcé", categorie: "Réseau", titre: "Exiger la signature SMB (client)",
        pourquoi: "Empêche la modification des échanges avec un partage réseau.", compat: "Vieux NAS ne gérant pas la signature.",
        mecanismes: &[Registre { cle: r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", nom: "RequireSecuritySignature", valeur: Dword(1) }],
    },
    Regle {
        id: "reseau.pare-feu", profil: "recommandé", categorie: "Réseau", titre: "Pare-feu actif sur tous les profils, entrées bloquées",
        pourquoi: "Garantit que le pare-feu ne peut pas être coupé par erreur ou par un programme.", compat: "",
        mecanismes: &[
            Registre { cle: r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile", nom: "EnableFirewall", valeur: Dword(1) },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile", nom: "EnableFirewall", valeur: Dword(1) },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile", nom: "EnableFirewall", valeur: Dword(1) },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile", nom: "DefaultInboundAction", valeur: Dword(1) },
        ],
    },
    Regle {
        id: "reseau.bureau-distance", profil: "recommandé", categorie: "Réseau", titre: "Bureau à distance et Assistance à distance désactivés",
        pourquoi: "Les arnaques au faux support technique et les intrusions passent souvent par là.", compat: "Si vous utilisez le Bureau à distance, ne l'appliquez pas.",
        mecanismes: &[
            Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", nom: "fDenyTSConnections", valeur: Dword(1) },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", nom: "fAllowToGetHelp", valeur: Dword(0) },
        ],
    },

    // ---------------------------------------------------------------- système
    Regle {
        id: "systeme.autorun", profil: "recommandé", categorie: "Système", titre: "Exécution automatique désactivée",
        pourquoi: "Une clé USB ou un CD ne peut plus lancer de programme tout seul.", compat: "",
        mecanismes: &[
            Registre { cle: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", nom: "NoDriveTypeAutoRun", valeur: Dword(255) },
            Registre { cle: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", nom: "NoAutorun", valeur: Dword(1) },
        ],
    },
    Regle {
        id: "systeme.wdigest", profil: "recommandé", categorie: "Système", titre: "Pas de mots de passe en clair en mémoire (WDigest)",
        pourquoi: "Empêche des outils comme Mimikatz de lire les mots de passe en clair.", compat: "",
        mecanismes: &[Registre { cle: r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", nom: "UseLogonCredential", valeur: Dword(0) }],
    },
    Regle {
        id: "systeme.uac", profil: "recommandé", categorie: "Système", titre: "Contrôle de compte (UAC) sur le bureau sécurisé",
        pourquoi: "La demande d'élévation ne peut pas être cliquée par un programme malveillant.", compat: "",
        mecanismes: &[
            Registre { cle: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", nom: "EnableLUA", valeur: Dword(1) },
            Registre { cle: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", nom: "ConsentPromptBehaviorAdmin", valeur: Dword(2) },
            Registre { cle: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", nom: "PromptOnSecureDesktop", valeur: Dword(1) },
        ],
    },
    Regle {
        id: "systeme.smartscreen", profil: "recommandé", categorie: "Système", titre: "SmartScreen de Windows activé",
        pourquoi: "Avertit avant de lancer un programme téléchargé inconnu.", compat: "",
        mecanismes: &[
            Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows\System", nom: "EnableSmartScreen", valeur: Dword(1) },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows\System", nom: "ShellSmartScreenLevel", valeur: Texte("Warn") },
        ],
    },
    Regle {
        id: "systeme.msi-eleve", profil: "recommandé", categorie: "Système", titre: "Pas d'installation MSI toujours en administrateur",
        pourquoi: "Ce réglage permettrait à n'importe quel programme de devenir administrateur.", compat: "",
        mecanismes: &[Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows\Installer", nom: "AlwaysInstallElevated", valeur: Dword(0) }],
    },
    Regle {
        id: "systeme.lsa", profil: "renforcé", categorie: "Système", titre: "Protection LSA (processus protégé)",
        pourquoi: "Empêche la lecture de la mémoire de LSASS, où Windows garde les secrets de connexion.",
        compat: "Redémarrage nécessaire. Rares pilotes ou anciens gestionnaires d'identifiants incompatibles.",
        mecanismes: &[Registre { cle: r"SYSTEM\CurrentControlSet\Control\Lsa", nom: "RunAsPPL", valeur: Dword(1) }],
    },
    Regle {
        id: "systeme.wsh", profil: "renforcé", categorie: "Système", titre: "Windows Script Host désactivé (.vbs, .js)",
        pourquoi: "Les pièces jointes .vbs et .js sont un vecteur classique de malware.", compat: "Certains installeurs et scripts d'entreprise.",
        mecanismes: &[Registre { cle: r"SOFTWARE\Microsoft\Windows Script Host\Settings", nom: "Enabled", valeur: Dword(0) }],
    },

    // ---------------------------------------------------------------- vie privée
    Regle {
        id: "vie-privee.telemetrie", profil: "recommandé", categorie: "Vie privée", titre: "Télémétrie Windows au minimum requis",
        pourquoi: "Limite les données de diagnostic envoyées à Microsoft (méthode officielle, Defender ne l'annule pas).", compat: "",
        mecanismes: &[Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", nom: "AllowTelemetry", valeur: Dword(1) }],
    },
    Regle {
        id: "vie-privee.publicite", profil: "recommandé", categorie: "Vie privée", titre: "Identifiant de publicité désactivé", pourquoi: "Empêche le suivi publicitaire entre applications.", compat: "",
        mecanismes: &[Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo", nom: "DisabledByGroupPolicy", valeur: Dword(1) }],
    },
    Regle {
        id: "vie-privee.activites", profil: "recommandé", categorie: "Vie privée", titre: "Historique des activités désactivé", pourquoi: "Windows ne garde ni n'envoie l'historique de vos activités.", compat: "",
        mecanismes: &[
            Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows\System", nom: "PublishUserActivities", valeur: Dword(0) },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows\System", nom: "UploadUserActivities", valeur: Dword(0) },
        ],
    },
    Regle {
        id: "vie-privee.recall", profil: "recommandé", categorie: "Vie privée", titre: "Captures Recall désactivées",
        pourquoi: "Recall photographie l'écran en continu : une mine d'or pour un voleur de données.", compat: "",
        mecanismes: &[Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", nom: "DisableAIDataAnalysis", valeur: Dword(1) }],
    },
];

// ------------------------------------------------------------ état et conformité

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct EtatRegle {
    pub id: String,
    pub profil: String,
    pub categorie: String,
    pub titre: String,
    pub pourquoi: String,
    pub compat: String,
    /// "conforme", "non conforme", "inconnu"
    pub etat: String,
    pub actuel: String,
    pub attendu: String,
    pub appliquee: bool,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase", default)]
pub struct EtatBaseline {
    pub mis_a_jour: String,
    pub regles: Vec<EtatRegle>,
    pub scores: HashMap<String, u32>,
    pub message: String,
}

/// Valeurs d'origine sauvegardées avant application, pour le retour en arrière
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct Sauvegarde {
    /// id de règle -> liste (mécanisme, valeur d'origine ou null)
    regles: HashMap<String, Vec<(String, Option<String>)>>,
}

fn decrire(v: &Valeur) -> String {
    match v {
        Dword(n) => n.to_string(),
        Texte(t) => t.to_string(),
    }
}

fn lire_registre(cle: &str, nom: &str) -> Option<String> {
    let k = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(cle, KEY_READ | KEY_WOW64_64KEY).ok()?;
    k.get_value::<u32, _>(nom).map(|n| n.to_string()).or_else(|_| k.get_value::<String, _>(nom)).ok()
}

fn nom_audit(v: u32) -> &'static str {
    match v {
        1 => "succès",
        2 => "échec",
        3 => "succès et échec",
        _ => "aucun",
    }
}

/// Valeurs dont l'absence équivaut déjà au réglage sûr sur Windows 10/11
const SURS_PAR_DEFAUT: &[(&str, &str)] = &[
    ("SMB1", "LanmanServer"),
    ("UseLogonCredential", "WDigest"),
    ("AlwaysInstallElevated", "Installer"),
    ("AllowInsecureGuestAuth", "LanmanWorkstation"),
    ("EnableLUA", "Policies\\System"),
];

/// État d'un mécanisme : (conforme ?, valeur actuelle lisible, valeur attendue lisible)
fn verifier_mecanisme(m: &Mecanisme) -> (Option<bool>, String, String) {
    match m {
        Registre { cle, nom, valeur } => {
            let actuel = lire_registre(cle, nom);
            let attendu = decrire(valeur);
            if actuel.is_none() && SURS_PAR_DEFAUT.iter().any(|(n, c)| n == nom && cle.contains(c)) {
                return (Some(true), "absent (sûr par défaut)".into(), attendu);
            }
            (Some(actuel.as_deref() == Some(attendu.as_str())), actuel.unwrap_or_else(|| "absent".into()), attendu)
        }
        Audit { guid, reglage, .. } => match gpo::audit_effectif(guid) {
            Some(v) => (Some(v & reglage == *reglage), nom_audit(v).into(), nom_audit(*reglage).into()),
            None => (None, "illisible (droits admin)".into(), nom_audit(*reglage).into()),
        },
        Journal { canal } => match evenements::journal_actif(canal) {
            Some(a) => (Some(a), if a { "actif" } else { "inactif" }.into(), "actif".into()),
            None => (None, "introuvable".into(), "actif".into()),
        },
    }
}

/// Gestion existante du poste : la GPO de domaine ou Intune écraserait la GPO locale, ou entrerait en conflit
/// avec elle ; dans ce cas la baseline est seulement évaluée (lecture seule). Calculé une fois.
pub fn gestion() -> Option<String> {
    static G: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    G.get_or_init(|| {
        let mut l = Vec::new();
        crate::mesure::powershell("baseline");
        let sortie = std::process::Command::new(crate::natif::powershell_exe())
            .args(["-NoProfile", "-NonInteractive", "-Command",
                "$d = (Get-CimInstance Win32_ComputerSystem).PartOfDomain; \
                 $m = @(Get-ChildItem HKLM:\\SOFTWARE\\Microsoft\\Enrollments -ErrorAction SilentlyContinue | \
                   Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProviderID -eq 'MS DM Server' }).Count; \
                 \"$d|$m\""])
            .output().map(|s| String::from_utf8_lossy(&s.stdout).trim().to_string()).unwrap_or_default();
        let (domaine, mdm) = sortie.split_once('|').unwrap_or(("False", "0"));
        if domaine.eq_ignore_ascii_case("true") {
            l.push("domaine Active Directory");
        }
        if mdm.trim().parse::<u32>().unwrap_or(0) > 0 {
            l.push("Intune (ou autre gestion MDM)");
        }
        (!l.is_empty()).then(|| format!("Poste géré par {} : la baseline est en lecture seule, pour ne pas entrer en conflit avec les stratégies de l'organisation.", l.join(" et ")))
    }).clone()
}

pub fn evaluer() -> EtatBaseline {
    let sauvegarde: Sauvegarde = commun::lire("baseline-sauvegarde.json").unwrap_or_default();
    let mut regles = Vec::new();
    let mut totaux: HashMap<&str, (u32, u32)> = HashMap::new();
    for r in REGLES {
        let verifs: Vec<_> = r.mecanismes.iter().map(verifier_mecanisme).collect();
        let etat = if verifs.iter().any(|v| v.0 == Some(false)) {
            "non conforme"
        } else if verifs.iter().all(|v| v.0 == Some(true)) {
            "conforme"
        } else {
            "inconnu"
        };
        let t = totaux.entry(r.profil).or_default();
        t.1 += 1;
        if etat == "conforme" {
            t.0 += 1;
        }
        regles.push(EtatRegle {
            id: r.id.into(),
            profil: r.profil.into(),
            categorie: r.categorie.into(),
            titre: r.titre.into(),
            pourquoi: r.pourquoi.into(),
            compat: r.compat.into(),
            etat: etat.into(),
            actuel: verifs.iter().map(|v| v.1.clone()).collect::<Vec<_>>().join(" / "),
            attendu: verifs.iter().map(|v| v.2.clone()).collect::<Vec<_>>().join(" / "),
            appliquee: sauvegarde.regles.contains_key(r.id),
        });
    }
    let scores = totaux.into_iter().map(|(p, (ok, n))| (p.to_string(), if n == 0 { 0 } else { ok * 100 / n })).collect();
    EtatBaseline { mis_a_jour: commun::maintenant(), regles, scores, message: gestion().unwrap_or_default() }
}

// ------------------------------------------------------------ application et retour en arrière

fn entree(cle: &str, nom: &str, v: &Valeur) -> EntreePol {
    match v {
        Dword(n) => EntreePol::dword(cle, nom, *n),
        Texte(t) => EntreePol::texte(cle, nom, t),
    }
}

fn sauvegarder_fichiers_gpo() {
    // Copie unique des fichiers d'origine de la GPO locale, avant toute première modification
    let dossier = commun::dossier().join(r"sauvegardes\gpo-origine");
    if dossier.exists() {
        return;
    }
    let _ = std::fs::create_dir_all(&dossier);
    let racine = gpo::racine();
    for (src, dst) in [(r"gpt.ini", "gpt.ini"), (r"Machine\Registry.pol", "Registry.pol"), (r"Machine\Microsoft\Windows NT\Audit\audit.csv", "audit.csv")] {
        let _ = std::fs::copy(racine.join(src), dossier.join(dst));
    }
}

/// Règles d'un profil (ou liste d'identifiants séparés par des virgules)
pub fn selection(cible: &str) -> Vec<&'static Regle> {
    let ids: Vec<&str> = cible.split(',').map(str::trim).collect();
    REGLES.iter().filter(|r| ids.contains(&r.profil) || ids.contains(&r.id) || (ids.contains(&"recommandé+") && r.profil != "renforcé")).collect()
}

pub fn appliquer(regles: &[&Regle]) -> Result<String, String> {
    if let Some(g) = gestion() {
        return Err(g);
    }
    sauvegarder_fichiers_gpo();
    let mut sauvegarde: Sauvegarde = commun::lire("baseline-sauvegarde.json").unwrap_or_default();
    let mut ajouts = Vec::new();
    let mut audit = gpo::lire_audit();
    let mut audit_modifie = false;
    for r in regles {
        let mut origine = Vec::new();
        for m in r.mecanismes {
            match m {
                Registre { cle, nom, valeur } => {
                    origine.push((format!(r"reg|{cle}|{nom}"), lire_registre(cle, nom)));
                    ajouts.push(entree(cle, nom, valeur));
                }
                Audit { guid, nom, reglage } => {
                    let actuel = gpo::audit_effectif(guid).unwrap_or(0);
                    origine.push((format!("audit|{guid}|{nom}"), Some(actuel.to_string())));
                    let guid_maj = guid.to_uppercase();
                    match audit.iter_mut().find(|l| l.0 == guid_maj) {
                        Some(l) => l.2 |= reglage,
                        None => audit.push((guid_maj, nom.to_string(), *reglage | actuel)),
                    }
                    audit_modifie = true;
                }
                Journal { canal } => {
                    let actif = evenements::journal_actif(canal).unwrap_or(false);
                    origine.push((format!("journal|{canal}"), Some(actif.to_string())));
                    evenements::activer_journal(canal, true);
                }
            }
        }
        // On ne garde que la toute première valeur d'origine d'une règle
        sauvegarde.regles.entry(r.id.to_string()).or_insert(origine);
    }
    gpo::modifier_pol(&ajouts, &[]).map_err(|e| format!("Registry.pol : {e}"))?;
    if audit_modifie {
        gpo::ecrire_audit(&audit).map_err(|e| format!("audit.csv : {e}"))?;
    }
    gpo::marquer_gpt(audit_modifie).map_err(|e| format!("gpt.ini : {e}"))?;
    let _ = commun::ecrire("baseline-sauvegarde.json", &sauvegarde);
    gpo::gpupdate()?;
    // Le service Journal d'événements ne relit la taille maximale qu'à son redémarrage : appliquée aussi tout de suite
    for r in regles {
        for m in r.mecanismes {
            if let Registre { cle, nom: "MaxSize", valeur: Dword(ko) } = m {
                if cle.contains(r"\EventLog\") {
                    let canal = cle.rsplit('\\').next().unwrap_or("");
                    let _ = std::process::Command::new("wevtutil.exe").args(["sl", canal, &format!("/ms:{}", *ko as u64 * 1024)]).output();
                }
            }
        }
    }
    Ok(format!("{} règle(s) appliquée(s) par la GPO locale.", regles.len()))
}

/// Taille effective des journaux pour les règles appliquées : le service Journal d'événements ne relit la
/// stratégie qu'à son redémarrage (appelé au démarrage du service)
pub fn forcer_tailles() {
    let sauvegarde: Sauvegarde = commun::lire("baseline-sauvegarde.json").unwrap_or_default();
    for r in REGLES.iter().filter(|r| sauvegarde.regles.contains_key(r.id)) {
        for m in r.mecanismes {
            if let Registre { cle, nom: "MaxSize", valeur: Dword(ko) } = m {
                if cle.contains(r"\EventLog\") {
                    let canal = cle.rsplit('\\').next().unwrap_or("");
                    let _ = std::process::Command::new("wevtutil.exe").args(["sl", canal, &format!("/ms:{}", *ko as u64 * 1024)]).output();
                }
            }
        }
    }
}

pub fn annuler(regles: &[&Regle]) -> Result<String, String> {
    let mut sauvegarde: Sauvegarde = commun::lire("baseline-sauvegarde.json").unwrap_or_default();
    let mut retraits = Vec::new();
    let mut audit = gpo::lire_audit();
    let mut audit_modifie = false;
    let mut n = 0;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    for r in regles {
        let Some(origine) = sauvegarde.regles.remove(r.id) else { continue };
        n += 1;
        for (m, valeur) in origine {
            let parties: Vec<&str> = m.splitn(3, '|').collect();
            match parties.as_slice() {
                ["reg", cle, nom] => {
                    retraits.push(EntreePol::dword(cle, nom, 0));
                    // La valeur posée reste dans le registre : on remet celle d'origine (ou on la supprime)
                    if let Ok((k, _)) = hklm.create_subkey_with_flags(cle, KEY_ALL_ACCESS | KEY_WOW64_64KEY) {
                        match valeur.as_deref().map(|v| v.parse::<u32>()) {
                            Some(Ok(d)) => {
                                let _ = k.set_value(nom, &d);
                            }
                            Some(Err(_)) => {
                                let _ = k.set_value(nom, &valeur.clone().unwrap_or_default());
                            }
                            None => {
                                let _ = k.delete_value(nom);
                            }
                        }
                    }
                }
                ["audit", guid, _] => {
                    let avant: u32 = valeur.as_deref().and_then(|v| v.parse().ok()).unwrap_or(0);
                    if let Some(l) = audit.iter_mut().find(|l| l.0 == guid.to_uppercase()) {
                        l.2 = avant;
                    }
                    let _ = std::process::Command::new("auditpol.exe")
                        .args(["/set", &format!("/subcategory:{guid}"),
                            &format!("/success:{}", if avant & 1 != 0 { "enable" } else { "disable" }),
                            &format!("/failure:{}", if avant & 2 != 0 { "enable" } else { "disable" })])
                        .output();
                    audit_modifie = true;
                }
                ["journal", canal] => {
                    if valeur.as_deref() == Some("false") {
                        evenements::activer_journal(canal, false);
                    }
                }
                _ => {}
            }
        }
    }
    // Réglages partagés (ExploitGuard_ASR_Rules pour toutes les règles ASR, EnableControlledFolderAccess pour
    // l'audit et le blocage…) : s'ils servent encore à une règle toujours appliquée, on remet sa valeur au lieu
    // de les retirer
    let mut ajouts = Vec::new();
    let retires: Vec<(String, String)> = retraits.iter().map(|e: &EntreePol| (e.cle.clone(), e.nom.clone())).collect();
    let restantes: Vec<&Regle> = REGLES.iter().filter(|r| sauvegarde.regles.contains_key(r.id)).collect();
    for (cle, nom, valeur) in reglages_partages(&retires, &restantes) {
        retraits.retain(|e: &EntreePol| !(e.cle.eq_ignore_ascii_case(cle) && e.nom.eq_ignore_ascii_case(nom)));
        ajouts.retain(|e: &EntreePol| !(e.cle.eq_ignore_ascii_case(cle) && e.nom.eq_ignore_ascii_case(nom)));
        ajouts.push(entree(cle, nom, valeur));
        if let Ok((k, _)) = hklm.create_subkey_with_flags(cle, KEY_ALL_ACCESS | KEY_WOW64_64KEY) {
            let _ = match valeur {
                Dword(n) => k.set_value(nom, n),
                Texte(t) => k.set_value(nom, &t.to_string()),
            };
        }
    }
    gpo::modifier_pol(&ajouts, &retraits).map_err(|e| format!("Registry.pol : {e}"))?;
    if audit_modifie {
        audit.retain(|l| l.2 != 0);
        gpo::ecrire_audit(&audit).map_err(|e| format!("audit.csv : {e}"))?;
    }
    gpo::marquer_gpt(audit_modifie).map_err(|e| format!("gpt.ini : {e}"))?;
    let _ = commun::ecrire("baseline-sauvegarde.json", &sauvegarde);
    gpo::gpupdate()?;
    Ok(format!("{n} règle(s) annulée(s) : valeurs d'origine restaurées."))
}

/// Écarts sur des règles appliquées par deR4Tizer : quelqu'un a modifié un réglage de sécurité
pub fn derives(avant: &EtatBaseline, apres: &EtatBaseline) -> Vec<Alerte> {
    let anciens: HashMap<&str, &EtatRegle> = avant.regles.iter().map(|r| (r.id.as_str(), r)).collect();
    apres.regles.iter()
        .filter(|r| r.appliquee && r.etat == "non conforme" && anciens.get(r.id.as_str()).map(|a| a.etat == "conforme").unwrap_or(false))
        .map(|r| Alerte {
            regle: crate::regles::BAS_001.into(),
            id: commun::nouvel_id(),
            heure: commun::maintenant(),
            niveau: "Alerte".into(),
            score: 5,
            processus: "?".into(),
            destination: format!("baseline : {}", r.titre),
            raisons: format!("réglage de sécurité MODIFIÉ hors de deR4Tizer (attendu : {}, actuel : {})", r.attendu, r.actuel),
            ..Default::default()
        })
        .collect()
}

/// Réglages retirés par une annulation mais encore utilisés par une règle toujours appliquée : on remet la
/// valeur de cette règle au lieu de les retirer (ExploitGuard_ASR_Rules, EnableControlledFolderAccess…)
pub fn reglages_partages<'a>(retires: &[(String, String)], restantes: &[&'a Regle]) -> Vec<(&'a str, &'a str, &'a Valeur)> {
    let mut l: Vec<(&str, &str, &Valeur)> = Vec::new();
    for r in restantes {
        for m in r.mecanismes {
            if let Registre { cle, nom, valeur } = m {
                if retires.iter().any(|(c, n)| c.eq_ignore_ascii_case(cle) && n.eq_ignore_ascii_case(nom))
                    && !l.iter().any(|(c, n, _)| c.eq_ignore_ascii_case(cle) && n.eq_ignore_ascii_case(nom)) {
                    l.push((cle, nom, valeur));
                }
            }
        }
    }
    l
}
