//! Baseline de sécurité, inspirée des baselines Intune / Microsoft Security Baseline, adaptée à un PC personnel.
//! Trois profils :
//!   - « journalisation » : journaux nécessaires à la détection, appliqué automatiquement par le service ;
//!   - « recommandé »     : durcissement courant, appliqué à la demande ; quelques règles changent l'usage du poste
//!                          (Bureau à distance, invites du contrôle de compte, partages invités), dites règle par règle ;
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
        pourquoi: "Adwares, mineurs de cryptomonnaie, faux optimiseurs.", compat: "Sécurité Windows peut alors afficher « géré par votre organisation » et griser l'interrupteur de ce réglage.",
        mecanismes: &[Registre { cle: DEFENDER, nom: "PUAProtection", valeur: Dword(1) }],
    },
    Regle {
        id: "defender.cloud", profil: "recommandé", categorie: "Defender", titre: "Protection cloud avancée et blocage renforcé",
        pourquoi: "Defender interroge le cloud Microsoft pour les fichiers inconnus et bloque plus tôt.",
        compat: "Envoie des métadonnées de fichiers à Microsoft (comme le réglage par défaut de Windows). Sécurité Windows peut alors afficher « géré par votre organisation » et griser l'interrupteur de ce réglage.",
        mecanismes: &[
            Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", nom: "SpynetReporting", valeur: Dword(2) },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", nom: "SubmitSamplesConsent", valeur: Dword(1) },
            Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine", nom: "MpCloudBlockLevel", valeur: Dword(2) },
        ],
    },
    Regle {
        id: "defender.reseau", profil: "recommandé", categorie: "Defender", titre: "Protection réseau",
        pourquoi: "Bloque l'accès aux sites malveillants connus depuis n'importe quel programme, pas seulement Edge.", compat: "Sécurité Windows peut alors afficher « géré par votre organisation » et griser l'interrupteur de ce réglage.",
        mecanismes: &[Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection", nom: "EnableNetworkProtection", valeur: Dword(1) }],
    },
    Regle {
        id: "defender.usb", profil: "recommandé", categorie: "Defender", titre: "Analyse des supports amovibles",
        pourquoi: "Les clés USB sont analysées lors de l'analyse complète.", compat: "Sécurité Windows peut alors afficher « géré par votre organisation » et griser l'interrupteur de ce réglage.",
        mecanismes: &[Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows Defender\Scan", nom: "DisableRemovableDriveScanning", valeur: Dword(0) }],
    },
    Regle {
        id: "defender.dossiers-audit", profil: "recommandé", categorie: "Defender", titre: "Accès contrôlé aux dossiers (mode audit)",
        pourquoi: "Note les programmes qui modifieraient Documents, Images… sans rien bloquer. Prépare le mode bloquant.", compat: "Sécurité Windows peut alors afficher « géré par votre organisation » et griser l'interrupteur de ce réglage.",
        mecanismes: &[Registre { cle: r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access", nom: "EnableControlledFolderAccess", valeur: Dword(2) }],
    },
    Regle {
        id: "defender.dossiers-blocage", profil: "renforcé", categorie: "Defender", titre: "Accès contrôlé aux dossiers (blocage)",
        pourquoi: "Protection forte contre les rançongiciels : seuls les programmes de confiance modifient vos dossiers personnels.",
        compat: "Certains jeux et logiciels de retouche devront être autorisés dans Sécurité Windows. Sécurité Windows peut alors afficher « géré par votre organisation » et griser l'interrupteur de ce réglage.",
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
        pourquoi: "Empêche de se connecter à un faux partage réseau sans authentification.", compat: "Les partages réseau en accès invité, sans mot de passe (certains vieux NAS), ne sont plus accessibles.",
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
        pourquoi: "Les arnaques au faux support technique et les intrusions passent souvent par là.", compat: "Coupe le Bureau à distance et l'Assistance à distance. Appliquée avec tout le profil, elle est laissée de côté si le Bureau à distance est activé sur ce poste.",
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
        pourquoi: "La demande d'élévation ne peut pas être cliquée par un programme malveillant.",
        compat: "Un compte administrateur reçoit une demande de confirmation, sur le bureau sécurisé, pour chaque élévation, y compris celles d'outils de Windows.",
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
        compat: "Redémarrage nécessaire. Rares pilotes ou anciens gestionnaires d'identifiants incompatibles. Windows 11 22H2 ou plus récent seulement : protection sans verrou UEFI, donc annulable (c'est déjà le réglage par défaut des installations récentes) ; sur une version plus ancienne, la règle est écartée (le reste du profil s'applique) et sortie du score.",
        mecanismes: &[Registre { cle: r"SYSTEM\CurrentControlSet\Control\Lsa", nom: "RunAsPPL", valeur: Dword(2) }],
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
    /// État lu dans le registre seul, gardé en mémoire et jamais publié : BAS-001 porte sur lui, pour qu'un tour
    /// « inconnu » ou « sans effet » dû à Defender ne casse pas la chaîne d'alertes (audit de #217, S217-01)
    #[serde(skip)]
    pub etat_registre: String,
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

/// Valeurs plus strictes qui satisfont une règle moins stricte posée sur la même clé (relecture de la baseline du
/// 2026-11-20, B3) : (nom de la valeur, valeur attendue, valeurs plus strictes acceptées). L'accès contrôlé aux
/// dossiers en blocage (1) satisfait la règle « mode audit » (2) et n'est jamais rétrogradé par elle
/// La protection LSA avec verrou UEFI (RunAsPPL = 1) satisfait la règle sans verrou (2) : elle protège autant, mais
/// n'est pas annulable sans l'outil de Microsoft ; deR4Tizer ne la pose jamais (B5)
pub const PLUS_STRICTES: &[(&str, u32, &[u32])] = &[("EnableControlledFolderAccess", 2, &[1]), ("RunAsPPL", 2, &[1])];

/// Build de Windows à partir duquel RunAsPPL = 2 (protection sans verrou UEFI) existe : Windows 11 22H2 (22621)
pub const BUILD_LSA_SANS_VERROU: u32 = 22621;

/// Décision pure : la règle LSA peut-elle être appliquée sur ce build ? Build illisible : non (échec fermé)
pub fn lsa_applicable(build: Option<u32>) -> bool {
    build.map(|b| b >= BUILD_LSA_SANS_VERROU).unwrap_or(false)
}

fn build_windows() -> Option<u32> {
    lire_registre(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber")?.trim().parse().ok()
}

/// Taille maximale effective d'un journal, lue dans la sortie de « wevtutil gl » (ligne « maxSize: N »)
pub fn taille_effective(sortie: &str) -> Option<u64> {
    sortie.lines().find_map(|l| {
        let (n, v) = l.trim().split_once(':')?;
        if n.trim().eq_ignore_ascii_case("maxSize") { v.trim().parse().ok() } else { None }
    })
}

fn lire_taille_journal(canal: &str) -> Option<u64> {
    let o = std::process::Command::new(gpo::outil_systeme("wevtutil.exe")).args(["gl", canal]).output().ok()?;
    if !o.status.success() {
        return None;
    }
    taille_effective(&String::from_utf8_lossy(&o.stdout))
}

fn plus_stricte(nom: &str, attendu: &Valeur, autre: &Valeur) -> bool {
    match (attendu, autre) {
        // Taille de journal : une taille plus grande que la cible est plus stricte (audit de #219, S219-05)
        (Dword(a), Dword(b)) if nom.eq_ignore_ascii_case("MaxSize") => b > a,
        (Dword(a), Dword(b)) => PLUS_STRICTES.iter().any(|(n, v, acc)| n.eq_ignore_ascii_case(nom) && v == a && acc.contains(b)),
        _ => false,
    }
}

/// Valeur actuelle conforme à l'attendu : égale, ou plus stricte selon PLUS_STRICTES
pub fn valeur_satisfaite(nom: &str, attendu: &Valeur, actuel: Option<&str>) -> bool {
    match actuel {
        None => false,
        Some(a) if a == decrire(attendu) => true,
        Some(a) => a.trim().parse::<u32>().map(|b| plus_stricte(nom, attendu, &Dword(b))).unwrap_or(false),
    }
}

/// Une valeur n'est pas écrite si une règle déjà appliquée, ou appliquée en même temps, pose une valeur plus
/// stricte sur la même clé : appliquer « recommandé » après « renforcé » ne rétrograde rien
pub fn ecriture_retenue(cle: &str, nom: &str, valeur: &Valeur, autres: &[(&str, &str, &Valeur)]) -> bool {
    !autres.iter().any(|(c, n, v)| c.eq_ignore_ascii_case(cle) && n.eq_ignore_ascii_case(nom) && plus_stricte(nom, valeur, v))
}

/// Valeur déjà en place plus stricte que celle de la règle (RunAsPPL = 1 posé par l'administrateur) : elle n'est pas
/// remplacée (audit de #218, S218-01)
pub fn deja_plus_stricte(nom: &str, valeur: &Valeur, actuel: Option<&str>) -> bool {
    actuel.and_then(|a| a.trim().parse::<u32>().ok()).map(|b| plus_stricte(nom, valeur, &Dword(b))).unwrap_or(false)
}

/// Taille de journal à poser seulement si la taille effective est plus petite que la cible : un journal plus grand
/// n'est jamais réduit (audit de #218, S218-02)
pub fn taille_a_poser(effective: u64, cible_ko: u32) -> bool {
    effective < cible_ko as u64 * 1024
}

/// Décision pure de l'évaluation : sans stratégie, un journal dont la taille effective atteint la cible est conforme ;
/// plus petit, illisible, ou avec une stratégie présente : jamais par ce chemin (prérelecture de #219, D1 ; S219-01)
pub fn conforme_par_taille_effective(strategie: Option<&str>, effective: Option<u64>, cible_ko: u32) -> bool {
    strategie.is_none() && effective.map(|t| !taille_a_poser(t, cible_ko)).unwrap_or(false)
}

/// Décision pure : la stratégie de taille est écrite si le journal est plus petit que la cible, ou si une stratégie
/// présente est plus petite que la cible ; absente avec un journal assez grand : rien (audit de #219, S219-01)
pub fn strategie_taille_a_ecrire(effective: u64, cible_ko: u32, strategie: Option<&str>) -> bool {
    match strategie.and_then(|s| s.trim().parse::<u64>().ok()) {
        Some(ko) if ko < cible_ko as u64 => true,
        // Stratégie au moins égale à la cible (2 Go posés par l'organisation) : jamais abaissée (audit de #219, S219-05)
        Some(_) => false,
        None if strategie.is_some() => true,
        None => taille_a_poser(effective, cible_ko),
    }
}

/// Canal d'une clé de stratégie de taille de journal (…\EventLog\<canal>), s'il en est une
fn canal_taille(cle: &str, nom: &str) -> Option<&'static str> {
    if nom != "MaxSize" || !cle.contains(r"\EventLog\") {
        return None;
    }
    REGLES.iter().flat_map(|r| r.mecanismes.iter()).find_map(|m| match m {
        Registre { cle: c, nom: "MaxSize", .. } if c.eq_ignore_ascii_case(cle) => c.rsplit('\\').next(),
        _ => None,
    })
}

/// Propriété de MSFT_MpPreference qui porte l'effet d'une valeur de stratégie Defender (B4)
pub fn propriete_effective(nom: &str) -> Option<&'static str> {
    match nom {
        "PUAProtection" => Some("PUAProtection"),
        "SpynetReporting" => Some("MAPSReporting"),
        "SubmitSamplesConsent" => Some("SubmitSamplesConsent"),
        "MpCloudBlockLevel" => Some("CloudBlockLevel"),
        "EnableNetworkProtection" => Some("EnableNetworkProtection"),
        "DisableRemovableDriveScanning" => Some("DisableRemovableDriveScanning"),
        "EnableControlledFolderAccess" => Some("EnableControlledFolderAccess"),
        _ => None,
    }
}

/// Effet réel d'un mécanisme Defender déjà posé dans le registre (relecture de la baseline du 2026-11-20, B4)
#[derive(Debug, Clone, PartialEq)]
pub enum Effet {
    /// Mécanisme hors Defender, ou sans état effectif propre (ExploitGuard_ASR_Rules)
    NonConcerne,
    Conforme,
    /// Posé, mais sans effet : la raison est dite
    SansEffet(String),
    /// État de Defender illisible : jamais « conforme »
    Illisible,
}

/// Décision pure : effet d'un mécanisme selon l'état effectif de Defender et son mode de fonctionnement
/// (AMRunningMode ; vide = illisible)
pub fn effet_defender(m: &Mecanisme, prefs: Option<&crate::defender::PrefsDefender>, mode: &str) -> Effet {
    let Registre { cle, nom, valeur } = m else { return Effet::NonConcerne };
    let est_asr = cle.eq_ignore_ascii_case(ASR);
    let propriete = if est_asr { None } else {
        match propriete_effective(nom) {
            Some(p) => Some(p),
            None => return Effet::NonConcerne,
        }
    };
    if mode.trim().is_empty() {
        return Effet::Illisible;
    }
    if !mode.trim().eq_ignore_ascii_case("Normal") {
        return Effet::SansEffet(format!("Microsoft Defender n'est pas l'antivirus actif (mode « {} »)", mode.trim()));
    }
    let Some(p) = prefs else { return Effet::Illisible };
    let effectif = match propriete {
        None => match p.asr.get(&nom.to_uppercase()) {
            Some(a) => a.clone(),
            None => return Effet::SansEffet("règle posée par stratégie, absente des règles ASR en vigueur dans Defender".into()),
        },
        Some(prop) => match p.valeurs.get(prop) {
            Some(v) => v.clone(),
            None => return Effet::Illisible,
        },
    };
    if valeur_satisfaite(nom, valeur, Some(&effectif)) {
        Effet::Conforme
    } else {
        Effet::SansEffet(format!("réglage posé, mais Defender applique la valeur {effectif}"))
    }
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

/// Lecture d'une valeur de registre qui distingue « introuvable » de toute autre erreur (réaudit de #270, S270-03)
#[derive(Clone, Debug, PartialEq)]
pub enum LectureRegistre {
    Valeur(String),
    /// Clé ou valeur introuvable
    Absente,
    /// Clé illisible, lecture en échec ou type non lu (QWORD, MULTI_SZ…)
    Illisible(String),
}

/// Décision pure de lire_registre_etat : seul « introuvable » (clé ou valeur) vaut absente ; une valeur DWORD ou
/// texte est lue ; toute autre erreur, ou un autre type, est illisible
pub fn classer_lecture(ouverture: Result<(), std::io::ErrorKind>, dword: Result<u32, std::io::ErrorKind>, texte: Result<String, std::io::ErrorKind>) -> LectureRegistre {
    use std::io::ErrorKind::NotFound;
    match ouverture {
        Ok(()) => {}
        Err(NotFound) => return LectureRegistre::Absente,
        Err(e) => return LectureRegistre::Illisible(format!("clé illisible : {e:?}")),
    }
    match dword {
        Ok(n) => return LectureRegistre::Valeur(n.to_string()),
        Err(NotFound) => return LectureRegistre::Absente,
        Err(_) => {}
    }
    match texte {
        Ok(s) => LectureRegistre::Valeur(s),
        Err(NotFound) => LectureRegistre::Absente,
        Err(e) => LectureRegistre::Illisible(format!("valeur illisible ou d'un type non lu : {e:?}")),
    }
}

fn lire_registre_etat(cle: &str, nom: &str) -> LectureRegistre {
    match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(cle, KEY_READ | KEY_WOW64_64KEY) {
        Err(e) => classer_lecture(Err(e.kind()), Err(e.kind()), Err(e.kind())),
        Ok(k) => classer_lecture(Ok(()), k.get_value::<u32, _>(nom).map_err(|e| e.kind()), k.get_value::<String, _>(nom).map_err(|e| e.kind())),
    }
}

/// Décision pure : texte des valeurs actuelles illisibles à l'annulation (S270-03) ; au plus 5 citées
pub fn message_illisibles(illisibles: &[String]) -> String {
    if illisibles.is_empty() {
        return String::new();
    }
    let citees: Vec<&str> = illisibles.iter().take(5).map(String::as_str).collect();
    let reste = if illisibles.len() > 5 { format!(" et {} autre(s)", illisibles.len() - 5) } else { String::new() };
    format!(" Valeur actuelle illisible, stratégie de deR4Tizer gardée et rien de modifié pour : {}{reste}.", citees.join(", "))
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
            // Journal déjà au moins aussi grand que la cible, sans stratégie : conforme, rien à poser (S218-02). Une
            // stratégie présente mais plus petite n'est jamais masquée par la taille effective (audit de #219, S219-01)
            if let (Some(canal), Dword(ko)) = (canal_taille(cle, nom), valeur) {
                if actuel.is_none() {
                    let t = lire_taille_journal(canal);
                    if conforme_par_taille_effective(actuel.as_deref(), t, *ko) {
                        return (Some(true), format!("taille effective {} octets", t.unwrap_or(0)), attendu);
                    }
                }
            }
            (Some(valeur_satisfaite(nom, valeur, actuel.as_deref())), actuel.unwrap_or_else(|| "absent".into()), attendu)
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

/// Gestion du poste lue : jamais « non géré » par défaut (relecture de la baseline du 2026-11-20, B2)
#[derive(Debug, Clone, PartialEq)]
pub enum Gestion {
    NonGere,
    /// Message pour l'utilisateur : par qui le poste est géré
    Gere(String),
    /// Lancement de PowerShell en échec, sortie vide ou mal formée
    Illisible,
}

/// Analyse de la sortie « PartOfDomain|nombre d'inscriptions MDM ». Seule une réponse complète et bien formée
/// vaut « non géré » ; tout le reste est illisible (échec fermé : la baseline reste en lecture seule)
pub fn analyser_gestion(sortie: Option<&str>) -> Gestion {
    let Some(s) = sortie else { return Gestion::Illisible };
    let Some((d, m)) = s.trim().split_once('|') else { return Gestion::Illisible };
    let domaine = match d.trim().to_ascii_lowercase().as_str() {
        "true" => true,
        "false" => false,
        _ => return Gestion::Illisible,
    };
    let Ok(mdm) = m.trim().parse::<u32>() else { return Gestion::Illisible };
    let mut l = Vec::new();
    if domaine {
        l.push("domaine Active Directory");
    }
    if mdm > 0 {
        l.push("Intune (ou autre gestion MDM)");
    }
    if l.is_empty() {
        Gestion::NonGere
    } else {
        Gestion::Gere(format!("Poste géré par {} : la baseline est en lecture seule, pour ne pas entrer en conflit avec les stratégies de l'organisation.", l.join(" et ")))
    }
}

/// Message de lecture seule, ou None si la baseline peut être appliquée
pub fn message_gestion(g: &Gestion) -> Option<String> {
    match g {
        Gestion::NonGere => None,
        Gestion::Gere(m) => Some(m.clone()),
        Gestion::Illisible => Some("Gestion du poste illisible (domaine ou Intune non vérifiable) : la baseline est en lecture seule, par prudence.".into()),
    }
}

fn lire_gestion() -> Gestion {
    crate::mesure::powershell("baseline");
    let enfant = std::process::Command::new(crate::natif::powershell_exe())
        .args(["-NoProfile", "-NonInteractive", "-Command",
            "$d = (Get-CimInstance Win32_ComputerSystem).PartOfDomain; \
             $m = @(Get-ChildItem HKLM:\\SOFTWARE\\Microsoft\\Enrollments -ErrorAction SilentlyContinue | \
               Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProviderID -eq 'MS DM Server' }).Count; \
             \"$d|$m\""])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn();
    let Ok(mut enfant) = enfant else { return analyser_gestion(None) };
    // Attente bornée (audit de #215, S215-04) : un WMI bloqué ne fige ni le fil « contrôles » ni une application
    let debut = std::time::Instant::now();
    loop {
        match enfant.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if debut.elapsed() < std::time::Duration::from_secs(60) => std::thread::sleep(std::time::Duration::from_millis(200)),
            _ => {
                let _ = enfant.kill();
                let _ = enfant.wait();
                commun::journal("baseline : gestion du poste sans réponse en 60 s, tenue pour illisible");
                return analyser_gestion(None);
            }
        }
    }
    match enfant.wait_with_output() {
        Ok(o) if o.status.success() => analyser_gestion(Some(&String::from_utf8_lossy(&o.stdout))),
        _ => analyser_gestion(None),
    }
}

static GESTION: std::sync::Mutex<Option<(std::time::Instant, Option<String>)>> = std::sync::Mutex::new(None);

/// Gestion existante du poste : la GPO de domaine ou Intune écraserait la GPO locale, ou entrerait en conflit
/// avec elle ; dans ce cas la baseline est seulement évaluée (lecture seule). Pour l'évaluation périodique :
/// gardée 10 minutes, puis relue (un poste joint à un domaine après le démarrage est vu sans redémarrage)
pub fn gestion() -> Option<String> {
    if let Ok(g) = GESTION.lock() {
        if let Some((t, m)) = g.as_ref() {
            if t.elapsed() < std::time::Duration::from_secs(600) {
                return m.clone();
            }
        }
    }
    gestion_fraiche()
}

/// Relue à l'instant : avant toute application
pub fn gestion_fraiche() -> Option<String> {
    let m = message_gestion(&lire_gestion());
    if let Ok(mut g) = GESTION.lock() {
        *g = Some((std::time::Instant::now(), m.clone()));
    }
    m
}

pub fn evaluer() -> EtatBaseline {
    let sauvegarde: Sauvegarde = commun::lire("baseline-sauvegarde.json").unwrap_or_default();
    let mut regles = Vec::new();
    let mut totaux: HashMap<&str, (u32, u32)> = HashMap::new();
    // État effectif de Defender, lu une fois par évaluation (B4), avec une échéance (audit de #217, S217-02)
    let (mode, prefs) = defender_borne();
    let lsa_ok = lsa_applicable(build_windows());
    for r in REGLES {
        let verifs: Vec<_> = r.mecanismes.iter().map(verifier_mecanisme).collect();
        let etat_registre = if verifs.iter().any(|v| v.0 == Some(false)) {
            "non conforme"
        } else if verifs.iter().all(|v| v.0 == Some(true)) {
            "conforme"
        } else {
            "inconnu"
        };
        // Une règle posée dans le registre n'est conforme que si Defender l'applique vraiment (B4)
        let effets: Vec<Effet> = r.mecanismes.iter().map(|m| effet_defender(m, prefs.as_ref(), &mode)).collect();
        let (etat, mut note) = etat_regle(etat_registre, &effets);
        let t = totaux.entry(r.profil).or_default();
        // Règle LSA impossible à appliquer sur ce Windows : dite, et hors du score (prérelecture de #218, D1)
        if r.id == "systeme.lsa" && etat != "conforme" && !lsa_ok {
            note.push_str(" (non applicable avant Windows 11 22H2 : hors du score)");
        } else {
            t.1 += 1;
        }
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
            actuel: verifs.iter().map(|v| v.1.clone()).collect::<Vec<_>>().join(" / ") + &note,
            attendu: verifs.iter().map(|v| v.2.clone()).collect::<Vec<_>>().join(" / "),
            appliquee: sauvegarde.regles.contains_key(r.id),
            etat_registre: etat_registre.into(),
        });
    }
    let scores = totaux.into_iter().map(|(p, (ok, n))| (p.to_string(), if n == 0 { 0 } else { ok * 100 / n })).collect();
    EtatBaseline { mis_a_jour: commun::maintenant(), regles, scores, message: gestion().unwrap_or_default() }
}

/// Lecture WMI d'un Defender bloqué : jamais plus de 30 s pendant que le drapeau de la baseline est tenu ; une
/// lecture encore bloquée n'en relance pas une autre. Dépassement : mode vide et préférences absentes, donc
/// « inconnu » pour les règles Defender (audit de #217, S217-02)
fn defender_borne() -> (String, Option<crate::defender::PrefsDefender>) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static EN_COURS: AtomicBool = AtomicBool::new(false);
    if EN_COURS.swap(true, Ordering::AcqRel) {
        return (String::new(), None);
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let lu = (crate::defender::etat().mode, crate::defender::preferences());
        EN_COURS.store(false, Ordering::Release);
        let _ = tx.send(lu);
    });
    rx.recv_timeout(std::time::Duration::from_secs(30)).unwrap_or_default()
}

/// Décision pure : état d'une règle à partir de l'état lu dans le registre et de l'effet réel de ses mécanismes
/// Defender. Trois états jamais confondus pour une règle posée : « conforme » (effectif), « sans effet » (avec la
/// raison), « inconnu » (état de Defender illisible). Seul « conforme » compte dans le score
pub fn etat_regle(etat_registre: &'static str, effets: &[Effet]) -> (&'static str, String) {
    if etat_registre != "conforme" {
        return (etat_registre, String::new());
    }
    if let Some(Effet::SansEffet(raison)) = effets.iter().find(|e| matches!(e, Effet::SansEffet(_))) {
        return ("sans effet", format!(" (posé, sans effet : {raison})"));
    }
    if effets.iter().any(|e| *e == Effet::Illisible) {
        return ("inconnu", " (état effectif de Microsoft Defender illisible)".into());
    }
    ("conforme", String::new())
}

// ------------------------------------------------------------ application et retour en arrière

/// Une étape d'application ou d'annulation : nom lisible et action
pub type Etape<'a> = (&'a str, Box<dyn FnMut() -> Result<(), String> + 'a>);

/// Enchaîne les étapes dans l'ordre et s'arrête à la première en échec. Le message dit ce qui est fait et ce
/// qui ne l'est pas ; si la première étape échoue (sauvegarde du retour arrière), rien n'a été modifié
/// (relecture de la baseline du 2026-11-20, B1)
pub fn executer_etapes(etapes: &mut [Etape]) -> Result<(), String> {
    let mut faites: Vec<&str> = Vec::new();
    for i in 0..etapes.len() {
        let nom = etapes[i].0;
        if let Err(e) = (etapes[i].1)() {
            let non_faites: Vec<&str> = etapes[i..].iter().map(|x| x.0).collect();
            return Err(if faites.is_empty() {
                format!("{nom} impossible ({e}) : rien n'a été modifié.")
            } else {
                format!("{nom} impossible ({e}). Fait : {}. Non fait : {}.", faites.join(", "), non_faites.join(", "))
            });
        }
        faites.push(nom);
    }
    Ok(())
}

/// Sauvegarde du retour arrière telle qu'elle est sur disque : absente, elle est vide ; présente mais illisible
/// (droits du dossier non vérifiés, propriétaire non admis, contenu abîmé), l'opération est refusée avant toute
/// écriture, pour ne jamais l'écraser par une sauvegarde vide (audit de #215, S215-01)
fn lire_sauvegarde() -> Result<Sauvegarde, String> {
    // Protection du dossier de données en échec : la sauvegarde n'est pas fiable, ni lisible ni relisible
    // (prérelecture de #215, D1)
    if commun::echec_protection().is_some() {
        return Err("protection du dossier de données en échec : la baseline n'est ni appliquée ni annulée, la sauvegarde du retour arrière n'étant pas fiable.".into());
    }
    // Toute erreur autre que « introuvable » vaut « présente » (audit de #215, S215-07)
    let existe = match std::fs::symlink_metadata(commun::dossier().join("baseline-sauvegarde.json")) {
        Ok(_) => true,
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    };
    decider_sauvegarde(existe, commun::lire("baseline-sauvegarde.json"))
}

/// Décision pure de lire_sauvegarde
pub fn decider_sauvegarde<T: Default>(existe: bool, lue: Option<T>) -> Result<T, String> {
    match (existe, lue) {
        (_, Some(s)) => Ok(s),
        (false, None) => Ok(T::default()),
        (true, None) => Err("sauvegarde du retour arrière présente mais illisible (droits ou contenu) : rien n'a été modifié, pour ne pas la perdre.".into()),
    }
}

/// Écrit la sauvegarde du retour arrière puis la relit : une sauvegarde qu'on ne peut pas relire à l'identique
/// ne protège rien
fn ecrire_sauvegarde(sauvegarde: &Sauvegarde) -> Result<(), String> {
    commun::ecrire("baseline-sauvegarde.json", sauvegarde)?;
    match commun::lire::<Sauvegarde>("baseline-sauvegarde.json") {
        Some(relue) if relue.regles == sauvegarde.regles => Ok(()),
        Some(_) => Err("relue différente de celle écrite".into()),
        None => Err("illisible après écriture".into()),
    }
}

/// Lecture vérifiée des fichiers de la GPO locale avant toute écriture (audit du 2026-11-23, A-2-2) : Registry.pol,
/// gpt.ini (version comprise) et audit.csv ; rend la stratégie d'audit. Un fichier présent mais illisible ou non
/// compris arrête l'opération, et le message le dit
fn lire_gpo_avant_ecriture() -> Result<gpo::AuditCsv, String> {
    gpo::lire_pol()
        .and_then(|_| gpo::lire_gpt())
        .and_then(|g| gpo::maj_gpt(&g, false))
        .and_then(|_| gpo::lire_audit())
        .map_err(|e| format!("GPO locale : {e} : rien n'a été modifié."))
}

/// Décision de l'annulation pour une valeur de registre
#[derive(Debug, PartialEq)]
pub enum Decision {
    /// Remettre la valeur d'origine
    RemettreOrigine,
    /// Valeur absente à l'origine : la supprimer
    Supprimer,
    /// Valeur changée depuis par un tiers (ni celle posée, ni celle d'origine) : laissée telle quelle
    Laisser,
}

/// Décision pure (audit du 2026-11-23, A-2-3) : l'annulation ne remet l'origine (ou ne supprime la valeur absente à
/// l'origine) que si la valeur actuelle est celle posée par deR4Tizer ou déjà celle d'origine ; un durcissement posé
/// depuis par un tiers (règle ASR passée en blocage, RunAsPPL…) est laissé en place
pub fn a_remettre(posee: &str, origine: Option<&str>, actuelle: Option<&str>) -> Decision {
    let egal = |a: Option<&str>, b: Option<&str>| match (a, b) {
        (Some(a), Some(b)) => a.trim() == b.trim(),
        (None, None) => true,
        _ => false,
    };
    if egal(actuelle, Some(posee)) || egal(actuelle, origine) {
        if origine.is_some() { Decision::RemettreOrigine } else { Decision::Supprimer }
    } else {
        Decision::Laisser
    }
}

/// Valeurs posées par deR4Tizer sur une clé : celle de la règle annulée, puis celles des règles appliquées avant
/// l'annulation (une règle plus stricte encore appliquée, ou annulée en même temps, n'est pas « un tiers »)
fn valeurs_posees(appliquees: &[String], catalogue: &Valeur, cle: &str, nom: &str) -> Vec<String> {
    let mut v = vec![decrire(catalogue)];
    for r in REGLES.iter().filter(|r| appliquees.iter().any(|a| a == r.id)) {
        if let Some(x) = mecanisme_de(r, cle, nom) {
            v.push(decrire(x));
        }
    }
    v
}

/// Décision pure de l'annulation sur toutes les valeurs posées par deR4Tizer pour cette clé : la valeur actuelle
/// n'est laissée que si elle n'est aucune d'elles, ni l'origine (A-2-3)
pub fn decision_annulation(posees: &[String], origine: Option<&str>, actuelle: Option<&str>) -> Decision {
    posees.iter().map(|p| a_remettre(p, origine, actuelle)).find(|d| *d != Decision::Laisser).unwrap_or(Decision::Laisser)
}

fn entree(cle: &str, nom: &str, v: &Valeur) -> EntreePol {
    match v {
        Dword(n) => EntreePol::dword(cle, nom, *n),
        Texte(t) => EntreePol::texte(cle, nom, t),
    }
}

/// Fichiers de la GPO locale copiés dans la sauvegarde d'origine : chemin sous la racine de la GPO, nom de la copie
pub const FICHIERS_GPO: [(&str, &str); 3] =
    [(r"gpt.ini", "gpt.ini"), (r"Machine\Registry.pol", "Registry.pol"), (r"Machine\Microsoft\Windows NT\Audit\audit.csv", "audit.csv")];

fn sauvegarder_fichiers_gpo() -> Result<String, String> {
    sauvegarder_fichiers_gpo_dans(&gpo::racine(), &commun::dossier().join(r"sauvegardes\gpo-origine"))
}

/// Copie unique des fichiers d'origine de la GPO locale, avant toute première modification (audit du 2026-11-23,
/// A-2-2) : chaque copie est relue et comparée à l'original ; un original illisible (autre qu'introuvable) ou une
/// copie différente arrête l'application avant toute écriture, et la copie incomplète est retirée pour être reprise
/// la fois suivante. Le dossier déjà présent n'est jamais refait (l'original a pu être modifié depuis) : un fichier
/// qui y manque alors que l'original existe est dit dans la note rendue
pub fn sauvegarder_fichiers_gpo_dans(racine: &std::path::Path, dossier: &std::path::Path) -> Result<String, String> {
    match std::fs::symlink_metadata(dossier) {
        Ok(m) if m.file_type().is_dir() => {
            let mut manquants = Vec::new();
            for (src, dst) in FICHIERS_GPO {
                let original = gpo::lire_ou_absent(&racine.join(src)).map(|o| o.is_some()).unwrap_or(true);
                let copie = !matches!(std::fs::symlink_metadata(dossier.join(dst)), Err(e) if e.kind() == std::io::ErrorKind::NotFound);
                if original && !copie {
                    manquants.push(dst);
                }
            }
            return Ok(if manquants.is_empty() {
                String::new()
            } else {
                format!(" Sauvegarde d'origine de la GPO locale incomplète : {} absent(s) de la copie alors que l'original existe (copie non refaite : l'original a pu être modifié depuis la première application).", manquants.join(", "))
            });
        }
        Ok(_) => return Err("le chemin de la sauvegarde d'origine de la GPO locale n'est pas un dossier".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("sauvegarde d'origine de la GPO locale illisible ({e})")),
    }
    std::fs::create_dir_all(dossier).map_err(|e| format!("dossier de la sauvegarde d'origine non créé ({e})"))?;
    let copier = || -> Result<(), String> {
        for (src, dst) in FICHIERS_GPO {
            let Some(o) = gpo::lire_ou_absent(&racine.join(src))? else { continue };
            std::fs::write(dossier.join(dst), &o).map_err(|e| format!("copie de {dst} impossible ({e})"))?;
            match std::fs::read(dossier.join(dst)) {
                Ok(relue) if relue == o => {}
                Ok(_) => return Err(format!("copie de {dst} différente de l'original")),
                Err(e) => return Err(format!("copie de {dst} illisible ({e})")),
            }
        }
        Ok(())
    };
    copier().map_err(|e| {
        // Copie incomplète retirée : la suivante reprendra une vraie origine, rien de la GPO n'ayant été modifié
        let _ = std::fs::remove_dir_all(dossier);
        format!("sauvegarde d'origine de la GPO locale impossible ({e})")
    })?;
    Ok(String::new())
}

/// Règles d'un profil (ou liste d'identifiants séparés par des virgules)
pub fn selection(cible: &str) -> Vec<&'static Regle> {
    let ids: Vec<&str> = cible.split(',').map(str::trim).collect();
    REGLES.iter().filter(|r| ids.contains(&r.profil) || ids.contains(&r.id) || (ids.contains(&"recommandé+") && r.profil != "renforcé")).collect()
}

/// Décision pure (prérelecture de #218, D1) : avant Windows 11 22H2 (ou build illisible), la règle LSA est écartée
/// d'une application de plusieurs règles, qui se fait sans elle ; demandée seule, elle est refusée
pub fn retirer_lsa(nb_regles: usize, applicable: bool) -> Result<bool, String> {
    if applicable {
        Ok(false)
    } else if nb_regles > 1 {
        Ok(true)
    } else {
        Err("Protection LSA non appliquée : elle demande Windows 11 22H2 ou plus récent (sinon elle ne serait pas annulable) ; rien n'a été modifié.".into())
    }
}

/// Décision pure (relecture de la baseline du 2026-11-20, U1) : la règle qui coupe le Bureau à distance est
/// laissée de côté quand elle est appliquée avec d'autres (profil entier) et que le Bureau à distance est activé, ou
/// que son état est illisible ; appliquée seule, elle est un choix explicite
pub fn retirer_bureau_distance(nb_regles: usize, rdp_actif: Option<bool>) -> bool {
    nb_regles > 1 && rdp_actif != Some(false)
}

/// Bureau à distance activé sur ce poste (fDenyTSConnections = 0) ; None si illisible
/// La stratégie (Terminal Services) prime sur la clé système : un Bureau à distance ouvert par stratégie est vu (audit
/// de #219, S219-03)
fn bureau_distance_actif() -> Option<bool> {
    let lire = |cle: &str| lire_registre(cle, "fDenyTSConnections");
    let v = lire(r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services").or_else(|| lire(r"SYSTEM\CurrentControlSet\Control\Terminal Server"))?;
    v.trim().parse::<u32>().ok().map(|v| v == 0)
}

pub fn appliquer(regles_demandees: &[&Regle]) -> Result<String, String> {
    if let Some(g) = gestion_fraiche() {
        return Err(g);
    }
    let mut sauvegarde = lire_sauvegarde()?;
    // Protection LSA sans verrou UEFI : seulement à partir de Windows 11 22H2, avant toute écriture (B5)
    let mut note = String::new();
    let mut regles: Vec<&Regle> = regles_demandees.to_vec();
    // Les deux écartements comptent les règles demandées, pas la liste déjà réduite (prérelecture de #219, D2)
    let demandees = regles_demandees.len();
    if regles.iter().any(|r| r.id == "systeme.lsa") && retirer_lsa(demandees, lsa_applicable(build_windows()))? {
        regles.retain(|r| r.id != "systeme.lsa");
        note = " « Protection LSA » non appliquée : elle demande Windows 11 22H2 ou plus récent.".into();
    }
    if regles.iter().any(|r| r.id == "reseau.bureau-distance") && retirer_bureau_distance(demandees, bureau_distance_actif()) {
        regles.retain(|r| r.id != "reseau.bureau-distance");
        note.push_str(" « Bureau à distance désactivé » non appliquée : le Bureau à distance est activé sur ce poste (l'appliquer seule pour le couper).");
    }
    // Tout écarté : ni sauvegarde ni gpupdate pour rien (prérelecture de #219, D2)
    if regles.is_empty() {
        return Ok(format!("Aucune règle appliquée.{note}"));
    }
    let regles: &[&Regle] = &regles;
    // GPO locale lue en échec fermé avant toute écriture : un fichier présent mais illisible ou non compris arrête
    // tout, au lieu d'être lu vide puis réécrit sans les stratégies d'autres outils (audit du 2026-11-23, A-2-2)
    let mut audit = lire_gpo_avant_ecriture()?;
    note.push_str(&sauvegarder_fichiers_gpo().map_err(|e| format!("{e} : rien n'a été modifié."))?);
    let mut ajouts = Vec::new();
    let mut audit_modifie = false;
    let mut journaux: Vec<&str> = Vec::new();
    // Valeurs plus strictes qui retiennent une écriture (B3) : celles posées dans le même appel, et celles des règles
    // déjà appliquées seulement si elles sont vraiment en place (audit de #216, S216-01 : jamais sur le seul marquage)
    let autres: Vec<(&str, &str, &Valeur)> = REGLES.iter()
        .flat_map(|r| r.mecanismes.iter().filter_map(move |m| if let Registre { cle, nom, valeur } = m { Some((r, *cle, *nom, valeur)) } else { None }))
        .filter(|(r, cle, nom, valeur)| regles.iter().any(|x| x.id == r.id)
            || (sauvegarde.regles.contains_key(r.id) && valeur_satisfaite(nom, valeur, lire_registre(cle, nom).as_deref())))
        .map(|(_, cle, nom, valeur)| (cle, nom, valeur))
        .collect();
    // Origine déjà relevée par une règle appliquée sur la même clé : c'est elle qui fait foi, pas la valeur posée
    // depuis par deR4Tizer (audit de #216, S216-02)
    let origines_connues: HashMap<String, Option<String>> = sauvegarde.regles.values()
        .flat_map(|l| l.iter().filter(|(m, _)| m.starts_with("reg|")).map(|(m, v)| (m.to_ascii_lowercase(), v.clone())))
        .collect();
    // Journaux déjà au moins aussi grands que la cible : ni stratégie ni wevtutil (S218-02)
    let mut deja_assez_grands: Vec<&str> = Vec::new();
    // Relevé des valeurs d'origine, sans rien modifier
    for r in regles {
        let mut origine = Vec::new();
        for m in r.mecanismes {
            match m {
                Registre { cle, nom, valeur } => {
                    let cle_origine = format!(r"reg|{cle}|{nom}");
                    let o = origines_connues.get(&cle_origine.to_ascii_lowercase()).cloned().unwrap_or_else(|| lire_registre(cle, nom));
                    origine.push((cle_origine, o));
                    // Taille de journal : la taille effective d'origine est relevée, pour la remettre à l'annulation
                    // (B5 : retirer la stratégie ne la remet pas, essai en VM du 2026-11-20)
                    let mut a_poser = true;
                    if let Some(canal) = canal_taille(cle, nom) {
                        let taille = lire_taille_journal(canal).ok_or_else(|| format!("taille du journal « {canal} » illisible : rien n'a été modifié."))?;
                        origine.push((format!("taille|{canal}"), Some(taille.to_string())));
                        if let Dword(ko) = valeur {
                            // wevtutil seulement si le journal est plus petit que la cible : jamais de réduction (S218-02)
                            if !taille_a_poser(taille, *ko) {
                                deja_assez_grands.push(canal);
                            }
                            // Stratégie écrite si le journal est trop petit, ou si une stratégie présente ne satisfait
                            // pas la règle (abaissée par un tiers) : jamais laissée en place (audit de #219, S219-01)
                            a_poser = strategie_taille_a_ecrire(taille, *ko, lire_registre(cle, nom).as_deref());
                        }
                    }
                    if a_poser && ecriture_retenue(cle, nom, valeur, &autres) && !deja_plus_stricte(nom, valeur, lire_registre(cle, nom).as_deref()) {
                        ajouts.push(entree(cle, nom, valeur));
                    }
                }
                Audit { guid, nom, reglage } => {
                    // Valeur d'origine illisible : refus, jamais « désactivé » par défaut (audit de #215, S215-03)
                    let actuel = gpo::audit_effectif(guid).ok_or_else(|| format!("audit « {nom} » illisible : rien n'a été modifié."))?;
                    origine.push((format!("audit|{guid}|{nom}"), Some(actuel.to_string())));
                    let guid_maj = guid.to_uppercase();
                    match audit.lignes.iter_mut().find(|l| l.0 == guid_maj) {
                        Some(l) => l.2 |= reglage,
                        None => audit.lignes.push((guid_maj, nom.to_string(), *reglage | actuel)),
                    }
                    audit_modifie = true;
                }
                Journal { canal } => {
                    let actif = evenements::journal_actif(canal).ok_or_else(|| format!("journal « {canal} » illisible : rien n'a été modifié."))?;
                    origine.push((format!("journal|{canal}"), Some(actif.to_string())));
                    journaux.push(canal);
                }
            }
        }
        // On ne garde que la toute première valeur d'origine d'une règle
        sauvegarde.regles.entry(r.id.to_string()).or_insert(origine);
    }
    // La sauvegarde du retour arrière d'abord : si elle ne peut pas être écrite et relue, rien n'est modifié
    let mut etapes: Vec<Etape> = vec![("sauvegarde du retour arrière", Box::new(|| ecrire_sauvegarde(&sauvegarde)))];
    etapes.push(("Registry.pol", Box::new(|| gpo::modifier_pol(&ajouts, &[]).map(|_| ()))));
    if audit_modifie {
        etapes.push(("audit.csv", Box::new(|| gpo::ecrire_audit(&audit))));
    }
    etapes.push(("gpt.ini", Box::new(|| gpo::marquer_gpt(audit_modifie))));
    if !journaux.is_empty() {
        etapes.push(("journaux d'événements", Box::new(|| {
            let echecs: Vec<&str> = journaux.iter().copied().filter(|c| !evenements::activer_journal(c, true)).collect();
            if echecs.is_empty() { Ok(()) } else { Err(format!("non activé(s) : {}", echecs.join(", "))) }
        })));
    }
    etapes.push(("mise à jour des stratégies (gpupdate)", Box::new(gpo::gpupdate)));
    if let Err(e) = executer_etapes(&mut etapes) {
        commun::journal(&format!("baseline : application en échec : {e}"));
        return Err(e);
    }
    drop(etapes);
    // Le service Journal d'événements ne relit la taille maximale qu'à son redémarrage : appliquée aussi tout de suite
    for r in regles {
        for m in r.mecanismes {
            if let Registre { cle, nom: nom @ "MaxSize", valeur: Dword(ko) } = m {
                if let Some(canal) = canal_taille(cle, nom) {
                    if !deja_assez_grands.contains(&canal) {
                        let _ = std::process::Command::new(gpo::outil_systeme("wevtutil.exe")).args(["sl", canal, &format!("/ms:{}", *ko as u64 * 1024)]).output();
                    }
                }
            }
        }
    }
    Ok(format!("{} règle(s) appliquée(s) par la GPO locale.{note}", regles.len()))
}

/// Taille effective des journaux pour les règles appliquées : le service Journal d'événements ne relit la
/// stratégie qu'à son redémarrage (appelé au démarrage du service)
pub fn forcer_tailles() {
    let sauvegarde: Sauvegarde = commun::lire("baseline-sauvegarde.json").unwrap_or_default();
    for r in REGLES.iter().filter(|r| sauvegarde.regles.contains_key(r.id)) {
        for m in r.mecanismes {
            if let Registre { cle, nom: nom @ "MaxSize", valeur: Dword(ko) } = m {
                if let Some(canal) = canal_taille(cle, nom) {
                    // Jamais de réduction : seulement si la taille effective est plus petite que la cible (S218-02)
                    if lire_taille_journal(canal).map(|t| taille_a_poser(t, *ko)).unwrap_or(false) {
                        let _ = std::process::Command::new(gpo::outil_systeme("wevtutil.exe")).args(["sl", canal, &format!("/ms:{}", *ko as u64 * 1024)]).output();
                    }
                }
            }
        }
    }
}

pub fn annuler(regles: &[&Regle]) -> Result<String, String> {
    let mut sauvegarde = lire_sauvegarde()?;
    if !regles.iter().any(|r| sauvegarde.regles.contains_key(r.id)) {
        return Ok("Aucune de ces règles n'a été appliquée par deR4Tizer : rien à annuler.".into());
    }
    let mut retraits = Vec::new();
    // Lue avant toute écriture, registre compris (A-2-2)
    let mut audit = lire_gpo_avant_ecriture()?;
    // Valeurs changées depuis par un tiers, laissées en place et citées dans le message (A-2-3)
    let mut laissees: Vec<String> = Vec::new();
    // Règles appliquées avant l'annulation : leurs valeurs sont celles posées par deR4Tizer, jamais « un tiers »
    let appliquees: Vec<String> = sauvegarde.regles.keys().cloned().collect();
    // Valeurs d'un tiers lues avant l'annulation (clé, nom, valeur ou absente, texte, règle) : rétablies après
    // gpupdate si l'entrée posée de Registry.pol a été retirée (prérelecture de #270, D1)
    let mut tiers: Vec<(String, String, Option<String>, bool, &str)> = Vec::new();
    // Valeurs actuelles illisibles : rien n'est touché, la règle reste dans la sauvegarde (S270-03)
    let mut illisibles: Vec<String> = Vec::new();
    let mut audit_modifie = false;
    let mut n = 0;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    // Règles dont une valeur d'origine n'a pas pu être remise : gardées dans la sauvegarde, et dites
    // (prérelecture de #215, D2)
    let mut non_remises: Vec<&str> = Vec::new();
    // Entrées de la sauvegarde étrangères à leur règle, citées dans le message (audit de #220, S220-03)
    let mut etrangeres: Vec<String> = Vec::new();
    // Valeurs d'origine présentes : remises encore une fois après la mise à jour des stratégies, qui retire la valeur
    // de Registry.pol en l'effaçant du registre (passage T3 en VM du 2026-11-20 : EnableLUA, ConsentPromptBehaviorAdmin
    // et PromptOnSecureDesktop effacés à l'annulation de systeme.uac ; limite S215-05)
    let mut valeurs_a_remettre: Vec<(String, String, String, bool, &str)> = Vec::new();
    // Origines des règles annulées, pour les remettre dans la sauvegarde si une remise échoue après gpupdate
    // (prérelecture de #220, D1)
    let mut annulees: HashMap<&str, Vec<(String, Option<String>)>> = HashMap::new();
    for r in regles {
        let Some(origine) = sauvegarde.regles.remove(r.id) else { continue };
        annulees.insert(r.id, origine.clone());
        n += 1;
        let mut remise = true;
        for (m, valeur) in origine.clone() {
            let parties: Vec<&str> = m.splitn(3, '|').collect();
            match parties.as_slice() {
                ["reg", cle, nom] => {
                    // Clé et nom recoupés avec un mécanisme de la règle : une entrée étrangère de la sauvegarde n'est
                    // jamais écrite ; la règle reste alors dans la sauvegarde et c'est dit (audit de #220, S220-01)
                    let Some(catalogue) = mecanisme_de(r, cle, nom) else {
                        remise = false;
                        // Bornée : au plus 5 entrées citées, chacune à 200 caractères (audit de #221, S221-02)
                        etrangeres.push(commun::borner_texte(&format!("{} : {cle}\\{nom}", r.id), 200));
                        continue;
                    };
                    // Type du catalogue : une valeur texte (règle ASR) est remise en texte (audit de #220, S220-02)
                    let texte = matches!(catalogue, Texte(_));
                    // Valeur changée depuis par un tiers (ni posée par deR4Tizer, ni d'origine) : jamais remplacée
                    // par l'origine (A-2-3). Son entrée de Registry.pol est retirée si elle vaut encore la valeur
                    // posée, sans quoi le gpupdate de l'annulation remettrait la valeur posée par-dessus celle du
                    // tiers ; la valeur du tiers lue ici est rétablie après gpupdate (prérelecture de #270, D1)
                    // Valeur actuelle illisible (clé illisible, lecture en échec, type non lu) : jamais prise pour
                    // « absente » ; l'entrée posée reste (ni retrait ni rétablissement), la règle reste dans la
                    // sauvegarde et c'est dit (réaudit de #270, S270-03)
                    let actuelle = match lire_registre_etat(cle, nom) {
                        LectureRegistre::Valeur(v) => Some(v),
                        LectureRegistre::Absente => None,
                        LectureRegistre::Illisible(e) => {
                            remise = false;
                            illisibles.push(commun::borner_texte(&format!("{} : {cle}\\{nom} ({e})", r.id), 200));
                            continue;
                        }
                    };
                    if decision_annulation(&valeurs_posees(&appliquees, catalogue, cle, nom), valeur.as_deref(), actuelle.as_deref()) == Decision::Laisser {
                        retraits.push(entree(cle, nom, catalogue));
                        tiers.push((cle.to_string(), nom.to_string(), actuelle, texte, r.id));
                        continue;
                    }
                    // Entrée de Registry.pol retirée seulement si elle vaut encore la valeur posée (A-2-3)
                    retraits.push(entree(cle, nom, catalogue));
                    if let Some(v) = &valeur {
                        valeurs_a_remettre.push((cle.to_string(), nom.to_string(), v.clone(), texte, r.id));
                    }
                    // La valeur posée reste dans le registre : on remet celle d'origine (ou on la supprime)
                    let ok = match hklm.create_subkey_with_flags(cle, KEY_ALL_ACCESS | KEY_WOW64_64KEY) {
                        Ok((k, _)) => match valeur.as_deref().map(|v| if texte { Err(()) } else { v.parse::<u32>().map_err(|_| ()) }) {
                            Some(Ok(d)) => k.set_value(nom, &d).is_ok(),
                            Some(Err(_)) => k.set_value(nom, &valeur.clone().unwrap_or_default()).is_ok(),
                            // Valeur absente à l'origine : supprimée ; déjà absente, c'est bon aussi
                            None => match k.delete_value(nom) {
                                Ok(()) => true,
                                Err(e) => e.kind() == std::io::ErrorKind::NotFound,
                            },
                        },
                        Err(_) => false,
                    };
                    remise &= ok;
                }
                ["audit", guid, _] => {
                    let avant: u32 = valeur.as_deref().and_then(|v| v.parse().ok()).unwrap_or(0);
                    if let Some(l) = audit.lignes.iter_mut().find(|l| l.0 == guid.to_uppercase()) {
                        l.2 = avant;
                    }
                    let ok = std::process::Command::new(gpo::outil_systeme("auditpol.exe"))
                        .args(["/set", &format!("/subcategory:{guid}"),
                            &format!("/success:{}", if avant & 1 != 0 { "enable" } else { "disable" }),
                            &format!("/failure:{}", if avant & 2 != 0 { "enable" } else { "disable" })])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false);
                    remise &= ok;
                    audit_modifie = true;
                }
                ["journal", canal] => {
                    if valeur.as_deref() == Some("false") {
                        remise &= evenements::activer_journal(canal, false);
                    }
                }
                ["taille", canal] => {
                    // Taille effective d'origine remise (B5), seulement pour un canal de la règle elle-même (S218-03)
                    let canal_de_la_regle = r.mecanismes.iter().any(|m| matches!(m, Registre { cle, nom, .. } if canal_taille(cle, nom).map(|c| c.eq_ignore_ascii_case(canal)).unwrap_or(false)));
                    let ok = match valeur.as_deref().and_then(|v| v.parse::<u64>().ok()).filter(|_| canal_de_la_regle) {
                        Some(t) => std::process::Command::new(gpo::outil_systeme("wevtutil.exe")).args(["sl", canal, &format!("/ms:{t}")]).output()
                            .map(|o| o.status.success()).unwrap_or(false),
                        None => false,
                    };
                    remise &= ok;
                }
                _ => {}
            }
        }
        if !remise {
            sauvegarde.regles.insert(r.id.to_string(), origine);
            non_remises.push(r.id);
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
    // Clé partagée encore utilisée par une règle appliquée : c'est sa valeur qui est posée
    tiers.retain(|(c, nm, _, _, _)| !ajouts.iter().any(|e: &EntreePol| e.cle.eq_ignore_ascii_case(c) && e.nom.eq_ignore_ascii_case(nm)));
    if audit_modifie {
        audit.lignes.retain(|l| l.2 != 0);
    }
    // Valeurs d'origine déjà remises dans le registre ci-dessus ; une étape en échec est dite, jamais masquée
    // (relecture de la baseline du 2026-11-20, B1) : si la sauvegarde ne peut pas être mise à jour, les règles
    // annulées restent marquées appliquées et le message le dit
    // Entrées de Registry.pol changées depuis par un tiers : gardées par modifier_pol, ni retirées ni remises (A-2-3)
    let gardees_pol: std::cell::RefCell<Vec<EntreePol>> = std::cell::RefCell::new(Vec::new());
    let mut etapes: Vec<Etape> = vec![("Registry.pol", Box::new(|| gpo::modifier_pol(&ajouts, &retraits).map(|g| *gardees_pol.borrow_mut() = g)))];
    if audit_modifie {
        etapes.push(("audit.csv", Box::new(|| gpo::ecrire_audit(&audit))));
    }
    etapes.push(("gpt.ini", Box::new(|| gpo::marquer_gpt(audit_modifie))));
    etapes.push(("mise à jour de la sauvegarde (sinon les règles annulées restent marquées appliquées)", Box::new(|| ecrire_sauvegarde(&sauvegarde))));
    etapes.push(("mise à jour des stratégies (gpupdate)", Box::new(gpo::gpupdate)));
    let non_remises_txt = format!("{}{}", message_non_remises(&non_remises, &etrangeres), message_illisibles(&illisibles));
    if let Err(e) = executer_etapes(&mut etapes) {
        let e = format!("annulation incomplète : {e}{non_remises_txt}");
        commun::journal(&format!("baseline : {e}"));
        return Err(e);
    }
    drop(etapes);
    // Après gpupdate : valeurs d'origine remises et relues, sauf celles d'un réglage partagé encore utilisé par une
    // règle appliquée (sa valeur reste posée)
    valeurs_a_remettre.retain(|(c, nm, _, _, _)| !ajouts.iter().any(|e: &EntreePol| e.cle.eq_ignore_ascii_case(c) && e.nom.eq_ignore_ascii_case(nm)));
    // Entrée de Registry.pol gardée (changée par un tiers) : sa valeur, appliquée par gpupdate, n'est pas écrasée
    for g in gardees_pol.borrow().iter() {
        laissees.push(commun::borner_texte(&format!("Registry.pol : {}\\{}", g.cle, g.nom), 200));
    }
    valeurs_a_remettre.retain(|(c, nm, _, _, _)| !gardees_pol.borrow().iter().any(|e| e.cle.eq_ignore_ascii_case(c) && e.nom.eq_ignore_ascii_case(nm)));
    // Valeurs d'un tiers : entrée de Registry.pol gardée (déjà citée) ou rétablie telle qu'elle était lue avant
    // l'annulation, puis relue ; en échec, la règle reste dans la sauvegarde (prérelecture de #270, D1)
    let mut tiers_echecs: Vec<(String, &str)> = Vec::new();
    for (c, nm, v, texte, id) in &tiers {
        if gardees_pol.borrow().iter().any(|e| e.cle.eq_ignore_ascii_case(c) && e.nom.eq_ignore_ascii_case(nm)) {
            continue;
        }
        let affiche = v.as_deref().map(commun::masquer_chemin).unwrap_or_else(|| "absente".into());
        if retablir_valeur(c, nm, v.as_deref(), *texte) {
            laissees.push(commun::borner_texte(&format!("{id} : {c}\\{nm} = {affiche}"), 200));
        } else {
            tiers_echecs.push((commun::borner_texte(&format!("{c}\\{nm} = {affiche}"), 200), *id));
        }
    }
    let laissees_txt = message_laissees(&laissees);
    let pas_remises = remettre_valeurs(&valeurs_a_remettre);
    if !pas_remises.is_empty() || !tiers_echecs.is_empty() {
        // Jamais perdue : la règle revient dans la sauvegarde (une nouvelle annulation la réessaie) et la valeur
        // d'origine est dite, pour une remise à la main au besoin (prérelecture de #220, D1)
        let mut ids: Vec<&str> = pas_remises.iter().map(|x| x.4).chain(tiers_echecs.iter().map(|x| x.1)).collect();
        ids.sort_unstable();
        ids.dedup();
        for id in &ids {
            if let Some(o) = annulees.get(id) {
                sauvegarde.regles.insert(id.to_string(), o.clone());
            }
        }
        let gardee = match ecrire_sauvegarde(&sauvegarde) {
            Ok(()) => format!("règle(s) {} gardée(s) dans la sauvegarde, marquée(s) appliquée(s) : à réessayer", ids.join(", ")),
            Err(e) => format!("sauvegarde non mise à jour ({e})"),
        };
        // Valeur d'origine dite pour une remise à la main, chemin de profil masqué (audit de #220, S220-04)
        let detail: Vec<String> = pas_remises.iter().map(|x| format!("{}\\{} = {}", x.0, x.1, commun::masquer_chemin(&x.2))).collect();
        let mut quoi = Vec::new();
        if !detail.is_empty() {
            quoi.push(format!("valeur d'origine non remise après la mise à jour des stratégies : {}", detail.join(", ")));
        }
        if !tiers_echecs.is_empty() {
            let d: Vec<&str> = tiers_echecs.iter().map(|x| x.0.as_str()).collect();
            quoi.push(format!("valeur posée hors de deR4Tizer non rétablie après la mise à jour des stratégies : {}", d.join(", ")));
        }
        let e = format!("annulation incomplète : {} ; {gardee}.{non_remises_txt}{laissees_txt}", quoi.join(" ; "));
        commun::journal(&format!("baseline : {e}"));
        return Err(e);
    }
    if !non_remises.is_empty() {
        let e = format!("{} règle(s) annulée(s) sur {n}.{non_remises_txt}{laissees_txt}", n - non_remises.len());
        commun::journal(&format!("baseline : annulation incomplète : {e}"));
        return Err(e);
    }
    Ok(format!("{n} règle(s) annulée(s) : valeurs d'origine restaurées.{laissees_txt}"))
}

/// Rétablit la valeur d'un tiers lue avant l'annulation (ou la laisse absente) et la relit (prérelecture de #270, D1)
fn retablir_valeur(cle: &str, nom: &str, v: Option<&str>, texte: bool) -> bool {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match v {
        Some(v) => {
            let ecrit = hklm.create_subkey_with_flags(cle, KEY_ALL_ACCESS | KEY_WOW64_64KEY).ok().map(|(k, _)| match (texte, v.parse::<u32>()) {
                (false, Ok(d)) => k.set_value(nom, &d).is_ok(),
                _ => k.set_value(nom, &v.to_string()).is_ok(),
            }).unwrap_or(false);
            remise_reussie(ecrit, v, lire_registre(cle, nom).as_deref())
        }
        None => {
            let efface = match hklm.open_subkey_with_flags(cle, KEY_ALL_ACCESS | KEY_WOW64_64KEY) {
                Ok(k) => match k.delete_value(nom) {
                    Ok(()) => true,
                    Err(e) => e.kind() == std::io::ErrorKind::NotFound,
                },
                Err(e) => e.kind() == std::io::ErrorKind::NotFound,
            };
            efface && lire_registre_etat(cle, nom) == LectureRegistre::Absente
        }
    }
}

/// Remet des valeurs d'origine dans le registre et les relit ; rend celles qui n'ont pas pu être remises
fn remettre_valeurs<'a, 'b>(valeurs: &'a [(String, String, String, bool, &'b str)]) -> Vec<&'a (String, String, String, bool, &'b str)> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    valeurs.iter().filter(|x| {
        let (cle, nom, v, texte, _) = x;
        let ecrit = hklm.create_subkey_with_flags(cle, KEY_ALL_ACCESS | KEY_WOW64_64KEY).ok().map(|(k, _)| match (texte, v.parse::<u32>()) {
            (false, Ok(d)) => k.set_value(nom, &d).is_ok(),
            _ => k.set_value(nom, v).is_ok(),
        }).unwrap_or(false);
        !remise_reussie(ecrit, v, lire_registre(cle, nom).as_deref())
    }).collect()
}

/// Décision pure : une remise n'est réussie que si l'écriture a réussi ET que la valeur relue est l'origine
/// (prérelecture de #220, D2)
pub fn remise_reussie(ecrit: bool, origine: &str, relue: Option<&str>) -> bool {
    ecrit && valeur_remise(origine, relue)
}

/// Décision pure : texte des règles non remises, avec les entrées étrangères à leur règle (audit de #220, S220-03)
pub fn message_non_remises(non_remises: &[&str], etrangeres: &[String]) -> String {
    let mut t = String::new();
    if !non_remises.is_empty() {
        t.push_str(&format!(" Valeur d'origine non remise pour : {} (gardées dans la sauvegarde, marquées appliquées : à réessayer).", non_remises.join(", ")));
    }
    if !etrangeres.is_empty() {
        let citees: Vec<&str> = etrangeres.iter().take(5).map(String::as_str).collect();
        let reste = if etrangeres.len() > 5 { format!(" et {} autre(s)", etrangeres.len() - 5) } else { String::new() };
        t.push_str(&format!(" Entrée(s) de la sauvegarde étrangère(s) à la règle, jamais écrite(s) (à retirer de baseline-sauvegarde.json par un administrateur) : {}{reste}.", citees.join(", ")));
    }
    t
}

/// Décision pure : texte des valeurs laissées en place parce qu'un tiers les a changées depuis l'application
/// (A-2-3) ; au plus 5 citées
pub fn message_laissees(laissees: &[String]) -> String {
    if laissees.is_empty() {
        return String::new();
    }
    let citees: Vec<&str> = laissees.iter().take(5).map(String::as_str).collect();
    let reste = if laissees.len() > 5 { format!(" et {} autre(s)", laissees.len() - 5) } else { String::new() };
    format!(" Valeur(s) changée(s) hors de deR4Tizer depuis l'application (ni posée(s) par deR4Tizer, ni d'origine), gardée(s) telle(s) quelle(s), stratégie de deR4Tizer retirée : {}{reste}.", citees.join(", "))
}

/// Mécanisme de registre de la règle pour une clé et un nom lus dans la sauvegarde ; None si étranger à la règle
pub fn mecanisme_de<'a>(r: &'a Regle, cle: &str, nom: &str) -> Option<&'a Valeur> {
    r.mecanismes.iter().find_map(|m| match m {
        Registre { cle: c, nom: n, valeur } if c.eq_ignore_ascii_case(cle) && n.eq_ignore_ascii_case(nom) => Some(valeur),
        _ => None,
    })
}

/// Décision pure : la valeur relue est bien la valeur d'origine
pub fn valeur_remise(origine: &str, relue: Option<&str>) -> bool {
    relue.map(|r| r.trim() == origine.trim()).unwrap_or(false)
}

/// État d'une règle dans le registre seul (celui de l'état publié pour un relevé qui ne le porte pas)
fn etat_lu_registre(r: &EtatRegle) -> &str {
    if r.etat_registre.is_empty() { &r.etat } else { &r.etat_registre }
}

/// Écarts sur des règles appliquées par deR4Tizer : quelqu'un a modifié un réglage de sécurité (registre), ou
/// Defender a cessé d'appliquer une règle conforme au relevé précédent. La modification se juge sur le registre
/// seul : un tour « inconnu » ou « sans effet » dû à Defender ne la masque pas (audit de #217, S217-01)
pub fn derives(avant: &EtatBaseline, apres: &EtatBaseline) -> Vec<Alerte> {
    let anciens: HashMap<&str, &EtatRegle> = avant.regles.iter().map(|r| (r.id.as_str(), r)).collect();
    let alerte = |r: &EtatRegle, raisons: String| Alerte {
        regle: crate::regles::BAS_001.into(),
        id: commun::nouvel_id(),
        heure: commun::maintenant(),
        niveau: "Alerte".into(),
        score: 5,
        processus: "?".into(),
        destination: format!("baseline : {}", r.titre),
        raisons,
        ..Default::default()
    };
    let mut alertes = Vec::new();
    let mut sans_effet: Vec<&EtatRegle> = Vec::new();
    for r in apres.regles.iter().filter(|r| r.appliquee) {
        let Some(a) = anciens.get(r.id.as_str()) else { continue };
        if etat_lu_registre(r) == "non conforme" && etat_lu_registre(a) == "conforme" {
            alertes.push(alerte(r, format!("réglage de sécurité MODIFIÉ hors de deR4Tizer (attendu : {}, actuel : {})", r.attendu, r.actuel)));
        } else if r.etat == "sans effet" && a.etat == "conforme" {
            sans_effet.push(r);
        }
    }
    // Defender qui cesse d'appliquer des règles (mode passif, redémarrage) : une seule alerte pour toutes, au lieu d'une
    // par règle (audit de #217, S217-04)
    match sans_effet.as_slice() {
        [] => {}
        [r] => alertes.push(alerte(r, format!("réglage de sécurité posé mais plus appliqué par Microsoft Defender (attendu : {}, actuel : {})", r.attendu, r.actuel))),
        [premiere, ..] => {
            let titres: Vec<&str> = sans_effet.iter().map(|r| r.titre.as_str()).collect();
            let mut a = alerte(premiere, format!("{} réglages de sécurité posés mais plus appliqués par Microsoft Defender : {} (état actuel de la première : {})", titres.len(), titres.join(", "), premiere.actuel));
            // Destination stable d'un regroupement à l'autre ; le nombre et les règles sont dans les raisons (S219-02)
            a.destination = "baseline : réglages Defender".into();
            alertes.push(a);
        }
    }
    alertes
}

/// Relevé gardé pour la comparaison suivante : une règle illisible à ce relevé (état effectif ou registre) garde son
/// dernier état connu, pour qu'un tour « inconnu » ne fasse pas manquer une alerte au tour suivant (audit de #217,
/// S217-05). Le relevé publié, lui, reste tel quel
pub fn retenir(avant: Option<&EtatBaseline>, b: &EtatBaseline) -> EtatBaseline {
    let mut r = b.clone();
    let Some(avant) = avant else { return r };
    let anciens: HashMap<&str, &EtatRegle> = avant.regles.iter().map(|x| (x.id.as_str(), x)).collect();
    for x in r.regles.iter_mut() {
        let Some(a) = anciens.get(x.id.as_str()) else { continue };
        if x.etat == "inconnu" {
            x.etat = a.etat.clone();
        }
        if x.etat_registre == "inconnu" {
            x.etat_registre = a.etat_registre.clone();
        }
    }
    r
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
