# Contrôles de l'installeur (U8a, dossier de conception U8), sans installation ni VM.
# Niveau 1, sources : la dernière page ne lance rien (ni case « Lancer », ni WixShellExec, ni action sur l'interface) ;
# quatre textes de dernière page (français, anglais ; lancement actif ou non), sans crochet ; condition de l'interface
# du MSI miroir de celle de la séquence d'exécution ; descriptions et licence sans promesse ; licence bilingue avec les
# faits attendus.
# Niveau 2, paquet construit (-Msi), lu par l'objet COM WindowsInstaller.Installer livré avec Windows : les textes sont
# des affectations de propriété (type 51) de la séquence de l'interface, aucun DoAction sur la dernière page, aucune
# action ne vise l'interface ; avec -Reference (MSI de main), tables d'exécution identiques.
# Usage (Windows PowerShell 5.1) : powershell -File tests\test-msi.ps1 [-Depot <racine>] [-Msi bin\deR4Tizer.msi [-Reference <MSI de main>]]
param([string]$Depot = (Split-Path $PSScriptRoot), [string]$Msi = '', [string]$Reference = '')
$ErrorActionPreference = 'Stop'
$ko = 0
function Cas([string]$Nom, [bool]$Ok, [string]$Detail = '') {
    if ($Ok) { "RÉUSSI  $Nom" } else { "ÉCHOUÉ  $Nom $Detail"; $script:ko++ }
}

# ---------------- niveau 1 : sources
$wxs = [IO.File]::ReadAllText((Join-Path $Depot 'installeur\deR4Tizer.wxs')) -replace "`r`n", "`n"
$sansCommentaires = [regex]::Replace($wxs, '<!--.*?-->', '', 'Singleline')
$interdits = @([regex]::Matches($sansCommentaires, 'WIXUI_EXITDIALOGOPTIONALCHECKBOX|WixShellExec|LaunchApplication|FileKey="InterfaceExe"|ExeCommand="[^"]*(?<!/IM )deR4Tizer\.exe(?!\.)') | ForEach-Object Value)
Cas 'Dernière page : aucune case « Lancer », aucun WixShellExec, aucune action qui lance l''interface (la fermer avant une mise à niveau, taskkill /IM, reste permis)' ($interdits.Count -eq 0) ($interdits -join ', ')

$textes = @([regex]::Matches($sansCommentaires, '<SetProperty Id="WIXUI_EXITDIALOGOPTIONALTEXT" Action="(\w+)"[^>]*Sequence="ui" Value="([^"]*)"><!\[CDATA\[(.*?)\]\]></SetProperty>') | ForEach-Object { [pscustomobject]@{ Action = $_.Groups[1].Value; Texte = $_.Groups[2].Value; Condition = $_.Groups[3].Value } })
Cas 'Dernière page : quatre textes (français et anglais, lancement actif ou non), posés dans la séquence de l''interface' ($textes.Count -eq 4 -and (($textes | ForEach-Object Action) -join '|') -eq 'TexteFinFrLance|TexteFinFrSans|TexteFinEnLance|TexteFinEnSans') "$($textes.Count)"
Cas 'Dernière page : textes sans crochet (texte formaté de Windows Installer), l''interface « ne la lance pas » dit dans les deux langues' ($textes.Count -eq 4 -and @($textes | Where-Object { $_.Texte -match '[\[\]]' }).Count -eq 0 -and $textes[0].Texte.Contains('Cette page ne la lance pas.') -and $textes[2].Texte.Contains('This page does not start it.') -and $textes[1].Texte.Contains('LANCEMENT_SESSION=0') -and $textes[3].Texte.Contains('LANCEMENT_SESSION=0'))

$execution = [regex]::Match($sansCommentaires, '<SetProperty Id="LANCEMENT_SESSION" Value="0" Before="CostInitialize" Sequence="execute"><!\[CDATA\[(.*?)\]\]></SetProperty>').Groups[1].Value
$miroir = 'LANCEMENT_SESSION="1" AND NOT (' + $execution + ')'
$fr = 'UserLanguageID=1036 OR UserLanguageID=2060 OR UserLanguageID=3084 OR UserLanguageID=4108 OR UserLanguageID=5132 OR UserLanguageID=6156'
$attendues = @("($fr) AND $miroir", "($fr) AND NOT ($miroir)", "NOT ($fr) AND $miroir", "NOT ($fr) AND NOT ($miroir)")
$ecarts = @(for ($k = 0; $k -lt [Math]::Min(4, $textes.Count); $k++) { if ($textes[$k].Condition -cne $attendues[$k]) { "$($textes[$k].Action) : $($textes[$k].Condition)" } })
Cas 'Dernière page : condition de lancement miroir exact de la séquence d''exécution, quatre cas disjoints' ($execution -ne '' -and $textes.Count -eq 4 -and $ecarts.Count -eq 0) ($ecarts -join ' ; ')

# Dossier de données point d'analyse (audit du 2026-11-23, C-1) : condition de lancement en échec fermé (seule la valeur
# « ok » passe, la désinstallation jamais bloquée), posée par une fonction JScript en lecture seule dans les deux séquences
# avant les conditions ; dossier de données permanent (la désinstallation le garde, vide et protégé : lot A, point 4)
$conditionLien = [regex]::Match($sansCommentaires, '<Condition Message="Le dossier de données \[CommonAppDataFolder\]deR4Tizer est un lien[^"]*">\s*<!\[CDATA\[(.*?)\]\]>\s*</Condition>').Groups[1].Value
$sequences = @([regex]::Matches($sansCommentaires, '<Custom Action="LireDossierDonnees" Before="LaunchConditions" />')).Count
Cas 'Dossier de données lien : condition de lancement en échec fermé (« ok » seulement), action de lecture avant les conditions dans les deux séquences' ($conditionLien -ceq 'REMOVE="ALL" OR DonneesEtat="ok"' -and $sequences -eq 2 -and $sansCommentaires.Contains('<CustomAction Id="LireDossierDonnees" BinaryKey="ScriptDossierDonnees" JScriptCall="LireDossierDonnees" Return="check" />')) "condition « $conditionLien », $sequences séquence(s)"
$js = [IO.File]::ReadAllText((Join-Path $Depot 'installeur\lire-dossier-donnees.js'))
$ecritures = @([regex]::Matches($js, '(?i)\.(Create\w*|Delete\w*|Move\w*|Copy\w*|Write\w*|OpenTextFile|Run|Exec)\s*\(|WScript\.Shell|Shell\.Application') | ForEach-Object Value)
Cas 'Dossier de données lien : script en lecture seule (aucune création, suppression, écriture ni lancement), en ASCII, « ok » posé seulement hors point d''analyse' ($ecritures.Count -eq 0 -and -not ($js -match '[^\x00-\x7F]') -and $js.Contains('(element.Attributes & 1024) !== 0 ? "lien" : "ok"') -and $js.Contains('Session.Property("DonneesEtat") = "inconnu";')) ($ecritures -join ', ')
Cas 'Dossier de données : composant permanent (racine gardée à la désinstallation)' ($sansCommentaires -match '<Component Id="Donnees" Guid="[^"]+" Win64="yes" Permanent="yes">')
# Audit du 2026-11-23, A-6-4 : l'audit de lecture posé dans les profils et les anciens comptes rendus de %SystemRoot%\Temp
# sont retirés par --nettoyer, lancé en SYSTEM après l'arrêt du service à toute désinstallation, quels que soient
# GARDER_DONNEES et GARDER_BASELINE (avec GARDER_BASELINE=1 l'audit « Système de fichiers » reste actif), jamais à une mise
# à niveau ; puis la suppression des données (A-4-3 : quarantaine non vide gardée) après la remise de la baseline
$nettoyer = '<Custom Action="Nettoyer" After="StopServices"><![CDATA[REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE]]></Custom>'
$supprimer = '<Custom Action="SupprimerDonnees" After="AnnulerBaseline"><![CDATA[REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE AND GARDER_DONNEES<>"1"]]></Custom>'
Cas 'Désinstallation : --nettoyer en SYSTEM après l''arrêt du service, sans condition GARDER_*, jamais à une mise à niveau ; suppression des données ensuite (A-6-4, A-4-3)' ($sansCommentaires.Contains($nettoyer) -and $sansCommentaires.Contains($supprimer) -and $sansCommentaires.Contains('<CustomAction Id="Nettoyer" FileKey="ServiceExe" ExeCommand="--nettoyer" Execute="deferred" Impersonate="no" Return="ignore" />'))

# Licence : RTF ANSI 1252 décodé
$rtf = [IO.File]::ReadAllText((Join-Path $Depot 'installeur\licence.rtf'))
$licence = [regex]::Replace($rtf, "\\'([0-9a-f]{2})", { param($m) [Text.Encoding]::GetEncoding(1252).GetString([byte[]]@([Convert]::ToByte($m.Groups[1].Value, 16))) })
$descriptions = (@([regex]::Matches($sansCommentaires, 'Description="([^"]*)"') | ForEach-Object { $_.Groups[1].Value }) -join ' | ')
$tout = $licence + ' ' + $descriptions + ' ' + (($textes | ForEach-Object Texte) -join ' ')
$promesses = @([regex]::Matches($tout, '(?i)prot[eé]g[eé]|protected|protection|en s[eé]curit[eé]|s[eé]curis[eé]|\bsafe\b|garantit|guarantees|bloque toutes|blocks all|remplace l.antivirus|replaces? (the |your )?antivirus|v[eé]rifi[eé] par Microsoft|verified by Microsoft') | ForEach-Object Value)
Cas 'Installeur : ni « protégé », ni « protection », ni promesse dans les descriptions, la licence et la dernière page' ($promesses.Count -eq 0) ($promesses -join ', ')
$faits = @('Aucune donnée du poste n''est envoyée à un tiers', 'No data from this computer is sent to a third party', 'Licence : EUPL-1.2', 'License: EUPL-1.2', 'sans garantie', 'without warranty', 'leurres', 'decoy files', 'LANCEMENT_SESSION=0', 'GARDER_DONNEES=1', 'GARDER_BASELINE=1', 'ne le désactive ni ne l''affaiblit', 'neither turns it off nor weakens it', 'L''installeur ne la lance pas.', 'The installer does not start it.', '7 jours', '7 days', 'jamais reprise automatiquement', 'never resumed automatically', 'Le paquet d''installation et les programmes publiés sont signés', 'The released installer and programs are signed', 'éditeur inconnu', 'unknown publisher')
$manquants = @($faits | Where-Object { -not $licence.Contains($_) })
# Vraies apostrophes françaises suivies de lettres hexadécimales, liste blanche explicite : d'administrateur, l'affaiblit
$casses = @([regex]::Matches($rtf, "(?<!\\)'[89a-f][0-9a-f](?!ministr|faibli)") | ForEach-Object { $rtf.Substring([Math]::Max(0, $_.Index - 12), 18) })
Cas 'Licence : aucun échappement RTF cassé (apostrophe suivie de deux chiffres hexadécimaux sans barre oblique inverse, audit de #155, S155-02)' ($casses.Count -eq 0) ($casses -join ' | ')
Cas 'Licence : français et anglais, avec les faits attendus (leurres, réponses automatiques et durées, lancement, options de désinstallation, Defender, paquet et programmes publiés signés, éditeur inconnu pour une compilation locale)' ($manquants.Count -eq 0 -and $rtf.StartsWith('{\rtf1\ansi\ansicpg1252') -and -not ($rtf -match '[^\x00-\x7F]')) ($manquants -join ' | ')

# Audit du 2026-11-23, A-4-1 : droits du dossier des programmes posés par le paquet, héritage coupé
$sddlProgrammes = 'O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'
$composantProgrammes = [regex]::Match($sansCommentaires, '<DirectoryRef Id="INSTALLFOLDER">.*?</DirectoryRef>', 'Singleline').Value
Cas 'Dossier des programmes (A-4-1) : PermissionEx protégé sur INSTALLFOLDER (SYSTEM et administrateurs contrôle total, Utilisateurs lecture et exécution, propriétaire Administrateurs), composant installé' ($composantProgrammes -match ('<Component Id="DossierProgrammes"[^>]*>\s*<CreateFolder>\s*<PermissionEx Sddl="' + [regex]::Escape($sddlProgrammes) + '" />\s*</CreateFolder>') -and $sansCommentaires.Contains('<ComponentRef Id="DossierProgrammes" />'))

# ---------------- niveau 2 : paquet construit
if ($Msi) {
    $wi = New-Object -ComObject WindowsInstaller.Installer
    $ouvrir = { param($p) $wi.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $wi, @($p, 0)) }
    $lignes = {
        param($db, [string]$requete, [int]$colonnes)
        $v = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @($requete))
        $v.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $v, $null) | Out-Null
        $res = New-Object Collections.Generic.List[string]
        while ($r = $v.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $v, $null)) {
            $res.Add((@(1..$colonnes | ForEach-Object { $r.GetType().InvokeMember('StringData', 'GetProperty', $null, $r, [object[]]@([int]$_)) }) -join "`t"))
        }
        $v.GetType().InvokeMember('Close', 'InvokeMethod', $null, $v, $null) | Out-Null
        $res.ToArray()
    }
    $tables = { param($db) @(& $lignes $db 'SELECT `Name` FROM `_Tables`' 1) }
    $db = & $ouvrir (Resolve-Path $Msi).Path
    $ca = @(& $lignes $db 'SELECT `Action`,`Type`,`Source`,`Target` FROM `CustomAction`' 4)
    $ui = @(& $lignes $db 'SELECT `Action`,`Condition`,`Sequence` FROM `InstallUISequence`' 3)
    $nouvelles = @('TexteFinFrLance', 'TexteFinFrSans', 'TexteFinEnLance', 'TexteFinEnSans')
    $type51 = @($ca | Where-Object { $nouvelles -contains $_.Split("`t")[0] } | Where-Object { $p = $_.Split("`t"); ([int]$p[1] -band 0x3F) -eq 51 -and $p[2] -eq 'WIXUI_EXITDIALOGOPTIONALTEXT' })
    $dansUi = @($ui | Where-Object { $nouvelles -contains $_.Split("`t")[0] })
    Cas 'Paquet : les quatre textes sont des affectations de propriété (type 51) de la séquence de l''interface, aucun code exécuté' ($type51.Count -eq 4 -and $dansUi.Count -eq 4) "$($type51.Count) / $($dansUi.Count)"
    $evenements = if ((& $tables $db) -contains 'ControlEvent') { & $lignes $db 'SELECT `Dialog_`,`Control_`,`Event`,`Argument` FROM `ControlEvent`' 4 } else { @() }
    $doAction = @($evenements | Where-Object { $p = $_.Split("`t"); $p[0] -eq 'ExitDialog' -and $p[2] -eq 'DoAction' })
    Cas 'Paquet : aucun DoAction sur la dernière page (ExitDialog)' ($doAction.Count -eq 0) ($doAction -join ' ; ')
    $vise = @($ca | Where-Object { $p = $_.Split("`t"); $p[2] -eq 'InterfaceExe' -or $p[3] -match '(?<!/IM )deR4Tizer\.exe(?!\.)' })
    Cas 'Paquet : aucune action personnalisée ne vise l''interface (deR4Tizer.exe)' ($vise.Count -eq 0) ($vise -join ' ; ')
    $verrous = @(& $lignes $db 'SELECT `LockObject`,`Table`,`SDDLText` FROM `MsiLockPermissionsEx`' 3)
    Cas 'Paquet (A-4-1) : MsiLockPermissionsEx porte les droits de INSTALLFOLDER' ($verrous -contains "INSTALLFOLDER`tCreateFolder`t$sddlProgrammes") ($verrous -join ' ; ')
    if ($Reference) {
        $ref = & $ouvrir (Resolve-Path $Reference).Path
        $ecartsTables = New-Object Collections.Generic.List[string]
        $requetes = [ordered]@{
            'InstallExecuteSequence' = @('SELECT `Action`,`Condition`,`Sequence` FROM `InstallExecuteSequence`', 3)
            'Component' = @('SELECT `Component`,`ComponentId`,`Directory_`,`Attributes`,`Condition`,`KeyPath` FROM `Component`', 6)
            'FeatureComponents' = @('SELECT `Feature_`,`Component_` FROM `FeatureComponents`', 2)
            'Registry' = @('SELECT `Registry`,`Root`,`Key`,`Name`,`Value`,`Component_` FROM `Registry`', 6)
            'ServiceInstall' = @('SELECT `ServiceInstall`,`Name`,`DisplayName`,`ServiceType`,`StartType`,`ErrorControl`,`Arguments`,`Component_`,`Description` FROM `ServiceInstall`', 9)
            'ServiceControl' = @('SELECT `ServiceControl`,`Name`,`Event`,`Arguments`,`Wait`,`Component_` FROM `ServiceControl`', 6)
            'CreateFolder' = @('SELECT `Directory_`,`Component_` FROM `CreateFolder`', 2)
            'MsiLockPermissionsEx' = @('SELECT `MsiLockPermissionsEx`,`LockObject`,`Table`,`SDDLText`,`Condition` FROM `MsiLockPermissionsEx`', 5)
            'CustomAction' = @('SELECT `Action`,`Type`,`Source`,`Target` FROM `CustomAction`', 4)
        }
        $tNouv = & $tables $db; $tRef = & $tables $ref
        foreach ($nom in $requetes.Keys) {
            if (($tNouv -contains $nom) -ne ($tRef -contains $nom)) { $ecartsTables.Add("$nom : présente d'un seul côté"); continue }
            if (-not ($tNouv -contains $nom)) { continue }
            $a = @(& $lignes $db $requetes[$nom][0] $requetes[$nom][1]); $b = @(& $lignes $ref $requetes[$nom][0] $requetes[$nom][1])
            if ($nom -eq 'CustomAction') { $a = @($a | Where-Object { $nouvelles -notcontains $_.Split("`t")[0] }) }
            $diff = @(Compare-Object ($a | Sort-Object) ($b | Sort-Object) -CaseSensitive)
            if ($diff.Count) { $ecartsTables.Add("$nom : $(($diff | Select-Object -First 3 | ForEach-Object { "$($_.SideIndicator) $($_.InputObject)" }) -join ' / ')") }
        }
        Cas 'Paquet : tables d''exécution identiques au MSI de main (séquence, actions hors textes, composants, registre, service, droits)' ($ecartsTables.Count -eq 0) ($ecartsTables -join ' ; ')
    }
}
if ($ko) { "$ko échec(s)"; exit 1 } else { 'Tous les cas réussis.' }
