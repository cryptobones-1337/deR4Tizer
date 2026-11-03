# Compile l'interface et vérifie la page « Réponses en cours » et le mode panique (PR 6.7b) : décisions pures (lignes,
# relance due, récupération par sorte, portée du mode panique, état effectif), lecture de reponses.json tel que le
# service l'écrit, neutralisation des textes, construction de la page ; puis contrôle du source de Gui.cs. La fenêtre
# n'est pas lancée.
# Usage (Windows PowerShell 5.1) : powershell -File tests\test-reponses-interface.ps1 [-Depot <racine du dépôt>]
param([string]$Depot = (Split-Path $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$src = Join-Path $Depot 'src'
$travail = Join-Path $env:TEMP ("d4t-reponses-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $travail | Out-Null
$ko = 0
function Cas([string]$Nom, [bool]$Ok, [string]$Detail = '') {
    if ($Ok) { "RÉUSSI  $Nom" } else { "ÉCHOUÉ  $Nom $Detail"; $script:ko++ }
}
try {
    $out = Join-Path $travail 'interface.exe'
    $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $csc /nologo /platform:anycpu /codepage:65001 /target:winexe /r:System.dll /r:System.Core.dll /r:System.Web.Extensions.dll /r:System.ServiceProcess.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll "/out:$out" "$src\Commun.cs" "$src\Langue.cs" "$src\Theme.cs" "$src\Gui.cs" "$src\Reglages.cs" "$src\Siem.cs" "$src\Incidents.cs" "$src\Reponses.cs" "$src\Trafic.cs" "$src\Reseau.cs" "/resource:$src\carte-pays.txt,carte-pays.txt"
    if ($LASTEXITCODE) { throw 'compilation' }
    Add-Type -AssemblyName System.Windows.Forms, System.Web.Extensions
    $asm = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($out))
    $t = { param($n) $asm.GetType("DeR4Tizer.$n") }
    $vr = & $t 'VueReponses'; $langue = & $t 'L'
    $appel = { param($type, $m, [object[]]$a) $type.GetMethod($m).Invoke($null, $a) }
    $json = New-Object Web.Script.Serialization.JavaScriptSerializer
    $lire = { param($nomType, $texte) $json.GetType().GetMethods() | Where-Object { $_.Name -eq 'Deserialize' -and $_.IsGenericMethod } | ForEach-Object { $_.MakeGenericMethod((& $t $nomType)).Invoke($json, @($texte)) } }
    $ok = $true; try { $langue.GetField('En').SetValue($null, $false) } catch { $ok = $false }
    Cas 'dictionnaire de langue : initialisé' $ok
    if (-not $ok) { throw 'dictionnaire de langue' }

    # reponses.json tel que politique.rs l'écrit (PascalCase), une action close, une cible piégée (inversion du sens)
    $texte = @'
{"Traces":[],"Actions":[
 {"Id":"a1","Sorte":"SuspensionAuto","Cible":"c:\\users\\a\\x\u202e.exe","Pid":4242,"Creation":133000000000000000,"Debut":1800000000,"Echeance":1800007200,"Relances":0,"DerniereRelance":0,"Etat":"Active","Declencheur":"automatique : leurre"},
 {"Id":"a2","Sorte":"Panique","Cible":"poste","Pid":null,"Creation":null,"Debut":1800000100,"Echeance":1800014500,"Relances":0,"DerniereRelance":0,"Etat":"Active","Declencheur":"administrateur"},
 {"Id":"a3","Sorte":"Isolation","Cible":"c:\\outils\\y.exe","Pid":null,"Creation":null,"Debut":1700000000,"Echeance":1900000000,"Relances":2,"DerniereRelance":1800000000,"Etat":"Active","Declencheur":"administrateur"},
 {"Id":"a4","Sorte":"Quarantaine","Cible":"c:\\users\\a\\z.bin","Pid":null,"Creation":null,"Debut":1800000000,"Echeance":1802592000,"Relances":0,"DerniereRelance":0,"Etat":"Levee","Declencheur":"administrateur"},
 {"Id":"a5","Sorte":"BlocageManuel","Cible":"203.0.113.9","Pid":null,"Creation":null,"Debut":1800000000,"Echeance":1807776000,"Relances":0,"DerniereRelance":0,"Etat":"Active"}
]}
'@
    $h = & $lire 'HistoriqueReponses' $texte
    Cas 'fichier du service lu : 5 actions, champs' ($h.Actions.Count -eq 5 -and $h.Actions[0].Pid -eq 4242 -and $h.Actions[1].Pid -eq $null -and $h.Actions[4].Declencheur -eq $null)
    $l = & $appel $vr 'Lignes' @($h, [long]1800010000)
    Cas 'seules les actions actives' ($l.Count -eq 4 -and -not ($l | Where-Object { $_.Action.Id -eq 'a4' }))
    Cas 'panique d''abord, en rouge' ($l[0].Action.Id -eq 'a2' -and $l[0].Gravite -eq 2)
    $a1 = $l | Where-Object { $_.Action.Id -eq 'a1' }
    Cas 'relance due : jaune, décision attendue, dite en texte' ($a1.Gravite -eq 1 -and $a1.Etat -match 'relance en attente')
    $a3 = $l | Where-Object { $_.Action.Id -eq 'a3' }
    Cas 'pas encore due : relances comptées' ($a3.Gravite -eq 0 -and $a3.Etat -eq 'en cours, relancé 2 fois')
    Cas 'cible neutralisée, PID montré' (-not $a1.Cible.Contains([string][char]0x202E) -and $a1.Cible.Contains('(PID 4242)'))
    Cas 'déclencheur absent : « ? »' (($l | Where-Object { $_.Action.Id -eq 'a5' }).Declencheur -eq '?')
    Cas 'récupération écrite, service arrêté compris' ($a3.Recuperation.Contains('deR4Tizer - isole') -and $a1.Recuperation.Contains('resmon'))
    Cas 'fichier absent ou vide : aucune ligne' ((& $appel $vr 'Lignes' @($null, [long]0)).Count -eq 0)

    # Récupération : la forme exacte vient de blocages.json et quarantaine.json (le registre garde des minuscules)
    $listeB = [Activator]::CreateInstance([Collections.Generic.List``1].MakeGenericType((& $t 'Blocage')))
    foreach ($b in @(@('programme', 'C:\Outils\Y.exe'), @('parefeu', '203.0.113.9'), @('hosts', 'exemple.test'))) {
        $o = [Activator]::CreateInstance((& $t 'Blocage')); $o.Type = $b[0]; $o.Cible = $b[1]; $listeB.Add($o)
    }
    $listeQ = [Activator]::CreateInstance([Collections.Generic.List``1].MakeGenericType((& $t 'ElementQuarantaine')))
    $q = [Activator]::CreateInstance((& $t 'ElementQuarantaine')); $q.Id = 'q-7'; $q.CheminOrigine = 'C:\Users\A\Z.bin'; $listeQ.Add($q)
    $rec = { param($sorte, $cible, $numero) $a = [Activator]::CreateInstance((& $t 'ActionEnCours')); $a.Sorte = $sorte; $a.Cible = $cible; if ($numero) { $a.Pid = $numero }; & $appel $vr 'Recuperer' @($a, $listeB, $listeQ) }
    $a0 = [Activator]::CreateInstance((& $t 'ActionEnCours')); $a0.Sorte = 'SuspensionAuto'; $a0.Cible = 'x'; $a0.Pid = 4242; $a0.Creation = 133000000000000000
    $c = & $appel $vr 'Recuperer' @($a0, $listeB, $listeQ)
    Cas 'suspension : reprendre par PID, heure de création du registre jointe (D1)' ($c.Action -eq 'reprendre' -and $c.Cible -eq '4242' -and $c.Creation -eq 133000000000000000)
    # L'assistant refuse un PID réutilisé : heure fausse sur ce processus PowerShell, puis la bonne
    $canal0 = & $t 'Canal'
    $cmd = [Activator]::CreateInstance((& $t 'Commande')); $cmd.Action = 'reprendre'; $cmd.Cible = [string]$PID; $cmd.Creation = 1
    $refus = $false; try { $canal0.GetMethod('PreparerIdentite').Invoke($null, @($cmd)) } catch { $refus = $_.Exception.InnerException.Message -match 'PID' }
    $cmd2 = [Activator]::CreateInstance((& $t 'Commande')); $cmd2.Action = 'reprendre'; $cmd2.Cible = [string]$PID
    $canal0.GetMethod('PreparerIdentite').Invoke($null, @($cmd2))
    $cmd3 = [Activator]::CreateInstance((& $t 'Commande')); $cmd3.Action = 'reprendre'; $cmd3.Cible = [string]$PID; $cmd3.Creation = $cmd2.Creation
    $accepte = $true; try { $canal0.GetMethod('PreparerIdentite').Invoke($null, @($cmd3)) } catch { $accepte = $false }
    Cas 'assistant : PID réutilisé refusé, bonne heure acceptée (D1)' ($refus -and $accepte -and $cmd3.Creation -eq $cmd2.Creation)
    Cas 'suspension sans PID : rien' ($null -eq (& $rec 'Suspension' 'x' $null))
    $c = & $rec 'Isolation' 'c:\outils\y.exe' $null
    Cas 'isolation : libérer, forme exacte' ($c.Action -eq 'debloquer' -and $c.Type -eq 'programme' -and $c.Cible -eq 'C:\Outils\Y.exe')
    $c = & $rec 'BlocageManuel' 'exemple.test' $null
    Cas 'blocage manuel de domaine : débloquer hosts' ($c.Action -eq 'debloquer' -and $c.Type -eq 'hosts')
    $c = & $rec 'BlocageManuel' '203.0.113.9' $null
    Cas 'blocage manuel d''adresse : débloquer pare-feu' ($c.Type -eq 'parefeu' -and $c.Cible -eq '203.0.113.9')
    $q2 = [Activator]::CreateInstance((& $t 'ElementQuarantaine')); $q2.Id = 'q-9'; $q2.CheminOrigine = 'c:\users\a\z.bin'; $q2.Date = '2026-11-03 01:00:00'; $listeQ.Add($q2)
    $q.Date = '2026-11-01 08:00:00'
    $c = & $rec 'Quarantaine' 'c:\users\a\z.bin' $null
    Cas 'quarantaine : restaurer par identifiant, la plus récente (R2)' ($c.Action -eq 'restaurer' -and $c.Cible -eq 'q-9')
    $c = & $rec 'Panique' 'poste' $null
    Cas 'panique : rétablir' ($c.Action -eq 'panique' -and $c.Valeur -eq 'off')
    Cas 'objet disparu : rien' ($null -eq (& $rec 'Isolation' 'c:\autre.exe' $null) -and $null -eq (& $rec 'Quarantaine' 'c:\autre' $null))

    # Audit de #120 : PID réutilisé (S120-02), dossier parent qui est un lien (S120-01)
    Cas 'même processus : refus seulement si lue et différente (R4)' ((& $appel $vr 'MemeProcessus' @([long]5, [long]5)) -and -not (& $appel $vr 'MemeProcessus' @([long]5, [long]6)) -and (& $appel $vr 'MemeProcessus' @([long]5, $null)) -and (& $appel $vr 'MemeProcessus' @($null, $null)))
    Cas 'registre : absent, illisible, lu (S120-04)' ((& $appel $vr 'EtatLecture' @($false, $false)) -eq 'absent' -and (& $appel $vr 'EtatLecture' @($true, $false)) -eq 'illisible' -and (& $appel $vr 'EtatLecture' @($true, $true)) -eq 'lu')
    $r0 = [IO.File]::ReadAllText("$src\Reponses.cs")
    Cas 'registre illisible : dernier affichage gardé' ($r0.Contains('if (illisible) Illisible(); else Afficher(l);'))
    $canal = & $t 'Canal'
    $d = Join-Path $travail 'vrai'; New-Item -ItemType Directory -Path (Join-Path $d 'sous') -Force | Out-Null
    Set-Content (Join-Path $d 'sous\x.exe') 'x'
    $j = Join-Path $travail 'j'; cmd.exe /c mklink /J "$j" "$d" | Out-Null
    Cas 'parent lien vu, sans le suivre' ([bool]$canal.GetMethod('ParentPointAnalyse').Invoke($null, @([string](Join-Path $j 'sous\x.exe'))) -and -not [bool]$canal.GetMethod('ParentPointAnalyse').Invoke($null, @([string](Join-Path $d 'sous\x.exe'))))
    cmd.exe /c rmdir "$j" | Out-Null
    $r = [IO.File]::ReadAllText("$src\Reponses.cs")
    Cas 'reprise : processus vérifié avant l''envoi' ($r.Contains('if (c.Action == "reprendre" && !VueReponses.MemeProcessus(x.Action.Creation, Canal.CreationProcessus(x.Action.Pid ?? 0)))'))
    $g0 = [IO.File]::ReadAllText("$src\Gui.cs")
    Cas 'chemin réel : échéance et parents lus avant l''ouverture' ($g0.Contains('lecture.Wait(2000) ? lecture.Result') -and $g0.IndexOf('if (ParentPointAnalyse(chemin))') -lt $g0.IndexOf('IntPtr h = CreateFileW(chemin, 0x80'))

    # Mode panique : portée, IPv6, relance, retour arrière ; état effectif
    $p = & $appel $vr 'ConfirmationPanique' @($true)
    Cas 'portée dite avant d''activer' ($p.Contains('IPv4 et IPv6') -and $p.Contains('IPv6 ouvertes ne le sont PAS') -and $p.Contains('réseau local') -and $p.Contains('4 h') -and $p.Contains('Rétablir Internet'))
    Cas 'désactivation : vérification dite' ((& $appel $vr 'ConfirmationPanique' @($false)).Contains('incertain'))
    $etat = { param($e, $p) $x = [Activator]::CreateInstance((& $t 'Etat')); $x.PaniqueEtat = $e; $x.Panique = $p; $x }
    Cas 'bouton : actif' ((& $appel $vr 'TexteBoutonPanique' @((& $etat 'active' $true))) -eq '◉ RÉTABLIR INTERNET')
    Cas 'bouton : incertain dit' ((& $appel $vr 'TexteBoutonPanique' @((& $etat 'incertaine' $true))).Contains('INCERTAINE'))
    Cas 'bouton : inactif' ((& $appel $vr 'TexteBoutonPanique' @((& $etat 'inactive' $false))).Contains('COUPER'))
    Cas 'service d''avant 6.5 : drapeau seul' ((& $appel $vr 'TexteBoutonPanique' @((& $etat $null $true))) -eq '◉ RÉTABLIR INTERNET')
    Cas 'pastille : rien si inactif, dite sinon' ($null -eq (& $appel $vr 'PastillePanique' @((& $etat 'inactive' $false))) -and (& $appel $vr 'PastillePanique' @((& $etat 'incertaine' $true))).Contains('INCERTAIN') -and $null -eq (& $appel $vr 'PastillePanique' @($null)))

    # Anglais
    $langue.GetField('En').SetValue($null, $true)
    Cas 'anglais : portée et bouton' ((& $appel $vr 'ConfirmationPanique' @($true)).Contains('IPv6 connections are NOT closed') -and (& $appel $vr 'Bouton' @('Isolation')) -eq 'Release')
    $langue.GetField('En').SetValue($null, $false)
    foreach ($s in 'SuspensionAuto', 'Suspension', 'Isolation', 'Panique', 'Quarantaine', 'BlocageManuel') {
        Cas "sorte $s : libellé, bouton, récupération" ((& $appel $vr 'Libelle' @($s)) -ne $s -and (& $appel $vr 'Bouton' @($s)) -ne '' -and (& $appel $vr 'Recuperation' @($s)) -ne '')
    }

    # Construction de la page (jamais affichée)
    $ok = $true; $m = ''
    try { $pg = [Activator]::CreateInstance((& $t 'PageReponses'), $true); $pg.Dispose() } catch { $ok = $false; $m = $_.Exception.InnerException.Message }
    Cas 'PageReponses construite' $ok $m

    # Branchements dans Gui.cs
    $g = [IO.File]::ReadAllText("$src\Gui.cs") -replace "`r`n", "`n"
    Cas 'navigation : Réponses en cours' ($g.Contains('var pageReponses = new PageReponses();') -and $g.Contains('Lien(liens, L.En ? "Ongoing responses" : "Réponses en cours", pageReponses, largeurNav);'))
    Cas 'bouton et pastille sur l''état effectif' ($g.Contains('btnPanique.Text = VueReponses.TexteBoutonPanique(etat);') -and $g.Contains('VueReponses.PastillePanique(etat)'))
    Cas 'une seule pastille du mode panique (dossier UI de la 6.7)' (-not $g.Contains('MODE PANIQUE : INTERNET COUPÉ') -and ([regex]::Matches($g, 'VueReponses\.PastillePanique\(etat\)')).Count -eq 1)
    Cas 'confirmation du mode panique : portée' ($g.Contains('string question = VueReponses.ConfirmationPanique(!paniqueActive);') -and $g.Contains('case "panique": return VueReponses.ConfirmationPanique(v != "off");'))
    Cas 'isolation : chemin réel dans la confirmation (S118-02)' ($g.Contains('+ CheminReelTexte(cible);') -and $g.Contains('CreateFileW(chemin, 0x80, 7, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero)'))
    Cas 'isolation : confirmation détaillée aussi pour un administrateur (D2)' ($g.Contains('if (ActionSurProcessus(c) || c.Action == "isolerProgramme")'))
    Cas 'chemin réel : disque fixe seulement (R1)' ($g.Contains('fixe = new DriveInfo(chemin.Substring(0, 2)).DriveType == DriveType.Fixed;'))
    # U0 (docs/roadmap/interface.md) : texte secondaire lisible (WCAG, 4,5:1 au moins sur chaque fond), en-tête traduit
    $theme = & $t 'Theme'
    $lum = { param($c) $v = foreach ($x in $c.R, $c.G, $c.B) { $s = $x / 255; if ($s -le 0.03928) { $s / 12.92 } else { [math]::Pow(($s + 0.055) / 1.055, 2.4) } }; 0.2126 * $v[0] + 0.7152 * $v[1] + 0.0722 * $v[2] }
    $contraste = { param($a, $b) $la = & $lum $a; $lb = & $lum $b; ([math]::Max($la, $lb) + 0.05) / ([math]::Min($la, $lb) + 0.05) }
    $dim = $theme.GetField('TexteDim').GetValue($null)
    foreach ($fond in 'Fond', 'Panneau', 'Panneau2') {
        $k = & $contraste $dim ($theme.GetField($fond).GetValue($null))
        Cas "contraste du texte secondaire sur $fond : $([math]::Round($k, 2)):1 (4,5 au moins)" ($k -ge 4.5)
    }
    Cas 'en-tête : sous-titre et pastille des listes traduits, sans capitales forcées' (-not $g.Contains('NETWORK THREAT MONITOR') -and -not $g.Contains('"INTEL "') -and $g.Contains('L.T("Surveillance des menaces réseau")') -and $g.Contains('L.T("Listes de menaces")'))
    $langue.GetField('En').SetValue($null, $true)
    $traduits = foreach ($fr in 'Surveillance des menaces réseau', 'service système', 'Listes de menaces', 'domaines') { & $appel $langue 'T' @($fr) }
    $langue.GetField('En').SetValue($null, $false)
    Cas 'en-tête : traductions anglaises' (($traduits -join '|') -eq 'Network threat monitoring|system service|Threat lists|domains') ($traduits -join '|')
    # U0, captures : pastilles en dur traduites ; pastilles jamais sous le titre, « +N » pour celles qui ne tiennent pas
    Cas 'en-tête et barre d''état : plus de texte en dur' (-not $g.Contains('Texte = "SERVICE EN LIGNE"') -and -not $g.Contains('"PROCESSUS : WMI"') -and -not $g.Contains('"▸ mis à jour "') -and -not $g.Contains('Texte = "BUREAU À DISTANCE ACTIF"') -and -not $g.Contains('Texte = "DEFENDER DÉSACTIVÉ"'))
    $langue.GetField('En').SetValue($null, $true)
    $en = foreach ($fr in 'SERVICE EN LIGNE', 'PROCESSUS', 'mis à jour', 'service démarré le', 'BUREAU À DISTANCE ACTIF', 'arrêté') { & $appel $langue 'T' @($fr) }
    $langue.GetField('En').SetValue($null, $false)
    Cas 'en-tête et barre d''état : traductions anglaises' (($en -join '|') -eq 'SERVICE ONLINE|PROCESSES|updated|service started on|REMOTE DESKTOP ON|stopped') ($en -join '|')
    $entete = & $t 'Entete'
    $vis = { param([int[]]$l, [int[]]$gr, [int]$d, [int]$r) (@($entete.GetMethod('PastillesVisibles').Invoke($null, [object[]]@($l, $gr, $d, $r))) -join ',') }
    Cas 'pastilles : toutes si elles tiennent' ((& $vis @(100, 100, 100) @(0, 0, 0) 316 40) -eq '0,1,2')
    Cas 'pastilles : les premières gardées à gravité égale, place du « +N » réservée' ((& $vis @(100, 100, 100) @(0, 0, 0) 315 40) -eq '0,1') "$(& $vis @(100, 100, 100) @(0, 0, 0) 315 40)"
    Cas 'pastilles : une rouge en fin de liste reste visible (relecture de #132, D2)' ((& $vis @(100, 100, 100) @(0, 0, 2) 315 40) -eq '0,2') "$(& $vis @(100, 100, 100) @(0, 0, 2) 315 40)"
    Cas 'pastilles : la rouge avant la jaune, ordre d''origine gardé à l''affichage' ((& $vis @(100, 100, 100) @(1, 0, 2) 200 40) -eq '2') "$(& $vis @(100, 100, 100) @(1, 0, 2) 200 40)"
    Cas 'pastilles : aucune si même la plus grave ne tient pas avec le « +N »' ((& $vis @(300, 10) @(2, 0) 200 40) -eq '')
    Cas 'pastilles : liste vide' ((& $vis @() @() 100 40) -eq '')
    $gravite = { param($nom) $entete.GetMethod('Gravite').Invoke($null, @($theme.GetField($nom).GetValue($null))) }
    Cas 'pastilles : gravité lue sur la couleur (rouge 2, jaune 1, autre 0)' ((& $gravite 'Rouge') -eq 2 -and (& $gravite 'Jaune') -eq 1 -and (& $gravite 'Cyan') -eq 0)
    Cas 'pastilles : le « +N » prend la couleur de la plus grave cachée' ($g.Contains('Couleur = pire == 2 ? Theme.Rouge : pire == 1 ? Theme.Jaune : Theme.TexteDim'))
    # PR 6.14 : confirmations qui disent l'effet de 7 jours (S110-08) et la portée de la signature (S113-09)
    Cas 'reprise : effet de 7 jours dit, sauf interpréteur (S110-08)' ($g.Contains('ce programme ne sera plus suspendu automatiquement pendant 7 jours (sauf interpréteur reconnu par son nom, ou programme de Windows)'))
    Cas 'déblocage, tout débloquer : effet de 7 jours dit (S110-08)' ($g.Contains('il ne sera pas reposé automatiquement pendant 7 jours') -and $g.Contains('ne seront pas reposés automatiquement pendant 7 jours'))
    Cas 'signature : celle du fichier à ce chemin (S113-09)' ($g.Contains('Signature du fichier à ce chemin (pas forcément celle du processus) : ') -and -not $g.Contains('+ "\n" + "Signature : " + signature'))
    $r = [IO.File]::ReadAllText("$src\Reponses.cs")
    Cas 'récupération par le canal (assistant élevé)' ($r.Contains('Canal.Executer(c);'))
    Cas 'lecture hors du fil de l''interface, une à la fois' ($r.Contains('ThreadPool.QueueUserWorkItem') -and $r.Contains('Interlocked.CompareExchange(ref enCours, 1, 0)'))
    foreach ($f in "$Depot\compiler.ps1", "$Depot\tests\test-confirmations.ps1", "$Depot\tests\test-incidents-interface.ps1", "$Depot\tests\test-collectes-interface.ps1") {
        Cas "compilation : Reponses.cs listé ($(Split-Path $f -Leaf))" (([IO.File]::ReadAllText($f)).Contains('"$src\Reponses.cs"'))
    }
} finally {
    Remove-Item $travail -Recurse -Force -ErrorAction SilentlyContinue
}
if ($ko) { "$ko cas en échec"; exit 1 }
