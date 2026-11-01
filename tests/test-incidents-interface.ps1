# Compile l'interface et vérifie les pages Incidents et Santé (PR 4.6) : décisions pures (état en texte, transitions, note, pastille, état ancien, lignes de
# santé), lecture des fichiers tels que le service les écrit, confirmation, construction des pages ; puis contrôle du source de Gui.cs. La fenêtre n'est pas lancée.
# Usage (Windows PowerShell 5.1) : powershell -File tests\test-incidents-interface.ps1 [-Depot <racine du dépôt>]
param([string]$Depot = (Split-Path $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$src = Join-Path $Depot 'src'
$travail = Join-Path $env:TEMP ("d4t-incidents-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $travail | Out-Null
$ko = 0
function Cas([string]$Nom, [bool]$Ok, [string]$Detail = '') {
    if ($Ok) { "RÉUSSI  $Nom" } else { "ÉCHOUÉ  $Nom $Detail"; $script:ko++ }
}
try {
    $out = Join-Path $travail 'interface.exe'
    $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $csc /nologo /platform:anycpu /codepage:65001 /target:winexe /r:System.dll /r:System.Core.dll /r:System.Web.Extensions.dll /r:System.ServiceProcess.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll "/out:$out" "$src\Commun.cs" "$src\Langue.cs" "$src\Theme.cs" "$src\Gui.cs" "$src\Reglages.cs" "$src\Siem.cs" "$src\Incidents.cs" "$src\Trafic.cs" "$src\Reseau.cs" "/resource:$src\carte-pays.txt,carte-pays.txt"
    if ($LASTEXITCODE) { throw 'compilation' }
    Add-Type -AssemblyName System.Windows.Forms, System.Web.Extensions
    $asm = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($out))
    $t = { param($n) $asm.GetType("DeR4Tizer.$n") }
    $vi = & $t 'VueIncidents'; $vs = & $t 'VueSante'; $langue = & $t 'L'; $canal = & $t 'Canal'
    $appel = { param($type, $m, [object[]]$a) $type.GetMethod($m).Invoke($null, $a) }
    $json = New-Object Web.Script.Serialization.JavaScriptSerializer
    $json.MaxJsonLength = 2147483647
    $lire = { param($nomType, $texte) $json.GetType().GetMethods() | Where-Object { $_.Name -eq 'Deserialize' -and $_.IsGenericMethod } | ForEach-Object { $_.MakeGenericMethod((& $t $nomType)).Invoke($json, @($texte)) } }
    # Une clé en double dans le dictionnaire ferait échouer l'initialisation de L : l'interface ne démarrerait plus
    $ok = $true; try { $langue.GetField('En').SetValue($null, $false) } catch { $ok = $false }
    Cas 'dictionnaire de langue : pas de clé en double' $ok
    if (-not $ok) { throw 'dictionnaire de langue' }

    # Fichier tel que le service l'écrit (noms de incidents.rs, en PascalCase)
    $texteIncident = @'
{"Modele":1,"Id":"inc-1","Ouverture":"2026-11-01 10:00:00","OuvertureUtc":"2026-11-01T09:00:00Z","DerniereActiviteUtc":"2026-11-01T09:05:00Z","Niveau":"Critique","Entite":"programme:c:\\temp\\x\u202e.exe","Regles":["LEU-001"],"Etat":"Clos","MotifCloture":"FauxPositif","Precedent":"inc-0","Alertes":[{"Id":"a","Heure":"2026-11-01 10:00:00","HeureUtc":"","Niveau":"Critique","Regle":"LEU-001","Processus":"x.exe","Chemin":"c:\\temp\\x.exe","Destination":"d","Raisons":"ligne\nfausse"}],"NombreAlertes":3,"Transitions":[{"Heure":"2026-11-01 10:05:00","HeureUtc":"","De":"Ouvert","Vers":"Clos","Motif":"FauxPositif","Auteur":"S-1-5-21","Note":"vu"}]}
'@
    $i = & $lire 'IncidentSuivi' $texteIncident
    Cas 'fichier du service lu : état, motif, règles, alertes, transitions' ($i.Id -eq 'inc-1' -and $i.Etat -eq 'Clos' -and $i.MotifCloture -eq 'FauxPositif' -and $i.Regles[0] -eq 'LEU-001' -and $i.Alertes.Count -eq 1 -and $i.Transitions[0].Vers -eq 'Clos' -and $i.NombreAlertes -eq 3)
    Cas 'état en texte, motif compris' ((& $appel $vi 'EtatComplet' @($i)) -eq 'Clos : faux positif')

    # Transitions : mêmes que incidents.rs
    $permise = { param($de, $vers) [bool](& $appel $vi 'Permise' @($de, $vers)) }
    foreach ($c in @(@('Ouvert', 'PrisEnCharge', $true), @('Ouvert', 'Clos', $true), @('PrisEnCharge', 'Clos', $true), @('Clos', 'Ouvert', $true), @('Clos', 'PrisEnCharge', $false), @('PrisEnCharge', 'Ouvert', $false), @('Ouvert', 'Ouvert', $false), @('Clos', 'Clos', $false))) {
        Cas "transition $($c[0]) vers $($c[1]) : $($c[2])" ((& $permise $c[0] $c[1]) -eq $c[2])
    }
    $cmd = & $appel $vi 'Transition' @('inc-1', 'Clos', 'Resolu', 'vu')
    Cas 'commande : action, cible, valeur, motif, note' ($cmd.Action -eq 'incident' -and $cmd.Cible -eq 'inc-1' -and $cmd.Valeur -eq 'Clos' -and $cmd.Type -eq 'Resolu' -and $cmd.Raison -eq 'vu')

    # Note : mêmes refus que le service
    Cas 'note vide acceptée' ((& $appel $vi 'NoteRefusee' @('')) -eq '')
    Cas 'note de 300 caractères acceptée' ((& $appel $vi 'NoteRefusee' @(('x' * 300))) -eq '')
    Cas 'note de 301 caractères refusée' ((& $appel $vi 'NoteRefusee' @(('x' * 301))) -ne '')
    Cas 'note avec retour à la ligne refusée' ((& $appel $vi 'NoteRefusee' @("a`nb")) -ne '')
    Cas 'note avec mise en forme refusée' ((& $appel $vi 'NoteRefusee' @("a$([char]0x202E)b")) -ne '')

    # Identifiant : rien n'est lu hors du dossier des chronologies
    foreach ($c in @(@('inc-1', $true), @('..\..\etat', $false), @('', $false), @('a/b', $false), @(('a' * 65), $false), @(('a' * 64), $true))) {
        Cas "identifiant « $($c[0]) » : $($c[1])" ([bool](& $appel $vi 'IdentifiantValide' @($c[0])) -eq $c[1])
    }

    # Tri : non clos d'abord, puis les plus récents
    $liste = [Activator]::CreateInstance([Collections.Generic.List`1].MakeGenericType((& $t 'IncidentSuivi')))
    foreach ($c in @(@('a', 'Clos', '2026-11-03'), @('b', 'Ouvert', '2026-11-01'), @('c', 'PrisEnCharge', '2026-11-02'))) {
        $x = [Activator]::CreateInstance((& $t 'IncidentSuivi')); $x.Id = $c[0]; $x.Etat = $c[1]; $x.DerniereActiviteUtc = $c[2]; $liste.Add($x)
    }
    $trie = & $appel $vi 'Trier' @(, $liste)
    Cas 'tri : non clos d''abord, puis récents' ((($trie | ForEach-Object Id) -join '') -eq 'cba')

    # Détail : textes neutralisés, une ligne par élément, chronologie incomplète dite
    $texteChrono = '{"CalculeeUtc":"2026-11-01T09:06:00Z","Elements":[{"Heure":"2026-11-01 10:00:00","HeureUtc":"","Seq":1,"Source":"securite","Type":"t","Niveau":"","Texte":"ouverture","ParNom":true}],"Tronquee":true,"SansHeureUtc":2,"PertesSiem":5,"FenetreSiemIncomplete":true}'
    $chrono = & $lire 'ChronologieIncident' $texteChrono
    $d = & $appel $vi 'Detail' @($i, $chrono)
    Cas 'détail : caractère de mise en forme neutralisé' (-not $d.Contains([string][char]0x202E))
    Cas 'détail : pas de fausse ligne dans une alerte' ($d -notmatch "(?m)^fausse")
    Cas 'détail : récidive, alertes partielles' ($d.Contains('inc-0') -and $d.Contains('(alertes gardées ici : 1 sur 3)'))
    Cas 'détail : transition, motif, note' ($d.Contains('Ouvert → Clos (faux positif)') -and $d.Contains('« vu »'))
    Cas 'détail : lien par le seul nom signalé' ($d.Contains('rattaché par le seul nom'))
    Cas 'détail : chronologie incomplète dite' ($d.Contains('Tronquée') -and $d.Contains('Lecture des événements incomplète') -and $d.Contains('5 événement(s) perdus') -and $d.Contains('2 événement(s) sans heure'))
    $d2 = & $appel $vi 'Detail' @($i, $null)
    Cas 'détail : chronologie absente dite' ($d2.Contains('Pas encore calculée'))
    $i.Transitions = $null
    Cas 'détail : aucune transition dite' ((& $appel $vi 'Detail' @($i, $null)).Contains('Aucune.'))

    # Pastille et état ancien
    $etatT = & $t 'Etat'; $colT = & $t 'EtatCollecte'
    $maintenant = [datetime]'2026-11-01 12:00:00'
    $etat = {
        param([object[]]$cols, $maj = '2026-11-01 11:59:30')
        $e = [Activator]::CreateInstance($etatT); $e.MisAJour = $maj; $e.Version = '4.3'; $e.Demarrage = '2026-11-01 08:00:00'; $e.ProtectionDonnees = ''
        $l = [Activator]::CreateInstance([Collections.Generic.List`1].MakeGenericType($colT))
        foreach ($c in $cols) { $o = [Activator]::CreateInstance($colT); $o.Id = $c[0]; $o.Etat = $c[1]; $o.Depuis = $c[2]; $l.Add($o) }
        $e.Collectes = $l; $e
    }
    $niveau = { param($e) [int](& $appel $vs 'NiveauPastille' @($e, $maintenant)) }
    $ilya = { param($m) $maintenant.AddMinutes(-$m).ToString('yyyy-MM-dd HH:mm:ss') }
    Cas 'pastille : tout va bien' ((& $niveau (& $etat @(, @('Connexions', 'Active', '')))) -eq 0)
    Cas 'pastille : collecte critique indisponible : jaune' ((& $niveau (& $etat @(, @('Connexions', 'Indisponible', (& $ilya 1))))) -eq 1)
    Cas 'pastille : Persistance est critique' ((& $niveau (& $etat @(, @('Persistance', 'Indisponible', (& $ilya 1))))) -eq 1)
    Cas 'pastille : collecte non critique : rien' ((& $niveau (& $etat @(, @('Sysmon', 'Indisponible', (& $ilya 90))))) -eq 0)
    Cas 'pastille : pas encore lue au démarrage : rien' ((& $niveau (& $etat @(, @('Connexions', 'Inconnue', (& $ilya 2))))) -eq 0)
    Cas 'pastille : jamais lue depuis plus de 30 min : jaune' ((& $niveau (& $etat @(, @('Connexions', 'Inconnue', (& $ilya 31))))) -eq 1)
    Cas 'pastille : un seul volet de Defender : jaune' ((& $niveau (& $etat @(, @('JournalDefender', 'Indisponible', (& $ilya 90))))) -eq 1)
    Cas 'pastille : Defender aveugle depuis moins de 30 min : jaune' ((& $niveau (& $etat @(@('JournalDefender', 'Indisponible', (& $ilya 10)), @('EtatDefender', 'Indisponible', (& $ilya 10))))) -eq 1)
    Cas 'pastille : Defender aveugle depuis plus de 30 min : rouge' ((& $niveau (& $etat @(@('JournalDefender', 'Indisponible', (& $ilya 31)), @('EtatDefender', 'Indisponible', (& $ilya 31))))) -eq 2)
    Cas 'pastille : état nul : rien' ((& $appel $vs 'NiveauPastille' @($null, $maintenant)) -eq 0)
    Cas 'pastille : texte selon le niveau' ((& $appel $vs 'TextePastille' @(0)) -eq '' -and (& $appel $vs 'TextePastille' @(1)) -match 'À VÉRIFIER' -and (& $appel $vs 'TextePastille' @(2)) -match 'DEFENDER')
    $ancien = { param($maj) [bool](& $appel $vs 'EtatAncien' @((& $etat @() $maj), $maintenant)) }
    Cas 'état récent : pas ancien' (-not (& $ancien (& $ilya 1)))
    Cas 'état de plus de 2 min : ancien' (& $ancien (& $ilya 3))
    Cas 'état sans heure lisible : ancien' (& $ancien 'illisible')

    # Lignes de santé : chaque ligne a sa source ; les pannes disent leur conséquence
    $remT = & $t 'EtatRemontee'
    $r = [Activator]::CreateInstance($remT); $r.NtfyConfigure = $true; $r.Envoyes = 2; $r.EnAttente = 1; $r.EchecDepuis = '2026-11-01 11:00:00'; $r.DerniereErreur = 'refus'; $r.DernierEnvoi = '2026-11-01 10:00:00'
    $e = & $etat @(@('Connexions', 'Indisponible', (& $ilya 5)), @('Sysmon', 'Active', ''))
    $lignes = @(& $appel $vs 'Lignes' @($e, $r, $maintenant))
    Cas 'santé : chaque ligne dit sa source' (@($lignes | Where-Object { -not $_.Source }).Count -eq 0)
    $li = $lignes | Where-Object Sujet -eq 'Connexions'
    Cas 'santé : panne avec conséquence, en tête du détail' ($li.Gravite -eq 1 -and $li.Detail -match '^connexions réseau non vues')
    $ep = & $etat @(@('Persistance', 'Partielle', (& $ilya 5)), @('Sysmon', 'Desactivee', ''))
    $lp = @(& $appel $vs 'Lignes' @($ep, $r, $maintenant))
    Cas 'santé : collecte partielle à vérifier' ((($lp | Where-Object Sujet -eq 'Persistance').Gravite -eq 1))
    $sy = $lp | Where-Object Sujet -eq 'Sysmon'
    Cas 'santé : collecte désactivée : rien à vérifier, pas de séparateur vide' ($sy.Gravite -eq 0 -and $sy.Detail -eq '')
    Cas 'santé : remontée en échec' (@($lignes | Where-Object { $_.Sujet -eq 'Remontée' -and $_.Gravite -eq 1 -and $_.Detail -match 'refus' -and $_.Detail -match '1 en attente' }).Count -eq 1)
    Cas 'santé : interface par session dite non publiée' (@($lignes | Where-Object { $_.Sujet -eq 'Interface par session' -and $_.Etat -eq 'non publié' }).Count -eq 1)
    Cas 'santé : remontée illisible dite' (@(& $appel $vs 'Lignes' @($e, $null, $maintenant) | Where-Object { $_.Sujet -eq 'Remontée' -and $_.Gravite -eq 1 }).Count -eq 1)
    Cas 'santé : état absent dit' (@(& $appel $vs 'Lignes' @($null, $null, $maintenant))[0].Gravite -eq 1)
    $vieux = @(& $appel $vs 'Lignes' @((& $etat @() (& $ilya 10)), $r, $maintenant))
    Cas 'santé : état ancien dit en première ligne' ($vieux[0].Etat -eq 'état ancien' -and $vieux[0].Gravite -eq 1)
    Cas 'santé : protection en échec dite' (@(& $appel $vs 'Lignes' @((& { $x = & $etat @(); $x.ProtectionDonnees = 'droits'; $x }), $r, $maintenant) | Where-Object { $_.Etat -eq 'en échec' -and $_.Detail -eq 'droits' }).Count -eq 1)

    # Confirmation : l'incident et la transition, textes neutralisés ; sans fichier, « inconnu »
    $cmdT = & $t 'Commande'
    $c = [Activator]::CreateInstance($cmdT); $c.Action = 'incident'; $c.Cible = 'inconnu-1'; $c.Valeur = 'Clos'; $c.Type = 'FauxPositif'; $c.Raison = "note$([char]0x202E)`nfausse"
    $texte = $canal.GetMethod('Decrire').Invoke($null, @($c))
    Cas 'confirmation : identifiant, inconnu dit, motif, note' ($texte.Contains('inconnu-1') -and $texte.Contains('(inconnu)') -and $texte.Contains('faux positif') -and $texte.Contains('note'))
    Cas 'confirmation : note neutralisée' (-not $texte.Contains([string][char]0x202E) -and $texte -notmatch "(?m)^fausse")

    # Anglais : textes des pages présents au dictionnaire
    $langue.GetField('En').SetValue($null, $true)
    Cas 'anglais : état, pastille, note' ((& $appel $vi 'EtatEnTexte' @('PrisEnCharge')) -eq 'In progress' -and (& $appel $vs 'TextePastille' @(1)) -eq 'HEALTH: TO CHECK' -and (& $appel $vi 'NoteRefusee' @(('x' * 301))) -match 'characters')
    $langue.GetField('En').SetValue($null, $false)

    # Construction des pages (jamais affichées)
    foreach ($nom in 'PageIncidents', 'PageSante') {
        $ok = $true; $m = ''
        try { $p = [Activator]::CreateInstance((& $t $nom), $true); $p.Dispose() } catch { $ok = $false; $m = $_.Exception.InnerException.Message }
        Cas "$nom construite" $ok $m
    }

    # Branchements dans Gui.cs (la fenêtre n'est pas lancée par ce script)
    $g = [IO.File]::ReadAllText("$src\Gui.cs") -replace "`r`n", "`n"
    Cas 'navigation : Incidents et Santé' ($g.Contains('Lien(liens, "Incidents", pageIncidents, largeurNav)') -and $g.Contains('Lien(liens, "Santé", pageSante, largeurNav)'))
    Cas 'pastille branchée, rouge seulement au niveau 2' ($g.Contains('VueSante.NiveauPastille(etat, DateTime.Now)') -and $g.Contains('niveauSante == 2 ? Theme.Rouge : Theme.Jaune'))
    Cas 'état ancien branché' ($g.Contains('VueSante.EtatAncien(etat, DateTime.Now)'))
    $p = [IO.File]::ReadAllText("$src\Incidents.cs")
    Cas 'transitions par le canal (assistant élevé)' ($p.Contains('Canal.Executer(VueIncidents.Transition('))
    Cas 'lectures hors du fil de l''interface' (([regex]::Matches($p, 'ThreadPool\.QueueUserWorkItem')).Count -eq 3)
    Cas 'compilation : fichier listé' (([IO.File]::ReadAllText("$Depot\compiler.ps1")).Contains('"$src\Incidents.cs"'))
} finally {
    Remove-Item $travail -Recurse -Force -ErrorAction SilentlyContinue
}
if ($ko) { "$ko cas en échec"; exit 1 }
'Tous les cas réussis.'
