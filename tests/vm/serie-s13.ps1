# Lot 4 de la couverture ATT&CK : série de consolidation de S-13 (service depuis un dossier inscriptible, compte créé
# puis ajouté aux Administrateurs, journal dédié effacé, sous-catégorie d'audit désactivée), avec les témoins N-07 à N-10.
# Lancé sur le poste (hôte Hyper-V), VM de test seulement ; liste v1.7, protocole de répétition (3.4) :
#   - remise à l'instantané de la configuration avant chaque essai (et à la fin) ; cibles distinctes par essai ;
#   - critère D-2 avant l'heure de départ : journaux Sécurité et Système « Active » (sinon D) ;
#   - actions faites par le compte administrateur de la VM (PowerShell Direct), jamais par SYSTEM ; l'émetteur du 4719 est
#     relevé (émis par le système : volet T1685.001 invalide, D) ;
#   - notation par volet (S-13 n'est jamais fusionné) : R5 pour T1543.003 et T1569.002, R3 ou R3b pour T1098, R4 pour
#     T1685.005, R7 pour T1685.001 ; VP si la corrélation attendue est levée au niveau attendu dans le délai ;
#   - latence : HeureUtc de l'alerte de corrélation moins TimeCreated de l'événement déclencheur (horloge de la VM) ;
#     HeureUtc est à la seconde : précision de ±1 s (une valeur légèrement négative est possible) ;
#   - BAS-001 n'est pas attendue (point 10 : NON ÉVALUÉE, relevée seulement si elle arrive dans la fenêtre).
# SIMULATION pour T1685.005 (journal dédié au test, jamais Sécurité ni Système) et T1685.001 (sous-catégorie désactivée,
# rétablie par la remise à l'instantané). Aucune donnée personnelle ; le mot de passe du compte jetable est tiré dans la
# VM et jamais écrit.
#
# Usage : .\tests\vm\serie-s13.ps1 -Configuration A|B|C [-Essais 10] [-Temoins 3] [-Observation 240]
param(
    [Parameter(Mandatory)] [ValidateSet('A', 'B', 'C')] [string]$Configuration,
    [int]$Essais = 10,
    [int]$Temoins = 3,
    [int]$Observation = 240,
    [int]$Stabilisation = 180,
    [string]$Vm = 'deR4Tizer-test-26H2',
    [string]$Racine = 'C:\d4t-bac-a-sable',
    [string]$Identifiants = (Join-Path $env:USERPROFILE '.d4t-vm-credential.xml')
)
$ErrorActionPreference = 'Stop'
$cred = Import-Clixml $Identifiants
$inst = Get-VMSnapshot -VMName $Vm | Where-Object Name -like "campagne $Configuration *" | Sort-Object CreationTime | Select-Object -Last 1
if (-not $inst) { throw "instantané « campagne $Configuration » absent" }
$sortie = Join-Path $Racine "sortie-serie-s13-$Configuration-$(Get-Date -Format yyyyMMdd-HHmmss)"
New-Item -ItemType Directory -Force $sortie | Out-Null
function Note($t) { $l = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $t"; Write-Host $l; Add-Content -Path (Join-Path $sortie 'journal.txt') -Value $l -Encoding utf8 }
$guidAudit = '{0CCE9215-69AE-11D9-BED3-505054503030}'   # Audit Logon (profil journalisation)

function Session-Propre {
    Restore-VMSnapshot -VMSnapshot $inst -Confirm:$false
    if ((Get-VM $Vm).State -ne 'Running') { Start-VM $Vm }
    $fin = (Get-Date).AddMinutes(5)
    do { $s = try { New-PSSession -VMName $Vm -Credential $cred -ErrorAction Stop } catch { Start-Sleep 5; $null } } while (-not $s -and (Get-Date) -lt $fin)
    if (-not $s) { throw 'VM injoignable par PowerShell Direct' }
    Invoke-Command -Session $s { w32tm /resync /force 2>&1 | Out-Null } -ErrorAction SilentlyContinue
    Start-Sleep -Seconds $Stabilisation
    $s
}

function Preconditions($s) {
    Invoke-Command -Session $s {
        $e = Get-Content 'C:\ProgramData\deR4Tizer\etat.json' -Raw -Encoding UTF8 | ConvertFrom-Json
        [pscustomobject]@{
            Securite = ($e.Collectes | Where-Object Id -eq 'JournalSecurite').Etat
            Systeme = ($e.Collectes | Where-Object Id -eq 'JournalSysteme').Etat
            Service = (Get-FileHash 'C:\Program Files\deR4Tizer\deR4TizerSvc.exe').Hash
            Sysmon = [bool](Get-Service Sysmon, Sysmon64 -ErrorAction SilentlyContinue)
        }
    }
}

# Alertes de corrélation et BAS-001 levées depuis $Depuis (UTC), lues dans alertes.json (déroulé : PS 5.1 côté VM)
function Alertes-Depuis($s, [datetime]$Depuis) {
    Invoke-Command -Session $s -ArgumentList $Depuis {
        param($d)
        $a = @(try { Get-Content 'C:\ProgramData\deR4Tizer\alertes.json' -Raw -Encoding UTF8 | ConvertFrom-Json | ForEach-Object { $_ } } catch { @() })
        $a | Where-Object { "$($_.Regle)" -like 'COR-*' -or "$($_.Regle)" -eq 'BAS-001' } | Where-Object {
            try { [datetime]::Parse($_.HeureUtc).ToUniversalTime() -ge $d } catch { $false }
        } | Select-Object Regle, Niveau, HeureUtc, Destination
    }
}

# Note un volet : alerte de la règle attendue (une des règles admises) au niveau attendu, latence depuis le déclencheur
function Volet($alertes, [string[]]$Regles, [string]$Niveau, $Declencheur) {
    $a = $alertes | Where-Object { $_.Regle -in $Regles } | Sort-Object HeureUtc | Select-Object -First 1
    if (-not $Declencheur) { return @{ Note = 'D (événement déclencheur absent)'; Regle = "$($a.Regle)"; Niveau = "$($a.Niveau)"; Latence = '' } }
    if (-not $a) { return @{ Note = 'FN'; Regle = ''; Niveau = ''; Latence = '' } }
    $lat = [math]::Round(([datetime]::Parse($a.HeureUtc).ToUniversalTime() - $Declencheur).TotalSeconds, 1)
    $note = if ($a.Niveau -eq $Niveau -or ($a.Regle -eq 'COR-R3' -and $Niveau -eq 'Alerte')) { 'VP' } else { "autre niveau ($($a.Niveau))" }
    @{ Note = $note; Regle = $a.Regle; Niveau = $a.Niveau; Latence = $lat }
}

$lignes = New-Object System.Collections.Generic.List[string]
$lignes.Add('serie;essai;ligne;regle;niveau;latence_s;note;detail')
Note "série S-13, configuration $Configuration, instantané « $($inst.Name) », $Essais essai(s), $Temoins témoin(s) par témoin"

for ($n = 1; $n -le $Essais; $n++) {
    $s = Session-Propre
    $pre = Preconditions $s
    if ($n -eq 1) { Note "service $($pre.Service) ; Sysmon $($pre.Sysmon)"; $script:empreinte = $pre.Service; $script:sysmon = $pre.Sysmon }
    if ($pre.Securite -ne 'Active' -or $pre.Systeme -ne 'Active') {
        Note "essai $n : D (journaux Sécurité=$($pre.Securite), Système=$($pre.Systeme))"
        $lignes.Add("S-13;$n;toutes;;;;D;journaux inactifs")
        Remove-PSSession $s
        continue
    }
    $t0 = (Invoke-Command -Session $s { Get-Date }).ToUniversalTime()
    # Actions, cibles distinctes par essai ; le 4720 est laissé lire avant le 4732 (rapprochement par nom)
    Invoke-Command -Session $s -ArgumentList $n, $guidAudit {
        param($n, $g)
        sc.exe create "d4t_s13svc_$n" binPath= "C:\Users\Public\d4t-s13-svc-$n.exe" start= demand 2>&1 | Out-Null
        $mdp = ([guid]::NewGuid().ToString('N') + 'Aa1!') | ConvertTo-SecureString -AsPlainText -Force
        New-LocalUser -Name "d4t_s13_$n" -Password $mdp -AccountNeverExpires | Out-Null
        Start-Sleep 5
        net.exe localgroup "$((Get-LocalGroup -SID 'S-1-5-32-544').Name)" "d4t_s13_$n" /add 2>&1 | Out-Null
        $j = "d4t-s13-$n"
        New-EventLog -LogName $j -Source $j
        Write-EventLog -LogName $j -Source $j -EventId 1 -Message 'témoin avant effacement'
        wevtutil.exe cl $j 2>&1 | Out-Null
        auditpol.exe /set /subcategory:$g /success:disable /failure:disable 2>&1 | Out-Null
    }
    Start-Sleep -Seconds $Observation
    # Déclencheurs (TimeCreated, UTC) et émetteur du 4719
    $ev = Invoke-Command -Session $s -ArgumentList $t0, $n {
        param($t0, $n)
        $debut = $t0.ToLocalTime()
        function Premier($log, $id, $filtre) {
            Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $id; StartTime = $debut } -ErrorAction SilentlyContinue |
                Where-Object $filtre | Sort-Object TimeCreated | Select-Object -First 1
        }
        $e7045 = Premier 'System' 7045 { $_.Message -match "d4t_s13svc_$n" }
        # Seul ajout au groupe Administrateurs de l'essai : le premier 4732 après l'heure de départ
        $e4732 = Premier 'Security' 4732 { $true }
        $e104 = Premier 'System' 104 { $_.Message -match "d4t-s13-$n" }
        $e4719 = Premier 'Security' 4719 { $true }
        [pscustomobject]@{
            T7045 = $(if ($e7045) { $e7045.TimeCreated.ToUniversalTime() })
            T4732 = $(if ($e4732) { $e4732.TimeCreated.ToUniversalTime() })
            T104 = $(if ($e104) { $e104.TimeCreated.ToUniversalTime() })
            T4719 = $(if ($e4719) { $e4719.TimeCreated.ToUniversalTime() })
            Emetteur4719 = $(if ($e4719) { "$($e4719.Properties[0].Value)" })
        }
    }
    $al = @(Alertes-Depuis $s $t0)
    $r5 = Volet $al @('COR-R5') 'Critique' $ev.T7045
    $r3 = Volet $al @('COR-R3', 'COR-R3b') 'Alerte' $ev.T4732
    $r4 = Volet $al @('COR-R4') 'Critique' $ev.T104
    $r7 = if ($ev.Emetteur4719 -eq 'S-1-5-18') { @{ Note = 'D (4719 émis par le système)'; Regle = ''; Niveau = ''; Latence = '' } } else { Volet $al @('COR-R7') 'Alerte' $ev.T4719 }
    $bas = @($al | Where-Object Regle -eq 'BAS-001').Count
    foreach ($v in @(@('T1543.003 / T1569.002', $r5), @('T1098', $r3), @('T1685.005', $r4), @('T1685.001', $r7))) {
        $lignes.Add("S-13;$n;$($v[0]);$($v[1].Regle);$($v[1].Niveau);$($v[1].Latence);$($v[1].Note);émetteur 4719 $($ev.Emetteur4719) ; BAS-001 $bas")
    }
    Note "essai $n : R5 $($r5.Note) $($r5.Latence) s ; R3/R3b $($r3.Note) ($($r3.Regle)) $($r3.Latence) s ; R4 $($r4.Note) $($r4.Latence) s ; R7 $($r7.Note) $($r7.Latence) s ; BAS-001 $bas (non évaluée)"
    Remove-PSSession $s
}

# Témoins N-07 à N-10 : une session propre par essai de témoins ; une corrélation de la famille attendue = FP
for ($n = 1; $n -le $Temoins; $n++) {
    $s = Session-Propre
    $t0 = (Invoke-Command -Session $s { Get-Date }).ToUniversalTime()
    $faits = Invoke-Command -Session $s -ArgumentList $n {
        param($n)
        $f = @{}
        # N-07 : service déclaré vers un programme signé de Program Files, démarrage manuel, jamais démarré
        sc.exe create "d4t_n07svc_$n" binPath= '"C:\Program Files\Windows Defender\MpCmdRun.exe"' start= demand 2>&1 | Out-Null
        $f.N07 = [bool](Get-Service "d4t_n07svc_$n" -ErrorAction SilentlyContinue)
        # N-08 : compte de test ajouté à un groupe local non administrateur
        $mdp = ([guid]::NewGuid().ToString('N') + 'Aa1!') | ConvertTo-SecureString -AsPlainText -Force
        New-LocalUser -Name "d4t_n08_$n" -Password $mdp -AccountNeverExpires | Out-Null
        Start-Sleep 5
        # « Lecteurs des journaux d'événements » (S-1-5-32-573) : groupe local non administrateur ; un nouveau compte est
        # déjà dans « Utilisateurs »
        Add-LocalGroupMember -SID 'S-1-5-32-573' -Member "d4t_n08_$n" -ErrorAction SilentlyContinue
        $f.N08 = [bool](Get-LocalGroupMember -SID 'S-1-5-32-573' -ErrorAction SilentlyContinue | Where-Object Name -like "*d4t_n08_$n")
        # N-09 : politique d'audit lue, puis stratégies locales réappliquées par le système
        auditpol.exe /get /category:* 2>&1 | Out-Null
        gpupdate.exe /target:computer /force 2>&1 | Out-Null
        $f.N09 = $true
        # N-10 : journal dédié exporté vers un fichier, sans effacement
        $j = "d4t-n10-$n"
        New-EventLog -LogName $j -Source $j
        Write-EventLog -LogName $j -Source $j -EventId 1 -Message 'témoin exporté'
        wevtutil.exe epl $j "C:\Users\Public\$j.evtx" 2>&1 | Out-Null
        $f.N10 = Test-Path "C:\Users\Public\$j.evtx"
        $f
    }
    Start-Sleep 120
    $al = @(Alertes-Depuis $s $t0)
    $e4719 = Invoke-Command -Session $s -ArgumentList $t0 { param($t0) @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4719; StartTime = $t0.ToLocalTime() } -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Properties[0].Value)" }) -join ',' }
    foreach ($t in @(@('N-07', 'COR-R5', $faits.N07), @('N-08', 'COR-R3|COR-R3b', $faits.N08), @('N-09', 'COR-R7|BAS-001', $faits.N09), @('N-10', 'COR-R4', $faits.N10))) {
        $fp = @($al | Where-Object { $_.Regle -match "^($($t[1]))$" -and $_.Niveau -in 'Alerte', 'Critique' })
        $note = if (-not $t[2]) { 'D (activité non constatée)' } elseif ($fp.Count) { "FP ($($fp[0].Regle) $($fp[0].Niveau))" } else { 'conforme' }
        $detail = if ($t[0] -eq 'N-09') { "4719 : $e4719" } else { '' }
        $lignes.Add("$($t[0]);$n;;$(($fp | Select-Object -First 1).Regle);$(($fp | Select-Object -First 1).Niveau);;$note;$detail")
        Note "témoin $($t[0]), essai $n : $note $detail"
    }
    Remove-PSSession $s
}

Restore-VMSnapshot -VMSnapshot $inst -Confirm:$false
$lignes | Set-Content (Join-Path $sortie 's13-essais.csv') -Encoding UTF8
"configuration=$Configuration ; instantane=$($inst.Name) ; liste=v1.8 ; essais=$Essais ; temoins=$Temoins ; service_sha256=$script:empreinte ; sysmon=$script:sysmon" | Set-Content (Join-Path $sortie 's13-versions.txt') -Encoding UTF8
Note "fin de série ; résultats dans $sortie"
