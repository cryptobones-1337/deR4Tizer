# Test de la capture des paquets (trafic, DPI, IDS, réseau local). Sans droits administrateur : lit les
# fichiers d'état du service. Envoie 3 paquets UDP contenant la chaîne de test de l'IDS (règle 9000000) vers
# 198.51.100.1, adresse réservée à la documentation (RFC 5737), jamais routée sur Internet.
$dossier = Join-Path $env:ProgramData 'deR4Tizer'
$udp = New-Object System.Net.Sockets.UdpClient
$charge = [Text.Encoding]::ASCII.GetBytes('test deR4Tizer-test-IDS-7f3a')
1..3 | ForEach-Object { [void]$udp.Send($charge, $charge.Length, '198.51.100.1', 9) }
$udp.Dispose()
try { Invoke-WebRequest -UseBasicParsing https://www.example.com -TimeoutSec 10 | Out-Null } catch { }
Start-Sleep -Seconds 8

function Lire($nom) { Get-Content (Join-Path $dossier $nom) -Raw -Encoding UTF8 | ConvertFrom-Json }
$ids = Lire 'ids.json'; $dpi = Lire 'dpi.json'; $trafic = Lire 'trafic.json'; $reseau = Lire 'reseau.json'
$test = @($ids.Detections | ForEach-Object { $_ } | Where-Object Sid -eq 9000000)
"IDS     : $($ids.Regles) règle(s), $($ids.PaquetsAnalyses) paquets analysés, test détecté : $(if ($test) { 'OUI' } else { 'non' })"
"DPI     : TLS $($dpi.SessionsTls), HTTP $($dpi.RequetesHttp), DNS $($dpi.RequetesDns) ; example.com vu en TLS : $(if (@($dpi.Tls | ForEach-Object { $_ } | Where-Object Nom -eq 'www.example.com')) { 'OUI' } else { 'non' })"
"Trafic  : reçu $($trafic.TotalEntrant) o, envoyé $($trafic.TotalSortant) o, $(@($trafic.Pays | ForEach-Object { $_ }).Count) pays, $($trafic.PlagesGeoip) plages GeoIP"
"Réseau  : interface $($reseau.Interface), passerelle $($reseau.Passerelle) ($($reseau.MacPasserelle)), $(@($reseau.Appareils | ForEach-Object { $_ }).Count) appareil(s)"
"Leurre  : $($reseau.ResultatLeurre)"
