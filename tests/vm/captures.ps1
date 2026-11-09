# Captures réelles de l'interface (phase « Interface et assistant d'installation », U0 : docs/roadmap/interface.md), dans
# la VM de test (jamais sur un poste réel). Installe le service, le laisse tourner quelques cycles, puis ouvre chaque page
# de l'interface installée (--page), en français puis en anglais, et enregistre la fenêtre en PNG dans la sortie du
# scénario. Les captures servent de référence avant la refonte : elles ne sont pas publiées dans le dépôt.
#
# Il faut une session interactive à la console (celle de l'instantané) : sans bureau, la capture serait noire, et le
# scénario le dit (NON EXÉCUTÉ) au lieu de rendre des images vides. Mise à l'échelle : celle de la session (relevée) ;
# 125 et 150 % demandent de rouvrir la session, prévu avec le pilote (U1).
#
# Lancé dans la VM par tests\vm\lancer.ps1 -Scenario captures (exécuteur tests\bac-a-sable\executer.ps1).
param(
    [Parameter(Mandatory)] [string]$Msi,
    [Parameter(Mandatory)] [string]$Sortie,
    [int]$Minutes = 3,
    [string]$Journaux = (Join-Path $env:RUNNER_TEMP 'journaux-msi')
)
. (Join-Path $PSScriptRoot '..\integration\commun.ps1')
New-Item -ItemType Directory -Force -Path $Journaux | Out-Null
$dossierCaptures = Join-Path $Sortie 'captures'
New-Item -ItemType Directory -Force -Path $dossierCaptures | Out-Null

Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Drawing;
using System.Runtime.InteropServices;
public static class D4tCapture
{
    [StructLayout(LayoutKind.Sequential)] struct RECT { public int G, H, D, B; }
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint options);
    [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr h, int n);
    [DllImport("user32.dll")] static extern int GetDpiForWindow(IntPtr h);
    [DllImport("user32.dll")] static extern IntPtr GetThreadDesktop(uint id);
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern bool GetUserObjectInformation(IntPtr h, int index, System.Text.StringBuilder info, int len, out int needed);
    public static void Pixels() { SetProcessDPIAware(); }
    // Bureau de ce fil : « Default » dans une session interactive ; autre chose (ou rien) sans bureau visible
    [DllImport("user32.dll")] static extern IntPtr GetProcessWindowStation();
    [DllImport("kernel32.dll")] static extern bool ProcessIdToSessionId(uint pid, out uint session);
    [DllImport("kernel32.dll")] static extern uint GetCurrentProcessId();
    [DllImport("kernel32.dll")] static extern uint WTSGetActiveConsoleSessionId();
    static string Nom(IntPtr objet)
    {
        var sb = new System.Text.StringBuilder(256); int n;
        return GetUserObjectInformation(objet, 2, sb, 512, out n) ? sb.ToString() : "";
    }
    public static string Bureau() { return Nom(GetThreadDesktop(GetCurrentThreadId())); }
    public static string Station() { return Nom(GetProcessWindowStation()); }
    public static uint Session() { uint s; return ProcessIdToSessionId(GetCurrentProcessId(), out s) ? s : uint.MaxValue; }
    public static uint SessionConsole() { return WTSGetActiveConsoleSessionId(); }
    // Bureau visible : station interactive WinSta0, bureau Default, et session du processus = session de la console.
    // Toute station non interactive a aussi un bureau « Default » (relecture de #132, D1)
    public static bool Interactif() { return Station() == "WinSta0" && Bureau() == "Default" && Session() == SessionConsole(); }
    public static int Dpi(IntPtr h) { try { return GetDpiForWindow(h); } catch { return 0; } }
    // PrintWindow avec PW_RENDERFULLCONTENT (2) : la fenêtre est rendue même si une autre la recouvre
    public static Bitmap Fenetre(IntPtr h)
    {
        ShowWindow(h, 9); SetForegroundWindow(h);
        RECT r; if (!GetWindowRect(h, out r)) return null;
        int l = r.D - r.G, ht = r.B - r.H;
        if (l <= 0 || ht <= 0) return null;
        var b = new Bitmap(l, ht);
        using (var g = Graphics.FromImage(b)) { IntPtr dc = g.GetHdc(); try { PrintWindow(h, dc, 2); } finally { g.ReleaseHdc(dc); } }
        return b;
    }
    // Pilote WPF (U1) : PrintWindow ne rend pas la composition WPF + WindowsFormsHost. La fenêtre est mise au premier plan
    // et sa zone est copiée depuis l'écran de la VM (jamais un poste réel : ce script ne tourne que dans la VM de test)
    public static Bitmap Ecran(IntPtr h)
    {
        ShowWindow(h, 9); SetForegroundWindow(h);
        System.Threading.Thread.Sleep(800);
        RECT r; if (!GetWindowRect(h, out r)) return null;
        int l = r.D - r.G, ht = r.B - r.H;
        if (l <= 0 || ht <= 0) return null;
        var b = new Bitmap(l, ht);
        using (var g = Graphics.FromImage(b)) g.CopyFromScreen(r.G, r.H, 0, 0, new Size(l, ht));
        return b;
    }
    // Part des pixels d'une seule couleur : une capture sans bureau est uniforme (noire)
    public static double Uniforme(Bitmap b)
    {
        var c0 = b.GetPixel(b.Width / 2, b.Height / 2); int pareils = 0, total = 0;
        for (int x = 0; x < b.Width; x += 7) for (int y = 0; y < b.Height; y += 7) { total++; if (b.GetPixel(x, y) == c0) pareils++; }
        return total == 0 ? 1 : (double)pareils / total;
    }
}
'@ -ReferencedAssemblies System.Drawing
[D4tCapture]::Pixels()

# Pages de la navigation, par leur clé française (--page accepte la clé dans les deux langues)
$pages = 'Connexions', 'Trafic', 'Alertes', 'Incidents', 'Événements', 'Détection', 'Réseau local', 'Chaînes', 'Vie privée',
    'Pare-feu', 'Démarrage auto', 'Baseline', 'Extensions', 'Blocages', 'Quarantaine', 'Réponses en cours', 'Menaces', 'Santé', 'Réglages'
$exe = Join-Path $script:Programme 'deR4Tizer.exe'

# Nom de fichier sans accent ni espace
function Nom-Fichier([string]$Texte) {
    $t = $Texte.Normalize([Text.NormalizationForm]::FormD) -replace '\p{Mn}', ''
    ($t -replace '[^A-Za-z0-9]+', '-').Trim('-').ToLowerInvariant()
}

function Arreter-Interface { Get-Process deR4Tizer -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep 1 }

# Langue de l'interface : réglages envoyés au service (config.json, que l'interface lit au démarrage)
function Langue([string]$Code) {
    # Juste après l'installation, config.json n'existe pas encore : réglages partiels, les autres champs gardent leur
    # valeur par défaut (serde, côté service)
    $f = Join-Path $script:Donnees 'config.json'
    $cfg = if (Test-Path $f) { Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json } else { [pscustomobject]@{ Langue = $Code } }
    $cfg.Langue = $Code
    $r = Commande (@{ Action = 'reglages'; Valeur = ($cfg | ConvertTo-Json -Depth 8 -Compress) } | ConvertTo-Json -Compress) 30000 | ConvertFrom-Json
    if (-not $r.Ok) { throw "réglage de la langue refusé : $($r.Message)" }
}

$installe = $false
Verifier 'Installation' {
    $c = Installer $Msi (Join-Path $Journaux 'installation-captures.log')
    if ($c -ne 0) { return "msiexec a rendu $c" }
    if (-not (Attendre-Canal)) { return "le service ne répond pas ; journal : $(Journal 'erreur')" }
    $script:installe = $true
    $true
}

$poste = "station « $([D4tCapture]::Station()) », bureau « $([D4tCapture]::Bureau()) », session $([D4tCapture]::Session()), session de la console $([D4tCapture]::SessionConsole())"
"$poste ; compte : $([Security.Principal.WindowsIdentity]::GetCurrent().Name)" | Set-Content (Join-Path $dossierCaptures 'session.txt') -Encoding UTF8
if (-not $installe) {
    NonExecute 'Captures' 'installation en échec'
} elseif (-not [D4tCapture]::Interactif()) {
    NonExecute 'Captures' "pas de bureau visible à la console ($poste) : il faut une session ouverte à la console"
} else {
    # Quelques cycles de surveillance : les pages montrent l'état réel d'une première ouverture
    Start-Sleep ($Minutes * 60)
    $index = New-Object System.Collections.Generic.List[string]
    foreach ($code in 'fr', 'en') {
        $okLangue = $true
        Verifier "Langue $code envoyée au service" { try { Langue $code; $true } catch { $script:okLangue = $false; $_.Exception.Message } }
        if (-not $okLangue) { continue }
        foreach ($page in $pages) {
            Verifier "Capture $code : $page" {
                Arreter-Interface
                $p = Start-Process $exe -ArgumentList '--page', "`"$page`"" -PassThru
                $fin = (Get-Date).AddSeconds(30)
                while ($p.MainWindowHandle -eq [IntPtr]::Zero -and -not $p.HasExited -and (Get-Date) -lt $fin) { Start-Sleep -Milliseconds 300; $p.Refresh() }
                if ($p.HasExited) { return "l'interface s'est fermée (code $($p.ExitCode))" }
                if ($p.MainWindowHandle -eq [IntPtr]::Zero) { return 'aucune fenêtre en 30 s' }
                # Rendu et premier rafraîchissement
                Start-Sleep 5
                $b = [D4tCapture]::Fenetre($p.MainWindowHandle)
                if (-not $b) { return 'fenêtre illisible' }
                try {
                    $u = [D4tCapture]::Uniforme($b)
                    if ($u -gt 0.98) { return "capture uniforme ($([math]::Round($u * 100)) % d'une seule couleur) : bureau non rendu" }
                    $f = Join-Path $dossierCaptures ("$code-" + (Nom-Fichier $page) + '.png')
                    $b.Save($f, [Drawing.Imaging.ImageFormat]::Png)
                    $script:index.Add("$code | $page | $([IO.Path]::GetFileName($f)) | $($b.Width) x $($b.Height) | $([D4tCapture]::Dpi($p.MainWindowHandle)) ppp")
                } finally { $b.Dispose() }
                $true
            }
        }
    }
    # Pilote de la refonte (U1) : même service, mêmes langues, coquille WPF ouverte par --fluent, Vue d'ensemble comprise
    foreach ($code in 'fr', 'en') {
        $okLangue = $true
        Verifier "Pilote, langue $code envoyée au service" { try { Langue $code; $true } catch { $script:okLangue = $false; $_.Exception.Message } }
        if (-not $okLangue) { continue }
        foreach ($page in @("Vue d'ensemble") + $pages) {
            Verifier "Capture du pilote $code : $page" {
                Arreter-Interface
                $p = Start-Process $exe -ArgumentList '--fluent', '--page', "`"$page`"" -PassThru
                $fin = (Get-Date).AddSeconds(30)
                while ($p.MainWindowHandle -eq [IntPtr]::Zero -and -not $p.HasExited -and (Get-Date) -lt $fin) { Start-Sleep -Milliseconds 300; $p.Refresh() }
                if ($p.HasExited) { return "le pilote s'est fermé (code $($p.ExitCode))" }
                if ($p.MainWindowHandle -eq [IntPtr]::Zero) { return 'aucune fenêtre en 30 s' }
                Start-Sleep 5
                $b = [D4tCapture]::Ecran($p.MainWindowHandle)
                if (-not $b) { return 'fenêtre illisible' }
                try {
                    $u = [D4tCapture]::Uniforme($b)
                    if ($u -gt 0.98) { return "capture uniforme ($([math]::Round($u * 100)) % d'une seule couleur) : bureau non rendu" }
                    $f = Join-Path $dossierCaptures ("pilote-$code-" + (Nom-Fichier $page) + '.png')
                    $b.Save($f, [Drawing.Imaging.ImageFormat]::Png)
                    $script:index.Add("pilote $code | $page | $([IO.Path]::GetFileName($f)) | $($b.Width) x $($b.Height) | $([D4tCapture]::Dpi($p.MainWindowHandle)) ppp")
                } finally { $b.Dispose() }
                $true
            }
        }
    }
    Arreter-Interface
    (@('langue | page | fichier | taille | résolution') + $index) | Set-Content (Join-Path $dossierCaptures 'index.txt') -Encoding UTF8
}

if ($installe) {
    Verifier 'Désinstallation' {
        Arreter-Interface
        $c = Desinstaller (Join-Path $Journaux 'desinstallation-captures.log')
        if ($c -ne 0) { return "msiexec a rendu $c" }
        $true
    }
}
Bilan 'Captures réelles de l''interface (U0)'
