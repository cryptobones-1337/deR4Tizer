// Action personnalisee LireDossierDonnees du paquet (installeur\deR4Tizer.wxs ; audit du 2026-11-23, C-1).
// Fichier en ASCII seulement : il est lu par le moteur JScript de Windows Installer, sans indication d'encodage.
// Lecture seule : lit les attributs de C:\ProgramData\deR4Tizer, n'ecrit rien, ne lance rien. DonneesEtat vaut "ok"
// si le dossier est absent ou n'est pas un point d'analyse, "lien" s'il en est un (jonction, lien symbolique :
// FILE_ATTRIBUTE_REPARSE_POINT, 1024), "inconnu" ou "illisible" sinon ; la condition de lancement n'accepte que
// "ok" (echec ferme).
function LireDossierDonnees() {
    Session.Property("DonneesEtat") = "inconnu";
    try {
        var chemin = Session.Property("CommonAppDataFolder") + "deR4Tizer";
        var fso = new ActiveXObject("Scripting.FileSystemObject");
        var element = fso.FolderExists(chemin) ? fso.GetFolder(chemin) : (fso.FileExists(chemin) ? fso.GetFile(chemin) : null);
        Session.Property("DonneesEtat") = element === null ? "ok" : ((element.Attributes & 1024) !== 0 ? "lien" : "ok");
    } catch (e) {
        Session.Property("DonneesEtat") = "illisible";
    }
    // msiDoActionStatusSuccess : la decision est portee par DonneesEtat, pas par le code de retour
    return 1;
}
