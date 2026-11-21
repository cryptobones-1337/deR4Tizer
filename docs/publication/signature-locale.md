# Signature locale d'une version (bloc 1.1)

Le certificat de signature de code (Certum, clé gardée dans SimplySign) ne peut pas être exporté en `.pfx` : la CI
compile, le poste du mainteneur signe. Décisions du mainteneur du 2026-11-21 :

| Question | Décision |
|---|---|
| D'où viennent les exécutables signés | De l'artefact « a-signer » de l'exécution « Publication » du tag (jamais une compilation locale), téléchargé par le script, son empreinte SHA-256 comparée à celle que GitHub donne pour l'artefact |
| Où le MSI est construit | Par le script, sur le poste, après la signature des exécutables, depuis les sources exactes du tag |
| Qui écrit `manifeste.json` | Le script, d'après le MSI signé |
| Comment les fichiers arrivent dans la version GitHub | Brouillon créé par le script (`gh release create --draft`) ; le mainteneur le relit et le publie lui-même |
| Serveur d'horodatage | Certum (`http://time.certum.pl/`), DigiCert en repli seulement |

## Prérequis sur le poste

- SimplySign Desktop connecté (le certificat apparaît dans le magasin personnel) ;
- `gh` authentifié sur le dépôt, `git`, Windows SDK (`signtool`) ;
- une copie du dépôt, propre.

## Procédure

1. Mettre la version du code au numéro de la version (`service-rs/Cargo.toml`, `service-rs/src/commun.rs`,
   `src/Commun.cs`) par une PR fusionnée ; le numéro doit être strictement supérieur à toute version déjà installée.
2. Créer et pousser le tag `vX.Y` sur ce commit de `main`. L'exécution « Publication » compile et dépose l'artefact
   « a-signer » (gardé 7 jours). Sans certificat dans la CI, son job « signer » échoue à la vérification des
   signatures et rien n'est publié : c'est attendu.
3. Sur le poste, dans la copie du dépôt :

   ```powershell
   git fetch --tags
   git checkout vX.Y
   .\signer-version.ps1 -Tag vX.Y -Empreinte <empreinte SHA-1 du certificat dans le magasin> -SansPublier
   ```

   `-SansPublier` est la répétition générale (bloc 1.2) : tout est fait et vérifié, rien n'est publié. Les fichiers et
   leurs empreintes SHA-256 sont dans le dossier de travail indiqué à la fin (gardé pour la relecture ; à effacer ensuite).
4. Même commande sans `-SansPublier` : le script crée le brouillon de version avec les quatre fichiers
   (`deR4Tizer.msi`, `deR4TizerSvc.exe`, `deR4Tizer.exe`, `manifeste.json`), après avoir vérifié que le tag de GitHub
   pointe sur le commit signé et revérifié les empreintes juste avant l'envoi ; le dossier de travail est ensuite effacé.
5. Relire le brouillon sur GitHub (fichiers, empreintes affichées par le script), puis le publier
   (« Publish release »).

## Ce que le script vérifie, et où il s'arrête

Il s'arrête à la première vérification en échec, sans rien publier :

- tag de la forme `vX.Y` ou `vX.Y.Z`, égal à la version du code ; copie du dépôt au commit du tag et propre ;
- clé du certificat dans `CLE_SIGNATURE` (seule l'empreinte de la clé est affichée, jamais le nom du titulaire) ;
- exécution « Publication » du tag sur ce commit, job « compiler » réussi ;
- artefact « a-signer » présent, empreinte égale à celle de GitHub, exactement les deux exécutables, non signés ;
- archive WiX 3.14 vérifiée par son empreinte ; MSI construit depuis une copie des sources du tag (rien n'est écrit
  dans le dépôt) ;
- `verifier-signatures.ps1` sur les trois fichiers : signature valide, horodatée, clé épinglée, chaîne et révocation ;
- `ProductVersion` du MSI égale à la version du tag ;
- aucune version GitHub de ce nom n'existe déjà.

## Après la publication

- Les postes déjà équipés d'une version signée installent celle-ci seuls (si l'installation automatique est activée),
  après avoir vérifié la signature et la clé épinglée.
- La première version signée s'installe à la main ; son paquet sert de retour arrière aux suivantes.
- Le certificat actuel expire le 2027-11-17 : la clé suivante doit être épinglée (`CLE_SIGNATURE`, deux empreintes)
  dans une version distribuée avant cette date (bloc 1.4).
