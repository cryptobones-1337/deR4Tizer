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

## Répétition sur une copie privée (point 4 de la revue de l'auditeur du 2026-11-22)

Décision du mainteneur : la répétition générale ne consomme aucun numéro de version du dépôt public. Elle se fait sur
une copie privée, avec `-Depot`, le même script et le même certificat. Le dépôt public ne reçoit ni tag ni brouillon.

1. Créer sur GitHub un dépôt **privé** vide (par exemple `<compte>/deR4Tizer-repetition`). Les minutes d'Actions d'un
   dépôt privé sont décomptées du quota gratuit du compte.
2. Y définir la variable de dépôt `CLE_SIGNATURE`, avec la même valeur que sur le dépôt public (Settings > Secrets and
   variables > Actions > Variables). Aucun secret n'est nécessaire.
3. Dans un clone à part (jamais la copie de travail du dépôt public, pour que le tag de répétition n'y entre pas) :

   ```powershell
   git clone https://github.com/cryptobones-1337/deR4Tizer.git deR4Tizer-repetition
   cd deR4Tizer-repetition
   git remote add repetition https://github.com/<compte>/deR4Tizer-repetition.git
   git push repetition main
   git tag vX.Y    # X.Y : la version du code de main (commun.rs), le tag doit lui être égal
   git push repetition vX.Y
   ```

   L'exécution « Publication » de la copie compile et dépose l'artefact « a-signer ». Son job « signer » échoue à la
   vérification des signatures (aucun certificat dans la CI) : c'est attendu.
4. Toujours dans ce clone, au commit du tag :

   ```powershell
   .\signer-version.ps1 -Tag vX.Y -Empreinte <empreinte SHA-1 du certificat> -Depot <compte>/deR4Tizer-repetition -SansPublier
   ```

   Toutes les vérifications sont faites contre la copie : exécution et artefact, `CLE_SIGNATURE`, clé compilée (`cles-compilees.txt`
   retrouvé dans le service), signatures, MSI, manifeste (ses adresses pointent vers la copie, ce qui est attendu). Rien n'est
   publié. Pour répéter aussi l'étape du brouillon, relancer sans `-SansPublier` : le brouillon est créé sur la copie privée,
   à supprimer ensuite.
5. Après la répétition : supprimer le tag et le brouillon de la copie (ou la copie entière), effacer le dossier de travail
   indiqué par le script, et supprimer le clone.

## Ce que le script vérifie, et où il s'arrête

Il s'arrête à la première vérification en échec, sans rien publier. Après un arrêt, le dossier de travail (indiqué au
début, dans `%TEMP%`) garde les exécutables non signés et les fichiers déjà signés pour le diagnostic : l'effacer
ensuite.

- tag de la forme `vX.Y` ou `vX.Y.Z`, égal à la version du code ; copie du dépôt au commit du tag et propre ;
- clé du certificat dans `CLE_SIGNATURE` (seule l'empreinte de la clé est affichée, jamais le nom du titulaire) ;
- exécution « Publication » du tag sur ce commit, job « compiler » réussi ;
- artefact « a-signer » présent, empreinte égale à celle de GitHub, exactement les deux exécutables (non signés) et
  `cles-compilees.txt` ;
- clé du certificat égale à l'une des clés compilées dans le service : `cles-compilees.txt` (valeur de `CLE_SIGNATURE`
  donnée à la compilation) doit se retrouver telle quelle dans `deR4TizerSvc.exe`, et contenir la clé du certificat ;
  sinon les postes refuseraient cette version (revue de l'auditeur du 2026-11-22, point 3 ; `cles-compilees.ps1`,
  testé par `tests\test-cles-compilees.ps1`) ;
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
