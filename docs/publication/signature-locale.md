# Local signing of a release (block 1.1)

The code signing certificate (Certum, key kept in SimplySign) cannot be exported as a `.pfx`: the CI
builds, the maintainer's computer signs. Decisions of the maintainer of 2026-11-21:

| Question | Decision |
|---|---|
| Where the signed executables come from | From the "a-signer" artifact of the tag's "Publication" run (never a local build), downloaded by the script, its SHA-256 hash compared with the one GitHub gives for the artifact |
| Where the MSI is built | By the script, on the computer, after the executables are signed, from the exact sources of the tag |
| Who writes `manifeste.json` | The script, from the signed MSI |
| How the files reach the GitHub release | Draft created by the script (`gh release create --draft`); the maintainer reviews it and publishes it himself |
| Timestamp server | Certum (`http://time.certum.pl/`), DigiCert as fallback only |

## Prerequisites on the computer

- SimplySign Desktop connected (the certificate appears in the personal store);
- `gh` authenticated on the repository, `git`, Windows SDK (`signtool`);
- a clean copy of the repository.

## Procedure

1. Set the code version to the release number (`service-rs/Cargo.toml`, `service-rs/src/commun.rs`,
   `src/Commun.cs`) through a merged PR; the number must be strictly greater than any version already installed.
2. Create and push the `vX.Y` tag on this commit of `main`. The "Publication" run builds and uploads the
   "a-signer" artifact (kept 7 days). With no certificate in the CI, its "signer" job fails at the signature
   check and nothing is published: this is expected.
3. On the computer, in the copy of the repository:

   ```powershell
   git fetch --tags
   git checkout vX.Y
   .\signer-version.ps1 -Tag vX.Y -Empreinte <empreinte SHA-1 du certificat dans le magasin> -SansPublier
   ```

   `-SansPublier` is the dress rehearsal (block 1.2): everything is done and checked, nothing is published. The files and
   their SHA-256 hashes are in the working folder shown at the end (kept for review; delete it afterwards).
4. Same command without `-SansPublier`: the script creates the release draft with the four files
   (`deR4Tizer.msi`, `deR4TizerSvc.exe`, `deR4Tizer.exe`, `manifeste.json`), after checking that the GitHub tag
   points to the signed commit and checking the hashes again just before the upload; the working folder is then deleted.
5. Review the draft on GitHub (files, hashes shown by the script), then publish it
   ("Publish release").

## Rehearsal on a private copy (point 4 of the auditor's review of 2026-11-22)

Decision of the maintainer: the dress rehearsal uses up no version number of the public repository. It is done on
a private copy, with `-Depot`, the same script and the same certificate. The public repository receives neither tag nor draft.

1. Create an empty **private** repository on GitHub (for example `<compte>/deR4Tizer-repetition`). The Actions minutes of a
   private repository count against the account's free quota.
2. Define the repository variable `CLE_SIGNATURE` there, with the same value as on the public repository (Settings > Secrets and
   variables > Actions > Variables). No secret is needed.
3. In a separate clone (never the working copy of the public repository, so that the rehearsal tag does not get into it):

   ```powershell
   git clone https://github.com/cryptobones-1337/deR4Tizer.git deR4Tizer-repetition
   cd deR4Tizer-repetition
   git remote add repetition https://github.com/<compte>/deR4Tizer-repetition.git
   git push repetition main
   git tag vX.Y    # X.Y : la version du code de main (commun.rs), le tag doit lui être égal
   git push repetition vX.Y
   ```

   The copy's "Publication" run builds and uploads the "a-signer" artifact. Its "signer" job fails at the
   signature check (no certificate in the CI): this is expected.
4. Still in this clone, at the tag's commit:

   ```powershell
   .\signer-version.ps1 -Tag vX.Y -Empreinte <empreinte SHA-1 du certificat> -Depot <compte>/deR4Tizer-repetition -SansPublier
   ```

   All checks are made against the copy: run and artifact, `CLE_SIGNATURE`, compiled key (`cles-compilees.txt`
   found in the service), signatures, MSI, manifest (its addresses point to the copy, which is expected). Nothing is
   published. To rehearse the draft step as well, run again without `-SansPublier`: the draft is created on the private copy,
   to be deleted afterwards.
5. After the rehearsal: delete the tag and the draft from the copy (or the whole copy), delete the working folder
   shown by the script, and delete the clone.

## What the script checks, and where it stops

It stops at the first failed check, without publishing anything. After a stop, the working folder (shown at the
start, in `%TEMP%`) keeps the unsigned executables and the files already signed for diagnosis: delete it
afterwards.

- tag of the form `vX.Y` or `vX.Y.Z`, equal to the code version; copy of the repository at the tag's commit and clean;
- certificate key in `CLE_SIGNATURE` (only the key hash is shown, never the holder's name);
- "Publication" run of the tag on this commit, "compiler" job successful;
- "a-signer" artifact present, hash equal to GitHub's, exactly the two executables (unsigned) and
  `cles-compilees.txt`;
- certificate key equal to one of the keys compiled into the service: `cles-compilees.txt` (value of `CLE_SIGNATURE`
  given at build time) must be found as it is in `deR4TizerSvc.exe`, and contain the certificate key;
  otherwise the computers would refuse this version (auditor's review of 2026-11-22, point 3; `cles-compilees.ps1`,
  tested by `tests\test-cles-compilees.ps1`);
- WiX 3.14 archive checked by its hash; MSI built from a copy of the tag's sources (nothing is written
  to the repository);
- `verifier-signatures.ps1` on the three files: valid signature, timestamped, pinned key, chain and revocation;
- `ProductVersion` of the MSI equal to the tag's version (`version-msi.ps1`, tested by `tests\test-version-msi.ps1` on the
  MSI built by the CI);
- no GitHub release of this name exists yet.

## After publication

- Computers already equipped with a signed version install this one on their own (if automatic installation is enabled),
  after checking the signature and the pinned key.
- The first signed version is installed by hand; its package serves as rollback for the following ones.
- The current certificate expires on 2027-11-17: the next key must be pinned (`CLE_SIGNATURE`, two hashes)
  in a version distributed before that date (block 1.4).
