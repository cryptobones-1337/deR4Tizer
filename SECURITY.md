# Security policy

deR4Tizer runs as a Windows service under the SYSTEM account. A flaw in it can let someone on the same computer gain
privileges, weaken Windows or Microsoft Defender settings, or hide an attack. Reports are welcome and treated seriously.

## Supported versions

Supported: the signed release v4.3 (first signed release, 2026-11-23) and the current `main` branch. Builds of 4.2
and 4.3 installed by hand before it are unsigned test builds: they do not update on their own and are not supported;
install the signed v4.3 instead.

## Reporting a vulnerability

Please report privately, never in a public issue:

- through GitHub's private vulnerability reporting: **Security** tab of this repository, then **Report a vulnerability**.

Include the version (or commit), the Windows version, what an attacker needs (standard account, administrator,
network access), the steps to reproduce, and the impact you observed. Please do not run tests against computers that
are not yours.

## What to expect

- Acknowledgement within 7 days.
- A first assessment (confirmed or not, severity) within 30 days.
- A fix in a signed release for confirmed flaws that let a standard account act with SYSTEM rights, weaken Windows or
  Defender, or disable detection; other confirmed flaws are fixed in a later release.
- Credit in the release notes if you wish.

## Scope

In scope: the service (`service-rs/`), the interface (`src/`), the installer (`installeur/`), the update mechanism and
the release workflow (`.github/workflows/publication.yml`). Out of scope: the third-party threat and filtering lists
themselves (report those to their authors), and findings that require an attacker who is already an administrator,
unless deR4Tizer makes their task easier.

The threat model is in [docs/security/threat-model.md](docs/security/threat-model.md).
