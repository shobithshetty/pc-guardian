# Supply-chain safety

pc-guardian runs on people's PCs, so a compromised dependency would reach all of them. This page lists what the
project trusts and how that trust is limited.

## What is pinned

| Dependency | How it is pinned |
|---|---|
| YARA program | Exact release and SHA-256 in `src/PcGuardian/data/pins.json`. A mismatch aborts the install. |
| YARA rules (`Neo23x0/signature-base`) | Exact commit plus a content hash of all rule files. A mismatch aborts the install. |
| ClamAV program | Installed separately by the user (winget). Not bundled. |
| ClamAV virus database | Downloaded by `freshclam`, which verifies the signed `.cvd` files itself. |
| CI actions | Referenced by full commit SHA, not by tag. |
| CI tooling (Pester, PSScriptAnalyzer) | Exact versions in `.github/workflows/ci.yml`. |

Nothing is fetched from a branch name or "latest".

## Updating a pin

Pins change only through a reviewed pull request:

1. Read the upstream diff between the old and new version.
2. Update `pins.json` with the new version, commit and hashes. Rule hashes come from `Get-RuleSetHash`.
3. Run the tests and `Install-GuardianScanner` against a scratch folder.
4. Merge only after review.

## What this does not protect against

- A rule set or program that was already malicious at the commit that was pinned.
- A compromised ClamAV signing key or a compromised GitHub account of this project's maintainer.
- False positives from third-party rules. A match means "look at this file".

## Reporting a problem

See [SECURITY.md](../SECURITY.md).
