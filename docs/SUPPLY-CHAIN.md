# Supply-chain safety

pc-guardian runs on people's PCs, so a compromised dependency would reach all of them. This page lists what the
project trusts and how that trust is limited.

## What is pinned

| Dependency | How it is pinned |
|---|---|
| YARA program | Exact release and SHA-256 in `src/PcGuardian/data/pins.json`. A mismatch aborts the install. |
| YARA rules (`Neo23x0/signature-base`) | Exact commit plus a content hash of all rule files. A mismatch aborts the install. |
| Hayabusa (event-log hunting, AGPL-3.0, run as a separate program) and its bundled rules | Exact release and SHA-256 in `pins.json`. A mismatch installs nothing. |
| HollowsHunter (injected-code scan, BSD-2) | Exact release and SHA-256 in `pins.json`. Run with options that write, kill and suspend nothing. |
| LOLDrivers list (vulnerable drivers, Apache-2.0) | Data only, compared against driver hashes and never run. It changes as drivers are added, so it is not pinned by hash: it is size-capped, shape-checked and refreshed weekly. |
| ClamAV program | Installed separately by the user (winget). Not bundled. |
| ClamAV virus database | Downloaded by `freshclam`, which verifies the signed `.cvd` files itself. |
| CI actions | Referenced by full commit SHA, not by tag. |
| Inno Setup (builds the installer in CI) | Exact release URL and SHA-256 in `.github/workflows/release.yml`. A mismatch fails the build. |
| NuGet packages (Windows app) | None. The app uses only the .NET 8 framework. |
| CI tooling (Pester, PSScriptAnalyzer) | Exact versions in `.github/workflows/ci.yml`. |

Nothing is fetched from a branch name or "latest".

## Updating a pin

Pins change only through a reviewed pull request:

1. Read the upstream diff between the old and new version.
2. Update `pins.json` with the new version, commit and hashes. Rule hashes come from `Get-RuleSetHash`.
3. Run the tests and `Install-GuardianScanner` against a scratch folder.
4. Merge only after review.

## Staying current without trusting automation

Threats change daily, so the project watches for new versions, but **automation only finds and proposes; a person
approves every change to what the tool trusts.**

| What | How it stays current | Who decides |
|---|---|---|
| ClamAV virus database | Refreshed by `freshclam` (signature-checked by ClamAV) before the daily scan | Automatic, no code change |
| YARA, rules, Inno Setup | `tools/Check-Pins.ps1` runs daily in `.github/workflows/pin-watch.yml` and opens or updates one issue with the new versions, the upstream diff link and the hashes to pin | A person reviews the diff, then edits the pins in a pull request |
| GitHub Actions | Dependabot opens weekly pull requests | A person reviews and merges |
| Known-exploited list | Public CISA file, cached for a day, used only when the person turns it on | Informational only |
| Threat news | A daily briefing report for the maintainer (see below) | A person reads it |

**Daily briefing.** A scheduled task on the maintainer's PC searches for the day's breaches, malware campaigns and
supply-chain attacks and writes a short report saying whether pc-guardian should change. It is report-only. Web
pages are untrusted text: the task is told to treat them as data, never to run anything it reads, and never to edit
the project. Any detection idea it proposes goes through the normal review, testing and pinning steps.

## What this does not protect against

- A rule set or program that was already malicious at the commit that was pinned.
- A compromised ClamAV signing key or a compromised GitHub account of this project's maintainer.
- False positives from third-party rules. A match means "look at this file".

## Reporting a problem

See [SECURITY.md](../SECURITY.md).
