# Code signing policy

Free code signing provided by [SignPath.io](https://signpath.io), certificate by
[SignPath Foundation](https://signpath.org). *(This sentence applies once the project is approved.
Until then, releases are unsigned and Windows SmartScreen may warn on first run.)*

## What is signed

- `PcGuardian.exe`, the Windows app, built from this repository.
- The PowerShell engine files shipped with the app.

Only builds made by the GitHub Actions workflow in `.github/workflows/release.yml`, from a tagged commit in
this repository, are submitted for signing. Nothing built on a developer's PC is signed.

## Roles

- **Author and approver:** the project maintainer. Every signing request is approved by a person.
- **Reviewers:** contributors' changes reach a release only through a reviewed pull request.

Accounts with signing or repository write access use multi-factor authentication.

## Privacy

The signed program does not send data anywhere on its own. Optional network features (updating scanners,
VirusTotal hash lookups) run only when the user starts them. See the [README](README.md).

## Third-party code

The app has no NuGet dependencies. The scanners it downloads (YARA, public rules, the ClamAV database) are
third-party and pinned by hash. See [docs/SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md). They are not signed by this project.

## Reporting a problem

See [SECURITY.md](SECURITY.md).
