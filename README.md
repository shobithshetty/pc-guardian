# pc-guardian

A small, open-source Windows tool that keeps your PC's security routine running on autopilot.

It **orchestrates** what Windows already provides (Microsoft Defender, winget, Windows Update) and adds an
**audit layer** Defender does not cover: startup items, scheduled tasks, listening ports and admin accounts.

> pc-guardian is **not** an antivirus engine and does not replace Defender. It cannot catch zero-days.
> It reports; it never deletes or quarantines anything on its own.

## What it does

1. **Audit** (v0.1): snapshot Defender state, startup items, non-Microsoft scheduled tasks, listening ports, local admins.
2. **Baseline and diff** (v0.2): the first run is saved as a baseline; later runs flag only what is new.
3. **Update and scan** (v0.3): refresh Defender signatures, upgrade apps via winget, run scheduled Defender scans.
4. **Schedule and alert** (v0.4): a scheduled task plus a toast notification when something needs attention.

## Status

Early development. v0.1 is a read-only audit with baseline comparison. Releases are unsigned until v1.0.

## Quick start

```powershell
Import-Module .\src\PcGuardian\PcGuardian.psd1 -Force
Invoke-GuardianRun
```

The first run creates a baseline. Run it again later to see what changed.

## Privacy and safety

- Everything stays on your machine. No telemetry. The audit makes no network calls.
- Optional network features are off by default: `-CheckUpdates` (winget sources) and `-VirusTotal`
  (sends only file SHA-256 hashes to virustotal.com, never files or paths).
- Read-only by default. Nothing is removed, quarantined or disabled.
- Data is stored in `%LOCALAPPDATA%\PcGuardian` (override with `-DataPath`).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [SECURITY.md](SECURITY.md).

## Support the project

pc-guardian is free and always will be. If it saved you time or worried you less, you can chip in via
the Sponsor button on this repository (GitHub Sponsors, Ko-fi or Buy Me a Coffee). Donations are optional
and unlock nothing. Bug reports, rule feedback and false-positive reports help just as much.

The tool prints one short support line after a run. Silence it with `Invoke-GuardianRun -NoDonateNote`.

## License

MIT
