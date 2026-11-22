# Changelog

## Unreleased

- Windows installer (`installer/pc-guardian.iss`, Inno Setup): Start menu entry, optional desktop shortcut,
  optional daily 2:00 AM scan task, clean uninstall, .NET 8 Desktop Runtime check. The release workflow builds it
  in CI with Inno Setup pinned by SHA-256.
- `installer/Install.ps1` registers or removes the daily scan task for the installed layout.
- Windows app (`app/PcGuardian.App`, C# / Windows Forms, no NuGet packages): a regular window with status,
  findings list, Scan now, Mark as safe, and Set up scanners. It runs the PowerShell engine as a child process.
- Safe list: `Add-/Get-/Remove-GuardianSafeItem` and `Invoke-GuardianRun -AsObject`. Malware cannot be marked safe.
- Release workflow (tag `v*`): CI-only build, optional SignPath signing, SHA-256 checksum, build provenance.
  `CODE_SIGNING_POLICY.md` added for the SignPath application.
- `Install-GuardianScanner` downloads ClamAV definitions, YARA and public rules. YARA and the rule set are pinned
  to an exact version, commit and hash in `data/pins.json`; a mismatch installs nothing. See docs/SUPPLY-CHAIN.md.
- CI: actions pinned to a commit SHA, tooling pinned to exact versions, read-only token, and a Windows PowerShell 5.1 job.
- Fix: the saved baseline was read as a single item on Windows PowerShell 5.1, so every run reported everything as new.

- Optional support note after each run (`-NoDonateNote` hides it) and a `.github/FUNDING.yml` template.
- Opt-in VirusTotal reputation lookup (`Invoke-GuardianRun -VirusTotal`): sends only the SHA-256 of recent,
  unsigned executables, caches results by hash, and needs a key stored encrypted by `Set-GuardianVirusTotalKey`.
  Three or more engines must flag a file before it becomes a finding.
- YARA scan (`Invoke-GuardianRun -Scan`, alongside ClamAV): runs a pre-compiled public rule set from
  `%LOCALAPPDATA%\PcGuardian\yara`. Rule files that depend on Loki-style externals (filename, filepath,
  extension, filetype, owner) are excluded, because without real values they false-positive.
- Exposure check: offline config audit (SMBv1, UAC, RDP, auto-logon, firewall profiles, Guest account,
  Defender real-time and signature age, stale Windows updates). Reported on every run, never baselined.
- `Invoke-GuardianRun -CheckUpdates` lists apps with newer winget versions (read-only; needs network).
- ClamAV second-engine scan (`Invoke-GuardianRun -Scan`): scans Downloads, Temp, Startup folders and
  startup/task executables. Read-only. Definitions are stored in `%LOCALAPPDATA%\PcGuardian\clamav-db`.
  Detections are never baselined. Files Defender blocks are reported too.
- Initial scaffold: module layout, read-only audits (Defender, startup, scheduled tasks, ports, admins),
  baseline snapshot and diff, CI, Pester tests.
