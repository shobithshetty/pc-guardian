# Changelog

## Unreleased

- Installer: `/DLocalBuild` makes a personal build that defaults the install and data folders to F:
  (`pc-guardian-setup-<version>-local.exe`). The public build keeps the standard Windows defaults.
- Hiding-place checks in the baseline: background services, trusted root certificates (a user-installed one
  is an alert), hosts-file entries, and browser extensions. Existing baselines absorb these once on upgrade
  (`baseline-checks.json`) instead of reporting everything as new.
- Always reported until marked safe (never baselined): Defender exclusions, WMI event consumers, and browser
  extensions that combine all-sites access with cookies, web requests, native messaging or the debugger.
- Full scans also look for stolen-credential risks and pasted-command (ClickFix) traces: plain-text tokens in
  well-known files and `.env` files in your code folders (values never shown), SSH private keys without a
  passphrase, and suspicious commands in the Run box and PowerShell history.
- Optional package check against osv.dev, including known-malicious packages (package-lock.json and pinned
  requirements.txt in your code folders; sends only names and versions). Off by default; Settings has a
  code-folders list and the checkbox. `ConvertFrom-JsonDictionary` reads lockfiles with empty keys on 5.1 and 7.
- Scan-complete signals: a result card (green, amber or red) that stays until dismissed, a taskbar flash if the
  window is in the background, and a remembered "Last full scan" line in the footer.
- Data folder you can choose: the installer has a "Data folder" page (default: the standard Windows location).
  A custom choice is stored as the user environment variable `PCGUARDIAN_DATA`; the engine (`Get-GuardianDataPath`),
  the app, the scheduled scan and Settings all follow it. Settings shows the folder and can open it.
- Real percentage progress bars: downloads report percent from the file size (YARA program, rules, ClamAV
  database), and the ClamAV file scan counts files first, so the bar fills as the scan advances. New `percent`
  progress event; downloads use a streaming client (`Save-GuardianDownload`).
- The installer no longer downloads in a hidden step with no progress. Its box now means "set up virus scanning
  when pc-guardian first opens"; the app then does the downloads with its progress card.
- Logo and menus: a shield app icon (window, .exe, installer; regenerate with `tools/New-AppIcon.ps1` or replace
  `Assets/pc-guardian.ico`), and a File / View / Help menu bar.
- Settings window (File > Settings, Ctrl+,): daily scan on/off and time, optional VirusTotal (off by default) with
  the key stored encrypted, and the safe list with Remove. About window with credits and licenses.
- Engine: `Get-/Set-GuardianSetting`, `Get-GuardianDailyScan`, `Set-GuardianVirusTotalKey -Key/-Remove`.
  VirusTotal runs during full scans only when turned on in Settings.
- Automatic setup, no "Set up scanners" button: the installer offers (ticked) to install ClamAV and download the
  protection data; the app checks on launch (`Get-GuardianScannerStatus`) and shows a one-time "Download and scan"
  card only if something is missing. Downloads show numbered steps and the current item in the progress card.
- Downloads only when something is new: YARA and the rules record the pinned versions they installed
  (`installed.json`) and are skipped when current; the ClamAV database updates incrementally. The daily task
  refreshes the virus database before it scans, and the app refreshes a database older than 3 days before a full scan.
- Live scan progress: the engine streams phase, current file, file count and findings (`-Progress`, `PCG|` lines);
  ClamAV now reports every file it checks. The app shows "Step 2 of 5", the current item, elapsed time and a Cancel button.
- New modern window in WPF (rounded cards, vector shield, per-row Mark as safe, dark mode follows Windows).
  The old Windows Forms files (`MainForm.cs`, `Program.cs`) are excluded from the build and can be deleted.
- The scan task `pc-guardian` is no longer reported as a new scheduled task.
- Docs: `docs/VISION.md` (what the project is and is not, detector sources, roadmap) and `docs/ENGINE-HUB.md`
  (detector contract, progress protocol, curated update feed).
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
