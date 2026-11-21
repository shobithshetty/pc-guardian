# Changelog

## Unreleased

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
