# Changelog

## Unreleased

- ClamAV second-engine scan (`Invoke-GuardianRun -Scan`): scans Downloads, Temp, Startup folders and
  startup/task executables. Read-only. Definitions are stored in `%LOCALAPPDATA%\PcGuardian\clamav-db`.
  Detections are never baselined. Files Defender blocks are reported too.
- Initial scaffold: module layout, read-only audits (Defender, startup, scheduled tasks, ports, admins),
  baseline snapshot and diff, CI, Pester tests.
