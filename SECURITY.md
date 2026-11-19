# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's "Report a vulnerability" feature on this repository.
Do not open a public issue for security problems.

## Design principles

- Read-only by default; destructive actions must be opt-in and confirmed.
- No telemetry and no data leaves the machine.
- Updates come only from Microsoft sources and winget; the tool does not self-update silently.
- Minimal, readable code so it can be audited.

## Limitations

pc-guardian orchestrates Microsoft Defender and audits system state. It is not an antivirus engine and
cannot detect zero-day or well-hidden threats.
