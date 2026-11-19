# Architecture

## Flow

```
Invoke-GuardianRun
  ├─ Get-*Audit  (read-only collectors, each returns Finding objects)
  ├─ Load baseline (if none: save snapshot as baseline and stop)
  ├─ Compare-Baseline  → new / removed findings
  ├─ Get-FindingSeverity → Alert | Info per new finding
  └─ Write report (+ later: toast notification)
```

## Finding object

Every collector returns objects with three properties:

| Property   | Meaning                                              |
|------------|------------------------------------------------------|
| `Category` | `Defender`, `Startup`, `Task`, `Port`, `Account`     |
| `Key`      | Stable identity used for diffing (e.g. `Port:8001`)  |
| `Detail`   | Human-readable description                           |

Diffing compares `Category` + `Key`, so details can change without raising a false "new" alert.

## Data

Stored in `%LOCALAPPDATA%\PcGuardian` by default: `baseline.json`, `last-report.txt`.

## Threat model (short)

In scope: surfacing persistence mechanisms and exposed services that appear after the baseline.
Out of scope: malware detection (Defender's job), zero-days, a fully compromised or already-infected baseline.
**Run the first baseline on a machine you believe is clean.**
