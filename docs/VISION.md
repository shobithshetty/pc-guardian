# Vision and roadmap

## What pc-guardian is

One Windows app that brings the best free and open-source detection tools together, runs them on your PC on a
schedule or on demand, and shows their findings in one plain list. It keeps its detection data up to date
without the user having to find, install or understand each tool.

It is a **complement to Microsoft Defender, not a replacement**.

## What it is not

- **Not real-time protection.** Blocking a file the moment it launches needs a kernel-mode driver. That is a
  separate, high-risk project and is out of scope. pc-guardian scans on a schedule and on demand.
- **Not able to include commercial engines** such as McAfee. Only open-source or freely licensed detectors can join.
- **Not a guarantee.** It can miss threats and public rules can false-positive. A finding means "look at this".
- **Never destructive.** It reports. It does not delete or quarantine on its own.

Until real-time protection exists, the project calls itself a *security scanner*, not an antivirus.

## Principles

1. **Open and inspectable.** Everything is open source and readable.
2. **Trust is earned by pinning.** Nothing is fetched from a moving target. Every download is verified against a
   hash that a reviewed change put in the repository. See [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md).
3. **Measure before enabling.** Every new detector is tested for false positives on a clean PC before it ships on.
4. **Plain results.** One list, one severity scale, one "mark as safe". No tool-specific jargon on screen.
5. **Private by default.** Nothing leaves the PC unless the user turns on a feature that says what it sends.

## Detector sources to evaluate

Licences below are my understanding and **must be verified before any source is bundled or fetched**.

| Source | What it gives | Status |
|---|---|---|
| ClamAV | Signature scanning of files | In use (installed separately, GPL-2.0) |
| YARA + signature-base rules | Pattern rules for malware and tools | In use (Detection Rule License 1.1) |
| Microsoft Defender state | Is protection on, are definitions fresh | In use (read-only) |
| VirusTotal | Hash reputation lookups | In use, opt-in, bring your own key |
| Exposure checks | Risky Windows settings (SMBv1, RDP, UAC...) | In use |
| abuse.ch feeds (MalwareBazaar, URLhaus, ThreatFox) | Known-bad hashes, URLs, indicators | To evaluate (terms to verify) |
| Sigma rules | Suspicious activity in Windows event logs | To evaluate (licence to verify) |
| YARA Forge or other consolidated YARA sets | More rules, already de-duplicated | To evaluate (licence to verify) |
| capa | What a program is capable of doing | To evaluate (licence to verify) |
| Detect It Easy | Packer and file-type detection | To evaluate (licence to verify) |

## Roadmap

| Version | Goal |
|---|---|
| 0.1 | Audit and baseline diff, ClamAV, YARA, exposure checks, safe list, Windows app, installer |
| 0.2 | Live scan progress and cancel, modern window, first-run setup that installs the scanners for the user |
| 0.3 | Engine hub: detectors as plug-ins, one result format, per-detector on/off and statistics |
| 0.4 | Curated update feed: a signed manifest of reviewed, hash-pinned updates the app can check for |
| 0.5 | Evaluated new sources (hash feeds, Sigma) added one at a time, each with false-positive measurements |
| later | Quarantine on user request, scheduled reports, optional notifications |

## Success looks like

A person with no security background installs it, lets it run, and understands the result without help. A
reviewer can read the code and the pins and see exactly what it trusts.
