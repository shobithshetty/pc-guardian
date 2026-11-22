# Engine hub design

How new detectors and updates plug in without rewriting the app. This is a design, not yet code.
Today's detectors are called directly from `Invoke-GuardianRun`; version 0.3 moves them behind one contract.

## Detector contract

A detector is a small PowerShell function plus a manifest. It is read-only and returns findings only.

```
Manifest (detectors/<name>.json)
  name          clamav
  version       1
  needs         ["ClamAV program", "virus database"]
  network       false            # does a scan itself ever use the network?
  cost          heavy            # light | heavy, so the app can order and cancel
  sources       [ pinned data this detector depends on ]

Function  Invoke-<Name>Detector -Targets <paths> -Report <progress callback>
  returns   findings:  Category, Key, Detail, Severity (Alert | Info), Evidence (optional)
```

Rules every detector follows:

1. **Read-only.** It never modifies, quarantines or deletes.
2. **Streams progress** through the callback: phase, current item, items done. No silent long waits.
3. **Cancellable.** It stops promptly when asked.
4. **Reports why it did nothing.** A missing tool or database is an Info finding, never a silent "clean".
5. **Never baselined.** Malware findings are always reported, never absorbed into "normal".

## One result format

Every detector returns the same finding shape, so the window needs no tool-specific code. The app shows the
detector name next to each finding and lets the user switch detectors on or off.

## Progress protocol

The engine writes one line per event to standard output, and the app reads them as they arrive:

```
PCG|phase|<n>|<total>|<name>        a new step began (for example 3 of 6, "ClamAV scan")
PCG|file|<path>                      the item being examined now
PCG|count|<items done>               running total for the current step
PCG|found|<json finding>             a finding, shown in the list immediately
```

The final structured result is still printed as one JSON document. Lines that start with `PCG|` are progress;
everything else is the result. Values are never inserted into a command line.

## Update feed (version 0.4)

Detectors depend on data that changes: signatures, rules, indicator lists. The app does not pull these from
arbitrary repositories. Instead:

1. The project publishes a **feed manifest**: for each source, an exact version or commit, the download URL,
   its SHA-256, its licence and the review date.
2. The manifest is **signed** by the project. The app refuses an unsigned or altered manifest.
3. The app checks the manifest, shows "updates available", and downloads only what the manifest names.
4. Each download is verified against the manifest hash before it is used. A mismatch installs nothing.
5. Every manifest change goes through a reviewed pull request that includes a **false-positive measurement**
   on a clean machine for any new or changed rule source.

This keeps updates automatic for the user while keeping every update a reviewed, reproducible change.

## What can go wrong

- A source is compromised before we pin it. Pinning limits damage after the fact, not before. Review the diff.
- A new source floods users with false positives. Measure first, ship switched off if unsure.
- Licence terms forbid redistribution or fetching. Verify every licence before adding a source.
- Too many detectors make scans slow. Order by cost, allow cancel, and let users turn detectors off.
