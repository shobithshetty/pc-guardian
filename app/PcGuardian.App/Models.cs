namespace PcGuardian.App;

/// <summary>One row of the results list. Mirrors the objects Invoke-GuardianRun -AsObject returns.</summary>
public sealed class FindingItem
{
    public string Kind { get; set; } = "";      // New, Removed, Scan, Exposed
    public string Severity { get; set; } = "";  // Alert or Info
    public string Category { get; set; } = "";
    public string Key { get; set; } = "";
    public string Detail { get; set; } = "";

    public bool IsMalware => Category == "Malware";
    public bool IsAlert => Severity == "Alert";
    public bool CanMarkSafe => !IsMalware;

    /// <summary>The label and colour class of the pill on the row: Threat, Alert or Info.</summary>
    public string Level => IsMalware ? "Threat" : IsAlert ? "Alert" : "Info";
}

public sealed class RunResult
{
    public string Generated { get; set; } = "";
    public bool FirstRun { get; set; }
    public int BaselineCount { get; set; }
    public List<FindingItem> Items { get; set; } = new();
}

/// <summary>What Get-GuardianScannerStatus reports: are the scanners and their data in place?</summary>
public sealed class ScannerStatus
{
    public bool ClamAvInstalled { get; set; }
    public bool DatabaseReady { get; set; }
    public int? DatabaseAgeDays { get; set; }
    public bool YaraReady { get; set; }
    public bool Ready { get; set; }

    /// <summary>True when the virus database is older than the daily refresh should allow.</summary>
    public bool IsStale => DatabaseAgeDays is >= 3;

    public string Summary =>
        !Ready ? "Protection data has not been downloaded yet"
        : DatabaseAgeDays is null or 0 ? "Protection data updated today"
        : DatabaseAgeDays == 1 ? "Protection data updated yesterday"
        : $"Protection data updated {DatabaseAgeDays} days ago";
}

/// <summary>Get-GuardianSetting: the options saved in Settings.</summary>
public sealed class AppSettings
{
    public bool VirusTotal { get; set; }
    public bool VirusTotalKeySet { get; set; }
    public bool Osv { get; set; }
    public List<string> DevFolders { get; set; } = new();
}

/// <summary>Get-GuardianDailyScan: the scheduled daily scan task.</summary>
public sealed class DailyScanInfo
{
    public bool Exists { get; set; }
    public bool Enabled { get; set; }
    public string? At { get; set; }
}

/// <summary>One entry on the safe list.</summary>
public sealed class SafeItem
{
    public string Key { get; set; } = "";
    public string Added { get; set; } = "";
}

/// <summary>One live progress line from the engine: phase, file, count or found.</summary>
public sealed record ProgressEvent(string Type, string Value);
