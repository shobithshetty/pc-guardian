namespace PcGuardian.App;

/// <summary>One line of the results list. Mirrors the objects Invoke-GuardianRun -AsObject returns.</summary>
public sealed class FindingItem
{
    public string Kind { get; set; } = "";      // New, Removed, Scan, Exposed
    public string Severity { get; set; } = "";  // Alert or Info
    public string Category { get; set; } = "";
    public string Key { get; set; } = "";
    public string Detail { get; set; } = "";

    public bool IsMalware => Category == "Malware";
    public bool IsAlert => Severity == "Alert";
}

public sealed class RunResult
{
    public string Generated { get; set; } = "";
    public bool FirstRun { get; set; }
    public int BaselineCount { get; set; }
    public List<FindingItem> Items { get; set; } = new();
}
