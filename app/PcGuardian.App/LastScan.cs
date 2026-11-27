using System.IO;
using System.Text.Json;

namespace PcGuardian.App;

/// <summary>The result of the most recent full scan, remembered between runs so the window can always show it.</summary>
public sealed class LastScan
{
    public DateTime Time { get; set; }
    public int Files { get; set; }
    public int Seconds { get; set; }
    public int Threats { get; set; }
    public int Review { get; set; }

    /// <summary>The threats that scan found, so they can be listed again after a restart (a quick check only shows changes).</summary>
    public List<FindingItem> Found { get; set; } = new();

    /// <summary>The saved threats to list again: those still on disk that the current check did not itself report.</summary>
    public static List<FindingItem> Restorable(IEnumerable<string> reportedKeys)
    {
        var reported = reportedKeys.ToHashSet();
        // Several rules can match one file, so a saved key may repeat; keep every finding, as the full scan showed them.
        return (Load()?.Found ?? new()).Where(f => !reported.Contains(f.Key) && (f.FilePath.Length == 0 || File.Exists(f.FilePath))).ToList();
    }

    /// <summary>Drops one saved threat (the person ignored that file) so it does not come back on the next start.</summary>
    public static void Forget(string key)
    {
        var last = Load();
        if (last is null || last.Found.RemoveAll(f => f.Key == key) == 0) return;
        last.Threats = last.Found.Count;
        last.Save();
    }

    private static string FilePath => Path.Combine(AppPaths.DataDir, "last-scan.json");

    public static LastScan? Load()
    {
        try { return File.Exists(FilePath) ? JsonSerializer.Deserialize<LastScan>(File.ReadAllText(FilePath)) : null; }
        catch { return null; }
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this));
        }
        catch { /* remembering the last scan is a convenience; never fail a scan over it */ }
    }

    /// <summary>The saved threats whose file is still on disk (a phone or non-file threat has no path and always counts).</summary>
    public int StillPresent => Found.Count(f => f.FilePath.Length == 0 || File.Exists(f.FilePath));

    /// <summary>"Last full scan: today 8:27 PM · 3,421 files · no threats"; adds "(27 still present)" once some flagged files are gone.</summary>
    public string Describe()
    {
        var day = Time.Date == DateTime.Today ? "today"
                : Time.Date == DateTime.Today.AddDays(-1) ? "yesterday"
                : Time.ToString("d MMM");
        var threats = Threats == 0 ? "no threats" : Threats == 1 ? "1 possible threat" : $"{Threats} possible threats";
        // Found is empty for scans saved by older versions, so only explain a gap we can actually measure.
        if (Found.Count > 0 && StillPresent < Threats) threats += $" ({StillPresent} still present)";
        var files = Files > 0 ? $" · {Files:N0} files" : "";
        return $"Last full scan: {day} {Time:t}{files} · {threats}";
    }
}
