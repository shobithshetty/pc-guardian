using System.IO;
using System.Text.Json;

namespace PcGuardian.App;

/// <summary>
/// Preferences that belong to the window rather than the scanning engine (so they are not part of Get-GuardianSetting).
/// Kept in the data folder as app-prefs.json. A missing or unreadable file means the defaults.
/// </summary>
public sealed class AppPrefs
{
    /// <summary>Run the quick check (startup items, tasks, ports, certificates, Windows settings) when the window opens.</summary>
    public bool QuickCheckOnStart { get; set; } = true;

    private static string FilePath => Path.Combine(AppPaths.DataDir, "app-prefs.json");

    public static AppPrefs Load()
    {
        try { return File.Exists(FilePath) ? JsonSerializer.Deserialize<AppPrefs>(File.ReadAllText(FilePath)) ?? new AppPrefs() : new AppPrefs(); }
        catch { return new AppPrefs(); }
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this));
        }
        catch { /* a preference is a convenience; never crash the window over it */ }
    }
}
