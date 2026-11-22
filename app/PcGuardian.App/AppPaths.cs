using System.IO;

namespace PcGuardian.App;

/// <summary>Where pc-guardian keeps its data. Must agree with Get-GuardianDataPath in the engine.</summary>
public static class AppPaths
{
    /// <summary>
    /// The PCGUARDIAN_DATA environment variable if set (the installer sets it when you choose another drive),
    /// otherwise %LOCALAPPDATA%\PcGuardian.
    /// </summary>
    public static string DataDir
    {
        get
        {
            var custom = Environment.GetEnvironmentVariable("PCGUARDIAN_DATA");
            return !string.IsNullOrWhiteSpace(custom)
                ? custom
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PcGuardian");
        }
    }
}
