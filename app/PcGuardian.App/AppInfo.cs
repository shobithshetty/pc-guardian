using System.Diagnostics;
using System.Reflection;

namespace PcGuardian.App;

/// <summary>Fixed facts about the app shown in the About window.</summary>
public static class AppInfo
{
    public static string Version =>
        (Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.1.0")
        .Split('+')[0];

    // Filled in when the project is published. Empty means "not published yet" and the links stay hidden.
    public const string ProjectUrl = "";

    /// <summary>GitHub "owner/name" used by the optional update notice. Empty until the project is published.</summary>
    public const string RepoSlug = "";
    public const string SponsorUrl = "";

    public const string Credits =
        "pc-guardian is free and open source (MIT license). It brings other people's free tools together and does not " +
        "replace Microsoft Defender.\n\n" +
        "ClamAV  -  open-source virus scanner by Cisco and the ClamAV community (GPL-2.0). Installed separately; pc-guardian " +
        "only runs it.\n\n" +
        "YARA  -  pattern-matching tool by VirusTotal (BSD-3-Clause).\n\n" +
        "YARA rules  -  Neo23x0/signature-base by Florian Roth and contributors (Detection Rule License 1.1). The rule " +
        "author is shown with each match.\n\n" +
        "VirusTotal  -  optional hash lookups with your own key. Only file fingerprints are sent, never files. A free key " +
        "is for personal, non-commercial use.\n\n" +
        "Microsoft .NET and Windows PowerShell  -  runtime and engine host.\n\n" +
        "Third-party tools can be wrong. A finding means \"take a look\", not \"this is definitely malware\".";

    /// <summary>Opens an https link in the default browser. Anything else is refused.</summary>
    public static void OpenLink(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps) return;
        Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
    }
}
