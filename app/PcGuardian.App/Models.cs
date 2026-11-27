namespace PcGuardian.App;

/// <summary>One row of the results list. Mirrors the objects Invoke-GuardianRun -AsObject returns.</summary>
public sealed class FindingItem
{
    public string Kind { get; set; } = "";      // New, Removed, Scan, Exposed
    public string Severity { get; set; } = "";  // Alert or Info
    public string Category { get; set; } = "";
    public string Key { get; set; } = "";
    public string Detail { get; set; } = "";

    // A spy app found on a phone is treated like malware on the PC: shown as a threat and never dismissible with "Mark as safe".
    public bool IsMalware => Category == "Malware" || Key.StartsWith("Phone:Stalkerware:", StringComparison.Ordinal);
    public bool IsAlert => Severity == "Alert";
    public bool CanMarkSafe => !IsMalware;

    /// <summary>The flagged file's path for scanner findings ("Malware:C:\x" or "Malware:YARA:C:\x"), else empty.</summary>
    public string FilePath
    {
        get
        {
            if (!IsMalware) return "";
            var m = System.Text.RegularExpressions.Regex.Match(Key, @"^Malware:(?:YARA:)?(?<p>[A-Za-z]:\\.+|\\\\.+)$");
            return m.Success ? m.Groups["p"].Value : "";
        }
    }

    public bool CanIgnoreFile => FilePath.Length > 0;

    /// <summary>Which phone or tablet a row came from, so PC and phone results are never mixed up. Empty for PC rows.</summary>
    public string Device { get; set; } = "";

    /// <summary>A readable title for the row. The raw Key stays as the identity used by the safe list.</summary>
    public string Title => Device.Length > 0 ? $"{TitleCore}  ·  {Device}" : TitleCore;

    private string TitleCore
    {
        get
        {
            // Ports: "Port:3000:node" -> "Open port 3000 (node)".
            if (Key.StartsWith("Port:", StringComparison.Ordinal))
            {
                var p = Key.Split(':');
                if (p.Length > 2) return $"Open port {p[1]} ({p[2]})";
            }
            // Scheduled tasks: drop the folder, the account ID (S-1-5-21-...) and the trailing {guid}.
            if (Key.StartsWith("Task:", StringComparison.Ordinal))
            {
                var leaf = Key[(Key.LastIndexOf('\\') + 1)..];
                leaf = System.Text.RegularExpressions.Regex.Replace(leaf, @"[-_ ]?\{[0-9a-fA-F-]{36}\}$", "");
                if (leaf.Length > 0) return "Scheduled task: " + leaf;
            }
            // Windows settings: say what is wrong in a sentence.
            if (Key.StartsWith("Exposure:Config:", StringComparison.Ordinal))
            {
                var what = Key["Exposure:Config:".Length..];
                if (what.StartsWith("Firewall:", StringComparison.Ordinal)) return $"Firewall is off ({what["Firewall:".Length..]} network)";
                return what switch
                {
                    "SMB1" => "Old file sharing (SMBv1) is on",
                    "UAC" => "User Account Control is off",
                    "RDP" => "Remote Desktop is on",
                    "AutoLogon" => "Automatic sign-in is on",
                    "Guest" => "Guest account is on",
                    "DefenderRealTime" => "Defender live protection is off",
                    "DefenderSignatures" => "Defender threat definitions are out of date",
                    "DefenderUnreadable" => "Could not read Defender's status",
                    "WindowsUpdate" => "Windows updates are overdue",
                    _ => "Windows setting: " + what
                };
            }
            if (Key.StartsWith("Exposure:Update:", StringComparison.Ordinal)) return "App update available: " + Key[(Key.LastIndexOf(':') + 1)..];
            // Certificates: show who it is for and where it applies, not the thumbprint.
            if (Key.StartsWith("Cert:Root:", StringComparison.Ordinal))
            {
                var parts = Key.Split(':');
                var cn = System.Text.RegularExpressions.Regex.Match(Detail, @"CN=([^,]+)");
                var where = parts.Length > 2 && parts[2] == "CurrentUser" ? "your account" : "this PC";
                if (cn.Success) return $"Trusted root certificate ({where}): {cn.Groups[1].Value.Trim()}";
            }
            if (Key.StartsWith("StartupFolder:", StringComparison.Ordinal)) return "Startup folder item: " + Key["StartupFolder:".Length..];
            if (Key.StartsWith("Startup:", StringComparison.Ordinal))
            {
                var p = Key.Split(':', 3);
                if (p.Length == 3) return "Starts with Windows: " + p[2];
            }
            if (Key.StartsWith("Admin:", StringComparison.Ordinal)) return "Administrator account: " + Key["Admin:".Length..];
            if (Key.StartsWith("User:", StringComparison.Ordinal)) return "User account: " + Key["User:".Length..];
            foreach (var (prefix, text) in TitlePrefixes)
                if (Key.StartsWith(prefix, StringComparison.Ordinal)) return text + Key[prefix.Length..];
            return Key;
        }
    }

    private static readonly (string Prefix, string Text)[] TitlePrefixes =
    {
        ("Defender:Exclusion:ExclusionPath:", "Defender skips this folder: "),
        ("Defender:Exclusion:ExclusionProcess:", "Defender skips this program: "),
        ("Defender:Exclusion:ExclusionExtension:", "Defender skips this file type: "),
        ("WMI:ActiveScriptEventConsumer:", "Background script (WMI): "),
        ("WMI:CommandLineEventConsumer:", "Background command (WMI): "),
        ("Service:", "Background service: "),
        ("Hosts:", "Hosts file redirect: "),
        ("Extension:", "Browser extension: "),
        ("Cert:Root:", "Trusted root certificate: "),
        ("Credential:SshKey:", "SSH key without passphrase: "),
        ("Credential:", "Secret in plain text: "),
        ("ClickFix:", "Pasted-command trace: "),
        ("Package:Malicious:", "Known-malicious package: "),
        ("Package:Vulnerable:", "Packages with known vulnerabilities: "),
        ("Phone:Stalkerware:", "Spy app on the phone: "),
        ("Phone:Watchware:", "Monitoring app on the phone: "),
        ("Phone:Sideloaded:", "Phone app from outside the stores: "),
        ("Phone:DeviceAdmin:", "Phone app with device-admin rights: "),
        ("Phone:Accessibility:", "Phone app with accessibility access: "),
        ("Phone:NotificationListener:", "Phone app that reads notifications: "),
        ("Phone:SecurityPatch", "The phone's security updates are old"),
        ("Phone:WirelessDebugging", "Wireless debugging is on"),
        ("Memory:", "Injected code in a running program: "),
        ("Driver:Malicious:", "Malicious driver: "),
        ("Driver:Vulnerable:", "Vulnerable driver: "),
        ("EventLog:", "Suspicious activity in event logs: "),
        ("Malware:YARA:", "Rule match: "),
        ("Malware:", "Possible threat: "),
    };

    /// <summary>Plain-English "what is this and is it normal" line for the row. Empty when there is nothing to add.</summary>
    public string Explanation
    {
        get
        {
            if (Key.StartsWith("Port:", StringComparison.Ordinal))
            {
                var parts = Key.Split(':');
                var port = parts.Length > 1 ? parts[1] : "?";
                var proc = parts.Length > 2 ? parts[2] : "a program";
                var m = System.Text.RegularExpressions.Regex.Match(Detail, @"on (\S+)");
                var addr = m.Success ? m.Groups[1].Value : "";
                string reach =
                    addr is "127.0.0.1" or "::1" ? "Only this PC can connect to it."
                    : addr.StartsWith("100.", StringComparison.Ordinal) ? "Reachable over your Tailscale/VPN network."
                    : "Other devices on your network may be able to connect to it.";
                string who = ProcessNotes.TryGetValue(proc.ToLowerInvariant(), out var note)
                    ? note : $"The program \"{proc}\" is waiting for connections.";
                return $"{who} Port {port}. {reach} Normal if you run this program; unexpected if you don't.";
            }
            if (Key.StartsWith("Task:", StringComparison.Ordinal))
            {
                if (Key.Contains("SoftLanding", StringComparison.OrdinalIgnoreCase))
                    return "A built-in Windows task that manages Action Center tips and notifications. Normal on Windows 11.";
                return "A task Windows runs on a schedule or at sign-in. New ones are worth a look if you didn't install something recently.";
            }
            if (Key.StartsWith("Exposure:Config:", StringComparison.Ordinal))
            {
                var what = Key["Exposure:Config:".Length..];
                if (what.StartsWith("Firewall", StringComparison.Ordinal))
                    return "The Windows Firewall blocks unwanted incoming connections. Turn it back on in Windows Security unless another firewall replaces it.";
                return what switch
                {
                    "SMB1" => "SMBv1 is an old file-sharing protocol that ransomware worms used (WannaCry). Almost nobody needs it; turn it off in Windows Features.",
                    "UAC" => "User Account Control asks before programs make big changes. With it off, malware gets full rights silently. Turn it on.",
                    "RDP" => "Remote Desktop lets others sign in to this PC over the network. Fine if you use it; otherwise turn it off.",
                    "AutoLogon" => "Windows signs in without a password, and the password is kept in the registry where other programs can read it.",
                    "Guest" => "A shared Guest account is enabled. Most people never need it.",
                    "DefenderRealTime" => "Microsoft Defender's live protection is off, so nothing is watching files as they open. Turn it on in Windows Security.",
                    "DefenderSignatures" => "Defender's threat definitions are old, so it can miss new malware. Run Windows Update.",
                    "WindowsUpdate" => "Windows hasn't installed updates in a while. Updates close security holes attackers use.",
                    _ => "A setting that makes this PC easier to attack."
                };
            }
            if (Key.StartsWith("Exposure:Update:", StringComparison.Ordinal))
                return "A newer version of this app exists. Updates often fix security holes. Update it from the app or with winget.";
            if (Key.StartsWith("Defender:Exclusion:", StringComparison.Ordinal))
                return "You or a program told Microsoft Defender not to scan this. Malware also does this to hide. Fine for developer folders you chose; suspicious if you didn't set it.";
            if (Key.StartsWith("WMI:", StringComparison.Ordinal))
                return "WMI can run a script or command in the background when something happens. Some PC makers (Dell, HP) use it; attackers use it to stay hidden.";
            if (Key.StartsWith("Service:", StringComparison.Ordinal))
                return "A program that runs in the background without a window. Check the file path: it should belong to software you installed.";
            if (Key.StartsWith("Cert:Root:", StringComparison.Ordinal))
                return "A root certificate makes your PC trust every site and file that authority vouches for. One you installed yourself (company VPN, proxy tool) is fine; an unknown one can let someone intercept your traffic.";
            if (Key.StartsWith("Hosts:", StringComparison.Ordinal))
                return "The hosts file overrides what a website name points to. Developers use it; malware uses it to send you to fake sites.";
            if (Key.StartsWith("Extension:", StringComparison.Ordinal))
                return "A browser add-on. It can see pages you visit; keep only ones you recognize. Some extensions have broad access (all sites, cookies), which is normal for password managers but worth knowing.";
            if (Key.StartsWith("Credential:SshKey:", StringComparison.Ordinal))
                return "An SSH key unlocks servers or GitHub. Without a passphrase, anyone who copies the file can use it. Add one with ssh-keygen -p.";
            if (Key.StartsWith("Credential:", StringComparison.Ordinal))
                return "A password or token is saved as plain text in a file. Infostealer malware looks for these files first. Move it to a password manager or environment secret, and rotate it if it was ever shared.";
            if (Key.StartsWith("ClickFix:", StringComparison.Ordinal))
                return "A command that looks like the \"paste this into Run/PowerShell to fix an error\" trick used to install malware. If you pasted something like this, treat the PC as possibly infected.";
            if (Key.StartsWith("Package:Malicious:", StringComparison.Ordinal))
                return "A code package in one of your projects is on a public list of known malicious packages. Remove it and rotate any secrets on that machine.";
            if (Key.StartsWith("Package:Vulnerable:", StringComparison.Ordinal))
                return "Your project uses packages with published security bugs. Update them when you can.";
            if (Key.StartsWith("KnownExploited:", StringComparison.Ordinal))
                return "Attackers are actively exploiting a recent flaw in software you have installed (US CISA list). Update this software.";
            if (Key.StartsWith("Memory:", StringComparison.Ordinal))
                return "A running program has code in its memory that doesn't come from its own file, a trick malware uses to hide inside normal programs. Security tools, game anti-cheat and some installers do it legitimately. If you don't recognize the program, treat it as serious.";
            if (Key.StartsWith("Driver:Malicious:", StringComparison.Ordinal))
                return "This driver file matches a known malicious driver. Drivers run with full control of Windows. Treat the PC as possibly compromised and check it with another scanner.";
            if (Key.StartsWith("Driver:Vulnerable:", StringComparison.Ordinal))
                return "A legitimate signed driver with a known security flaw that attackers load to switch off security tools. Not an infection by itself. Update the software that installed it, or remove it if you no longer use it.";
            if (Key.StartsWith("EventLog:", StringComparison.Ordinal))
                return "Windows' own activity log shows something matching a known attack pattern in the last 30 days. Detection rules can false-positive, especially for admin and developer tools. Search the rule name to see what triggers it.";
            if (Key.StartsWith("Malware:", StringComparison.Ordinal))
                return "A scanner thinks this file matches known malware. Don't open it. Check it on virustotal.com before deleting; false alarms happen.";
            return Category switch
            {
                "Startup" => "A program set to start automatically when you sign in. Fine for apps you use; unfamiliar ones are worth a search.",
                "Account" => "A Windows account on this PC. Administrators have full control, so only accounts you recognize should be there.",
                "Defender" => "A Microsoft Defender status reading.",
                _ => ""
            };
        }
    }

    public bool HasExplanation => Explanation.Length > 0;

    /// <summary>What to search for. Built only from names that are the same on every PC: never user names, file paths, account IDs or secrets.</summary>
    public string SearchQuery
    {
        get
        {
            var p = Key.Split(':');
            if (Key.StartsWith("Port:", StringComparison.Ordinal) && p.Length > 2) return $"what is {p[2]} listening on port {p[1]} windows";
            if (Key.StartsWith("Task:", StringComparison.Ordinal))
            {
                var name = Key.Substring(Key.LastIndexOf('\\') + 1);
                return $"windows scheduled task {name}";
            }
            if (Key.StartsWith("Startup:", StringComparison.Ordinal) || Key.StartsWith("StartupFolder:", StringComparison.Ordinal))
                return $"windows startup item {p[^1]} what is it";
            if (Key.StartsWith("Service:", StringComparison.Ordinal)) return $"windows service {p[1]} what is it";
            if (Key.StartsWith("Extension:", StringComparison.Ordinal) && p.Length > 2) return $"{p[2]} {p[1]} browser extension safe";
            if (Key.StartsWith("Hosts:", StringComparison.Ordinal)) return $"hosts file entry {p[1]}";
            if (Key.StartsWith("WMI:", StringComparison.Ordinal)) return "WMI event consumer persistence legitimate or malware";
            if (Key.StartsWith("Defender:Exclusion:", StringComparison.Ordinal)) return "Microsoft Defender exclusion suspicious";
            if (Key.StartsWith("Cert:Root:", StringComparison.Ordinal)) return "user installed trusted root certificate windows risk";
            if (Key.StartsWith("Credential:", StringComparison.Ordinal)) return "plain text API token in file risk how to fix";
            if (Key.StartsWith("ClickFix:", StringComparison.Ordinal)) return "ClickFix malware paste command into Run box";
            if (Key.StartsWith("Exposure:Config:", StringComparison.Ordinal)) return $"windows {p[^1]} security setting should it be on";
            if (Key.StartsWith("Exposure:Update:", StringComparison.Ordinal)) return "";
            if (Key.StartsWith("Memory:", StringComparison.Ordinal)) return "injected code in running process memory legitimate or malware " + (p.Length > 1 && p[1] != "Suspicious" ? p[1] : "");
            if (Key.StartsWith("Driver:", StringComparison.Ordinal) && p.Length > 2) return $"{p[2]} driver loldrivers vulnerable or malicious";
            if (Key.StartsWith("EventLog:", StringComparison.Ordinal)) return Key.Substring("EventLog:".Length) + " windows event detection hayabusa sigma";
            if (Key.StartsWith("Malware:", StringComparison.Ordinal)) return "malware scanner detection how to check false positive";
            return Key.Length > 80 ? "" : Key;
        }
    }

    public bool CanSearch => SearchQuery.Length > 0;

    private static readonly Dictionary<string, string> ProcessNotes = new()
    {
        ["node"] = "Node.js, usually a web or development server you started.",
        ["ollama"] = "Ollama, the local AI model server.",
        ["python"] = "A Python program, often a script or local server you ran.",
        ["services"] = "Windows Service Control Manager, part of Windows itself.",
        ["svchost"] = "A Windows system process that hosts built-in services.",
        ["lsass"] = "Windows sign-in security process.",
        ["spoolsv"] = "The Windows print spooler.",
        ["wininit"] = "Windows startup process.",
    };

    /// <summary>The label and colour class of the pill on the row: Threat, Alert or Info.</summary>
    public string Level => IsMalware ? "Threat" : IsAlert ? "Alert" : "Info";

    /// <summary>The section this row sits in. Threats and alerts come first and start open; routine noise is folded away.</summary>
    public string Group =>
        IsMalware ? "Possible threats"
        : IsAlert ? "Needs attention"
        : Key.StartsWith("Phone:", StringComparison.Ordinal) ? "Phone or tablet"
        : Key.StartsWith("Exposure:Update:", StringComparison.Ordinal) ? "Software updates"
        : Key.StartsWith("ClickFix:", StringComparison.Ordinal) ? "Pasted commands"
        : Key.StartsWith("Port:", StringComparison.Ordinal) ? "Open ports"
        : Key.StartsWith("Task:", StringComparison.Ordinal) ? "Scheduled tasks"
        : Key.StartsWith("Cert:", StringComparison.Ordinal) ? "Trusted certificates"
        : Category == "Scanner" ? "Scanner notes"
        : "Other items";

    /// <summary>Sort position of <see cref="Group"/>: what matters most is listed first.</summary>
    public int GroupOrder => Group switch
    {
        "Possible threats" => 0, "Needs attention" => 1, "Phone or tablet" => 2, "Pasted commands" => 3,
        "Other items" => 4, "Software updates" => 5, "Open ports" => 6, "Scheduled tasks" => 7,
        "Trusted certificates" => 8, _ => 9,
    };

    /// <summary>True for the sections that should be open when the list is first shown.</summary>
    public bool StartsOpen => GroupOrder <= 4;

    /// <summary>A Segoe Fluent / MDL2 icon for the row's kind, so a port, a certificate and a threat look different at a glance.</summary>
    public string Glyph => Group switch
    {
        "Possible threats" => "", "Needs attention" => "", "Phone or tablet" => "",
        "Pasted commands" => "", "Software updates" => "", "Open ports" => "",
        "Scheduled tasks" => "", "Trusted certificates" => "", "Scanner notes" => "",
        _ => "",
    };
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
    public bool DetectorsReady { get; set; }
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
    public bool KnownExploited { get; set; }
    public bool UpdateCheck { get; set; }
    public List<string> DevFolders { get; set; } = new();
}

/// <summary>One Android device that adb can see. Only devices in the "device" state have approved this PC.</summary>
public sealed class PhoneDevice
{
    public string Serial { get; set; } = "";
    public string State { get; set; } = "";
    public string Model { get; set; } = "";
    public string Transport { get; set; } = "usb";

    public bool Ready => State == "device";
    public string Label => (string.IsNullOrWhiteSpace(Model) ? "Android device" : Model.Replace('_', ' ')) +
                           (Transport == "wireless" ? " (wireless)" : " (USB)");
}

/// <summary>Get-GuardianPhoneStatus: are the phone tools downloaded, and which devices are connected?</summary>
public sealed class PhoneStatus
{
    public bool ToolsReady { get; set; }
    /// <summary>Another program's adb is running and may be holding the phone, so it can look missing.</summary>
    public bool OtherAdbRunning { get; set; }
    public List<PhoneDevice> Devices { get; set; } = new();
}

public sealed class PhoneInfo
{
    public string Serial { get; set; } = "";
    public string Model { get; set; } = "";
    public string? Android { get; set; }
    public string? SecurityPatch { get; set; }
}

/// <summary>Invoke-GuardianPhoneCheck: what the read-only check of one phone found.</summary>
public sealed class PhoneResult
{
    public PhoneInfo Device { get; set; } = new();
    public int Packages { get; set; }
    public int ThirdParty { get; set; }
    public List<string> Checked { get; set; } = new();
    public List<FindingItem> Items { get; set; } = new();
}

/// <summary>Get-GuardianUpdateInfo: is a newer pc-guardian release on GitHub?</summary>
public sealed class UpdateInfo
{
    public bool Available { get; set; }
    public string? Current { get; set; }
    public string? Latest { get; set; }
    public string? Url { get; set; }
    /// <summary>The release's installer and checksum list; both are set only for real downloads of this project's release.</summary>
    public string? InstallerUrl { get; set; }
    public string? ChecksumsUrl { get; set; }
}

/// <summary>Save-GuardianUpdate: an installer that was downloaded and checked against the release's checksum list.</summary>
public sealed class DownloadedUpdate
{
    public string Path { get; set; } = "";
    public string Name { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public long Bytes { get; set; }
    public string Signature { get; set; } = "";
    public string Signer { get; set; } = "";
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
