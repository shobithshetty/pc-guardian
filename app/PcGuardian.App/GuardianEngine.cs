using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;

namespace PcGuardian.App;

/// <summary>
/// Talks to the PowerShell engine (the PcGuardian module) by running it as a child process.
/// Nothing user-controlled is ever pasted into a command line: values travel in environment variables.
/// </summary>
public sealed class GuardianEngine
{
    private const string Prelude = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Import-Module -Name $env:PCG_MODULE -Force; ";
    private const string ProgressPrefix = "PCG|";
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true };
    private readonly string _modulePath;

    public GuardianEngine(string modulePath) => _modulePath = modulePath;

    /// <summary>Finds PcGuardian.psd1 next to the .exe (installed) or in the repo's src folder (development).</summary>
    public static string? FindModule()
    {
        var installed = Path.Combine(AppContext.BaseDirectory, "module", "PcGuardian", "PcGuardian.psd1");
        if (File.Exists(installed)) return installed;

        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
        {
            var dev = Path.Combine(dir.FullName, "src", "PcGuardian", "PcGuardian.psd1");
            if (File.Exists(dev)) return dev;
        }
        return null;
    }

    /// <summary>Runs a check. Live progress lines are reported while it works; the final result is returned.</summary>
    public async Task<RunResult> RunAsync(bool deepScan, IProgress<ProgressEvent>? progress, CancellationToken ct = default,
        IReadOnlyList<string>? scanPaths = null)
    {
        var switches = deepScan ? " -Scan -CheckUpdates" : "";
        // Folders or drives to scan in full. They travel as JSON in an environment variable, never on the command line.
        Dictionary<string, string>? env = null;
        if (scanPaths is { Count: > 0 })
        {
            env = new() { ["PCG_SCANPATHS"] = JsonSerializer.Serialize(scanPaths) };
            switches = " -ScanPath @(ConvertFrom-Json $env:PCG_SCANPATHS)";
        }
        var lines = new Progress<string>(line =>
        {
            if (!line.StartsWith(ProgressPrefix, StringComparison.Ordinal)) return;
            var parts = line.Split('|', 3);
            if (parts.Length == 3) progress?.Report(new ProgressEvent(parts[1], parts[2]));
        });
        var (code, stdout, stderr) = await PowerShellAsync(
            Prelude + $"Invoke-GuardianRun -AsObject -Progress{switches} | ConvertTo-Json -Depth 6 -Compress",
            env, lines, ct);
        if (code != 0)
            throw new InvalidOperationException(FirstLine(stderr) ?? $"The scan engine exited with code {code}.");

        // The result is the one line that is not a progress line.
        var json = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .LastOrDefault(l => !l.StartsWith(ProgressPrefix, StringComparison.Ordinal));
        if (string.IsNullOrWhiteSpace(json))
            throw new InvalidOperationException(FirstLine(stderr) ?? "The scan engine returned no result.");

        return JsonSerializer.Deserialize<RunResult>(json, Json)
               ?? throw new InvalidOperationException("The scan engine returned no result.");
    }

    public static FindingItem? ParseFound(string json) => JsonSerializer.Deserialize<FindingItem>(json, Json);

    public Task MarkSafeAsync(string key, CancellationToken ct = default) => MarkSafeAsync(new[] { key }, ct);

    /// <summary>Marks several findings safe in one engine call. The keys travel as JSON in an environment variable.</summary>
    public async Task MarkSafeAsync(IEnumerable<string> keys, CancellationToken ct = default)
    {
        var env = new Dictionary<string, string> { ["PCG_KEYS"] = JsonSerializer.Serialize(keys.ToArray()) };
        var (code, _, stderr) = await PowerShellAsync(
            Prelude + "$k = ConvertFrom-Json $env:PCG_KEYS; Add-GuardianSafeItem -Key @($k)", env, null, ct);
        if (code != 0) throw new InvalidOperationException(FirstLine(stderr) ?? "Could not save to the safe list.");
    }

    /// <summary>Ignores one flagged file while its contents stay the same. The path travels in an environment variable.</summary>
    public async Task IgnoreFileAsync(string path, CancellationToken ct = default)
    {
        var (code, _, stderr) = await PowerShellAsync(
            Prelude + "Add-GuardianIgnoredFile -Path $env:PCG_PATH", new Dictionary<string, string> { ["PCG_PATH"] = path }, null, ct);
        if (code != 0) throw new InvalidOperationException(FirstLine(stderr) ?? "Could not ignore that file.");
    }

    // ---- Settings -----------------------------------------------------------------------------------------

    public async Task<AppSettings> GetSettingsAsync(CancellationToken ct = default) =>
        await QueryAsync<AppSettings>("Get-GuardianSetting", ct) ?? new AppSettings();

    public async Task<DailyScanInfo> GetDailyScanAsync(CancellationToken ct = default) =>
        await QueryAsync<DailyScanInfo>("Get-GuardianDailyScan", ct) ?? new DailyScanInfo();

    public async Task<List<SafeItem>> GetSafeItemsAsync(CancellationToken ct = default) =>
        await QueryAsync<List<SafeItem>>("ConvertTo-Json -InputObject @(Get-GuardianSafeItem) -Compress", ct, rawJson: true) ?? new();

    public Task SetVirusTotalEnabledAsync(bool enabled, CancellationToken ct = default) =>
        RunVoidAsync("Set-GuardianSetting -Name virusTotal -Value ([bool]::Parse($env:PCG_VALUE))",
            new() { ["PCG_VALUE"] = enabled ? "true" : "false" }, ct);

    public Task SetKnownExploitedEnabledAsync(bool enabled, CancellationToken ct = default) =>
        RunVoidAsync("Set-GuardianSetting -Name knownExploited -Value ([bool]::Parse($env:PCG_VALUE))",
            new() { ["PCG_VALUE"] = enabled ? "true" : "false" }, ct);

    public Task SetUpdateCheckEnabledAsync(bool enabled, CancellationToken ct = default) =>
        RunVoidAsync("Set-GuardianSetting -Name updateCheck -Value ([bool]::Parse($env:PCG_VALUE))",
            new() { ["PCG_VALUE"] = enabled ? "true" : "false" }, ct);

    /// <summary>Asks the engine whether a newer release exists. The engine caches the answer for about a day.</summary>
    public async Task<UpdateInfo> GetUpdateInfoAsync(string repository, string currentVersion, CancellationToken ct = default)
    {
        var env = new Dictionary<string, string> { ["PCG_REPO"] = repository, ["PCG_VERSION"] = currentVersion };
        var (code, stdout, stderr) = await PowerShellAsync(
            Prelude + "Get-GuardianUpdateInfo -Repository $env:PCG_REPO -CurrentVersion $env:PCG_VERSION | ConvertTo-Json -Compress", env, null, ct);
        if (code != 0) throw new InvalidOperationException(FirstLine(stderr) ?? "Could not check for updates.");
        return JsonSerializer.Deserialize<UpdateInfo>(stdout.Trim(), Json) ?? new UpdateInfo();
    }

    public Task SetOsvEnabledAsync(bool enabled, CancellationToken ct = default) =>
        RunVoidAsync("Set-GuardianSetting -Name osv -Value ([bool]::Parse($env:PCG_VALUE))",
            new() { ["PCG_VALUE"] = enabled ? "true" : "false" }, ct);

    public Task AddDevFolderAsync(string path, CancellationToken ct = default) =>
        RunVoidAsync("Add-GuardianDevFolder -Path $env:PCG_PATH", new() { ["PCG_PATH"] = path }, ct);

    public Task RemoveDevFolderAsync(string path, CancellationToken ct = default) =>
        RunVoidAsync("Remove-GuardianDevFolder -Path $env:PCG_PATH", new() { ["PCG_PATH"] = path }, ct);

    /// <summary>The key travels in an environment variable, never in the command line.</summary>
    public Task SetVirusTotalKeyAsync(string key, CancellationToken ct = default) =>
        RunVoidAsync("Set-GuardianVirusTotalKey -Key (ConvertTo-SecureString $env:PCG_VTKEY -AsPlainText -Force) | Out-Null",
            new() { ["PCG_VTKEY"] = key }, ct);

    public Task RemoveVirusTotalKeyAsync(CancellationToken ct = default) =>
        RunVoidAsync("Set-GuardianVirusTotalKey -Remove | Out-Null", null, ct);

    public Task RemoveSafeItemAsync(string key, CancellationToken ct = default) =>
        RunVoidAsync("Remove-GuardianSafeItem -Key $env:PCG_KEY", new() { ["PCG_KEY"] = key }, ct);

    /// <summary>
    /// Turns the daily scan on (at HH:mm) or off. Changing a scheduled task needs administrator rights,
    /// so Windows shows its normal permission prompt.
    /// </summary>
    public async Task SetDailyScanAsync(bool enabled, string time, CancellationToken ct = default)
    {
        if (enabled && !System.Text.RegularExpressions.Regex.IsMatch(time, @"^([01]\d|2[0-3]):[0-5]\d$"))
            throw new ArgumentException("Enter the time as HH:mm, for example 02:00.");

        var script = FindTool("Install.ps1") ?? throw new InvalidOperationException("The scheduling script is missing. Reinstall the app.");
        var args = $"-NoProfile -ExecutionPolicy Bypass -File \"{script}\" " +
                   (enabled ? $"-ModulePath \"{_modulePath}\" -At {time}" : "-Remove");
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"), args)
        {
            UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden,
        };
        try
        {
            using var p = Process.Start(psi) ?? throw new InvalidOperationException("Could not start the scheduler.");
            await p.WaitForExitAsync(ct);
            if (p.ExitCode != 0) throw new InvalidOperationException($"The scheduler exited with code {p.ExitCode}.");
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            throw new OperationCanceledException("The permission prompt was cancelled, so nothing was changed.");
        }
    }

    private static string? FindTool(string name)
    {
        var installed = Path.Combine(AppContext.BaseDirectory, "tools", name);
        if (File.Exists(installed)) return installed;
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
        {
            var dev = Path.Combine(dir.FullName, "installer", name);
            if (File.Exists(dev)) return dev;
        }
        return null;
    }

    private async Task<T?> QueryAsync<T>(string command, CancellationToken ct, bool rawJson = false)
    {
        var full = Prelude + (rawJson ? command : command + " | ConvertTo-Json -Compress");
        var (code, stdout, stderr) = await PowerShellAsync(full, null, null, ct);
        if (code != 0) throw new InvalidOperationException(FirstLine(stderr) ?? "The engine could not answer.");
        var text = stdout.Trim();
        return text.Length == 0 ? default : JsonSerializer.Deserialize<T>(text, Json);
    }

    private async Task RunVoidAsync(string command, Dictionary<string, string>? env, CancellationToken ct)
    {
        var (code, _, stderr) = await PowerShellAsync(Prelude + command, env, null, ct);
        if (code != 0) throw new InvalidOperationException(FirstLine(stderr) ?? "The engine reported an error.");
    }

    public async Task<ScannerStatus> GetScannerStatusAsync(CancellationToken ct = default)
    {
        var (code, stdout, stderr) = await PowerShellAsync(
            Prelude + "Get-GuardianScannerStatus | ConvertTo-Json -Compress", null, null, ct);
        if (code != 0) throw new InvalidOperationException(FirstLine(stderr) ?? "Could not check the scanners.");
        return JsonSerializer.Deserialize<ScannerStatus>(stdout.Trim(), Json) ?? new ScannerStatus();
    }

    /// <summary>
    /// Downloads the pinned scanner data. Numbered steps arrive as phase events and everything else the tools
    /// print (such as download progress) arrives as file events, so the window can show them live.
    /// </summary>
    public async Task SetupScannersAsync(bool installClamAv, bool clamAvOnly, IProgress<ProgressEvent> progress, CancellationToken ct = default)
    {
        var args = " -Progress" + (installClamAv ? " -InstallClamAv" : "") + (clamAvOnly ? " -ClamAv" : "");
        var lines = new Progress<string>(line =>
        {
            if (line.StartsWith(ProgressPrefix, StringComparison.Ordinal))
            {
                var parts = line.Split('|', 3);
                if (parts.Length == 3) progress.Report(new ProgressEvent(parts[1], parts[2]));
            }
            else if (!string.IsNullOrWhiteSpace(line))
            {
                progress.Report(new ProgressEvent("file", line.Trim()));
            }
        });
        var (code, _, stderr) = await PowerShellAsync(Prelude + "Install-GuardianScanner" + args, null, lines, ct);
        if (code != 0) throw new InvalidOperationException(FirstLine(stderr) ?? $"Setup exited with code {code}.");
    }

    // ---- Phone check --------------------------------------------------------------------------------------

    public async Task<PhoneStatus> GetPhoneStatusAsync(CancellationToken ct = default)
    {
        var (code, stdout, stderr) = await PowerShellAsync(
            Prelude + "Get-GuardianPhoneStatus | ConvertTo-Json -Depth 4 -Compress", null, null, ct);
        if (code != 0) throw new InvalidOperationException(FirstLine(stderr) ?? "Could not look for phones.");
        return JsonSerializer.Deserialize<PhoneStatus>(stdout.Trim(), Json) ?? new PhoneStatus();
    }

    /// <summary>
    /// Downloads Google's adb and the stalkerware lists. Call it only after the person accepted the Android SDK License:
    /// the engine refuses without -AcceptAndroidSdkLicense.
    /// </summary>
    public async Task InstallPhoneToolsAsync(IProgress<ProgressEvent> progress, CancellationToken ct = default)
    {
        var lines = new Progress<string>(line =>
        {
            if (line.StartsWith(ProgressPrefix, StringComparison.Ordinal))
            {
                var parts = line.Split('|', 3);
                if (parts.Length == 3) progress.Report(new ProgressEvent(parts[1], parts[2]));
            }
            else if (!string.IsNullOrWhiteSpace(line)) progress.Report(new ProgressEvent("file", line.Trim()));
        });
        var (code, _, stderr) = await PowerShellAsync(
            Prelude + "Install-GuardianPhoneTools -AcceptAndroidSdkLicense -Progress", null, lines, ct);
        if (code != 0) throw new InvalidOperationException(FirstLine(stderr) ?? $"The download exited with code {code}.");
    }

    /// <summary>Checks exactly one device. The serial travels in an environment variable, never on the command line.</summary>
    public async Task<PhoneResult> CheckPhoneAsync(string serial, CancellationToken ct = default)
    {
        var (code, stdout, stderr) = await PowerShellAsync(
            Prelude + "Invoke-GuardianPhoneCheck -Serial $env:PCG_SERIAL | ConvertTo-Json -Depth 6 -Compress",
            new Dictionary<string, string> { ["PCG_SERIAL"] = serial }, null, ct);
        if (code != 0) throw new InvalidOperationException(FirstLine(stderr) ?? "The phone check failed.");
        return JsonSerializer.Deserialize<PhoneResult>(stdout.Trim(), Json) ?? throw new InvalidOperationException("The phone check returned no result.");
    }

    private static string? FirstLine(string text) =>
        text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();

    private async Task<(int Code, string Out, string Err)> PowerShellAsync(
        string command, Dictionary<string, string>? env, IProgress<string>? lines, CancellationToken ct)
    {
        var exe = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        // Bypass applies to this one child process only; it lets the engine load from a downloaded folder.
        foreach (var a in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command })
            psi.ArgumentList.Add(a);
        psi.Environment["PCG_MODULE"] = _modulePath;
        if (env != null) foreach (var kv in env) psi.Environment[kv.Key] = kv.Value;

        using var p = new Process { StartInfo = psi };
        var sbOut = new StringBuilder();
        var sbErr = new StringBuilder();
        p.OutputDataReceived += (_, e) => { if (e.Data != null) { sbOut.AppendLine(e.Data); lines?.Report(e.Data); } };
        p.ErrorDataReceived += (_, e) => { if (e.Data != null) sbErr.AppendLine(e.Data); };
        p.Start();
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        // Cancel kills the whole process tree, so a running clamscan stops too.
        await using var registration = ct.Register(() => { try { p.Kill(true); } catch { /* already exited */ } });
        await p.WaitForExitAsync(CancellationToken.None);
        ct.ThrowIfCancellationRequested();
        return (p.ExitCode, sbOut.ToString(), sbErr.ToString());
    }
}
