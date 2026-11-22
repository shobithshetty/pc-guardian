using System.Diagnostics;
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

    public async Task<RunResult> RunAsync(bool deepScan, CancellationToken ct = default)
    {
        var switches = deepScan ? " -Scan -CheckUpdates" : "";
        var (code, stdout, stderr) = await PowerShellAsync(
            Prelude + $"Invoke-GuardianRun -AsObject{switches} | ConvertTo-Json -Depth 6 -Compress",
            null, null, ct);
        if (code != 0 || string.IsNullOrWhiteSpace(stdout))
            throw new InvalidOperationException(FirstLine(stderr) ?? $"The scan engine exited with code {code}.");

        return JsonSerializer.Deserialize<RunResult>(stdout, Json)
               ?? throw new InvalidOperationException("The scan engine returned no result.");
    }

    public async Task MarkSafeAsync(string key, CancellationToken ct = default)
    {
        var env = new Dictionary<string, string> { ["PCG_KEY"] = key };
        var (code, _, stderr) = await PowerShellAsync(Prelude + "Add-GuardianSafeItem -Key $env:PCG_KEY", env, null, ct);
        if (code != 0) throw new InvalidOperationException(FirstLine(stderr) ?? "Could not save to the safe list.");
    }

    /// <summary>Downloads the pinned scanners. Output lines are reported as they arrive.</summary>
    public async Task InstallScannersAsync(IProgress<string> lines, CancellationToken ct = default)
    {
        var (code, _, stderr) = await PowerShellAsync(Prelude + "Install-GuardianScanner", null, lines, ct);
        if (code != 0) throw new InvalidOperationException(FirstLine(stderr) ?? $"Setup exited with code {code}.");
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
        await using var registration = ct.Register(() => { try { p.Kill(true); } catch { /* already exited */ } });
        await p.WaitForExitAsync(ct);
        return (p.ExitCode, sbOut.ToString(), sbErr.ToString());
    }
}
