using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace PcGuardian.App;

public partial class MainWindow : Window
{
    private readonly GuardianEngine _engine;
    private readonly ObservableCollection<FindingItem> _items = new();
    private readonly DispatcherTimer _clock = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly Stopwatch _elapsed = new();
    private CancellationTokenSource? _cts;
    private ScannerStatus? _scanner;
    private bool _working;
    private int _fileCount;
    private int _phase, _phaseTotal;
    private int _percent = -1;   // percent done within the current step; -1 when the amount of work is unknown
    private int _maxFiles;       // most files any step reported checking; shown in the scan result

    public MainWindow(GuardianEngine engine)
    {
        _engine = engine;
        InitializeComponent();
        ResultsList.ItemsSource = _items;
        _items.CollectionChanged += (_, _) => UpdateMarkAll();
        _clock.Tick += (_, _) => UpdateStats();
        PreviewKeyDown += (_, e) =>
        {
            if (e.Key == System.Windows.Input.Key.OemComma && System.Windows.Input.Keyboard.Modifiers == System.Windows.Input.ModifierKeys.Control)
            {
                Settings_Click(this, new RoutedEventArgs());
                e.Handled = true;
            }
        };
        Loaded += async (_, _) =>
        {
            StatusText.Text = LastScan.Load()?.Describe() ?? "No full scan yet. Press Scan now to run one.";
            await RefreshScannerStatusAsync();
            // The installer's "set up virus scanning" box leaves a flag: the person already agreed, so start now.
            if (_scanner is { Ready: false } && ConsumeAutoSetupFlag())
                await RunSetupAsync(installClamAv: !_scanner.ClamAvInstalled, clamAvOnly: false);
            await RunScanAsync(deep: false);
            await CheckForUpdateAsync();
        };
    }

    // ---- Menu ---------------------------------------------------------------------------------------------------

    private async void QuickCheck_Click(object sender, RoutedEventArgs e)
    {
        if (!_working) await RunScanAsync(deep: false);
    }

    private void Exit_Click(object sender, RoutedEventArgs e) => Close();

    private void Settings_Click(object sender, RoutedEventArgs e) => new SettingsWindow(_engine, focusSafeList: false) { Owner = this }.ShowDialog();

    private void SafeList_Click(object sender, RoutedEventArgs e) => new SettingsWindow(_engine, focusSafeList: true) { Owner = this }.ShowDialog();

    private async void RefreshStatus_Click(object sender, RoutedEventArgs e) => await RefreshScannerStatusAsync();

    private void About_Click(object sender, RoutedEventArgs e) => new AboutWindow { Owner = this }.ShowDialog();

    // Match the title bar to the app theme (dark title bar when Windows is in dark mode).
    private void Window_SourceInitialized(object? sender, EventArgs e)
    {
        if (FindResource("WindowBg") is SolidColorBrush bg && bg.Color.R < 100)
        {
            var on = 1;
            _ = DwmSetWindowAttribute(new WindowInteropHelper(this).Handle, 20, ref on, sizeof(int));
        }
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    // ---- Finished-work signals --------------------------------------------------------------------------------

    /// <summary>A card that says what just finished and stays until dismissed. Tone is Good, Warn or Bad.</summary>
    private string? _resultActionUrl;

    private void ShowResultCard(string title, string detail, string tone, string? actionText = null, string? actionUrl = null)
    {
        _resultActionUrl = actionUrl;
        ResultAction.Content = actionText;
        ResultAction.Visibility = actionText != null && actionUrl != null ? Visibility.Visible : Visibility.Collapsed;
        ResultTitle.Text = title;
        ResultDetail.Text = detail;
        ResultDot.SetResourceReference(Shape.FillProperty, tone);
        ResultCard.SetResourceReference(Border.BorderBrushProperty, tone);
        ResultTitle.SetResourceReference(TextBlock.ForegroundProperty, tone);
        ResultCard.Visibility = Visibility.Visible;
    }

    private void DismissResult_Click(object sender, RoutedEventArgs e) => ResultCard.Visibility = Visibility.Collapsed;

    private void ResultAction_Click(object sender, RoutedEventArgs e)
    {
        if (_resultActionUrl != null) AppInfo.OpenLink(_resultActionUrl);   // https only; anything else is refused
    }

    /// <summary>Only when the person turned it on in Settings and the project has a GitHub address. Never installs anything.</summary>
    private async Task CheckForUpdateAsync()
    {
        if (AppInfo.RepoSlug.Length == 0) return;
        try
        {
            var settings = await _engine.GetSettingsAsync();
            if (!settings.UpdateCheck) return;
            var info = await _engine.GetUpdateInfoAsync(AppInfo.RepoSlug, AppInfo.Version);
            if (info is { Available: true, Url: not null })
                ShowResultCard($"pc-guardian {info.Latest} is available",
                    $"You have {AppInfo.Version}. Nothing is installed automatically: open the download page, check the checksum, then run the new installer.",
                    "Accent", "Open download page", info.Url);
        }
        catch { /* an update notice is a convenience; never bother the person with its errors */ }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FlashInfo
    {
        public uint Size; public IntPtr Window; public uint Flags; public uint Count; public uint Timeout;
    }

    [DllImport("user32.dll")]
    private static extern bool FlashWindowEx(ref FlashInfo info);

    /// <summary>If the window is behind other apps, flash its taskbar button until the person brings it back.</summary>
    private void FlashIfInactive()
    {
        if (IsActive) return;
        var info = new FlashInfo
        {
            Size = (uint)Marshal.SizeOf<FlashInfo>(), Window = new WindowInteropHelper(this).Handle,
            Flags = 0x0F,   // flash the taskbar button and caption until the window is in front
            Count = uint.MaxValue, Timeout = 0,
        };
        FlashWindowEx(ref info);
    }

    private static bool ConsumeAutoSetupFlag()
    {
        var flag = System.IO.Path.Combine(AppPaths.DataDir, "auto-setup.flag");
        if (!System.IO.File.Exists(flag)) return false;
        try { System.IO.File.Delete(flag); } catch { /* if it cannot be deleted, it only means a second prompt */ }
        return true;
    }

    // ---- Protection data (scanners) ---------------------------------------------------------------------------

    /// <summary>Checks what is installed and shows the one-time download card only when something is missing.</summary>
    private async Task RefreshScannerStatusAsync()
    {
        try { _scanner = await _engine.GetScannerStatusAsync(); }
        catch { _scanner = null; }

        ProtectionText.Text = _scanner?.Summary ?? "";
        ProtectionText.SetResourceReference(TextBlock.ForegroundProperty, _scanner is { IsStale: true } ? "Warn" : "TextSecondary");

        var missing = _scanner is { Ready: false };
        SetupCard.Visibility = missing && !_working ? Visibility.Visible : Visibility.Collapsed;
        if (_scanner is { Ready: false })
        {
            SetupText.Text = !_scanner.ClamAvInstalled
                ? "pc-guardian will install ClamAV (Windows asks for permission once), then download about 100 MB of virus " +
                  "signatures and the YARA rules from GitHub. Everything is checked against pinned hashes first."
                : "pc-guardian will download about 100 MB of virus signatures and the YARA rules from GitHub. " +
                  "Everything is checked against pinned hashes first. It only downloads again when something is new.";
        }
    }

    private async void Setup_Click(object sender, RoutedEventArgs e)
    {
        var ok = await RunSetupAsync(installClamAv: _scanner?.ClamAvInstalled == false, clamAvOnly: false);
        if (ok) await RunScanAsync(deep: true);
    }

    private async Task<bool> RunSetupAsync(bool installClamAv, bool clamAvOnly)
    {
        if (_working) return false;
        _cts = new CancellationTokenSource();
        _fileCount = 0;
        SetupCard.Visibility = Visibility.Collapsed;
        SetWorking(true);
        StepText.Text = "Getting protection ready...";
        CurrentText.Text = "";
        Bar.Value = 0;
        Headline.Text = clamAvOnly ? "Updating the virus database" : "Getting protection ready";
        Subline.Text = "Downloading and checking scanner data. You can keep using your PC.";
        SetTone("Accent");
        var ok = false;
        try
        {
            await _engine.SetupScannersAsync(installClamAv, clamAvOnly, new Progress<ProgressEvent>(OnProgress), _cts.Token);
            Bar.Value = 1;
            StatusText.Text = "Protection data ready (" + FormatElapsed(_elapsed.Elapsed) + ")";
            ShowResultCard("Protection data is ready",
                $"Virus signatures and YARA rules are installed and up to date ({FormatElapsed(_elapsed.Elapsed)}).", "Good");
            FlashIfInactive();
            ok = true;
        }
        catch (OperationCanceledException)
        {
            Headline.Text = "Download cancelled";
            Subline.Text = "Nothing was changed. You can download the protection data again whenever you like.";
            SetTone("Warn");
            StatusText.Text = "Cancelled";
        }
        catch (Exception ex)
        {
            Headline.Text = "The download did not finish";
            Subline.Text = ex.Message;
            SetTone("Bad");
            StatusText.Text = "Failed";
        }
        finally
        {
            SetWorking(false);
            _cts.Dispose();
            _cts = null;
            await RefreshScannerStatusAsync();
        }
        return ok;
    }

    // ---- Scanning ---------------------------------------------------------------------------------------------

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        if (_working) return;
        if (_scanner is { Ready: false })
        {
            // Never download without being asked: show the card and let the person press its button.
            await RefreshScannerStatusAsync();
            Subline.Text = "Download the protection data first, then the scan can run.";
            return;
        }
        // A stale database is refreshed automatically before a full scan, with visible progress.
        if (_scanner is { IsStale: true })
            await RunSetupAsync(installClamAv: false, clamAvOnly: true);
        await RunScanAsync(deep: true);
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        CancelButton.IsEnabled = false;
        StepText.Text = "Cancelling...";
        _cts?.Cancel();
    }

    private async Task RunScanAsync(bool deep, IReadOnlyList<string>? paths = null)
    {
        if (_working) return;
        var custom = paths is { Count: > 0 };
        _cts = new CancellationTokenSource();
        _fileCount = 0;
        SetWorking(true);
        ScanButton.Content = "Scan now";
        _maxFiles = 0;
        StepText.Text = deep ? "Starting a full scan..." : "Checking for changes...";
        CurrentText.Text = "";
        Bar.Value = 0;
        _items.Clear();
        Headline.Text = custom ? "Scanning " + string.Join(", ", paths!) : deep ? "Scanning your PC" : "Checking your PC";
        Subline.Text = custom ? "Every file is checked, so this can take a long time (a whole drive can take hours). You can keep using your PC, and Cancel stops it."
            : deep ? "The first scan can take several minutes; later ones only check new or changed files. You can keep using your PC."
            : "This takes a few seconds.";
        SetTone("Accent");

        try
        {
            var result = await _engine.RunAsync(deep, new Progress<ProgressEvent>(OnProgress), _cts.Token, paths);
            _items.Clear();
            foreach (var f in result.Items.OrderByDescending(i => i.IsMalware).ThenByDescending(i => i.IsAlert))
                _items.Add(f);
            UpdateHeadline(result.FirstRun ? $"Baseline saved with {result.BaselineCount} items. Later checks show what changes." : null);
            var threats = result.Items.Count(i => i.IsMalware);
            var review = result.Items.Count - threats;
            if (deep)
            {
                // Make the end of a full scan impossible to miss, and remember it for next time.
                var last = new LastScan { Time = DateTime.Now, Files = _maxFiles, Seconds = (int)_elapsed.Elapsed.TotalSeconds, Threats = threats, Review = review };
                // A folder or drive scan is its own thing: it must not replace the "last full scan" of the usual places.
                if (!custom) last.Save();
                StatusText.Text = custom ? $"Scanned {string.Join(", ", paths!)} · {_maxFiles:N0} files" : last.Describe();
                var files = _maxFiles > 0 ? $"{_maxFiles:N0} files checked" : "No files were scanned by ClamAV (see the list)";
                ShowResultCard(
                    threats > 0 ? "Scan complete: possible threats found"
                    : review > 0 ? "Scan complete: no threats, a few items to review"
                    : "Scan complete: no threats found",
                    $"{files} in {FormatElapsed(_elapsed.Elapsed)}  ·  {threats} possible threat{(threats == 1 ? "" : "s")}  ·  {review} item{(review == 1 ? "" : "s")} to review",
                    threats > 0 ? "Bad" : review > 0 ? "Warn" : "Good");
                FlashIfInactive();
            }
            else
            {
                StatusText.Text = LastScan.Load()?.Describe() ?? "Quick check finished at " + DateTime.Now.ToString("t");
            }
        }
        catch (OperationCanceledException)
        {
            _items.Clear();
            Headline.Text = "Scan cancelled";
            Subline.Text = "Nothing was changed. Run a scan again whenever you like.";
            SetTone("Warn");
            StatusText.Text = "Cancelled";
        }
        catch (Exception ex)
        {
            Headline.Text = "Something went wrong";
            Subline.Text = ex.Message;
            SetTone("Bad");
            StatusText.Text = "Failed";
        }
        finally
        {
            SetWorking(false);
            _cts.Dispose();
            _cts = null;
        }
    }

    private void OnProgress(ProgressEvent p)
    {
        switch (p.Type)
        {
            case "phase":
                var parts = p.Value.Split('|', 3);
                if (parts.Length == 3 && int.TryParse(parts[0], out var n) && int.TryParse(parts[1], out var total))
                {
                    _fileCount = 0;
                    _percent = -1;
                    _phase = n;
                    _phaseTotal = total;
                    StepText.Text = $"Step {n} of {total}: {parts[2]}";
                    SetBar();
                    CurrentText.Text = "";
                }
                break;
            case "percent":
                if (int.TryParse(p.Value, out var pct))
                {
                    _percent = Math.Clamp(pct, 0, 100);
                    SetBar();
                }
                break;
            case "file":
                CurrentText.Text = p.Value;
                break;
            case "count":
                if (int.TryParse(p.Value, out var c)) { _fileCount = c; _maxFiles = Math.Max(_maxFiles, c); }
                break;
            case "found":
                var item = GuardianEngine.ParseFound(p.Value);
                if (item != null && _items.All(i => i.Key != item.Key))
                {
                    _items.Add(item);
                    UpdateHeadline(null, live: true);
                }
                break;
        }
        UpdateStats();
    }

    /// <summary>Overall bar = finished steps plus the percent done inside the current step, out of all steps.</summary>
    private void SetBar()
    {
        if (_phaseTotal <= 0) { Bar.Value = 0; return; }
        var within = _percent < 0 ? 0 : _percent / 100.0;
        Bar.Value = Math.Min(1.0, ((_phase - 1) + within) / _phaseTotal);
    }

    private void UpdateStats()
    {
        if (!_working) return;
        var text = "Elapsed " + FormatElapsed(_elapsed.Elapsed);
        if (_percent >= 0) text += $"  ·  {_percent}% of this step";
        if (_fileCount > 0) text += $"  ·  {_fileCount:N0} files checked";
        if (_items.Count > 0) text += $"  ·  {_items.Count} finding{(_items.Count == 1 ? "" : "s")} so far";
        StatsText.Text = text;
    }

    private static string FormatElapsed(TimeSpan t) => $"{(int)t.TotalMinutes}:{t.Seconds:00}";

    private void SetWorking(bool working)
    {
        _working = working;
        UpdateMarkAll();
        ProgressCard.Visibility = working ? Visibility.Visible : Visibility.Collapsed;
        ScanButton.IsEnabled = !working;
        SetupButton.IsEnabled = !working;
        CancelButton.IsEnabled = working;
        if (working) { ResultCard.Visibility = Visibility.Collapsed; _elapsed.Restart(); _clock.Start(); }
        else { _elapsed.Stop(); _clock.Stop(); }
        EmptyText.Visibility = !working && _items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>Sets the shield and headline colour: Good, Warn, Bad or Accent.</summary>
    private void SetTone(string brushKey)
    {
        ShieldPath.SetResourceReference(Shape.FillProperty, brushKey);
        Headline.SetResourceReference(TextBlock.ForegroundProperty, brushKey == "Accent" ? "TextPrimary" : brushKey);
    }

    private void UpdateHeadline(string? note, bool live = false)
    {
        var threats = _items.Count(i => i.IsMalware);
        if (threats > 0)
        {
            Headline.Text = threats == 1 ? "1 possible threat found" : $"{threats} possible threats found";
            Subline.Text = "Review the red items. Public rules can false-positive, so check the file before acting.";
            SetTone("Bad");
        }
        else if (live)
        {
            // Mid-scan: keep the scanning message; only a threat changes it.
        }
        else if (_items.Count > 0)
        {
            Headline.Text = _items.Count == 1 ? "1 item needs a look" : $"{_items.Count} items need a look";
            Subline.Text = note ?? "No malware found. Mark items you recognize as safe.";
            SetTone("Warn");
        }
        else
        {
            Headline.Text = "All clear";
            Subline.Text = note ?? "Nothing new to review.";
            SetTone("Good");
        }
        EmptyText.Visibility = !_working && _items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>"Mark all as safe" shows only when there is more than one item that can be marked.</summary>
    private void UpdateMarkAll() =>
        MarkAllButton.Visibility = !_working && _items.Count(i => i.CanMarkSafe) >= 2 ? Visibility.Visible : Visibility.Collapsed;

    private async void MarkAll_Click(object sender, RoutedEventArgs e)
    {
        var markable = _items.Where(i => i.CanMarkSafe).ToList();
        if (markable.Count == 0) return;
        var ok = MessageBox.Show(this,
            $"Mark all {markable.Count} items as safe?\n\nThey will not be reported again unless something new appears. " +
            "Possible threats are never included, and you can undo this in Settings > Safe list.",
            "Mark all as safe", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (ok != MessageBoxResult.Yes) return;
        try
        {
            await _engine.MarkSafeAsync(markable.Select(i => i.Key));
            foreach (var item in markable) _items.Remove(item);
            UpdateHeadline(null);
            StatusText.Text = $"Marked {markable.Count} items as safe";
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "pc-guardian", MessageBoxButton.OK, MessageBoxImage.Warning); }
    }

    /// <summary>
    /// Developer aid: fills the window with sample results and saves a picture of it, without showing it or running
    /// the engine (start the app with --screenshot file.png [--scenario info|mixed|threats]). Lets the look of the real
    /// window be checked without a person clicking through it.
    /// </summary>
    internal void RenderScreenshot(string path, string scenario, int width = 980, int height = 760)
    {
        FindingItem F(string sev, string cat, string key, string detail) =>
            new() { Kind = "Scan", Severity = sev, Category = cat, Key = key, Detail = detail };
        var info = new[]
        {
            F("Info", "Task", @"Task:\SoftLanding\S-1-5-21-1-2-3-1002\ActionCenterDeferralTask-{3de30000-0000-0000-0000-000000000000}", ""),
            F("Info", "Port", "Port:3000:node", "Listening on 0.0.0.0 (node)"),
            F("Info", "Port", "Port:8765:python", "Listening on 100.72.232.65 (python)"),
        };
        var mixed = new[]
        {
            F("Alert", "Memory", "Memory:updater.exe", "x"),
            F("Alert", "EventLog", "EventLog:Suspicious Service Installation Script", "3 event(s) matched this detection rule (level: high), most recent 2026-11-20."),
            F("Info", "Driver", "Driver:Vulnerable:RTCore64.sys", "vulnerable driver on the LOLDrivers list (listed as: RTCore64.sys) at C:\\Windows\\System32\\drivers\\RTCore64.sys"),
            F("Info", "Certificate", "Cert:Root:LocalMachine:EC2C834072AF269510FF0EF203EE3170F6789DCA", "CN=SSL.com TLS RSA Root CA 2022, O=SSL Corporation, C=US (expires 2046-08-19)"),
            F("Alert", "Exposure", "Exposure:Config:UAC", "User Account Control is disabled."),
        };
        var phone = new[]
        {
            F("Alert", "Phone", "Phone:Stalkerware:com.spy.one", "SpyOne (stalkerware) is installed on samsung SM-T505: package com.spy.one. This kind of app secretly reports the phone owner's location, messages and more."),
            F("Alert", "Phone", "Phone:WirelessDebugging", "Wireless debugging is on: a computer on the same Wi-Fi that was paired once can control this phone. Turn it off in Developer options when you are not using it."),
            F("Info", "Phone", "Phone:Accessibility:com.x8bit.bitwarden", "Is an accessibility service: it can read the screen and what is typed. Normal for screen readers and password managers; a common stalkerware trick otherwise."),
            F("Info", "Phone", "Phone:Sideloaded:app.meridian.focusclock.preview", "Installed from outside the app stores (installer: null). Fine if you installed it yourself from a file; worth a look if not."),
            F("Info", "Phone", "Phone:SecurityPatch", "The last Android security update is dated 2024-06-01 (30 months ago). Old phones miss fixes for flaws that spyware uses."),
        };
        var tablet = new[]
        {
            F("Alert", "Phone", "Phone:WirelessDebugging", "Wireless debugging is on: a computer on the same Wi-Fi that was paired once can control this phone. Turn it off in Developer options when you are not using it."),
            F("Info", "Phone", "Phone:Sideloaded:app.meridian.focusclock", "Installed from outside the app stores (installer: null). Fine if you installed it yourself from a file; worth a look if not."),
            F("Info", "Phone", "Phone:Accessibility:com.x8bit.bitwarden", "Is an accessibility service: it can read the screen and what is typed. Normal for screen readers and password managers; a common stalkerware trick otherwise."),
            F("Info", "Phone", "Phone:Accessibility:com.teslacoilsw.launcher", "Is an accessibility service: it can read the screen and what is typed. Normal for screen readers and password managers; a common stalkerware trick otherwise."),
            F("Info", "Phone", "Phone:Accessibility:eu.darken.sdmse", "Is an accessibility service: it can read the screen and what is typed. Normal for screen readers and password managers; a common stalkerware trick otherwise."),
            F("Info", "Phone", "Phone:SecurityPatch", "The last Android security update is dated 2024-06-01 (30 months ago). Old phones miss fixes for flaws that spyware uses."),
        };
        var threats = new[]
        {
            F("Alert", "Malware", @"Malware:C:\Users\me\Downloads\invoice.exe", "ClamAV detected Win.Trojan.Agent-123"),
            F("Alert", "Malware", @"Malware:YARA:C:\Users\me\AppData\Local\Temp\x.dll", "YARA rule APT_Sample (author: someone) matched; public rules can false-positive, review the file"),
        };
        _items.Clear();
        if (scenario is "tablet" or "phone") { foreach (var f in scenario == "tablet" ? tablet : phone) f.Device = "Samsung SM-T505"; ScanButton.Content = "Scan this PC"; }
        foreach (var f in scenario switch { "mixed" => mixed, "threats" => threats, "phone" => phone, "tablet" => tablet, "empty" => Array.Empty<FindingItem>(), _ => info }) _items.Add(f);
        UpdateHeadline(null);
        StatusText.Text = "Last full scan: today 9:41 PM  ·  7,787 files  ·  " + _items.Count + " items";
        ProtectionText.Text = "Protection data updated today";

        var root = (FrameworkElement)Content;
        root.Measure(new Size(width, height));
        root.Arrange(new Rect(0, 0, width, height));
        root.UpdateLayout();
        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen()) dc.DrawRectangle(Background, null, new Rect(0, 0, width, height));
        var bmp = new System.Windows.Media.Imaging.RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        bmp.Render(visual);
        bmp.Render(root);
        var enc = new System.Windows.Media.Imaging.PngBitmapEncoder();
        enc.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bmp));
        using var fs = System.IO.File.Create(path);
        enc.Save(fs);
    }

    /// <summary>
    /// Checks an Android phone or tablet plugged in by USB. Every step asks first: the Google download (with its
    /// licence), which device, and the check itself. Only a device that already approved this PC can be chosen.
    /// </summary>
    private async void CheckPhone_Click(object sender, RoutedEventArgs e)
    {
        if (_working) return;
        try
        {
            var status = await _engine.GetPhoneStatusAsync();
            if (!status.ToolsReady)
            {
                var terms = "https://developer.android.com/studio/terms";
                while (true)
                {
                    var answer = MessageBox.Show(this,
                        "To check an Android phone, pc-guardian needs two things:\n\n" +
                        "• Google's Android tools (adb, about 8 MB). pc-guardian checks the download against a pinned hash and Google's signature before using it.\n" +
                        "• A public list of known spy apps (about 100 KB).\n\n" +
                        "Google's tools are covered by the Android SDK License:\n" + terms + "\n\n" +
                        "Yes = I accept the terms, download now\nNo = open the terms in my browser first\nCancel = stop",
                        "Android phone check", MessageBoxButton.YesNoCancel, MessageBoxImage.Question, MessageBoxResult.Cancel);
                    if (answer == MessageBoxResult.No) { AppInfo.OpenLink(terms); continue; }
                    if (answer != MessageBoxResult.Yes) return;
                    break;
                }
                if (!await RunPhoneToolsDownloadAsync()) return;
                status = await _engine.GetPhoneStatusAsync();
            }

            var ready = status.Devices.Where(d => d.Ready).ToList();
            if (ready.Count == 0)
            {
                var waiting = status.Devices.Count > 0
                    ? "A device is connected but has not approved this PC yet (or is asleep). Unlock it and tap Allow on the \"Allow USB debugging?\" prompt, then try again."
                    : "No Android device was found.";
                MessageBox.Show(this,
                    waiting + "\n\nTo get a phone ready:\n" +
                    "1. Settings > About phone > tap Build number 7 times to turn on Developer options.\n" +
                    "2. Settings > Developer options > turn on USB debugging.\n" +
                    "3. Plug the phone in with a USB cable and unlock it.\n" +
                    "4. Tap Allow on the \"Allow USB debugging?\" prompt.\n\n" +
                    "You can turn USB debugging off again afterwards.",
                    "No phone ready", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var chosen = ready.Count == 1 ? ready[0] : PickPhone(ready);
            if (chosen == null) return;
            var go = MessageBox.Show(this,
                $"Check {chosen.Label}?\n\nThis reads only settings and app names: no messages, photos or files, and nothing is changed or uploaded. " +
                "Your phone may show a small \"USB debugging connected\" notification.\n\nA clean result is not proof that a phone is safe.",
                "Check this phone", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.Yes);
            if (go != MessageBoxResult.Yes) return;
            await RunPhoneCheckAsync(chosen);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Android phone check", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    /// <summary>A small list dialog for choosing between several ready devices.</summary>
    private PhoneDevice? PickPhone(List<PhoneDevice> devices)
    {
        var list = new ListBox { ItemsSource = devices, DisplayMemberPath = "Label", SelectedIndex = 0, Margin = new Thickness(0, 0, 0, 12), MinHeight = 90 };
        PhoneDevice? result = null;
        var ok = new Button { Content = "Check this one", IsDefault = true, Padding = new Thickness(14, 5, 14, 5), Margin = new Thickness(0, 0, 8, 0) };
        var cancel = new Button { Content = "Cancel", IsCancel = true, Padding = new Thickness(14, 5, 14, 5) };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        buttons.Children.Add(ok); buttons.Children.Add(cancel);
        var panel = new StackPanel { Margin = new Thickness(18) };
        panel.Children.Add(new TextBlock { Text = "More than one device is ready. Which one should pc-guardian check?", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 10) });
        panel.Children.Add(list); panel.Children.Add(buttons);
        var win = new Window { Title = "Choose a device", Content = panel, Owner = this, Width = 400, SizeToContent = SizeToContent.Height, WindowStartupLocation = WindowStartupLocation.CenterOwner, ResizeMode = ResizeMode.NoResize };
        win.SetResourceReference(BackgroundProperty, "WindowBg");
        ok.Click += (_, _) => { result = list.SelectedItem as PhoneDevice; win.DialogResult = true; };
        return win.ShowDialog() == true ? result : null;
    }

    private async Task<bool> RunPhoneToolsDownloadAsync()
    {
        _cts = new CancellationTokenSource();
        _fileCount = 0;
        SetWorking(true);
        StepText.Text = "Getting the phone tools ready...";
        CurrentText.Text = "";
        Bar.Value = 0;
        Headline.Text = "Downloading the phone tools";
        Subline.Text = "Google's adb and the public spy-app list, checked against pinned hashes and Google's signature.";
        SetTone("Accent");
        var ok = false;
        try
        {
            await _engine.InstallPhoneToolsAsync(new Progress<ProgressEvent>(OnProgress), _cts.Token);
            Bar.Value = 1;
            ShowResultCard("Phone tools are ready", "adb and the spy-app list are downloaded and verified.", "Good");
            ok = true;
        }
        catch (OperationCanceledException) { Headline.Text = "Download cancelled"; Subline.Text = "Nothing was changed."; SetTone("Warn"); }
        catch (Exception ex) { Headline.Text = "The download did not finish"; Subline.Text = ex.Message; SetTone("Bad"); }
        finally { SetWorking(false); _cts.Dispose(); _cts = null; }
        return ok;
    }

    private async Task RunPhoneCheckAsync(PhoneDevice device)
    {
        _cts = new CancellationTokenSource();
        _fileCount = 0;
        SetWorking(true);
        _items.Clear();
        ScanButton.Content = "Scan now";
        StepText.Text = "Checking " + device.Label + "...";
        CurrentText.Text = "Reading settings and app names (no messages, photos or files)";
        Bar.Value = 0.5;
        Headline.Text = "Checking your phone";
        Subline.Text = "This takes a few seconds. Keep the phone unlocked and plugged in.";
        SetTone("Accent");
        try
        {
            var result = await _engine.CheckPhoneAsync(device.Serial);
            foreach (var f in result.Items.OrderByDescending(i => i.IsAlert)) { f.Device = device.Label; _items.Add(f); }
            UpdateHeadline($"{device.Label}: {result.Packages} apps checked.");
            ScanButton.Content = "Scan this PC";   // the headline button scans the PC, not the phone
            var alerts = result.Items.Count(i => i.IsAlert);
            var info = result.Device.Model + (result.Device.Android != null ? $", Android {result.Device.Android}" : "") +
                       (result.Device.SecurityPatch != null ? $", security update {result.Device.SecurityPatch}" : "");
            StatusText.Text = $"Phone check: {device.Label} · {result.Packages} apps";
            ShowResultCard(
                alerts > 0 ? "Phone check complete: something needs attention"
                : result.Items.Count > 0 ? "Phone check complete: no spy apps found, a few items to review"
                : "Phone check complete: nothing found",
                $"{info}  ·  {result.Packages} apps checked  ·  {result.Items.Count} item{(result.Items.Count == 1 ? "" : "s")} to review  ·  read-only, nothing was changed",
                alerts > 0 ? "Bad" : result.Items.Count > 0 ? "Warn" : "Good");
            FlashIfInactive();
        }
        catch (Exception ex)
        {
            Headline.Text = "The phone check did not finish";
            Subline.Text = ex.Message;
            SetTone("Bad");
            StatusText.Text = "Phone check failed";
        }
        finally { SetWorking(false); _cts.Dispose(); _cts = null; }
    }

    /// <summary>Lets the person pick a folder or drive and scans every file in it.</summary>
    private async void ScanFolder_Click(object sender, RoutedEventArgs e)
    {
        if (_working) return;
        var dlg = new Microsoft.Win32.OpenFolderDialog { Title = "Choose a folder or drive to scan" };
        if (dlg.ShowDialog(this) != true || string.IsNullOrWhiteSpace(dlg.FolderName)) return;
        await RunScanAsync(deep: true, new[] { dlg.FolderName });
    }

    /// <summary>Scans every file on every fixed drive, after saying plainly that it takes a long time.</summary>
    private async void ScanAllDrives_Click(object sender, RoutedEventArgs e)
    {
        if (_working) return;
        var drives = System.IO.DriveInfo.GetDrives().Where(d => d.DriveType == System.IO.DriveType.Fixed && d.IsReady).ToList();
        if (drives.Count == 0) return;
        var usedGb = drives.Sum(d => (d.TotalSize - d.AvailableFreeSpace) / 1_000_000_000.0);
        var ok = MessageBox.Show(this,
            $"Scan every file on {string.Join(", ", drives.Select(d => d.Name))} (about {usedGb:N0} GB in use)?\n\n" +
            "This can take several hours. You can keep using your PC and Cancel stops it. Nothing is changed or deleted.\n\n" +
            "The usual full scan already checks the places malware most often lands, in minutes.",
            "Scan all drives", MessageBoxButton.OKCancel, MessageBoxImage.Question, MessageBoxResult.Cancel);
        if (ok != MessageBoxResult.OK) return;
        await RunScanAsync(deep: true, drives.Select(d => d.RootDirectory.FullName).ToList());
    }

    /// <summary>Explains Microsoft Defender Offline, then opens Windows Security. pc-guardian never restarts the PC itself.</summary>
    private void OfflineScan_Click(object sender, RoutedEventArgs e)
    {
        var ok = MessageBox.Show(this,
            "Some malware (rootkits) can hide while Windows is running. Microsoft Defender Offline scans before Windows loads, so nothing can hide.\n\n" +
            "This opens Windows Security. There, choose Scan options, then \"Microsoft Defender Antivirus (offline scan)\", then Scan now.\n\n" +
            "Your PC will restart and the scan takes about 15 minutes. Save your work first.\n\nOpen Windows Security now?",
            "Scan before Windows starts", MessageBoxButton.OKCancel, MessageBoxImage.Information);
        if (ok != MessageBoxResult.OK) return;
        try { Process.Start(new ProcessStartInfo("windowsdefender://threat/") { UseShellExecute = true }); }
        catch (Exception ex) { MessageBox.Show(this, "Could not open Windows Security: " + ex.Message, "pc-guardian", MessageBoxButton.OK, MessageBoxImage.Warning); }
    }

    /// <summary>Opens a Google search for the item in the default browser. The query holds only generic names (see FindingItem.SearchQuery).</summary>
    private void Search_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: FindingItem item } || item.SearchQuery.Length == 0) return;
        AppInfo.OpenLink("https://www.google.com/search?q=" + Uri.EscapeDataString(item.SearchQuery));
    }

    /// <summary>Ignores one flagged file while its contents are unchanged. Asks first, because it hides a scanner result.</summary>
    private async void IgnoreFile_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: FindingItem item } || item.FilePath.Length == 0) return;
        var ok = MessageBox.Show(this,
            "Ignore this file?\n\n" + item.FilePath + "\n\nOnly do this if you are sure it is a false alarm (for example a detection-rule or test file). " +
            "pc-guardian remembers the file's exact fingerprint, so it is reported again if the file ever changes.",
            "Ignore this file", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
        if (ok != MessageBoxResult.Yes) return;
        try
        {
            await _engine.IgnoreFileAsync(item.FilePath);
            _items.Remove(item);
            UpdateHeadline(null);
            StatusText.Text = "Ignoring: " + item.FilePath;
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "pc-guardian", MessageBoxButton.OK, MessageBoxImage.Warning); }
    }

    private async void MarkSafe_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: FindingItem item } || item.IsMalware) return;
        try
        {
            await _engine.MarkSafeAsync(item.Key);
            _items.Remove(item);
            UpdateHeadline(null);
            StatusText.Text = "Marked as safe: " + item.Key;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "pc-guardian", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}
