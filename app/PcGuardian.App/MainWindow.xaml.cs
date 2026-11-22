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

    private async Task RunScanAsync(bool deep)
    {
        if (_working) return;
        _cts = new CancellationTokenSource();
        _fileCount = 0;
        SetWorking(true);
        _maxFiles = 0;
        StepText.Text = deep ? "Starting a full scan..." : "Checking for changes...";
        CurrentText.Text = "";
        Bar.Value = 0;
        _items.Clear();
        Headline.Text = deep ? "Scanning your PC" : "Checking your PC";
        Subline.Text = deep ? "This can take several minutes. You can keep using your PC." : "This takes a few seconds.";
        SetTone("Accent");

        try
        {
            var result = await _engine.RunAsync(deep, new Progress<ProgressEvent>(OnProgress), _cts.Token);
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
                last.Save();
                StatusText.Text = last.Describe();
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
