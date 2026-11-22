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

    public MainWindow(GuardianEngine engine)
    {
        _engine = engine;
        InitializeComponent();
        ResultsList.ItemsSource = _items;
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
            await RefreshScannerStatusAsync();
            await RunScanAsync(deep: false);
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
            StatusText.Text = (deep ? "Full scan" : "Quick check") + " finished at " + DateTime.Now.ToString("t") +
                              " (" + FormatElapsed(_elapsed.Elapsed) + ")";
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
                    StepText.Text = $"Step {n} of {total}: {parts[2]}";
                    Bar.Value = total == 0 ? 0 : (n - 1) / (double)total;
                    CurrentText.Text = "";
                }
                break;
            case "file":
                CurrentText.Text = p.Value;
                break;
            case "count":
                if (int.TryParse(p.Value, out var c)) _fileCount = c;
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

    private void UpdateStats()
    {
        if (!_working) return;
        var text = "Elapsed " + FormatElapsed(_elapsed.Elapsed);
        if (_fileCount > 0) text += $"  ·  {_fileCount:N0} files checked";
        if (_items.Count > 0) text += $"  ·  {_items.Count} finding{(_items.Count == 1 ? "" : "s")} so far";
        StatsText.Text = text;
    }

    private static string FormatElapsed(TimeSpan t) => $"{(int)t.TotalMinutes}:{t.Seconds:00}";

    private void SetWorking(bool working)
    {
        _working = working;
        ProgressCard.Visibility = working ? Visibility.Visible : Visibility.Collapsed;
        ScanButton.IsEnabled = !working;
        SetupButton.IsEnabled = !working;
        CancelButton.IsEnabled = working;
        if (working) { _elapsed.Restart(); _clock.Start(); }
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
