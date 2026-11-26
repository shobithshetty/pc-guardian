using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;

namespace PcGuardian.App;

public partial class SettingsWindow : Window
{
    private readonly GuardianEngine _engine;
    private readonly bool _focusSafeList;
    private bool _loading;

    public SettingsWindow(GuardianEngine engine, bool focusSafeList)
    {
        _engine = engine;
        _focusSafeList = focusSafeList;
        InitializeComponent();
        DataFolderBox.Text = AppPaths.DataDir;
        Loaded += async (_, _) =>
        {
            await LoadAsync();
            if (_focusSafeList) SafeCard.BringIntoView();
        };
    }

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

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void OpenDataFolder_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            System.IO.Directory.CreateDirectory(AppPaths.DataDir);
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe", $"\"{AppPaths.DataDir}\"") { UseShellExecute = true });
        }
        catch (Exception ex) { Notice.Text = ex.Message; }
    }

    private async Task LoadAsync()
    {
        _loading = true;
        try
        {
            var settings = await _engine.GetSettingsAsync();
            var daily = await _engine.GetDailyScanAsync();
            var safe = await _engine.GetSafeItemsAsync();

            QuickStartCheck.IsChecked = AppPrefs.Load().QuickCheckOnStart;
            OsvCheck.IsChecked = settings.Osv;
            KevCheck.IsChecked = settings.KnownExploited;
            UpdateCheck.IsChecked = settings.UpdateCheck;
            if (AppInfo.RepoSlug.Length == 0)
            {
                UpdateCheck.IsEnabled = false;
                UpdateCheckNote.Text = "Available once the project is published on GitHub.";
            }
            DevFolderList.ItemsSource = settings.DevFolders;
            VtCheck.IsChecked = settings.VirusTotal;
            VtStatus.Text = settings.VirusTotalKeySet ? "A key is saved (encrypted for your Windows account only)."
                : settings.VirusTotal ? "Turned on, but no key is saved yet. Paste one above and press Save key."
                : "No key saved.";

            DailyCheck.IsChecked = daily.Exists && daily.Enabled;
            if (!string.IsNullOrEmpty(daily.At)) TimeBox.Text = daily.At;
            DailyStatus.Text = daily.Exists && daily.Enabled ? $"Scheduled daily at {daily.At}." : "The daily scan is off.";

            SafeList.ItemsSource = safe;
            SafeEmpty.Visibility = safe.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            Notice.Text = "";
        }
        catch (Exception ex) { Notice.Text = ex.Message; }
        finally { _loading = false; }
    }

    private void QuickStartCheck_Changed(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        var prefs = AppPrefs.Load();
        prefs.QuickCheckOnStart = QuickStartCheck.IsChecked == true;
        prefs.Save();
        Notice.Text = "Saved. It applies the next time pc-guardian opens.";
    }

    private async void VtCheck_Changed(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        try
        {
            await _engine.SetVirusTotalEnabledAsync(VtCheck.IsChecked == true);
            await LoadAsync();
            Notice.Text = "Saved.";
        }
        catch (Exception ex) { Notice.Text = ex.Message; }
    }

    private async void KevCheck_Changed(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        try { await _engine.SetKnownExploitedEnabledAsync(KevCheck.IsChecked == true); Notice.Text = "Saved."; }
        catch (Exception ex) { Notice.Text = ex.Message; }
    }

    private async void UpdateCheck_Changed(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        try { await _engine.SetUpdateCheckEnabledAsync(UpdateCheck.IsChecked == true); Notice.Text = "Saved."; }
        catch (Exception ex) { Notice.Text = ex.Message; }
    }

    private async void OsvCheck_Changed(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        try
        {
            await _engine.SetOsvEnabledAsync(OsvCheck.IsChecked == true);
            Notice.Text = "Saved.";
        }
        catch (Exception ex) { Notice.Text = ex.Message; }
    }

    private async void AddDevFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog { Title = "Choose a folder that holds your code projects" };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            await _engine.AddDevFolderAsync(dialog.FolderName);
            await LoadAsync();
            Notice.Text = "Folder added.";
        }
        catch (Exception ex) { Notice.Text = ex.Message; }
    }

    private async void RemoveDevFolder_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string path }) return;
        try
        {
            await _engine.RemoveDevFolderAsync(path);
            await LoadAsync();
            Notice.Text = "Folder removed.";
        }
        catch (Exception ex) { Notice.Text = ex.Message; }
    }

    private async void SaveKey_Click(object sender, RoutedEventArgs e)
    {
        var key = VtKeyBox.Password.Trim();
        if (key.Length == 0) { Notice.Text = "Paste your VirusTotal API key first."; return; }
        try
        {
            await _engine.SetVirusTotalKeyAsync(key);
            VtKeyBox.Clear();
            await LoadAsync();
            Notice.Text = "Key saved.";
        }
        catch (Exception ex) { Notice.Text = ex.Message; }
    }

    private async void RemoveKey_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            await _engine.RemoveVirusTotalKeyAsync();
            await LoadAsync();
            Notice.Text = "Key removed.";
        }
        catch (Exception ex) { Notice.Text = ex.Message; }
    }

    private async void SaveDaily_Click(object sender, RoutedEventArgs e)
    {
        SaveDailyButton.IsEnabled = false;
        Notice.Text = "Waiting for Windows permission...";
        try
        {
            await _engine.SetDailyScanAsync(DailyCheck.IsChecked == true, TimeBox.Text.Trim());
            await LoadAsync();
            Notice.Text = "Saved.";
        }
        catch (OperationCanceledException ex) { Notice.Text = ex.Message; }
        catch (Exception ex) { Notice.Text = ex.Message; }
        finally { SaveDailyButton.IsEnabled = true; }
    }

    private async void RemoveSafe_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string key }) return;
        try
        {
            await _engine.RemoveSafeItemAsync(key);
            await LoadAsync();
            Notice.Text = "Removed. It will be reported again if it is still new.";
        }
        catch (Exception ex) { Notice.Text = ex.Message; }
    }
}
