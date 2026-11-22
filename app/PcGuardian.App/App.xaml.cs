using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

namespace PcGuardian.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var module = GuardianEngine.FindModule();
        if (module == null)
        {
            MessageBox.Show("The pc-guardian engine files are missing. Reinstall the app.",
                "pc-guardian", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
            return;
        }

        if (IsWindowsInDarkMode()) ApplyDarkTheme();
        new MainWindow(new GuardianEngine(module)).Show();
    }

    private static bool IsWindowsInDarkMode()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int v && v == 0;
        }
        catch { return false; }
    }

    private void ApplyDarkTheme()
    {
        void Set(string key, string hex) => Resources[key] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        Set("WindowBg", "#202020");
        Set("CardBg", "#2B2B2B");
        Set("CardBorder", "#3A3A3A");
        Set("TextPrimary", "#FFFFFF");
        Set("TextSecondary", "#B5B5B5");
        Set("Accent", "#4CC2FF");
        Set("AccentHover", "#6FCDFF");
        Set("OnAccent", "#003A5C");
        Set("Good", "#6CCB5F");
        Set("Warn", "#FCB35A");
        Set("Bad", "#FF99A4");
        Set("TrackBg", "#3F3F3F");
        Set("ButtonBg", "#333333");
        Set("ButtonHover", "#3D3D3D");
        Set("PillThreatBg", "#442726");
        Set("PillThreatFg", "#FF99A4");
        Set("PillAlertBg", "#433519");
        Set("PillAlertFg", "#FCE100");
        Set("PillInfoBg", "#3A3A3A");
        Set("PillInfoFg", "#D6D6D6");
    }
}
