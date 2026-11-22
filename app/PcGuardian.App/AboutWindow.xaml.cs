using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;

namespace PcGuardian.App;

public partial class AboutWindow : Window
{
    public AboutWindow()
    {
        InitializeComponent();
        VersionText.Text = "Version " + AppInfo.Version;
        CreditsText.Text = AppInfo.Credits;
        var hasSponsor = AppInfo.SponsorUrl.Length > 0;
        var hasProject = AppInfo.ProjectUrl.Length > 0;
        SponsorButton.Visibility = hasSponsor ? Visibility.Visible : Visibility.Collapsed;
        ProjectButton.Visibility = hasProject ? Visibility.Visible : Visibility.Collapsed;
        NoLinks.Visibility = hasSponsor || hasProject ? Visibility.Collapsed : Visibility.Visible;
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
    private void Sponsor_Click(object sender, RoutedEventArgs e) => AppInfo.OpenLink(AppInfo.SponsorUrl);
    private void Project_Click(object sender, RoutedEventArgs e) => AppInfo.OpenLink(AppInfo.ProjectUrl);
}
