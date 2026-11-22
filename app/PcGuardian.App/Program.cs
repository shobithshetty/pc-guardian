namespace PcGuardian.App;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();

        var module = GuardianEngine.FindModule();
        if (module == null)
        {
            MessageBox.Show("The pc-guardian engine files are missing. Reinstall the app.",
                "pc-guardian", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }
        Application.Run(new MainForm(new GuardianEngine(module)));
    }
}
