namespace PcGuardian.App;

/// <summary>The one window of the app: status at the top, findings below, buttons on the side.</summary>
public sealed class MainForm : Form
{
    private readonly GuardianEngine _engine;
    private readonly Label _headline = new() { AutoSize = true, Font = new Font("Segoe UI Semibold", 16f) };
    private readonly Label _subline = new() { AutoSize = true, ForeColor = SystemColors.GrayText };
    private readonly Button _scanButton = new() { Text = "Scan now", AutoSize = true, Padding = new Padding(10, 4, 10, 4) };
    private readonly Button _safeButton = new() { Text = "Mark as safe", AutoSize = true, Enabled = false, Padding = new Padding(10, 4, 10, 4) };
    private readonly ListView _list = new()
    {
        View = View.Details, FullRowSelect = true, MultiSelect = false, HideSelection = false,
        Dock = DockStyle.Fill, BorderStyle = BorderStyle.FixedSingle,
    };
    private readonly ToolStripStatusLabel _status = new("Starting...");
    private readonly ProgressBar _busy = new() { Style = ProgressBarStyle.Marquee, Visible = false, Dock = DockStyle.Top, Height = 4 };
    private bool _working;

    public MainForm(GuardianEngine engine)
    {
        _engine = engine;
        Text = "pc-guardian";
        Size = new Size(920, 560);
        MinimumSize = new Size(700, 420);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9.5f);

        _list.Columns.Add("Level", 70);
        _list.Columns.Add("Item", 360);
        _list.Columns.Add("Detail", 440);
        _list.SelectedIndexChanged += (_, _) => UpdateSafeButton();
        _scanButton.Click += async (_, _) => await RunScanAsync(deep: true);
        _safeButton.Click += async (_, _) => await MarkSelectedSafeAsync();

        var header = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 2, Padding = new Padding(16, 14, 16, 10) };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var text = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false };
        text.Controls.AddRange(new Control[] { _headline, _subline });
        var buttons = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight, Anchor = AnchorStyles.Right };
        buttons.Controls.AddRange(new Control[] { _safeButton, _scanButton });
        header.Controls.Add(text, 0, 0);
        header.Controls.Add(buttons, 1, 0);

        var listHost = new Panel { Dock = DockStyle.Fill, Padding = new Padding(16, 0, 16, 8) };
        listHost.Controls.Add(_list);

        var statusStrip = new StatusStrip();
        statusStrip.Items.Add(_status);

        Controls.Add(listHost);
        Controls.Add(header);
        Controls.Add(_busy);
        Controls.Add(statusStrip);
        MainMenuStrip = BuildMenu();
        Controls.Add(MainMenuStrip);

        Shown += async (_, _) => await RunScanAsync(deep: false);
    }

    private MenuStrip BuildMenu()
    {
        var menu = new MenuStrip();
        var file = new ToolStripMenuItem("&File");
        var setup = new ToolStripMenuItem("Set up scanners...", null, async (_, _) => await SetupScannersAsync());
        file.DropDownItems.Add(setup);
        file.DropDownItems.Add(new ToolStripSeparator());
        file.DropDownItems.Add(new ToolStripMenuItem("E&xit", null, (_, _) => Close()));

        var scan = new ToolStripMenuItem("&Scan");
        scan.DropDownItems.Add(new ToolStripMenuItem("Quick check (changes only)", null, async (_, _) => await RunScanAsync(deep: false)));
        scan.DropDownItems.Add(new ToolStripMenuItem("Full scan now", null, async (_, _) => await RunScanAsync(deep: true)));

        var help = new ToolStripMenuItem("&Help");
        help.DropDownItems.Add(new ToolStripMenuItem("About pc-guardian", null, (_, _) => MessageBox.Show(this,
            "pc-guardian 0.1.0\n\nFree and open source. It reports what changed on your PC and never deletes anything.\n" +
            "It does not replace Microsoft Defender and cannot catch every threat.\n\n" +
            "Sponsor links are on the project's GitHub page.", "About", MessageBoxButtons.OK, MessageBoxIcon.Information)));

        menu.Items.AddRange(new ToolStripItem[] { file, scan, help });
        return menu;
    }

    private async Task RunScanAsync(bool deep)
    {
        if (_working) return;
        SetBusy(true, deep ? "Scanning your PC (this can take a few minutes)..." : "Checking for changes...");
        try
        {
            var result = await _engine.RunAsync(deep);
            ShowResult(result, deep);
        }
        catch (Exception ex)
        {
            _headline.Text = "Something went wrong";
            _subline.Text = ex.Message;
            _status.Text = "Failed";
        }
        finally { SetBusy(false, null); }
    }

    private void ShowResult(RunResult r, bool deep)
    {
        _list.BeginUpdate();
        _list.Items.Clear();
        foreach (var f in r.Items.OrderByDescending(i => i.IsMalware).ThenByDescending(i => i.IsAlert))
        {
            var row = new ListViewItem(f.Severity) { Tag = f };
            row.SubItems.Add(f.Key);
            row.SubItems.Add(f.Detail);
            if (f.IsMalware) row.ForeColor = Color.Firebrick;
            else if (f.IsAlert) row.ForeColor = Color.DarkOrange;
            _list.Items.Add(row);
        }
        _list.EndUpdate();
        UpdateHeadline(r.FirstRun ? $"Baseline saved with {r.BaselineCount} items. Later checks show what changes." : null);
        _status.Text = (deep ? "Full scan" : "Quick check") + " finished at " + DateTime.Now.ToString("t");
    }

    private void UpdateHeadline(string? note)
    {
        var items = _list.Items.Cast<ListViewItem>().Select(i => (FindingItem)i.Tag!).ToList();
        var malware = items.Count(i => i.IsMalware);
        if (malware > 0)
        {
            _headline.Text = $"{malware} possible threat{(malware > 1 ? "s" : "")} found";
            _headline.ForeColor = Color.Firebrick;
            _subline.Text = "Review the red items. Public rules can false-positive, so check the file before acting.";
        }
        else if (items.Count > 0)
        {
            _headline.Text = $"{items.Count} item{(items.Count > 1 ? "s" : "")} need a look";
            _headline.ForeColor = Color.DarkOrange;
            _subline.Text = note ?? "No malware found. Mark items you recognize as safe.";
        }
        else
        {
            _headline.Text = "All clear";
            _headline.ForeColor = Color.SeaGreen;
            _subline.Text = note ?? "Nothing new to review.";
        }
    }

    private void UpdateSafeButton()
    {
        var f = SelectedItem();
        _safeButton.Enabled = f != null && !f.IsMalware && !_working;
    }

    private FindingItem? SelectedItem() => _list.SelectedItems.Count == 1 ? (FindingItem?)_list.SelectedItems[0].Tag : null;

    private async Task MarkSelectedSafeAsync()
    {
        var f = SelectedItem();
        if (f == null || f.IsMalware) return;
        SetBusy(true, "Saving...");
        try
        {
            await _engine.MarkSafeAsync(f.Key);
            _list.Items.Remove(_list.SelectedItems[0]);
            UpdateHeadline(null);
            _status.Text = "Marked as safe: " + f.Key;
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "pc-guardian", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        finally { SetBusy(false, null); }
    }

    private async Task SetupScannersAsync()
    {
        if (_working) return;
        var ok = MessageBox.Show(this,
            "This downloads the ClamAV virus database (about 100 MB) and the pinned YARA program and rules from the internet.\n\n" +
            "ClamAV itself must already be installed (winget install Cisco.ClamAV).\n\nContinue?",
            "Set up scanners", MessageBoxButtons.OKCancel, MessageBoxIcon.Question);
        if (ok != DialogResult.OK) return;

        using var dlg = new Form { Text = "Setting up scanners", Size = new Size(640, 380), StartPosition = FormStartPosition.CenterParent };
        var log = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, Font = new Font("Consolas", 9f) };
        var close = new Button { Text = "Close", Dock = DockStyle.Bottom, Enabled = false, Height = 32 };
        close.Click += (_, _) => dlg.Close();
        dlg.Controls.Add(log);
        dlg.Controls.Add(close);
        dlg.Show(this);

        SetBusy(true, "Setting up scanners...");
        try
        {
            await _engine.InstallScannersAsync(new Progress<string>(l => log.AppendText(l + Environment.NewLine)));
            log.AppendText(Environment.NewLine + "Done.");
            _status.Text = "Scanners ready";
        }
        catch (Exception ex) { log.AppendText(Environment.NewLine + "Failed: " + ex.Message); _status.Text = "Setup failed"; }
        finally { SetBusy(false, null); close.Enabled = true; }
    }

    private void SetBusy(bool busy, string? status)
    {
        _working = busy;
        _busy.Visible = busy;
        _scanButton.Enabled = !busy;
        if (status != null) _status.Text = status;
        UpdateSafeButton();
    }
}
