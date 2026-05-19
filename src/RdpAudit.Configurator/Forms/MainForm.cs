// File:    src/RdpAudit.Configurator/Forms/MainForm.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Top-level WinForms shell with tab navigation across the 5 configuration pages.
//          Async event handlers use ConfigureAwait(true) so continuations stay on the UI thread.
// Extends: System.Windows.Forms.Form
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Ipc;

namespace RdpAudit.Configurator.Forms;

/// <summary>Top-level WinForms shell.</summary>
[SupportedOSPlatform("windows")]
public sealed class MainForm : Form
{
	private readonly TabControl _tabs;
	private readonly IpcClient _ipc = new();
	private readonly System.Windows.Forms.Timer _statusTimer;
	private readonly StatusStrip _statusStrip;
	private readonly ToolStripStatusLabel _statusLabel;

	public MainForm()
	{
		Text = "RdpAudit Configurator";
		Width = 1200;
		Height = 820;
		StartPosition = FormStartPosition.CenterScreen;

		_tabs = new TabControl { Dock = DockStyle.Fill };
		_tabs.TabPages.Add(new OverviewPage { Text = "Overview" });
		_tabs.TabPages.Add(new PrerequisitesPage { Text = "Prerequisites" });
		_tabs.TabPages.Add(new AuditPolicyPage { Text = "Audit Policy" });
		_tabs.TabPages.Add(new ServicePage(_ipc) { Text = "Service" });
		_tabs.TabPages.Add(new SettingsPage(_ipc) { Text = "Settings" });
		_tabs.TabPages.Add(new LiveEventsPage(_ipc) { Text = "Live Events" });
		_tabs.TabPages.Add(new FirewallPage(_ipc) { Text = "Firewall" });
		_tabs.TabPages.Add(new AttackStatisticsPage(_ipc) { Text = "Attack Statistics" });

		Controls.Add(_tabs);

		_statusStrip = new StatusStrip();
		_statusLabel = new ToolStripStatusLabel("Initializing...");
		_statusStrip.Items.Add(_statusLabel);
		Controls.Add(_statusStrip);

		_statusTimer = new System.Windows.Forms.Timer { Interval = 5_000 };
		_statusTimer.Tick += async (_, _) => await RefreshServiceStatusAsync().ConfigureAwait(true);
		Load += async (_, _) =>
		{
			_statusTimer.Start();
			await RefreshServiceStatusAsync().ConfigureAwait(true);
		};
		FormClosing += (_, _) => _statusTimer.Stop();
	}

	private async Task RefreshServiceStatusAsync()
	{
		try
		{
			ServiceStatus? status = await _ipc.SendAsync<ServiceStatus>(IpcCommand.GetStatus).ConfigureAwait(true);
			_statusLabel.Text = status is null
				? "Service: not reachable"
				: string.Format(CultureInfo.InvariantCulture,
					"Service v{0} | uptime {1:hh\\:mm\\:ss} | events {2} (dropped {3}) | alerts {4}",
					status.Version, status.Uptime, status.EventsCaptured, status.EventsDropped, status.AlertsRaised);
		}
		catch (Exception ex)
		{
			_statusLabel.Text = $"Service: error — {ex.GetType().Name}";
		}
	}

	protected override void Dispose(bool disposing)
	{
		if (disposing)
		{
			_statusTimer.Dispose();
		}

		base.Dispose(disposing);
	}
}
