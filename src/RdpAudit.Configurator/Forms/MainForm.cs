// File:    src/RdpAudit.Configurator/Forms/MainForm.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Top-level WinForms shell with tab navigation across the 5 configuration pages.
// Extends: System.Windows.Forms.Form
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

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
		_tabs.TabPages.Add(new PrerequisitesPage { Text = "Prerequisites" });
		_tabs.TabPages.Add(new AuditPolicyPage { Text = "Audit Policy" });
		_tabs.TabPages.Add(new ServicePage(_ipc) { Text = "Service" });
		_tabs.TabPages.Add(new SettingsPage(_ipc) { Text = "Settings" });
		_tabs.TabPages.Add(new LiveEventsPage { Text = "Live Events" });

		Controls.Add(_tabs);

		_statusStrip = new StatusStrip();
		_statusLabel = new ToolStripStatusLabel("Initializing...");
		_statusStrip.Items.Add(_statusLabel);
		Controls.Add(_statusStrip);

		_statusTimer = new System.Windows.Forms.Timer { Interval = 5_000 };
		_statusTimer.Tick += async (_, _) => await RefreshServiceStatusAsync().ConfigureAwait(false);
		Load += async (_, _) =>
		{
			_statusTimer.Start();
			await RefreshServiceStatusAsync().ConfigureAwait(false);
		};
		FormClosing += (_, _) => _statusTimer.Stop();
	}

	private async Task RefreshServiceStatusAsync()
	{
		try
		{
			ServiceStatus? status = await _ipc.SendAsync<ServiceStatus>(IpcCommand.GetStatus).ConfigureAwait(false);
			string text = status is null
				? "Service: not reachable"
				: $"Service v{status.Version} | uptime {status.Uptime:hh\\:mm\\:ss} | events {status.EventsCaptured} (dropped {status.EventsDropped}) | alerts {status.AlertsRaised}";
			if (InvokeRequired)
			{
				Invoke(() => _statusLabel.Text = text);
			}
			else
			{
				_statusLabel.Text = text;
			}
		}
		catch (Exception ex)
		{
			string text = $"Service: error — {ex.Message}";
			if (InvokeRequired)
			{
				Invoke(() => _statusLabel.Text = text);
			}
			else
			{
				_statusLabel.Text = text;
			}
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
