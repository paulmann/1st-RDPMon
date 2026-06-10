// File:    src/RdpAudit.Configurator/Forms/MainForm.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Top-level WinForms shell with tab navigation across the 5 configuration pages.
//          Async event handlers use ConfigureAwait(true) so continuations stay on the UI thread.
// Extends: System.Windows.Forms.Form
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Reflection;
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

		// Owner-drawn tabs: each page label is prefixed with a glyph for fast visual scanning, and the
		// selected tab is rendered bold on a highlighted background with an accent bar so the active page
		// is obvious at a glance. DrawMode=OwnerDrawFixed keeps tab sizing native (no layout shift /
		// flicker); only the per-tab paint is customized. SizeMode=Fixed gives every tab a stable width so
		// the bold selected label does not reflow neighbours. Multiline=true lets the full row of tabs wrap
		// onto additional rows instead of clipping behind scroll arrows when the window is narrow or DPI is
		// high — every page stays reachable without horizontal scrolling.
		_tabs = new TabControl
		{
			Dock = DockStyle.Fill,
			DrawMode = TabDrawMode.OwnerDrawFixed,
			SizeMode = TabSizeMode.Fixed,
			Multiline = true,
			ItemSize = new Size(160, 30),
			Padding = new Point(10, 4),
		};
		_tabs.TabPages.Add(new OverviewPage(_ipc) { Text = "\U0001F4CA Overview" });
		_tabs.TabPages.Add(new PrerequisitesPage { Text = "✅ Prerequisites" });
		_tabs.TabPages.Add(new AuditPolicyPage { Text = "\U0001F4DC Audit Policy" });
		_tabs.TabPages.Add(new ServicePage(_ipc) { Text = "⚙️ Service" });
		_tabs.TabPages.Add(new RdpConfigurationPage(_ipc) { Text = "\U0001F5A5️ RDP Configuration" });
		_tabs.TabPages.Add(new SettingsPage(_ipc) { Text = "\U0001F527 Settings" });
		_tabs.TabPages.Add(new LiveEventsPage(_ipc) { Text = "\U0001F4E1 Live Events" });
		_tabs.TabPages.Add(new LogsPage(_ipc) { Text = "\U0001F4DC Logs" });
		_tabs.TabPages.Add(new FirewallPage(_ipc) { Text = "\U0001F6E1️ Firewall" });
		_tabs.TabPages.Add(new AttackStatisticsPage(_ipc) { Text = "\U0001F4C8 Attack Statistics" });
		_tabs.TabPages.Add(new RemoteRdpClientsPage(_ipc) { Text = "\U0001F310 Remote RDP Clients" });
		_tabs.TabPages.Add(new AbuseIpDbPage(_ipc) { Text = "\U0001F9FE AbuseIPDB" });
		_tabs.TabPages.Add(new MikroTikPage(_ipc) { Text = "\U0001F4F6 MikroTik" });
		_tabs.TabPages.Add(new DiagnosticsPage(_ipc) { Text = "\U0001FA7A Diagnostic" });
		_tabs.TabPages.Add(new ToolsDiagPage(_ipc) { Text = "\U0001F9EA Tools Diag" });

		_tabs.DrawItem += OnDrawTab;

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

	/// <summary>Owner-draws a single tab header: emoji-prefixed label, with the selected tab rendered
	/// bold on a highlighted background so the active page stands out. Falls back gracefully if the
	/// index is out of range (can happen transiently during tab mutation).</summary>
	private void OnDrawTab(object? sender, DrawItemEventArgs e)
	{
		if (e.Index < 0 || e.Index >= _tabs.TabPages.Count)
		{
			return;
		}

		TabPage page = _tabs.TabPages[e.Index];
		bool selected = e.Index == _tabs.SelectedIndex;
		Rectangle bounds = e.Bounds;

		Color back = selected ? SystemColors.Highlight : SystemColors.Control;
		Color fore = selected ? SystemColors.HighlightText : SystemColors.ControlText;

		using (SolidBrush backBrush = new(back))
		{
			e.Graphics.FillRectangle(backBrush, bounds);
		}

		// A thick accent bar along the top edge of the selected tab gives the active page a strong,
		// glanceable cue that survives high-contrast themes where Highlight/Control differ only subtly.
		if (selected)
		{
			using SolidBrush accentBrush = new(SystemColors.HotTrack);
			e.Graphics.FillRectangle(accentBrush, bounds.Left, bounds.Top, bounds.Width, 4);
		}

		using Font font = new(Font, selected ? FontStyle.Bold : FontStyle.Regular);
		TextRenderer.DrawText(
			e.Graphics,
			page.Text,
			font,
			bounds,
			fore,
			TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);

		if (selected)
		{
			e.DrawFocusRectangle();
		}
	}

	private async Task RefreshServiceStatusAsync()
	{
		try
		{
			IpcCallResult<ServiceStatus> call =
				await _ipc.SendDetailedAsync<ServiceStatus>(IpcCommand.GetStatus).ConfigureAwait(true);

			if (call.IsSuccess && call.Value is { } status)
			{
				string baseLine = string.Format(CultureInfo.InvariantCulture,
					"Service v{0} | uptime {1:hh\\:mm\\:ss} | events {2} (dropped {3}) | alerts {4}",
					status.Version, status.Uptime, status.EventsCaptured, status.EventsDropped, status.AlertsRaised);

				// Warn prominently when the running service was built from a different version than this
				// Configurator — the most common cause of "I fixed it but nothing changed" is launching a
				// freshly built Configurator against a stale installed service that was never re-published.
				string mismatch = DescribeVersionMismatch(status.Version);
				_statusLabel.Text = mismatch.Length == 0 ? baseLine : baseLine + "  ⚠ " + mismatch;
				_statusLabel.ForeColor = mismatch.Length == 0 ? SystemColors.ControlText : Color.Firebrick;
			}
			else
			{
				// Distinguish a stopped service from a busy one rather than the blanket "not reachable".
				_statusLabel.Text = "Service: " + call.Headline();
				_statusLabel.ForeColor = call.ServiceLikelyReachable ? SystemColors.ControlText : Color.Firebrick;
			}
		}
		catch (Exception ex)
		{
			_statusLabel.Text = $"Service: error — {ex.GetType().Name}";
			_statusLabel.ForeColor = Color.Firebrick;
		}
	}

	/// <summary>Returns a short warning when the running service's version differs from this Configurator's
	/// own version, else an empty string. Compares the bare SemVer (build-metadata "+sha" suffix trimmed),
	/// so a SHA difference on the same version is not flagged here — the Service tab diagnostics report
	/// performs the deeper SHA / fingerprint comparison.</summary>
	private static string DescribeVersionMismatch(string? serviceVersion)
	{
		if (string.IsNullOrWhiteSpace(serviceVersion))
		{
			return string.Empty;
		}

		string configurator = ResolveConfiguratorVersion();
		string serviceSemVer = TrimBuildMetadata(serviceVersion);
		if (string.Equals(configurator, serviceSemVer, StringComparison.OrdinalIgnoreCase))
		{
			return string.Empty;
		}

		return string.Format(CultureInfo.InvariantCulture,
			"VERSION MISMATCH: Configurator {0} vs Service {1} — the running service is likely a stale build. Re-publish & restart the service.",
			configurator, serviceSemVer);
	}

	private static string ResolveConfiguratorVersion()
	{
		System.Reflection.Assembly asm = typeof(MainForm).Assembly;
		string? info = asm
			.GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>()?.InformationalVersion;
		if (!string.IsNullOrWhiteSpace(info))
		{
			return TrimBuildMetadata(info);
		}

		return asm.GetName().Version?.ToString() ?? "0.0.0";
	}

	private static string TrimBuildMetadata(string version)
	{
		int plus = version.IndexOf('+', StringComparison.Ordinal);
		return plus > 0 ? version[..plus] : version;
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
