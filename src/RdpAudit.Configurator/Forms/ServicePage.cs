// File:    src/RdpAudit.Configurator/Forms/ServicePage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Service status panel, lifecycle controls, and recent alerts grid.
//          Service install computes the absolute service binary path, never literal %ProgramFiles%.
//          All Process.Start + WaitForExit calls are wrapped in Task.Run so the UI thread is free.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.Versioning;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Forms;

/// <summary>Service status panel, lifecycle controls, and recent alerts grid.</summary>
[SupportedOSPlatform("windows")]
public sealed class ServicePage : TabPage
{
	private const string ServiceName = InstallationService.ServiceName;

	private readonly IpcClient _ipc;
	private readonly Label _status;
	private readonly TextBox _layoutPanel;
	private readonly DataGridView _alertsGrid;
	private readonly System.Windows.Forms.Timer _timer;

	public ServicePage(IpcClient ipc)
	{
		_ipc = ipc;

		FlowLayoutPanel buttons = new() { Dock = DockStyle.Top, Height = 36 };
		Button install = new() { Text = "Install service", Width = 130 };
		Button uninstall = new() { Text = "Uninstall service", Width = 130 };
		Button start = new() { Text = "Start", Width = 80 };
		Button stop = new() { Text = "Stop", Width = 80 };
		Button restart = new() { Text = "Restart", Width = 80 };

		install.Click += async (_, _) => await InstallServiceAsync().ConfigureAwait(true);
		uninstall.Click += async (_, _) => await ScAsync("delete", new[] { ServiceName }).ConfigureAwait(true);
		start.Click += async (_, _) => await ScAsync("start", new[] { ServiceName }).ConfigureAwait(true);
		stop.Click += async (_, _) => await ScAsync("stop", new[] { ServiceName }).ConfigureAwait(true);
		restart.Click += async (_, _) =>
		{
			await ScAsync("stop", new[] { ServiceName }).ConfigureAwait(true);
			await ScAsync("start", new[] { ServiceName }).ConfigureAwait(true);
		};

		buttons.Controls.AddRange(new Control[] { install, uninstall, start, stop, restart });

		_status = new Label { Dock = DockStyle.Top, Height = 80, Text = "Connecting…", AutoSize = false };
		_layoutPanel = new TextBox
		{
			Dock = DockStyle.Top,
			Height = 160,
			Multiline = true,
			ReadOnly = true,
			ScrollBars = ScrollBars.Vertical,
			WordWrap = true,
			Font = new Font(FontFamily.GenericMonospace, 9f),
		};

		_alertsGrid = new DataGridView
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			ReadOnly = true,
			RowHeadersVisible = false,
			AllowUserToAddRows = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
		};
		_alertsGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Time (UTC)", DataPropertyName = nameof(Alert.TimeUtc), Width = 160 });
		_alertsGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Severity", DataPropertyName = nameof(Alert.Severity), Width = 90 });
		_alertsGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Rule", DataPropertyName = nameof(Alert.RuleId), Width = 200 });
		_alertsGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "User", DataPropertyName = nameof(Alert.UserName), Width = 160 });
		_alertsGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "IP", DataPropertyName = nameof(Alert.SourceIp), Width = 130 });
		_alertsGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Message", DataPropertyName = nameof(Alert.Message), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });

		_alertsGrid.CellFormatting += SeverityColoring;

		Controls.Add(_alertsGrid);
		Controls.Add(_layoutPanel);
		Controls.Add(_status);
		Controls.Add(buttons);

		_timer = new System.Windows.Forms.Timer { Interval = 5_000 };
		_timer.Tick += async (_, _) => await RefreshAsync().ConfigureAwait(true);
		HandleCreated += async (_, _) =>
		{
			_timer.Start();
			await RefreshAsync().ConfigureAwait(true);
		};
	}

	private static void SeverityColoring(object? sender, DataGridViewCellFormattingEventArgs e)
	{
		if (e.RowIndex < 0)
		{
			return;
		}

		DataGridView grid = (DataGridView)sender!;
		if (grid.Rows[e.RowIndex].DataBoundItem is not Alert alert)
		{
			return;
		}

		e.CellStyle!.BackColor = alert.Severity switch
		{
			AlertSeverity.Critical => Color.FromArgb(255, 180, 180),
			AlertSeverity.High => Color.FromArgb(255, 220, 160),
			AlertSeverity.Medium => Color.FromArgb(255, 255, 160),
			AlertSeverity.Low => Color.FromArgb(180, 220, 255),
			_ => SystemColors.Window,
		};
	}

	private async Task RefreshAsync()
	{
		ServiceStatus? status = await _ipc.SendAsync<ServiceStatus>(IpcCommand.GetStatus).ConfigureAwait(true);
		string label = status is null
			? "Service: not reachable (start the service or run as administrator)"
			: $"Version: {status.Version}\r\nUptime: {status.Uptime}\r\nEvents captured: {status.EventsCaptured} (dropped {status.EventsDropped})\r\nAlerts raised: {status.AlertsRaised}";

		List<Alert>? alerts = await _ipc.SendAsync<List<Alert>>(IpcCommand.GetRecentAlerts).ConfigureAwait(true);
		ServiceLayoutInfo layout = await Task.Run(() => ServiceLayout.Discover(AppContext.BaseDirectory)).ConfigureAwait(true);

		_status.Text = label;
		_layoutPanel.Text = FormatLayout(layout);
		_alertsGrid.DataSource = alerts ?? new List<Alert>();
	}

	private static string FormatLayout(ServiceLayoutInfo layout)
	{
		string source = layout.DistributionDirectory ?? ServiceLayout.ResolveSiblingDistribution(layout.ConfiguratorDirectory);
		string distLine = layout.DistributionExists
			? (layout.ServiceExecutableExists
				? $"present (RdpAudit.Service.exe found at {layout.ExpectedServiceExecutable})"
				: $"present but missing executable {layout.ExpectedServiceExecutable}")
			: "NOT FOUND — sc install will refuse to run";

		return string.Format(CultureInfo.InvariantCulture,
			"Install destination: {0}\r\n"
			+ "Database path:       {1}\r\n"
			+ "appsettings.json:    {2}\r\n"
			+ "\r\n"
			+ "Service distribution source\r\n"
			+ "  Configurator dir: {3}\r\n"
			+ "  Distribution dir: {4}\r\n"
			+ "  Status:           {5}",
			layout.InstallDirectory,
			layout.DefaultDatabasePath,
			layout.AppSettingsPath,
			layout.ConfiguratorDirectory,
			source,
			distLine);
	}

	/// <summary>Discover the sibling Service distribution, copy it under Program Files,
	/// and register/start the Windows service via the shared <see cref="InstallationService"/>.</summary>
	private async Task InstallServiceAsync()
	{
		ServiceLayoutInfo layout = await Task.Run(() => ServiceLayout.Discover(AppContext.BaseDirectory)).ConfigureAwait(true);
		if (!layout.DistributionExists || !layout.ServiceExecutableExists)
		{
			MessageBox.Show(
				string.Format(CultureInfo.InvariantCulture,
					"Service distribution not found at:\r\n{0}\r\n"
					+ "Run publish.ps1 so the Configurator can copy {1} to {2}.",
					ServiceLayout.ResolveSiblingDistribution(layout.ConfiguratorDirectory),
					ServiceLayout.ServiceExeName,
					layout.InstallDirectory),
				"RdpAudit",
				MessageBoxButtons.OK,
				MessageBoxIcon.Warning);
			return;
		}

		InstallationService installer = new(layout);
		InstallationOutcome outcome = await installer.RunAsync().ConfigureAwait(true);

		System.Text.StringBuilder sb = new();
		foreach (string step in outcome.Steps)
		{
			sb.AppendLine("OK   " + step);
		}

		foreach (string warning in outcome.Warnings)
		{
			sb.AppendLine("WARN " + warning);
		}

		foreach (string error in outcome.Errors)
		{
			sb.AppendLine("FAIL " + error);
		}

		MessageBox.Show(sb.ToString(), "RdpAudit Install", MessageBoxButtons.OK,
			outcome.Success ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
	}

	private static async Task ScAsync(string? leadingVerb, IReadOnlyList<string> args)
	{
		try
		{
			ProcessStartInfo psi = new("sc.exe")
			{
				UseShellExecute = false,
				CreateNoWindow = true,
				RedirectStandardError = true,
				RedirectStandardOutput = true,
			};
			if (leadingVerb is not null)
			{
				psi.ArgumentList.Add(leadingVerb);
			}

			foreach (string a in args)
			{
				psi.ArgumentList.Add(a);
			}

			await Task.Run(() =>
			{
				using Process? p = Process.Start(psi);
				p?.WaitForExit(30_000);
			}).ConfigureAwait(true);
		}
		catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
		{
			MessageBox.Show("UAC was cancelled.", "RdpAudit", MessageBoxButtons.OK, MessageBoxIcon.Warning);
		}
		catch (Exception ex)
		{
			MessageBox.Show(ex.Message, "RdpAudit", MessageBoxButtons.OK, MessageBoxIcon.Error);
		}
	}

	protected override void Dispose(bool disposing)
	{
		if (disposing)
		{
			_timer.Dispose();
		}

		base.Dispose(disposing);
	}
}
