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
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Models;

namespace RdpAudit.Configurator.Forms;

/// <summary>Service status panel, lifecycle controls, and recent alerts grid.</summary>
[SupportedOSPlatform("windows")]
public sealed class ServicePage : TabPage
{
	private const string ServiceName = "RdpAuditService";

	private readonly IpcClient _ipc;
	private readonly Label _status;
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

		_status.Text = label;
		_alertsGrid.DataSource = alerts ?? new List<Alert>();
	}

	/// <summary>Resolve the absolute path to the installed service binary, validate it, and call sc create.</summary>
	private async Task InstallServiceAsync()
	{
		string binaryPath = ResolveServiceBinaryPath();
		if (!File.Exists(binaryPath))
		{
			MessageBox.Show(
				string.Format(CultureInfo.InvariantCulture,
					"Service binary not found at:\r\n{0}\r\n\r\nCopy the published Service folder under Program Files first.",
					binaryPath),
				"RdpAudit",
				MessageBoxButtons.OK,
				MessageBoxIcon.Warning);
			return;
		}

		// sc.exe expects: name= value pairs separated by spaces. The binPath value, if quoted, must
		// have its quoted absolute path embedded inside the quoted argument (sc parses one whitespace
		// after the "="). ProcessStartInfo.ArgumentList handles quoting per-argument.
		string[] args =
		{
			"create",
			ServiceName,
			"binPath= " + Quote(binaryPath),
			"start= auto",
			"obj= LocalSystem",
			"DisplayName= RdpAudit Service",
		};

		await ScAsync(null, args).ConfigureAwait(true);
		// Configure failure restart policy: restart 60s, 60s, 60s
		await ScAsync(null, new[] { "failure", ServiceName, "reset= 86400", "actions= restart/60000/restart/60000/restart/60000" }).ConfigureAwait(true);
	}

	internal static string ResolveServiceBinaryPath()
	{
		string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
		return Path.Combine(programFiles, "RdpAudit", "Service", "RdpAudit.Service.exe");
	}

	private static string Quote(string value) =>
		value.Contains(' ', StringComparison.Ordinal) ? "\"" + value + "\"" : value;

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
