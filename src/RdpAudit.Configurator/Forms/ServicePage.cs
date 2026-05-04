// File:    src/RdpAudit.Configurator/Forms/ServicePage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Service status panel, lifecycle controls, and recent alerts grid.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Runtime.Versioning;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Models;

namespace RdpAudit.Configurator.Forms;

/// <summary>Service status panel, lifecycle controls, and recent alerts grid.</summary>
[SupportedOSPlatform("windows")]
public sealed class ServicePage : TabPage
{
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

		install.Click += (_, _) => Sc("create RdpAuditService binPath= \"%ProgramFiles%\\RdpAudit\\RdpAudit.Service.exe\" start= auto obj= LocalSystem");
		uninstall.Click += (_, _) => Sc("delete RdpAuditService");
		start.Click += (_, _) => Sc("start RdpAuditService");
		stop.Click += (_, _) => Sc("stop RdpAuditService");
		restart.Click += (_, _) =>
		{
			Sc("stop RdpAuditService");
			Sc("start RdpAuditService");
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
		_timer.Tick += async (_, _) => await RefreshAsync().ConfigureAwait(false);
		HandleCreated += async (_, _) =>
		{
			_timer.Start();
			await RefreshAsync().ConfigureAwait(false);
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
		ServiceStatus? status = await _ipc.SendAsync<ServiceStatus>(IpcCommand.GetStatus).ConfigureAwait(false);
		string label = status is null
			? "Service: not reachable (start the service or run as administrator)"
			: $"Version: {status.Version}\r\nUptime: {status.Uptime}\r\nEvents captured: {status.EventsCaptured} (dropped {status.EventsDropped})\r\nAlerts raised: {status.AlertsRaised}";

		List<Alert>? alerts = await _ipc.SendAsync<List<Alert>>(IpcCommand.GetRecentAlerts).ConfigureAwait(false);

		void apply()
		{
			_status.Text = label;
			_alertsGrid.DataSource = alerts ?? new List<Alert>();
		}

		if (InvokeRequired)
		{
			Invoke(apply);
		}
		else
		{
			apply();
		}
	}

	private static void Sc(string args)
	{
		try
		{
			ProcessStartInfo psi = new("sc.exe", args)
			{
				Verb = "runas",
				UseShellExecute = true,
				WindowStyle = ProcessWindowStyle.Hidden,
			};
			using Process? p = Process.Start(psi);
			p?.WaitForExit();
		}
		catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
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
