// File:    src/RdpAudit.Configurator/Forms/ServicePage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Service status panel, lifecycle controls, and recent alerts grid.
//          Service install computes the absolute service binary path, never literal %ProgramFiles%.
//          All Process.Start + WaitForExit calls are wrapped in Task.Run so the UI thread is free.
//          Every lifecycle button (Start / Stop / Restart / Uninstall / Install) reports a
//          consistent ServiceOperationResult including the action, per-step outcomes, the final
//          service state, the hosting PID, the executable path, and a UTC timestamp.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.Versioning;
using System.Text;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Forms;

/// <summary>Service status panel, lifecycle controls, and recent alerts grid.</summary>
[SupportedOSPlatform("windows")]
public sealed class ServicePage : TabPage
{
	private const string ServiceName = InstallationService.ServiceName;
	private const string ServiceDisplayName = InstallationService.ServiceDisplayName;

	private readonly IpcClient _ipc;
	private readonly Label _status;
	private readonly Label _process;
	private readonly TextBox _layoutPanel;
	private readonly DataGridView _alertsGrid;
	private readonly System.Windows.Forms.Timer _timer;
	private readonly ServiceControlRunner _runner = new(ServiceName, ServiceDisplayName);

	public ServicePage(IpcClient ipc)
	{
		_ipc = ipc;

		FlowLayoutPanel buttons = new() { Dock = DockStyle.Top, Height = 36 };
		Button install = new() { Text = "Install service", Width = 130 };
		Button uninstall = new() { Text = "Uninstall service", Width = 130 };
		Button start = new() { Text = "Start", Width = 80 };
		Button stop = new() { Text = "Stop", Width = 80 };
		Button restart = new() { Text = "Restart", Width = 80 };
		Button backup = new() { Text = "Backup Settings", Width = 140 };
		Button restore = new() { Text = "Restore Registry/Policy", Width = 180 };

		install.Click += async (_, _) => await InstallServiceAsync().ConfigureAwait(true);
		uninstall.Click += async (_, _) => await RunLifecycleAsync(uninstall, _runner.UninstallAsync, "RdpAudit Uninstall").ConfigureAwait(true);
		start.Click += async (_, _) => await RunLifecycleAsync(start, _runner.StartAsync, "RdpAudit Start").ConfigureAwait(true);
		stop.Click += async (_, _) => await RunLifecycleAsync(stop, _runner.StopAsync, "RdpAudit Stop").ConfigureAwait(true);
		restart.Click += async (_, _) => await RunLifecycleAsync(restart, _runner.RestartAsync, "RdpAudit Restart").ConfigureAwait(true);
		backup.Click += async (_, _) => await BackupAsync().ConfigureAwait(true);
		restore.Click += async (_, _) => await RestoreAsync().ConfigureAwait(true);

		buttons.Controls.AddRange(new Control[] { install, uninstall, start, stop, restart, backup, restore });

		_process = new Label
		{
			Dock = DockStyle.Top,
			Height = 22,
			Text = "Process: probing…",
			AutoSize = false,
			TextAlign = ContentAlignment.MiddleLeft,
			Padding = new Padding(4, 2, 4, 2),
		};

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
		Controls.Add(_process);
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
		ServiceProcessInfo processInfo = await _runner.QueryAsync().ConfigureAwait(true);

		_status.Text = label;
		_process.Text = FormatProcessInfo(processInfo);
		_layoutPanel.Text = FormatLayout(layout);
		_alertsGrid.DataSource = alerts ?? new List<Alert>();
	}

	private static string FormatProcessInfo(ServiceProcessInfo info)
	{
		if (!info.Installed)
		{
			return "Process: Not installed";
		}

		if (info.ProcessId is null)
		{
			return $"Process: Not running (state: {info.FinalState})";
		}

		StringBuilder sb = new();
		sb.Append("Process: PID ").Append(info.ProcessId.Value.ToString(CultureInfo.InvariantCulture));
		sb.Append("  state ").Append(info.FinalState);
		if (info.StartTimeUtc is DateTime started)
		{
			sb.Append("  started ").Append(started.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture));
		}

		if (!string.IsNullOrEmpty(info.ExecutablePath))
		{
			sb.Append("  exe ").Append(info.ExecutablePath);
		}

		if (!string.IsNullOrEmpty(info.Detail))
		{
			sb.Append("  (").Append(info.Detail).Append(')');
		}

		return sb.ToString();
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

	private async Task RunLifecycleAsync(
		Button trigger,
		Func<CancellationToken, Task<ServiceOperationResult>> action,
		string title)
	{
		trigger.Enabled = false;
		try
		{
			ServiceOperationResult result = await action(CancellationToken.None).ConfigureAwait(true);
			MessageBox.Show(result.Format(), title, MessageBoxButtons.OK,
				result.Success ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
			await RefreshAsync().ConfigureAwait(true);
		}
		catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
		{
			MessageBox.Show("UAC was cancelled.", title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
		}
		catch (Exception ex)
		{
			MessageBox.Show(ex.Message, title, MessageBoxButtons.OK, MessageBoxIcon.Error);
		}
		finally
		{
			trigger.Enabled = true;
		}
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
		await RefreshAsync().ConfigureAwait(true);
	}

	private async Task BackupAsync()
	{
		try
		{
			ServiceLayoutInfo layout = await Task.Run(() => ServiceLayout.Discover(AppContext.BaseDirectory)).ConfigureAwait(true);
			BackupRunner runner = new(layout);
			BackupOutcome outcome = await runner.RunAsync(BackupReason.Manual).ConfigureAwait(true);
			ShowBackupOutcome(outcome);
		}
		catch (Exception ex)
		{
			MessageBox.Show(ex.Message, "RdpAudit Backup", MessageBoxButtons.OK, MessageBoxIcon.Error);
		}
	}

	private async Task RestoreAsync()
	{
		try
		{
			ServiceLayoutInfo layout = await Task.Run(() => ServiceLayout.Discover(AppContext.BaseDirectory)).ConfigureAwait(true);
			BackupRunner runner = new(layout);
			IReadOnlyList<string> snapshots = await Task.Run(runner.ListSnapshots).ConfigureAwait(true);
			if (snapshots.Count == 0)
			{
				MessageBox.Show(
					"No backup snapshots available. Use Backup Settings to create one first.",
					"RdpAudit Restore",
					MessageBoxButtons.OK,
					MessageBoxIcon.Information);
				return;
			}

			string selected = snapshots[0];
			string confirm = string.Format(CultureInfo.InvariantCulture,
				"Restore registry/SACL and audit policy settings from snapshot {0}?\r\n\r\n"
				+ "A pre-restore safety snapshot will be captured first. The audit event database is NOT modified.",
				selected);
			DialogResult choice = MessageBox.Show(
				confirm,
				"RdpAudit Restore",
				MessageBoxButtons.YesNo,
				MessageBoxIcon.Warning);
			if (choice != DialogResult.Yes)
			{
				return;
			}

			RestoreRunner restorer = new(layout, runner);
			RestoreOutcome outcome = await restorer.RunAsync(selected, RestoreScope.PoliciesAndRegistry).ConfigureAwait(true);
			ShowRestoreOutcome(outcome, selected);
		}
		catch (Exception ex)
		{
			MessageBox.Show(ex.Message, "RdpAudit Restore", MessageBoxButtons.OK, MessageBoxIcon.Error);
		}
	}

	private static void ShowBackupOutcome(BackupOutcome outcome)
	{
		StringBuilder sb = new();
		sb.AppendLine("Snapshot folder:");
		sb.AppendLine("  " + outcome.Snapshot.SnapshotDirectory);
		sb.AppendLine();
		foreach (BackupStep step in outcome.Steps)
		{
			sb.Append(step.Ok ? "OK   " : "FAIL ");
			sb.Append(step.Description);
			if (!string.IsNullOrEmpty(step.Detail))
			{
				sb.Append(" — ").Append(step.Detail);
			}

			sb.AppendLine();
		}

		MessageBox.Show(sb.ToString(), "RdpAudit Backup",
			MessageBoxButtons.OK,
			outcome.Success ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
	}

	private static void ShowRestoreOutcome(RestoreOutcome outcome, string snapshotName)
	{
		StringBuilder sb = new();
		sb.AppendLine("Source snapshot: " + snapshotName);
		sb.AppendLine("Safety snapshot:");
		sb.AppendLine("  " + outcome.SafetySnapshot.SnapshotDirectory);
		sb.AppendLine();
		foreach (RestoreStep step in outcome.Steps)
		{
			sb.Append(step.Ok ? "OK   " : "FAIL ");
			sb.Append(step.Description);
			if (!string.IsNullOrEmpty(step.Detail))
			{
				sb.Append(" — ").Append(step.Detail);
			}

			sb.AppendLine();
		}

		MessageBox.Show(sb.ToString(), "RdpAudit Restore",
			MessageBoxButtons.OK,
			outcome.Success ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
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
