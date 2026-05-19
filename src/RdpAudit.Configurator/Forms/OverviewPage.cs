// File:    src/RdpAudit.Configurator/Forms/OverviewPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Primary "home" tab: product info, project links, version, first-run
//          install button, and a live status panel summarising DB readiness,
//          service installation state, and detected errors/warnings.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.Versioning;
using System.Text;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Backup;

namespace RdpAudit.Configurator.Forms;

/// <summary>Primary home tab: product info, links, version and first-run install button.</summary>
[SupportedOSPlatform("windows")]
public sealed class OverviewPage : TabPage
{
	private const string ProjectUrl = "https://github.com/paulmann/1st-RDPMon";
	private const string AuthorName = "Mikhail Deynekin";
	private const string AuthorUrl = "https://Deynekin.com";
	private const string AuthorEmail = "rdp@deynekin.com";

	private readonly Label _title;
	private readonly Label _purpose;
	private readonly Label _versionLabel;
	private readonly LinkLabel _projectLink;
	private readonly Label _authorLabel;
	private readonly LinkLabel _authorLink;
	private readonly LinkLabel _emailLink;
	private readonly TextBox _statusReport;
	private readonly Button _install;
	private readonly Button _refresh;
	private readonly Button _backup;
	private readonly Button _restore;
	private readonly Label _status;
	private readonly OverviewProbe _probe = new();

	public OverviewPage()
	{
		Text = "Overview";
		Padding = new Padding(12);

		_title = new Label
		{
			Text = "RdpAudit — RDP & Logon Security Monitor",
			AutoSize = true,
			Font = new Font(SystemFonts.MessageBoxFont!.FontFamily, 14f, FontStyle.Bold),
			Location = new Point(12, 12),
		};

		_purpose = new Label
		{
			Text = "Monitors RDP, account, Kerberos and accessibility-backdoor events. "
				+ "The Configurator manages first-run installation, audit policy / SACL "
				+ "configuration, service lifecycle, and live event review.",
			AutoSize = false,
			Width = 1100,
			Height = 48,
			Location = new Point(12, 50),
		};

		_versionLabel = new Label
		{
			Text = $"Version: {GetProductVersion()}",
			AutoSize = true,
			Location = new Point(12, 104),
		};

		_projectLink = new LinkLabel
		{
			Text = "Project: " + ProjectUrl,
			AutoSize = true,
			Location = new Point(12, 128),
		};
		_projectLink.LinkArea = new LinkArea("Project: ".Length, ProjectUrl.Length);
		_projectLink.LinkClicked += (_, _) => OpenUrl(ProjectUrl);

		_authorLabel = new Label
		{
			Text = "Author: " + AuthorName,
			AutoSize = true,
			Location = new Point(12, 152),
		};

		_authorLink = new LinkLabel
		{
			Text = "Website: " + AuthorUrl,
			AutoSize = true,
			Location = new Point(12, 176),
		};
		_authorLink.LinkArea = new LinkArea("Website: ".Length, AuthorUrl.Length);
		_authorLink.LinkClicked += (_, _) => OpenUrl(AuthorUrl);

		_emailLink = new LinkLabel
		{
			Text = "Email: " + AuthorEmail,
			AutoSize = true,
			Location = new Point(12, 200),
		};
		_emailLink.LinkArea = new LinkArea("Email: ".Length, AuthorEmail.Length);
		_emailLink.LinkClicked += (_, _) => OpenUrl("mailto:" + AuthorEmail);

		_install = new Button
		{
			Text = "Install / Repair",
			Width = 180,
			Height = 32,
			Location = new Point(12, 236),
		};
		_install.Click += async (_, _) => await OnInstallClickAsync().ConfigureAwait(true);

		_refresh = new Button
		{
			Text = "Refresh status",
			Width = 140,
			Height = 32,
			Location = new Point(200, 236),
		};
		_refresh.Click += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_backup = new Button
		{
			Text = "Backup Settings",
			Width = 160,
			Height = 32,
			Location = new Point(352, 236),
		};
		_backup.Click += async (_, _) => await OnBackupClickAsync().ConfigureAwait(true);

		_restore = new Button
		{
			Text = "Restore Registry/Policy Settings",
			Width = 260,
			Height = 32,
			Location = new Point(524, 236),
		};
		_restore.Click += async (_, _) => await OnRestoreClickAsync().ConfigureAwait(true);

		_status = new Label
		{
			Text = "Ready",
			AutoSize = false,
			Width = 1100,
			Height = 22,
			Location = new Point(12, 276),
		};

		_statusReport = new TextBox
		{
			Multiline = true,
			ScrollBars = ScrollBars.Vertical,
			ReadOnly = true,
			WordWrap = true,
			Font = new Font(FontFamily.GenericMonospace, 9.5f),
			Width = 1100,
			Height = 432,
			Location = new Point(12, 304),
		};

		Controls.Add(_title);
		Controls.Add(_purpose);
		Controls.Add(_versionLabel);
		Controls.Add(_projectLink);
		Controls.Add(_authorLabel);
		Controls.Add(_authorLink);
		Controls.Add(_emailLink);
		Controls.Add(_install);
		Controls.Add(_refresh);
		Controls.Add(_backup);
		Controls.Add(_restore);
		Controls.Add(_status);
		Controls.Add(_statusReport);

		HandleCreated += async (_, _) => await RefreshAsync().ConfigureAwait(true);
	}

	private static string GetProductVersion()
	{
		Assembly asm = Assembly.GetExecutingAssembly();
		string? info = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
		if (!string.IsNullOrWhiteSpace(info))
		{
			int plus = info.IndexOf('+', StringComparison.Ordinal);
			return plus < 0 ? info : info[..plus];
		}

		return asm.GetName().Version?.ToString() ?? "0.0.0";
	}

	private static void OpenUrl(string url)
	{
		try
		{
			Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
		}
		catch (Exception ex)
		{
			MessageBox.Show($"Could not open {url}\r\n{ex.Message}", "RdpAudit", MessageBoxButtons.OK, MessageBoxIcon.Warning);
		}
	}

	private async Task RefreshAsync()
	{
		_refresh.Enabled = false;
		_status.Text = "Probing local state...";
		try
		{
			OverviewSnapshot snapshot = await Task.Run(() => _probe.Capture()).ConfigureAwait(true);
			_statusReport.Text = FormatSnapshot(snapshot);
			_install.Text = snapshot.IsFirstRun ? "Install (first run)" : "Repair / Reinstall";
			_status.Text = snapshot.IsFirstRun
				? "First-run setup required."
				: snapshot.Errors.Count > 0
					? "Issues detected — review the report below."
					: "RdpAudit looks healthy.";
		}
		catch (Exception ex)
		{
			_status.Text = "Probe failed: " + ex.GetType().Name;
			_statusReport.Text = ex.ToString();
		}
		finally
		{
			_refresh.Enabled = true;
		}
	}

	private async Task OnInstallClickAsync()
	{
		_install.Enabled = false;
		_status.Text = "Running first-run install...";
		try
		{
			OverviewSnapshot snapshot = await Task.Run(() => _probe.Capture()).ConfigureAwait(true);
			InstallationService installer = new(snapshot.Layout);
			InstallationOutcome outcome = await installer.RunAsync().ConfigureAwait(true);

			StringBuilder sb = new();
			sb.AppendLine("=== Install steps ===");
			foreach (string step in outcome.Steps)
			{
				sb.AppendLine("- " + step);
			}

			if (outcome.Warnings.Count > 0)
			{
				sb.AppendLine();
				sb.AppendLine("=== Warnings ===");
				foreach (string w in outcome.Warnings)
				{
					sb.AppendLine("- " + w);
				}
			}

			if (outcome.Errors.Count > 0)
			{
				sb.AppendLine();
				sb.AppendLine("=== Errors ===");
				foreach (string e in outcome.Errors)
				{
					sb.AppendLine("- " + e);
				}
			}

			_statusReport.Text = sb.ToString();
			_status.Text = outcome.Success
				? "Installation completed."
				: "Installation finished with errors — see report.";
		}
		catch (Exception ex)
		{
			_status.Text = "Install failed: " + ex.GetType().Name;
			_statusReport.Text = ex.ToString();
		}
		finally
		{
			_install.Enabled = true;
			await RefreshAsync().ConfigureAwait(true);
		}
	}

	private async Task OnBackupClickAsync()
	{
		_backup.Enabled = false;
		_status.Text = "Capturing backup snapshot...";
		try
		{
			OverviewSnapshot snapshot = await Task.Run(() => _probe.Capture()).ConfigureAwait(true);
			BackupRunner runner = new(snapshot.Layout);
			BackupOutcome outcome = await runner.RunAsync(BackupReason.Manual).ConfigureAwait(true);

			StringBuilder sb = new();
			sb.AppendLine("=== Backup snapshot ===");
			sb.AppendLine("Folder: " + outcome.Snapshot.SnapshotDirectory);
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

			_statusReport.Text = sb.ToString();
			_status.Text = outcome.Success
				? "Backup completed: " + outcome.Snapshot.SnapshotDirectory
				: "Backup completed with errors — see report.";
		}
		catch (Exception ex)
		{
			_status.Text = "Backup failed: " + ex.GetType().Name;
			_statusReport.Text = ex.ToString();
		}
		finally
		{
			_backup.Enabled = true;
		}
	}

	private async Task OnRestoreClickAsync()
	{
		_restore.Enabled = false;
		_status.Text = "Preparing restore...";
		try
		{
			OverviewSnapshot snapshot = await Task.Run(() => _probe.Capture()).ConfigureAwait(true);
			BackupRunner runner = new(snapshot.Layout);
			IReadOnlyList<string> available = await Task.Run(runner.ListSnapshots).ConfigureAwait(true);
			if (available.Count == 0)
			{
				MessageBox.Show(
					"No backup snapshots are available yet. Use the Backup Settings button to capture one first.",
					"RdpAudit Restore",
					MessageBoxButtons.OK,
					MessageBoxIcon.Information);
				_status.Text = "Restore cancelled — no snapshots available.";
				return;
			}

			string selected = available[0];
			string confirm = string.Format(CultureInfo.InvariantCulture,
				"Restore registry/SACL and audit policy settings from snapshot {0}?\r\n\r\n"
				+ "A pre-restore safety snapshot will be captured automatically. The audit "
				+ "event database is NOT modified. Continue?",
				selected);
			DialogResult choice = MessageBox.Show(
				confirm,
				"RdpAudit Restore",
				MessageBoxButtons.YesNo,
				MessageBoxIcon.Warning,
				MessageBoxDefaultButton.Button2);
			if (choice != DialogResult.Yes)
			{
				_status.Text = "Restore cancelled by user.";
				return;
			}

			RestoreRunner restoreRunner = new(snapshot.Layout, runner);
			RestoreOutcome outcome = await restoreRunner.RunAsync(selected, RestoreScope.PoliciesAndRegistry).ConfigureAwait(true);

			StringBuilder sb = new();
			sb.AppendLine("=== Restore ===");
			sb.AppendLine("Source snapshot: " + selected);
			sb.AppendLine("Safety snapshot: " + outcome.SafetySnapshot.SnapshotDirectory);
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

			_statusReport.Text = sb.ToString();
			_status.Text = outcome.Success
				? "Restore completed."
				: "Restore completed with errors — see report.";
		}
		catch (Exception ex)
		{
			_status.Text = "Restore failed: " + ex.GetType().Name;
			_statusReport.Text = ex.ToString();
		}
		finally
		{
			_restore.Enabled = true;
		}
	}

	private static string FormatSnapshot(OverviewSnapshot s)
	{
		StringBuilder sb = new();
		sb.AppendLine("=== Installation status ===");
		sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "First-run required: {0}", s.IsFirstRun));
		sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "ProgramData folder: {0} (writable={1})", s.Layout.ProgramDataDirectory, s.ProgramDataWritable));
		sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "appsettings.json:   {0} ({1})", s.Layout.AppSettingsPath, s.AppSettingsExists ? "present" : "missing"));
		sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Database path:      {0} ({1})", s.DatabasePath, s.DatabaseExists ? "present" : "missing"));
		sb.AppendLine();
		sb.AppendLine("=== Service ===");
		sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Installed:    {0}", s.ServiceInstalled));
		sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Status:       {0}", s.ServiceStatus));
		sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Install dir:  {0}", s.Layout.InstallDirectory));
		sb.AppendLine();
		sb.AppendLine("=== Service distribution discovery ===");
		sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Configurator dir:  {0}", s.Layout.ConfiguratorDirectory));
		sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Distribution dir:  {0}", s.Layout.DistributionDirectory ?? "(not found)"));
		sb.AppendLine(string.Format(CultureInfo.InvariantCulture, "Service exe:       {0} ({1})", s.Layout.ExpectedServiceExecutable, s.Layout.ServiceExecutableExists ? "present" : "missing"));
		if (s.Warnings.Count > 0)
		{
			sb.AppendLine();
			sb.AppendLine("=== Warnings ===");
			foreach (string w in s.Warnings)
			{
				sb.AppendLine("- " + w);
			}
		}

		if (s.Errors.Count > 0)
		{
			sb.AppendLine();
			sb.AppendLine("=== Errors ===");
			foreach (string e in s.Errors)
			{
				sb.AppendLine("- " + e);
			}
		}

		return sb.ToString();
	}
}
