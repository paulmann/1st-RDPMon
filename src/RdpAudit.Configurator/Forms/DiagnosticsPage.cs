// File:    src/RdpAudit.Configurator/Forms/DiagnosticsPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Diagnostic tab — renders the LLM-friendly DiagnosticsSnapshotDto returned by the
//          service. Shows effective channels and event IDs, Security watcher / backfill state,
//          DB counts grouped by channel and event ID, the most recent monitoring-config repair
//          report, the install path, and last pipeline errors. Operators can Copy the rendered
//          report to the clipboard or Export it to a timestamped .txt file. All DB lookups run
//          via Microsoft.Data.Sqlite through EF Core on the service side; no external sqlite3.exe
//          dependency is introduced.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Configurator.Forms;

/// <summary>Diagnostic tab — renders the LLM-friendly DiagnosticsSnapshotDto returned by the service.</summary>
[SupportedOSPlatform("windows")]
public sealed class DiagnosticsPage : TabPage
{
	private readonly IpcClient _ipc;
	private readonly TextBox _report;
	private readonly Button _refresh;
	private readonly Button _copy;
	private readonly Button _export;
	private readonly Label _status;

	public DiagnosticsPage(IpcClient ipc)
	{
		_ipc = ipc;
		Text = "Diagnostic";
		Padding = new Padding(8);

		FlowLayoutPanel toolbar = new()
		{
			Dock = DockStyle.Top,
			Height = 36,
			AutoSize = false,
			FlowDirection = FlowDirection.LeftToRight,
		};

		_refresh = new Button { Text = "Refresh", Width = 110 };
		_copy = new Button { Text = "Copy to clipboard", Width = 150 };
		_export = new Button { Text = "Export to file…", Width = 150 };
		_refresh.Click += async (_, _) => await RefreshAsync().ConfigureAwait(true);
		_copy.Click += OnCopy;
		_export.Click += OnExport;

		toolbar.Controls.AddRange(new Control[] { _refresh, _copy, _export });

		_status = new Label
		{
			Dock = DockStyle.Top,
			Height = 22,
			Text = "Awaiting first refresh…",
			AutoSize = false,
			TextAlign = ContentAlignment.MiddleLeft,
			Padding = new Padding(4, 2, 4, 2),
		};

		_report = new TextBox
		{
			Dock = DockStyle.Fill,
			Multiline = true,
			ReadOnly = true,
			ScrollBars = ScrollBars.Both,
			WordWrap = false,
			Font = new Font(FontFamily.GenericMonospace, 9f),
		};

		Controls.Add(_report);
		Controls.Add(_status);
		Controls.Add(toolbar);

		HandleCreated += async (_, _) => await RefreshAsync().ConfigureAwait(true);
	}

	private async Task RefreshAsync()
	{
		_status.Text = "Refreshing…";
		try
		{
			DiagnosticsSnapshotDto? snapshot = await _ipc.SendAsync<DiagnosticsSnapshotDto>(IpcCommand.GetDiagnostics).ConfigureAwait(true);
			if (snapshot is null)
			{
				_status.Text = "Service: IPC GetDiagnostics returned nothing — is the service running?";
				_report.Text = "No diagnostics available. Start the service or run as administrator and retry.";
				return;
			}

			_report.Text = DiagnosticsReportFormatter.Format(snapshot);
			_status.Text = string.Format(
				CultureInfo.InvariantCulture,
				"Snapshot at {0:yyyy-MM-dd HH:mm:ss}Z  |  Status={1}  |  RawEvents={2}  AuthAttemptFacts={3}",
				snapshot.GeneratedUtc,
				snapshot.Status,
				snapshot.RawEventsTotal,
				snapshot.AuthAttemptFactsTotal);
		}
		catch (Exception ex)
		{
			_status.Text = "Service: error — " + ex.GetType().Name;
			_report.Text = ex.Message;
		}
	}

	private void OnCopy(object? sender, EventArgs e)
	{
		if (string.IsNullOrEmpty(_report.Text))
		{
			return;
		}

		try
		{
			Clipboard.SetText(_report.Text);
			_status.Text = "Copied diagnostics to clipboard.";
		}
		catch (Exception ex)
		{
			_status.Text = "Clipboard copy failed: " + ex.Message;
		}
	}

	private void OnExport(object? sender, EventArgs e)
	{
		if (string.IsNullOrEmpty(_report.Text))
		{
			return;
		}

		using SaveFileDialog dlg = new()
		{
			Title = "Export RdpAudit diagnostics",
			Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
			FileName = string.Format(
				CultureInfo.InvariantCulture,
				"rdpaudit-diagnostics-{0:yyyyMMdd-HHmmss}.txt",
				DateTime.UtcNow),
			OverwritePrompt = true,
		};
		if (dlg.ShowDialog(FindForm()) != DialogResult.OK)
		{
			return;
		}

		try
		{
			File.WriteAllText(dlg.FileName, _report.Text, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
			_status.Text = "Exported diagnostics to " + dlg.FileName;
		}
		catch (Exception ex)
		{
			_status.Text = "Export failed: " + ex.Message;
		}
	}
}

/// <summary>Pure formatter that turns a <see cref="DiagnosticsSnapshotDto"/> into a flat,
/// monospace-friendly report. Pulled out of the TabPage so it can be unit-tested without WinForms
/// and so the same string can be piped to either the clipboard or an exported .txt.</summary>
public static class DiagnosticsReportFormatter
{
	/// <summary>Format the snapshot for the Diagnostic tab. Always English; never throws.</summary>
	public static string Format(DiagnosticsSnapshotDto dto)
	{
		ArgumentNullException.ThrowIfNull(dto);
		StringBuilder sb = new();
		sb.AppendLine("RdpAudit diagnostics snapshot");
		sb.AppendLine("============================");
		sb.AppendFormat(CultureInfo.InvariantCulture, "Generated (UTC):       {0:O}", dto.GeneratedUtc).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Result status:         {0}", dto.Status).AppendLine();
		if (!string.IsNullOrWhiteSpace(dto.Message))
		{
			sb.AppendFormat(CultureInfo.InvariantCulture, "Message:               {0}", dto.Message).AppendLine();
		}
		sb.AppendFormat(CultureInfo.InvariantCulture, "Service version:       {0}", dto.ServiceVersion ?? "(unknown)").AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Install path:          {0}", dto.InstallPath ?? "(unknown)").AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Database path:         {0}", dto.DatabasePath ?? "(unknown)").AppendLine();
		sb.AppendLine();

		sb.AppendLine("Effective monitoring configuration");
		sb.AppendLine("----------------------------------");
		sb.AppendFormat(CultureInfo.InvariantCulture, "Channels ({0}):", dto.EnabledChannels.Count).AppendLine();
		if (dto.EnabledChannels.Count == 0)
		{
			sb.AppendLine("  (none — falling back to EventCatalog defaults)");
		}
		else
		{
			foreach (string c in dto.EnabledChannels)
			{
				sb.AppendFormat(CultureInfo.InvariantCulture, "  - {0}", c).AppendLine();
			}
		}
		sb.AppendFormat(CultureInfo.InvariantCulture, "Event IDs filter ({0}):", dto.EnabledEventIds.Count).AppendLine();
		if (dto.EnabledEventIds.Count == 0)
		{
			sb.AppendLine("  (empty — every catalog event ID for the enabled channels)");
		}
		else
		{
			sb.AppendFormat(CultureInfo.InvariantCulture, "  {0}", string.Join(", ", dto.EnabledEventIds)).AppendLine();
		}
		sb.AppendLine();

		sb.AppendLine("Monitoring config repair (stale appsettings.json)");
		sb.AppendLine("-------------------------------------------------");
		sb.AppendFormat(CultureInfo.InvariantCulture, "Changed this run:      {0}", dto.MonitoringConfigRepairChanged).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Changed runs (total):  {0}", dto.MonitoringConfigRepairChangedRunCount).AppendLine();
		if (dto.MonitoringConfigRepairUtc is DateTime repUtc)
		{
			sb.AppendFormat(CultureInfo.InvariantCulture, "Last run (UTC):        {0:O}", repUtc).AppendLine();
		}
		if (dto.MonitoringConfigRepairAddedChannels.Count > 0)
		{
			sb.AppendFormat(CultureInfo.InvariantCulture, "Added channels:        {0}", string.Join(", ", dto.MonitoringConfigRepairAddedChannels)).AppendLine();
		}
		if (dto.MonitoringConfigRepairAddedEventIds.Count > 0)
		{
			sb.AppendFormat(CultureInfo.InvariantCulture, "Added event IDs:       {0}", string.Join(", ", dto.MonitoringConfigRepairAddedEventIds)).AppendLine();
		}
		if (!string.IsNullOrWhiteSpace(dto.MonitoringConfigRepairReason))
		{
			sb.AppendFormat(CultureInfo.InvariantCulture, "Reason:                {0}", dto.MonitoringConfigRepairReason).AppendLine();
		}
		sb.AppendLine();

		sb.AppendLine("Per-channel collector status");
		sb.AppendLine("----------------------------");
		if (dto.ChannelStatus.Count == 0)
		{
			sb.AppendLine("  (no channel arm/restart events recorded yet)");
		}
		else
		{
			foreach (KeyValuePair<string, string> kv in dto.ChannelStatus)
			{
				sb.AppendFormat(CultureInfo.InvariantCulture, "  {0,-70} {1}", kv.Key, kv.Value).AppendLine();
			}
		}
		sb.AppendLine();

		sb.AppendLine("Security watcher & backfill");
		sb.AppendLine("---------------------------");
		sb.AppendFormat(CultureInfo.InvariantCulture, "Watcher armed:                  {0}", dto.SecurityWatcherEnabled).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Events read (live):             {0}", dto.SecurityEventsRead).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Events normalized:              {0}", dto.SecurityEventsNormalized).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Events rejected:                {0}", dto.SecurityEventsRejected).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Security 4624 / 4625 / 4648:    {0} / {1} / {2}", dto.Security4624Count, dto.Security4625Count, dto.Security4648Count).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Last Security event (UTC):      {0}", dto.LastSecurityEventUtc?.ToString("O", CultureInfo.InvariantCulture) ?? "(never)").AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Last Security channel error:    {0}", dto.LastSecurityChannelError ?? "(none)").AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Backfill last run (UTC):        {0}", dto.SecurityBackfillLastRunUtc?.ToString("O", CultureInfo.InvariantCulture) ?? "(never)").AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Backfill read / fwd / dup:      {0} / {1} / {2}", dto.SecurityBackfillRecordsRead, dto.SecurityBackfillRecordsForwarded, dto.SecurityBackfillRecordsDeduped).AppendLine();
		sb.AppendLine();

		sb.AppendLine("AuthAttemptFact counters");
		sb.AppendLine("------------------------");
		sb.AppendFormat(CultureInfo.InvariantCulture, "Created (failed+succeeded):     {0}", dto.AuthAttemptFactCreated).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Failed:                         {0}", dto.AuthAttemptFactFailed).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Succeeded:                      {0}", dto.AuthAttemptFactSucceeded).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "Last created (UTC):             {0}", dto.LastAuthAttemptFactCreatedUtc?.ToString("O", CultureInfo.InvariantCulture) ?? "(never)").AppendLine();
		sb.AppendLine();

		sb.AppendLine("Database counts (EF Core / Microsoft.Data.Sqlite)");
		sb.AppendLine("-------------------------------------------------");
		sb.AppendFormat(CultureInfo.InvariantCulture, "RawEvents total:                {0}", dto.RawEventsTotal).AppendLine();
		sb.AppendFormat(CultureInfo.InvariantCulture, "AuthAttemptFacts total:         {0}", dto.AuthAttemptFactsTotal).AppendLine();
		sb.AppendLine();

		sb.AppendLine("RawEvents grouped by channel");
		sb.AppendLine("-----------------------------");
		if (dto.RawEventsByChannel.Count == 0)
		{
			sb.AppendLine("  (no rows)");
		}
		else
		{
			foreach (DiagnosticsChannelCount row in dto.RawEventsByChannel)
			{
				sb.AppendFormat(CultureInfo.InvariantCulture, "  {0,10}  {1}", row.Count, row.Channel).AppendLine();
			}
		}
		sb.AppendLine();

		sb.AppendLine("RawEvents grouped by event ID (top 30)");
		sb.AppendLine("---------------------------------------");
		if (dto.RawEventsByEventId.Count == 0)
		{
			sb.AppendLine("  (no rows)");
		}
		else
		{
			foreach (DiagnosticsEventIdCount row in dto.RawEventsByEventId)
			{
				sb.AppendFormat(CultureInfo.InvariantCulture, "  {0,10}  {1,6}  {2}", row.Count, row.EventId, row.Channel).AppendLine();
			}
		}
		sb.AppendLine();

		sb.AppendLine("AuthAttemptFacts grouped by EvidenceEventId / Outcome (top 30)");
		sb.AppendLine("---------------------------------------------------------------");
		if (dto.AuthAttemptFactsByOutcome.Count == 0)
		{
			sb.AppendLine("  (no rows)");
		}
		else
		{
			foreach (DiagnosticsFactOutcomeCount row in dto.AuthAttemptFactsByOutcome)
			{
				sb.AppendFormat(CultureInfo.InvariantCulture, "  {0,10}  {1,6}  {2}", row.Count, row.EvidenceEventId, row.Outcome).AppendLine();
			}
		}
		sb.AppendLine();

		sb.AppendLine("Recent pipeline errors");
		sb.AppendLine("----------------------");
		if (dto.RecentPipelineErrors.Count == 0)
		{
			sb.AppendLine("  (none)");
		}
		else
		{
			foreach (string err in dto.RecentPipelineErrors)
			{
				sb.AppendFormat(CultureInfo.InvariantCulture, "  - {0}", err).AppendLine();
			}
		}

		return sb.ToString();
	}
}
