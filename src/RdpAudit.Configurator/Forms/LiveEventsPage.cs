// File:    src/RdpAudit.Configurator/Forms/LiveEventsPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Live tail of recent events. Uses IPC GetRecentEvents — never opens the SQLite file
//          directly so we honour the service's Storage.DatabasePath setting.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Ipc;

namespace RdpAudit.Configurator.Forms;

/// <summary>Live tail of recent events fetched over IPC.</summary>
[SupportedOSPlatform("windows")]
public sealed class LiveEventsPage : TabPage
{
	private readonly IpcClient _ipc;
	private readonly DataGridView _grid;
	private readonly Label _info;
	private readonly Button _pause;
	private readonly System.Windows.Forms.Timer _timer;
	private bool _paused;
	private long _lastSeenId;

	public LiveEventsPage(IpcClient ipc)
	{
		_ipc = ipc;
		_grid = new DataGridView
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			ReadOnly = true,
			RowHeadersVisible = false,
			AllowUserToAddRows = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
		};
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Id", DataPropertyName = nameof(LiveEventRow.Id), Width = 70 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Time (UTC)", DataPropertyName = nameof(LiveEventRow.TimeUtc), Width = 160 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Event", DataPropertyName = nameof(LiveEventRow.EventId), Width = 70 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Channel", DataPropertyName = nameof(LiveEventRow.Channel), Width = 220 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "User", DataPropertyName = nameof(LiveEventRow.UserName), Width = 140 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "IP", DataPropertyName = nameof(LiveEventRow.SourceIp), Width = 130 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "LogonType", DataPropertyName = nameof(LiveEventRow.LogonType), Width = 80 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Process", DataPropertyName = nameof(LiveEventRow.ProcessName), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });

		_info = new Label { Dock = DockStyle.Top, Height = 22, Text = "Waiting for first event…" };

		_pause = new Button { Text = "Pause", Dock = DockStyle.Top, Height = 26 };
		_pause.Click += (_, _) =>
		{
			_paused = !_paused;
			_pause.Text = _paused ? "Resume" : "Pause";
		};

		Controls.Add(_grid);
		Controls.Add(_info);
		Controls.Add(_pause);

		_timer = new System.Windows.Forms.Timer { Interval = 2_000 };
		_timer.Tick += async (_, _) => await RefreshAsync().ConfigureAwait(true);
		HandleCreated += async (_, _) =>
		{
			_timer.Start();
			await RefreshAsync().ConfigureAwait(true);
		};
	}

	private async Task RefreshAsync()
	{
		if (_paused)
		{
			return;
		}

		try
		{
			List<LiveEventRow>? rows = await _ipc.SendAsync<List<LiveEventRow>>(IpcCommand.GetRecentEvents).ConfigureAwait(true);
			rows ??= new List<LiveEventRow>();

			_grid.DataSource = rows;
			if (rows.Count > 0)
			{
				long latest = rows[0].Id;
				int newRows = rows.Count(r => r.Id > _lastSeenId);
				_lastSeenId = latest;
				_info.Text = string.Format(CultureInfo.InvariantCulture,
					"Latest id={0}  |  shown={1}  |  new since last refresh={2}",
					latest, rows.Count, newRows);
			}
			else
			{
				_info.Text = "No events recorded yet (or service unreachable).";
			}
		}
		catch (Exception ex)
		{
			_info.Text = $"IPC read failed: {ex.GetType().Name}: {ex.Message}";
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

	/// <summary>DTO used for the live tail grid binding (matches the IPC GetRecentEvents projection).</summary>
	public sealed class LiveEventRow
	{
		[JsonPropertyName("id")] public long Id { get; set; }
		[JsonPropertyName("eventId")] public int EventId { get; set; }
		[JsonPropertyName("channel")] public string? Channel { get; set; }
		[JsonPropertyName("timeUtc")] public DateTime TimeUtc { get; set; }
		[JsonPropertyName("sourceIp")] public string? SourceIp { get; set; }
		[JsonPropertyName("userName")] public string? UserName { get; set; }
		[JsonPropertyName("domain")] public string? Domain { get; set; }
		[JsonPropertyName("logonType")] public int? LogonType { get; set; }
		[JsonPropertyName("authPackage")] public string? AuthPackage { get; set; }
		[JsonPropertyName("processName")] public string? ProcessName { get; set; }
	}
}
