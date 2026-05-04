// File:    src/RdpAudit.Configurator/Forms/LiveEventsPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Live tail of the RawEvents table, polling the read-only DB context every 2 seconds.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Models;

namespace RdpAudit.Configurator.Forms;

/// <summary>Live tail of the RawEvents table.</summary>
[SupportedOSPlatform("windows")]
public sealed class LiveEventsPage : TabPage
{
	private readonly DataGridView _grid;
	private readonly Label _info;
	private readonly Button _pause;
	private readonly System.Windows.Forms.Timer _timer;
	private bool _paused;
	private long _lastSeenId;

	public LiveEventsPage()
	{
		_grid = new DataGridView
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			ReadOnly = true,
			RowHeadersVisible = false,
			AllowUserToAddRows = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
		};
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Id", DataPropertyName = nameof(RawEvent.Id), Width = 70 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Time (UTC)", DataPropertyName = nameof(RawEvent.TimeUtc), Width = 160 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Event", DataPropertyName = nameof(RawEvent.EventId), Width = 70 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Channel", DataPropertyName = nameof(RawEvent.Channel), Width = 220 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "User", DataPropertyName = nameof(RawEvent.UserName), Width = 140 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "IP", DataPropertyName = nameof(RawEvent.SourceIp), Width = 130 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "LogonType", DataPropertyName = nameof(RawEvent.LogonType), Width = 80 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Process", DataPropertyName = nameof(RawEvent.ProcessName), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });

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
		_timer.Tick += async (_, _) => await RefreshAsync().ConfigureAwait(false);
		HandleCreated += async (_, _) =>
		{
			_timer.Start();
			await RefreshAsync().ConfigureAwait(false);
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
			List<RawEvent> rows;
			await using (var db = ReadOnlyDb.Open())
			{
				rows = await db.RawEvents
					.AsNoTracking()
					.OrderByDescending(e => e.Id)
					.Take(500)
					.ToListAsync()
					.ConfigureAwait(false);
			}

			void apply()
			{
				_grid.DataSource = rows;
				if (rows.Count > 0)
				{
					long latest = rows[0].Id;
					int newRows = rows.Count(r => r.Id > _lastSeenId);
					_lastSeenId = latest;
					_info.Text = $"Latest id={latest}  |  shown={rows.Count}  |  new since last refresh={newRows}";
				}
				else
				{
					_info.Text = "No events recorded yet.";
				}
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
		catch (Exception ex)
		{
			void showError() => _info.Text = $"DB read failed: {ex.Message}";
			if (InvokeRequired)
			{
				Invoke(showError);
			}
			else
			{
				showError();
			}
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
