// File:    src/RdpAudit.Configurator/Forms/AttackStatisticsPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Stage 6 Attack Statistics tab. Mirrors the cameyo / rdpmon connection summary —
//          per-IP rows coloured green / yellow / red against the deterministic ThreatScore the
//          service-side AttackStatsRefreshWorker materialises. All reads route through the
//          GetAttackStats IPC command; the Configurator never opens the SQLite file directly.
//          Auto-refresh runs on a 5-second timer with a re-entry guard so a slow service round-
//          trip never queues a backlog of refresh calls. Operator actions reuse Stage 3 IPC
//          handlers (BlockAddress / UnblockAddress, AddToBlocklist / AddToWhitelist) so this tab
//          adds no new mutation surface.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.ComponentModel;
using System.Drawing;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Forms;

/// <summary>Stage 6 Attack Statistics tab.</summary>
[SupportedOSPlatform("windows")]
public sealed class AttackStatisticsPage : TabPage
{
	private static readonly Color GreenRow = Color.FromArgb(220, 248, 220);
	private static readonly Color YellowRow = Color.FromArgb(255, 247, 200);
	private static readonly Color RedRow = Color.FromArgb(255, 220, 220);

	private readonly IpcClient _ipc;

	private readonly StatusStrip _statusStrip;
	private readonly ToolStripStatusLabel _statusLabel;

	// Filter / toolbar -----------------------------------------------------------------------------
	private readonly TextBox _ipQueryBox;
	private readonly NumericUpDown _minThreatInput;
	private readonly CheckBox _onlyBlockedCheck;
	private readonly ComboBox _timeRangeCombo;
	private readonly NumericUpDown _limitInput;
	private readonly Button _refreshButton;
	private readonly CheckBox _autoRefreshCheck;

	// Grid ----------------------------------------------------------------------------------------
	private readonly DataGridView _grid;
	private readonly BindingList<AttackStatRow> _rows = new();
	private readonly List<AttackStatEntryDto> _all = new();

	// Right-click menu ----------------------------------------------------------------------------
	private readonly ContextMenuStrip _rowMenu;
	private readonly ToolStripMenuItem _copyRowItem;
	private readonly ToolStripMenuItem _blockIpItem;
	private readonly ToolStripMenuItem _whitelistIpItem;

	private readonly System.Windows.Forms.Timer _timer;
	private int _refreshInFlight;
	private AttackStatRow? _menuTargetRow;

	public AttackStatisticsPage(IpcClient ipc)
	{
		_ipc = ipc;
		Text = "Attack Statistics";

		_statusStrip = new StatusStrip { SizingGrip = false };
		_statusLabel = new ToolStripStatusLabel("Ready.")
		{
			Spring = true,
			TextAlign = System.Drawing.ContentAlignment.MiddleLeft,
		};
		_statusStrip.Items.Add(_statusLabel);

		// --- Filter toolbar --------------------------------------------------------------------
		TableLayoutPanel toolbar = new()
		{
			Dock = DockStyle.Top,
			ColumnCount = 12,
			RowCount = 1,
			Height = 38,
			Padding = new Padding(4),
			AutoSize = false,
		};
		for (int i = 0; i < 12; i++)
		{
			toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
		}

		_ipQueryBox = new TextBox { PlaceholderText = "Filter IP…", Width = 180 };
		_ipQueryBox.TextChanged += (_, _) => ApplyFilter();

		_minThreatInput = new NumericUpDown
		{
			Minimum = 0,
			Maximum = (decimal)AttackThreatScoring.ScoreMax,
			DecimalPlaces = 0,
			Width = 60,
		};
		_minThreatInput.ValueChanged += (_, _) => ApplyFilter();

		_onlyBlockedCheck = new CheckBox { Text = "Only blocked", AutoSize = true };
		_onlyBlockedCheck.CheckedChanged += (_, _) => ApplyFilter();

		_timeRangeCombo = new ComboBox
		{
			DropDownStyle = ComboBoxStyle.DropDownList,
			Width = 150,
		};
		_timeRangeCombo.Items.Add(new TimeRangeChoice("All time", null));
		_timeRangeCombo.Items.Add(new TimeRangeChoice("Last 5 minutes", TimeSpan.FromMinutes(5)));
		_timeRangeCombo.Items.Add(new TimeRangeChoice("Last 15 minutes", TimeSpan.FromMinutes(15)));
		_timeRangeCombo.Items.Add(new TimeRangeChoice("Last 1 hour", TimeSpan.FromHours(1)));
		_timeRangeCombo.Items.Add(new TimeRangeChoice("Last 24 hours", TimeSpan.FromHours(24)));
		_timeRangeCombo.Items.Add(new TimeRangeChoice("Last 7 days", TimeSpan.FromDays(7)));
		_timeRangeCombo.SelectedIndex = 0;
		_timeRangeCombo.SelectedIndexChanged += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_limitInput = new NumericUpDown
		{
			Minimum = 50,
			Maximum = 2000,
			Value = 500,
			Increment = 50,
			Width = 80,
		};
		_limitInput.ValueChanged += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_refreshButton = new Button { Text = "Refresh", AutoSize = true };
		_refreshButton.Click += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_autoRefreshCheck = new CheckBox { Text = "Auto-refresh", AutoSize = true, Checked = true };
		_timer = new System.Windows.Forms.Timer { Interval = 5_000 };
		_autoRefreshCheck.CheckedChanged += (_, _) =>
		{
			if (_autoRefreshCheck.Checked)
			{
				_timer.Start();
			}
			else
			{
				_timer.Stop();
			}
		};

		toolbar.Controls.Add(new Label { Text = "IP:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
		toolbar.Controls.Add(_ipQueryBox, 1, 0);
		toolbar.Controls.Add(new Label { Text = "Min threat:", AutoSize = true, Anchor = AnchorStyles.Left }, 2, 0);
		toolbar.Controls.Add(_minThreatInput, 3, 0);
		toolbar.Controls.Add(_onlyBlockedCheck, 4, 0);
		toolbar.Controls.Add(new Label { Text = "Range:", AutoSize = true, Anchor = AnchorStyles.Left }, 5, 0);
		toolbar.Controls.Add(_timeRangeCombo, 6, 0);
		toolbar.Controls.Add(new Label { Text = "Limit:", AutoSize = true, Anchor = AnchorStyles.Left }, 7, 0);
		toolbar.Controls.Add(_limitInput, 8, 0);
		toolbar.Controls.Add(_refreshButton, 9, 0);
		toolbar.Controls.Add(_autoRefreshCheck, 10, 0);

		// --- Grid ------------------------------------------------------------------------------
		_grid = new DataGridView
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			ReadOnly = true,
			RowHeadersVisible = false,
			AllowUserToAddRows = false,
			AllowUserToDeleteRows = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = false,
			DataSource = _rows,
		};
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "IP", DataPropertyName = nameof(AttackStatRow.Ip), Width = 140 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Threat", DataPropertyName = nameof(AttackStatRow.ThreatScoreText), Width = 70 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Status", DataPropertyName = nameof(AttackStatRow.StatusText), Width = 90 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Total", DataPropertyName = nameof(AttackStatRow.TotalAttempts), Width = 70 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Failed", DataPropertyName = nameof(AttackStatRow.Failed), Width = 70 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Successful", DataPropertyName = nameof(AttackStatRow.Successful), Width = 80 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "First seen (UTC)", DataPropertyName = nameof(AttackStatRow.FirstSeenText), Width = 150 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Last seen (UTC)", DataPropertyName = nameof(AttackStatRow.LastSeenText), Width = 150 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Duration", DataPropertyName = nameof(AttackStatRow.DurationText), Width = 90 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Top logins", DataPropertyName = nameof(AttackStatRow.TopLoginsText), Width = 220 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Last logon type", DataPropertyName = nameof(AttackStatRow.LastLoginTypeText), Width = 90 });
		_grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Blocked", DataPropertyName = nameof(AttackStatRow.BlockedText), Width = 70 });

		_grid.RowPrePaint += (_, e) => ColorRow(e.RowIndex);
		_grid.CellMouseDown += OnGridCellMouseDown;
		_grid.CellDoubleClick += OnGridCellDoubleClick;

		// --- Right-click menu ------------------------------------------------------------------
		_rowMenu = new ContextMenuStrip();
		_copyRowItem = new ToolStripMenuItem("Copy row");
		_copyRowItem.Click += (_, _) => CopySelectedRow();
		_blockIpItem = new ToolStripMenuItem("Block IP (BlockAddress + AddToBlocklist)");
		_blockIpItem.Click += async (_, _) => await BlockSelectedAsync().ConfigureAwait(true);
		_whitelistIpItem = new ToolStripMenuItem("Whitelist IP (AddToWhitelist + UnblockAddress)");
		_whitelistIpItem.Click += async (_, _) => await WhitelistSelectedAsync().ConfigureAwait(true);
		_rowMenu.Items.Add(_copyRowItem);
		_rowMenu.Items.Add(new ToolStripSeparator());
		_rowMenu.Items.Add(_blockIpItem);
		_rowMenu.Items.Add(_whitelistIpItem);

		// Order matters: docked panels added later sit closer to the top edge.
		Controls.Add(_grid);
		Controls.Add(_statusStrip);
		Controls.Add(toolbar);

		_timer.Tick += async (_, _) =>
		{
			if (!_autoRefreshCheck.Checked)
			{
				return;
			}
			await RefreshAsync().ConfigureAwait(true);
		};
		HandleCreated += async (_, _) =>
		{
			_timer.Start();
			await RefreshAsync().ConfigureAwait(true);
		};
	}

	// ----------------------------------------------------------------------------------------------
	// Refresh + IPC
	// ----------------------------------------------------------------------------------------------

	private async Task RefreshAsync()
	{
		if (Interlocked.CompareExchange(ref _refreshInFlight, 1, 0) == 1)
		{
			return;
		}

		try
		{
			AttackStatsRequest req = BuildRequest();
			AttackStatsDto? dto = await _ipc.SendAsync<AttackStatsDto>(IpcCommand.GetAttackStats, req).ConfigureAwait(true);

			if (dto is null)
			{
				SetStatus("Refresh FAILED: service unreachable.");
				return;
			}

			_all.Clear();
			_all.AddRange(dto.Entries);
			ApplyFilter();

			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"Refresh OK. entries={0} matching={1} limit={2} window={3:HH:mm:ss}Z..{4:HH:mm:ss}Z",
				dto.Entries.Count, dto.TotalMatching, dto.AppliedLimit, dto.WindowStartUtc, dto.WindowEndUtc));
		}
		catch (Exception ex)
		{
			SetStatus("Refresh FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
		finally
		{
			Volatile.Write(ref _refreshInFlight, 0);
		}
	}

	private AttackStatsRequest BuildRequest()
	{
		AttackStatsRequest req = new()
		{
			IpQuery = string.IsNullOrWhiteSpace(_ipQueryBox.Text) ? null : _ipQueryBox.Text.Trim(),
			MinThreatScore = _minThreatInput.Value > 0 ? (double)_minThreatInput.Value : null,
			OnlyBlocked = _onlyBlockedCheck.Checked,
			Limit = (int)_limitInput.Value,
		};

		if (_timeRangeCombo.SelectedItem is TimeRangeChoice choice && choice.Window is TimeSpan span)
		{
			req.UntilUtc = DateTime.UtcNow;
			req.SinceUtc = req.UntilUtc - span;
		}

		return req;
	}

	private void ApplyFilter()
	{
		AttackStatsFilter filter = new()
		{
			IpQuery = string.IsNullOrWhiteSpace(_ipQueryBox.Text) ? null : _ipQueryBox.Text.Trim(),
			MinThreatScore = _minThreatInput.Value > 0 ? (double)_minThreatInput.Value : null,
			OnlyBlocked = _onlyBlockedCheck.Checked,
		};

		_rows.RaiseListChangedEvents = false;
		_rows.Clear();
		foreach (AttackStatEntryDto entry in _all)
		{
			if (filter.Matches(entry))
			{
				_rows.Add(AttackStatRow.From(entry));
			}
		}
		_rows.RaiseListChangedEvents = true;
		_rows.ResetBindings();
	}

	private void ColorRow(int rowIndex)
	{
		if (rowIndex < 0 || rowIndex >= _rows.Count)
		{
			return;
		}

		AttackStatRow row = _rows[rowIndex];
		Color colour = row.ThreatLevel switch
		{
			AttackThreatLevel.Red => RedRow,
			AttackThreatLevel.Yellow => YellowRow,
			_ => GreenRow,
		};
		_grid.Rows[rowIndex].DefaultCellStyle.BackColor = colour;
	}

	// ----------------------------------------------------------------------------------------------
	// Row actions
	// ----------------------------------------------------------------------------------------------

	private void OnGridCellMouseDown(object? sender, DataGridViewCellMouseEventArgs e)
	{
		if (e.Button != MouseButtons.Right || e.RowIndex < 0 || e.RowIndex >= _rows.Count)
		{
			return;
		}

		_grid.ClearSelection();
		_grid.Rows[e.RowIndex].Selected = true;
		_menuTargetRow = _rows[e.RowIndex];

		bool ipPresent = !string.IsNullOrWhiteSpace(_menuTargetRow.Ip);
		_blockIpItem.Enabled = ipPresent;
		_whitelistIpItem.Enabled = ipPresent;
		_copyRowItem.Enabled = true;

		_rowMenu.Show(_grid, _grid.PointToClient(Cursor.Position));
	}

	private void OnGridCellDoubleClick(object? sender, DataGridViewCellEventArgs e)
	{
		if (e.RowIndex < 0 || e.RowIndex >= _rows.Count)
		{
			return;
		}

		_menuTargetRow = _rows[e.RowIndex];
		CopySelectedRow();
	}

	private void CopySelectedRow()
	{
		if (_menuTargetRow is null)
		{
			return;
		}

		try
		{
			Clipboard.SetText(_menuTargetRow.ToTabSeparated());
			SetStatus("Row copied to clipboard.");
		}
		catch (Exception ex)
		{
			SetStatus("Copy FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	private async Task BlockSelectedAsync()
	{
		AttackStatRow? row = _menuTargetRow;
		if (row is null || string.IsNullOrWhiteSpace(row.Ip))
		{
			SetStatus("Block aborted: no row / IP.");
			return;
		}

		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Block {0}?\r\n\r\nThis routes through AddToBlocklist (with whitelist precedence) and "
			+ "the legacy BlockAddress to install a Windows Firewall rule when the service is on a "
			+ "Windows host.", row.Ip);
		if (!Confirm(prompt, "Confirm block"))
		{
			SetStatus("Block cancelled.");
			return;
		}

		bool blOk;
		try
		{
			AddressListMutationRequest req = new()
			{
				Address = row.Ip,
				Note = "Configurator Attack Statistics tab manual block",
			};
			JsonElement? resp = await _ipc.SendAsync<JsonElement?>(IpcCommand.AddToBlocklist, req).ConfigureAwait(true);
			blOk = resp is not null;
		}
		catch
		{
			blOk = false;
		}

		bool fwOk;
		try
		{
			bool? legacy = await _ipc.SendAsync<bool?>(IpcCommand.BlockAddress, row.Ip).ConfigureAwait(true);
			fwOk = legacy == true;
		}
		catch
		{
			fwOk = false;
		}

		SetStatus(string.Format(CultureInfo.InvariantCulture,
			"Block {0}: blocklist={1}, firewall={2}",
			row.Ip, blOk ? "OK" : "FAIL", fwOk ? "OK" : "FAIL"));
		await RefreshAsync().ConfigureAwait(true);
	}

	private async Task WhitelistSelectedAsync()
	{
		AttackStatRow? row = _menuTargetRow;
		if (row is null || string.IsNullOrWhiteSpace(row.Ip))
		{
			SetStatus("Whitelist aborted: no row / IP.");
			return;
		}

		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Whitelist {0}?\r\n\r\nThis routes through AddToWhitelist and the legacy UnblockAddress "
			+ "to remove any matching Windows Firewall rule.", row.Ip);
		if (!Confirm(prompt, "Confirm whitelist"))
		{
			SetStatus("Whitelist cancelled.");
			return;
		}

		bool wlOk;
		try
		{
			AddressListMutationRequest req = new()
			{
				Address = row.Ip,
				Note = "Configurator Attack Statistics tab manual whitelist",
			};
			JsonElement? resp = await _ipc.SendAsync<JsonElement?>(IpcCommand.AddToWhitelist, req).ConfigureAwait(true);
			wlOk = resp is not null;
		}
		catch
		{
			wlOk = false;
		}

		bool unblockOk;
		try
		{
			bool? legacy = await _ipc.SendAsync<bool?>(IpcCommand.UnblockAddress, row.Ip).ConfigureAwait(true);
			unblockOk = legacy == true;
		}
		catch
		{
			unblockOk = false;
		}

		SetStatus(string.Format(CultureInfo.InvariantCulture,
			"Whitelist {0}: whitelist={1}, unblock={2}",
			row.Ip, wlOk ? "OK" : "FAIL", unblockOk ? "OK" : "FAIL"));
		await RefreshAsync().ConfigureAwait(true);
	}

	// ----------------------------------------------------------------------------------------------
	// Helpers
	// ----------------------------------------------------------------------------------------------

	private static bool Confirm(string message, string caption) =>
		MessageBox.Show(message, caption, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes;

	private void SetStatus(string message)
	{
		string stamped = string.Format(CultureInfo.InvariantCulture,
			"[{0:HH:mm:ss}Z] {1}", DateTime.UtcNow, message);
		if (_statusStrip.InvokeRequired)
		{
			_statusStrip.BeginInvoke(new Action(() => _statusLabel.Text = stamped));
		}
		else
		{
			_statusLabel.Text = stamped;
		}
	}

	protected override void Dispose(bool disposing)
	{
		if (disposing)
		{
			_timer.Dispose();
			_rowMenu.Dispose();
		}

		base.Dispose(disposing);
	}

	// ----------------------------------------------------------------------------------------------
	// View-models exposed for grid binding (sealed; values are computed once at construction).
	// ----------------------------------------------------------------------------------------------

	private sealed record TimeRangeChoice(string Display, TimeSpan? Window)
	{
		public override string ToString() => Display;
	}

	/// <summary>Grid view-model for a single attack statistics row.</summary>
	public sealed class AttackStatRow
	{
		public string Ip { get; init; } = string.Empty;

		public AttackThreatLevel ThreatLevel { get; init; }

		public string StatusText { get; init; } = string.Empty;

		public string ThreatScoreText { get; init; } = string.Empty;

		public long TotalAttempts { get; init; }

		public long Failed { get; init; }

		public long Successful { get; init; }

		public string FirstSeenText { get; init; } = string.Empty;

		public string LastSeenText { get; init; } = string.Empty;

		public string DurationText { get; init; } = string.Empty;

		public string TopLoginsText { get; init; } = string.Empty;

		public string LastLoginTypeText { get; init; } = string.Empty;

		public string BlockedText { get; init; } = string.Empty;

		public static AttackStatRow From(AttackStatEntryDto dto)
		{
			IReadOnlyList<string> logins = AttackStatProjection.DeserializeTopLogins(dto.Top10AttemptedLogins);
			return new AttackStatRow
			{
				Ip = dto.Ip,
				ThreatLevel = dto.ThreatLevel,
				StatusText = dto.ThreatLevel.ToString(),
				ThreatScoreText = dto.ThreatScore.ToString("F1", CultureInfo.InvariantCulture),
				TotalAttempts = dto.TotalAttempts,
				Failed = dto.Failed,
				Successful = dto.Successful,
				FirstSeenText = FormatUtc(dto.FirstSeenUtc),
				LastSeenText = FormatUtc(dto.LastSeenUtc),
				DurationText = FormatDuration(dto.DurationSeconds),
				TopLoginsText = string.Join(", ", logins),
				LastLoginTypeText = dto.LastLoginType?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
				BlockedText = dto.IsBlocked ? "yes" : "no",
			};
		}

		internal string ToTabSeparated()
		{
			StringBuilder sb = new();
			sb.Append(Ip).Append('\t')
				.Append(ThreatScoreText).Append('\t')
				.Append(StatusText).Append('\t')
				.Append(TotalAttempts.ToString(CultureInfo.InvariantCulture)).Append('\t')
				.Append(Failed.ToString(CultureInfo.InvariantCulture)).Append('\t')
				.Append(Successful.ToString(CultureInfo.InvariantCulture)).Append('\t')
				.Append(FirstSeenText).Append('\t')
				.Append(LastSeenText).Append('\t')
				.Append(DurationText).Append('\t')
				.Append(TopLoginsText).Append('\t')
				.Append(LastLoginTypeText).Append('\t')
				.Append(BlockedText);
			return sb.ToString();
		}

		private static string FormatUtc(DateTime value) =>
			value == default
				? string.Empty
				: value.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

		private static string FormatDuration(long seconds)
		{
			if (seconds < 0)
			{
				return string.Empty;
			}
			TimeSpan span = TimeSpan.FromSeconds(seconds);
			if (span.TotalDays >= 1)
			{
				return string.Format(CultureInfo.InvariantCulture,
					"{0}d {1:D2}:{2:D2}:{3:D2}",
					(int)span.TotalDays, span.Hours, span.Minutes, span.Seconds);
			}
			return string.Format(CultureInfo.InvariantCulture,
				"{0:D2}:{1:D2}:{2:D2}",
				(int)span.TotalHours, span.Minutes, span.Seconds);
		}
	}
}
