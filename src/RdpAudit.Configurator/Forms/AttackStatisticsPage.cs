// File:    src/RdpAudit.Configurator/Forms/AttackStatisticsPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Stage 6B SOC-operator Attack Statistics tab. Consumes the Stage 6A GetAttackStats IPC
//          contract only — the Configurator never opens the SQLite file directly. Renders one row
//          per attacker IP with a cameyo / rdpmon-style green / yellow / red threat band, a filter
//          toolbar (IP search, min threat score, only-blocked, recent-period preset, limit), an
//          optional 5-second auto-refresh timer guarded against re-entry, a bounded context menu
//          (copy row, copy IP, block / whitelist) and a status strip that timestamps every refresh
//          / action in UTC.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.ComponentModel;
using System.Drawing;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Forms;

/// <summary>
/// Stage 6B SOC-operator Attack Statistics tab.
/// </summary>
/// <remarks>
/// <para>
/// All reads flow through <see cref="IpcCommand.GetAttackStats"/>. The page never writes to the
/// <c>AttackStats</c> table directly. Optional context actions (block / whitelist) reuse the
/// existing Stage 5 IPC mutations and are confirmation-gated.
/// </para>
/// <para>
/// The auto-refresh timer fires every <see cref="AutoRefreshIntervalMs"/> milliseconds when the
/// <c>Auto refresh</c> checkbox is set. A <see cref="System.Threading.SemaphoreSlim"/>-like
/// guard (<see cref="_refreshing"/>) drops overlapping ticks rather than queuing them, so a slow
/// service cannot pile up unbounded background work.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class AttackStatisticsPage : TabPage
{
	private const int AutoRefreshIntervalMs = 5_000;
	private const int DefaultLimit = 500;

	private static readonly int[] LimitChoices = { 100, 250, 500, 1000, 2000 };

	private static readonly Color RowColorGreen = Color.FromArgb(220, 245, 220);
	private static readonly Color RowColorYellow = Color.FromArgb(255, 248, 200);
	private static readonly Color RowColorRed = Color.FromArgb(255, 220, 220);

	private readonly IpcClient _ipc;
	private readonly DataGridView _grid;
	private readonly BindingList<AttackStatRow> _binding = new();
	private readonly List<AttackStatEntryDto> _allEntries = new();

	private readonly TextBox _ipFilter;
	private readonly NumericUpDown _minScoreFilter;
	private readonly CheckBox _onlyBlockedCheck;
	private readonly ComboBox _rangeCombo;
	private readonly ComboBox _limitCombo;
	private readonly CheckBox _autoRefreshCheck;
	private readonly Button _refreshButton;
	private readonly Button _clearFiltersButton;

	private readonly StatusStrip _statusStrip;
	private readonly ToolStripStatusLabel _statusLabel;
	private readonly System.Windows.Forms.Timer _autoRefreshTimer;

	private readonly ContextMenuStrip _menu;
	private readonly ToolStripMenuItem _menuCopyDetails;
	private readonly ToolStripMenuItem _menuCopyIp;
	private readonly ToolStripMenuItem _menuBlockIp;
	private readonly ToolStripMenuItem _menuWhitelistIp;

	private AttackStatRow? _menuRow;

	private bool _refreshing;
	private bool _suppressFilterRefresh;

	public AttackStatisticsPage(IpcClient ipc)
	{
		ArgumentNullException.ThrowIfNull(ipc);
		_ipc = ipc;
		Text = "Attack Statistics";

		// --- Toolbar ---------------------------------------------------------------------------
		_ipFilter = new TextBox
		{
			Dock = DockStyle.Fill,
			PlaceholderText = "IP contains…",
		};
		_ipFilter.TextChanged += (_, _) => OnLocalFilterChanged();

		_minScoreFilter = new NumericUpDown
		{
			Minimum = 0,
			Maximum = 100,
			DecimalPlaces = 0,
			Increment = 5,
			Value = 0,
			Dock = DockStyle.Fill,
		};
		_minScoreFilter.ValueChanged += (_, _) => OnLocalFilterChanged();

		_onlyBlockedCheck = new CheckBox
		{
			Text = "Only blocked",
			Dock = DockStyle.Fill,
			AutoSize = false,
			TextAlign = ContentAlignment.MiddleLeft,
		};
		_onlyBlockedCheck.CheckedChanged += (_, _) => OnLocalFilterChanged();

		_rangeCombo = new ComboBox
		{
			Dock = DockStyle.Fill,
			DropDownStyle = ComboBoxStyle.DropDownList,
		};
		foreach (AttackStatsRecentRange range in Enum.GetValues<AttackStatsRecentRange>())
		{
			_rangeCombo.Items.Add(new RangeChoice(range));
		}
		_rangeCombo.SelectedIndex = (int)AttackStatsRecentRange.Last7Days;
		_rangeCombo.SelectedIndexChanged += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_limitCombo = new ComboBox
		{
			Dock = DockStyle.Fill,
			DropDownStyle = ComboBoxStyle.DropDownList,
		};
		foreach (int n in LimitChoices)
		{
			_limitCombo.Items.Add(n);
		}
		_limitCombo.SelectedItem = DefaultLimit;
		_limitCombo.SelectedIndexChanged += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_autoRefreshTimer = new System.Windows.Forms.Timer { Interval = AutoRefreshIntervalMs };
		_autoRefreshTimer.Tick += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_autoRefreshCheck = new CheckBox
		{
			Text = "Auto refresh (5s)",
			Dock = DockStyle.Fill,
			AutoSize = false,
			TextAlign = ContentAlignment.MiddleLeft,
		};
		_autoRefreshCheck.CheckedChanged += (_, _) =>
		{
			if (_autoRefreshCheck.Checked)
			{
				_autoRefreshTimer.Start();
				SetStatus("Auto refresh enabled (every 5 seconds).");
			}
			else
			{
				_autoRefreshTimer.Stop();
				SetStatus("Auto refresh disabled.");
			}
		};

		_refreshButton = new Button { Text = "Refresh", Dock = DockStyle.Fill, AutoSize = false };
		_refreshButton.Click += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_clearFiltersButton = new Button { Text = "Clear filters", Dock = DockStyle.Fill, AutoSize = false };
		_clearFiltersButton.Click += async (_, _) => await OnClearFiltersAsync().ConfigureAwait(true);

		TableLayoutPanel toolbar = BuildToolbar();

		// --- Grid ------------------------------------------------------------------------------
		_grid = new DataGridView
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			ReadOnly = true,
			RowHeadersVisible = false,
			AllowUserToAddRows = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = false,
		};
		ConfigureGridColumns(_grid);
		_grid.DataSource = _binding;
		_grid.RowPrePaint += OnRowPrePaint;
		_grid.CellMouseDown += OnCellMouseDown;

		// --- Context menu ----------------------------------------------------------------------
		_menuCopyDetails = new ToolStripMenuItem("Copy Row Details", null, (_, _) => OnCopyDetails());
		_menuCopyIp = new ToolStripMenuItem("Copy IP", null, (_, _) => OnCopyIp());
		_menuBlockIp = new ToolStripMenuItem("Block IP…", null, async (_, _) => await OnBlockIpAsync().ConfigureAwait(true));
		_menuWhitelistIp = new ToolStripMenuItem("Whitelist IP…", null, async (_, _) => await OnWhitelistIpAsync().ConfigureAwait(true));
		_menu = new ContextMenuStrip();
		_menu.Items.Add(_menuCopyDetails);
		_menu.Items.Add(_menuCopyIp);
		_menu.Items.Add(new ToolStripSeparator());
		_menu.Items.Add(_menuBlockIp);
		_menu.Items.Add(_menuWhitelistIp);
		_menu.Opening += OnMenuOpening;
		_grid.ContextMenuStrip = _menu;

		// --- Status strip ----------------------------------------------------------------------
		_statusStrip = new StatusStrip { SizingGrip = false };
		_statusLabel = new ToolStripStatusLabel("Waiting for first refresh…")
		{
			Spring = true,
			TextAlign = ContentAlignment.MiddleLeft,
		};
		_statusStrip.Items.Add(_statusLabel);

		// --- Compose ---------------------------------------------------------------------------
		// Order matters: docked panels added later sit closer to the top edge.
		Controls.Add(_grid);
		Controls.Add(_statusStrip);
		Controls.Add(toolbar);

		HandleCreated += async (_, _) => await RefreshAsync().ConfigureAwait(true);
	}

	// ---------------------------------------------------------------------------------------------
	// Toolbar composition
	// ---------------------------------------------------------------------------------------------

	private TableLayoutPanel BuildToolbar()
	{
		TableLayoutPanel toolbar = new()
		{
			Dock = DockStyle.Top,
			Height = 72,
			ColumnCount = 9,
			RowCount = 2,
			Padding = new Padding(4),
		};
		for (int i = 0; i < 9; i++)
		{
			toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / 9));
		}
		toolbar.RowStyles.Add(new RowStyle(SizeType.Absolute, 20));
		toolbar.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));

		Label ipSearchCaption = MakeCaption("IP search");
		toolbar.Controls.Add(ipSearchCaption, 0, 0);
		toolbar.SetColumnSpan(ipSearchCaption, 2);
		toolbar.Controls.Add(_ipFilter, 0, 1);
		toolbar.SetColumnSpan(_ipFilter, 2);

		toolbar.Controls.Add(MakeCaption("Min threat"), 2, 0);
		toolbar.Controls.Add(_minScoreFilter, 2, 1);

		toolbar.Controls.Add(MakeCaption("Recent period"), 3, 0);
		toolbar.Controls.Add(_rangeCombo, 3, 1);

		toolbar.Controls.Add(MakeCaption("Limit"), 4, 0);
		toolbar.Controls.Add(_limitCombo, 4, 1);

		toolbar.Controls.Add(MakeCaption(" "), 5, 0);
		toolbar.Controls.Add(_onlyBlockedCheck, 5, 1);

		toolbar.Controls.Add(MakeCaption(" "), 6, 0);
		toolbar.Controls.Add(_autoRefreshCheck, 6, 1);

		toolbar.Controls.Add(MakeCaption(" "), 7, 0);
		toolbar.Controls.Add(_refreshButton, 7, 1);

		toolbar.Controls.Add(MakeCaption(" "), 8, 0);
		toolbar.Controls.Add(_clearFiltersButton, 8, 1);

		return toolbar;
	}

	private static Label MakeCaption(string text) => new()
	{
		Text = text,
		Dock = DockStyle.Fill,
		TextAlign = ContentAlignment.MiddleLeft,
		AutoSize = false,
	};

	private static void ConfigureGridColumns(DataGridView grid)
	{
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "IP",
			DataPropertyName = nameof(AttackStatRow.Ip),
			Width = 140,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Threat",
			DataPropertyName = nameof(AttackStatRow.ThreatDisplay),
			Width = 110,
			ToolTipText = "Threat score (0–100) and band (Green / Yellow / Red).",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Total",
			DataPropertyName = nameof(AttackStatRow.TotalAttempts),
			Width = 70,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Failed",
			DataPropertyName = nameof(AttackStatRow.Failed),
			Width = 70,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Successful",
			DataPropertyName = nameof(AttackStatRow.Successful),
			Width = 80,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "First Seen (UTC)",
			DataPropertyName = nameof(AttackStatRow.FirstSeenUtcText),
			Width = 150,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Last Seen (UTC)",
			DataPropertyName = nameof(AttackStatRow.LastSeenUtcText),
			Width = 150,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Duration",
			DataPropertyName = nameof(AttackStatRow.DurationText),
			Width = 100,
			ToolTipText = "Active-window duration (LastSeenUtc − FirstSeenUtc).",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Top 10 Attempted Logins",
			DataPropertyName = nameof(AttackStatRow.TopLoginsText),
			AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Last LogonType",
			DataPropertyName = nameof(AttackStatRow.LastLoginTypeText),
			Width = 110,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Blocked",
			DataPropertyName = nameof(AttackStatRow.IsBlockedText),
			Width = 80,
		});
	}

	// ---------------------------------------------------------------------------------------------
	// Refresh / IPC plumbing
	// ---------------------------------------------------------------------------------------------

	/// <summary>
	/// Fetches the current snapshot via <see cref="IpcCommand.GetAttackStats"/> using the toolbar
	/// filters. Server-side filters (IP query, min threat, only-blocked, since-utc, limit) are sent
	/// in the request; client-side pre-filtering for the editable IP / min-threat / only-blocked
	/// controls happens additionally so typing feels responsive between IPC round-trips.
	/// </summary>
	public async Task RefreshAsync()
	{
		if (_refreshing)
		{
			return;
		}

		_refreshing = true;
		_refreshButton.Enabled = false;
		try
		{
			AttackStatsRequest request = BuildRequest();
			AttackStatsDto? response = await _ipc
				.SendAsync<AttackStatsDto>(IpcCommand.GetAttackStats, request)
				.ConfigureAwait(true);

			if (response is null)
			{
				SetStatus("Refresh FAILED: service unreachable.");
				return;
			}

			if (response.Status != IpcResultStatus.Success)
			{
				SetStatus(string.Format(
					CultureInfo.InvariantCulture,
					"Refresh returned non-success status {0}: {1}",
					response.Status,
					response.Message ?? "no message"));
				// Still apply whatever entries came back so the operator sees the current state.
			}

			_allEntries.Clear();
			_allEntries.AddRange(response.Entries);
			ApplyLocalFilter();
			SetStatus(string.Format(
				CultureInfo.InvariantCulture,
				"Refresh OK. rows={0} (matching={1}, server limit={2}, window=[{3:yyyy-MM-dd HH:mm:ss}Z..{4:yyyy-MM-dd HH:mm:ss}Z]).",
				_binding.Count,
				response.TotalMatching,
				response.AppliedLimit,
				response.WindowStartUtc,
				response.WindowEndUtc));
		}
		catch (Exception ex)
		{
			SetStatus("Refresh FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
		finally
		{
			_refreshing = false;
			_refreshButton.Enabled = true;
		}
	}

	private AttackStatsRequest BuildRequest()
	{
		AttackStatsRecentRange range = ((RangeChoice)_rangeCombo.SelectedItem!).Range;
		double minScore = (double)_minScoreFilter.Value;
		int limit = _limitCombo.SelectedItem is int n ? n : DefaultLimit;

		return new AttackStatsRequest
		{
			IpQuery = string.IsNullOrWhiteSpace(_ipFilter.Text) ? null : _ipFilter.Text.Trim(),
			MinThreatScore = minScore > 0 ? minScore : null,
			OnlyBlocked = _onlyBlockedCheck.Checked,
			SinceUtc = AttackStatsRecentRanges.ToSinceUtc(range, DateTime.UtcNow),
			UntilUtc = null,
			Limit = limit,
		};
	}

	private void OnLocalFilterChanged()
	{
		if (_suppressFilterRefresh)
		{
			return;
		}

		ApplyLocalFilter();
	}

	private void ApplyLocalFilter()
	{
		AttackStatsFilter filter = new()
		{
			IpQuery = _ipFilter.Text,
			MinThreatScore = _minScoreFilter.Value > 0 ? (double)_minScoreFilter.Value : null,
			OnlyBlocked = _onlyBlockedCheck.Checked,
		};

		_binding.RaiseListChangedEvents = false;
		_binding.Clear();
		foreach (AttackStatEntryDto entry in _allEntries)
		{
			if (filter.Matches(entry))
			{
				_binding.Add(AttackStatRow.From(entry));
			}
		}
		_binding.RaiseListChangedEvents = true;
		_binding.ResetBindings();
	}

	private async Task OnClearFiltersAsync()
	{
		_suppressFilterRefresh = true;
		try
		{
			_ipFilter.Text = string.Empty;
			_minScoreFilter.Value = 0;
			_onlyBlockedCheck.Checked = false;
			_rangeCombo.SelectedIndex = (int)AttackStatsRecentRange.Last7Days;
			_limitCombo.SelectedItem = DefaultLimit;
		}
		finally
		{
			_suppressFilterRefresh = false;
		}

		await RefreshAsync().ConfigureAwait(true);
	}

	// ---------------------------------------------------------------------------------------------
	// Row coloring
	// ---------------------------------------------------------------------------------------------

	private void OnRowPrePaint(object? sender, DataGridViewRowPrePaintEventArgs e)
	{
		if (e.RowIndex < 0 || e.RowIndex >= _binding.Count)
		{
			return;
		}

		AttackStatRow row = _binding[e.RowIndex];
		Color color = row.ThreatLevel switch
		{
			AttackThreatLevel.Red => RowColorRed,
			AttackThreatLevel.Yellow => RowColorYellow,
			_ => RowColorGreen,
		};

		_grid.Rows[e.RowIndex].DefaultCellStyle.BackColor = color;
	}

	// ---------------------------------------------------------------------------------------------
	// Context menu
	// ---------------------------------------------------------------------------------------------

	private void OnCellMouseDown(object? sender, DataGridViewCellMouseEventArgs e)
	{
		if (e.Button != MouseButtons.Right || e.RowIndex < 0 || e.RowIndex >= _binding.Count)
		{
			_menuRow = null;
			return;
		}

		// Move the selection to the right-clicked row so menu actions target what the operator clicked.
		_grid.ClearSelection();
		_grid.Rows[e.RowIndex].Selected = true;
		_menuRow = _binding[e.RowIndex];
	}

	private void OnMenuOpening(object? sender, CancelEventArgs e)
	{
		bool hasRow = _menuRow is not null;
		_menuCopyDetails.Enabled = hasRow;
		_menuCopyIp.Enabled = hasRow && !string.IsNullOrEmpty(_menuRow!.Ip);
		_menuBlockIp.Enabled = hasRow && !string.IsNullOrEmpty(_menuRow!.Ip) && !_menuRow.IsBlocked;
		_menuWhitelistIp.Enabled = hasRow && !string.IsNullOrEmpty(_menuRow!.Ip);
	}

	private void OnCopyDetails()
	{
		if (_menuRow is null)
		{
			return;
		}

		string text = AttackStatRowFormatter.FormatMultiline(_menuRow.Source);
		TrySetClipboard(text, "Copy row details");
	}

	private void OnCopyIp()
	{
		if (_menuRow is null || string.IsNullOrEmpty(_menuRow.Ip))
		{
			return;
		}

		TrySetClipboard(_menuRow.Ip, "Copy IP");
	}

	private async Task OnBlockIpAsync()
	{
		if (_menuRow is null || string.IsNullOrEmpty(_menuRow.Ip))
		{
			return;
		}

		string ip = _menuRow.Ip;
		if (!AddressListFilter.IsValidIp(ip))
		{
			SetStatus("Block IP aborted: " + ip + " is not a valid IPv4 / IPv6 address.");
			return;
		}

		string prompt = string.Format(
			CultureInfo.InvariantCulture,
			"Block {0}? The service will install a firewall block via the configured provider and "
			+ "add the address to the blocklist.",
			ip);
		if (!Confirm(prompt, "Confirm block IP"))
		{
			SetStatus("Block IP cancelled.");
			return;
		}

		AddressListMutationRequest payload = new()
		{
			Address = AddressListFilter.NormalizeIp(ip),
			Note = "Configurator Attack Statistics tab manual block",
		};

		bool ok = await SendMutationAsync(IpcCommand.AddToBlocklist, payload).ConfigureAwait(true);
		SetStatus(string.Format(
			CultureInfo.InvariantCulture,
			"AddToBlocklist {0}: {1}",
			ip,
			ok ? "OK" : "FAILED"));
		if (ok)
		{
			await RefreshAsync().ConfigureAwait(true);
		}
	}

	private async Task OnWhitelistIpAsync()
	{
		if (_menuRow is null || string.IsNullOrEmpty(_menuRow.Ip))
		{
			return;
		}

		string ip = _menuRow.Ip;
		if (!AddressListFilter.IsValidIp(ip))
		{
			SetStatus("Whitelist IP aborted: " + ip + " is not a valid IPv4 / IPv6 address.");
			return;
		}

		string prompt = string.Format(
			CultureInfo.InvariantCulture,
			"Whitelist {0}? The address will be exempt from auto-blocking. Existing active blocks are "
			+ "not removed by this action — use the Firewall tab to unblock if required.",
			ip);
		if (!Confirm(prompt, "Confirm whitelist IP"))
		{
			SetStatus("Whitelist IP cancelled.");
			return;
		}

		AddressListMutationRequest payload = new()
		{
			Address = AddressListFilter.NormalizeIp(ip),
			Note = "Configurator Attack Statistics tab manual whitelist",
		};

		bool ok = await SendMutationAsync(IpcCommand.AddToWhitelist, payload).ConfigureAwait(true);
		SetStatus(string.Format(
			CultureInfo.InvariantCulture,
			"AddToWhitelist {0}: {1}",
			ip,
			ok ? "OK" : "FAILED"));
		if (ok)
		{
			await RefreshAsync().ConfigureAwait(true);
		}
	}

	// ---------------------------------------------------------------------------------------------
	// Helpers
	// ---------------------------------------------------------------------------------------------

	private async Task<bool> SendMutationAsync(IpcCommand command, object payload)
	{
		try
		{
			JsonElement? response = await _ipc.SendAsync<JsonElement?>(command, payload).ConfigureAwait(true);
			return response is not null;
		}
		catch
		{
			return false;
		}
	}

	private void TrySetClipboard(string text, string actionLabel)
	{
		try
		{
			if (string.IsNullOrEmpty(text))
			{
				Clipboard.Clear();
			}
			else
			{
				Clipboard.SetText(text);
			}

			SetStatus(actionLabel + ": OK.");
		}
		catch (Exception ex)
		{
			SetStatus(actionLabel + " FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	private static bool Confirm(string message, string caption) =>
		MessageBox.Show(
			message,
			caption,
			MessageBoxButtons.YesNo,
			MessageBoxIcon.Warning,
			MessageBoxDefaultButton.Button2) == DialogResult.Yes;

	private void SetStatus(string message)
	{
		string stamped = string.Format(
			CultureInfo.InvariantCulture,
			"[{0:yyyy-MM-dd HH:mm:ss}Z] {1}",
			DateTime.UtcNow,
			message);
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
			_autoRefreshTimer.Stop();
			_autoRefreshTimer.Dispose();
			_menu.Dispose();
		}

		base.Dispose(disposing);
	}

	// ---------------------------------------------------------------------------------------------
	// View-models
	// ---------------------------------------------------------------------------------------------

	private sealed record RangeChoice(AttackStatsRecentRange Range)
	{
		public override string ToString() => AttackStatsRecentRanges.ToDisplayLabel(Range);
	}

	/// <summary>Grid view-model for one <see cref="AttackStatEntryDto"/> row.</summary>
	public sealed class AttackStatRow
	{
		private const string TimeFormat = "yyyy-MM-dd HH:mm:ss";

		public string Ip { get; init; } = string.Empty;

		public double ThreatScore { get; init; }

		public AttackThreatLevel ThreatLevel { get; init; }

		public string ThreatDisplay { get; init; } = string.Empty;

		public long TotalAttempts { get; init; }

		public long Failed { get; init; }

		public long Successful { get; init; }

		public string FirstSeenUtcText { get; init; } = string.Empty;

		public string LastSeenUtcText { get; init; } = string.Empty;

		public string DurationText { get; init; } = string.Empty;

		public string TopLoginsText { get; init; } = string.Empty;

		public string LastLoginTypeText { get; init; } = string.Empty;

		public bool IsBlocked { get; init; }

		public string IsBlockedText => IsBlocked ? "yes" : "no";

		/// <summary>Reference to the original DTO; used by the clipboard formatter so format drift cannot occur.</summary>
		[Browsable(false)]
		public AttackStatEntryDto Source { get; init; } = new();

		public static AttackStatRow From(AttackStatEntryDto dto)
		{
			ArgumentNullException.ThrowIfNull(dto);
			return new AttackStatRow
			{
				Ip = dto.Ip,
				ThreatScore = dto.ThreatScore,
				ThreatLevel = dto.ThreatLevel,
				ThreatDisplay = string.Format(
					CultureInfo.InvariantCulture,
					"{0:F1} ({1})",
					dto.ThreatScore,
					dto.ThreatLevel),
				TotalAttempts = dto.TotalAttempts,
				Failed = dto.Failed,
				Successful = dto.Successful,
				FirstSeenUtcText = dto.FirstSeenUtc.ToString(TimeFormat, CultureInfo.InvariantCulture),
				LastSeenUtcText = dto.LastSeenUtc.ToString(TimeFormat, CultureInfo.InvariantCulture),
				DurationText = AttackStatRowFormatter.FormatDuration(dto.DurationSeconds),
				TopLoginsText = AttackStatRowFormatter.FormatTopLogins(dto.Top10AttemptedLogins),
				LastLoginTypeText = dto.LastLoginType?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
				IsBlocked = dto.IsBlocked,
				Source = dto,
			};
		}
	}
}
