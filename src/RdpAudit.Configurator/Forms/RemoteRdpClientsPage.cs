// File:    src/RdpAudit.Configurator/Forms/RemoteRdpClientsPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Stage 7 SOC-operator Remote RDP Clients tab. Lists active / inactive /
//          disconnected RDP sessions, lets the operator disconnect / log off / shadow
//          a selected session (every destructive action confirmation-gated), and surfaces
//          the current Terminal Services shadow policy with apply / backup / restore
//          controls. All reads / mutations flow through the Service IPC.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.ComponentModel;
using System.Drawing;
using System.Globalization;
using System.Runtime.Versioning;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Events;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Forms;

/// <summary>
/// Stage 7 Remote RDP Clients tab. Provides session listing, session control
/// (disconnect / logoff / shadow) and shadow policy management.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RemoteRdpClientsPage : TabPage
{
	private const int AutoRefreshIntervalMs = 5_000;

	private static readonly Color RowColorActive = Color.FromArgb(220, 245, 220);
	private static readonly Color RowColorDisconnected = Color.FromArgb(255, 235, 220);
	private static readonly Color RowColorInactive = Color.FromArgb(240, 240, 240);

	private readonly IpcClient _ipc;
	private readonly ShadowLauncher _launcher = new();
	private readonly LocalRdpSessionProvider _localSessions = new();
	private readonly LocalShadowPolicyReader _localShadowPolicy = new();

	private readonly DataGridView _grid;
	private readonly BindingList<SessionRow> _binding = new();
	private readonly List<RdpSessionDto> _allSessions = new();

	private readonly TextBox _searchFilter;
	private readonly ComboBox _stateCombo;
	private readonly CheckBox _autoRefreshCheck;
	private readonly Button _refreshButton;
	private readonly Button _clearFiltersButton;

	private readonly StatusStrip _statusStrip;
	private readonly ToolStripStatusLabel _statusLabel;
	private readonly System.Windows.Forms.Timer _autoRefreshTimer;

	private readonly ContextMenuStrip _menu;
	private readonly ToolStripMenuItem _menuDisconnect;
	private readonly ToolStripMenuItem _menuLogoff;
	private readonly ToolStripMenuItem _menuShadowView;
	private readonly ToolStripMenuItem _menuShadowControl;
	private readonly ToolStripMenuItem _menuShadowControlNoConsent;
	private readonly ToolStripMenuItem _menuExportFacts;

	// Shadow policy panel controls.
	private readonly Label _shadowSummaryLabel;
	private readonly DataGridView _shadowGrid;
	private readonly BindingList<ShadowValueRow> _shadowBinding = new();
	private readonly Button _enableAllButton;
	private readonly Button _backupButton;
	private readonly Button _restoreButton;
	private readonly Button _refreshPolicyButton;

	private SessionRow? _menuRow;
	private bool _refreshing;
	private bool _suppressFilterRefresh;

	public RemoteRdpClientsPage(IpcClient ipc)
	{
		ArgumentNullException.ThrowIfNull(ipc);
		_ipc = ipc;
		Text = "Remote RDP Clients";

		_searchFilter = new TextBox
		{
			Dock = DockStyle.Fill,
			PlaceholderText = "search user / client / IP…",
		};
		_searchFilter.TextChanged += (_, _) => OnLocalFilterChanged();

		_stateCombo = new ComboBox
		{
			Dock = DockStyle.Fill,
			DropDownStyle = ComboBoxStyle.DropDownList,
		};
		_stateCombo.Items.Add("All states");
		_stateCombo.Items.Add("Active");
		_stateCombo.Items.Add("Disconnected");
		_stateCombo.Items.Add("Inactive (other)");
		_stateCombo.SelectedIndex = 0;
		_stateCombo.SelectedIndexChanged += (_, _) => OnLocalFilterChanged();

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
		ConfigureSessionGrid(_grid);
		_grid.DataSource = _binding;
		_grid.RowPrePaint += OnRowPrePaint;
		_grid.CellMouseDown += OnCellMouseDown;

		_menuDisconnect = new ToolStripMenuItem("Disconnect session…", null, async (_, _) => await OnDisconnectAsync().ConfigureAwait(true));
		_menuLogoff = new ToolStripMenuItem("Log off (kill) session…", null, async (_, _) => await OnLogoffAsync().ConfigureAwait(true));
		_menuShadowView = new ToolStripMenuItem("Shadow — view only…", null, async (_, _) => await OnShadowAsync(SessionCommandBuilder.ShadowMode.ViewOnly).ConfigureAwait(true));
		_menuShadowControl = new ToolStripMenuItem("Shadow — view + control…", null, async (_, _) => await OnShadowAsync(SessionCommandBuilder.ShadowMode.Control).ConfigureAwait(true));
		_menuShadowControlNoConsent = new ToolStripMenuItem("Shadow — view + control (NO CONSENT)…", null, async (_, _) => await OnShadowAsync(SessionCommandBuilder.ShadowMode.ControlNoConsent).ConfigureAwait(true));
		_menuExportFacts = BuildExportFactsSubmenu();
		_menu = new ContextMenuStrip();
		_menu.Items.Add(_menuDisconnect);
		_menu.Items.Add(_menuLogoff);
		_menu.Items.Add(new ToolStripSeparator());
		_menu.Items.Add(_menuShadowView);
		_menu.Items.Add(_menuShadowControl);
		_menu.Items.Add(_menuShadowControlNoConsent);
		_menu.Items.Add(new ToolStripSeparator());
		_menu.Items.Add(_menuExportFacts);
		_menu.Opening += OnMenuOpening;
		_grid.ContextMenuStrip = _menu;

		_statusStrip = new StatusStrip { SizingGrip = false };
		_statusLabel = new ToolStripStatusLabel("Waiting for first refresh…")
		{
			Spring = true,
			TextAlign = ContentAlignment.MiddleLeft,
		};
		_statusStrip.Items.Add(_statusLabel);

		// --- Shadow policy panel ---------------------------------------------------------------
		_shadowSummaryLabel = new Label
		{
			Dock = DockStyle.Fill,
			TextAlign = ContentAlignment.MiddleLeft,
			AutoSize = false,
			Text = "Shadow policy: loading…",
		};

		_shadowGrid = new DataGridView
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			ReadOnly = true,
			RowHeadersVisible = false,
			AllowUserToAddRows = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = false,
			Height = 130,
		};
		ConfigureShadowGrid(_shadowGrid);
		_shadowGrid.DataSource = _shadowBinding;

		_enableAllButton = new Button { Text = "Enable all permissions…", Dock = DockStyle.Fill, AutoSize = false };
		_enableAllButton.Click += async (_, _) => await OnEnableAllAsync().ConfigureAwait(true);

		_backupButton = new Button { Text = "Backup", Dock = DockStyle.Fill, AutoSize = false };
		_backupButton.Click += async (_, _) => await OnBackupPolicyAsync().ConfigureAwait(true);

		_restoreButton = new Button { Text = "Restore latest…", Dock = DockStyle.Fill, AutoSize = false };
		_restoreButton.Click += async (_, _) => await OnRestorePolicyAsync().ConfigureAwait(true);

		_refreshPolicyButton = new Button { Text = "Refresh policy", Dock = DockStyle.Fill, AutoSize = false };
		_refreshPolicyButton.Click += async (_, _) => await RefreshShadowPolicyAsync().ConfigureAwait(true);

		Panel shadowPanel = BuildShadowPanel();

		// --- Compose ---------------------------------------------------------------------------
		// Order matters: docked panels added later sit closer to the top edge.
		SplitContainer split = new()
		{
			Dock = DockStyle.Fill,
			Orientation = Orientation.Horizontal,
			SplitterWidth = 6,
		};
		split.Panel1.Controls.Add(_grid);
		split.Panel2.Controls.Add(shadowPanel);
		split.HandleCreated += (_, _) =>
		{
			try
			{
				split.SplitterDistance = Math.Max(200, split.Height - 250);
			}
			catch (InvalidOperationException)
			{
				// Layout not ready — fall back to the default which is fine.
			}
		};

		Controls.Add(split);
		Controls.Add(_statusStrip);
		Controls.Add(toolbar);

		HandleCreated += async (_, _) =>
		{
			await RefreshAsync().ConfigureAwait(true);
			await RefreshShadowPolicyAsync().ConfigureAwait(true);
		};
	}

	private TableLayoutPanel BuildToolbar()
	{
		TableLayoutPanel toolbar = new()
		{
			Dock = DockStyle.Top,
			Height = 72,
			ColumnCount = 6,
			RowCount = 2,
			Padding = new Padding(4),
		};
		for (int i = 0; i < 6; i++)
		{
			toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / 6));
		}
		toolbar.RowStyles.Add(new RowStyle(SizeType.Absolute, 20));
		toolbar.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));

		toolbar.Controls.Add(MakeCaption("Search"), 0, 0);
		toolbar.Controls.Add(_searchFilter, 0, 1);
		toolbar.SetColumnSpan(_searchFilter, 2);
		toolbar.SetColumnSpan(toolbar.GetControlFromPosition(0, 0)!, 2);

		toolbar.Controls.Add(MakeCaption("State filter"), 2, 0);
		toolbar.Controls.Add(_stateCombo, 2, 1);

		toolbar.Controls.Add(MakeCaption(" "), 3, 0);
		toolbar.Controls.Add(_autoRefreshCheck, 3, 1);

		toolbar.Controls.Add(MakeCaption(" "), 4, 0);
		toolbar.Controls.Add(_refreshButton, 4, 1);

		toolbar.Controls.Add(MakeCaption(" "), 5, 0);
		toolbar.Controls.Add(_clearFiltersButton, 5, 1);

		return toolbar;
	}

	private Panel BuildShadowPanel()
	{
		Panel panel = new() { Dock = DockStyle.Fill };

		TableLayoutPanel buttons = new()
		{
			Dock = DockStyle.Bottom,
			Height = 36,
			ColumnCount = 4,
			RowCount = 1,
			Padding = new Padding(4),
		};
		for (int i = 0; i < 4; i++)
		{
			buttons.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25f));
		}
		buttons.Controls.Add(_enableAllButton, 0, 0);
		buttons.Controls.Add(_backupButton, 1, 0);
		buttons.Controls.Add(_restoreButton, 2, 0);
		buttons.Controls.Add(_refreshPolicyButton, 3, 0);

		Panel summaryPanel = new() { Dock = DockStyle.Top, Height = 28, Padding = new Padding(4, 4, 4, 0) };
		summaryPanel.Controls.Add(_shadowSummaryLabel);

		panel.Controls.Add(_shadowGrid);
		panel.Controls.Add(buttons);
		panel.Controls.Add(summaryPanel);
		return panel;
	}

	private static Label MakeCaption(string text) => new()
	{
		Text = text,
		Dock = DockStyle.Fill,
		TextAlign = ContentAlignment.MiddleLeft,
		AutoSize = false,
	};

	private static void ConfigureSessionGrid(DataGridView grid)
	{
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "●",
			DataPropertyName = nameof(SessionRow.StateBullet),
			Width = 30,
			ToolTipText = "Green = active, orange = disconnected, grey = inactive / other.",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "ID",
			DataPropertyName = nameof(SessionRow.SessionId),
			Width = 60,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "User",
			DataPropertyName = nameof(SessionRow.UserName),
			Width = 180,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Session",
			DataPropertyName = nameof(SessionRow.SessionName),
			Width = 120,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "State",
			DataPropertyName = nameof(SessionRow.State),
			Width = 110,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Client",
			DataPropertyName = nameof(SessionRow.ClientName),
			Width = 140,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Client IP",
			DataPropertyName = nameof(SessionRow.ClientAddress),
			Width = 140,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Current?",
			DataPropertyName = nameof(SessionRow.CurrentText),
			Width = 70,
		});

		// --- Stage IP-E historical-context columns (additive). Never overrides ClientAddress (live).
		// Populated only when matching RdpConnectionFacts exist for the session's source IP.
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Hist First Seen (UTC)",
			DataPropertyName = nameof(SessionRow.HistoricalFirstSeenUtcText),
			Width = 160,
			ToolTipText = "Earliest FirstSeenUtc across matching RdpConnectionFacts for this session's source IP.",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Hist Last Seen (UTC)",
			DataPropertyName = nameof(SessionRow.HistoricalLastSeenUtcText),
			Width = 160,
			ToolTipText = "Latest LastSeenUtc across matching RdpConnectionFacts for this session's source IP.",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Hist Failed",
			DataPropertyName = nameof(SessionRow.HistoricalFailedLogons),
			Width = 90,
			ToolTipText = "Sum of failed logons across matching RdpConnectionFacts for this source IP.",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Hist Success",
			DataPropertyName = nameof(SessionRow.HistoricalSuccessfulLogons),
			Width = 90,
			ToolTipText = "Sum of successful logons across matching RdpConnectionFacts for this source IP.",
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Hist Users Attempted",
			DataPropertyName = nameof(SessionRow.HistoricalUserNamesAttemptedText),
			Width = 200,
			ToolTipText = "Comma-separated, deduplicated usernames attempted from this IP across matching facts.",
		});
	}

	private static void ConfigureShadowGrid(DataGridView grid)
	{
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Registry key",
			DataPropertyName = nameof(ShadowValueRow.KeyPath),
			AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Value",
			DataPropertyName = nameof(ShadowValueRow.ValueName),
			Width = 140,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Current",
			DataPropertyName = nameof(ShadowValueRow.CurrentText),
			Width = 80,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Recommended",
			DataPropertyName = nameof(ShadowValueRow.RecommendedText),
			Width = 100,
		});
		grid.Columns.Add(new DataGridViewTextBoxColumn
		{
			HeaderText = "Description",
			DataPropertyName = nameof(ShadowValueRow.Description),
			Width = 240,
		});
	}

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
			RdpSessionFallbackOrchestrator orchestrator = new(
				ipcFetch: ct => _ipc.SendAsync<RdpSessionListDto>(IpcCommand.ListRdpSessions, null, ct),
				localFetch: _localSessions.FetchForOrchestratorAsync);
			RdpSessionListSnapshot snapshot = await orchestrator.CaptureAsync().ConfigureAwait(true);

			if (!snapshot.HasSessions)
			{
				SetStatus(string.Format(CultureInfo.InvariantCulture,
					"Sessions refresh FAILED: service IPC ({0}); local fallback ({1}).",
					snapshot.IpcDetail ?? "unknown",
					snapshot.LocalDetail ?? "unknown"));
				return;
			}

			_allSessions.Clear();
			_allSessions.AddRange(snapshot.Sessions);
			ApplyLocalFilter();

			if (snapshot.Source == RdpSessionListSource.ServiceIpc)
			{
				SetStatus(string.Format(CultureInfo.InvariantCulture,
					"Sessions refresh OK (service IPC). count={0}, active={1}, disconnected={2}.",
					_allSessions.Count,
					_allSessions.Count(s => s.IsActive),
					_allSessions.Count(s => s.IsDisconnected)));
			}
			else
			{
				SetStatus(string.Format(CultureInfo.InvariantCulture,
					"Source: local session fallback ({4}); historical enrichment unavailable. "
					+ "count={0}, active={1}, disconnected={2}. Service IPC: {3}.",
					_allSessions.Count,
					_allSessions.Count(s => s.IsActive),
					_allSessions.Count(s => s.IsDisconnected),
					snapshot.IpcDetail ?? "unreachable",
					snapshot.LocalDetail ?? "unspecified mode"));
			}
		}
		catch (Exception ex)
		{
			SetStatus("Sessions refresh FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
		finally
		{
			_refreshing = false;
			_refreshButton.Enabled = true;
		}
	}

	public async Task RefreshShadowPolicyAsync()
	{
		ShadowPolicyStatusDto? response = null;
		try
		{
			response = await _ipc
				.SendAsync<ShadowPolicyStatusDto>(IpcCommand.GetShadowPolicyStatus)
				.ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			SetStatus("Shadow policy refresh via IPC failed (" + ex.GetType().Name + "): " + ex.Message
				+ " — falling back to local registry read.");
		}

		if (response is not null)
		{
			ApplyShadowStatus(response);
			return;
		}

		// Local fallback: synthesize a minimal ShadowPolicyStatusDto from the registry so the
		// operator still sees the effective policy when the service IPC is unreachable.
		ShadowPolicyMode local = _localShadowPolicy.Read();
		int rawValue = local == ShadowPolicyMode.NotConfigured ? -1 : (int)local;
		ShadowPolicyStatusDto localSnapshot = new()
		{
			Status = IpcResultStatus.Success,
			ShadowMode = rawValue,
			AllPermissionsEnabled = rawValue == ShadowPolicyModel.EnableAllPermissionsValue,
			Message = "Local registry fallback (service IPC unreachable).",
		};
		ApplyShadowStatus(localSnapshot);
	}

	private void ApplyShadowStatus(ShadowPolicyStatusDto? status)
	{
		if (status is null)
		{
			_shadowSummaryLabel.Text = "Shadow policy: service unreachable.";
			_shadowBinding.Clear();
			return;
		}

		ShadowPolicyMode mode = ShadowPolicyModel.FromRawValue(status.ShadowMode == -1 ? null : status.ShadowMode);
		string backupText = status.HasBackup && status.LatestSnapshotId is not null
			? "  | latest backup: " + status.LatestSnapshotId
			: "  | no backup yet";
		_shadowSummaryLabel.Text = string.Format(CultureInfo.InvariantCulture,
			"Shadow policy: {0} (raw={1}). AllPermissions={2}{3}",
			ShadowPolicyModel.Describe(mode),
			status.ShadowMode,
			status.AllPermissionsEnabled ? "yes" : "no",
			backupText);

		_shadowBinding.RaiseListChangedEvents = false;
		_shadowBinding.Clear();
		foreach (ShadowPolicyValueDto v in status.Values)
		{
			_shadowBinding.Add(new ShadowValueRow
			{
				KeyPath = v.KeyPath,
				ValueName = v.ValueName,
				CurrentText = v.CurrentValue < 0 ? "(unset)" : v.CurrentValue.ToString(CultureInfo.InvariantCulture),
				RecommendedText = v.RecommendedValue < 0 ? "—" : v.RecommendedValue.ToString(CultureInfo.InvariantCulture),
				Description = v.Description ?? string.Empty,
			});
		}
		_shadowBinding.RaiseListChangedEvents = true;
		_shadowBinding.ResetBindings();

		SetStatus("Shadow policy snapshot loaded: " + (status.Message ?? string.Empty));
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
		string query = _searchFilter.Text?.Trim() ?? string.Empty;
		string stateChoice = _stateCombo.SelectedItem as string ?? "All states";

		_binding.RaiseListChangedEvents = false;
		_binding.Clear();
		foreach (RdpSessionDto session in _allSessions)
		{
			if (!MatchesStateFilter(session, stateChoice))
			{
				continue;
			}

			if (!string.IsNullOrEmpty(query) && !MatchesSearchQuery(session, query))
			{
				continue;
			}

			_binding.Add(SessionRow.From(session));
		}
		_binding.RaiseListChangedEvents = true;
		_binding.ResetBindings();
	}

	private static bool MatchesStateFilter(RdpSessionDto session, string stateChoice) => stateChoice switch
	{
		"Active" => session.IsActive,
		"Disconnected" => session.IsDisconnected,
		"Inactive (other)" => !session.IsActive && !session.IsDisconnected,
		_ => true,
	};

	private static bool MatchesSearchQuery(RdpSessionDto session, string query) =>
		(session.UserName?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false)
		|| (session.ClientName?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false)
		|| (session.ClientAddress?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false)
		|| (session.SessionName?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false)
		|| session.SessionId.ToString(CultureInfo.InvariantCulture).Contains(query, StringComparison.OrdinalIgnoreCase);

	private async Task OnClearFiltersAsync()
	{
		_suppressFilterRefresh = true;
		try
		{
			_searchFilter.Text = string.Empty;
			_stateCombo.SelectedIndex = 0;
		}
		finally
		{
			_suppressFilterRefresh = false;
		}

		await RefreshAsync().ConfigureAwait(true);
	}

	private void OnRowPrePaint(object? sender, DataGridViewRowPrePaintEventArgs e)
	{
		if (e.RowIndex < 0 || e.RowIndex >= _binding.Count)
		{
			return;
		}

		SessionRow row = _binding[e.RowIndex];
		Color color = row.IsActive ? RowColorActive
			: row.IsDisconnected ? RowColorDisconnected
			: RowColorInactive;
		_grid.Rows[e.RowIndex].DefaultCellStyle.BackColor = color;
	}

	private void OnCellMouseDown(object? sender, DataGridViewCellMouseEventArgs e)
	{
		if (e.Button != MouseButtons.Right || e.RowIndex < 0 || e.RowIndex >= _binding.Count)
		{
			_menuRow = null;
			return;
		}

		_grid.ClearSelection();
		_grid.Rows[e.RowIndex].Selected = true;
		_menuRow = _binding[e.RowIndex];
	}

	private void OnMenuOpening(object? sender, CancelEventArgs e)
	{
		bool hasRow = _menuRow is not null;
		bool hasValidIp = hasRow && !string.IsNullOrWhiteSpace(_menuRow!.ClientAddress) && AddressListFilter.IsValidIp(_menuRow.ClientAddress);
		_menuDisconnect.Enabled = hasRow;
		_menuLogoff.Enabled = hasRow;
		_menuShadowView.Enabled = hasRow;
		_menuShadowControl.Enabled = hasRow;
		_menuShadowControlNoConsent.Enabled = hasRow;
		_menuExportFacts.Enabled = hasValidIp;
	}

	private async Task OnDisconnectAsync()
	{
		if (_menuRow is null)
		{
			return;
		}

		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Disconnect session {0} (user {1})?\n\nThe user's apps remain running on the server but their RDP "
			+ "viewer is detached. The user can reconnect.",
			_menuRow.SessionId, FormatUserForPrompt(_menuRow));
		if (!Confirm(prompt, "Confirm disconnect session"))
		{
			SetStatus("Disconnect cancelled.");
			return;
		}

		await SendSessionActionAsync(
			IpcCommand.DisconnectSession,
			new SessionActionRequest { SessionId = _menuRow.SessionId, Reason = "Configurator manual disconnect" },
			"DisconnectSession").ConfigureAwait(true);
		await RefreshAsync().ConfigureAwait(true);
	}

	private async Task OnLogoffAsync()
	{
		if (_menuRow is null)
		{
			return;
		}

		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Log off (kill) session {0} (user {1})?\n\nWARNING: this terminates every process owned by the "
			+ "session — unsaved work WILL be lost. This action is irreversible.",
			_menuRow.SessionId, FormatUserForPrompt(_menuRow));
		if (!Confirm(prompt, "Confirm log off session"))
		{
			SetStatus("Log off cancelled.");
			return;
		}

		await SendSessionActionAsync(
			IpcCommand.LogoffSession,
			new SessionActionRequest { SessionId = _menuRow.SessionId, Reason = "Configurator manual logoff" },
			"LogoffSession").ConfigureAwait(true);
		await RefreshAsync().ConfigureAwait(true);
	}

	private async Task OnShadowAsync(SessionCommandBuilder.ShadowMode mode)
	{
		if (_menuRow is null)
		{
			return;
		}

		string modeDescription = mode switch
		{
			SessionCommandBuilder.ShadowMode.ViewOnly => "view only (the user will be prompted to allow)",
			SessionCommandBuilder.ShadowMode.Control => "view + control (the user will be prompted to allow)",
			SessionCommandBuilder.ShadowMode.ControlNoConsent => "view + control with NO CONSENT PROMPT",
			_ => mode.ToString(),
		};
		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Initiate shadow session: {0} (user {1})?\n\nMode: {2}.\n\nThis is an auditable observation/control action.",
			_menuRow.SessionId, FormatUserForPrompt(_menuRow), modeDescription);
		if (!Confirm(prompt, "Confirm shadow session"))
		{
			SetStatus("Shadow cancelled.");
			return;
		}

		// 1) Ask the service to validate against policy — service may be unreachable.
		ShadowServiceDecision serviceDecision;
		try
		{
			SessionActionResult? policy = await _ipc
				.SendAsync<SessionActionResult>(IpcCommand.ShadowSession, new SessionActionRequest
				{
					SessionId = _menuRow.SessionId,
					Reason = "Configurator shadow request",
					ShadowMode = (int)mode,
				})
				.ConfigureAwait(true);

			if (policy is null)
			{
				serviceDecision = ShadowServiceDecision.FromUnreachable("IPC returned null");
			}
			else if (policy.Status == IpcResultStatus.Success)
			{
				serviceDecision = ShadowServiceDecision.FromApproval(policy.Message);
			}
			else
			{
				serviceDecision = ShadowServiceDecision.FromRefusal(policy.Message ?? policy.Status.ToString());
			}
		}
		catch (Exception ex)
		{
			serviceDecision = ShadowServiceDecision.FromUnreachable(ex.GetType().Name + " — " + ex.Message);
		}

		// 2) Read the local Shadow policy as a fallback / cross-check.
		ShadowPolicyMode localPolicy = _localShadowPolicy.Read();
		ShadowGateDecision decision = ShadowGate.Evaluate(serviceDecision, localPolicy, mode);

		if (!decision.ShouldLaunch)
		{
			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"ShadowSession refused: {0}", decision.Reason));
			return;
		}

		// 3) Spawn mstsc with sanitized arguments.
		ShadowLaunchResult launch = _launcher.Launch(_menuRow.SessionId, mode);
		string sourceTag = decision.Outcome switch
		{
			ShadowGateOutcome.AllowByService => "service-approved",
			ShadowGateOutcome.AllowByLocalPolicy => "local-policy fallback (service unreachable)",
			ShadowGateOutcome.AllowOverridingStaleService => "local-policy override (service refusal treated as stale)",
			_ => "approved",
		};
		SetStatus(launch.Started
			? string.Format(CultureInfo.InvariantCulture,
				"mstsc /shadow started for session {0} (pid {1}, mode {2}, gate={3}).",
				_menuRow.SessionId, launch.ProcessId, mode, sourceTag)
			: string.Format(CultureInfo.InvariantCulture,
				"mstsc /shadow FAILED for session {0}: {1}",
				_menuRow.SessionId, launch.Error ?? "(unknown error)"));
	}

	private async Task OnEnableAllAsync()
	{
		string prompt =
			"Apply 'Enable all permissions' shadow policy?\n\n"
			+ "This sets the Microsoft Shadow value to 2 (full control with NO user consent prompt) under\n"
			+ "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services.\n\n"
			+ "A snapshot of the current policy is captured first so the change is reversible via Restore.";
		if (!Confirm(prompt, "Confirm Enable all permissions"))
		{
			SetStatus("Enable all permissions cancelled.");
			return;
		}

		try
		{
			ShadowPolicyStatusDto? response = await _ipc
				.SendAsync<ShadowPolicyStatusDto>(IpcCommand.ApplyShadowPolicy, new ShadowPolicyApplyRequest
				{
					EnableAllPermissions = true,
					TakeBackupFirst = true,
					Reason = "Configurator Enable all permissions",
				})
				.ConfigureAwait(true);
			ApplyShadowStatus(response);
			SetStatus("ApplyShadowPolicy(EnableAllPermissions) completed.");
		}
		catch (Exception ex)
		{
			SetStatus("ApplyShadowPolicy FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	private async Task OnBackupPolicyAsync()
	{
		try
		{
			ShadowPolicyStatusDto? response = await _ipc
				.SendAsync<ShadowPolicyStatusDto>(IpcCommand.BackupShadowPolicy)
				.ConfigureAwait(true);
			ApplyShadowStatus(response);
			SetStatus("BackupShadowPolicy completed.");
		}
		catch (Exception ex)
		{
			SetStatus("BackupShadowPolicy FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	private async Task OnRestorePolicyAsync()
	{
		string prompt =
			"Restore the most recent shadow policy backup?\n\n"
			+ "Current registry values will be overwritten with the snapshot taken before the last Apply.";
		if (!Confirm(prompt, "Confirm Restore latest"))
		{
			SetStatus("Restore cancelled.");
			return;
		}

		try
		{
			ShadowPolicyStatusDto? response = await _ipc
				.SendAsync<ShadowPolicyStatusDto>(IpcCommand.RestoreShadowPolicy, payload: null)
				.ConfigureAwait(true);
			ApplyShadowStatus(response);
			SetStatus("RestoreShadowPolicy completed.");
		}
		catch (Exception ex)
		{
			SetStatus("RestoreShadowPolicy FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	// ---------------------------------------------------------------------------------------------
	// Export Connection Facts (Stage IP-E) — submenu wired into the sessions context menu.
	// ---------------------------------------------------------------------------------------------

	private ToolStripMenuItem BuildExportFactsSubmenu()
	{
		ToolStripMenuItem root = new("Export Connection Facts");
		root.DropDownItems.Add(new ToolStripMenuItem("JSON…", null, async (_, _) => await OnExportFactsAsync(ConnectionFactsExportFormat.Json).ConfigureAwait(true)));
		root.DropDownItems.Add(new ToolStripMenuItem("TXT…", null, async (_, _) => await OnExportFactsAsync(ConnectionFactsExportFormat.Txt).ConfigureAwait(true)));
		root.DropDownItems.Add(new ToolStripMenuItem("Markdown…", null, async (_, _) => await OnExportFactsAsync(ConnectionFactsExportFormat.Markdown).ConfigureAwait(true)));
		root.DropDownItems.Add(new ToolStripMenuItem("CSV…", null, async (_, _) => await OnExportFactsAsync(ConnectionFactsExportFormat.Csv).ConfigureAwait(true)));
		return root;
	}

	private async Task OnExportFactsAsync(ConnectionFactsExportFormat format)
	{
		if (_menuRow is null
			|| string.IsNullOrWhiteSpace(_menuRow.ClientAddress)
			|| !AddressListFilter.IsValidIp(_menuRow.ClientAddress))
		{
			SetStatus("Export Connection Facts aborted: no valid IP on the selected session row.");
			return;
		}

		await ConnectionFactsExportRunner.RunAsync(_ipc, _menuRow.ClientAddress, format, SetStatus).ConfigureAwait(true);
	}

	private async Task SendSessionActionAsync(IpcCommand command, SessionActionRequest request, string label)
	{
		try
		{
			SessionActionResult? response = await _ipc
				.SendAsync<SessionActionResult>(command, request)
				.ConfigureAwait(true);
			if (response is null)
			{
				SetStatus(label + " FAILED: service unreachable.");
				return;
			}

			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"{0} session={1} status={2}: {3}",
				label, response.SessionId, response.Status, response.Message ?? string.Empty));
		}
		catch (Exception ex)
		{
			SetStatus(label + " FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	private static bool Confirm(string message, string caption) =>
		MessageBox.Show(
			message,
			caption,
			MessageBoxButtons.YesNo,
			MessageBoxIcon.Warning,
			MessageBoxDefaultButton.Button2) == DialogResult.Yes;

	private static string FormatUserForPrompt(SessionRow row)
	{
		if (string.IsNullOrEmpty(row.UserName))
		{
			return "(no user)";
		}

		return "'" + row.UserName + "'";
	}

	private void SetStatus(string message)
	{
		string stamped = string.Format(CultureInfo.InvariantCulture,
			"[{0:yyyy-MM-dd HH:mm:ss}Z] {1}",
			DateTime.UtcNow, message);
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

	/// <summary>Grid view-model for one <see cref="RdpSessionDto"/> row.</summary>
	public sealed class SessionRow
	{
		public int SessionId { get; init; }

		public string UserName { get; init; } = string.Empty;

		public string SessionName { get; init; } = string.Empty;

		public string State { get; init; } = string.Empty;

		public string ClientName { get; init; } = string.Empty;

		public string ClientAddress { get; init; } = string.Empty;

		public bool IsActive { get; init; }

		public bool IsDisconnected { get; init; }

		public bool IsCurrent { get; init; }

		public string StateBullet => IsActive ? "●" : IsDisconnected ? "◐" : "○";

		public string CurrentText => IsCurrent ? "yes" : string.Empty;

		// --- Stage IP-E historical-context fields (additive). Never overrides live ClientAddress.

		/// <summary>Earliest <c>FirstSeenUtc</c> across matching connection facts; empty when none exist.</summary>
		public string HistoricalFirstSeenUtcText { get; init; } = string.Empty;

		/// <summary>Latest <c>LastSeenUtc</c> across matching connection facts; empty when none exist.</summary>
		public string HistoricalLastSeenUtcText { get; init; } = string.Empty;

		/// <summary>Sum of failed logons across matching connection facts; zero when no facts exist.</summary>
		public long HistoricalFailedLogons { get; init; }

		/// <summary>Sum of successful logons across matching connection facts; zero when no facts exist.</summary>
		public long HistoricalSuccessfulLogons { get; init; }

		/// <summary>Comma-separated deduplicated usernames attempted from this IP across matching facts.</summary>
		public string HistoricalUserNamesAttemptedText { get; init; } = string.Empty;

		public static SessionRow From(RdpSessionDto dto)
		{
			ArgumentNullException.ThrowIfNull(dto);
			RdpSessionHistoricalDisplay hist = ConnectionFactRowProjection.FromRdpSession(dto);
			return new SessionRow
			{
				SessionId = dto.SessionId,
				UserName = dto.UserName ?? string.Empty,
				SessionName = dto.SessionName ?? string.Empty,
				State = dto.State ?? string.Empty,
				ClientName = dto.ClientName ?? string.Empty,
				ClientAddress = dto.ClientAddress ?? string.Empty,
				IsActive = dto.IsActive,
				IsDisconnected = dto.IsDisconnected,
				IsCurrent = dto.IsCurrent,
				HistoricalFirstSeenUtcText = hist.HistoricalFirstSeenUtcText,
				HistoricalLastSeenUtcText = hist.HistoricalLastSeenUtcText,
				HistoricalFailedLogons = hist.HistoricalFailedLogons,
				HistoricalSuccessfulLogons = hist.HistoricalSuccessfulLogons,
				HistoricalUserNamesAttemptedText = hist.HistoricalUserNamesAttemptedText,
			};
		}
	}

	/// <summary>Grid view-model for one <see cref="ShadowPolicyValueDto"/> row.</summary>
	public sealed class ShadowValueRow
	{
		public string KeyPath { get; init; } = string.Empty;

		public string ValueName { get; init; } = string.Empty;

		public string CurrentText { get; init; } = string.Empty;

		public string RecommendedText { get; init; } = string.Empty;

		public string Description { get; init; } = string.Empty;
	}
}
