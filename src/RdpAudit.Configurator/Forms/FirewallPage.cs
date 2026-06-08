// File:    src/RdpAudit.Configurator/Forms/FirewallPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Stage 5 Firewall tab. Surfaces provider status / availability, the auto-block policy
//          knobs from FirewallOptions, blocklist / whitelist / login-rule / active-block grids
//          with search and validated add/remove, an Unblock control for installed rules, and a
//          status strip that timestamps every operator action. All writes flow through IPC; the
//          Configurator never opens the SQLite file directly. Settings persistence reuses the
//          existing SaveSettings IPC round-trip (load options → mutate firewall block → save).
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Config;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Forms;

/// <summary>Stage 5 Firewall tab: provider status, auto-block policy, lists, active blocks.</summary>
[SupportedOSPlatform("windows")]
public sealed class FirewallPage : TabPage
{
	private readonly IpcClient _ipc;
	private readonly StatusStrip _statusStrip;
	private readonly ToolStripStatusLabel _statusLabel;
	private readonly TabControl _innerTabs;

	// Provider / status section ---------------------------------------------------------------------
	private readonly CheckBox _enableBlockingCheck;
	private readonly ComboBox _providerCombo;
	private readonly Label _providerStatusLabel;
	private readonly Label _windowsStatusLabel;
	private readonly Label _countersLabel;
	private readonly Button _refreshStatus;

	// Auto-block policy section ---------------------------------------------------------------------
	private readonly CheckBox _autoBlockBruteForceCheck;
	private readonly NumericUpDown _thresholdInput;
	private readonly NumericUpDown _durationDays;
	private readonly NumericUpDown _durationHours;
	private readonly NumericUpDown _durationMinutes;
	private readonly CheckBox _blockOnBlacklistedLoginCheck;
	private readonly CheckBox _refusePrivateAddressCheck;
	private readonly Button _savePolicyButton;
	private readonly Button _reloadPolicyButton;

	// Grids ----------------------------------------------------------------------------------------
	private readonly BindingList<AddressListRow> _blocklistRows = new();
	private readonly BindingList<AddressListRow> _whitelistRows = new();
	private readonly BindingList<LoginRuleRow> _loginRuleRows = new();
	private readonly BindingList<ActiveBlockRow> _activeBlockRows = new();

	private readonly List<AddressListEntryDto> _blocklistAll = new();
	private readonly List<AddressListEntryDto> _whitelistAll = new();
	private readonly List<LoginRuleDto> _loginRulesAll = new();
	private readonly List<ActiveBlockDto> _activeBlocksAll = new();

	private readonly DataGridView _blocklistGrid;
	private readonly DataGridView _whitelistGrid;
	private readonly DataGridView _loginRulesGrid;
	private readonly DataGridView _activeBlocksGrid;

	private readonly TextBox _blocklistFilter;
	private readonly TextBox _whitelistFilter;
	private readonly TextBox _loginRulesFilter;
	private readonly TextBox _activeBlocksFilter;

	private readonly TextBox _blocklistInput;
	private readonly TextBox _whitelistInput;
	private readonly TextBox _loginRuleInput;

	private readonly System.Windows.Forms.Timer _timer;

	private RdpAuditOptions _lastLoadedOptions = new();
	private FirewallStatusDto? _lastStatus;

	// --- Firewall provider diagnostics panel (Kaspersky / third-party awareness).
	private readonly Label _providerKindLabel;
	private readonly Label _providerKasperskyLabel;
	private readonly Label _providerLocalRulesLabel;
	private readonly TextBox _providerDiagnosticsText;
	private readonly Button _providerRefreshButton;
	private readonly Button _providerCopyButton;
	private readonly FirewallProviderDiagnosticsProbe _providerProbe = new();
	private FirewallProviderDiagnostics? _lastProviderDiagnostics;

	public FirewallPage(IpcClient ipc)
	{
		_ipc = ipc;
		Text = "Firewall";

		_statusStrip = new StatusStrip { SizingGrip = false };
		_statusLabel = new ToolStripStatusLabel("Ready.")
		{
			Spring = true,
			TextAlign = System.Drawing.ContentAlignment.MiddleLeft,
		};
		_statusStrip.Items.Add(_statusLabel);

		// --- Provider / status panel -----------------------------------------------------------
		// AutoSize so the GroupBox always fits its rows and never overlaps the inner tabs below.
		GroupBox providerBox = new()
		{
			Text = "Provider and status",
			Dock = DockStyle.Fill,
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			MinimumSize = new Size(0, 130),
		};
		TableLayoutPanel providerLayout = new()
		{
			Dock = DockStyle.Fill,
			ColumnCount = 4,
			RowCount = 4,
			Padding = new Padding(8),
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
		};
		providerLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 220));
		providerLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
		providerLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 140));
		providerLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

		_enableBlockingCheck = new CheckBox
		{
			Text = "Enable Windows Firewall blocking (add attackers to firewall)",
			AutoSize = true,
		};

		_providerCombo = new ComboBox
		{
			Dock = DockStyle.Fill,
			DropDownStyle = ComboBoxStyle.DropDownList,
		};
		_providerCombo.Items.Add(new ProviderChoice("None — audit only", FirewallProviderKind.None, true));
		_providerCombo.Items.Add(new ProviderChoice("Windows Firewall (advfirewall)", FirewallProviderKind.Windows, true));
		_providerCombo.Items.Add(new ProviderChoice("MikroTik (Stage 6 — disabled)", FirewallProviderKind.MikroTik, false));
		_providerCombo.Items.Add(new ProviderChoice("Both Windows + MikroTik (Stage 6 — disabled)", FirewallProviderKind.Both, false));
		_providerCombo.SelectedIndex = 1;

		_providerStatusLabel = new Label { Dock = DockStyle.Fill, AutoSize = false, Text = "Provider status: unknown" };
		_windowsStatusLabel = new Label { Dock = DockStyle.Fill, AutoSize = false, Text = "Windows: unknown" };
		_countersLabel = new Label { Dock = DockStyle.Fill, AutoSize = false, Text = "Counters: unknown" };

		_refreshStatus = new Button { Text = "Refresh status", AutoSize = true };
		_refreshStatus.Click += async (_, _) => await RefreshAllAsync().ConfigureAwait(true);

		providerLayout.Controls.Add(_enableBlockingCheck, 0, 0);
		providerLayout.SetColumnSpan(_enableBlockingCheck, 3);
		providerLayout.Controls.Add(_refreshStatus, 3, 0);
		providerLayout.Controls.Add(new Label { Text = "Active provider:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 1);
		providerLayout.Controls.Add(_providerCombo, 1, 1);
		providerLayout.SetColumnSpan(_providerCombo, 3);
		providerLayout.Controls.Add(_providerStatusLabel, 0, 2);
		providerLayout.SetColumnSpan(_providerStatusLabel, 2);
		providerLayout.Controls.Add(_windowsStatusLabel, 2, 2);
		providerLayout.SetColumnSpan(_windowsStatusLabel, 2);
		providerLayout.Controls.Add(_countersLabel, 0, 3);
		providerLayout.SetColumnSpan(_countersLabel, 4);
		providerBox.Controls.Add(providerLayout);

		// --- Auto-block policy panel -----------------------------------------------------------
		// Layout strategy:
		//   * GroupBox + inner TableLayoutPanel are both AutoSize so the row count drives the
		//     final height — the inner tabs below can never overlap because the root grid uses
		//     RowStyle AutoSize for the policy row.
		//   * The policy grid has TWO columns (label / value). Anything that needs to fit several
		//     widgets side-by-side (the d / h / m duration spinners) is bundled into a child
		//     FlowLayoutPanel placed in the value column, so the parent grid never has to widen.
		//   * Each NumericUpDown sits next to its compact unit label inside the FlowLayoutPanel.
		//     "Default block duration" stays a single compact group regardless of window width.
		GroupBox policyBox = new()
		{
			Text = "Auto-block policy",
			Dock = DockStyle.Fill,
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			MinimumSize = new Size(0, 170),
		};
		TableLayoutPanel policyLayout = new()
		{
			Dock = DockStyle.Fill,
			ColumnCount = 2,
			RowCount = 6,
			Padding = new Padding(8),
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
		};
		policyLayout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
		policyLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
		for (int i = 0; i < 6; i++)
		{
			policyLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		}

		_autoBlockBruteForceCheck = new CheckBox
		{
			Text = "Auto-block if source is not whitelisted and failed attempts exceed threshold",
			AutoSize = true,
		};
		_blockOnBlacklistedLoginCheck = new CheckBox
		{
			Text = "Auto-block if attempted login is blacklisted",
			AutoSize = true,
		};
		_refusePrivateAddressCheck = new CheckBox
		{
			Text = "Refuse blocks against loopback / private / multicast addresses",
			AutoSize = true,
		};

		_thresholdInput = new NumericUpDown
		{
			Minimum = 1,
			Maximum = 100_000,
			Value = 50,
			Width = 90,
			Anchor = AnchorStyles.Left,
			Margin = new Padding(0, 2, 0, 2),
		};

		_durationDays = MakeCompactDurationInput(0, 365);
		_durationHours = MakeCompactDurationInput(0, 23);
		_durationMinutes = MakeCompactDurationInput(0, 59);

		// Compact FlowLayoutPanel grouping the three spinners with their unit labels so the
		// default-block-duration row stays tight (~260 px) no matter how wide the parent column
		// becomes. Anchor=Left keeps the group left-aligned inside the percent-100 value column.
		FlowLayoutPanel durationRow = new()
		{
			FlowDirection = FlowDirection.LeftToRight,
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			WrapContents = false,
			Margin = new Padding(0),
			Anchor = AnchorStyles.Left,
		};
		durationRow.Controls.Add(_durationDays);
		durationRow.Controls.Add(MakeUnitLabel("days"));
		durationRow.Controls.Add(_durationHours);
		durationRow.Controls.Add(MakeUnitLabel("hours"));
		durationRow.Controls.Add(_durationMinutes);
		durationRow.Controls.Add(MakeUnitLabel("min"));

		_savePolicyButton = new Button { Text = "Save policy", AutoSize = true };
		_savePolicyButton.Click += async (_, _) => await SavePolicyAsync().ConfigureAwait(true);

		_reloadPolicyButton = new Button { Text = "Reload from service", AutoSize = true };
		_reloadPolicyButton.Click += async (_, _) => await ReloadPolicyAsync().ConfigureAwait(true);

		// Row 0 — full-width brute-force checkbox.
		policyLayout.Controls.Add(_autoBlockBruteForceCheck, 0, 0);
		policyLayout.SetColumnSpan(_autoBlockBruteForceCheck, 2);

		// Row 1 — threshold (label | value column).
		policyLayout.Controls.Add(MakePolicyLabel("Threshold (failed attempts):"), 0, 1);
		policyLayout.Controls.Add(_thresholdInput, 1, 1);

		// Row 2 — default block duration (label | compact d/h/m group).
		policyLayout.Controls.Add(MakePolicyLabel("Default block duration:"), 0, 2);
		policyLayout.Controls.Add(durationRow, 1, 2);

		// Row 3 — blacklisted-login checkbox (full width).
		policyLayout.Controls.Add(_blockOnBlacklistedLoginCheck, 0, 3);
		policyLayout.SetColumnSpan(_blockOnBlacklistedLoginCheck, 2);

		// Row 4 — refuse-private checkbox (full width).
		policyLayout.Controls.Add(_refusePrivateAddressCheck, 0, 4);
		policyLayout.SetColumnSpan(_refusePrivateAddressCheck, 2);

		FlowLayoutPanel policyButtons = new() { FlowDirection = FlowDirection.LeftToRight, AutoSize = true, Margin = new Padding(0, 4, 0, 0) };
		policyButtons.Controls.Add(_savePolicyButton);
		policyButtons.Controls.Add(_reloadPolicyButton);
		policyLayout.Controls.Add(policyButtons, 0, 5);
		policyLayout.SetColumnSpan(policyButtons, 2);

		policyBox.Controls.Add(policyLayout);

		// --- Inner tab control (lists) ---------------------------------------------------------
		// MinimumSize keeps the grids usable even when the host window shrinks below the original
		// screenshot size; the root TableLayoutPanel still gives the auto-block policy row its
		// AutoSize height before the inner tabs claim the remaining space.
		_innerTabs = new TabControl
		{
			Dock = DockStyle.Fill,
			MinimumSize = new Size(0, 220),
		};

		_blocklistGrid = MakeAddressGrid();
		_blocklistGrid.DataSource = _blocklistRows;
		SortableGrid.Enable(_blocklistGrid, _blocklistRows);
		AttachReputationMenu(_blocklistGrid, () => SelectedRow(_blocklistGrid, _blocklistRows)?.Address);
		_blocklistFilter = MakeFilterBox("Filter IP / reason / source…", () => ApplyBlocklistFilter());
		_blocklistInput = MakeInputBox("IP to add to blocklist (e.g. 203.0.113.10)");
		Button blocklistAdd = MakeButton("Add IP", async (_, _) => await OnAddBlocklistAsync().ConfigureAwait(true));
		Button blocklistRemove = MakeButton("Remove selected", async (_, _) => await OnRemoveBlocklistAsync().ConfigureAwait(true));
		_innerTabs.TabPages.Add(BuildGridTab("Blocklist", _blocklistGrid, _blocklistFilter, _blocklistInput, blocklistAdd, blocklistRemove));

		_whitelistGrid = MakeAddressGrid();
		_whitelistGrid.DataSource = _whitelistRows;
		SortableGrid.Enable(_whitelistGrid, _whitelistRows);
		AttachReputationMenu(_whitelistGrid, () => SelectedRow(_whitelistGrid, _whitelistRows)?.Address);
		_whitelistFilter = MakeFilterBox("Filter IP / note / source…", () => ApplyWhitelistFilter());
		_whitelistInput = MakeInputBox("IP to add to whitelist (e.g. 198.51.100.5)");
		Button whitelistAdd = MakeButton("Add IP", async (_, _) => await OnAddWhitelistAsync().ConfigureAwait(true));
		Button whitelistRemove = MakeButton("Remove selected", async (_, _) => await OnRemoveWhitelistAsync().ConfigureAwait(true));
		_innerTabs.TabPages.Add(BuildGridTab("Whitelist", _whitelistGrid, _whitelistFilter, _whitelistInput, whitelistAdd, whitelistRemove));

		_loginRulesGrid = MakeLoginRulesGrid();
		_loginRulesGrid.DataSource = _loginRuleRows;
		SortableGrid.Enable(_loginRulesGrid, _loginRuleRows);
		_loginRulesFilter = MakeFilterBox("Filter login / note…", () => ApplyLoginRuleFilter());
		_loginRuleInput = MakeInputBox("Login to trip-wire (e.g. administrator)");
		Button loginAdd = MakeButton("Add login", async (_, _) => await OnAddLoginRuleAsync().ConfigureAwait(true));
		Button loginRemove = MakeButton("Remove selected", async (_, _) => await OnRemoveLoginRuleAsync().ConfigureAwait(true));
		Button loginToggle = MakeButton("Toggle enabled", async (_, _) => await OnToggleLoginRuleAsync().ConfigureAwait(true));
		_innerTabs.TabPages.Add(BuildGridTab("Login trip-wires", _loginRulesGrid, _loginRulesFilter, _loginRuleInput, loginAdd, loginRemove, loginToggle));

		_activeBlocksGrid = MakeActiveBlocksGrid();
		_activeBlocksGrid.DataSource = _activeBlockRows;
		SortableGrid.Enable(_activeBlocksGrid, _activeBlockRows);
		AttachReputationMenu(_activeBlocksGrid, () => SelectedRow(_activeBlocksGrid, _activeBlockRows)?.Ip);
		_activeBlocksFilter = MakeFilterBox("Filter IP / reason / provider / status…", () => ApplyActiveBlockFilter());
		Button activeUnblock = MakeButton("Unblock selected", async (_, _) => await OnUnblockActiveAsync().ConfigureAwait(true));
		_innerTabs.TabPages.Add(BuildGridTab("Active blocks", _activeBlocksGrid, _activeBlocksFilter, null, activeUnblock));

		// --- Firewall provider diagnostics panel -------------------------------------------------
		// Surfaces the detected provider (plain Windows Defender Firewall vs. Kaspersky-detected vs.
		// Kaspersky-managed vs. unclassified third-party) so the operator immediately understands
		// whether direct rule writes are expected to succeed. The Copy diagnostics button puts the
		// full provider / netsh state on the clipboard for inclusion in support tickets.
		GroupBox diagnosticsBox = new()
		{
			Text = "Firewall provider diagnostics",
			Dock = DockStyle.Fill,
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
			MinimumSize = new Size(0, 140),
		};
		TableLayoutPanel diagnosticsLayout = new()
		{
			Dock = DockStyle.Fill,
			ColumnCount = 4,
			RowCount = 4,
			Padding = new Padding(8),
			AutoSize = true,
			AutoSizeMode = AutoSizeMode.GrowAndShrink,
		};
		diagnosticsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 220));
		diagnosticsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
		diagnosticsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 160));
		diagnosticsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 160));
		for (int i = 0; i < 4; i++)
		{
			diagnosticsLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		}

		_providerKindLabel = new Label
		{
			Dock = DockStyle.Fill,
			AutoSize = false,
			Text = "Detected provider: probe pending…",
		};
		_providerKasperskyLabel = new Label
		{
			Dock = DockStyle.Fill,
			AutoSize = false,
			Text = "Kaspersky / third-party: probe pending…",
		};
		_providerLocalRulesLabel = new Label
		{
			Dock = DockStyle.Fill,
			AutoSize = false,
			Text = "Direct Windows Firewall rule management: probe pending…",
		};
		_providerDiagnosticsText = new TextBox
		{
			Dock = DockStyle.Fill,
			Multiline = true,
			ReadOnly = true,
			ScrollBars = ScrollBars.Vertical,
			WordWrap = false,
			Height = 110,
			Text = "(diagnostics will appear after refresh)",
		};
		_providerRefreshButton = new Button { Text = "Refresh diagnostics", AutoSize = true };
		_providerRefreshButton.Click += (_, _) => RefreshProviderDiagnostics();

		_providerCopyButton = new Button { Text = "Copy diagnostics", AutoSize = true };
		_providerCopyButton.Click += async (_, _) => await CopyProviderDiagnosticsAsync().ConfigureAwait(true);

		diagnosticsLayout.Controls.Add(_providerKindLabel, 0, 0);
		diagnosticsLayout.SetColumnSpan(_providerKindLabel, 2);
		diagnosticsLayout.Controls.Add(_providerRefreshButton, 2, 0);
		diagnosticsLayout.Controls.Add(_providerCopyButton, 3, 0);
		diagnosticsLayout.Controls.Add(_providerKasperskyLabel, 0, 1);
		diagnosticsLayout.SetColumnSpan(_providerKasperskyLabel, 4);
		diagnosticsLayout.Controls.Add(_providerLocalRulesLabel, 0, 2);
		diagnosticsLayout.SetColumnSpan(_providerLocalRulesLabel, 4);
		diagnosticsLayout.Controls.Add(_providerDiagnosticsText, 0, 3);
		diagnosticsLayout.SetColumnSpan(_providerDiagnosticsText, 4);
		diagnosticsBox.Controls.Add(diagnosticsLayout);

		// Root layout: TableLayoutPanel guarantees the auto-block policy controls are never
		// overlapped by the inner tabs at small client sizes or high DPI. Provider and policy
		// panels auto-size to their content; the inner tabs absorb remaining vertical space; the
		// status strip docks at the bottom. AutoScroll on the root grid is a safety-net for the
		// pathological case where the user shrinks the host window below the combined minimum
		// heights — a vertical scrollbar is far better UX than overlapped controls.
		TableLayoutPanel root = new()
		{
			Dock = DockStyle.Fill,
			ColumnCount = 1,
			RowCount = 5,
			AutoScroll = true,
		};
		root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
		root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
		root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
		root.Controls.Add(providerBox, 0, 0);
		root.Controls.Add(diagnosticsBox, 0, 1);
		root.Controls.Add(policyBox, 0, 2);
		root.Controls.Add(_innerTabs, 0, 3);
		root.Controls.Add(_statusStrip, 0, 4);

		Controls.Add(root);

		_timer = new System.Windows.Forms.Timer { Interval = 5_000 };
		_timer.Tick += async (_, _) => await RefreshAllAsync().ConfigureAwait(true);
		HandleCreated += async (_, _) =>
		{
			_timer.Start();
			await ReloadPolicyAsync().ConfigureAwait(true);
			await RefreshAllAsync().ConfigureAwait(true);
			RefreshProviderDiagnostics();
		};
	}

	private void RefreshProviderDiagnostics()
	{
		try
		{
			FirewallProviderDiagnostics diag = _providerProbe.Probe();
			_lastProviderDiagnostics = diag;

			_providerKindLabel.Text = string.Format(CultureInfo.InvariantCulture,
				"Detected provider: {0} ({1}). Configured RDP port: {2}.",
				diag.ProviderName,
				diag.ProviderKind,
				diag.ConfiguredRdpPort?.ToString(CultureInfo.InvariantCulture) ?? "unknown");

			_providerKasperskyLabel.Text = diag.ProviderKind switch
			{
				FirewallProviderDetectedKind.KasperskyManagedWindowsFirewall =>
					"Kaspersky is likely managing Windows Firewall — direct netsh writes may be blocked. "
					+ "Add allow / block rules through Kaspersky Security Center policy instead.",
				FirewallProviderDetectedKind.KasperskyDetected =>
					"Kaspersky product detected. Direct Windows Firewall writes may still succeed; "
					+ "watch the Copy diagnostics output for netsh failures.",
				FirewallProviderDetectedKind.ThirdPartyFirewallUnknown =>
					"Third-party security stack detected — RdpAudit cannot guarantee direct Windows Firewall writes.",
				FirewallProviderDetectedKind.WindowsDefenderFirewall =>
					"Plain Windows Defender Firewall — RdpAudit can manage rules directly via netsh.",
				_ => "Provider context could not be classified.",
			};

			string localRulesText = diag.LocalRuleManagementAllowed switch
			{
				true => "yes — RdpAudit will attempt direct rule writes.",
				false => "no — direct rule writes are expected to fail / be overridden.",
				_ => "unknown — see netsh diagnostics below.",
			};
			_providerLocalRulesLabel.Text = "Direct Windows Firewall rule management: " + localRulesText;

			_providerDiagnosticsText.Text = diag.BuildDiagnosticsText();
			SetStatus("Firewall provider diagnostics refreshed.");
		}
		catch (Exception ex)
		{
			SetStatus("Firewall provider diagnostics FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	private async Task CopyProviderDiagnosticsAsync()
	{
		try
		{
			string clientPart = _lastProviderDiagnostics?.BuildDiagnosticsText() ?? "(no client-side diagnostics captured yet)";

			string servicePart;
			try
			{
				FirewallDiagnosticsDto? dto = await _ipc
					.SendAsync<FirewallDiagnosticsDto>(IpcCommand.GetFirewallDiagnostics)
					.ConfigureAwait(true);
				servicePart = dto is null
					? "(service-side firewall diagnostics unreachable)"
					: dto.ReportText;
			}
			catch (Exception ex)
			{
				servicePart = "(service-side firewall diagnostics failed: " + ex.GetType().Name + " — " + ex.Message + ")";
			}

			string payload = "=== Client-side (Configurator) firewall provider probe ===" + Environment.NewLine
				+ clientPart + Environment.NewLine + Environment.NewLine
				+ "=== Service-side firewall enforcement diagnostics ===" + Environment.NewLine
				+ servicePart;

			Clipboard.SetText(payload);
			SetStatus("Firewall diagnostics (client + service) copied to clipboard.");
		}
		catch (Exception ex)
		{
			SetStatus("Copy diagnostics FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	// ---------------------------------------------------------------------------------------------
	// Status / refresh
	// ---------------------------------------------------------------------------------------------

	private async Task RefreshAllAsync()
	{
		try
		{
			Task<FirewallStatusDto?> statusTask = _ipc.SendAsync<FirewallStatusDto>(IpcCommand.GetFirewallStatus);
			Task<List<AddressListEntryDto>?> blockTask = _ipc.SendAsync<List<AddressListEntryDto>>(IpcCommand.ListBlocklist);
			Task<List<AddressListEntryDto>?> whiteTask = _ipc.SendAsync<List<AddressListEntryDto>>(IpcCommand.ListWhitelist);
			Task<List<LoginRuleDto>?> rulesTask = _ipc.SendAsync<List<LoginRuleDto>>(IpcCommand.ListLoginRules);
			Task<List<ActiveBlockDto>?> activeTask = _ipc.SendAsync<List<ActiveBlockDto>>(IpcCommand.ListActiveBlocksDetailed);

			await Task.WhenAll(statusTask, blockTask, whiteTask, rulesTask, activeTask).ConfigureAwait(true);

			FirewallStatusDto? statusDto = await statusTask.ConfigureAwait(true);
			List<AddressListEntryDto>? blocklist = await blockTask.ConfigureAwait(true);
			List<AddressListEntryDto>? whitelist = await whiteTask.ConfigureAwait(true);
			List<LoginRuleDto>? loginRules = await rulesTask.ConfigureAwait(true);
			List<ActiveBlockDto>? activeBlocks = await activeTask.ConfigureAwait(true);

			_lastStatus = statusDto;
			RenderProviderStatus(_lastStatus);

			_blocklistAll.Clear();
			if (blocklist is not null)
			{
				_blocklistAll.AddRange(blocklist);
			}
			ApplyBlocklistFilter();

			_whitelistAll.Clear();
			if (whitelist is not null)
			{
				_whitelistAll.AddRange(whitelist);
			}
			ApplyWhitelistFilter();

			_loginRulesAll.Clear();
			if (loginRules is not null)
			{
				_loginRulesAll.AddRange(loginRules);
			}
			ApplyLoginRuleFilter();

			_activeBlocksAll.Clear();
			if (activeBlocks is not null)
			{
				_activeBlocksAll.AddRange(activeBlocks);
			}
			ApplyActiveBlockFilter();

			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"Refresh OK. blocklist={0} whitelist={1} logins={2} activeBlocks={3}",
				_blocklistAll.Count, _whitelistAll.Count, _loginRulesAll.Count, _activeBlocksAll.Count));
		}
		catch (Exception ex)
		{
			SetStatus("Refresh FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	private void RenderProviderStatus(FirewallStatusDto? dto)
	{
		if (dto is null)
		{
			_providerStatusLabel.Text = "Provider status: service unreachable";
			_windowsStatusLabel.Text = "Windows: unknown";
			_countersLabel.Text = "Counters: unavailable";
			return;
		}

		string configured = dto.ConfiguredProvider.ToString();
		_providerStatusLabel.Text = string.Format(CultureInfo.InvariantCulture,
			"Configured provider: {0} | message: {1}",
			configured, dto.Message ?? "n/a");

		string windowsState;
		if (dto.ConfiguredProvider == FirewallProviderKind.None)
		{
			windowsState = "Disabled (audit only)";
		}
		else if (dto.WindowsAvailable)
		{
			windowsState = "Enabled (Windows Firewall reachable)";
		}
		else if (!OperatingSystem.IsWindows())
		{
			windowsState = "Unavailable (non-Windows host)";
		}
		else
		{
			windowsState = "Unavailable — verify netsh / advfirewall or possible third-party replacement";
		}
		_windowsStatusLabel.Text = "Windows: " + windowsState;

		_countersLabel.Text = string.Format(CultureInfo.InvariantCulture,
			"Active blocks: {0}   |   Whitelist rows: {1}   |   Blacklist rows: {2}",
			dto.ActiveBlockCount, dto.WhitelistCount, dto.BlacklistCount);
	}

	// ---------------------------------------------------------------------------------------------
	// Policy load / save
	// ---------------------------------------------------------------------------------------------

	private async Task ReloadPolicyAsync()
	{
		try
		{
			JsonNode? settings = await _ipc.SendAsync<JsonNode>(IpcCommand.GetSettings).ConfigureAwait(true);
			if (settings is null)
			{
				SetStatus("Policy reload FAILED: service unreachable.");
				return;
			}

			RdpAuditOptions? opts = JsonSerializer.Deserialize<RdpAuditOptions>(
				settings.ToJsonString(), JsonOptions.Default);
			if (opts is null)
			{
				SetStatus("Policy reload FAILED: settings JSON did not bind to RdpAuditOptions.");
				return;
			}

			_lastLoadedOptions = opts;
			FirewallOptions cfg = opts.Firewall;
			_enableBlockingCheck.Checked = cfg.Provider != FirewallProviderKind.None;
			SelectProviderCombo(cfg.Provider);
			_autoBlockBruteForceCheck.Checked = cfg.AutoBlockBruteForce;
			_blockOnBlacklistedLoginCheck.Checked = cfg.BlockOnBlacklistedLogin;
			_refusePrivateAddressCheck.Checked = cfg.RefusePrivateAddressBlock;
			_thresholdInput.Value = ClampToRange(cfg.AutoBlockThreshold, (int)_thresholdInput.Minimum, (int)_thresholdInput.Maximum);
			SetDurationFromMinutes(cfg.DefaultBlockDurationMinutes);
			SetStatus("Policy reloaded from service.");
		}
		catch (Exception ex)
		{
			SetStatus("Policy reload FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	private async Task SavePolicyAsync()
	{
		try
		{
			JsonNode? settings = await _ipc.SendAsync<JsonNode>(IpcCommand.GetSettings).ConfigureAwait(true);
			if (settings is null)
			{
				SetStatus("Save FAILED: service unreachable.");
				return;
			}

			// Mutate the firewall sub-tree in place so other unrelated sections survive verbatim.
			JsonObject root = settings.AsObject();
			if (!root.TryGetPropertyValue("Firewall", out JsonNode? firewallNode) || firewallNode is null)
			{
				firewallNode = new JsonObject();
				root["Firewall"] = firewallNode;
			}

			JsonObject firewall = firewallNode.AsObject();
			ProviderChoice choice = (ProviderChoice)_providerCombo.SelectedItem!;
			FirewallProviderKind effective = _enableBlockingCheck.Checked ? choice.Kind : FirewallProviderKind.None;
			firewall["Provider"] = (int)effective;
			firewall["AutoBlockBruteForce"] = _autoBlockBruteForceCheck.Checked;
			firewall["AutoBlockThreshold"] = (int)_thresholdInput.Value;
			firewall["BlockOnBlacklistedLogin"] = _blockOnBlacklistedLoginCheck.Checked;
			firewall["RefusePrivateAddressBlock"] = _refusePrivateAddressCheck.Checked;
			firewall["DefaultBlockDurationMinutes"] = ComputeDurationMinutes();

			JsonObject wrapped = new()
			{
				[RdpAuditOptions.SectionName] = settings.DeepClone(),
			};

			object? saveResp = await _ipc.SendAsync<object>(IpcCommand.SaveSettings, wrapped.ToJsonString()).ConfigureAwait(true);
			SetStatus(saveResp is null
				? "Save FAILED: service unreachable."
				: "Save OK. Service will hot-reload from disk.");

			await RefreshAllAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			SetStatus("Save FAILED: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	private void SelectProviderCombo(FirewallProviderKind kind)
	{
		for (int i = 0; i < _providerCombo.Items.Count; i++)
		{
			if (_providerCombo.Items[i] is ProviderChoice c && c.Kind == kind && c.Enabled)
			{
				_providerCombo.SelectedIndex = i;
				return;
			}
		}

		// Fall through: select first enabled entry.
		for (int i = 0; i < _providerCombo.Items.Count; i++)
		{
			if (_providerCombo.Items[i] is ProviderChoice c && c.Enabled)
			{
				_providerCombo.SelectedIndex = i;
				return;
			}
		}
	}

	private void SetDurationFromMinutes(int totalMinutes)
	{
		if (totalMinutes < 0)
		{
			totalMinutes = 0;
		}

		int days = totalMinutes / (24 * 60);
		int rem = totalMinutes % (24 * 60);
		int hours = rem / 60;
		int minutes = rem % 60;

		_durationDays.Value = Math.Min(days, (int)_durationDays.Maximum);
		_durationHours.Value = Math.Min(hours, (int)_durationHours.Maximum);
		_durationMinutes.Value = Math.Min(minutes, (int)_durationMinutes.Maximum);
	}

	private int ComputeDurationMinutes() =>
		(int)_durationDays.Value * 24 * 60
		+ (int)_durationHours.Value * 60
		+ (int)_durationMinutes.Value;

	// ---------------------------------------------------------------------------------------------
	// Blocklist actions
	// ---------------------------------------------------------------------------------------------

	private async Task OnAddBlocklistAsync()
	{
		string raw = _blocklistInput.Text;
		if (!AddressListFilter.IsValidIp(raw))
		{
			SetStatus("Add to blocklist aborted: input is not a valid IPv4 / IPv6 address.");
			return;
		}

		string ip = AddressListFilter.NormalizeIp(raw);
		AddressListMutationRequest payload = new()
		{
			Address = ip,
			Note = "Configurator Firewall tab manual add",
			DurationMinutes = ComputeDurationMinutes(),
		};

		bool ok = await SendMutationAsync(IpcCommand.AddToBlocklist, payload).ConfigureAwait(true);
		SetStatus(string.Format(CultureInfo.InvariantCulture,
			"AddToBlocklist {0}: {1}", ip, ok ? "OK" : "FAILED"));
		if (ok)
		{
			_blocklistInput.Text = string.Empty;
			await RefreshAllAsync().ConfigureAwait(true);
		}
	}

	private async Task OnRemoveBlocklistAsync()
	{
		AddressListRow? row = SelectedRow(_blocklistGrid, _blocklistRows);
		if (row is null)
		{
			SetStatus("Remove blocklist entry aborted: no row selected.");
			return;
		}

		string ip = row.Address;
		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Remove {0} from the blocklist? The row will be soft-disabled in the database.", ip);
		if (!Confirm(prompt, "Confirm remove blocklist entry"))
		{
			SetStatus("Remove blocklist entry cancelled.");
			return;
		}

		AddressListMutationRequest payload = new() { Address = ip };
		bool ok = await SendMutationAsync(IpcCommand.RemoveFromBlocklist, payload).ConfigureAwait(true);
		SetStatus(string.Format(CultureInfo.InvariantCulture,
			"RemoveFromBlocklist {0}: {1}", ip, ok ? "OK" : "FAILED"));
		if (ok)
		{
			await RefreshAllAsync().ConfigureAwait(true);
		}
	}

	// ---------------------------------------------------------------------------------------------
	// Whitelist actions
	// ---------------------------------------------------------------------------------------------

	private async Task OnAddWhitelistAsync()
	{
		string raw = _whitelistInput.Text;
		if (!AddressListFilter.IsValidIp(raw))
		{
			SetStatus("Add to whitelist aborted: input is not a valid IPv4 / IPv6 address.");
			return;
		}

		string ip = AddressListFilter.NormalizeIp(raw);
		AddressListMutationRequest payload = new()
		{
			Address = ip,
			Note = "Configurator Firewall tab manual add",
		};

		bool wlOk = await SendMutationAsync(IpcCommand.AddToWhitelist, payload).ConfigureAwait(true);

		bool unblockOk = true;
		if (wlOk)
		{
			DialogResult choice = MessageBox.Show(
				string.Format(CultureInfo.InvariantCulture,
					"Also unblock any active Windows Firewall rule that targets {0}?", ip),
				"Whitelist follow-up",
				MessageBoxButtons.YesNo,
				MessageBoxIcon.Question,
				MessageBoxDefaultButton.Button1);
			if (choice == DialogResult.Yes)
			{
				try
				{
					bool? legacy = await _ipc.SendAsync<bool?>(IpcCommand.UnblockAddress, ip).ConfigureAwait(true);
					unblockOk = legacy == true;
				}
				catch
				{
					unblockOk = false;
				}
			}
		}

		SetStatus(string.Format(CultureInfo.InvariantCulture,
			"AddToWhitelist {0}: whitelist={1}, unblock={2}",
			ip, wlOk ? "OK" : "FAIL", unblockOk ? "OK" : "FAIL"));
		if (wlOk)
		{
			_whitelistInput.Text = string.Empty;
			await RefreshAllAsync().ConfigureAwait(true);
		}
	}

	private async Task OnRemoveWhitelistAsync()
	{
		AddressListRow? row = SelectedRow(_whitelistGrid, _whitelistRows);
		if (row is null)
		{
			SetStatus("Remove whitelist entry aborted: no row selected.");
			return;
		}

		string ip = row.Address;
		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Remove {0} from the whitelist? The address will no longer be exempt from auto-blocking, "
			+ "but no firewall block is installed by this action.", ip);
		if (!Confirm(prompt, "Confirm remove whitelist entry"))
		{
			SetStatus("Remove whitelist entry cancelled.");
			return;
		}

		AddressListMutationRequest payload = new() { Address = ip };
		bool ok = await SendMutationAsync(IpcCommand.RemoveFromWhitelist, payload).ConfigureAwait(true);
		SetStatus(string.Format(CultureInfo.InvariantCulture,
			"RemoveFromWhitelist {0}: {1}", ip, ok ? "OK" : "FAILED"));
		if (ok)
		{
			await RefreshAllAsync().ConfigureAwait(true);
		}
	}

	// ---------------------------------------------------------------------------------------------
	// Login rule actions
	// ---------------------------------------------------------------------------------------------

	private async Task OnAddLoginRuleAsync()
	{
		string raw = _loginRuleInput.Text;
		if (string.IsNullOrWhiteSpace(raw))
		{
			SetStatus("Add login rule aborted: input is empty.");
			return;
		}

		string login;
		try
		{
			login = AddressListFilter.NormalizeLogin(raw);
		}
		catch (FormatException ex)
		{
			SetStatus("Add login rule aborted: " + ex.Message);
			return;
		}

		LoginRuleMutationRequest payload = new()
		{
			Login = login,
			Note = "Configurator Firewall tab manual add",
			Enabled = true,
		};
		bool ok = await SendMutationAsync(IpcCommand.AddLoginRule, payload).ConfigureAwait(true);
		SetStatus(string.Format(CultureInfo.InvariantCulture,
			"AddLoginRule '{0}': {1}", login, ok ? "OK" : "FAILED"));
		if (ok)
		{
			_loginRuleInput.Text = string.Empty;
			await RefreshAllAsync().ConfigureAwait(true);
		}
	}

	private async Task OnRemoveLoginRuleAsync()
	{
		LoginRuleRow? row = SelectedRow(_loginRulesGrid, _loginRuleRows);
		if (row is null)
		{
			SetStatus("Remove login rule aborted: no row selected.");
			return;
		}

		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Remove login rule '{0}'?\r\n\r\nFuture attempts using this login will no longer be "
			+ "treated as trip-wires. Local Windows accounts are NOT affected by this action.",
			row.Login);
		if (!Confirm(prompt, "Confirm remove login rule"))
		{
			SetStatus("Remove login rule cancelled.");
			return;
		}

		LoginRuleMutationRequest payload = new() { Id = row.Id, Login = row.Login };
		bool ok = await SendMutationAsync(IpcCommand.RemoveLoginRule, payload).ConfigureAwait(true);
		SetStatus(string.Format(CultureInfo.InvariantCulture,
			"RemoveLoginRule '{0}': {1}", row.Login, ok ? "OK" : "FAILED"));
		if (ok)
		{
			await RefreshAllAsync().ConfigureAwait(true);
		}
	}

	private async Task OnToggleLoginRuleAsync()
	{
		LoginRuleRow? row = SelectedRow(_loginRulesGrid, _loginRuleRows);
		if (row is null)
		{
			SetStatus("Toggle login rule aborted: no row selected.");
			return;
		}

		LoginRuleMutationRequest payload = new()
		{
			Id = row.Id,
			Login = row.Login,
			Enabled = !row.Enabled,
		};
		bool ok = await SendMutationAsync(IpcCommand.SetLoginRuleEnabled, payload).ConfigureAwait(true);
		SetStatus(string.Format(CultureInfo.InvariantCulture,
			"SetLoginRuleEnabled '{0}' → {1}: {2}",
			row.Login, payload.Enabled, ok ? "OK" : "FAILED"));
		if (ok)
		{
			await RefreshAllAsync().ConfigureAwait(true);
		}
	}

	// ---------------------------------------------------------------------------------------------
	// Active block actions
	// ---------------------------------------------------------------------------------------------

	private async Task OnUnblockActiveAsync()
	{
		ActiveBlockRow? row = SelectedRow(_activeBlocksGrid, _activeBlockRows);
		if (row is null)
		{
			SetStatus("Unblock aborted: no row selected.");
			return;
		}

		string prompt = string.Format(CultureInfo.InvariantCulture,
			"Unblock {0} via provider {1}?\r\n\r\nThis removes the installed firewall rule and "
			+ "soft-disables any matching blocklist entries.",
			row.Ip, row.Provider);
		if (!Confirm(prompt, "Confirm unblock"))
		{
			SetStatus("Unblock cancelled.");
			return;
		}

		try
		{
			JsonElement? response = await _ipc.SendAsync<JsonElement?>(IpcCommand.UnblockActiveBlock, row.Id).ConfigureAwait(true);
			SetStatus(response is null
				? string.Format(CultureInfo.InvariantCulture, "Unblock {0}: FAILED (no response).", row.Ip)
				: string.Format(CultureInfo.InvariantCulture, "Unblock {0}: response received.", row.Ip));
			await RefreshAllAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			SetStatus(string.Format(CultureInfo.InvariantCulture,
				"Unblock {0}: FAILED — {1}", row.Ip, ex.GetType().Name));
		}
	}

	// ---------------------------------------------------------------------------------------------
	// Filtering helpers
	// ---------------------------------------------------------------------------------------------

	private void ApplyBlocklistFilter()
	{
		AddressListFilter filter = new() { Query = _blocklistFilter.Text };
		_blocklistRows.RaiseListChangedEvents = false;
		_blocklistRows.Clear();
		foreach (AddressListEntryDto dto in _blocklistAll)
		{
			if (filter.Matches(dto.Address, dto.Note, dto.Source))
			{
				_blocklistRows.Add(AddressListRow.From(dto));
			}
		}

		_blocklistRows.RaiseListChangedEvents = true;
		_blocklistRows.ResetBindings();
	}

	private void ApplyWhitelistFilter()
	{
		AddressListFilter filter = new() { Query = _whitelistFilter.Text };
		_whitelistRows.RaiseListChangedEvents = false;
		_whitelistRows.Clear();
		foreach (AddressListEntryDto dto in _whitelistAll)
		{
			if (filter.Matches(dto.Address, dto.Note, dto.Source))
			{
				_whitelistRows.Add(AddressListRow.From(dto));
			}
		}

		_whitelistRows.RaiseListChangedEvents = true;
		_whitelistRows.ResetBindings();
	}

	private void ApplyLoginRuleFilter()
	{
		AddressListFilter filter = new() { Query = _loginRulesFilter.Text };
		_loginRuleRows.RaiseListChangedEvents = false;
		_loginRuleRows.Clear();
		foreach (LoginRuleDto dto in _loginRulesAll)
		{
			if (filter.Matches(dto.Login, dto.DisplayLogin, dto.Note, dto.Enabled ? "enabled" : "disabled"))
			{
				_loginRuleRows.Add(LoginRuleRow.From(dto));
			}
		}

		_loginRuleRows.RaiseListChangedEvents = true;
		_loginRuleRows.ResetBindings();
	}

	private void ApplyActiveBlockFilter()
	{
		AddressListFilter filter = new() { Query = _activeBlocksFilter.Text };
		_activeBlockRows.RaiseListChangedEvents = false;
		_activeBlockRows.Clear();
		foreach (ActiveBlockDto dto in _activeBlocksAll)
		{
			if (filter.Matches(
				dto.Ip,
				dto.Reason,
				dto.Provider.ToString(),
				dto.Status.ToString(),
				dto.LastError,
				dto.RuleHandle))
			{
				_activeBlockRows.Add(ActiveBlockRow.From(dto));
			}
		}

		_activeBlockRows.RaiseListChangedEvents = true;
		_activeBlockRows.ResetBindings();
	}

	// ---------------------------------------------------------------------------------------------
	// IPC plumbing helpers
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

	// ---------------------------------------------------------------------------------------------
	// UI helpers
	// ---------------------------------------------------------------------------------------------

	private static NumericUpDown MakeCompactDurationInput(int min, int max) => new()
	{
		Minimum = min,
		Maximum = max,
		Value = min,
		Width = 60,
		Margin = new Padding(0, 2, 2, 2),
		Anchor = AnchorStyles.Left,
	};

	private static Label MakeUnitLabel(string unit) => new()
	{
		Text = unit,
		AutoSize = true,
		Margin = new Padding(0, 6, 10, 0),
		TextAlign = ContentAlignment.MiddleLeft,
	};

	private static Label MakePolicyLabel(string text) => new()
	{
		Text = text,
		AutoSize = true,
		Anchor = AnchorStyles.Left,
		Margin = new Padding(0, 6, 12, 0),
		TextAlign = ContentAlignment.MiddleLeft,
	};

	private TextBox MakeFilterBox(string placeholder, Action onChanged)
	{
		ArgumentNullException.ThrowIfNull(onChanged);
		TextBox tb = new()
		{
			Dock = DockStyle.Top,
			PlaceholderText = placeholder,
		};
		tb.TextChanged += (_, _) => onChanged();
		return tb;
	}

	private static TextBox MakeInputBox(string placeholder) => new()
	{
		Dock = DockStyle.Top,
		PlaceholderText = placeholder,
	};

	private static Button MakeButton(string text, EventHandler onClick)
	{
		ArgumentNullException.ThrowIfNull(onClick);
		Button b = new() { Text = text, AutoSize = true, Margin = new Padding(2) };
		b.Click += onClick;
		return b;
	}

	private static TabPage BuildGridTab(
		string title,
		DataGridView grid,
		Control filterBox,
		Control? input,
		params Button[] buttons)
	{
		TabPage page = new() { Text = title };

		FlowLayoutPanel buttonBar = new() { Dock = DockStyle.Top, FlowDirection = FlowDirection.LeftToRight, AutoSize = true, Height = 36 };
		foreach (Button b in buttons)
		{
			buttonBar.Controls.Add(b);
		}

		page.Controls.Add(grid);
		page.Controls.Add(buttonBar);
		if (input is not null)
		{
			input.Dock = DockStyle.Top;
			page.Controls.Add(input);
		}
		filterBox.Dock = DockStyle.Top;
		page.Controls.Add(filterBox);
		return page;
	}

	private static DataGridView MakeAddressGrid()
	{
		DataGridView g = new()
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			ReadOnly = true,
			RowHeadersVisible = false,
			AllowUserToAddRows = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = false,
		};
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Address", DataPropertyName = nameof(AddressListRow.Address), Width = 200 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Source", DataPropertyName = nameof(AddressListRow.Source), Width = 130 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Added (UTC)", DataPropertyName = nameof(AddressListRow.AddedUtcText), Width = 170 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Expires (UTC)", DataPropertyName = nameof(AddressListRow.ExpiresUtcText), Width = 170 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Note / reason", DataPropertyName = nameof(AddressListRow.Note), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
		return g;
	}

	private static DataGridView MakeLoginRulesGrid()
	{
		DataGridView g = new()
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			ReadOnly = true,
			RowHeadersVisible = false,
			AllowUserToAddRows = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = false,
		};
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Id", DataPropertyName = nameof(LoginRuleRow.Id), Width = 60 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Login", DataPropertyName = nameof(LoginRuleRow.DisplayLogin), Width = 180 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Enabled", DataPropertyName = nameof(LoginRuleRow.EnabledText), Width = 70 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Trigger Count", DataPropertyName = nameof(LoginRuleRow.TriggerCount), Width = 100 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "First Triggered (UTC)", DataPropertyName = nameof(LoginRuleRow.FirstTriggeredText), Width = 160 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Last Triggered (UTC)", DataPropertyName = nameof(LoginRuleRow.LastTriggeredText), Width = 160 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Last Source IP", DataPropertyName = nameof(LoginRuleRow.LastSourceIp), Width = 130 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Added (UTC)", DataPropertyName = nameof(LoginRuleRow.AddedUtcText), Width = 160 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Note", DataPropertyName = nameof(LoginRuleRow.Note), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
		return g;
	}

	private static DataGridView MakeActiveBlocksGrid()
	{
		DataGridView g = new()
		{
			Dock = DockStyle.Fill,
			AutoGenerateColumns = false,
			ReadOnly = true,
			RowHeadersVisible = false,
			AllowUserToAddRows = false,
			SelectionMode = DataGridViewSelectionMode.FullRowSelect,
			MultiSelect = false,
		};
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Id", DataPropertyName = nameof(ActiveBlockRow.Id), Width = 70 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "IP", DataPropertyName = nameof(ActiveBlockRow.Ip), Width = 140 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Provider", DataPropertyName = nameof(ActiveBlockRow.ProviderText), Width = 100 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Rule handle", DataPropertyName = nameof(ActiveBlockRow.RuleHandle), Width = 200 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Status", DataPropertyName = nameof(ActiveBlockRow.StatusText), Width = 90 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Created (UTC)", DataPropertyName = nameof(ActiveBlockRow.CreatedUtcText), Width = 170 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Expires (UTC)", DataPropertyName = nameof(ActiveBlockRow.ExpiresUtcText), Width = 170 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Remaining", DataPropertyName = nameof(ActiveBlockRow.RemainingText), Width = 110 });
		g.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Reason / error", DataPropertyName = nameof(ActiveBlockRow.ReasonOrError), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
		return g;
	}

	private void AttachReputationMenu(DataGridView grid, Func<string?> getIp)
	{
		ContextMenuStrip menu = new();
		ToolStripMenuItem ripeStat = new(IpReputationBrowser.RipeStatMenuLabel, null, (_, _) =>
		{
			IpReputationBrowser.LaunchOutcome outcome = IpReputationBrowser.OpenRipeStat(getIp());
			SetStatus(outcome.Format());
		});
		ToolStripMenuItem abuseIpDb = new(IpReputationBrowser.AbuseIpDbMenuLabel, null, (_, _) =>
		{
			IpReputationBrowser.LaunchOutcome outcome = IpReputationBrowser.OpenAbuseIpDb(getIp());
			SetStatus(outcome.Format());
		});
		menu.Items.Add(ripeStat);
		menu.Items.Add(abuseIpDb);
		menu.Opening += (_, e) =>
		{
			bool eligible = IpReputationBrowser.IsLookupEligible(getIp());
			ripeStat.Enabled = eligible;
			abuseIpDb.Enabled = eligible;
			if (getIp() is null)
			{
				e.Cancel = true;
			}
		};
		grid.ContextMenuStrip = menu;
		grid.CellMouseDown += (_, e) =>
		{
			if (e.Button != MouseButtons.Right || e.RowIndex < 0 || e.RowIndex >= grid.RowCount)
			{
				return;
			}

			grid.ClearSelection();
			grid.Rows[e.RowIndex].Selected = true;
		};
	}

	private static T? SelectedRow<T>(DataGridView grid, BindingList<T> binding) where T : class
	{
		if (grid.SelectedRows.Count == 0)
		{
			if (grid.CurrentRow is { Index: >= 0 } cr && cr.Index < binding.Count)
			{
				return binding[cr.Index];
			}
			return null;
		}

		int index = grid.SelectedRows[0].Index;
		return index >= 0 && index < binding.Count ? binding[index] : null;
	}

	private static int ClampToRange(int value, int min, int max)
	{
		if (value < min)
		{
			return min;
		}

		return value > max ? max : value;
	}

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
		}

		base.Dispose(disposing);
	}

	// ---------------------------------------------------------------------------------------------
	// Row view-models exposed for grid binding (sealed; values are computed once at construction).
	// ---------------------------------------------------------------------------------------------

	private sealed record ProviderChoice(string Display, FirewallProviderKind Kind, bool Enabled)
	{
		public override string ToString() => Display;
	}

	/// <summary>Grid view-model for blocklist / whitelist entries.</summary>
	public sealed class AddressListRow
	{
		public string Address { get; init; } = string.Empty;

		public string? Source { get; init; }

		public string? Note { get; init; }

		public string AddedUtcText { get; init; } = string.Empty;

		public string ExpiresUtcText { get; init; } = string.Empty;

		public static AddressListRow From(AddressListEntryDto dto) => new()
		{
			Address = dto.Address,
			Source = dto.Source,
			Note = dto.Note,
			AddedUtcText = FormatUtc(dto.AddedUtc),
			ExpiresUtcText = BlockExpiryFormatter.FormatExpiresUtc(dto.ExpiresUtc),
		};
	}

	/// <summary>Grid view-model for login trip-wire entries.</summary>
	public sealed class LoginRuleRow
	{
		public long Id { get; init; }

		/// <summary>Normalized matching key (case-insensitive); retained for selection / mutation.</summary>
		public string Login { get; init; } = string.Empty;

		/// <summary>Original-case spelling shown in the grid.</summary>
		public string DisplayLogin { get; init; } = string.Empty;

		public bool Enabled { get; init; }

		public string EnabledText => Enabled ? "yes" : "no";

		public long TriggerCount { get; init; }

		public string FirstTriggeredText { get; init; } = string.Empty;

		public string LastTriggeredText { get; init; } = string.Empty;

		public string? LastSourceIp { get; init; }

		public string AddedUtcText { get; init; } = string.Empty;

		public string? Note { get; init; }

		public static LoginRuleRow From(LoginRuleDto dto) => new()
		{
			Id = dto.Id,
			Login = dto.Login,
			DisplayLogin = string.IsNullOrEmpty(dto.DisplayLogin) ? dto.Login : dto.DisplayLogin,
			Enabled = dto.Enabled,
			TriggerCount = dto.TriggerCount,
			FirstTriggeredText = FormatUtc(dto.FirstTriggeredUtc),
			LastTriggeredText = FormatUtc(dto.LastTriggeredUtc),
			LastSourceIp = dto.LastSourceIp,
			AddedUtcText = FormatUtc(dto.AddedUtc),
			Note = dto.Note,
		};
	}

	/// <summary>Grid view-model for active firewall blocks.</summary>
	public sealed class ActiveBlockRow
	{
		public long Id { get; init; }

		public string Ip { get; init; } = string.Empty;

		public FirewallProviderKind Provider { get; init; }

		public string ProviderText => Provider.ToString();

		public string? RuleHandle { get; init; }

		public string StatusText { get; init; } = string.Empty;

		public string CreatedUtcText { get; init; } = string.Empty;

		public string ExpiresUtcText { get; init; } = string.Empty;

		public string RemainingText { get; init; } = string.Empty;

		public string ReasonOrError { get; init; } = string.Empty;

		public static ActiveBlockRow From(ActiveBlockDto dto)
		{
			StringBuilder sb = new();
			if (!string.IsNullOrEmpty(dto.Reason))
			{
				sb.Append(dto.Reason);
			}

			if (!string.IsNullOrEmpty(dto.LastError))
			{
				if (sb.Length > 0)
				{
					sb.Append(" — ");
				}
				sb.Append("error: ").Append(dto.LastError);
			}

			return new ActiveBlockRow
			{
				Id = dto.Id,
				Ip = dto.Ip,
				Provider = dto.Provider,
				RuleHandle = dto.RuleHandle,
				StatusText = dto.Status.ToString(),
				CreatedUtcText = FormatUtc(dto.CreatedUtc),
				ExpiresUtcText = BlockExpiryFormatter.FormatExpiresUtc(dto.ExpiresUtc),
				RemainingText = BlockExpiryFormatter.FormatRemaining(dto.ExpiresUtc, DateTime.UtcNow),
				ReasonOrError = sb.ToString(),
			};
		}
	}

	private static string FormatUtc(DateTime? value)
	{
		if (value is null)
		{
			return string.Empty;
		}

		return value.Value.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
	}
}
