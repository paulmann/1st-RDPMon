// File:    src/RdpAudit.Configurator/Forms/RdpConfigurationPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Editable WinForms tab that surfaces the live Windows Terminal Services configuration
//          relevant to RDP — listener port, enabled state, NLA / SecurityLayer authentication mode,
//          Single Session per User, Hide Users on Logon Screen, Session Shadowing mode — plus
//          TermService status and the termsrv.dll product version. Every control carries a short
//          description so the operator understands exactly what each setting controls. Values are
//          requested from RdpAudit.Service over IPC first; when the service is not reachable
//          (not installed, stopped, or pipe timeout) the page falls back to an in-process direct
//          registry / service inspection equivalent to the model used by stascorp/rdpwrap's
//          RDPConf.exe. The UI clearly indicates whether the displayed snapshot came from the
//          service or the local fallback. Mutating the registry flows through
//          <see cref="LocalRdpConfigurationWriter"/>, which captures a JSON backup of the affected
//          values before any write is committed and refuses to mutate the registry when that
//          backup step fails.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Forms;

/// <summary>Editable view of the live RDP configuration the Service reports over IPC, with an
/// in-process registry-based fallback when IPC is unavailable. Apply is guarded by a JSON
/// backup that is captured before any registry mutation lands.</summary>
[SupportedOSPlatform("windows")]
public sealed class RdpConfigurationPage : TabPage
{
	private readonly RdpConfigurationSnapshotService _snapshots;
	private readonly LocalRdpConfigurationWriter _writer;

	private readonly Label _header;
	private readonly Label _serviceLine;
	private readonly Label _versionLine;
	private readonly Label _enabledDescription;
	private readonly CheckBox _enabledCheck;
	private readonly Label _portDescription;
	private readonly NumericUpDown _portInput;

	private readonly Label _authDescription;
	private readonly RadioButton _authNla;
	private readonly RadioButton _authNegotiate;
	private readonly RadioButton _authRdpSec;

	private readonly CheckBox _singleSession;
	private readonly Label _singleSessionDescription;
	private readonly CheckBox _hideUsers;
	private readonly Label _hideUsersDescription;

	private readonly ComboBox _shadowMode;
	private readonly Label _shadowDescription;

	private readonly Button _refresh;
	private readonly Button _apply;
	private readonly Button _cancel;
	private readonly Label _status;

	private RdpConfigurationDto? _baseline;
	private RdpConfigurationEditModel _edits = new();
	private bool _suppressDirtyEvents;
	private bool _dirty;

	public RdpConfigurationPage(IpcClient ipc)
		: this(BuildSnapshotService(ipc, new LocalRdpConfigurationProvider()), new LocalRdpConfigurationWriter())
	{
	}

	public RdpConfigurationPage(RdpConfigurationSnapshotService snapshots, LocalRdpConfigurationWriter writer)
	{
		ArgumentNullException.ThrowIfNull(snapshots);
		ArgumentNullException.ThrowIfNull(writer);
		_snapshots = snapshots;
		_writer = writer;
		Text = "RDP Configuration";
		Padding = new Padding(12);
		AutoScroll = true;

		_header = new Label
		{
			Text = "RDP Listener Configuration",
			AutoSize = true,
			Font = new Font(SystemFonts.MessageBoxFont!.FontFamily, 14f, FontStyle.Bold),
			Location = new Point(12, 12),
		};

		_serviceLine = new Label { AutoSize = false, Width = 1100, Height = 22, Location = new Point(12, 50), Text = "TermService: probing..." };
		_versionLine = new Label { AutoSize = false, Width = 1100, Height = 22, Location = new Point(12, 76), Text = "termsrv.dll: probing..." };

		_enabledCheck = new CheckBox
		{
			AutoSize = true,
			Location = new Point(12, 110),
			Text = "Enable Remote Desktop (fDenyTSConnections = 0)",
		};
		_enabledCheck.CheckedChanged += (_, _) => OnEditChanged(() => _edits.RdpEnabled = _enabledCheck.Checked);
		_enabledDescription = NewDescription(134);
		_enabledDescription.Text = RdpConfigurationModel.DescribeRdpEnabled;

		_portInput = new NumericUpDown
		{
			Minimum = RdpConfigurationModel.MinPort,
			Maximum = RdpConfigurationModel.MaxPort,
			Width = 140,
			Location = new Point(12, 178),
		};
		_portInput.ValueChanged += (_, _) => OnEditChanged(() => _edits.Port = (int)_portInput.Value);
		_portDescription = NewDescription(208);
		_portDescription.Text = RdpConfigurationModel.DescribePortNumber;

		Label authHeader = NewSectionHeader("Authentication Mode", 256);
		_authNla = new RadioButton
		{
			AutoSize = true,
			Location = new Point(12, 282),
			Text = "Network Level Authentication required (UserAuthentication=1, SecurityLayer=2). Recommended.",
		};
		_authNla.CheckedChanged += (_, _) => OnAuthModeChanged();

		_authNegotiate = new RadioButton
		{
			AutoSize = true,
			Location = new Point(12, 304),
			Text = "Default RDP authentication — negotiate (UserAuthentication=0, SecurityLayer=1).",
		};
		_authNegotiate.CheckedChanged += (_, _) => OnAuthModeChanged();

		_authRdpSec = new RadioButton
		{
			AutoSize = true,
			Location = new Point(12, 326),
			Text = "RDP Security Layer — legacy (UserAuthentication=0, SecurityLayer=0). Not recommended.",
		};
		_authRdpSec.CheckedChanged += (_, _) => OnAuthModeChanged();

		_authDescription = NewDescription(350);
		_authDescription.Text = RdpConfigurationModel.DescribeAuthenticationMode(RdpUserAuthenticationMode.NlaRequired);

		_singleSession = new CheckBox
		{
			AutoSize = true,
			Location = new Point(12, 394),
			Text = "Single session per user",
		};
		_singleSession.CheckedChanged += (_, _) => OnEditChanged(() => _edits.SingleSessionPerUser = _singleSession.Checked);
		_singleSessionDescription = NewDescription(418);
		_singleSessionDescription.Text = RdpConfigurationModel.DescribeSingleSession;

		_hideUsers = new CheckBox
		{
			AutoSize = true,
			Location = new Point(12, 462),
			Text = "Hide users on logon screen",
		};
		_hideUsers.CheckedChanged += (_, _) => OnEditChanged(() => _edits.HideUsersOnLogon = _hideUsers.Checked);
		_hideUsersDescription = NewDescription(486);
		_hideUsersDescription.Text = RdpConfigurationModel.DescribeHideUsersOnLogon;

		Label shadowHeader = NewSectionHeader("Session Shadowing Mode", 530);
		_shadowMode = new ComboBox
		{
			DropDownStyle = ComboBoxStyle.DropDownList,
			Width = 460,
			Location = new Point(12, 554),
		};
		_shadowMode.Items.AddRange(new object[]
		{
			"Not configured (Windows default)",
			"0 - No shadow allowed",
			"1 - Full control with user consent",
			"2 - Full control without user consent",
			"3 - View only with user consent",
			"4 - View only without user consent",
		});
		_shadowMode.SelectedIndex = 0;
		_shadowMode.SelectedIndexChanged += (_, _) => OnEditChanged(() => _edits.ShadowMode = ShadowFromComboIndex(_shadowMode.SelectedIndex));
		_shadowDescription = NewDescription(586);
		_shadowDescription.Text = RdpConfigurationModel.DescribeShadowMode;

		_refresh = new Button { Text = "Reload", Width = 100, Height = 28, Location = new Point(12, 650) };
		_refresh.Click += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_apply = new Button { Text = "Apply", Width = 100, Height = 28, Location = new Point(124, 650), Enabled = false };
		_apply.Click += (_, _) => OnApply();

		_cancel = new Button { Text = "Cancel", Width = 100, Height = 28, Location = new Point(236, 650), Enabled = false };
		_cancel.Click += (_, _) => OnCancel();

		_status = new Label
		{
			AutoSize = false,
			Width = 1100,
			Height = 36,
			Location = new Point(12, 686),
			Text = "Ready.",
		};

		Controls.Add(_header);
		Controls.Add(_serviceLine);
		Controls.Add(_versionLine);
		Controls.Add(_enabledCheck);
		Controls.Add(_enabledDescription);
		Controls.Add(_portInput);
		Controls.Add(_portDescription);
		Controls.Add(authHeader);
		Controls.Add(_authNla);
		Controls.Add(_authNegotiate);
		Controls.Add(_authRdpSec);
		Controls.Add(_authDescription);
		Controls.Add(_singleSession);
		Controls.Add(_singleSessionDescription);
		Controls.Add(_hideUsers);
		Controls.Add(_hideUsersDescription);
		Controls.Add(shadowHeader);
		Controls.Add(_shadowMode);
		Controls.Add(_shadowDescription);
		Controls.Add(_refresh);
		Controls.Add(_apply);
		Controls.Add(_cancel);
		Controls.Add(_status);

		SetEditControlsEnabled(false);
		HandleCreated += async (_, _) => await RefreshAsync().ConfigureAwait(true);
	}

	private static RdpConfigurationSnapshotService BuildSnapshotService(
		IpcClient ipc,
		LocalRdpConfigurationProvider local)
	{
		ArgumentNullException.ThrowIfNull(ipc);
		ArgumentNullException.ThrowIfNull(local);
		return new RdpConfigurationSnapshotService(
			ipcFetch: ct => ipc.SendAsync<RdpConfigurationDto>(IpcCommand.GetRdpConfiguration, null, ct),
			localFetch: local.Read);
	}

	private static Label NewSectionHeader(string text, int y)
	{
		return new Label
		{
			Text = text,
			AutoSize = true,
			Location = new Point(12, y),
			Font = new Font(SystemFonts.MessageBoxFont!, FontStyle.Bold),
		};
	}

	private static Label NewDescription(int y)
	{
		return new Label
		{
			AutoSize = false,
			Width = 1100,
			Height = 38,
			Location = new Point(12, y),
			ForeColor = SystemColors.GrayText,
		};
	}

	private async Task RefreshAsync()
	{
		_refresh.Enabled = false;
		_apply.Enabled = false;
		_cancel.Enabled = false;
		_status.Text = "Reading live configuration...";
		try
		{
			RdpConfigurationSnapshotResult result = await _snapshots.CaptureAsync().ConfigureAwait(true);
			if (!result.HasSnapshot || result.Snapshot is null)
			{
				ApplyUnreadableSnapshot();
				_status.Text = result.Error is null
					? "Could not read RDP configuration from the service or the local registry."
					: "Reload failed: " + result.Error;
				return;
			}

			_baseline = result.Snapshot;
			LoadEditsFromSnapshot(_baseline);
			SetEditControlsEnabled(true);
			SetDirty(false);
			_status.Text = string.Format(CultureInfo.InvariantCulture,
				"Source: {0}. Snapshot captured {1:yyyy-MM-dd HH:mm:ss} UTC.",
				DescribeSource(result.Source),
				_baseline.CapturedUtc);
		}
		catch (Exception ex)
		{
			ApplyUnreadableSnapshot();
			_status.Text = "Reload failed: " + ex.GetType().Name + ": " + ex.Message;
		}
		finally
		{
			_refresh.Enabled = true;
		}
	}

	private static string DescribeSource(RdpConfigurationSnapshotSource source) => source switch
	{
		RdpConfigurationSnapshotSource.ServiceIpc => "RdpAudit service (IPC)",
		RdpConfigurationSnapshotSource.LocalFallback => "local machine fallback",
		_ => "unknown",
	};

	private void ApplyUnreadableSnapshot()
	{
		_baseline = null;
		_serviceLine.Text = "TermService: unknown";
		_versionLine.Text = "OS: unknown    termsrv.dll: unknown";
		_suppressDirtyEvents = true;
		try
		{
			_enabledCheck.Checked = false;
			_portInput.Value = RdpConfigurationModel.DefaultRdpPort;
			_authNla.Checked = true;
			_singleSession.Checked = false;
			_hideUsers.Checked = false;
			_shadowMode.SelectedIndex = 0;
		}
		finally
		{
			_suppressDirtyEvents = false;
		}

		SetEditControlsEnabled(false);
	}

	private void LoadEditsFromSnapshot(RdpConfigurationDto dto)
	{
		_serviceLine.Text = string.Format(CultureInfo.InvariantCulture,
			"TermService: {0}{1}",
			dto.TermServiceInstalled ? "installed" : "not installed",
			dto.TermServiceInstalled ? (dto.TermServiceRunning ? " (running)" : " (stopped)") : string.Empty);

		StringBuilder version = new();
		version.Append("OS: ").Append(string.IsNullOrWhiteSpace(dto.OsVersion) ? "unknown" : dto.OsVersion);
		if (!string.IsNullOrWhiteSpace(dto.TermServiceVersion))
		{
			version.Append("    termsrv.dll: ").Append(dto.TermServiceVersion);
		}

		_versionLine.Text = version.ToString();

		_edits = RdpConfigurationEditModel.FromSnapshot(dto);

		_suppressDirtyEvents = true;
		try
		{
			_enabledCheck.Checked = _edits.RdpEnabled;
			_portInput.Value = Math.Clamp(_edits.Port, (int)_portInput.Minimum, (int)_portInput.Maximum);
			_singleSession.Checked = _edits.SingleSessionPerUser;
			_hideUsers.Checked = _edits.HideUsersOnLogon;
			SelectAuthMode(_edits.AuthenticationMode);
			_shadowMode.SelectedIndex = ComboIndexFromShadow(_edits.ShadowMode);
		}
		finally
		{
			_suppressDirtyEvents = false;
		}

		_authDescription.Text = DescribeAuthMode(_edits.AuthenticationMode);

		string hideDetail = string.Format(CultureInfo.InvariantCulture,
			" Current values: dontdisplaylastusername={0}, DontEnumerateConnectedUsers={1}.",
			dto.DontDisplayLastUserNameRaw?.ToString(CultureInfo.InvariantCulture) ?? "missing",
			dto.DontEnumerateConnectedUsersRaw?.ToString(CultureInfo.InvariantCulture) ?? "missing");
		_hideUsersDescription.Text = RdpConfigurationModel.DescribeHideUsersOnLogon + hideDetail;
		_singleSessionDescription.Text = RdpConfigurationModel.DescribeSingleSession
			+ (dto.SingleSessionPerUserRaw is null ? " (value is currently absent)" : string.Empty);
	}

	private void SelectAuthMode(RdpAuthenticationMode mode)
	{
		_authNla.Checked = mode == RdpAuthenticationMode.NetworkLevelAuth;
		_authNegotiate.Checked = mode == RdpAuthenticationMode.NegotiateNoNla;
		_authRdpSec.Checked = mode == RdpAuthenticationMode.RdpSecurityLayer;
	}

	private void OnAuthModeChanged()
	{
		if (_suppressDirtyEvents)
		{
			return;
		}

		RdpAuthenticationMode mode = _authNla.Checked ? RdpAuthenticationMode.NetworkLevelAuth
			: _authNegotiate.Checked ? RdpAuthenticationMode.NegotiateNoNla
			: _authRdpSec.Checked ? RdpAuthenticationMode.RdpSecurityLayer
			: RdpAuthenticationMode.NetworkLevelAuth;
		_edits.AuthenticationMode = mode;
		_authDescription.Text = DescribeAuthMode(mode);
		SetDirty(true);
	}

	private static string DescribeAuthMode(RdpAuthenticationMode mode) => mode switch
	{
		RdpAuthenticationMode.NetworkLevelAuth =>
			RdpConfigurationModel.DescribeAuthenticationMode(RdpUserAuthenticationMode.NlaRequired)
			+ "  /  "
			+ RdpConfigurationModel.DescribeSecurityLayer(RdpSecurityLayerMode.SslTls),
		RdpAuthenticationMode.NegotiateNoNla =>
			RdpConfigurationModel.DescribeAuthenticationMode(RdpUserAuthenticationMode.NlaNotRequired)
			+ "  /  "
			+ RdpConfigurationModel.DescribeSecurityLayer(RdpSecurityLayerMode.Negotiate),
		RdpAuthenticationMode.RdpSecurityLayer =>
			RdpConfigurationModel.DescribeAuthenticationMode(RdpUserAuthenticationMode.NlaNotRequired)
			+ "  /  "
			+ RdpConfigurationModel.DescribeSecurityLayer(RdpSecurityLayerMode.RdpSecurity),
		_ => string.Empty,
	};

	private void OnEditChanged(Action mutate)
	{
		if (_suppressDirtyEvents)
		{
			return;
		}

		mutate();
		SetDirty(true);
	}

	private void SetDirty(bool dirty)
	{
		_dirty = dirty;
		_cancel.Enabled = dirty && _baseline is not null;
		_apply.Enabled = dirty && _baseline is not null && _edits.Validate().IsValid;
	}

	private void SetEditControlsEnabled(bool enabled)
	{
		_enabledCheck.Enabled = enabled;
		_portInput.Enabled = enabled;
		_authNla.Enabled = enabled;
		_authNegotiate.Enabled = enabled;
		_authRdpSec.Enabled = enabled;
		_singleSession.Enabled = enabled;
		_hideUsers.Enabled = enabled;
		_shadowMode.Enabled = enabled;
	}

	private void OnCancel()
	{
		if (_baseline is null)
		{
			return;
		}

		LoadEditsFromSnapshot(_baseline);
		SetDirty(false);
		_status.Text = "Reverted edits to last loaded snapshot.";
	}

	private void OnApply()
	{
		if (_baseline is null)
		{
			_status.Text = "Apply blocked: no baseline snapshot loaded.";
			return;
		}

		RdpConfigurationValidationResult validation = _edits.Validate();
		if (!validation.IsValid)
		{
			_status.Text = "Apply blocked: " + string.Join("  |  ", validation.Errors);
			return;
		}

		RdpConfigurationChangeSet changes = _edits.ComputeChanges(_baseline);
		if (!changes.HasChanges)
		{
			_status.Text = "Nothing to apply — no fields diverged from the loaded snapshot.";
			SetDirty(false);
			return;
		}

		string confirmation = string.Format(CultureInfo.InvariantCulture,
			"Apply {0} RDP configuration change(s)?\n\nA JSON backup of every affected value is "
			+ "captured first under %ProgramData%\\RdpAudit\\Backups so the change is reversible.",
			changes.Writes.Count);
		if (MessageBox.Show(confirmation, "Confirm Apply", MessageBoxButtons.YesNo,
			MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
		{
			_status.Text = "Apply cancelled by operator.";
			return;
		}

		_apply.Enabled = false;
		_cancel.Enabled = false;
		_status.Text = "Applying configuration...";
		LocalRdpConfigurationApplyResult result;
		try
		{
			result = _writer.Apply(changes);
		}
		catch (Exception ex)
		{
			_status.Text = "Apply failed: " + ex.GetType().Name + " — " + ex.Message;
			return;
		}

		if (!result.Success)
		{
			_status.Text = "Apply failed: " + (result.Error ?? "(unknown)");
			return;
		}

		StringBuilder summary = new();
		summary.Append(string.Format(CultureInfo.InvariantCulture,
			"Applied {0} change(s). Backup: {1}.",
			result.WrittenValueLabels.Count,
			result.BackupFilePath ?? "(none)"));
		if (PortMutationRequiresRestart(changes))
		{
			summary.Append(" Listener port change requires TermService restart or reboot to take effect.");
		}

		_status.Text = summary.ToString();
		_ = RefreshAsync();
	}

	private static bool PortMutationRequiresRestart(RdpConfigurationChangeSet changes)
	{
		foreach (RdpRegistryWrite write in changes.Writes)
		{
			if (string.Equals(write.KeyPath, RdpConfigurationModel.RdpTcpListenerKey, StringComparison.OrdinalIgnoreCase)
				&& string.Equals(write.ValueName, RdpConfigurationModel.PortNumberValueName, StringComparison.Ordinal))
			{
				return true;
			}
		}

		return false;
	}

	private static int ComboIndexFromShadow(ShadowPolicyMode mode) => mode switch
	{
		ShadowPolicyMode.NoShadow => 1,
		ShadowPolicyMode.FullControlWithConsent => 2,
		ShadowPolicyMode.FullControlNoConsent => 3,
		ShadowPolicyMode.ViewWithConsent => 4,
		ShadowPolicyMode.ViewNoConsent => 5,
		_ => 0,
	};

	private static ShadowPolicyMode ShadowFromComboIndex(int index) => index switch
	{
		1 => ShadowPolicyMode.NoShadow,
		2 => ShadowPolicyMode.FullControlWithConsent,
		3 => ShadowPolicyMode.FullControlNoConsent,
		4 => ShadowPolicyMode.ViewWithConsent,
		5 => ShadowPolicyMode.ViewNoConsent,
		_ => ShadowPolicyMode.NotConfigured,
	};
}
