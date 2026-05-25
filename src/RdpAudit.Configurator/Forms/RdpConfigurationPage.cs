// File:    src/RdpAudit.Configurator/Forms/RdpConfigurationPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Read-only WinForms tab that surfaces the live Windows Terminal Services configuration
//          relevant to RDP — listener port, enabled state, NLA / SecurityLayer authentication mode,
//          Single Session per User, Hide Users on Logon Screen, Session Shadowing mode — plus
//          TermService status and the termsrv.dll product version. Each control carries a short
//          description so the operator understands exactly what each setting controls. Values are
//          requested from RdpAudit.Service over IPC first; when the service is not reachable
//          (not installed, stopped, or pipe timeout) the page falls back to an in-process direct
//          registry / service inspection equivalent to the model used by stascorp/rdpwrap's
//          RDPConf.exe. The UI clearly indicates whether the displayed snapshot came from the
//          service or the local fallback. Mutating the registry is intentionally NOT exposed in
//          this stage; write-paths flow through the existing elevated registry / policy helpers
//          and are tracked separately.
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

/// <summary>Read-only view of the live RDP configuration the Service reports over IPC, with an
/// in-process registry-based fallback when IPC is unavailable.</summary>
[SupportedOSPlatform("windows")]
public sealed class RdpConfigurationPage : TabPage
{
	private readonly RdpConfigurationSnapshotService _snapshots;
	private readonly Label _header;
	private readonly Label _serviceLine;
	private readonly Label _versionLine;
	private readonly Label _portLine;
	private readonly Label _enabledLine;

	private readonly Label _authValue;
	private readonly Label _authDescription;
	private readonly Label _secLayerValue;
	private readonly Label _secLayerDescription;

	private readonly CheckBox _singleSession;
	private readonly Label _singleSessionDescription;
	private readonly CheckBox _hideUsers;
	private readonly Label _hideUsersDescription;

	private readonly ComboBox _shadowMode;
	private readonly Label _shadowDescription;

	private readonly Button _refresh;
	private readonly Label _status;

	public RdpConfigurationPage(IpcClient ipc)
		: this(BuildSnapshotService(ipc, new LocalRdpConfigurationProvider()))
	{
	}

	public RdpConfigurationPage(RdpConfigurationSnapshotService snapshots)
	{
		ArgumentNullException.ThrowIfNull(snapshots);
		_snapshots = snapshots;
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
		_portLine = new Label { AutoSize = false, Width = 1100, Height = 22, Location = new Point(12, 102), Text = "Configured RDP port: probing...", Font = new Font(SystemFonts.MessageBoxFont!, FontStyle.Bold) };
		_enabledLine = new Label { AutoSize = false, Width = 1100, Height = 22, Location = new Point(12, 126), Text = "RDP enabled: probing..." };

		Label authHeader = NewSectionHeader("Authentication Mode", 160);
		_authValue = new Label
		{
			AutoSize = false,
			Width = 1100,
			Height = 22,
			Location = new Point(12, 184),
			Text = "—",
		};
		_authDescription = NewDescription(208);

		Label secLayerHeader = NewSectionHeader("Security Layer", 252);
		_secLayerValue = new Label
		{
			AutoSize = false,
			Width = 1100,
			Height = 22,
			Location = new Point(12, 276),
			Text = "—",
		};
		_secLayerDescription = NewDescription(300);

		_singleSession = new CheckBox
		{
			AutoSize = true,
			Enabled = false,
			Location = new Point(12, 344),
			Text = "Single session per user",
		};
		_singleSessionDescription = NewDescription(368);
		_singleSessionDescription.Text = RdpConfigurationModel.DescribeSingleSession;

		_hideUsers = new CheckBox
		{
			AutoSize = true,
			Enabled = false,
			Location = new Point(12, 412),
			Text = "Hide users on logon screen",
		};
		_hideUsersDescription = NewDescription(436);
		_hideUsersDescription.Text = RdpConfigurationModel.DescribeHideUsersOnLogon;

		Label shadowHeader = NewSectionHeader("Session Shadowing Mode", 480);
		_shadowMode = new ComboBox
		{
			DropDownStyle = ComboBoxStyle.DropDownList,
			Enabled = false,
			Width = 460,
			Location = new Point(12, 504),
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
		_shadowDescription = NewDescription(536);
		_shadowDescription.Text = RdpConfigurationModel.DescribeShadowMode;

		_refresh = new Button
		{
			Text = "Refresh",
			Width = 120,
			Height = 28,
			Location = new Point(12, 600),
		};
		_refresh.Click += async (_, _) => await RefreshAsync().ConfigureAwait(true);

		_status = new Label
		{
			AutoSize = false,
			Width = 1100,
			Height = 22,
			Location = new Point(140, 604),
			Text = "Ready.",
		};

		Controls.Add(_header);
		Controls.Add(_serviceLine);
		Controls.Add(_versionLine);
		Controls.Add(_portLine);
		Controls.Add(_enabledLine);
		Controls.Add(authHeader);
		Controls.Add(_authValue);
		Controls.Add(_authDescription);
		Controls.Add(secLayerHeader);
		Controls.Add(_secLayerValue);
		Controls.Add(_secLayerDescription);
		Controls.Add(_singleSession);
		Controls.Add(_singleSessionDescription);
		Controls.Add(_hideUsers);
		Controls.Add(_hideUsersDescription);
		Controls.Add(shadowHeader);
		Controls.Add(_shadowMode);
		Controls.Add(_shadowDescription);
		Controls.Add(_refresh);
		Controls.Add(_status);

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
		_status.Text = "Reading live configuration...";
		try
		{
			RdpConfigurationSnapshotResult result = await _snapshots.CaptureAsync().ConfigureAwait(true);
			if (!result.HasSnapshot || result.Snapshot is null)
			{
				ApplyUnreadableSnapshot();
				_status.Text = result.Error is null
					? "Could not read RDP configuration from the service or the local registry."
					: "Refresh failed: " + result.Error;
				return;
			}

			ApplySnapshot(result.Snapshot);
			_status.Text = string.Format(CultureInfo.InvariantCulture,
				"Source: {0}. Snapshot captured {1:yyyy-MM-dd HH:mm:ss} UTC.",
				DescribeSource(result.Source),
				result.Snapshot.CapturedUtc);
		}
		catch (Exception ex)
		{
			ApplyUnreadableSnapshot();
			_status.Text = "Refresh failed: " + ex.GetType().Name + ": " + ex.Message;
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
		// Replace any lingering "probing..." placeholders with explicit "unknown" so the operator
		// is not left looking at a perpetually in-progress UI when both paths failed.
		_serviceLine.Text = "TermService: unknown";
		_versionLine.Text = "OS: unknown    termsrv.dll: unknown";
		_portLine.Text = string.Format(CultureInfo.InvariantCulture,
			"Configured RDP port: unknown (registry not readable; default would be {0})",
			RdpConfigurationModel.DefaultRdpPort);
		_enabledLine.Text = "RDP enabled: unknown (fDenyTSConnections not readable).";
		_authValue.Text = "Unknown (UserAuthentication value not readable)";
		_authDescription.Text = RdpConfigurationModel.DescribeAuthenticationMode(RdpUserAuthenticationMode.Unknown);
		_secLayerValue.Text = "Unknown (SecurityLayer value not readable)";
		_secLayerDescription.Text = RdpConfigurationModel.DescribeSecurityLayer(RdpSecurityLayerMode.Unknown);
		_singleSession.Checked = false;
		_hideUsers.Checked = false;
		_shadowMode.SelectedIndex = 0;
	}

	private void ApplySnapshot(RdpConfigurationDto dto)
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

		int displayedPort = dto.ConfiguredPort ?? RdpConfigurationModel.DefaultRdpPort;
		string portHint = dto.ConfiguredPort is null
			? string.Format(CultureInfo.InvariantCulture,
				" (PortNumber not configured — Windows defaults to {0})",
				RdpConfigurationModel.DefaultRdpPort)
			: string.Empty;
		_portLine.Text = string.Format(CultureInfo.InvariantCulture,
			"Configured RDP port: {0}{1}",
			displayedPort, portHint);

		_enabledLine.Text = dto.RdpEnabled switch
		{
			true => "RDP enabled: yes (fDenyTSConnections = 0). " + RdpConfigurationModel.DescribeRdpEnabled,
			false => "RDP enabled: no (fDenyTSConnections = 1). " + RdpConfigurationModel.DescribeRdpEnabled,
			_ => "RDP enabled: unknown (fDenyTSConnections value missing).",
		};

		RdpUserAuthenticationMode auth = RdpConfigurationModel.AuthenticationFromRaw(
			dto.UserAuthenticationRaw == -1 ? null : dto.UserAuthenticationRaw);
		_authValue.Text = auth switch
		{
			RdpUserAuthenticationMode.NlaRequired => "NLA required (UserAuthentication = 1)",
			RdpUserAuthenticationMode.NlaNotRequired => "NLA NOT required (UserAuthentication = 0)",
			_ => "Unknown (UserAuthentication value missing)",
		};
		_authDescription.Text = RdpConfigurationModel.DescribeAuthenticationMode(auth);

		RdpSecurityLayerMode sec = RdpConfigurationModel.SecurityLayerFromRaw(
			dto.SecurityLayerRaw == -1 ? null : dto.SecurityLayerRaw);
		_secLayerValue.Text = sec switch
		{
			RdpSecurityLayerMode.SslTls => "SSL/TLS (SecurityLayer = 2)",
			RdpSecurityLayerMode.Negotiate => "Negotiate (SecurityLayer = 1)",
			RdpSecurityLayerMode.RdpSecurity => "RDP Security Layer (SecurityLayer = 0)",
			_ => "Unknown (SecurityLayer value missing)",
		};
		_secLayerDescription.Text = RdpConfigurationModel.DescribeSecurityLayer(sec);

		_singleSession.Checked = RdpConfigurationModel.BoolFlagFromRaw(dto.SingleSessionPerUserRaw);
		_singleSessionDescription.Text = RdpConfigurationModel.DescribeSingleSession
			+ (dto.SingleSessionPerUserRaw is null ? " (value is currently absent)" : string.Empty);

		bool hideUsers = RdpConfigurationModel.BoolFlagFromRaw(dto.DontDisplayLastUserNameRaw)
			|| RdpConfigurationModel.BoolFlagFromRaw(dto.DontEnumerateConnectedUsersRaw);
		_hideUsers.Checked = hideUsers;
		string hideDetail = string.Format(CultureInfo.InvariantCulture,
			" Current values: dontdisplaylastusername={0}, DontEnumerateConnectedUsers={1}.",
			dto.DontDisplayLastUserNameRaw?.ToString(CultureInfo.InvariantCulture) ?? "missing",
			dto.DontEnumerateConnectedUsersRaw?.ToString(CultureInfo.InvariantCulture) ?? "missing");
		_hideUsersDescription.Text = RdpConfigurationModel.DescribeHideUsersOnLogon + hideDetail;

		_shadowMode.SelectedIndex = ResolveShadowComboIndex(dto.ShadowModeRaw);
		_shadowDescription.Text = RdpConfigurationModel.DescribeShadowMode;
	}

	private static int ResolveShadowComboIndex(int raw) => raw switch
	{
		0 => 1,
		1 => 2,
		2 => 3,
		3 => 4,
		4 => 5,
		_ => 0,
	};
}
