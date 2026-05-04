// File:    tests/RdpAudit.Service.Tests/AlertRuleTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit tests covering the alert rule decision boundaries (threshold / whitelist / wrong id).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Models;
using RdpAudit.Service.Alerts;
using Xunit;

namespace RdpAudit.Service.Tests;

public class AlertRuleTests
{
	private static RawEvent Logon(int eventId, string? ip = "1.2.3.4", string? user = "alice", int? logonType = 10, string? authPackage = "Kerberos") =>
		new()
		{
			Id = 42,
			EventId = eventId,
			Channel = "Security",
			TimeUtc = DateTime.UtcNow,
			SourceIp = ip,
			UserName = user,
			LogonType = logonType,
			AuthPackage = authPackage,
			Status = "0xC000006A",
		};

	[Fact]
	public async Task BruteForce_BelowThreshold_ReturnsNull()
	{
		var ctx = new MockAlertContext(
			options: new RdpAuditOptions { Alerts = new AlertOptions { BruteForceThreshold = 10 } },
			byIp: Enumerable.Range(0, 5).Select(_ => Logon(4625)));
		Assert.Null(await new BruteForceRule().EvaluateAsync(Logon(4625), ctx, default));
	}

	[Fact]
	public async Task BruteForce_AtThreshold_ReturnsAlert()
	{
		var ctx = new MockAlertContext(
			options: new RdpAuditOptions { Alerts = new AlertOptions { BruteForceThreshold = 5 } },
			byIp: Enumerable.Range(0, 5).Select(_ => Logon(4625)));
		Alert? alert = await new BruteForceRule().EvaluateAsync(Logon(4625), ctx, default);
		Assert.NotNull(alert);
		Assert.Equal("BRUTE_FORCE_01", alert!.RuleId);
	}

	[Fact]
	public async Task BruteForce_WhitelistedIp_ReturnsNull()
	{
		var opts = new RdpAuditOptions { Alerts = new AlertOptions { BruteForceThreshold = 5, WhitelistIps = new() { "1.2.3.4" } } };
		var ctx = new MockAlertContext(opts, byIp: Enumerable.Range(0, 50).Select(_ => Logon(4625)));
		Assert.Null(await new BruteForceRule().EvaluateAsync(Logon(4625), ctx, default));
	}

	[Fact]
	public async Task BruteForce_WrongEventId_ReturnsNull()
	{
		var ctx = new MockAlertContext();
		Assert.Null(await new BruteForceRule().EvaluateAsync(Logon(4624), ctx, default));
	}

	[Fact]
	public async Task PassTheHash_NtlmType3WithoutPriorExplicit_ReturnsAlert()
	{
		RawEvent evt = Logon(4624, logonType: 3, authPackage: "NTLM");
		evt.LogonId = "0xABC";
		var ctx = new MockAlertContext();
		Alert? alert = await new PassTheHashRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task PassTheHash_PrecedingExplicitMatchingLogonId_ReturnsNull()
	{
		RawEvent evt = Logon(4624, logonType: 3, authPackage: "NTLM");
		evt.LogonId = "0xABC";
		var preceding = new[]
		{
			new RawEvent { EventId = 4648, LogonId = "0xABC", UserName = evt.UserName },
		};
		var ctx = new MockAlertContext(byUser: preceding);
		Assert.Null(await new PassTheHashRule().EvaluateAsync(evt, ctx, default));
	}

	[Fact]
	public async Task PassTheHash_NonNtlm_ReturnsNull()
	{
		RawEvent evt = Logon(4624, logonType: 3, authPackage: "Kerberos");
		var ctx = new MockAlertContext();
		Assert.Null(await new PassTheHashRule().EvaluateAsync(evt, ctx, default));
	}

	[Fact]
	public async Task ExternalRdpLogin_LocalIp_ReturnsNull()
	{
		var ctx = new MockAlertContext();
		Assert.Null(await new ExternalRdpLoginRule().EvaluateAsync(Logon(4624, ip: "10.0.0.1"), ctx, default));
	}

	[Fact]
	public async Task ExternalRdpLogin_PublicIp_ReturnsAlert()
	{
		var ctx = new MockAlertContext();
		Alert? alert = await new ExternalRdpLoginRule().EvaluateAsync(Logon(4624, ip: "8.8.8.8"), ctx, default);
		Assert.NotNull(alert);
		Assert.Equal("EXTERNAL_RDP_LOGIN", alert!.RuleId);
	}

	[Fact]
	public async Task GoldenTicket_Rc4OnAesDomain_ReturnsAlert()
	{
		RawEvent evt = Logon(4769);
		evt.Details = "{\"TicketEncryptionType\":\"0x17\",\"ServiceName\":\"krbtgt\"}";
		var ctx = new MockAlertContext(new RdpAuditOptions { Alerts = new AlertOptions { KerberosExpectedEncryptionType = "0x12" } });
		Alert? alert = await new GoldenTicketRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task GoldenTicket_AesTicket_ReturnsNull()
	{
		RawEvent evt = Logon(4769);
		evt.Details = "{\"TicketEncryptionType\":\"0x12\"}";
		var ctx = new MockAlertContext(new RdpAuditOptions { Alerts = new AlertOptions { KerberosExpectedEncryptionType = "0x12" } });
		Assert.Null(await new GoldenTicketRule().EvaluateAsync(evt, ctx, default));
	}

	[Fact]
	public async Task RdpSessionHijack_TsconExe_ReturnsAlert()
	{
		RawEvent evt = Logon(4688);
		evt.ProcessName = "C:\\Windows\\System32\\tscon.exe";
		var ctx = new MockAlertContext();
		Alert? alert = await new RdpSessionHijackRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task RdpSessionHijack_NormalProcess_ReturnsNull()
	{
		RawEvent evt = Logon(4688);
		evt.ProcessName = "C:\\Windows\\System32\\notepad.exe";
		var ctx = new MockAlertContext();
		Assert.Null(await new RdpSessionHijackRule().EvaluateAsync(evt, ctx, default));
	}

	[Fact]
	public async Task UnknownIpSuccess_PriorFailures_ReturnsAlert()
	{
		var addr = new Address { Ip = "1.2.3.4", FailCount = 10, SuccessCount = 1 };
		var ctx = new MockAlertContext(address: addr);
		Alert? alert = await new UnknownIpSuccessRule().EvaluateAsync(Logon(4624), ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task UnknownIpSuccess_NoPriorFailures_ReturnsNull()
	{
		var addr = new Address { Ip = "1.2.3.4", FailCount = 0, SuccessCount = 0 };
		var ctx = new MockAlertContext(address: addr);
		Assert.Null(await new UnknownIpSuccessRule().EvaluateAsync(Logon(4624), ctx, default));
	}

	[Fact]
	public async Task RdpPortChanged_OnRdpRegistry_ReturnsAlert()
	{
		RawEvent evt = Logon(4657);
		evt.ObjectName = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\PortNumber";
		var ctx = new MockAlertContext();
		Alert? alert = await new RdpPortChangedRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task LsassPplTamper_OnLsaRunAsPpl_ReturnsAlert()
	{
		RawEvent evt = Logon(4657);
		evt.ObjectName = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL";
		var ctx = new MockAlertContext();
		Alert? alert = await new LsassPplTamperRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task StickyKeysBackdoor_IfeoSethc_ReturnsAlert()
	{
		RawEvent evt = Logon(4657);
		evt.ObjectName = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe";
		var ctx = new MockAlertContext();
		Alert? alert = await new StickyKeysBackdoorRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task OffHoursLogin_OutsideBusinessHours_ReturnsAlert()
	{
		RawEvent evt = Logon(4624, logonType: 10);
		evt.TimeUtc = DateTime.SpecifyKind(DateTime.Today.AddHours(2), DateTimeKind.Utc);
		var ctx = new MockAlertContext(new RdpAuditOptions
		{
			Alerts = new AlertOptions
			{
				OffHoursAlertEnabled = true,
				BusinessHoursStart = TimeSpan.FromHours(9),
				BusinessHoursEnd = TimeSpan.FromHours(18),
			},
		});
		Alert? alert = await new OffHoursLoginRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task NewAccount_4720_ReturnsAlert()
	{
		var ctx = new MockAlertContext();
		Alert? alert = await new NewAccountRule().EvaluateAsync(Logon(4720), ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task ServiceInstall_4697_ReturnsAlert()
	{
		var ctx = new MockAlertContext();
		Alert? alert = await new ServiceInstallRule().EvaluateAsync(Logon(4697), ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task TaskPersistence_4698_ReturnsAlert()
	{
		var ctx = new MockAlertContext();
		Alert? alert = await new TaskPersistenceRule().EvaluateAsync(Logon(4698), ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task TaskModified_4702_ReturnsAlert()
	{
		var ctx = new MockAlertContext();
		Alert? alert = await new TaskModifiedRule().EvaluateAsync(Logon(4702), ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task PrivilegedGroupChange_4732AdminsGroup_ReturnsAlert()
	{
		RawEvent evt = Logon(4732);
		evt.Details = "{\"TargetUserName\":\"Administrators\"}";
		var ctx = new MockAlertContext(new RdpAuditOptions
		{
			Alerts = new AlertOptions { PrivilegedGroups = new() { "Administrators" } },
		});
		Alert? alert = await new PrivilegedGroupChangeRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task BruteForceNtlm_BelowThreshold_ReturnsNull()
	{
		var ctx = new MockAlertContext(
			options: new RdpAuditOptions { Alerts = new AlertOptions { BruteForceNtlmThreshold = 20 } },
			byIp: Enumerable.Range(0, 10).Select(_ => Logon(4776)));
		Assert.Null(await new BruteForceNtlmRule().EvaluateAsync(Logon(4776), ctx, default));
	}

	[Fact]
	public async Task KerberosSpray_AtThreshold_ReturnsAlert()
	{
		var ctx = new MockAlertContext(
			options: new RdpAuditOptions { Alerts = new AlertOptions { KerberosSprayThreshold = 5, BruteForceWindowMinutes = 5 } },
			byIp: Enumerable.Range(0, 5).Select(_ => Logon(4771)));
		Alert? alert = await new KerberosSprayRule().EvaluateAsync(Logon(4771), ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task RapidReconnect_DifferentIpWithinWindow_ReturnsAlert()
	{
		RawEvent reconnect = Logon(25, ip: "9.9.9.9");
		reconnect.SessionId = 7;
		var disconnect = new RawEvent { EventId = 24, SessionId = 7, SourceIp = "1.1.1.1", TimeUtc = DateTime.UtcNow.AddSeconds(-5) };
		var ctx = new MockAlertContext(
			options: new RdpAuditOptions { Alerts = new AlertOptions { RapidReconnectSeconds = 30 } },
			bySession: new[] { disconnect });
		Alert? alert = await new RapidReconnectRule().EvaluateAsync(reconnect, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task ProcessAnomaly_PowerShellFromSvchost_ReturnsAlert()
	{
		RawEvent evt = Logon(4688);
		evt.ProcessName = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
		evt.Details = "{\"ParentProcessName\":\"C:\\\\Windows\\\\System32\\\\svchost.exe\"}";
		var ctx = new MockAlertContext();
		Alert? alert = await new ProcessAnomalyRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task PrivilegedLogin_SeDebugInDetails_ReturnsAlert()
	{
		RawEvent evt = Logon(4672);
		evt.Details = "{\"PrivilegeList\":\"SeDebugPrivilege SeBackupPrivilege\"}";
		var ctx = new MockAlertContext();
		Alert? alert = await new PrivilegedLoginRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}

	[Fact]
	public async Task LsassAccess_NonLsassObject_ReturnsNull()
	{
		RawEvent evt = Logon(4656);
		evt.ObjectName = "C:\\Windows\\System32\\notepad.exe";
		evt.AccessMask = "0x10";
		var ctx = new MockAlertContext();
		Assert.Null(await new LsassAccessRule().EvaluateAsync(evt, ctx, default));
	}

	[Fact]
	public async Task LsassAccess_SensitiveMaskOnLsass_ReturnsAlert()
	{
		RawEvent evt = Logon(4656);
		evt.ObjectName = "\\Device\\HarddiskVolume1\\Windows\\System32\\lsass.exe";
		evt.AccessMask = "0x1010";
		evt.Details = "{\"ProcessName\":\"C:\\\\Tools\\\\mimikatz.exe\"}";
		var ctx = new MockAlertContext();
		Alert? alert = await new LsassAccessRule().EvaluateAsync(evt, ctx, default);
		Assert.NotNull(alert);
	}
}
