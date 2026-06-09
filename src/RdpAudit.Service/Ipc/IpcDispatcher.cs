// File:    src/RdpAudit.Service/Ipc/IpcDispatcher.cs
// Module:  RdpAudit.Service.Ipc
// Purpose: Dispatches IpcRequests to handlers and produces an IpcResponse.
//          Server-side errors are logged with full exception details; the client receives a
//          sanitised, generic error string only — never raw exception messages or stack traces.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.AbuseIpDb;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.MikroTik;
using RdpAudit.Core.Models;
using RdpAudit.Core.Security;
using RdpAudit.Core.Util;
using RdpAudit.Service.Services;

namespace RdpAudit.Service.Ipc;

/// <summary>Dispatches IpcRequests to handlers and produces an IpcResponse.</summary>
public sealed class IpcDispatcher
{
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly ServiceMetrics _metrics;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly SettingsManager _settings;
	private readonly FirewallManager _firewall;
	private readonly IEnumerable<IFirewallProvider> _providers;
	private readonly ILogger<IpcDispatcher> _logger;
	private readonly RdpSessionManager? _sessions;
	private readonly ShadowPolicyManager? _shadow;
	private readonly RdpConfigurationReader? _rdpConfigReader;
	private readonly IAbuseIpDbClient? _abuseClient;
	private readonly ISecretProtector? _protector;
	private readonly IMikroTikClient? _mikroTikClient;
	private readonly ConfigRepairReporter? _configRepair;
	private readonly SecurityAuthProbeService? _securityAuthProbe;
	private readonly Firewall.IRdpPortProvider? _rdpPortProvider;
	private readonly EnforcementReconciliationService? _reconciliation;

	public IpcDispatcher(
		IDbContextFactory<AuditDbContext> factory,
		ServiceMetrics metrics,
		IOptionsMonitor<RdpAuditOptions> options,
		SettingsManager settings,
		FirewallManager firewall,
		IEnumerable<IFirewallProvider> providers,
		ILogger<IpcDispatcher> logger,
		RdpSessionManager? sessions = null,
		ShadowPolicyManager? shadow = null,
		IAbuseIpDbClient? abuseClient = null,
		ISecretProtector? protector = null,
		IMikroTikClient? mikroTikClient = null,
		RdpConfigurationReader? rdpConfigReader = null,
		ConfigRepairReporter? configRepair = null,
		SecurityAuthProbeService? securityAuthProbe = null,
		Firewall.IRdpPortProvider? rdpPortProvider = null,
		EnforcementReconciliationService? reconciliation = null)
	{
		_factory = factory;
		_metrics = metrics;
		_options = options;
		_settings = settings;
		_firewall = firewall;
		_providers = providers;
		_logger = logger;
		_sessions = sessions;
		_shadow = shadow;
		_abuseClient = abuseClient;
		_protector = protector;
		_mikroTikClient = mikroTikClient;
		_rdpConfigReader = rdpConfigReader;
		_configRepair = configRepair;
		_securityAuthProbe = securityAuthProbe;
		_rdpPortProvider = rdpPortProvider;
		_reconciliation = reconciliation;
	}

	public async Task<IpcResponse> DispatchAsync(IpcRequest request, CancellationToken ct)
	{
		try
		{
			object? payload = request.Command switch
			{
				IpcCommand.Ping => "pong",
				IpcCommand.GetStatus => BuildStatus(),
				IpcCommand.GetRecentEvents => await GetRecentEventsAsync(ct).ConfigureAwait(false),
				IpcCommand.GetRecentAlerts => await GetRecentAlertsAsync(ct).ConfigureAwait(false),
				IpcCommand.GetAddresses => await GetAddressesAsync(ct).ConfigureAwait(false),
				IpcCommand.GetSessions => await GetSessionsAsync(ct).ConfigureAwait(false),
				IpcCommand.AcknowledgeAlert => await AcknowledgeAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.BlockAddress => await BlockAddressAsync(request.Payload, true, ct).ConfigureAwait(false),
				IpcCommand.UnblockAddress => await BlockAddressAsync(request.Payload, false, ct).ConfigureAwait(false),
				IpcCommand.GetSettings => GetMaskedSettings(),
				IpcCommand.SaveSettings => SaveSettings(request.Payload),

				// --- Stage 3 handlers (backend-only). UI is deferred to a later stage. ---
				IpcCommand.GetFirewallStatus => await GetFirewallStatusAsync(ct).ConfigureAwait(false),
				IpcCommand.ListBlocklist => await ListBlocklistAsync(ct).ConfigureAwait(false),
				IpcCommand.ListWhitelist => await ListWhitelistAsync(ct).ConfigureAwait(false),
				IpcCommand.AddToBlocklist => await AddToBlocklistAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.RemoveFromBlocklist => await RemoveFromBlocklistAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.AddToWhitelist => await AddToWhitelistAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.RemoveFromWhitelist => await RemoveFromWhitelistAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.ListActiveBlocks => await ListActiveBlocksAsync(ct).ConfigureAwait(false),

				// --- Stage 5 handlers (Firewall tab UI support). ---
				IpcCommand.ListLoginRules => await ListLoginRulesAsync(ct).ConfigureAwait(false),
				IpcCommand.AddLoginRule => await AddLoginRuleAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.RemoveLoginRule => await RemoveLoginRuleAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.SetLoginRuleEnabled => await SetLoginRuleEnabledAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.ListActiveBlocksDetailed => await ListActiveBlocksDetailedAsync(ct).ConfigureAwait(false),
				IpcCommand.UnblockActiveBlock => await UnblockActiveBlockAsync(request.Payload, ct).ConfigureAwait(false),

				// --- Stage 6 handlers (Attack Statistics tab). ---
				IpcCommand.GetAttackStats => await GetAttackStatsAsync(request.Payload, ct).ConfigureAwait(false),

				// --- Stage 7 handlers (Remote RDP Clients tab). ---
				IpcCommand.ListRdpSessions => await ListRdpSessionsAsync(ct).ConfigureAwait(false),
				IpcCommand.DisconnectSession => await DisconnectSessionAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.LogoffSession => await LogoffSessionAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.ShadowSession => ShadowSessionPolicyCheck(request.Payload),
				IpcCommand.GetShadowPolicyStatus => GetShadowPolicyStatusHandler(),
				IpcCommand.ApplyShadowPolicy => ApplyShadowPolicyHandler(request.Payload),
				IpcCommand.BackupShadowPolicy => BackupShadowPolicyHandler(),
				IpcCommand.RestoreShadowPolicy => RestoreShadowPolicyHandler(request.Payload),

				// --- Stage 8 handlers (AbuseIPDB integration). ---
				IpcCommand.GetAbuseIpDbStatus => await GetAbuseIpDbStatusAsync(ct).ConfigureAwait(false),
				IpcCommand.TestAbuseIpDbKey => await TestAbuseIpDbKeyAsync(ct).ConfigureAwait(false),
				IpcCommand.ListAbuseIpDbReportLog => await ListAbuseIpDbReportLogAsync(request.Payload, ct).ConfigureAwait(false),

				// --- Stage 9 handlers (MikroTik integration). ---
				IpcCommand.GetMikroTikStatus => await GetMikroTikStatusAsync(ct).ConfigureAwait(false),
				IpcCommand.TestMikroTik => await TestMikroTikAsync(ct).ConfigureAwait(false),

				// --- Stage A handlers (Overview dashboard + IP events export). ---
				IpcCommand.GetOverviewSummary => await GetOverviewSummaryAsync(ct).ConfigureAwait(false),
				IpcCommand.GetEventsForIp => await GetEventsForIpAsync(request.Payload, ct).ConfigureAwait(false),

				// --- Stage IP-D handlers (RdpConnectionFacts read paths). ---
				IpcCommand.ListConnectionFacts => await ListConnectionFactsAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.GetConnectionFactsForIp => await GetConnectionFactsForIpAsync(request.Payload, ct).ConfigureAwait(false),

				// --- Stage RDP-Config handler (RDP Configuration tab). ---
				IpcCommand.GetRdpConfiguration => GetRdpConfigurationHandler(),

				// --- Stage Diag handler (Diagnostic tab). ---
				IpcCommand.GetDiagnostics => await GetDiagnosticsAsync(ct).ConfigureAwait(false),

				// --- Stage Diag2: Security auth probe ---
				IpcCommand.RunSecurityAuthProbe => RunSecurityAuthProbeHandler(),

				// --- Stage 8: Firewall enforcement diagnostics ---
				IpcCommand.GetFirewallDiagnostics => await GetFirewallDiagnosticsAsync(ct).ConfigureAwait(false),

				// --- Stage 1.2.4: live enforcement reconciliation ---
				IpcCommand.ReconcileEnforcement => await ReconcileEnforcementAsync(ct).ConfigureAwait(false),
				IpcCommand.RepairActiveBlock => await RepairActiveBlockAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.RemoveAllEnforcement => await RemoveAllEnforcementAsync(ct).ConfigureAwait(false),
				IpcCommand.RepairBlocklistEnforcement => await RepairBlocklistEnforcementAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.RepairAllEnabledBlocklistEnforcement => await RepairAllEnabledBlocklistEnforcementAsync(ct).ConfigureAwait(false),

				_ => throw new IpcException(string.Format(CultureInfo.InvariantCulture, "Unknown command: {0}", request.Command)),
			};

			return new IpcResponse
			{
				Success = true,
				Payload = payload is null ? null : JsonSerializer.Serialize(payload, JsonOptions.Default),
			};
		}
		catch (IpcException ex)
		{
			// IpcException is a controlled error class — its Message is curated and safe to surface.
			_logger.LogWarning(ex, "IPC dispatch returned controlled error for {Command}", request.Command);
			return new IpcResponse { Success = false, Error = ex.Message };
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			return new IpcResponse { Success = false, Error = "Request cancelled." };
		}
		catch (Exception ex)
		{
			// Log full exception server-side; surface only generic class to the client.
			_logger.LogError(ex, "IPC dispatch failed for {Command}", request.Command);
			return new IpcResponse
			{
				Success = false,
				Error = string.Format(CultureInfo.InvariantCulture,
					"Internal service error processing {0}. See service logs for details.",
					request.Command),
			};
		}
	}

	private ServiceStatus BuildStatus()
	{
		using Process self = Process.GetCurrentProcess();
		string version = ResolveRuntimeVersion();
		Dictionary<string, string> channelStatus = _metrics.SnapshotChannels();
		SecurityVisibilityFlags flags = SecurityVisibilityDiagnosticBuilder.Build(
			new SecurityVisibilityInputs(
				SecurityEventsRead: _metrics.SecurityEventsRead,
				Security4624Count: _metrics.Security4624Count,
				Security4625Count: _metrics.Security4625Count,
				Security4648Count: _metrics.Security4648Count,
				RdpCorePreAuthOrphans: _metrics.RdpCorePreAuthOrphans,
				SecurityWatcherEnabled: _metrics.SecurityWatcherEnabled,
				LastSecurityChannelError: _metrics.LastSecurityChannelError,
				ChannelStatus: channelStatus,
				LastRdpCorePreAuthUtc: _metrics.LastRdpCorePreAuthUtc,
				LastSecurityEventUtc: _metrics.LastSecurityEventUtc,
				SecurityBackfillLastRunUtc: _metrics.SecurityBackfillLastRunUtc,
				SecurityBackfillRecordsRead: _metrics.SecurityBackfillRecordsRead));

		return new ServiceStatus
		{
			Version = version,
			StartedUtc = _metrics.StartedUtc,
			Uptime = DateTime.UtcNow - _metrics.StartedUtc,
			ProcessId = self.Id,
			EventsCaptured = _metrics.EventsCaptured,
			EventsDropped = _metrics.EventsDropped,
			AlertsRaised = _metrics.AlertsRaised,
			ChannelStatus = channelStatus,
			Security4625Count = _metrics.Security4625Count,
			Security4624Count = _metrics.Security4624Count,
			Security4648Count = _metrics.Security4648Count,
			RdpCorePreAuthOrphans = _metrics.RdpCorePreAuthOrphans,
			LastSecurityEventUtc = _metrics.LastSecurityEventUtc,
			LastRdpCorePreAuthUtc = _metrics.LastRdpCorePreAuthUtc,
			SecurityCorrelationDiagnostic = _metrics.SecurityCorrelationDiagnostic,
			SecurityWatcherEnabled = _metrics.SecurityWatcherEnabled,
			SecurityEventsRead = _metrics.SecurityEventsRead,
			SecurityEventsNormalized = _metrics.SecurityEventsNormalized,
			SecurityEventsRejected = _metrics.SecurityEventsRejected,
			SecurityBackfillLastRunUtc = _metrics.SecurityBackfillLastRunUtc,
			SecurityBackfillRecordsRead = _metrics.SecurityBackfillRecordsRead,
			SecurityBackfillRecordsForwarded = _metrics.SecurityBackfillRecordsForwarded,
			SecurityBackfillRecordsDeduped = _metrics.SecurityBackfillRecordsDeduped,
			LastSecurityChannelError = _metrics.LastSecurityChannelError,
			LastSecurityRejectReason = _metrics.LastSecurityRejectReason,
			SecurityRejectReasonCount = _metrics.SecurityRejectReasonCount,
			LastAuthAttemptFactCreatedUtc = _metrics.LastAuthAttemptFactCreatedUtc,
			AuthAttemptFactCreated = _metrics.AuthAttemptFactCreated,
			AuthAttemptFactFailed = _metrics.AuthAttemptFactFailed,
			AuthAttemptFactSucceeded = _metrics.AuthAttemptFactSucceeded,
			SecurityLogMissing = flags.SecurityLogMissing,
			AuditPolicyMissingLogon = flags.AuditPolicyMissingLogon,
			SecurityReadDenied = flags.SecurityReadDenied,
			ChannelDisabled = flags.ChannelDisabled,
			BookmarkStaleOrLogRetentionGap = flags.BookmarkStaleOrLogRetentionGap,
		};
	}

	/// <summary>Resolves the runtime version surfaced in <see cref="ServiceStatus.Version"/>.
	/// Delegates to <see cref="RuntimeVersionResolver"/>, which is single-file-publish-safe and
	/// never calls System.Reflection.Assembly.Location (avoids IL3000).</summary>
	private static string ResolveRuntimeVersion() => RuntimeVersionResolver.Resolve();

	private async Task<object?> GetRecentEventsAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		return await db.RawEvents.AsNoTracking()
			.OrderByDescending(e => e.Id)
			.Take(200)
			.Select(e => new
			{
				e.Id,
				e.EventId,
				e.Channel,
				e.TimeUtc,
				e.SourceIp,
				e.SourceIpDerived,
				e.SourceIpUnresolved,
				e.UserName,
				e.Domain,
				e.LogonId,
				e.LogonType,
				e.AuthPackage,
				e.ProcessName,
			})
			.ToListAsync(ct)
			.ConfigureAwait(false);
	}

	private async Task<object?> GetRecentAlertsAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		return await db.Alerts.AsNoTracking()
			.OrderByDescending(a => a.Id)
			.Take(200)
			.ToListAsync(ct)
			.ConfigureAwait(false);
	}

	private async Task<object?> GetAddressesAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		return await db.Addresses.AsNoTracking()
			.OrderByDescending(a => a.LastSeen)
			.Take(500)
			.ToListAsync(ct)
			.ConfigureAwait(false);
	}

	private async Task<object?> GetSessionsAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		return await db.Sessions.AsNoTracking()
			.OrderByDescending(s => s.ConnectUtc)
			.Take(500)
			.ToListAsync(ct)
			.ConfigureAwait(false);
	}

	private async Task<object?> AcknowledgeAsync(string? payload, CancellationToken ct)
	{
		if (string.IsNullOrEmpty(payload))
		{
			throw new IpcException("AcknowledgeAlert requires a payload with the alert id.");
		}

		long id = JsonSerializer.Deserialize<long>(payload, JsonOptions.Default);
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		var alert = await db.Alerts.FindAsync(new object?[] { id }, ct).ConfigureAwait(false);
		if (alert is null)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture, "Alert {0} not found.", id));
		}

		alert.Acknowledged = true;
		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return true;
	}

	private async Task<object?> BlockAddressAsync(string? payload, bool blocked, CancellationToken ct)
	{
		if (string.IsNullOrEmpty(payload))
		{
			throw new IpcException("BlockAddress requires a payload with the IP address.");
		}

		string ip = JsonSerializer.Deserialize<string>(payload, JsonOptions.Default)
			?? throw new IpcException("Invalid IP payload.");

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		var addr = await db.Addresses.FirstOrDefaultAsync(a => a.Ip == ip, ct).ConfigureAwait(false);
		if (addr is null)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture, "Address {0} not found.", ip));
		}

		addr.IsBlocked = blocked;
		addr.BlockReason = blocked ? "Manual block via Configurator" : null;
		await db.SaveChangesAsync(ct).ConfigureAwait(false);

		// Apply (or remove) the firewall block rule. On non-Windows hosts (tests) skip silently.
		if (OperatingSystem.IsWindows())
		{
			await ApplyFirewallChangeAsync(ip, blocked, ct).ConfigureAwait(false);
		}

		return true;
	}

	[SupportedOSPlatform("windows")]
	private async Task ApplyFirewallChangeAsync(string ip, bool blocked, CancellationToken ct)
	{
		string ruleName = _options.CurrentValue.Firewall.BlockRuleName;
		if (string.IsNullOrWhiteSpace(ruleName))
		{
			ruleName = "RdpAudit-Block";
		}

		FirewallOperationResult result = blocked
			? await _firewall.BlockAsync(ruleName, ip, ct).ConfigureAwait(false)
			: await _firewall.UnblockAsync(ruleName, ip, ct).ConfigureAwait(false);
		if (!result.Success)
		{
			_logger.LogWarning("Firewall {Action} for {Ip} returned exit={Exit}",
				blocked ? "block" : "unblock", ip, result.ExitCode);
		}
	}

	private object SaveSettings(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("SaveSettings requires a JSON payload.");
		}

		// The IPC payload is the JSON document string wrapped in a single string by JsonSerializer at client.
		// Accept either form: a direct JSON-string payload (escaped string) or a raw JSON document.
		string body = payload;
		if (body.Length > 0 && body[0] == '"')
		{
			try
			{
				string? unwrapped = JsonSerializer.Deserialize<string>(payload, JsonOptions.Default);
				if (!string.IsNullOrWhiteSpace(unwrapped))
				{
					body = unwrapped;
				}
			}
			catch (JsonException)
			{
				// not a wrapped string — use as-is.
			}
		}

		try
		{
			_settings.Save(body);
			return new { saved = true };
		}
		catch (JsonException ex)
		{
			throw new IpcException("Settings JSON is invalid: " + ex.Message);
		}
		catch (InvalidOperationException ex)
		{
			throw new IpcException(ex.Message);
		}
	}

	// ----------------------------------------------------------------------------------------------
	// Stage 3 handlers
	// ----------------------------------------------------------------------------------------------

	private async Task<object?> GetFirewallStatusAsync(CancellationToken ct)
	{
		FirewallOptions cfg = _options.CurrentValue.Firewall;
		FirewallStatusDto dto = new()
		{
			Status = IpcResultStatus.Success,
			ConfiguredProvider = cfg.Provider,
		};

		foreach (IFirewallProvider provider in _providers)
		{
			FirewallStatusReport report;
			try
			{
				report = await provider.GetStatusAsync(ct).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "Failed to query provider {ProviderId}", provider.ProviderId);
				continue;
			}

			bool available = report.Status == FirewallProviderStatus.Available;
			if (string.Equals(provider.ProviderId, "Windows", StringComparison.OrdinalIgnoreCase))
			{
				dto.WindowsAvailable = available;
			}
			else if (string.Equals(provider.ProviderId, "MikroTik", StringComparison.OrdinalIgnoreCase))
			{
				dto.MikroTikAvailable = available;
			}
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		dto.ActiveBlockCount = await db.ActiveBlocks
			.CountAsync(b => b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending, ct)
			.ConfigureAwait(false);
		dto.WhitelistCount = await db.WhitelistEntries.CountAsync(ct).ConfigureAwait(false);
		dto.BlacklistCount = await db.BlocklistEntries.CountAsync(b => b.IsEnabled, ct).ConfigureAwait(false);

		int enabledBlocklistRows = dto.BlacklistCount;
		dto.EnabledBlocklistRows = enabledBlocklistRows;

		// Never claim enforcement from DB rows alone — only live reconciliation verifies real firewall rules.
		if (_reconciliation is not null)
		{
			try
			{
				ReconciliationReportDto rec = await _reconciliation.ReconcileAsync(ct).ConfigureAwait(false);
				dto.VerifiedEnforcedCount = rec.VerifiedCount;
				dto.RdpAuditFirewallRuleCount = rec.VerifiedCount + rec.Orphans.Count;
				dto.EnforcementHealth = EnforcementReconciler.DeriveHealth(enabledBlocklistRows, rec.VerifiedCount, rec.UnenforcedCount);
			}
			catch (OperationCanceledException) when (ct.IsCancellationRequested)
			{
				throw;
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "GetFirewallStatus reconciliation failed");
				dto.EnforcementHealth = FirewallEnforcementHealth.Unknown;
			}
		}
		else
		{
			dto.EnforcementHealth = FirewallEnforcementHealth.Unknown;
		}

		dto.Message = EnforcementReconciler.DescribeHealth(dto.EnforcementHealth, enabledBlocklistRows, dto.VerifiedEnforcedCount);
		return dto;
	}

	private async Task<object?> GetFirewallDiagnosticsAsync(CancellationToken ct)
	{
		FirewallOptions cfg = _options.CurrentValue.Firewall;

		List<FirewallProviderDiagnostic> providers = new();
		string routeState = "(not registered)";
		string ipsecState = "(not registered)";
		foreach (IFirewallProvider provider in _providers)
		{
			FirewallStatusReport report;
			try
			{
				report = await provider.GetStatusAsync(ct).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "Diagnostics: failed to query provider {ProviderId}", provider.ProviderId);
				providers.Add(new FirewallProviderDiagnostic(provider.ProviderId, false, 0, "status query failed"));
				continue;
			}

			bool available = report.Status == FirewallProviderStatus.Available;
			providers.Add(new FirewallProviderDiagnostic(
				provider.ProviderId, available, report.ActiveBlockCount, report.Status + (report.Message is null ? string.Empty : " — " + report.Message)));

			if (string.Equals(provider.ProviderId, FirewallProviderRouting.RouteBlackholeProviderId, StringComparison.Ordinal))
			{
				routeState = report.Status + (report.Message is null ? string.Empty : " — " + report.Message);
			}
			else if (string.Equals(provider.ProviderId, FirewallProviderRouting.IPsecProviderId, StringComparison.Ordinal))
			{
				ipsecState = report.Status + (report.Message is null ? string.Empty : " — " + report.Message);
			}
		}

		// Resolve the real RDP listener port without hardcoding 3389: registry-backed provider on
		// Windows, documented default elsewhere (e.g. when running cross-platform in tests/dev).
		int rdpPort;
		bool fromRegistry;
		if (_rdpPortProvider is not null)
		{
			rdpPort = _rdpPortProvider.GetRdpPort();
			fromRegistry = rdpPort != RdpConfigurationModel.DefaultRdpPort;
		}
		else
		{
			rdpPort = RdpConfigurationModel.DefaultRdpPort;
			fromRegistry = false;
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		int blocklistRows = await db.BlocklistEntries.CountAsync(b => b.IsEnabled, ct).ConfigureAwait(false);
		int activeRows = await db.ActiveBlocks
			.CountAsync(b => b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending, ct)
			.ConfigureAwait(false);

		// Live reconciliation: never claim enforcement from DB rows alone. When the reconciliation
		// service is available, the verified count and per-IP detail come from a real firewall scan.
		List<ReconciledEnforcementLine> reconciledLines = new();
		List<string> orphanNames = new();
		int verifiedEnforced = 0;
		int rdpAuditRuleCount = 0;
		bool thirdPartySuspected = false;
		string? thirdPartyNote = null;
		if (_reconciliation is not null)
		{
			ReconciliationReportDto rec = await _reconciliation.ReconcileAsync(ct).ConfigureAwait(false);
			verifiedEnforced = rec.VerifiedCount;
			rdpAuditRuleCount = rec.VerifiedCount;
			foreach (ReconciledBlockDto b in rec.Blocks)
			{
				reconciledLines.Add(new ReconciledEnforcementLine(
					Ip: b.Ip,
					Status: EnforcementReconciler.DescribeStatus(b.Status),
					Confidence: EnforcementReconciler.DescribeConfidence(b.Confidence),
					EnforcementObjectId: b.EnforcementObjectId,
					RecommendedAction: b.RecommendedAction));

				if (b.Confidence == EnforcementConfidence.ExistsButProviderMayBypass)
				{
					thirdPartySuspected = true;
					thirdPartyNote ??= "Windows Firewall rule verified; a third-party provider (e.g. Kaspersky) "
						+ "may control effective enforcement.";
				}
			}

			foreach (ReconciledBlockDto o in rec.Orphans)
			{
				if (!string.IsNullOrEmpty(o.EnforcementObjectId))
				{
					orphanNames.Add(o.EnforcementObjectId);
				}
			}
		}
		else
		{
			// Fallback proxy when reconciliation is unavailable: an Active row with a rule handle.
			verifiedEnforced = await db.ActiveBlocks
				.CountAsync(b => b.Status == ActiveBlockStatus.Active && b.RuleHandle != null && b.RuleHandle != string.Empty, ct)
				.ConfigureAwait(false);
			rdpAuditRuleCount = verifiedEnforced;
		}

		FirewallDiagnosticsInput input = new(
			ConfiguredProviderKind: cfg.Provider.ToString(),
			ConfiguredEnforcementBackend: cfg.EnforcementBackend.ToString(),
			ConfiguredBlockScope: cfg.BlockScope.ToString(),
			ResolvedRdpPort: rdpPort,
			RdpPortFromRegistry: fromRegistry,
			Providers: providers,
			RdpAuditGroupBlockRuleCount: rdpAuditRuleCount,
			EnabledAllowInboundTcpPorts: Array.Empty<int>(),
			RdpAuditAllowRuleForResolvedPort: false,
			RouteBackendState: routeState,
			IPsecBackendState: ipsecState,
			ThirdPartyFirewallSuspected: thirdPartySuspected,
			ThirdPartyFirewallNote: thirdPartyNote,
			BlocklistRowCount: blocklistRows,
			ActiveBlockRowCount: activeRows,
			VerifiedEnforcedCount: verifiedEnforced)
		{
			ReconciledBlocks = reconciledLines,
			OrphanedRuleNames = orphanNames,
		};

		return new FirewallDiagnosticsDto
		{
			Status = IpcResultStatus.Success,
			ReportText = FirewallDiagnosticsReportBuilder.Build(input),
			Message = "Firewall enforcement diagnostics snapshot with live reconciliation. Combine with the "
				+ "client-side netsh / provider probe shown above for the full picture.",
		};
	}

	private async Task<object?> ListBlocklistAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<BlocklistEntry> rows = await db.BlocklistEntries.AsNoTracking()
			.OrderByDescending(b => b.AddedUtc)
			.Take(2000)
			.ToListAsync(ct).ConfigureAwait(false);

		return rows.ConvertAll(b => new AddressListEntryDto
		{
			Id = b.Id,
			Address = b.Ip ?? b.Login ?? string.Empty,
			Note = b.Reason,
			AddedUtc = b.AddedUtc,
			ExpiresUtc = b.ExpiresUtc,
			Source = b.Source.ToString(),
		});
	}

	private async Task<object?> ListWhitelistAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<WhitelistEntry> rows = await db.WhitelistEntries.AsNoTracking()
			.OrderByDescending(w => w.AddedUtc)
			.Take(2000)
			.ToListAsync(ct).ConfigureAwait(false);

		return rows.ConvertAll(w => new AddressListEntryDto
		{
			Address = w.Ip,
			Note = w.Note,
			AddedUtc = w.AddedUtc,
			ExpiresUtc = null,
			Source = w.AddedBy ?? "Configurator",
		});
	}

	private async Task<object?> AddToBlocklistAsync(string? payload, CancellationToken ct)
	{
		AddressListMutationRequest req = DeserializeMutation(payload, "AddToBlocklist");
		string ip = NormalizeAndValidateAddress(req.Address);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		// Whitelist precedence: refuse to add a row that contradicts an active whitelist entry.
		bool whitelisted = await db.WhitelistEntries.AnyAsync(w => w.Ip == ip, ct).ConfigureAwait(false);
		if (whitelisted)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"Cannot add {0} to blocklist: it is whitelisted.", ip));
		}

		DateTime nowUtc = DateTime.UtcNow;
		DateTime? expiresUtc = req.DurationMinutes > 0 ? nowUtc.AddMinutes(req.DurationMinutes) : null;

		BlocklistEntry? existing = await db.BlocklistEntries
			.FirstOrDefaultAsync(b => b.Ip == ip && b.IsEnabled, ct).ConfigureAwait(false);

		if (existing is null)
		{
			db.BlocklistEntries.Add(new BlocklistEntry
			{
				Ip = ip,
				Reason = string.IsNullOrWhiteSpace(req.Note) ? "Configurator manual add" : req.Note!,
				AddedUtc = nowUtc,
				ExpiresUtc = expiresUtc,
				Source = BlocklistSource.Manual,
				IsEnabled = true,
			});
		}
		else
		{
			existing.ExpiresUtc = expiresUtc;
			if (!string.IsNullOrWhiteSpace(req.Note))
			{
				existing.Reason = req.Note!;
			}
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return new { status = IpcResultStatus.Success.ToString(), address = ip };
	}

	private async Task<object?> RemoveFromBlocklistAsync(string? payload, CancellationToken ct)
	{
		AddressListMutationRequest req = DeserializeMutation(payload, "RemoveFromBlocklist");

		// Prefer the stable surrogate key so we delete exactly the selected row even when several
		// rows share an address (e.g. one Manual + one AutoBlock). Fall back to address matching for
		// legacy callers that do not carry an Id.
		string? ip = null;
		List<BlocklistEntry> rows;
		await using (AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false))
		{
			if (req.Id > 0)
			{
				_logger.LogDebug("RemoveFromBlocklist by Id={Id} (address hint '{Address}')", req.Id, req.Address);
				rows = await db.BlocklistEntries
					.Where(b => b.Id == req.Id && b.IsEnabled).ToListAsync(ct).ConfigureAwait(false);
			}
			else
			{
				ip = NormalizeAndValidateAddress(req.Address);
				_logger.LogDebug("RemoveFromBlocklist by address '{Address}'", ip);
				rows = await db.BlocklistEntries
					.Where(b => b.Ip == ip && b.IsEnabled).ToListAsync(ct).ConfigureAwait(false);
			}

			foreach (BlocklistEntry row in rows)
			{
				row.IsEnabled = false;
			}

			await db.SaveChangesAsync(ct).ConfigureAwait(false);
		}

		int removed = rows.Count;
		string targetIp = ip ?? rows.Select(r => r.Ip).FirstOrDefault(x => x is not null) ?? req.Address;
		_logger.LogInformation(
			"RemoveFromBlocklist soft-disabled {Removed} row(s) for Id={Id} address='{Address}'",
			removed, req.Id, targetIp);

		if (removed == 0)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"No enabled blocklist row matched {0} (Id={1}); nothing was removed.",
				targetIp, req.Id));
		}

		return new { status = IpcResultStatus.Success.ToString(), address = targetIp, removed };
	}

	private async Task<object?> AddToWhitelistAsync(string? payload, CancellationToken ct)
	{
		AddressListMutationRequest req = DeserializeMutation(payload, "AddToWhitelist");
		string ip = NormalizeAndValidateAddress(req.Address);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		WhitelistEntry? existing = await db.WhitelistEntries
			.FirstOrDefaultAsync(w => w.Ip == ip, ct).ConfigureAwait(false);
		if (existing is null)
		{
			db.WhitelistEntries.Add(new WhitelistEntry
			{
				Ip = ip,
				Note = string.IsNullOrWhiteSpace(req.Note) ? "Configurator manual add" : req.Note,
				AddedUtc = DateTime.UtcNow,
				AddedBy = "Configurator",
			});
		}
		else
		{
			existing.Note = string.IsNullOrWhiteSpace(req.Note) ? existing.Note : req.Note;
		}

		// Whitelist precedence: disable any active blocklist rows that reference this IP.
		List<BlocklistEntry> conflicting = await db.BlocklistEntries
			.Where(b => b.Ip == ip && b.IsEnabled).ToListAsync(ct).ConfigureAwait(false);
		foreach (BlocklistEntry row in conflicting)
		{
			row.IsEnabled = false;
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return new { status = IpcResultStatus.Success.ToString(), address = ip };
	}

	private async Task<object?> RemoveFromWhitelistAsync(string? payload, CancellationToken ct)
	{
		AddressListMutationRequest req = DeserializeMutation(payload, "RemoveFromWhitelist");
		string ip = NormalizeAndValidateAddress(req.Address);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		WhitelistEntry? existing = await db.WhitelistEntries
			.FirstOrDefaultAsync(w => w.Ip == ip, ct).ConfigureAwait(false);

		if (existing is not null)
		{
			db.WhitelistEntries.Remove(existing);
			await db.SaveChangesAsync(ct).ConfigureAwait(false);
		}

		return new { status = IpcResultStatus.Success.ToString(), address = ip, removed = existing is not null };
	}

	private async Task<object?> ListActiveBlocksAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<ActiveBlock> rows = await db.ActiveBlocks.AsNoTracking()
			.OrderByDescending(b => b.CreatedUtc)
			.Take(2000)
			.ToListAsync(ct).ConfigureAwait(false);

		return rows.ConvertAll(b => new AddressListEntryDto
		{
			Address = b.Ip,
			Note = string.IsNullOrEmpty(b.LastError) ? b.Reason : b.Reason + " (" + b.LastError + ")",
			AddedUtc = b.CreatedUtc,
			ExpiresUtc = b.ExpiresUtc,
			Source = b.Provider.ToString() + ":" + b.Status,
		});
	}

	private static AddressListMutationRequest DeserializeMutation(string? payload, string commandName)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} requires a JSON payload with an Address field.", commandName));
		}

		AddressListMutationRequest? parsed;
		try
		{
			parsed = JsonSerializer.Deserialize<AddressListMutationRequest>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} payload is not valid JSON: {1}", commandName, ex.Message));
		}

		if (parsed is null || string.IsNullOrWhiteSpace(parsed.Address))
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} requires an Address field.", commandName));
		}
		return parsed;
	}

	private static string NormalizeAndValidateAddress(string address)
	{
		if (string.IsNullOrWhiteSpace(address))
		{
			throw new IpcException("Address must not be empty.");
		}

		string trimmed = address.Trim();
		if (!IPAddress.TryParse(trimmed, out IPAddress? parsed))
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"Address '{0}' is not a valid IPv4 / IPv6 address.", trimmed));
		}
		return parsed.ToString();
	}

	// ----------------------------------------------------------------------------------------------
	// Stage 5 handlers
	// ----------------------------------------------------------------------------------------------

	private async Task<object?> ListLoginRulesAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<LoginRule> rows = await db.LoginRules.AsNoTracking()
			.OrderByDescending(r => r.AddedUtc)
			.Take(2000)
			.ToListAsync(ct).ConfigureAwait(false);

		return rows.ConvertAll(r => new LoginRuleDto
		{
			Id = r.Id,
			Login = r.Login,
			DisplayLogin = string.IsNullOrEmpty(r.DisplayLogin) ? r.Login : r.DisplayLogin,
			Note = r.Note,
			Enabled = r.Enabled,
			AddedUtc = r.AddedUtc,
			TriggerCount = r.TriggerCount,
			FirstTriggeredUtc = r.FirstTriggeredUtc,
			LastTriggeredUtc = r.LastTriggeredUtc,
			LastSourceIp = r.LastSourceIp,
		});
	}

	private async Task<object?> AddLoginRuleAsync(string? payload, CancellationToken ct)
	{
		LoginRuleMutationRequest req = DeserializeLoginRuleRequest(payload, "AddLoginRule");
		string login = NormalizeAndValidateLogin(req.Login);
		string displayLogin = req.Login.Trim();

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		LoginRule? existing = await db.LoginRules
			.FirstOrDefaultAsync(r => r.Login == login, ct).ConfigureAwait(false);

		if (existing is null)
		{
			db.LoginRules.Add(new LoginRule
			{
				Login = login,
				DisplayLogin = displayLogin,
				Note = string.IsNullOrWhiteSpace(req.Note) ? "Configurator manual add" : req.Note,
				Enabled = true,
				AddedUtc = DateTime.UtcNow,
			});
		}
		else
		{
			existing.Enabled = true;
			if (string.IsNullOrEmpty(existing.DisplayLogin))
			{
				existing.DisplayLogin = displayLogin;
			}
			if (!string.IsNullOrWhiteSpace(req.Note))
			{
				existing.Note = req.Note;
			}
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return new { status = IpcResultStatus.Success.ToString(), login };
	}

	private async Task<object?> RemoveLoginRuleAsync(string? payload, CancellationToken ct)
	{
		LoginRuleMutationRequest req = DeserializeLoginRuleRequest(payload, "RemoveLoginRule");

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		LoginRule? target = null;
		if (req.Id > 0)
		{
			target = await db.LoginRules.FirstOrDefaultAsync(r => r.Id == req.Id, ct).ConfigureAwait(false);
		}

		if (target is null && !string.IsNullOrWhiteSpace(req.Login))
		{
			string login = NormalizeAndValidateLogin(req.Login);
			target = await db.LoginRules.FirstOrDefaultAsync(r => r.Login == login, ct).ConfigureAwait(false);
		}

		if (target is null)
		{
			throw new IpcException("Login rule not found.");
		}

		db.LoginRules.Remove(target);
		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return new { status = IpcResultStatus.Success.ToString(), id = target.Id, login = target.Login };
	}

	private async Task<object?> SetLoginRuleEnabledAsync(string? payload, CancellationToken ct)
	{
		LoginRuleMutationRequest req = DeserializeLoginRuleRequest(payload, "SetLoginRuleEnabled");
		if (req.Id <= 0)
		{
			throw new IpcException("SetLoginRuleEnabled requires a positive Id.");
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		LoginRule? target = await db.LoginRules.FirstOrDefaultAsync(r => r.Id == req.Id, ct).ConfigureAwait(false);
		if (target is null)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"Login rule {0} not found.", req.Id));
		}

		target.Enabled = req.Enabled;
		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return new { status = IpcResultStatus.Success.ToString(), id = target.Id, enabled = target.Enabled };
	}

	private async Task<object?> ListActiveBlocksDetailedAsync(CancellationToken ct)
	{
		// The Active Blocks view is built from live reconciliation results — never DB rows alone — so
		// RdpAudit never claims an IP is actively blocked unless a matching backend object is found.
		if (_reconciliation is not null)
		{
			return await _reconciliation.ReconcileToActiveBlockDtosAsync(ct).ConfigureAwait(false);
		}

		// Fallback (reconciliation service not wired): surface DB rows but mark enforcement unknown so
		// the operator is never misled into believing a row is verified.
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<ActiveBlock> rows = await db.ActiveBlocks.AsNoTracking()
			.OrderByDescending(b => b.CreatedUtc)
			.Take(2000)
			.ToListAsync(ct).ConfigureAwait(false);

		return rows.ConvertAll(b => new ActiveBlockDto
		{
			Id = b.Id,
			Ip = b.Ip,
			Provider = b.Provider,
			RuleHandle = b.RuleHandle,
			CreatedUtc = b.CreatedUtc,
			ExpiresUtc = b.ExpiresUtc,
			Reason = b.Reason,
			Status = b.Status,
			LastError = b.LastError,
			EnforcementStatus = EnforcementStatus.EffectiveUnknown,
			EnforcementConfidence = EnforcementConfidence.Unknown,
			RecommendedAction = "Reconciliation service unavailable; enforcement not verified.",
		});
	}

	private async Task<object?> ReconcileEnforcementAsync(CancellationToken ct)
	{
		if (_reconciliation is null)
		{
			throw new IpcException("Enforcement reconciliation service is not available in this build.");
		}

		return await _reconciliation.ReconcileAsync(ct).ConfigureAwait(false);
	}

	private async Task<object?> RepairActiveBlockAsync(string? payload, CancellationToken ct)
	{
		if (_reconciliation is null)
		{
			throw new IpcException("Enforcement reconciliation service is not available in this build.");
		}

		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("RepairActiveBlock requires a JSON payload with the row Id.");
		}

		long id;
		try
		{
			id = JsonSerializer.Deserialize<long>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException("RepairActiveBlock payload is not a valid Id: " + ex.Message);
		}

		if (id <= 0)
		{
			throw new IpcException("RepairActiveBlock requires a positive Id.");
		}

		return await _reconciliation.RepairAsync(id, ct).ConfigureAwait(false);
	}

	private async Task<object?> RepairBlocklistEnforcementAsync(string? payload, CancellationToken ct)
	{
		if (_reconciliation is null)
		{
			throw new IpcException("Enforcement reconciliation service is not available in this build.");
		}

		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("RepairBlocklistEnforcement requires a JSON payload with the BlockList row Id.");
		}

		long id;
		try
		{
			id = JsonSerializer.Deserialize<long>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException("RepairBlocklistEnforcement payload is not a valid Id: " + ex.Message);
		}

		if (id <= 0)
		{
			throw new IpcException("RepairBlocklistEnforcement requires a positive Id.");
		}

		return await _reconciliation.RepairBlocklistAsync(id, ct).ConfigureAwait(false);
	}

	private async Task<object?> RepairAllEnabledBlocklistEnforcementAsync(CancellationToken ct)
	{
		if (_reconciliation is null)
		{
			throw new IpcException("Enforcement reconciliation service is not available in this build.");
		}

		return await _reconciliation.RepairAllEnabledBlocklistAsync(ct).ConfigureAwait(false);
	}

	private async Task<object?> RemoveAllEnforcementAsync(CancellationToken ct)
	{
		if (_reconciliation is null)
		{
			throw new IpcException("Enforcement reconciliation service is not available in this build.");
		}

		return await _reconciliation.RemoveAllEnforcementAsync(ct).ConfigureAwait(false);
	}

	private async Task<object?> UnblockActiveBlockAsync(string? payload, CancellationToken ct)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("UnblockActiveBlock requires a JSON payload with the row Id.");
		}

		long id;
		try
		{
			id = JsonSerializer.Deserialize<long>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException("UnblockActiveBlock payload is not a valid Id: " + ex.Message);
		}

		if (id <= 0)
		{
			throw new IpcException("UnblockActiveBlock requires a positive Id.");
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		ActiveBlock? row = await db.ActiveBlocks.FirstOrDefaultAsync(b => b.Id == id, ct).ConfigureAwait(false);
		if (row is null)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"ActiveBlock {0} not found.", id));
		}

		string ip = row.Ip;
		bool providerOk = true;
		string? providerError = null;

		if (row.Provider == FirewallProviderKind.Windows && OperatingSystem.IsWindows())
		{
			try
			{
				FirewallOperationResult res = await _firewall.UnblockAsync(
					_options.CurrentValue.Firewall.BlockRuleName, ip, ct).ConfigureAwait(false);
				providerOk = res.Success || res.ExitCode == 1;
				if (!providerOk)
				{
					providerError = "netsh exit " + res.ExitCode.ToString(CultureInfo.InvariantCulture);
				}
			}
			catch (Exception ex)
			{
				providerOk = false;
				providerError = ex.GetType().Name;
				_logger.LogWarning(ex, "Provider unblock failed for {Ip}", ip);
			}
		}

		row.Status = providerOk ? ActiveBlockStatus.Removed : ActiveBlockStatus.Failed;
		row.LastError = providerError;

		List<BlocklistEntry> related = await db.BlocklistEntries
			.Where(b => b.Ip == ip && b.IsEnabled).ToListAsync(ct).ConfigureAwait(false);
		foreach (BlocklistEntry entry in related)
		{
			entry.IsEnabled = false;
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return new
		{
			status = (providerOk ? IpcResultStatus.Success : IpcResultStatus.Unavailable).ToString(),
			id = row.Id,
			address = ip,
			providerOk,
			providerError,
			blocklistDisabled = related.Count,
		};
	}

	private static LoginRuleMutationRequest DeserializeLoginRuleRequest(string? payload, string commandName)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} requires a JSON payload.", commandName));
		}

		LoginRuleMutationRequest? parsed;
		try
		{
			parsed = JsonSerializer.Deserialize<LoginRuleMutationRequest>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} payload is not valid JSON: {1}", commandName, ex.Message));
		}

		if (parsed is null)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} payload could not be parsed.", commandName));
		}
		return parsed;
	}

	// ----------------------------------------------------------------------------------------------
	// Stage 6 handlers
	// ----------------------------------------------------------------------------------------------

	/// <summary>Default cap on rows returned by <c>GetAttackStats</c> when no limit is supplied.</summary>
	internal const int AttackStatsDefaultLimit = 500;

	/// <summary>Upper bound on rows returned by <c>GetAttackStats</c> regardless of caller intent.</summary>
	internal const int AttackStatsMaxLimit = 2000;

	private async Task<object?> GetAttackStatsAsync(string? payload, CancellationToken ct)
	{
		AttackStatsRequest req = ParseAttackStatsRequest(payload);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		DateTime windowEnd = req.UntilUtc ?? DateTime.UtcNow;
		DateTime windowStart = req.SinceUtc ?? (windowEnd - TimeSpan.FromDays(7));

		IQueryable<AttackStat> q = db.AttackStats.AsNoTracking();

		if (!string.IsNullOrWhiteSpace(req.IpQuery))
		{
			string needle = req.IpQuery.Trim();
			q = q.Where(s => EF.Functions.Like(s.Ip, "%" + needle + "%"));
		}

		if (req.MinThreatScore.HasValue)
		{
			double min = req.MinThreatScore.Value;
			q = q.Where(s => s.ThreatScore >= min);
		}

		if (req.OnlyBlocked)
		{
			q = q.Where(s => s.IsBlocked);
		}

		if (req.SinceUtc.HasValue)
		{
			DateTime since = req.SinceUtc.Value;
			q = q.Where(s => s.LastSeenUtc >= since);
		}

		if (req.UntilUtc.HasValue)
		{
			DateTime until = req.UntilUtc.Value;
			q = q.Where(s => s.LastSeenUtc <= until);
		}

		int totalMatching = await q.CountAsync(ct).ConfigureAwait(false);

		int limit = req.Limit <= 0 ? AttackStatsDefaultLimit : req.Limit;
		if (limit > AttackStatsMaxLimit)
		{
			limit = AttackStatsMaxLimit;
		}

		List<AttackStat> rows = await q
			.OrderByDescending(s => s.LastSeenUtc)
			.ThenByDescending(s => s.ThreatScore)
			.ThenBy(s => s.Ip)
			.Take(limit)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		// Window summary counters — computed against AuthAttemptFacts in the requested window.
		// Detect_Attack_Strategy_v3.md §8.1 makes AuthAttemptFact the atomic source of truth for
		// authentication outcomes. RDP/Operational, RdpCoreTS, and TerminalServices events are
		// context / enrichment only — they MUST NOT move Total / Failed / Successful counters.
		// Querying AuthAttemptFacts directly (rather than RawEvents + Classify) keeps the IPC
		// window summary consistent with the per-IP Fact* columns and with AttackStat rows
		// projected by AttackStatsRefreshWorker.
		var windowFacts = await db.AuthAttemptFacts.AsNoTracking()
			.Where(f => f.TimeUtc >= windowStart && f.TimeUtc <= windowEnd)
			.Select(f => new { f.Outcome, f.SourceIp })
			.ToListAsync(ct).ConfigureAwait(false);

		long failed = 0;
		long successful = 0;
		HashSet<string> distinctIpSet = new(StringComparer.OrdinalIgnoreCase);
		foreach (var fact in windowFacts)
		{
			switch (fact.Outcome)
			{
				case AuthAttemptOutcome.Failed:
				case AuthAttemptOutcome.Denied:
					failed++;
					if (string.IsNullOrEmpty(fact.SourceIp))
					{
						distinctIpSet.Add(AttackStatsAggregator.SentinelUnresolvedIp);
					}
					break;
				case AuthAttemptOutcome.Succeeded:
					successful++;
					break;
			}

			if (!string.IsNullOrEmpty(fact.SourceIp))
			{
				distinctIpSet.Add(fact.SourceIp);
			}
		}
		long distinctIps = distinctIpSet.Count;
		long alertsRaised = await db.Alerts.AsNoTracking()
			.Where(a => a.TimeUtc >= windowStart && a.TimeUtc <= windowEnd)
			.LongCountAsync(ct).ConfigureAwait(false);
		long autoBlocked = await db.ActiveBlocks.AsNoTracking()
			.Where(b => b.CreatedUtc >= windowStart && b.CreatedUtc <= windowEnd
				&& (b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending))
			.LongCountAsync(ct).ConfigureAwait(false);

		AttackStatsDto dto = new()
		{
			Status = IpcResultStatus.Success,
			WindowStartUtc = windowStart,
			WindowEndUtc = windowEnd,
			FailedLogons = failed,
			SuccessfulLogons = successful,
			DistinctSourceIps = distinctIps,
			AlertsRaised = alertsRaised,
			AddressesAutoBlocked = autoBlocked,
			Message = string.Format(CultureInfo.InvariantCulture,
				"Stage 6 attack statistics snapshot. matching={0} returned={1}",
				totalMatching, rows.Count),
			TotalMatching = totalMatching,
			AppliedLimit = limit,
		};

		// Stage IP-D: augment with RdpConnectionFacts aggregates for the IPs in this page. We never
		// overwrite the AttackStat columns — the augmentation lives on dedicated fact-* fields so the
		// existing UI keeps rendering AttackStat as today, and forward-looking pages can opt in.
		Dictionary<string, FactAggregate> factAggregates = await LoadFactAggregatesAsync(db, rows.Select(r => r.Ip), ct).ConfigureAwait(false);

		foreach (AttackStat row in rows)
		{
			AttackStatEntryDto entry = new()
			{
				Ip = row.Ip,
				TotalAttempts = row.TotalAttempts,
				Successful = row.Successful,
				Failed = row.Failed,
				FirstSeenUtc = row.FirstSeenUtc,
				LastSeenUtc = row.LastSeenUtc,
				DurationSeconds = row.DurationSeconds,
				Top10AttemptedLogins = row.Top10AttemptedLogins,
				LastLoginType = row.LastLoginType,
				ThreatScore = row.ThreatScore,
				ThreatLevel = AttackThreatScoring.ClassifyScore(row.ThreatScore),
				IsBlocked = row.IsBlocked,
				LastUpdatedUtc = row.LastUpdatedUtc,
			};

			if (factAggregates.TryGetValue(row.Ip, out FactAggregate agg))
			{
				entry.HasActiveConnectionFact = agg.AnyActive;
				entry.FactFailedLogons = agg.Failed;
				entry.FactSuccessfulLogons = agg.Successful;
				entry.FactFirstSeenUtc = agg.FirstSeen;
				entry.FactLastSeenUtc = agg.LastSeen;
			}

			dto.Entries.Add(entry);
		}

		return dto;
	}

	internal readonly struct FactAggregate
	{
		public FactAggregate(DateTime firstSeen, DateTime lastSeen, long failed, long successful, bool anyActive)
		{
			FirstSeen = firstSeen;
			LastSeen = lastSeen;
			Failed = failed;
			Successful = successful;
			AnyActive = anyActive;
		}

		public DateTime FirstSeen { get; }

		public DateTime LastSeen { get; }

		public long Failed { get; }

		public long Successful { get; }

		public bool AnyActive { get; }
	}

	internal static async Task<Dictionary<string, FactAggregate>> LoadFactAggregatesAsync(
		AuditDbContext db,
		IEnumerable<string> ips,
		CancellationToken ct)
	{
		HashSet<string> set = new(ips, StringComparer.Ordinal);
		if (set.Count == 0)
		{
			return new Dictionary<string, FactAggregate>(StringComparer.Ordinal);
		}

		// v3 invariant (Detect_Attack_Strategy_v3.md §8.1): "All counters in IpFact and UserIpFact
		// are computed only from AuthAttemptFact." The Configurator's Fact Failed / Fact Success
		// columns therefore aggregate AuthAttemptFacts, not RdpConnectionFacts (which mix in
		// LSM-21 / RCM-1149 session telemetry that is NOT authoritative for outcome).
		var groupedAuth = await db.AuthAttemptFacts.AsNoTracking()
			.Where(f => f.SourceIp != null && set.Contains(f.SourceIp))
			.GroupBy(f => f.SourceIp!)
			.Select(g => new
			{
				Ip = g.Key,
				FirstSeen = g.Min(f => f.TimeUtc),
				LastSeen = g.Max(f => f.TimeUtc),
				Failed = g.LongCount(f => f.Outcome == AuthAttemptOutcome.Failed || f.Outcome == AuthAttemptOutcome.Denied),
				Successful = g.LongCount(f => f.Outcome == AuthAttemptOutcome.Succeeded),
			})
			.ToListAsync(ct).ConfigureAwait(false);

		// "Active fact" is still a connection-state question (is there an open RDP session from
		// this IP?), so it continues to be sourced from RdpConnectionFacts.IsActive — that field
		// is a session-lifecycle bit, not a counter.
		Dictionary<string, bool> activeByIp = (await db.RdpConnectionFacts.AsNoTracking()
			.Where(r => set.Contains(r.Ip))
			.GroupBy(r => r.Ip)
			.Select(g => new { Ip = g.Key, AnyActive = g.Any(r => r.IsActive) })
			.ToListAsync(ct).ConfigureAwait(false))
			.ToDictionary(x => x.Ip, x => x.AnyActive, StringComparer.Ordinal);

		var grouped = groupedAuth.Select(g => new
		{
			g.Ip,
			g.FirstSeen,
			g.LastSeen,
			g.Failed,
			g.Successful,
			AnyActive = activeByIp.TryGetValue(g.Ip, out bool active) && active,
		}).ToList();

		Dictionary<string, FactAggregate> result = new(StringComparer.Ordinal);
		foreach (var g in grouped)
		{
			result[g.Ip] = new FactAggregate(g.FirstSeen, g.LastSeen, g.Failed, g.Successful, g.AnyActive);
		}

		return result;
	}

	private static AttackStatsRequest ParseAttackStatsRequest(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			return new AttackStatsRequest();
		}

		try
		{
			AttackStatsRequest? parsed = JsonSerializer.Deserialize<AttackStatsRequest>(payload, JsonOptions.Default);
			return parsed ?? new AttackStatsRequest();
		}
		catch (JsonException ex)
		{
			throw new IpcException("GetAttackStats payload is not valid JSON: " + ex.Message);
		}
	}

	// ----------------------------------------------------------------------------------------------
	// Stage 7 handlers — Remote RDP Clients tab.
	// ----------------------------------------------------------------------------------------------

	private async Task<object?> ListRdpSessionsAsync(CancellationToken ct)
	{
		if (!OperatingSystem.IsWindows() || _sessions is null)
		{
			return new RdpSessionListDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "Session enumeration is only available on Windows hosts.",
				QueriedUtc = DateTime.UtcNow,
			};
		}

		RdpSessionListDto list = await _sessions.ListAsync(ct).ConfigureAwait(false);

		// Stage IP-B: resolve missing ClientAddress from the durable SessionIpCorrelations table.
		// Preference order per session: (WtsSessionId + UserName) → UserName fallback. We never
		// fall back to a 24h RawEvents heuristic any more — the dedicated correlation table
		// already carries the deterministic facts the processor persists.
		if (list.Sessions.Count > 0)
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
			await EnrichSessionsFromCorrelationsAsync(db, list.Sessions, ct).ConfigureAwait(false);
		}

		return list;
	}

	/// <summary>Stage IP-B helper: enriches the supplied sessions with <c>ClientAddress</c> values
	/// resolved from <see cref="SessionIpCorrelation"/> rows. Exposed internally for unit testing
	/// without needing a Windows <c>RdpSessionManager</c>.</summary>
	internal static async Task EnrichSessionsFromCorrelationsAsync(
		AuditDbContext db,
		IList<RdpSessionDto> sessions,
		CancellationToken ct)
	{
		List<RdpSessionDto> needIp = new(sessions.Count);
		foreach (RdpSessionDto s in sessions)
		{
			if (string.IsNullOrEmpty(s.ClientAddress) && !string.IsNullOrEmpty(s.UserName))
			{
				needIp.Add(s);
			}
		}

		if (needIp.Count == 0)
		{
			return;
		}

		HashSet<int> wtsIds = new();
		HashSet<string> usernames = new(StringComparer.OrdinalIgnoreCase);
		foreach (RdpSessionDto s in needIp)
		{
			wtsIds.Add(s.SessionId);
			usernames.Add(s.UserName);
		}

		List<SessionIpCorrelation> wtsMatches = await db.SessionIpCorrelations
			.AsNoTracking()
			.Where(r => r.WtsSessionId != null
				&& wtsIds.Contains(r.WtsSessionId.Value)
				&& r.UserName != null
				&& usernames.Contains(r.UserName))
			.OrderByDescending(r => r.LastSeenUtc)
			.ToListAsync(ct).ConfigureAwait(false);

		Dictionary<(int Wts, string User), string> wtsUserToIp = new();
		foreach (SessionIpCorrelation row in wtsMatches)
		{
			if (row.WtsSessionId is int wts && row.UserName is string u)
			{
				(int, string) key = (wts, u.Trim());
				if (!wtsUserToIp.ContainsKey(key))
				{
					wtsUserToIp[key] = row.Ip;
				}
			}
		}

		List<SessionIpCorrelation> userMatches = await db.SessionIpCorrelations
			.AsNoTracking()
			.Where(r => r.UserName != null && usernames.Contains(r.UserName))
			.OrderByDescending(r => r.LastSeenUtc)
			.ToListAsync(ct).ConfigureAwait(false);

		Dictionary<string, string> userToIp = new(StringComparer.OrdinalIgnoreCase);
		foreach (SessionIpCorrelation row in userMatches)
		{
			if (row.UserName is string u && !userToIp.ContainsKey(u.Trim()))
			{
				userToIp[u.Trim()] = row.Ip;
			}
		}

		foreach (RdpSessionDto session in needIp)
		{
			if (wtsUserToIp.TryGetValue((session.SessionId, session.UserName.Trim()), out string? ip))
			{
				session.ClientAddress = ip;
				continue;
			}

			if (userToIp.TryGetValue(session.UserName.Trim(), out ip))
			{
				session.ClientAddress = ip;
			}
		}

		// Stage IP-C: fallback historical enrichment from RdpConnectionFacts. Only fills in
		// ClientAddress that remained empty after the active SessionIpCorrelations pass — the
		// correlations table is still authoritative for live sessions, the connection facts only
		// add the most recent historical observation when no live correlation exists.
		await EnrichSessionsFromConnectionFactsAsync(db, sessions, ct).ConfigureAwait(false);
	}

	/// <summary>Stage IP-C helper: enriches sessions with the most recent <see cref="RdpConnectionFact"/>
	/// IP for the same (WtsSessionId, UserName) or UserName. Only fills <c>ClientAddress</c> when it
	/// is still empty — does not override values set by the live correlation lookup.</summary>
	internal static async Task EnrichSessionsFromConnectionFactsAsync(
		AuditDbContext db,
		IList<RdpSessionDto> sessions,
		CancellationToken ct)
	{
		List<RdpSessionDto> needIp = new(sessions.Count);
		foreach (RdpSessionDto s in sessions)
		{
			if (string.IsNullOrEmpty(s.ClientAddress) && !string.IsNullOrEmpty(s.UserName))
			{
				needIp.Add(s);
			}
		}

		if (needIp.Count == 0)
		{
			return;
		}

		HashSet<int> wtsIds = new();
		HashSet<string> usernames = new(StringComparer.OrdinalIgnoreCase);
		foreach (RdpSessionDto s in needIp)
		{
			wtsIds.Add(s.SessionId);
			usernames.Add(s.UserName);
		}

		List<RdpConnectionFact> wtsMatches = await db.RdpConnectionFacts
			.AsNoTracking()
			.Where(r => r.WtsSessionId != null
				&& wtsIds.Contains(r.WtsSessionId.Value)
				&& r.UserName != null
				&& usernames.Contains(r.UserName))
			.OrderByDescending(r => r.LastSeenUtc)
			.ToListAsync(ct).ConfigureAwait(false);

		Dictionary<(int Wts, string User), string> wtsUserToIp = new();
		foreach (RdpConnectionFact row in wtsMatches)
		{
			if (row.WtsSessionId is int wts && row.UserName is string u)
			{
				(int, string) key = (wts, u.Trim());
				if (!wtsUserToIp.ContainsKey(key))
				{
					wtsUserToIp[key] = row.Ip;
				}
			}
		}

		List<RdpConnectionFact> userMatches = await db.RdpConnectionFacts
			.AsNoTracking()
			.Where(r => r.UserName != null && usernames.Contains(r.UserName))
			.OrderByDescending(r => r.LastSeenUtc)
			.ToListAsync(ct).ConfigureAwait(false);

		Dictionary<string, string> userToIp = new(StringComparer.OrdinalIgnoreCase);
		foreach (RdpConnectionFact row in userMatches)
		{
			if (row.UserName is string u && !userToIp.ContainsKey(u.Trim()))
			{
				userToIp[u.Trim()] = row.Ip;
			}
		}

		foreach (RdpSessionDto session in needIp)
		{
			if (wtsUserToIp.TryGetValue((session.SessionId, session.UserName.Trim()), out string? ip))
			{
				session.ClientAddress = ip;
				continue;
			}

			if (userToIp.TryGetValue(session.UserName.Trim(), out ip))
			{
				session.ClientAddress = ip;
			}
		}

		// Stage IP-D: fill historical context (first/last seen, counters, attempted usernames)
		// for every session that has a UserName, even those whose ClientAddress was already known
		// from the live correlation lookup. We never overwrite ClientAddress here — that path is
		// authoritative for the live row — but the historical context is purely additive.
		await EnrichSessionsHistoricalContextAsync(db, sessions, ct).ConfigureAwait(false);
	}

	/// <summary>Stage IP-D helper: fills historical-only fields on each session from RdpConnectionFacts.
	/// Never overwrites live <c>ClientAddress</c>; only sets the dedicated Historical* columns and
	/// only when the live row has none. Exposed internally so unit tests can validate without a
	/// Windows session manager.</summary>
	internal static async Task EnrichSessionsHistoricalContextAsync(
		AuditDbContext db,
		IList<RdpSessionDto> sessions,
		CancellationToken ct)
	{
		if (sessions.Count == 0)
		{
			return;
		}

		HashSet<string> usernames = new(StringComparer.OrdinalIgnoreCase);
		foreach (RdpSessionDto s in sessions)
		{
			if (!string.IsNullOrEmpty(s.UserName))
			{
				usernames.Add(s.UserName.Trim());
			}
		}

		if (usernames.Count == 0)
		{
			return;
		}

		var grouped = await db.RdpConnectionFacts.AsNoTracking()
			.Where(r => r.UserName != null && usernames.Contains(r.UserName))
			.GroupBy(r => r.UserName!)
			.Select(g => new
			{
				UserName = g.Key,
				FirstSeen = g.Min(r => r.FirstSeenUtc),
				LastSeen = g.Max(r => r.LastSeenUtc),
				Failed = g.Sum(r => (long)r.FailedLogons),
				Successful = g.Sum(r => (long)r.SuccessfulLogons),
			})
			.ToListAsync(ct).ConfigureAwait(false);

		Dictionary<string, (DateTime First, DateTime Last, long Failed, long Successful)> byUser =
			new(StringComparer.OrdinalIgnoreCase);
		foreach (var g in grouped)
		{
			byUser[g.UserName.Trim()] = (g.FirstSeen, g.LastSeen, g.Failed, g.Successful);
		}

		// Pull attempted-username summaries by joining each session's user back to facts.
		List<RdpConnectionFact> usernameFacts = await db.RdpConnectionFacts.AsNoTracking()
			.Where(r => r.UserName != null && usernames.Contains(r.UserName))
			.OrderByDescending(r => r.LastSeenUtc)
			.Select(r => new RdpConnectionFact
			{
				UserName = r.UserName,
				UserNamesAttempted = r.UserNamesAttempted,
			})
			.ToListAsync(ct).ConfigureAwait(false);

		Dictionary<string, string?> attemptedByUser = new(StringComparer.OrdinalIgnoreCase);
		foreach (RdpConnectionFact r in usernameFacts)
		{
			if (r.UserName is null)
			{
				continue;
			}

			string key = r.UserName.Trim();
			if (!attemptedByUser.ContainsKey(key))
			{
				attemptedByUser[key] = r.UserNamesAttempted;
			}
		}

		foreach (RdpSessionDto session in sessions)
		{
			if (string.IsNullOrEmpty(session.UserName))
			{
				continue;
			}

			string key = session.UserName.Trim();
			if (byUser.TryGetValue(key, out var agg))
			{
				session.HistoricalFirstSeenUtc = agg.First;
				session.HistoricalLastSeenUtc = agg.Last;
				session.HistoricalFailedLogons = agg.Failed;
				session.HistoricalSuccessfulLogons = agg.Successful;
			}

			if (attemptedByUser.TryGetValue(key, out string? attempted) && !string.IsNullOrEmpty(attempted))
			{
				session.HistoricalUserNamesAttempted = attempted;
			}
		}

		// Stage 2: per-IP historical aggregation. Populates HistoricalFailedLogonsByIp /
		// HistoricalSuccessfulLogonsByIp / HistoricalUsersAttemptedFromIp / HistoricalFirstSeenByIpUtc /
		// HistoricalLastSeenByIpUtc from RdpConnectionFacts keyed on the session's ClientAddress.
		// Sessions without a resolved IP keep these fields null (operator sees blank, not 0).
		await EnrichSessionsHistoricalByIpAsync(db, sessions, ct).ConfigureAwait(false);
	}

	/// <summary>Stage 2 helper: fills per-IP historical context on each session from RdpConnectionFacts.
	/// Populates the *ByIp fields only — never touches the user-keyed historical columns. Sessions
	/// whose <c>ClientAddress</c> is empty or unparseable are skipped, leaving the new fields null so
	/// the UI can distinguish unknown IP from a real zero.</summary>
	internal static async Task EnrichSessionsHistoricalByIpAsync(
		AuditDbContext db,
		IList<RdpSessionDto> sessions,
		CancellationToken ct)
	{
		if (sessions.Count == 0)
		{
			return;
		}

		HashSet<string> ips = new(StringComparer.Ordinal);
		foreach (RdpSessionDto s in sessions)
		{
			if (!string.IsNullOrEmpty(s.ClientAddress))
			{
				ips.Add(s.ClientAddress.Trim());
			}
		}

		if (ips.Count == 0)
		{
			return;
		}

		var grouped = await db.RdpConnectionFacts.AsNoTracking()
			.Where(r => ips.Contains(r.Ip))
			.GroupBy(r => r.Ip)
			.Select(g => new
			{
				Ip = g.Key,
				FirstSeen = g.Min(r => r.FirstSeenUtc),
				LastSeen = g.Max(r => r.LastSeenUtc),
				Failed = g.Sum(r => (long)r.FailedLogons),
				Successful = g.Sum(r => (long)r.SuccessfulLogons),
			})
			.ToListAsync(ct).ConfigureAwait(false);

		Dictionary<string, (DateTime First, DateTime Last, long Failed, long Successful)> byIp =
			new(StringComparer.Ordinal);
		foreach (var g in grouped)
		{
			byIp[g.Ip] = (g.FirstSeen, g.LastSeen, g.Failed, g.Successful);
		}

		// Distinct attempted usernames per IP (deduplicated, bounded). Order by LastSeenUtc desc so
		// the most recently attempted usernames come first.
		List<RdpConnectionFact> userFacts = await db.RdpConnectionFacts.AsNoTracking()
			.Where(r => ips.Contains(r.Ip) && r.UserName != null && r.UserName != string.Empty)
			.OrderByDescending(r => r.LastSeenUtc)
			.Select(r => new RdpConnectionFact
			{
				Ip = r.Ip,
				UserName = r.UserName,
			})
			.ToListAsync(ct).ConfigureAwait(false);

		Dictionary<string, List<string>> distinctUsersByIp = new(StringComparer.Ordinal);
		const int maxUsersPerIp = 20;
		foreach (RdpConnectionFact r in userFacts)
		{
			if (string.IsNullOrEmpty(r.UserName))
			{
				continue;
			}

			if (!distinctUsersByIp.TryGetValue(r.Ip, out List<string>? list))
			{
				list = new List<string>();
				distinctUsersByIp[r.Ip] = list;
			}

			if (list.Count >= maxUsersPerIp)
			{
				continue;
			}

			string trimmed = r.UserName.Trim();
			if (trimmed.Length == 0)
			{
				continue;
			}

			bool exists = false;
			foreach (string u in list)
			{
				if (string.Equals(u, trimmed, StringComparison.OrdinalIgnoreCase))
				{
					exists = true;
					break;
				}
			}

			if (!exists)
			{
				list.Add(trimmed);
			}
		}

		foreach (RdpSessionDto session in sessions)
		{
			if (string.IsNullOrEmpty(session.ClientAddress))
			{
				continue;
			}

			string ipKey = session.ClientAddress.Trim();
			if (byIp.TryGetValue(ipKey, out var agg))
			{
				session.HistoricalFirstSeenByIpUtc = agg.First;
				session.HistoricalLastSeenByIpUtc = agg.Last;
				session.HistoricalFailedLogonsByIp = agg.Failed;
				session.HistoricalSuccessfulLogonsByIp = agg.Successful;
			}
			else
			{
				// No fact rows yet for this IP — still populate counters with 0 so operators can
				// distinguish "we know the IP, just no history" from "no IP at all" (which leaves
				// the fields null and shows blank).
				session.HistoricalFailedLogonsByIp = 0;
				session.HistoricalSuccessfulLogonsByIp = 0;
			}

			if (distinctUsersByIp.TryGetValue(ipKey, out List<string>? users) && users.Count > 0)
			{
				session.HistoricalUsersAttemptedFromIp = string.Join(", ", users);
			}
		}
	}

	private async Task<object?> DisconnectSessionAsync(string? payload, CancellationToken ct)
	{
		SessionActionRequest req = DeserializeSessionRequest(payload, "DisconnectSession");
		if (!OperatingSystem.IsWindows() || _sessions is null)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.Unavailable,
				SessionId = req.SessionId,
				Message = "Session control is only available on Windows hosts.",
			};
		}

		if (!_options.CurrentValue.SessionControl.Enabled || !_options.CurrentValue.SessionControl.AllowDisconnect)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.Refused,
				SessionId = req.SessionId,
				Message = "Disconnect is disabled by SessionControl policy.",
			};
		}

		_logger.LogInformation("Operator-issued disconnect for session {Id} reason='{Reason}'",
			req.SessionId, req.Reason ?? string.Empty);
		return await _sessions.DisconnectAsync(req.SessionId, ct).ConfigureAwait(false);
	}

	private async Task<object?> LogoffSessionAsync(string? payload, CancellationToken ct)
	{
		SessionActionRequest req = DeserializeSessionRequest(payload, "LogoffSession");
		if (!OperatingSystem.IsWindows() || _sessions is null)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.Unavailable,
				SessionId = req.SessionId,
				Message = "Session control is only available on Windows hosts.",
			};
		}

		if (!_options.CurrentValue.SessionControl.Enabled || !_options.CurrentValue.SessionControl.AllowLogoff)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.Refused,
				SessionId = req.SessionId,
				Message = "Logoff is disabled by SessionControl policy.",
			};
		}

		_logger.LogInformation("Operator-issued logoff for session {Id} reason='{Reason}'",
			req.SessionId, req.Reason ?? string.Empty);
		return await _sessions.LogoffAsync(req.SessionId, ct).ConfigureAwait(false);
	}

	/// <summary>The actual <c>mstsc.exe /shadow</c> spawn must happen in the operator's interactive
	/// desktop session — the service runs under LocalSystem and cannot launch interactive UI. This
	/// handler therefore only enforces policy and returns a Success/Refused result; the Configurator
	/// is responsible for spawning mstsc with sanitized arguments built by the same Core helper.</summary>
	private SessionActionResult ShadowSessionPolicyCheck(string? payload)
	{
		SessionActionRequest req = DeserializeSessionRequest(payload, "ShadowSession");
		if (!OperatingSystem.IsWindows())
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.Unavailable,
				SessionId = req.SessionId,
				Message = "Shadow is only available on Windows hosts.",
			};
		}

		SessionControlOptions cfg = _options.CurrentValue.SessionControl;
		if (!cfg.Enabled || !cfg.AllowShadow)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.Refused,
				SessionId = req.SessionId,
				Message = "Shadow is disabled by SessionControl policy.",
			};
		}

		SessionIdValidation v = SessionCommandBuilder.ValidateSessionId(req.SessionId);
		if (!v.Ok)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.InvalidRequest,
				SessionId = req.SessionId,
				Message = v.Error,
			};
		}

		if (cfg.RequireShadowPolicy && _shadow is not null)
		{
			ShadowPolicyStatusDto status = _shadow.GetStatus();
			ShadowPolicyMode policy = ShadowPolicyModel.FromRawValue(status.ShadowMode);
			SessionCommandBuilder.ShadowMode requested = req.ShadowMode switch
			{
				1 => SessionCommandBuilder.ShadowMode.Control,
				2 => SessionCommandBuilder.ShadowMode.ControlNoConsent,
				_ => SessionCommandBuilder.ShadowMode.ViewOnly,
			};
			if (!ShadowPolicyModel.AllowsMode(policy, requested))
			{
				return new SessionActionResult
				{
					Status = IpcResultStatus.Refused,
					SessionId = req.SessionId,
					Message = string.Format(CultureInfo.InvariantCulture,
						"Shadow {0} refused — current policy '{1}' does not permit it. Use Apply Shadow Policy first.",
						requested, ShadowPolicyModel.Describe(policy)),
				};
			}
		}

		_logger.LogInformation("Operator-approved shadow request for session {Id} mode={Mode} reason='{Reason}'",
			req.SessionId, req.ShadowMode, req.Reason ?? string.Empty);
		return new SessionActionResult
		{
			Status = IpcResultStatus.Success,
			SessionId = req.SessionId,
			Message = "Shadow request approved by policy. Configurator must launch mstsc in the operator's desktop.",
		};
	}

	private RdpConfigurationDto GetRdpConfigurationHandler()
	{
		if (!OperatingSystem.IsWindows() || _rdpConfigReader is null)
		{
			return new RdpConfigurationDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "RDP configuration is only available on Windows hosts.",
			};
		}

		return _rdpConfigReader.Read();
	}

	private ShadowPolicyStatusDto GetShadowPolicyStatusHandler()
	{
		if (!OperatingSystem.IsWindows() || _shadow is null)
		{
			return new ShadowPolicyStatusDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "Shadow policy management is only available on Windows hosts.",
			};
		}

		return _shadow.GetStatus();
	}

	private ShadowPolicyStatusDto ApplyShadowPolicyHandler(string? payload)
	{
		if (!OperatingSystem.IsWindows() || _shadow is null)
		{
			return new ShadowPolicyStatusDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "Shadow policy management is only available on Windows hosts.",
			};
		}

		ShadowPolicyApplyRequest req = DeserializeApplyRequest(payload);
		_logger.LogInformation(
			"Operator-issued ApplyShadowPolicy mode={Mode} enableAll={Enable} backup={Backup} reason='{Reason}'",
			req.ShadowMode, req.EnableAllPermissions, req.TakeBackupFirst, req.Reason ?? string.Empty);
		return _shadow.Apply(req);
	}

	private ShadowPolicyStatusDto BackupShadowPolicyHandler()
	{
		if (!OperatingSystem.IsWindows() || _shadow is null)
		{
			return new ShadowPolicyStatusDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "Shadow policy management is only available on Windows hosts.",
			};
		}

		_logger.LogInformation("Operator-issued BackupShadowPolicy");
		return _shadow.Backup();
	}

	private ShadowPolicyStatusDto RestoreShadowPolicyHandler(string? payload)
	{
		if (!OperatingSystem.IsWindows() || _shadow is null)
		{
			return new ShadowPolicyStatusDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "Shadow policy management is only available on Windows hosts.",
			};
		}

		string? snapshotId = null;
		if (!string.IsNullOrWhiteSpace(payload))
		{
			try
			{
				snapshotId = JsonSerializer.Deserialize<string>(payload, JsonOptions.Default);
			}
			catch (JsonException ex)
			{
				throw new IpcException("RestoreShadowPolicy payload is not a valid JSON string: " + ex.Message);
			}
		}

		_logger.LogInformation("Operator-issued RestoreShadowPolicy snapshot='{Snapshot}'", snapshotId ?? string.Empty);
		return _shadow.Restore(snapshotId);
	}

	private static SessionActionRequest DeserializeSessionRequest(string? payload, string commandName)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} requires a JSON payload with the SessionId.", commandName));
		}

		SessionActionRequest? parsed;
		try
		{
			parsed = JsonSerializer.Deserialize<SessionActionRequest>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} payload is not valid JSON: {1}", commandName, ex.Message));
		}

		if (parsed is null)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} payload could not be parsed.", commandName));
		}

		SessionIdValidation v = SessionCommandBuilder.ValidateSessionId(parsed.SessionId);
		if (!v.Ok)
		{
			throw new IpcException(v.Error ?? "Invalid SessionId.");
		}

		return parsed;
	}

	private static ShadowPolicyApplyRequest DeserializeApplyRequest(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			return new ShadowPolicyApplyRequest();
		}

		try
		{
			ShadowPolicyApplyRequest? parsed = JsonSerializer.Deserialize<ShadowPolicyApplyRequest>(payload, JsonOptions.Default);
			return parsed ?? new ShadowPolicyApplyRequest();
		}
		catch (JsonException ex)
		{
			throw new IpcException("ApplyShadowPolicy payload is not valid JSON: " + ex.Message);
		}
	}

	// ----------------------------------------------------------------------------------------------

	/// <summary>Returns a copy of the current settings with every secret field masked.</summary>
	private RdpAuditOptions GetMaskedSettings()
	{
		RdpAuditOptions src = _options.CurrentValue;
		RdpAuditOptions copy = new()
		{
			Monitoring = src.Monitoring,
			Alerts = src.Alerts,
			Firewall = src.Firewall,
			Storage = src.Storage,
			Diagnostics = src.Diagnostics,
			SessionControl = src.SessionControl,
			AbuseIpDb = CloneAbuse(src.AbuseIpDb),
			MikroTik = CloneMikroTik(src.MikroTik),
		};
		copy.AbuseIpDb.ApiKey = MaskSecret(src.AbuseIpDb.ApiKey);
		copy.MikroTik.Password = MaskSecret(src.MikroTik.Password);
		return copy;
	}

	private static AbuseIpDbOptions CloneAbuse(AbuseIpDbOptions src) => new()
	{
		Enabled = src.Enabled,
		ReportAttacks = src.ReportAttacks,
		ApiKey = src.ApiKey,
		BaseUrl = src.BaseUrl,
		EndpointUrl = src.EndpointUrl,
		TimeoutSeconds = src.TimeoutSeconds,
		MaxReportsPerMinute = src.MaxReportsPerMinute,
		MaxReportsPerHour = src.MaxReportsPerHour,
		MaxReportsPerDay = src.MaxReportsPerDay,
		DeduplicationWindowMinutes = src.DeduplicationWindowMinutes,
		CacheLookups = src.CacheLookups,
		CacheTtlMinutes = src.CacheTtlMinutes,
		ReportThreshold = src.ReportThreshold,
		MinThreatScore = src.MinThreatScore,
		MinFailedAttempts = src.MinFailedAttempts,
		ReportCategories = new List<int>(src.ReportCategories),
	};

	private static MikroTikOptions CloneMikroTik(MikroTikOptions src) => new()
	{
		Enabled = src.Enabled,
		AddAttackerRules = src.AddAttackerRules,
		BaseUrl = src.BaseUrl,
		UseHttps = src.UseHttps,
		Host = src.Host,
		Port = src.Port,
		UserName = src.UserName,
		Password = src.Password,
		TimeoutSeconds = src.TimeoutSeconds,
		AddressList = src.AddressList,
		FilterChain = src.FilterChain,
		FilterAction = src.FilterAction,
		CommentTemplate = src.CommentTemplate,
		CommentPrefix = src.CommentPrefix,
		ValidateServerCertificate = src.ValidateServerCertificate,
		MaxOperationsPerMinute = src.MaxOperationsPerMinute,
		BlockDurationDays = src.BlockDurationDays,
		BlockDurationHours = src.BlockDurationHours,
		BlockDurationMinutes = src.BlockDurationMinutes,
	};

	private static string MaskSecret(string raw)
	{
		if (string.IsNullOrWhiteSpace(raw))
		{
			return string.Empty;
		}
		// Never echo the protected envelope or the plaintext. Just signal that a value is set.
		return "***configured***";
	}

	// ----------------------------------------------------------------------------------------------
	// Stage 8 handlers — AbuseIPDB integration.
	// ----------------------------------------------------------------------------------------------

	private async Task<object?> GetAbuseIpDbStatusAsync(CancellationToken ct)
	{
		AbuseIpDbOptions opts = _options.CurrentValue.AbuseIpDb;
		AbuseIpDbStatusDto dto = new()
		{
			Status = IpcResultStatus.Success,
			CredentialPresent = !string.IsNullOrWhiteSpace(opts.ApiKey),
			ReportingEnabled = opts.Enabled && opts.ReportAttacks,
			EndpointUrl = string.IsNullOrWhiteSpace(opts.EndpointUrl)
				? "https://api.abuseipdb.com/api/v2/report"
				: opts.EndpointUrl,
			DeduplicationWindowMinutes = Math.Max(15, opts.DeduplicationWindowMinutes),
			MaxReportsPerHour = Math.Max(1, opts.MaxReportsPerHour),
			MaxReportsPerDay = Math.Max(1, opts.MaxReportsPerDay),
			ReportDedupeEnabled = opts.ReportDedupeEnabled,
			ReportCooldownHours = Math.Clamp(opts.ReportCooldownHours, 1, 8760),
		};

		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
			DateTime nowUtc = DateTime.UtcNow;

			dto.TotalReports = await db.AbuseReports.AsNoTracking().LongCountAsync(ct).ConfigureAwait(false);
			dto.ReportsLastHour = await db.AbuseReports.AsNoTracking()
				.LongCountAsync(r => r.ReportedUtc >= nowUtc.AddHours(-1), ct).ConfigureAwait(false);
			dto.ReportsLastDay = await db.AbuseReports.AsNoTracking()
				.LongCountAsync(r => r.ReportedUtc >= nowUtc.AddDays(-1), ct).ConfigureAwait(false);

			AbuseReport? last = await db.AbuseReports.AsNoTracking()
				.OrderByDescending(r => r.ReportedUtc)
				.FirstOrDefaultAsync(ct)
				.ConfigureAwait(false);
			if (last is not null)
			{
				dto.LastResponseCode = last.ResponseCode;
				dto.LastReportUtc = last.ReportedUtc;
				dto.LastReportedIp = last.Ip;
				if (!string.IsNullOrEmpty(last.Error))
				{
					dto.LastError = last.Error;
				}
			}

			dto.RateLimited = dto.ReportsLastHour >= dto.MaxReportsPerHour
				|| dto.ReportsLastDay >= dto.MaxReportsPerDay;

			dto.Message = string.Format(CultureInfo.InvariantCulture,
				"AbuseIPDB status: enabled={0} reportAttacks={1} credential={2} lastHour={3} lastDay={4}",
				opts.Enabled,
				opts.ReportAttacks,
				dto.CredentialPresent ? "configured" : "missing",
				dto.ReportsLastHour,
				dto.ReportsLastDay);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "GetAbuseIpDbStatus database lookup failed");
			dto.Status = IpcResultStatus.Unavailable;
			dto.Message = "AbuseIPDB status: database lookup failed.";
		}

		return dto;
	}

	private async Task<object?> TestAbuseIpDbKeyAsync(CancellationToken ct)
	{
		AbuseIpDbOptions opts = _options.CurrentValue.AbuseIpDb;
		AbuseIpDbTestResult result = new();

		if (string.IsNullOrWhiteSpace(opts.ApiKey))
		{
			result.Status = IpcResultStatus.InvalidRequest;
			result.KeyFormatValid = false;
			result.RemoteVerified = false;
			result.ResponseCode = 0;
			result.Message = "No API key configured.";
			return result;
		}

		string? plaintext = null;
		if (_protector is not null)
		{
			try
			{
				plaintext = _protector.Unprotect(opts.ApiKey);
			}
			catch (SecretProtectionException)
			{
				plaintext = null;
			}
		}
		else
		{
			plaintext = opts.ApiKey;
		}

		bool formatOk = AbuseIpDbApiKeyValidator.IsLikelyValid(plaintext);
		result.KeyFormatValid = formatOk;

		if (!formatOk)
		{
			result.Status = IpcResultStatus.Refused;
			result.Message = "Key format check failed.";
			return result;
		}

		if (_abuseClient is null)
		{
			result.Status = IpcResultStatus.Unavailable;
			result.Message = "AbuseIPDB client is not registered on this host.";
			return result;
		}

		AbuseIpDbReportResult probe = await _abuseClient.ValidateKeyAsync(ct).ConfigureAwait(false);
		result.ResponseCode = probe.ResponseCode;
		result.Message = probe.Message;
		switch (probe.Outcome)
		{
			case AbuseIpDbReportOutcome.Accepted:
				result.RemoteVerified = true;
				result.Status = IpcResultStatus.Success;
				break;
			case AbuseIpDbReportOutcome.Rejected:
				result.RemoteVerified = false;
				result.Status = IpcResultStatus.Refused;
				break;
			case AbuseIpDbReportOutcome.RateLimited:
				result.RemoteVerified = false;
				result.Status = IpcResultStatus.Unavailable;
				break;
			case AbuseIpDbReportOutcome.NotConfigured:
				result.RemoteVerified = false;
				result.Status = IpcResultStatus.InvalidRequest;
				break;
			default:
				result.RemoteVerified = false;
				result.Status = IpcResultStatus.Unavailable;
				break;
		}
		return result;
	}

	private const int AbuseIpDbReportLogDefaultLimit = 200;
	private const int AbuseIpDbReportLogMaxLimit = 1000;

	private async Task<object?> ListAbuseIpDbReportLogAsync(string? payload, CancellationToken ct)
	{
		int limit = AbuseIpDbReportLogDefaultLimit;
		if (!string.IsNullOrWhiteSpace(payload))
		{
			try
			{
				int requested = JsonSerializer.Deserialize<int>(payload, JsonOptions.Default);
				if (requested > 0)
				{
					limit = requested;
				}
			}
			catch (JsonException)
			{
				// Tolerate a missing / malformed limit and fall back to the default.
			}
		}

		if (limit > AbuseIpDbReportLogMaxLimit)
		{
			limit = AbuseIpDbReportLogMaxLimit;
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		List<AbuseIpDbReportHistory> rows = await db.AbuseIpDbReportHistory.AsNoTracking()
			.OrderByDescending(r => r.ReportedAtUtc)
			.ThenByDescending(r => r.Id)
			.Take(limit)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		return rows.ConvertAll(r => new AbuseIpDbReportLogDto
		{
			Id = r.Id,
			TimeUtc = r.ReportedAtUtc,
			SourceIp = r.IpAddress,
			Classification = r.Classification,
			Action = r.Action,
			Reason = r.Reason,
			HttpStatusCode = r.HttpStatusCode,
			ReportId = r.ReportId,
			CooldownExpiresUtc = r.CooldownExpiresUtc,
			FailedCount = r.FailedCount,
			SuccessfulCount = r.SuccessfulCount,
			FirstSeenUtc = r.FirstSeenUtc,
			LastSeenUtc = r.LastSeenUtc,
			UsernamesSample = r.UsernamesSample,
			CommentPreview = r.CommentPreview,
			Source = r.Source,
		});
	}

	// ----------------------------------------------------------------------------------------------
	// Stage 9 handlers — MikroTik integration.
	// ----------------------------------------------------------------------------------------------

	private async Task<object?> GetMikroTikStatusAsync(CancellationToken ct)
	{
		MikroTikOptions opts = _options.CurrentValue.MikroTik;
		MikroTikUrlBuilder.Result built = MikroTikUrlBuilder.Build(opts);
		string endpoint = built.Ok ? built.Url : opts.DescribeEndpoint();

		MikroTikStatusDto dto = new()
		{
			Status = IpcResultStatus.Success,
			Configured = built.Ok && !string.IsNullOrWhiteSpace(opts.UserName),
			CredentialPresent = !string.IsNullOrWhiteSpace(opts.Password),
			Enabled = opts.Enabled,
			AddAttackerRules = opts.AddAttackerRules,
			Endpoint = endpoint,
			Scheme = built.Ok && !string.IsNullOrEmpty(endpoint) && endpoint.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
				? "https"
				: (built.Ok && !string.IsNullOrEmpty(endpoint) ? "http" : string.Empty),
			Host = opts.Host,
			Port = opts.Port,
			FilterChain = opts.FilterChain,
			FilterAction = opts.FilterAction,
			CommentPrefix = string.IsNullOrWhiteSpace(opts.CommentPrefix) ? "RdpAudit" : opts.CommentPrefix,
			BlockDurationSeconds = (long)opts.ComposedBlockDuration().TotalSeconds,
			ValidateServerCertificate = opts.ValidateServerCertificate,
			ProviderStatus = FirewallProviderStatus.NotConfigured.ToString(),
		};

		if (!built.Ok)
		{
			dto.LastError = built.Error;
		}

		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
			dto.ActiveBlockCount = await db.ActiveBlocks.AsNoTracking()
				.LongCountAsync(b => b.Provider == FirewallProviderKind.MikroTik
					&& (b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending), ct)
				.ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "GetMikroTikStatus active-block lookup failed");
			dto.Status = IpcResultStatus.Unavailable;
		}

		// Resolve the actual provider status from the registered providers when available.
		foreach (IFirewallProvider provider in _providers)
		{
			if (!string.Equals(provider.ProviderId, "MikroTik", StringComparison.OrdinalIgnoreCase))
			{
				continue;
			}

			try
			{
				FirewallStatusReport report = await provider.GetStatusAsync(ct).ConfigureAwait(false);
				dto.ProviderStatus = report.Status.ToString();
				if (report.Status != FirewallProviderStatus.Available && !string.IsNullOrWhiteSpace(report.Message))
				{
					dto.LastError = report.Message;
				}
				else if (report.Status == FirewallProviderStatus.Available)
				{
					dto.LastError = null;
				}
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "MikroTik provider GetStatus threw");
				dto.ProviderStatus = FirewallProviderStatus.Unreachable.ToString();
				dto.LastError = ex.GetType().Name;
			}
			break;
		}

		dto.Message = string.Format(CultureInfo.InvariantCulture,
			"MikroTik status: enabled={0} addRules={1} credential={2} endpoint={3} active={4}",
			opts.Enabled,
			opts.AddAttackerRules,
			dto.CredentialPresent ? "configured" : "missing",
			string.IsNullOrEmpty(endpoint) ? "(unset)" : endpoint,
			dto.ActiveBlockCount);
		return dto;
	}

	private async Task<object?> TestMikroTikAsync(CancellationToken ct)
	{
		MikroTikOptions opts = _options.CurrentValue.MikroTik;
		MikroTikUrlBuilder.Result built = MikroTikUrlBuilder.Build(opts);
		MikroTikTestResult result = new()
		{
			Endpoint = built.Ok ? built.Url : opts.DescribeEndpoint(),
		};

		if (!built.Ok)
		{
			result.Status = IpcResultStatus.InvalidRequest;
			result.CredentialFormatValid = false;
			result.RemoteVerified = false;
			result.Message = built.Error ?? "Endpoint composition failed.";
			return result;
		}

		if (string.IsNullOrWhiteSpace(opts.UserName) || string.IsNullOrWhiteSpace(opts.Password))
		{
			result.Status = IpcResultStatus.InvalidRequest;
			result.CredentialFormatValid = false;
			result.RemoteVerified = false;
			result.Message = "Username and password must be configured before testing.";
			return result;
		}

		result.CredentialFormatValid = true;

		if (_mikroTikClient is null)
		{
			result.Status = IpcResultStatus.Unavailable;
			result.RemoteVerified = false;
			result.Message = "MikroTik client is not registered on this host.";
			return result;
		}

		MikroTikOperationResult probe = await _mikroTikClient.PingAsync(ct).ConfigureAwait(false);
		result.ResponseCode = probe.ResponseCode;
		result.Message = probe.Message;

		switch (probe.Outcome)
		{
			case MikroTikOutcome.Accepted:
				result.RemoteVerified = true;
				result.Status = IpcResultStatus.Success;
				break;
			case MikroTikOutcome.Rejected:
				result.RemoteVerified = false;
				result.Status = IpcResultStatus.Refused;
				break;
			case MikroTikOutcome.RateLimited:
			case MikroTikOutcome.ServerError:
			case MikroTikOutcome.TransportError:
				result.RemoteVerified = false;
				result.Status = IpcResultStatus.Unavailable;
				break;
			case MikroTikOutcome.NotConfigured:
				result.RemoteVerified = false;
				result.Status = IpcResultStatus.InvalidRequest;
				break;
			default:
				result.RemoteVerified = false;
				result.Status = IpcResultStatus.Unavailable;
				break;
		}
		return result;
	}

	// ----------------------------------------------------------------------------------------------
	// Stage A handlers — Overview dashboard summary + IP events export.
	// ----------------------------------------------------------------------------------------------

	/// <summary>Default cap on RawEvents returned by <c>GetEventsForIp</c> when no limit is supplied.</summary>
	internal const int EventsForIpDefaultLimit = 1000;

	/// <summary>Upper bound on RawEvents returned by <c>GetEventsForIp</c> regardless of caller intent.</summary>
	internal const int EventsForIpMaxLimit = 5000;

	private async Task<object?> GetOverviewSummaryAsync(CancellationToken ct)
	{
		DateTime nowUtc = DateTime.UtcNow;
		DateTime dayStart = nowUtc.Date;
		DateTime cutoff24h = nowUtc - TimeSpan.FromDays(1);

		OverviewSummaryDto dto = new()
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = nowUtc,
			DatabaseSizeBytes = -1,
		};

		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

			dto.AttacksToday = await db.Alerts.AsNoTracking()
				.LongCountAsync(a => a.TimeUtc >= dayStart, ct).ConfigureAwait(false);

			dto.BlockedIps = await db.ActiveBlocks.AsNoTracking()
				.Where(b => b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending)
				.Select(b => b.Ip)
				.Distinct()
				.LongCountAsync(ct).ConfigureAwait(false);

			dto.FailedLogins24h = await db.RawEvents.AsNoTracking()
				.LongCountAsync(
					e => e.TimeUtc >= cutoff24h && e.EventId == AttackStatsAggregator.EventIdLogonFailure,
					ct).ConfigureAwait(false);

			List<DbProp> snapshots = await db.DbProps.AsNoTracking()
				.Where(p => p.Key.StartsWith("OverviewDbSize:"))
				.ToListAsync(ct).ConfigureAwait(false);

			string dbPath = _options.CurrentValue.Storage.ResolveDatabasePath();
			try
			{
				FileInfo fi = new(dbPath);
				dto.DatabaseSizeBytes = fi.Exists ? fi.Length : -1;
			}
			catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
			{
				_logger.LogDebug(ex, "Database file size lookup failed");
				dto.DatabaseSizeBytes = -1;
			}

			if (dto.DatabaseSizeBytes >= 0)
			{
				List<DbSizeSnapshot> parsed = new();
				foreach (DbProp prop in snapshots)
				{
					if (DbSizeGrowthCalculator.TryDecode(prop.Value, out DbSizeSnapshot s))
					{
						parsed.Add(s);
					}
				}

				DbSizeGrowth growth = DbSizeGrowthCalculator.Compute(parsed, dto.DatabaseSizeBytes, nowUtc);
				dto.DatabaseGrowthBytesDay = growth.GrowthBytesDay;
				dto.DatabaseGrowthBytesWeek = growth.GrowthBytesWeek;
				dto.DatabaseGrowthBytesMonth = growth.GrowthBytesMonth;
			}

			RdpSessionListDto? sessions = null;
			if (OperatingSystem.IsWindows() && _sessions is not null)
			{
				try
				{
					sessions = await _sessions.ListAsync(ct).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					_logger.LogWarning(ex, "GetOverviewSummary session enumeration failed");
				}
			}
			dto.ActiveSessions = sessions is null
				? 0
				: ActiveSessionCounter.CountActiveUserSessions(sessions.Sessions);

			dto.ServiceHealth = "Running";
			dto.Message = string.Format(CultureInfo.InvariantCulture,
				"attacksToday={0} blockedIps={1} activeSessions={2} failed24h={3} dbBytes={4}",
				dto.AttacksToday, dto.BlockedIps, dto.ActiveSessions, dto.FailedLogins24h, dto.DatabaseSizeBytes);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "GetOverviewSummary lookup failed");
			dto.Status = IpcResultStatus.Unavailable;
			dto.Message = "Overview summary lookup failed — see service log.";
		}

		return dto;
	}

	private async Task<object?> GetEventsForIpAsync(string? payload, CancellationToken ct)
	{
		EventsForIpRequest req = ParseEventsForIpRequest(payload);
		string ip = NormalizeAndValidateAddress(req.Ip);

		int limit = req.Limit <= 0 ? EventsForIpDefaultLimit : req.Limit;
		if (limit > EventsForIpMaxLimit)
		{
			limit = EventsForIpMaxLimit;
		}

		DateTime nowUtc = DateTime.UtcNow;
		EventsForIpDto dto = new()
		{
			Status = IpcResultStatus.Success,
			Ip = ip,
			QueriedUtc = nowUtc,
		};

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		List<RawEvent> recent = await db.RawEvents.AsNoTracking()
			.Where(e => e.SourceIp == ip)
			.OrderByDescending(e => e.TimeUtc)
			.Take(limit)
			.ToListAsync(ct).ConfigureAwait(false);

		dto.TotalEvents = await db.RawEvents.AsNoTracking()
			.LongCountAsync(e => e.SourceIp == ip, ct).ConfigureAwait(false);

		if (dto.TotalEvents > 0)
		{
			dto.FirstSeenUtc = await db.RawEvents.AsNoTracking()
				.Where(e => e.SourceIp == ip)
				.MinAsync(e => (DateTime?)e.TimeUtc, ct).ConfigureAwait(false);
			dto.LastSeenUtc = await db.RawEvents.AsNoTracking()
				.Where(e => e.SourceIp == ip)
				.MaxAsync(e => (DateTime?)e.TimeUtc, ct).ConfigureAwait(false);
			dto.FailedCount = await db.RawEvents.AsNoTracking()
				.LongCountAsync(e => e.SourceIp == ip && e.EventId == AttackStatsAggregator.EventIdLogonFailure, ct)
				.ConfigureAwait(false);
			dto.SuccessCount = await db.RawEvents.AsNoTracking()
				.LongCountAsync(e => e.SourceIp == ip && e.EventId == AttackStatsAggregator.EventIdLogonSuccess, ct)
				.ConfigureAwait(false);

			if (dto.FirstSeenUtc.HasValue && dto.LastSeenUtc.HasValue)
			{
				dto.DurationSeconds = Math.Max(0, (long)(dto.LastSeenUtc.Value - dto.FirstSeenUtc.Value).TotalSeconds);
			}
		}

		dto.AttemptedUserNames = await db.RawEvents.AsNoTracking()
			.Where(e => e.SourceIp == ip && e.UserName != null && e.UserName != string.Empty)
			.OrderByDescending(e => e.TimeUtc)
			.Select(e => e.UserName!)
			.Distinct()
			.Take(20)
			.ToListAsync(ct).ConfigureAwait(false);

		AttackStat? stat = await db.AttackStats.AsNoTracking()
			.FirstOrDefaultAsync(s => s.Ip == ip, ct).ConfigureAwait(false);
		if (stat is not null)
		{
			dto.ThreatLevel = AttackThreatScoring.ClassifyScore(stat.ThreatScore).ToString();
			dto.IsBlocked = stat.IsBlocked;
			dto.AttackType = (stat.Failed > 0 && stat.Successful == 0)
				? "BruteForce"
				: (stat.Failed > 0 && stat.Successful > 0)
					? "BruteForceWithSuccess"
					: "LogonActivity";
		}
		else
		{
			dto.IsBlocked = await db.ActiveBlocks.AsNoTracking()
				.AnyAsync(b => b.Ip == ip
					&& (b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending), ct)
				.ConfigureAwait(false);
		}

		foreach (RawEvent ev in recent)
		{
			dto.Events.Add(new IpEventEntryDto
			{
				Id = ev.Id,
				TimeUtc = ev.TimeUtc,
				EventId = ev.EventId,
				Channel = ev.Channel,
				UserName = ev.UserName,
				Domain = ev.Domain,
				LogonType = ev.LogonType,
				AuthPackage = ev.AuthPackage,
				ProcessName = ev.ProcessName,
				Status = ev.Status,
			});
		}

		dto.Message = string.Format(CultureInfo.InvariantCulture,
			"events for {0}: returned={1} total={2}",
			ip, recent.Count, dto.TotalEvents);
		return dto;
	}

	private static EventsForIpRequest ParseEventsForIpRequest(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("GetEventsForIp requires a JSON payload with an Ip field.");
		}

		EventsForIpRequest? parsed;
		try
		{
			parsed = JsonSerializer.Deserialize<EventsForIpRequest>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException("GetEventsForIp payload is not valid JSON: " + ex.Message);
		}

		if (parsed is null || string.IsNullOrWhiteSpace(parsed.Ip))
		{
			throw new IpcException("GetEventsForIp requires an Ip field.");
		}

		return parsed;
	}

	// ----------------------------------------------------------------------------------------------
	// Stage IP-D handlers — RdpConnectionFacts read paths.
	// ----------------------------------------------------------------------------------------------

	/// <summary>Default cap on rows returned by <c>ListConnectionFacts</c> when no limit is supplied.</summary>
	internal const int ConnectionFactsDefaultLimit = 200;

	/// <summary>Upper bound on rows returned by <c>ListConnectionFacts</c> / <c>GetConnectionFactsForIp</c>.</summary>
	internal const int ConnectionFactsMaxLimit = 1000;

	private async Task<object?> ListConnectionFactsAsync(string? payload, CancellationToken ct)
	{
		ConnectionFactsRequest req = ParseConnectionFactsRequest(payload);

		int limit = req.Limit <= 0 ? ConnectionFactsDefaultLimit : req.Limit;
		if (limit > ConnectionFactsMaxLimit)
		{
			limit = ConnectionFactsMaxLimit;
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		IQueryable<RdpConnectionFact> q = db.RdpConnectionFacts.AsNoTracking();

		if (!string.IsNullOrWhiteSpace(req.IpQuery))
		{
			string needle = req.IpQuery.Trim();
			q = q.Where(r => EF.Functions.Like(r.Ip, "%" + needle + "%"));
		}

		if (!string.IsNullOrWhiteSpace(req.UserQuery))
		{
			string needleU = req.UserQuery.Trim();
			q = q.Where(r => r.UserName != null && EF.Functions.Like(r.UserName, "%" + needleU + "%"));
		}

		if (req.SinceUtc.HasValue)
		{
			DateTime since = req.SinceUtc.Value;
			q = q.Where(r => r.LastSeenUtc >= since);
		}

		if (req.UntilUtc.HasValue)
		{
			DateTime until = req.UntilUtc.Value;
			q = q.Where(r => r.LastSeenUtc <= until);
		}

		if (req.OnlyActive)
		{
			q = q.Where(r => r.IsActive);
		}

		int totalMatching = await q.CountAsync(ct).ConfigureAwait(false);

		List<RdpConnectionFact> rows = await q
			.OrderByDescending(r => r.LastSeenUtc)
			.ThenByDescending(r => r.Id)
			.Take(limit)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		ConnectionFactsDto dto = new()
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = DateTime.UtcNow,
			TotalMatching = totalMatching,
			AppliedLimit = limit,
			Message = string.Format(CultureInfo.InvariantCulture,
				"connection facts: matching={0} returned={1}",
				totalMatching, rows.Count),
		};

		foreach (RdpConnectionFact row in rows)
		{
			dto.Facts.Add(ProjectFact(row));
		}

		return dto;
	}

	private async Task<object?> GetConnectionFactsForIpAsync(string? payload, CancellationToken ct)
	{
		ConnectionFactsForIpRequest req = ParseConnectionFactsForIpRequest(payload);
		string ip = NormalizeAndValidateAddress(req.Ip);

		int limit = req.Limit <= 0 ? ConnectionFactsDefaultLimit : req.Limit;
		if (limit > ConnectionFactsMaxLimit)
		{
			limit = ConnectionFactsMaxLimit;
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		IQueryable<RdpConnectionFact> q = db.RdpConnectionFacts.AsNoTracking()
			.Where(r => r.Ip == ip);

		int totalMatching = await q.CountAsync(ct).ConfigureAwait(false);

		ConnectionFactsForIpDto dto = new()
		{
			Status = IpcResultStatus.Success,
			Ip = ip,
			QueriedUtc = DateTime.UtcNow,
			TotalMatching = totalMatching,
			AppliedLimit = limit,
		};

		if (totalMatching == 0)
		{
			dto.Message = string.Format(CultureInfo.InvariantCulture,
				"no connection facts recorded for {0}", ip);
			return dto;
		}

		List<RdpConnectionFact> rows = await q
			.OrderByDescending(r => r.LastSeenUtc)
			.ThenByDescending(r => r.Id)
			.Take(limit)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		// Aggregate counters span the entire IP, not just the bounded page — operators want totals.
		var aggregate = await db.RdpConnectionFacts.AsNoTracking()
			.Where(r => r.Ip == ip)
			.GroupBy(r => r.Ip)
			.Select(g => new
			{
				FirstSeen = g.Min(r => r.FirstSeenUtc),
				LastSeen = g.Max(r => r.LastSeenUtc),
				Failed = g.Sum(r => (long)r.FailedLogons),
				Successful = g.Sum(r => (long)r.SuccessfulLogons),
				AnyActive = g.Any(r => r.IsActive),
			})
			.FirstOrDefaultAsync(ct).ConfigureAwait(false);

		if (aggregate is not null)
		{
			dto.FirstSeenUtc = aggregate.FirstSeen;
			dto.LastSeenUtc = aggregate.LastSeen;
			dto.FailedLogons = aggregate.Failed;
			dto.SuccessfulLogons = aggregate.Successful;
			dto.HasActiveFact = aggregate.AnyActive;
		}

		foreach (RdpConnectionFact row in rows)
		{
			dto.Facts.Add(ProjectFact(row));
		}

		dto.Message = string.Format(CultureInfo.InvariantCulture,
			"connection facts for {0}: matching={1} returned={2}",
			ip, totalMatching, rows.Count);
		return dto;
	}

	private static ConnectionFactDto ProjectFact(RdpConnectionFact row) => new()
	{
		Id = row.Id,
		Ip = row.Ip,
		UserName = row.UserName,
		Domain = row.Domain,
		WtsSessionId = row.WtsSessionId,
		LogonId = row.LogonId,
		FirstSeenUtc = row.FirstSeenUtc,
		LastSeenUtc = row.LastSeenUtc,
		ConnectedUtc = row.ConnectedUtc,
		AuthenticatedUtc = row.AuthenticatedUtc,
		DisconnectedUtc = row.DisconnectedUtc,
		ReconnectedUtc = row.ReconnectedUtc,
		LoggedOffUtc = row.LoggedOffUtc,
		FailedLogons = row.FailedLogons,
		SuccessfulLogons = row.SuccessfulLogons,
		ObservedEventIds = row.ObservedEventIds,
		UserNamesAttempted = row.UserNamesAttempted,
		IsActive = row.IsActive,
	};

	private static ConnectionFactsRequest ParseConnectionFactsRequest(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			return new ConnectionFactsRequest();
		}

		try
		{
			ConnectionFactsRequest? parsed = JsonSerializer.Deserialize<ConnectionFactsRequest>(payload, JsonOptions.Default);
			return parsed ?? new ConnectionFactsRequest();
		}
		catch (JsonException ex)
		{
			throw new IpcException("ListConnectionFacts payload is not valid JSON: " + ex.Message);
		}
	}

	private static ConnectionFactsForIpRequest ParseConnectionFactsForIpRequest(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("GetConnectionFactsForIp requires a JSON payload with an Ip field.");
		}

		ConnectionFactsForIpRequest? parsed;
		try
		{
			parsed = JsonSerializer.Deserialize<ConnectionFactsForIpRequest>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException("GetConnectionFactsForIp payload is not valid JSON: " + ex.Message);
		}

		if (parsed is null || string.IsNullOrWhiteSpace(parsed.Ip))
		{
			throw new IpcException("GetConnectionFactsForIp requires an Ip field.");
		}

		return parsed;
	}

	// ----------------------------------------------------------------------------------------------

	private static string NormalizeAndValidateLogin(string login)
	{
		if (string.IsNullOrWhiteSpace(login))
		{
			throw new IpcException("Login must not be empty.");
		}

		string trimmed = login.Trim();
		if (trimmed.Length > 256)
		{
			throw new IpcException("Login is too long (max 256 characters).");
		}

		foreach (char c in trimmed)
		{
			if (char.IsControl(c))
			{
				throw new IpcException("Login contains control characters.");
			}
		}

		return trimmed.ToLowerInvariant();
	}

	// ----------------------------------------------------------------------------------------------
	// Stage Diag: GetDiagnostics
	// ----------------------------------------------------------------------------------------------

	/// <summary>Build the LLM-friendly diagnostics snapshot exposed via IpcCommand.GetDiagnostics.
	/// All DB lookups go through Microsoft.Data.Sqlite via EF Core — no external sqlite3.exe.</summary>
	private async Task<DiagnosticsSnapshotDto> GetDiagnosticsAsync(CancellationToken ct)
	{
		DiagnosticsSnapshotDto dto = new()
		{
			GeneratedUtc = DateTime.UtcNow,
			ServiceVersion = ResolveRuntimeVersion(),
			ChannelStatus = _metrics.SnapshotChannels(),
			SecurityWatcherEnabled = _metrics.SecurityWatcherEnabled,
			SecurityEventsRead = _metrics.SecurityEventsRead,
			SecurityEventsNormalized = _metrics.SecurityEventsNormalized,
			SecurityEventsRejected = _metrics.SecurityEventsRejected,
			LastSecurityChannelError = _metrics.LastSecurityChannelError,
			LastSecurityEventUtc = _metrics.LastSecurityEventUtc,
			SecurityBackfillLastRunUtc = _metrics.SecurityBackfillLastRunUtc,
			SecurityBackfillRecordsRead = _metrics.SecurityBackfillRecordsRead,
			SecurityBackfillRecordsForwarded = _metrics.SecurityBackfillRecordsForwarded,
			SecurityBackfillRecordsDeduped = _metrics.SecurityBackfillRecordsDeduped,
			Security4624Count = _metrics.Security4624Count,
			Security4625Count = _metrics.Security4625Count,
			Security4648Count = _metrics.Security4648Count,
			AuthAttemptFactCreated = _metrics.AuthAttemptFactCreated,
			AuthAttemptFactFailed = _metrics.AuthAttemptFactFailed,
			AuthAttemptFactSucceeded = _metrics.AuthAttemptFactSucceeded,
			LastAuthAttemptFactCreatedUtc = _metrics.LastAuthAttemptFactCreatedUtc,
		};

		// Effective channels/event IDs come from the live options snapshot — the post-configure
		// repair has already run by the time options are materialised here.
		RdpAuditOptions opts = _options.CurrentValue;
		dto.EnabledChannels.AddRange(opts.Monitoring.EnabledChannels);
		dto.EnabledEventIds.AddRange(opts.Monitoring.EnabledEventIds);
		dto.DatabasePath = opts.Storage.ResolveDatabasePath();

		// Service install path — best-effort runtime discovery via AppContext.BaseDirectory
		// (RdpAudit.Service.exe lives next to the worker DLLs). For SCM-authoritative ImagePath
		// resolution use ServiceInstallationInfo on the Configurator side.
		try
		{
			dto.InstallPath = AppContext.BaseDirectory;
		}
		catch (Exception ex)
		{
			dto.RecentPipelineErrors.Add("InstallPath probe failed: " + ex.Message);
		}

		if (_configRepair?.LastReport is { } report)
		{
			dto.MonitoringConfigRepairChanged = report.Changed;
			dto.MonitoringConfigRepairAddedChannels.AddRange(report.AddedChannels);
			dto.MonitoringConfigRepairAddedEventIds.AddRange(report.AddedEventIds);
			dto.MonitoringConfigRepairReason = report.Reason;
			dto.MonitoringConfigRepairUtc = _configRepair.LastReportUtc;
			dto.MonitoringConfigRepairChangedRunCount = _configRepair.ChangedRunCount;
		}

		if (!string.IsNullOrEmpty(_metrics.LastSecurityChannelError))
		{
			dto.RecentPipelineErrors.Add("Security channel: " + _metrics.LastSecurityChannelError);
		}
		if (!string.IsNullOrEmpty(_metrics.LastSecurityRejectReason))
		{
			dto.RecentPipelineErrors.Add(string.Format(
				CultureInfo.InvariantCulture,
				"Last reject ({0}): {1}",
				_metrics.SecurityRejectReasonCount,
				_metrics.LastSecurityRejectReason));
		}
		if (!string.IsNullOrEmpty(_metrics.SecurityCorrelationDiagnostic))
		{
			dto.RecentPipelineErrors.Add("Correlation diagnostic: " + _metrics.SecurityCorrelationDiagnostic);
		}

		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

			dto.RawEventsTotal = await db.RawEvents.AsNoTracking().LongCountAsync(ct).ConfigureAwait(false);
			dto.AuthAttemptFactsTotal = await db.AuthAttemptFacts.AsNoTracking().LongCountAsync(ct).ConfigureAwait(false);

			List<DiagnosticsChannelCount> byChannel = await db.RawEvents.AsNoTracking()
				.GroupBy(e => e.Channel)
				.Select(g => new DiagnosticsChannelCount { Channel = g.Key, Count = g.LongCount() })
				.OrderByDescending(x => x.Count)
				.Take(20)
				.ToListAsync(ct).ConfigureAwait(false);
			dto.RawEventsByChannel.AddRange(byChannel);

			List<DiagnosticsEventIdCount> byEventId = await db.RawEvents.AsNoTracking()
				.GroupBy(e => new { e.Channel, e.EventId })
				.Select(g => new DiagnosticsEventIdCount
				{
					Channel = g.Key.Channel,
					EventId = g.Key.EventId,
					Count = g.LongCount(),
				})
				.OrderByDescending(x => x.Count)
				.Take(30)
				.ToListAsync(ct).ConfigureAwait(false);
			dto.RawEventsByEventId.AddRange(byEventId);

			List<DiagnosticsFactOutcomeCount> byOutcome = await db.AuthAttemptFacts.AsNoTracking()
				.GroupBy(f => new { f.EvidenceEventId, f.Outcome })
				.Select(g => new DiagnosticsFactOutcomeCount
				{
					EvidenceEventId = g.Key.EvidenceEventId,
					Outcome = g.Key.Outcome.ToString(),
					Count = g.LongCount(),
				})
				.OrderByDescending(x => x.Count)
				.Take(30)
				.ToListAsync(ct).ConfigureAwait(false);
			dto.AuthAttemptFactsByOutcome.AddRange(byOutcome);
		}
		catch (Exception ex)
		{
			dto.Status = IpcResultStatus.Unavailable;
			dto.RecentPipelineErrors.Add("DB diagnostics failed: " + ex.GetType().Name + " — " + ex.Message);
		}

		dto.Message = string.Format(
			CultureInfo.InvariantCulture,
			"Snapshot built at {0:O}. RawEvents={1} AuthAttemptFacts={2} SecurityWatcher={3} RepairChanged={4}",
			dto.GeneratedUtc,
			dto.RawEventsTotal,
			dto.AuthAttemptFactsTotal,
			dto.SecurityWatcherEnabled,
			dto.MonitoringConfigRepairChanged);

		return dto;
	}

	// ----------------------------------------------------------------------------------------------
	// Stage Diag2: RunSecurityAuthProbe
	// ----------------------------------------------------------------------------------------------

	/// <summary>Run a one-shot bounded Security-channel auth read inside the service process and
	/// return AccessDenied vs Timeout vs NoEvents vs a parsed first event. This is the canonical
	/// way to disambiguate "Security Armed but zero events" symptoms on a real host.</summary>
	private SecurityAuthProbeDto RunSecurityAuthProbeHandler()
	{
		if (_securityAuthProbe is null)
		{
			return new SecurityAuthProbeDto
			{
				Status = IpcResultStatus.Unavailable,
				Outcome = "Unavailable",
				Message = "Security auth probe service is not registered in this build.",
				GeneratedUtc = DateTime.UtcNow,
			};
		}

		return _securityAuthProbe.Run();
	}
}
