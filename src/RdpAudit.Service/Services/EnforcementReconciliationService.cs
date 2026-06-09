// File:    src/RdpAudit.Service/Services/EnforcementReconciliationService.cs
// Module:  RdpAudit.Service.Services
// Purpose: Orchestrates live enforcement reconciliation. Reads the database-intended blocks
//          (ActiveBlock rows that are Active / Pending / Failed), live-scans the real backend
//          (Windows Firewall via IFirewallRuleScanner), feeds both into the pure
//          EnforcementReconciler, and projects the result into IPC DTOs. Also implements the two
//          mutating operations the operator can trigger from the result: repairing one block by
//          re-installing its missing/mismatched rule through the owning provider, and the emergency
//          "remove all RdpAudit enforcement" cleanup that deletes every RdpAudit-created firewall
//          rule (and marks the corresponding rows Removed) while never touching unrelated admin
//          rules. RdpAudit never reports an IP as actively blocked unless this reconciliation finds
//          a matching backend object — so the Configurator builds the Active Blocks view from the
//          reconciled DTOs, not from raw DB rows.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Service.Firewall;

namespace RdpAudit.Service.Services;

/// <summary>Orchestrates live enforcement reconciliation, repair, and emergency cleanup.</summary>
public sealed class EnforcementReconciliationService
{
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly IEnumerable<IFirewallProvider> _providers;
	private readonly IFirewallRuleScanner _scanner;
	private readonly ILogger<EnforcementReconciliationService> _logger;
	private readonly TimeProvider _time;

	public EnforcementReconciliationService(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		IEnumerable<IFirewallProvider> providers,
		IFirewallRuleScanner scanner,
		ILogger<EnforcementReconciliationService> logger,
		TimeProvider? time = null)
	{
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(providers);
		ArgumentNullException.ThrowIfNull(scanner);
		ArgumentNullException.ThrowIfNull(logger);
		_factory = factory;
		_options = options;
		_providers = providers;
		_scanner = scanner;
		_logger = logger;
		_time = time ?? TimeProvider.System;
	}

	/// <summary>Runs one reconciliation pass and returns the aggregate report DTO.</summary>
	public async Task<ReconciliationReportDto> ReconcileAsync(CancellationToken ct)
	{
		FirewallOptions cfg = _options.CurrentValue.Firewall;
		DateTime nowUtc = _time.GetUtcNow().UtcDateTime;
		string rulePrefix = NetshCommandBuilder.NormalizeRulePrefix(cfg.BlockRuleName);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<ActiveBlock> rows = await db.ActiveBlocks.AsNoTracking()
			.Where(b => b.Status == ActiveBlockStatus.Active
				|| b.Status == ActiveBlockStatus.Pending
				|| b.Status == ActiveBlockStatus.Failed)
			.OrderByDescending(b => b.CreatedUtc)
			.Take(5000)
			.ToListAsync(ct).ConfigureAwait(false);

		ReconciliationReport report = await BuildReportAsync(rows, cfg, rulePrefix, nowUtc, ct).ConfigureAwait(false);
		return MapReport(report);
	}

	/// <summary>Reconciles the supplied rows and returns the full reconciled set as ActiveBlockDto so
	/// the Active Blocks view is built from reconciliation results, not raw DB rows.</summary>
	public async Task<List<ActiveBlockDto>> ReconcileToActiveBlockDtosAsync(CancellationToken ct)
	{
		FirewallOptions cfg = _options.CurrentValue.Firewall;
		DateTime nowUtc = _time.GetUtcNow().UtcDateTime;
		string rulePrefix = NetshCommandBuilder.NormalizeRulePrefix(cfg.BlockRuleName);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<ActiveBlock> rows = await db.ActiveBlocks.AsNoTracking()
			.OrderByDescending(b => b.CreatedUtc)
			.Take(2000)
			.ToListAsync(ct).ConfigureAwait(false);

		// Only Active/Pending/Failed rows are reconciled against the live scan; Removed/AuditOnly
		// rows are surfaced as-is so the operator still sees their history without a false claim.
		List<ActiveBlock> reconcilable = rows.FindAll(b =>
			b.Status is ActiveBlockStatus.Active or ActiveBlockStatus.Pending or ActiveBlockStatus.Failed);

		ReconciliationReport report = await BuildReportAsync(reconcilable, cfg, rulePrefix, nowUtc, ct).ConfigureAwait(false);

		Dictionary<long, ReconciledBlock> byId = new();
		foreach (ReconciledBlock rb in report.Blocks)
		{
			byId[rb.ActiveBlockId] = rb;
		}

		List<ActiveBlockDto> dtos = new(rows.Count);
		foreach (ActiveBlock row in rows)
		{
			ActiveBlockDto dto = new()
			{
				Id = row.Id,
				Ip = row.Ip,
				Provider = row.Provider,
				RuleHandle = row.RuleHandle,
				CreatedUtc = row.CreatedUtc,
				ExpiresUtc = row.ExpiresUtc,
				Reason = row.Reason,
				Status = row.Status,
				LastError = row.LastError,
			};

			if (byId.TryGetValue(row.Id, out ReconciledBlock? rb))
			{
				dto.EnforcementBackend = rb.Backend;
				dto.EnforcementObjectId = rb.EnforcementObjectId;
				dto.EnforcementStatus = rb.Status;
				dto.EnforcementConfidence = rb.Confidence;
				dto.LastVerifiedUtc = report.GeneratedUtc;
				dto.RecommendedAction = rb.RecommendedAction;
			}
			else
			{
				// Not reconciled (Removed / AuditOnly): report unknown enforcement, no false claim.
				dto.EnforcementBackend = ResolveBackend(cfg, row.Provider);
				dto.EnforcementStatus = EnforcementStatus.EffectiveUnknown;
				dto.EnforcementConfidence = EnforcementConfidence.Unknown;
				dto.RecommendedAction = "No reconciliation performed for this row state.";
			}

			dtos.Add(dto);
		}

		return dtos;
	}

	/// <summary>Repairs one ActiveBlock row by id: re-installs the missing/mismatched rule through the
	/// owning provider, then re-reconciles and returns the post-repair reconciled row (or a Failed
	/// row when the provider could not re-install it).</summary>
	public async Task<ReconciledBlockDto> RepairAsync(long activeBlockId, CancellationToken ct)
	{
		if (activeBlockId <= 0)
		{
			throw new ArgumentOutOfRangeException(nameof(activeBlockId), "ActiveBlock id must be positive.");
		}

		FirewallOptions cfg = _options.CurrentValue.Firewall;
		string rulePrefix = NetshCommandBuilder.NormalizeRulePrefix(cfg.BlockRuleName);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		ActiveBlock? row = await db.ActiveBlocks.FirstOrDefaultAsync(b => b.Id == activeBlockId, ct).ConfigureAwait(false);
		if (row is null)
		{
			return new ReconciledBlockDto
			{
				ActiveBlockId = activeBlockId,
				Status = EnforcementStatus.Failed,
				Confidence = EnforcementConfidence.Failed,
				Detail = "ActiveBlock row not found.",
				RecommendedAction = "Refresh the Active Blocks list; the row may have been removed.",
			};
		}

		IFirewallProvider? provider = ResolveProvider(cfg, row.Provider);
		string? repairError = null;
		if (provider is null)
		{
			repairError = "No firewall provider is registered for this block's backend.";
		}
		else
		{
			FirewallBlockRequest request = new(row.Ip, cfg.BlockRuleName) { Reason = row.Reason };
			FirewallActionResult action = await provider.BlockAsync(request, ct).ConfigureAwait(false);
			if (action.Status == FirewallActionStatus.Success)
			{
				row.Status = ActiveBlockStatus.Active;
				row.RuleHandle = action.RuleId ?? row.RuleHandle;
				row.LastError = null;
			}
			else
			{
				row.Status = ActiveBlockStatus.Failed;
				row.LastError = action.Message ?? action.Status.ToString();
				repairError = action.Message ?? ("Provider returned " + action.Status + ".");
			}

			await db.SaveChangesAsync(ct).ConfigureAwait(false);
		}

		// Re-reconcile just this row so the caller sees verified vs still-missing.
		DateTime nowUtc = _time.GetUtcNow().UtcDateTime;
		ReconciliationReport report = await BuildReportAsync(new List<ActiveBlock> { row }, cfg, rulePrefix, nowUtc, ct)
			.ConfigureAwait(false);

		ReconciledBlock reconciled = report.Blocks.Count > 0
			? report.Blocks[0]
			: new ReconciledBlock(row.Id, row.Ip, row.Provider, ResolveBackend(cfg, row.Provider),
				EnforcementStatus.Failed, EnforcementConfidence.Failed, null, row.ExpiresUtc,
				repairError ?? "Repair did not produce a reconciled row.", "Inspect service logs.");

		ReconciledBlockDto dto = MapBlock(reconciled);
		if (repairError is not null && dto.Detail is null)
		{
			dto.Detail = repairError;
		}
		return dto;
	}

	/// <summary>
	/// Repairs enforcement for one enabled BlockList row: ensures a matching ActiveBlock exists for
	/// the row's IP (creating a Pending row routed to the configured provider when none is found),
	/// then delegates to <see cref="RepairAsync"/> which (re-)installs the backend rule and proves
	/// enforcement by re-reading the firewall. Returns the post-repair reconciled row so the caller
	/// sees verified vs still-missing — never a silent success.
	/// </summary>
	public async Task<ReconciledBlockDto> RepairBlocklistAsync(long blocklistId, CancellationToken ct)
	{
		if (blocklistId <= 0)
		{
			throw new ArgumentOutOfRangeException(nameof(blocklistId), "BlockList id must be positive.");
		}

		FirewallOptions cfg = _options.CurrentValue.Firewall;

		long activeBlockId;
		await using (AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false))
		{
			BlocklistEntry? entry = await db.BlocklistEntries
				.FirstOrDefaultAsync(b => b.Id == blocklistId, ct).ConfigureAwait(false);
			if (entry is null)
			{
				return new ReconciledBlockDto
				{
					ActiveBlockId = 0,
					Status = EnforcementStatus.Failed,
					Confidence = EnforcementConfidence.Failed,
					Detail = "BlockList row not found.",
					RecommendedAction = "Refresh the BlockList; the row may have been removed.",
				};
			}

			if (!entry.IsEnabled)
			{
				return new ReconciledBlockDto
				{
					ActiveBlockId = 0,
					Ip = entry.Ip ?? string.Empty,
					Status = EnforcementStatus.Failed,
					Confidence = EnforcementConfidence.Failed,
					Detail = "BlockList row is disabled; enforcement is not expected for disabled rows.",
					RecommendedAction = "Re-enable the row before repairing its enforcement.",
				};
			}

			if (string.IsNullOrWhiteSpace(entry.Ip))
			{
				return new ReconciledBlockDto
				{
					ActiveBlockId = 0,
					Status = EnforcementStatus.Failed,
					Confidence = EnforcementConfidence.Failed,
					Detail = "BlockList row has no IP (login-only rule); firewall enforcement does not apply.",
					RecommendedAction = "Login-only rules are enforced by the auth pipeline, not the firewall.",
				};
			}

			activeBlockId = await EnsureActiveBlockAsync(db, entry, cfg, ct).ConfigureAwait(false);
		}

		return await RepairAsync(activeBlockId, ct).ConfigureAwait(false);
	}

	/// <summary>
	/// Repairs enforcement for every enabled BlockList IP row in one pass and returns an aggregate
	/// report (attempted = Blocks.Count, VerifiedCount, UnenforcedCount). Never claims success when
	/// zero rules were installed: the per-row reconciled results carry the exact outcome.
	/// </summary>
	public async Task<ReconciliationReportDto> RepairAllEnabledBlocklistAsync(CancellationToken ct)
	{
		FirewallOptions cfg = _options.CurrentValue.Firewall;

		List<long> ids;
		await using (AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false))
		{
			ids = await db.BlocklistEntries.AsNoTracking()
				.Where(b => b.IsEnabled && b.Ip != null && b.Ip != string.Empty)
				.OrderByDescending(b => b.AddedUtc)
				.Select(b => b.Id)
				.Take(5000)
				.ToListAsync(ct).ConfigureAwait(false);
		}

		ReconciliationReportDto report = new()
		{
			Status = IpcResultStatus.Success,
			GeneratedUtc = _time.GetUtcNow().UtcDateTime,
		};

		foreach (long id in ids)
		{
			ct.ThrowIfCancellationRequested();
			ReconciledBlockDto rb = await RepairBlocklistAsync(id, ct).ConfigureAwait(false);
			report.Blocks.Add(rb);
			if (rb.Status == EnforcementStatus.Active)
			{
				report.VerifiedCount++;
			}
			else
			{
				report.UnenforcedCount++;
			}
		}

		report.Message = report.Blocks.Count == 0
			? "No enabled BlockList IP rows to repair."
			: string.Format(CultureInfo.InvariantCulture,
				"Repaired {0} enabled BlockList row(s): {1} verified enforced, {2} still unenforced.",
				report.Blocks.Count, report.VerifiedCount, report.UnenforcedCount);
		return report;
	}

	/// <summary>
	/// Finds an existing reconcilable ActiveBlock for the entry's IP, or creates a fresh Pending row
	/// routed to the configured provider. Returns the ActiveBlock id to repair. The actual rule
	/// install + verification is performed by <see cref="RepairAsync"/>.
	/// </summary>
	private async Task<long> EnsureActiveBlockAsync(
		AuditDbContext db, BlocklistEntry entry, FirewallOptions cfg, CancellationToken ct)
	{
		string ip = entry.Ip!;
		ActiveBlock? existing = await db.ActiveBlocks
			.Where(b => b.Ip == ip
				&& (b.Status == ActiveBlockStatus.Active
					|| b.Status == ActiveBlockStatus.Pending
					|| b.Status == ActiveBlockStatus.Failed))
			.OrderByDescending(b => b.CreatedUtc)
			.FirstOrDefaultAsync(ct).ConfigureAwait(false);

		if (existing is not null)
		{
			return existing.Id;
		}

		// Route to the configured provider; Both fans out to Windows for the local reconciler (the
		// MikroTik leg is owned by its own provider and reconciled separately).
		FirewallProviderKind target = cfg.Provider == FirewallProviderKind.Both
			? FirewallProviderKind.Windows
			: cfg.Provider;
		if (target == FirewallProviderKind.None)
		{
			target = FirewallProviderKind.Windows;
		}

		ActiveBlock created = new()
		{
			Ip = ip,
			Provider = target,
			CreatedUtc = _time.GetUtcNow().UtcDateTime,
			ExpiresUtc = entry.ExpiresUtc,
			Reason = string.IsNullOrWhiteSpace(entry.Reason) ? "BlockList repair" : entry.Reason,
			Status = ActiveBlockStatus.Pending,
		};
		db.ActiveBlocks.Add(created);
		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		_logger.LogInformation(
			"BlockList repair created Pending ActiveBlock {Id} for {Ip} via {Provider}",
			created.Id, ip, target);
		return created.Id;
	}

	/// <summary>Emergency cleanup: removes every RdpAudit-created firewall rule discovered live and
	/// marks the corresponding ActiveBlock rows Removed. Never deletes unrelated admin rules — only
	/// rules whose name carries the RdpAudit prefix are touched.</summary>
	public async Task<EnforcementCleanupResultDto> RemoveAllEnforcementAsync(CancellationToken ct)
	{
		FirewallOptions cfg = _options.CurrentValue.Firewall;
		string rulePrefix = NetshCommandBuilder.NormalizeRulePrefix(cfg.BlockRuleName);

		EnforcementCleanupResultDto result = new();

		IFirewallProvider? windows = FindProvider(FirewallProviderRouting.WindowsProviderId);
		FirewallScanResult scan = await _scanner.ScanRdpAuditBlockRulesAsync(rulePrefix, ct).ConfigureAwait(false);

		if (!scan.Scannable)
		{
			result.Message = scan.Note ?? "Firewall could not be scanned; no enforcement objects removed.";
		}
		else if (windows is null)
		{
			result.Message = "Windows firewall provider is not registered; cannot remove rules.";
		}
		else
		{
			HashSet<string> removedIps = new(StringComparer.OrdinalIgnoreCase);
			foreach (DiscoveredBlockRule rule in scan.Rules)
			{
				string ip = rule.RemoteIps.Count > 0 ? rule.RemoteIps[0] : string.Empty;
				if (ip.Length == 0)
				{
					continue;
				}

				FirewallActionResult action;
				try
				{
					action = await windows.UnblockAsync(ip, cfg.BlockRuleName, ct).ConfigureAwait(false);
				}
				catch (OperationCanceledException)
				{
					throw;
				}
				catch (Exception ex)
				{
					result.Failures++;
					result.Actions.Add(string.Format(CultureInfo.InvariantCulture,
						"Failed to remove rule {0}: {1}", rule.RuleName, ex.GetType().Name));
					_logger.LogWarning(ex, "Emergency cleanup failed to remove rule {RuleName}", rule.RuleName);
					continue;
				}

				if (action.Status is FirewallActionStatus.Success or FirewallActionStatus.NotFound)
				{
					result.FirewallRulesRemoved++;
					removedIps.Add(ip);
					result.Actions.Add(string.Format(CultureInfo.InvariantCulture,
						"Removed firewall rule {0} ({1}).", rule.RuleName, ip));
				}
				else
				{
					result.Failures++;
					result.Actions.Add(string.Format(CultureInfo.InvariantCulture,
						"Provider returned {0} removing rule {1}.", action.Status, rule.RuleName));
				}
			}

			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
			List<ActiveBlock> activeRows = await db.ActiveBlocks
				.Where(b => b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending)
				.ToListAsync(ct).ConfigureAwait(false);
			foreach (ActiveBlock row in activeRows)
			{
				row.Status = ActiveBlockStatus.Removed;
				row.LastError = "Removed by emergency enforcement cleanup.";
				result.ActiveBlockRowsMarkedRemoved++;
			}

			await db.SaveChangesAsync(ct).ConfigureAwait(false);

			result.Message = string.Format(CultureInfo.InvariantCulture,
				"Removed {0} RdpAudit firewall rule(s); marked {1} ActiveBlock row(s) Removed.",
				result.FirewallRulesRemoved,
				result.ActiveBlockRowsMarkedRemoved);
		}

		result.Status = result.Failures > 0 ? IpcResultStatus.Unavailable : IpcResultStatus.Success;
		_logger.LogInformation(
			"Emergency enforcement cleanup completed: rulesRemoved={Rules} rowsRemoved={Rows} failures={Failures}",
			result.FirewallRulesRemoved,
			result.ActiveBlockRowsMarkedRemoved,
			result.Failures);
		return result;
	}

	/// <summary>Builds the pure reconciliation report from the supplied DB rows by scanning every
	/// backend that owns at least one row.</summary>
	private async Task<ReconciliationReport> BuildReportAsync(
		IReadOnlyList<ActiveBlock> rows,
		FirewallOptions cfg,
		string rulePrefix,
		DateTime nowUtc,
		CancellationToken ct)
	{
		List<DesiredBlock> desired = new(rows.Count);
		HashSet<FirewallProviderKind> providerKinds = new();
		foreach (ActiveBlock row in rows)
		{
			FirewallEnforcementBackend backend = ResolveBackend(cfg, row.Provider);
			desired.Add(new DesiredBlock(
				ActiveBlockId: row.Id,
				Ip: row.Ip,
				Provider: row.Provider,
				Backend: backend,
				RuleHandle: row.RuleHandle,
				CreatedUtc: row.CreatedUtc,
				ExpiresUtc: row.ExpiresUtc,
				Reason: row.Reason,
				RecordedFailed: row.Status == ActiveBlockStatus.Failed));
			providerKinds.Add(row.Provider);
		}

		// Scan the Windows backend once if any desired block (or orphan detection) needs it. Other
		// backends (route / IPsec) are not live-scannable here and are reported as such.
		List<BackendScanResult> scans = new();
		bool needWindows = providerKinds.Count == 0 || providerKinds.Contains(FirewallProviderKind.Windows);
		if (needWindows)
		{
			scans.Add(await ScanWindowsAsync(cfg, rulePrefix, ct).ConfigureAwait(false));
		}

		foreach (FirewallProviderKind kind in providerKinds)
		{
			if (kind == FirewallProviderKind.Windows)
			{
				continue;
			}

			scans.Add(BuildUnscannableScan(kind, cfg));
		}

		return EnforcementReconciler.Reconcile(desired, scans, rulePrefix, nowUtc);
	}

	private async Task<BackendScanResult> ScanWindowsAsync(FirewallOptions cfg, string rulePrefix, CancellationToken ct)
	{
		FirewallEnforcementBackend backend = ResolveBackend(cfg, FirewallProviderKind.Windows);
		FirewallScanResult scan = await _scanner.ScanRdpAuditBlockRulesAsync(rulePrefix, ct).ConfigureAwait(false);
		bool thirdPartyMayBypass = await DetectThirdPartyBypassAsync(ct).ConfigureAwait(false);

		string? thirdPartyNote = thirdPartyMayBypass
			? "A third-party provider may control effective enforcement."
			: null;
		string? note = (scan.Note, thirdPartyNote) switch
		{
			(null, null) => null,
			(string s, null) => s,
			(null, string t) => t,
			(string s, string t) => s + " " + t,
		};

		return new BackendScanResult(
			Provider: FirewallProviderKind.Windows,
			Backend: backend,
			ProviderAvailable: scan.Scannable,
			Scannable: scan.Scannable,
			DiscoveredRules: scan.Rules,
			ThirdPartyMayBypass: thirdPartyMayBypass,
			Note: note)
		{
			ScannerBackend = scan.Backend.ToString(),
		};
	}

	private BackendScanResult BuildUnscannableScan(FirewallProviderKind kind, FirewallOptions cfg)
	{
		FirewallEnforcementBackend backend = ResolveBackend(cfg, kind);
		string providerId = FirewallProviderRouting.ResolveProviderId(kind, backend);
		IFirewallProvider? provider = FindProvider(providerId);
		bool available = provider is not null;
		return new BackendScanResult(
			Provider: kind,
			Backend: backend,
			ProviderAvailable: available,
			Scannable: false,
			DiscoveredRules: Array.Empty<DiscoveredBlockRule>(),
			ThirdPartyMayBypass: false,
			Note: kind == FirewallProviderKind.MikroTik
				? "External MikroTik backend is not live-scanned by the local reconciler."
				: "This backend (" + backend + ") cannot be live-scanned for enforcement here.");
	}

	/// <summary>Best-effort detection that a third-party firewall (e.g. Kaspersky) is present and may
	/// control or bypass effective enforcement. Non-Windows hosts always return false.</summary>
	private async Task<bool> DetectThirdPartyBypassAsync(CancellationToken ct)
	{
		if (!OperatingSystem.IsWindows())
		{
			return false;
		}

		IFirewallProvider? windows = FindProvider(FirewallProviderRouting.WindowsProviderId);
		if (windows is null)
		{
			return false;
		}

		try
		{
			FirewallStatusReport report = await windows.GetStatusAsync(ct).ConfigureAwait(false);
			// A disabled Windows firewall while RdpAudit believes it installed rules strongly implies
			// a third-party stack is managing enforcement; surface the may-bypass caveat.
			return report.Status == FirewallProviderStatus.Disabled;
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "Third-party bypass detection failed; assuming no third-party interference");
			return false;
		}
	}

	private IFirewallProvider? ResolveProvider(FirewallOptions cfg, FirewallProviderKind kind)
	{
		FirewallEnforcementBackend backend = ResolveBackend(cfg, kind);
		string providerId = FirewallProviderRouting.ResolveProviderId(kind, backend);
		return FindProvider(providerId);
	}

	private IFirewallProvider? FindProvider(string providerId)
	{
		if (string.IsNullOrEmpty(providerId))
		{
			return null;
		}

		foreach (IFirewallProvider provider in _providers)
		{
			if (string.Equals(provider.ProviderId, providerId, StringComparison.OrdinalIgnoreCase))
			{
				return provider;
			}
		}

		return null;
	}

	/// <summary>Resolves the enforcement backend for a block: Windows-host blocks honour the
	/// configured local backend; external providers (MikroTik) always use WindowsFirewall as a
	/// neutral placeholder since the local reconciler does not own their objects.</summary>
	private static FirewallEnforcementBackend ResolveBackend(FirewallOptions cfg, FirewallProviderKind kind)
		=> kind == FirewallProviderKind.Windows ? cfg.EnforcementBackend : FirewallEnforcementBackend.WindowsFirewall;

	private static ReconciliationReportDto MapReport(ReconciliationReport report)
	{
		ReconciliationReportDto dto = new()
		{
			Status = IpcResultStatus.Success,
			GeneratedUtc = report.GeneratedUtc,
			VerifiedCount = report.VerifiedCount,
			UnenforcedCount = report.UnenforcedCount,
			ScannerBackend = report.ScannerBackend,
			ScannerNote = report.ScannerNote,
		};

		foreach (ReconciledBlock b in report.Blocks)
		{
			dto.Blocks.Add(MapBlock(b));
		}

		foreach (ReconciledBlock o in report.Orphans)
		{
			dto.Orphans.Add(MapBlock(o));
		}

		dto.Message = string.Format(CultureInfo.InvariantCulture,
			"Reconciled {0} block(s): {1} verified, {2} unenforced, {3} orphan(s).",
			report.Blocks.Count,
			report.VerifiedCount,
			report.UnenforcedCount,
			report.Orphans.Count);
		return dto;
	}

	private static ReconciledBlockDto MapBlock(ReconciledBlock b) => new()
	{
		ActiveBlockId = b.ActiveBlockId,
		Ip = b.Ip,
		Provider = b.Provider,
		Backend = b.Backend,
		Status = b.Status,
		Confidence = b.Confidence,
		EnforcementObjectId = b.EnforcementObjectId,
		ExpiresUtc = b.ExpiresUtc,
		Detail = b.Detail,
		RecommendedAction = b.RecommendedAction,
	};
}
