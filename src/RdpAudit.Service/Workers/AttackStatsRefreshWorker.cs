// File:    src/RdpAudit.Service/Workers/AttackStatsRefreshWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Stage 6 background worker that materialises per-IP AttackStat rows from RawEvents +
//          ActiveBlocks on a 60-second cadence (and once at startup). Honours CancellationToken,
//          guards against concurrent re-entry, and bounds each pass by a fixed look-back window so
//          full table scans never grow without bound. The current implementation is correctness-
//          first; a future optimisation (incremental high-water marker per IP) is captured in
//          docs/46-attack-statistics.md.
// Extends: Microsoft.Extensions.Hosting.BackgroundService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Workers;

/// <summary>Stage 6 background worker that materialises per-IP <see cref="AttackStat"/> rows.</summary>
public sealed class AttackStatsRefreshWorker : BackgroundService
{
	/// <summary>Refresh cadence. Operator-facing dashboards happily tolerate 60-second lag.</summary>
	internal static readonly TimeSpan Period = TimeSpan.FromSeconds(60);

	/// <summary>Bounded look-back window. Older rows decay via <c>MaintenanceWorker</c>.</summary>
	internal static readonly TimeSpan LookBackWindow = TimeSpan.FromDays(30);

	/// <summary>Upper bound on rows fetched from <c>RawEvents</c> per pass.</summary>
	internal const int MaxRawEventsPerPass = 50_000;

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly ILogger<AttackStatsRefreshWorker> _logger;
	private readonly SemaphoreSlim _gate = new(1, 1);

	public AttackStatsRefreshWorker(
		IDbContextFactory<AuditDbContext> factory,
		ILogger<AttackStatsRefreshWorker> logger)
	{
		_factory = factory;
		_logger = logger;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(AttackStatsRefreshWorker));
		try
		{
			// Startup refresh: kick the first pass without waiting for the cadence.
			await SafeRefreshAsync(stoppingToken).ConfigureAwait(false);

			while (!stoppingToken.IsCancellationRequested)
			{
				try
				{
					await Task.Delay(Period, stoppingToken).ConfigureAwait(false);
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					break;
				}

				await SafeRefreshAsync(stoppingToken).ConfigureAwait(false);
			}
		}
		finally
		{
			_logger.LogInformation("{Worker} stopped", nameof(AttackStatsRefreshWorker));
		}
	}

	/// <summary>Public for tests: runs a single deterministic refresh pass.</summary>
	public async Task<int> RefreshOnceAsync(CancellationToken ct)
	{
		if (!await _gate.WaitAsync(0, ct).ConfigureAwait(false))
		{
			_logger.LogDebug("{Worker} refresh skipped: previous pass still running", nameof(AttackStatsRefreshWorker));
			return 0;
		}

		try
		{
			return await RunRefreshAsync(ct).ConfigureAwait(false);
		}
		finally
		{
			_gate.Release();
		}
	}

	private async Task SafeRefreshAsync(CancellationToken ct)
	{
		try
		{
			int rows = await RefreshOnceAsync(ct).ConfigureAwait(false);
			_logger.LogDebug("{Worker} pass complete, rows materialised: {Rows}", nameof(AttackStatsRefreshWorker), rows);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			// Service shutdown — quiet return.
		}
		catch (Exception ex)
		{
			_logger.LogError(ex, "{Worker} pass failed", nameof(AttackStatsRefreshWorker));
		}
	}

	private async Task<int> RunRefreshAsync(CancellationToken ct)
	{
		DateTime nowUtc = DateTime.UtcNow;
		DateTime sinceUtc = nowUtc - LookBackWindow;

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		// v3 invariant (Detect_Attack_Strategy_v3.md §8.1, §17.14): Total / Successful / Failed
		// counters MUST derive exclusively from AuthAttemptFact — the atomic source of truth.
		// We pull a bounded slice from AuthAttemptFacts, then synthesize AttackEventSample rows
		// keyed by the fact's authoritative SourceIp (or the unresolved-IP sentinel when NLA
		// stripped the address and no transport-IP correlation could supply one).
		List<AuthAttemptFact> facts = await db.AuthAttemptFacts.AsNoTracking()
			.Where(f => f.TimeUtc >= sinceUtc)
			.OrderBy(f => f.Id)
			.Take(MaxRawEventsPerPass)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		HashSet<string> blockedIps = (await db.ActiveBlocks.AsNoTracking()
			.Where(b => b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending)
			.Select(b => b.Ip)
			.ToListAsync(ct)
			.ConfigureAwait(false))
			.ToHashSet(StringComparer.OrdinalIgnoreCase);

		int unresolvedCount = 0;
		List<AttackEventSample> samples = new(facts.Count);
		foreach (AuthAttemptFact fact in facts)
		{
			string? sourceIp;
			if (!string.IsNullOrEmpty(fact.SourceIp))
			{
				sourceIp = fact.SourceIp;
			}
			else if (fact.Outcome == AuthAttemptOutcome.Failed || fact.Outcome == AuthAttemptOutcome.Denied)
			{
				// Preserve the failure under the unresolved-IP sentinel so Attack Statistics
				// reflects brute-force pressure even when Windows stripped the IpAddress field.
				sourceIp = AttackStatsAggregator.SentinelUnresolvedIp;
				unresolvedCount++;
			}
			else
			{
				continue;
			}

			samples.Add(new AttackEventSample(
				sourceIp,
				MapFactOutcomeToSyntheticEventId(fact.Outcome, fact.EvidenceEventId),
				fact.TimeUtc,
				fact.TargetUser,
				fact.LogonType,
				"Security"));
		}

		if (unresolvedCount > 0)
		{
			_logger.LogInformation(
				"{Worker} included {Count} unresolved-IP AuthAttemptFacts under sentinel {Sentinel}",
				nameof(AttackStatsRefreshWorker),
				unresolvedCount,
				AttackStatsAggregator.SentinelUnresolvedIp);
		}

		IReadOnlyList<AttackStat> projected = AttackStatsAggregator.Aggregate(samples, blockedIps, nowUtc);

		// Upsert into AttackStats. AttackStat.Ip is the primary key (Stage 2 schema).
		Dictionary<string, AttackStat> existing = await db.AttackStats
			.ToDictionaryAsync(s => s.Ip, ct)
			.ConfigureAwait(false);

		HashSet<string> projectedIps = new(StringComparer.OrdinalIgnoreCase);
		int upserts = 0;
		foreach (AttackStat row in projected)
		{
			projectedIps.Add(row.Ip);
			if (existing.TryGetValue(row.Ip, out AttackStat? current))
			{
				current.TotalAttempts = row.TotalAttempts;
				current.Successful = row.Successful;
				current.Failed = row.Failed;
				current.FirstSeenUtc = row.FirstSeenUtc;
				current.LastSeenUtc = row.LastSeenUtc;
				current.DurationSeconds = row.DurationSeconds;
				current.Top10AttemptedLogins = row.Top10AttemptedLogins;
				current.LastLoginType = row.LastLoginType;
				current.ThreatScore = row.ThreatScore;
				current.IsBlocked = row.IsBlocked;
				current.LastUpdatedUtc = row.LastUpdatedUtc;
			}
			else
			{
				db.AttackStats.Add(row);
			}
			upserts++;
		}

		// Rows whose IPs are no longer in the look-back window get a refreshed IsBlocked flag (the
		// firewall state may have changed) but are otherwise left alone so the dashboard keeps
		// historical context. Stale rows are removed by MaintenanceWorker on its retention pass.
		foreach (KeyValuePair<string, AttackStat> kvp in existing)
		{
			if (projectedIps.Contains(kvp.Key))
			{
				continue;
			}

			bool nowBlocked = blockedIps.Contains(kvp.Key);
			if (kvp.Value.IsBlocked != nowBlocked)
			{
				kvp.Value.IsBlocked = nowBlocked;
				kvp.Value.LastUpdatedUtc = nowUtc;
			}
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return upserts;
	}

	/// <summary>
	/// Bridge between the AuthAttemptFact-derived facts and the existing
	/// <see cref="AttackStatsAggregator"/> contract, which classifies samples by raw Windows event id.
	/// We keep using the same aggregator (one source of truth for scoring) by mapping each fact
	/// outcome to the canonical Security event id (4624 success / 4625 failure). The original
	/// EvidenceEventId is preserved for diagnostic logs but never drives counter classification —
	/// per v3 §6.3 rule 3, only AuthAttemptFact's Outcome field is authoritative.
	/// </summary>
	internal static int MapFactOutcomeToSyntheticEventId(AuthAttemptOutcome outcome, int evidenceEventId)
	{
		_ = evidenceEventId;
		return outcome switch
		{
			AuthAttemptOutcome.Succeeded => AttackStatsAggregator.EventIdLogonSuccess,
			AuthAttemptOutcome.Failed => AttackStatsAggregator.EventIdLogonFailure,
			AuthAttemptOutcome.Denied => AttackStatsAggregator.EventIdLogonFailure,
			_ => 0,
		};
	}

	public override void Dispose()
	{
		_gate.Dispose();
		base.Dispose();
	}
}
