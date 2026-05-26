// File:    src/RdpAudit.Service/Workers/SecurityBackfillWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Bounded, idempotent backfill for the Security authentication event set.
//          The previous implementation issued ONE giant XPath OR-clause covering ~20 event
//          IDs across the whole channel and a 3-minute lookback. On a host whose Security
//          log holds millions of events, the combined query times out and the worker reports
//          QueryFailed for every poll — exactly the symptom captured in the v1.2.0 task brief.
//          This version splits the read into per-EventID queries that mirror the canonical
//          PowerShell triage path: ReverseDirection=true, per-id MaxEvents cap, narrow XPath
//          per id. A timeout / failure on one id does NOT stall the others; the worker
//          records per-id outcomes via ServiceMetrics so the Diagnostic tab can name the
//          exact id that is misbehaving. The first tick after service start runs a wider
//          24h "latest backfill" so a stale bookmark can never keep us in a permanent
//          zero-events state on an upgraded host.
// Extends: Microsoft.Extensions.Hosting.BackgroundService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Service.Services;

namespace RdpAudit.Service.Workers;

/// <summary>Polls the local Security channel for recent auth events on a fixed cadence,
/// pushing any new EventRecordIDs into the same in-memory <see cref="EventChannel"/> the
/// realtime watcher uses. Per-EventID isolation means a single slow id cannot starve the
/// others.</summary>
public sealed class SecurityBackfillWorker : BackgroundService
{
	/// <summary>Full v3 Security backfill set per Detect_Attack_Strategy_v3.md §5.2. Kept as a
	/// public surface so the historical contract tests still pass and an operator who reads the
	/// strategy doc sees one source of truth. The actual query path now splits these ids across
	/// individual XPaths so a per-id failure cannot starve the rest.</summary>
	internal static readonly IReadOnlyList<int> BackfillEventIds = new[]
	{
		// Logon / Logoff
		4624, 4625, 4634, 4647, 4648, 4672,
		// Account / privilege management (post-compromise persistence + lockout)
		4719, 4720, 4724, 4732, 4740,
		// Kerberos + NTLM credential validation (carries Kerberos IP and DC-side fail evidence)
		4768, 4769, 4771, 4776,
		// Reconnect / disconnect (session hijacking detection)
		4778, 4779,
		// RDP authorization-denied
		4825,
		// Tamper indicator: audit log cleared (critical adversary TTP)
		1102,
	};

	/// <summary>Auth-priority IDs read every tick. The remaining BackfillEventIds are still
	/// queried per-tick but always behind these. This ordering means that under sustained
	/// load the authoritative authentication outcome ids never wait behind tampering /
	/// privilege-management ids that fire orders of magnitude less often.</summary>
	internal static readonly IReadOnlyList<int> PriorityAuthIds = SecurityAuthQuery.AuthEventIds;

	/// <summary>Cap on the in-memory dedup ring. Older record ids are dropped FIFO.</summary>
	internal const int SeenRingCapacity = 8192;

	/// <summary>Hard ceiling on rows returned per (EventID, tick) so a backlog cannot starve
	/// the live pipeline. Matches the order-of-magnitude PowerShell -MaxEvents 100 ceiling.</summary>
	internal const int MaxRowsPerEventId = 200;

	/// <summary>Wider rows-per-id ceiling used on the first tick / latest-backfill scenario when
	/// the persisted bookmark is older than ~1h or the database has zero AuthAttemptFacts.</summary>
	internal const int LatestBackfillMaxRowsPerEventId = 500;

	/// <summary>Per-record read budget. Combined with MaxRowsPerEventId this gives a per-id
	/// per-tick read budget of ≤ 200 * 50ms = 10s in the worst case.</summary>
	internal static readonly TimeSpan PerRecordReadTimeout = TimeSpan.FromMilliseconds(50);

	private static readonly TimeSpan DefaultInterval = TimeSpan.FromMinutes(2);
	private static readonly TimeSpan DefaultLookback = TimeSpan.FromMinutes(15);
	private static readonly TimeSpan LatestBackfillLookback = TimeSpan.FromHours(24);
	private static readonly TimeSpan StartupGrace = TimeSpan.FromSeconds(15);

	private readonly EventChannel _channel;
	private readonly ServiceMetrics _metrics;
	private readonly ILogger<SecurityBackfillWorker> _logger;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly BookmarkStore? _bookmarks;
	private readonly IDbContextFactory<AuditDbContext>? _factory;
	private readonly object _ringGate = new();
	private readonly Queue<long> _seenOrder = new();
	private readonly HashSet<long> _seen = new();
	private bool _firstTickDone;

	public SecurityBackfillWorker(
		EventChannel channel,
		ServiceMetrics metrics,
		ILogger<SecurityBackfillWorker> logger,
		IOptionsMonitor<RdpAuditOptions> options)
		: this(channel, metrics, logger, options, bookmarks: null, factory: null)
	{
	}

	public SecurityBackfillWorker(
		EventChannel channel,
		ServiceMetrics metrics,
		ILogger<SecurityBackfillWorker> logger,
		IOptionsMonitor<RdpAuditOptions> options,
		BookmarkStore? bookmarks,
		IDbContextFactory<AuditDbContext>? factory)
	{
		_channel = channel;
		_metrics = metrics;
		_logger = logger;
		_options = options;
		_bookmarks = bookmarks;
		_factory = factory;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(SecurityBackfillWorker));
		if (!OperatingSystem.IsWindows())
		{
			_logger.LogInformation("SecurityBackfillWorker requires Windows; idling on this host");
			try
			{
				await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken).ConfigureAwait(false);
			}
			catch (OperationCanceledException)
			{
			}

			return;
		}

		try
		{
			// Brief startup grace so the live watcher has a moment to arm before we pile a
			// wide-window backfill on top.
			await Task.Delay(StartupGrace, stoppingToken).ConfigureAwait(false);

			// Stage 1.2.0: if the service has never persisted an AuthAttemptFact, an existing
			// bookmark pointing past the most recent Security event would freeze the live
			// watcher AND the periodic backfill at zero forever. Drop the stale Security
			// bookmark before the first wide read so the watcher rebuilds it from the actual
			// tail of the channel.
			bool needLatestBackfill = await DetectLatestBackfillNeededAsync(stoppingToken).ConfigureAwait(false);
			if (needLatestBackfill)
			{
				await TryDropStaleSecurityBookmarkAsync(stoppingToken).ConfigureAwait(false);
			}

			while (!stoppingToken.IsCancellationRequested)
			{
				try
				{
					bool latest = !_firstTickDone && needLatestBackfill;
					await PollOnceAsync(stoppingToken, latest).ConfigureAwait(false);
					_firstTickDone = true;
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					break;
				}
				catch (Exception ex)
				{
					_logger.LogDebug(ex, "Security backfill poll iteration failed; will retry on next interval");
				}

				try
				{
					await Task.Delay(DefaultInterval, stoppingToken).ConfigureAwait(false);
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					break;
				}
			}
		}
		finally
		{
			_logger.LogInformation("{Worker} stopped", nameof(SecurityBackfillWorker));
		}
	}

	[SupportedOSPlatform("windows")]
	internal async Task PollOnceAsync(CancellationToken ct, bool latestBackfill = false)
	{
		DateTime startedUtc = DateTime.UtcNow;
		TimeSpan lookback = latestBackfill ? LatestBackfillLookback : DefaultLookback;
		int maxPerId = latestBackfill ? LatestBackfillMaxRowsPerEventId : MaxRowsPerEventId;
		DateTime sinceUtc = startedUtc - lookback;

		int totalRead = 0;
		int totalForwarded = 0;
		int totalDuplicate = 0;
		string? lastChannelError = null;
		bool hadFatalChannelError = false;

		// Read priority ids first; the rest after. Iterating per-id keeps each individual
		// query tiny — Windows uses an event-id index for these — and isolates timeouts.
		IEnumerable<int> ordered = PriorityAuthIds.Concat(BackfillEventIds.Except(PriorityAuthIds));
		foreach (int id in ordered)
		{
			if (ct.IsCancellationRequested)
			{
				break;
			}

			PerIdResult r = ReadEventsForId(id, sinceUtc, maxPerId, ct);
			totalRead += r.Read;
			totalForwarded += r.Forwarded;
			totalDuplicate += r.Duplicate;
			if (r.Error is not null)
			{
				lastChannelError = "ID " + id + ": " + r.Error;
				_metrics.SetChannelStatus(EventCatalog.ChannelSecurity + "::Backfill::" + id, r.ErrorOutcome ?? "QueryFailed");
				if (r.IsFatalChannelError)
				{
					hadFatalChannelError = true;
				}
			}
			else
			{
				_metrics.SetChannelStatus(
					EventCatalog.ChannelSecurity + "::Backfill::" + id,
					r.Read == 0 ? "Idle" : "Forwarded:" + r.Forwarded);
			}
		}

		if (lastChannelError is not null)
		{
			_metrics.SetLastSecurityChannelError(lastChannelError);
		}

		if (!hadFatalChannelError)
		{
			_metrics.SetChannelStatus(
				EventCatalog.ChannelSecurity + "::Backfill",
				totalRead == 0 ? "Idle" : "Forwarded:" + totalForwarded);
		}

		_metrics.RecordSecurityBackfillRun(startedUtc, totalRead, totalForwarded, totalDuplicate);

		if (totalForwarded > 0 || totalDuplicate > 0 || latestBackfill)
		{
			_logger.LogDebug(
				"Security backfill tick: read={Read} forwarded={Forwarded} duplicate={Duplicate} lookback={Lookback} latest={Latest}",
				totalRead, totalForwarded, totalDuplicate, lookback, latestBackfill);
		}

		await Task.CompletedTask.ConfigureAwait(false);
	}

	[SupportedOSPlatform("windows")]
	private PerIdResult ReadEventsForId(int eventId, DateTime sinceUtc, int maxRows, CancellationToken ct)
	{
		string xpath = SecurityAuthQuery.BuildXPathSingleId(eventId, sinceUtc);
		EventLogQuery query;
		try
		{
			query = new EventLogQuery(EventCatalog.ChannelSecurity, PathType.LogName, xpath)
			{
				ReverseDirection = true,
			};
		}
		catch (Exception ex)
		{
			return new PerIdResult(0, 0, 0, ex.Message, "QueryBuildFailed", false);
		}

		int read = 0;
		int forwarded = 0;
		int duplicate = 0;

		try
		{
			using EventLogReader reader = new(query);
			while (read < maxRows && !ct.IsCancellationRequested)
			{
				using EventRecord? record = reader.ReadEvent(PerRecordReadTimeout);
				if (record is null)
				{
					break;
				}

				read++;
				long recordId = record.RecordId ?? unchecked((long)record.GetHashCode());
				if (!TryMarkSeen(recordId))
				{
					duplicate++;
					continue;
				}

				string xml;
				try
				{
					xml = record.ToXml();
				}
				catch (EventLogException ex)
				{
					_logger.LogDebug(ex, "Backfill could not read Security EventRecord (RecordId={RecordId})", recordId);
					continue;
				}

				if (xml.Length > 65_536)
				{
					xml = xml[..65_536];
				}

				RawEventDto dto = new()
				{
					EventId = record.Id,
					Channel = record.LogName ?? EventCatalog.ChannelSecurity,
					TimeUtc = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow,
					XmlPayload = xml,
				};

				if (_channel.Channel.Writer.TryWrite(dto))
				{
					forwarded++;
					_metrics.IncrementCaptured();
				}
				else
				{
					_metrics.IncrementDropped();
					if (_options.CurrentValue.Diagnostics.LogChannelDrops)
					{
						_logger.LogWarning("Security backfill: channel full — dropped EventID {EventId}", dto.EventId);
					}
				}
			}
		}
		catch (UnauthorizedAccessException ex)
		{
			_metrics.SetLastSecurityChannelError("AccessDenied: " + ex.Message);
			return new PerIdResult(read, forwarded, duplicate, ex.Message, "AccessDenied", true);
		}
		catch (EventLogNotFoundException ex)
		{
			_metrics.SetLastSecurityChannelError("ChannelNotFound: " + ex.Message);
			return new PerIdResult(read, forwarded, duplicate, ex.Message, "ChannelNotFound", true);
		}
		catch (EventLogException ex)
		{
			return new PerIdResult(read, forwarded, duplicate, ex.Message, "QueryFailed", false);
		}

		return new PerIdResult(read, forwarded, duplicate, null, null, false);
	}

	internal static string BuildXPath(DateTime sinceUtc)
	{
		// Preserved for compatibility with the v3 contract tests. The actual poll path now
		// splits per-EventID — see ReadEventsForId.
		return SecurityAuthQuery.BuildXPath(BackfillEventIds, sinceUtc);
	}

	internal bool TryMarkSeen(long recordId)
	{
		lock (_ringGate)
		{
			if (!_seen.Add(recordId))
			{
				return false;
			}

			_seenOrder.Enqueue(recordId);
			while (_seenOrder.Count > SeenRingCapacity)
			{
				long expired = _seenOrder.Dequeue();
				_seen.Remove(expired);
			}

			return true;
		}
	}

	private async Task<bool> DetectLatestBackfillNeededAsync(CancellationToken ct)
	{
		if (_factory is null)
		{
			// Test/legacy compose path without the DB hook — treat every startup as latest
			// backfill so a stale bookmark never wedges the worker.
			return true;
		}

		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
			bool anyFact = await db.AuthAttemptFacts.AsNoTracking().AnyAsync(ct).ConfigureAwait(false);
			return !anyFact;
		}
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "Could not query AuthAttemptFacts to decide latest-backfill; defaulting to TRUE");
			return true;
		}
	}

	private async Task TryDropStaleSecurityBookmarkAsync(CancellationToken ct)
	{
		if (_bookmarks is null)
		{
			return;
		}

		try
		{
			string? existing = _bookmarks.GetBookmarkXml(EventCatalog.ChannelSecurity);
			if (existing is null)
			{
				return;
			}

			await _bookmarks.DeleteBookmarkAsync(EventCatalog.ChannelSecurity, ct).ConfigureAwait(false);
			_logger.LogInformation(
				"Dropped stale Security bookmark — no AuthAttemptFacts have ever been observed, so the latest-backfill path will rebuild the bookmark from the actual tail of the channel.");
		}
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "Could not drop stale Security bookmark");
		}
	}

	internal readonly record struct PerIdResult(
		int Read,
		int Forwarded,
		int Duplicate,
		string? Error,
		string? ErrorOutcome,
		bool IsFatalChannelError);
}
