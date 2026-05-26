// File:    src/RdpAudit.Service/Workers/SecurityBackfillWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Bounded, idempotent backfill for the full v3 Security event set
//          (Detect_Attack_Strategy_v3.md §5.2 "Critical Backfill Targets"): 4624, 4625, 4634, 4647,
//          4648, 4672, 4719, 4720, 4724, 4732, 4740, 4768, 4769, 4771, 4776, 4778, 4779, 4825, 1102.
//          The primary collection path is EventLogWatcher; this worker recovers events the
//          push-based watcher missed on overloaded hosts, after a service restart that landed past
//          the persisted bookmark, or when the live channel was briefly unavailable. The poll is
//          strictly bounded by a short XPath time window and a fixed event-id list, so it never
//          scans the entire Security log. Duplicates are dropped by EventRecordID before being
//          forwarded to the in-memory pipeline.
// Extends: Microsoft.Extensions.Hosting.BackgroundService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Events;

namespace RdpAudit.Service.Workers;

/// <summary>
/// Polls the local Security channel for recent 4624/4625/4648 events on a fixed cadence, pushing
/// any new EventRecordIDs into the same in-memory <see cref="EventChannel"/> the realtime watcher
/// uses. Only records whose EventRecordID has not been seen this process tick are forwarded —
/// the in-memory <see cref="_seen"/> ring is kept tiny (a few thousand entries) so the worker's
/// memory and CPU cost are negligible even on busy domain controllers.
/// </summary>
public sealed class SecurityBackfillWorker : BackgroundService
{
	/// <summary>Full v3 Security backfill set per Detect_Attack_Strategy_v3.md §5.2. The list is
	/// expressed as <see cref="IReadOnlyList{T}"/> so tests can introspect the contract without
	/// re-encoding it. Adding new ids here requires updating the v3 strategy document — the two
	/// are tested for parity.</summary>
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

	/// <summary>Cap on the in-memory dedup ring. Older record ids are dropped FIFO.</summary>
	internal const int SeenRingCapacity = 8192;

	private static readonly TimeSpan DefaultInterval = TimeSpan.FromMinutes(2);
	private static readonly TimeSpan DefaultLookback = TimeSpan.FromMinutes(3);
	private static readonly TimeSpan StartupGrace = TimeSpan.FromSeconds(30);

	private readonly EventChannel _channel;
	private readonly ServiceMetrics _metrics;
	private readonly ILogger<SecurityBackfillWorker> _logger;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly object _ringGate = new();
	private readonly Queue<long> _seenOrder = new();
	private readonly HashSet<long> _seen = new();

	public SecurityBackfillWorker(
		EventChannel channel,
		ServiceMetrics metrics,
		ILogger<SecurityBackfillWorker> logger,
		IOptionsMonitor<RdpAuditOptions> options)
	{
		_channel = channel;
		_metrics = metrics;
		_logger = logger;
		_options = options;
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
			// Brief startup grace so the live watcher has a moment to arm and ingest first batch
			// before we begin polling — avoids a redundant scan at t=0 when the bookmark replay is
			// already streaming the same events into the channel.
			await Task.Delay(StartupGrace, stoppingToken).ConfigureAwait(false);

			while (!stoppingToken.IsCancellationRequested)
			{
				try
				{
					await PollOnceAsync(stoppingToken).ConfigureAwait(false);
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
	private Task PollOnceAsync(CancellationToken ct)
	{
		// Bounded lookback window: we never scan more than the last few minutes of the Security
		// channel. Combined with the event-id filter this makes the poll O(few) on a typical host.
		DateTime startedUtc = DateTime.UtcNow;
		DateTime sinceUtc = startedUtc - DefaultLookback;
		string xpath = BuildXPath(sinceUtc);
		int recordsRead = 0;

		EventLogQuery query;
		try
		{
			query = new EventLogQuery(EventCatalog.ChannelSecurity, PathType.LogName, xpath)
			{
				ReverseDirection = false,
			};
		}
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "Could not build Security backfill query — skipping this tick");
			return Task.CompletedTask;
		}

		int forwarded = 0;
		int seenDuplicate = 0;
		try
		{
			using EventLogReader reader = new(query);
			while (!ct.IsCancellationRequested)
			{
				using EventRecord? record = reader.ReadEvent(TimeSpan.FromMilliseconds(50));
				if (record is null)
				{
					break;
				}

				recordsRead++;
				long recordId = record.RecordId ?? unchecked((long)record.GetHashCode());
				if (!TryMarkSeen(recordId))
				{
					seenDuplicate++;
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

			if (forwarded > 0 || seenDuplicate > 0)
			{
				_logger.LogDebug(
					"Security backfill tick: forwarded={Forwarded} duplicate={Duplicate} lookback={Lookback}",
					forwarded, seenDuplicate, DefaultLookback);
			}
		}
		catch (UnauthorizedAccessException ex)
		{
			_metrics.SetChannelStatus(
				EventCatalog.ChannelSecurity + "::Backfill",
				"AccessDenied");
			_metrics.SetLastSecurityChannelError("AccessDenied: " + ex.Message);
			_logger.LogWarning(
				ex,
				"Security backfill cannot read the Security channel — service account is missing 'Manage auditing and security log' or membership in Event Log Readers");
		}
		catch (EventLogNotFoundException ex)
		{
			_metrics.SetChannelStatus(
				EventCatalog.ChannelSecurity + "::Backfill",
				"ChannelNotFound");
			_metrics.SetLastSecurityChannelError("ChannelNotFound: " + ex.Message);
			_logger.LogWarning(ex, "Security backfill: Security channel not found");
		}
		catch (EventLogException ex)
		{
			_metrics.SetChannelStatus(
				EventCatalog.ChannelSecurity + "::Backfill",
				"QueryFailed");
			_metrics.SetLastSecurityChannelError("QueryFailed: " + ex.Message);
			_logger.LogDebug(ex, "Security backfill query failed");
		}
		finally
		{
			_metrics.RecordSecurityBackfillRun(startedUtc, recordsRead, forwarded, seenDuplicate);
		}

		return Task.CompletedTask;
	}

	internal static string BuildXPath(DateTime sinceUtc)
	{
		// XPath time literal must be a Windows-recognised ISO-8601 string with millisecond
		// precision and explicit Z. Format invariantly.
		string iso = sinceUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);
		string ids = string.Join(" or ", BackfillEventIds.Select(id => $"EventID={id}"));
		return $"*[System[({ids}) and TimeCreated[@SystemTime >= '{iso}']]]";
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
}
