// File:    src/RdpAudit.Service/Workers/EventCollectorWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Captures events from configured channels via EventLogWatcher and pushes RawEventDto into
//          the in-memory channel for downstream processing. Saves the latest per-channel bookmark
//          every 100 events AND every 30 seconds, whichever comes first, to bound recovery loss.
//          Uses ChannelHealthPolicy to debounce repeated Invalid-Handle failures so the Windows
//          Application log is not spammed every 30s on hosts where an optional channel (e.g. the
//          TS-Gateway channel on Win10 Pro) is unavailable, and to attempt one bookmark-reset
//          recovery before disabling a channel.
// Extends: Microsoft.Extensions.Hosting.BackgroundService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Service.Collectors;

namespace RdpAudit.Service.Workers;

/// <summary>
/// Captures events from configured channels via EventLogWatcher and pushes RawEventDto into the
/// in-memory channel for downstream processing.  EventLogWatcher is a Windows-only API; on
/// non-Windows hosts this worker logs and exits cleanly.
/// </summary>
public sealed class EventCollectorWorker : BackgroundService
{
	private const int FlushEventThreshold = 100;
	private static readonly TimeSpan FlushTimerPeriod = TimeSpan.FromSeconds(30);

	private readonly EventChannel _channel;
	private readonly BookmarkStore _bookmarks;
	private readonly ServiceMetrics _metrics;
	private readonly ILogger<EventCollectorWorker> _logger;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ChannelHealthPolicy _health;

	private readonly ConcurrentDictionary<string, EventLogWatcher> _watchers = new(StringComparer.OrdinalIgnoreCase);
	private readonly object _watcherLock = new();
	private readonly object _bookmarkLock = new();
	private readonly Dictionary<string, string> _pendingBookmarks = new(StringComparer.OrdinalIgnoreCase);
	private readonly Dictionary<string, string> _flushedBookmarks = new(StringComparer.OrdinalIgnoreCase);
	private readonly Dictionary<string, int> _eventCounters = new(StringComparer.OrdinalIgnoreCase);
	private readonly ConcurrentDictionary<string, byte> _restartInFlight = new(StringComparer.OrdinalIgnoreCase);

	private CancellationTokenSource? _shutdownCts;
	private CancellationToken _stoppingToken;
	private Timer? _bookmarkTimer;
	private volatile bool _shuttingDown;

	public EventCollectorWorker(
		EventChannel channel,
		BookmarkStore bookmarks,
		ServiceMetrics metrics,
		ILogger<EventCollectorWorker> logger,
		IOptionsMonitor<RdpAuditOptions> options)
		: this(channel, bookmarks, metrics, logger, options, new ChannelHealthPolicy())
	{
	}

	internal EventCollectorWorker(
		EventChannel channel,
		BookmarkStore bookmarks,
		ServiceMetrics metrics,
		ILogger<EventCollectorWorker> logger,
		IOptionsMonitor<RdpAuditOptions> options,
		ChannelHealthPolicy health)
	{
		_channel = channel;
		_bookmarks = bookmarks;
		_metrics = metrics;
		_logger = logger;
		_options = options;
		_health = health;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_shutdownCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
		_stoppingToken = _shutdownCts.Token;
		_logger.LogInformation("{Worker} starting", nameof(EventCollectorWorker));

		if (!OperatingSystem.IsWindows())
		{
			_logger.LogWarning("EventLogWatcher requires Windows; collector will idle on this host");
			await Task.Delay(Timeout.InfiniteTimeSpan, _stoppingToken).ConfigureAwait(false);
			return;
		}

		try
		{
			StartWatchers();
			_bookmarkTimer = new Timer(
				_ => _ = FlushPendingBookmarksAsync(),
				state: null,
				dueTime: FlushTimerPeriod,
				period: FlushTimerPeriod);

			await Task.Delay(Timeout.InfiniteTimeSpan, _stoppingToken).ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (_stoppingToken.IsCancellationRequested)
		{
		}
		catch (Exception ex)
		{
			_logger.LogCritical(ex, "{Worker} unhandled — service will stop", nameof(EventCollectorWorker));
			throw;
		}
		finally
		{
			_shuttingDown = true;
			_shutdownCts?.Cancel();
			DisposeAllWatchers();
			if (_bookmarkTimer is not null)
			{
				await _bookmarkTimer.DisposeAsync().ConfigureAwait(false);
			}

			// Final best-effort flush so we never lose more than the latest bookmark per channel.
			try
			{
				await FlushPendingBookmarksAsync().ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				_logger.LogDebug(ex, "Final bookmark flush failed");
			}

			_shutdownCts?.Dispose();
			_logger.LogInformation("{Worker} stopped", nameof(EventCollectorWorker));
		}
	}

	public override async Task StopAsync(CancellationToken cancellationToken)
	{
		_shuttingDown = true;
		_shutdownCts?.Cancel();
		await base.StopAsync(cancellationToken).ConfigureAwait(false);
	}

	[SupportedOSPlatform("windows")]
	private void StartWatchers()
	{
		RdpAuditOptions opts = _options.CurrentValue;
		IEnumerable<string> channels = opts.Monitoring.EnabledChannels.Count > 0
			? opts.Monitoring.EnabledChannels
			: EventCatalog.AllChannels();

		foreach (string channel in channels)
		{
			ArmChannel(channel);
		}
	}

	[SupportedOSPlatform("windows")]
	private void ArmChannel(string channel)
	{
		if (_shuttingDown || _stoppingToken.IsCancellationRequested)
		{
			return;
		}

		// Capability probe — for optional channels this avoids the Invalid-Handle callback loop.
		ChannelProbeResult probe = ChannelCapability.Probe(channel);
		if (!probe.IsAvailable)
		{
			ChannelImportance importance = _health.ClassifyChannel(channel);
			if (importance == ChannelImportance.Optional)
			{
				_health.ReportUnavailable(channel, probe.Reason);
				_metrics.SetChannelStatus(channel, "SkippedUnavailable");
				_logger.LogWarning(
					"Skipping optional channel {Channel}: {Reason}",
					channel, probe.Reason);
				return;
			}

			// Critical channel that failed capability check: log once at error, still try to arm —
			// the EventLogWatcher will surface the real failure and the health policy will gate
			// any restart loop.
			_logger.LogError(
				"Critical channel {Channel} failed capability probe: {Reason}. Attempting to arm anyway.",
				channel, probe.Reason);
		}

		try
		{
			EventLogWatcher watcher = CreateWatcher(channel);
			lock (_watcherLock)
			{
				if (_watchers.TryRemove(channel, out EventLogWatcher? old))
				{
					SafeDisposeWatcher(old);
				}

				watcher.Enabled = true;
				_watchers[channel] = watcher;
			}

			_health.ReportSuccess(channel);
			_metrics.SetChannelStatus(channel, "Armed");
			if (string.Equals(channel, EventCatalog.ChannelSecurity, StringComparison.OrdinalIgnoreCase))
			{
				_metrics.SetSecurityWatcherEnabled(true);
			}
			_logger.LogInformation("Watcher armed for channel {Channel}", channel);
		}
		catch (Exception ex)
		{
			HandleWatcherFailure(channel, ex, isCallback: false);
		}
	}

	[SupportedOSPlatform("windows")]
	private EventLogWatcher CreateWatcher(string channel)
	{
		IEnumerable<int> catalogIds = EventCatalog.EventIdsForChannel(channel);
		IReadOnlyCollection<int> filterSet = _options.CurrentValue.Monitoring.EnabledEventIds;
		List<int> ids = filterSet.Count > 0
			? catalogIds.Where(filterSet.Contains).ToList()
			: catalogIds.ToList();
		string xpath = ids.Count == 0
			? "*"
			: "*[System[(" + string.Join(" or ", ids.Select(id => $"EventID={id}")) + ")]]";

		EventLogQuery query = new(channel, PathType.LogName, xpath)
		{
			ReverseDirection = false,
		};

		string? bookmarkXml = _bookmarks.GetBookmarkXml(channel);
		EventLogWatcher watcher;
		try
		{
			watcher = bookmarkXml is null
				? new EventLogWatcher(query)
				: new EventLogWatcher(query, BookmarkSerializer.Deserialize(bookmarkXml));
		}
		catch (EventLogException) when (bookmarkXml is not null)
		{
			// Stale bookmark made the watcher constructor throw — fall back to no bookmark.
			_logger.LogWarning(
				"Stale bookmark rejected by EventLogWatcher constructor for {Channel}; arming without bookmark",
				channel);
			_ = Task.Run(async () =>
			{
				try { await _bookmarks.DeleteBookmarkAsync(channel, _stoppingToken).ConfigureAwait(false); }
				catch (OperationCanceledException) { }
				catch (Exception ex) { _logger.LogDebug(ex, "Failed to delete stale bookmark for {Channel}", channel); }
			});
			watcher = new EventLogWatcher(query);
		}

		watcher.EventRecordWritten += (sender, e) => OnEventRecordWritten(channel, e);
		return watcher;
	}

	[SupportedOSPlatform("windows")]
	private void OnEventRecordWritten(string channel, EventRecordWrittenEventArgs e)
	{
		if (e.EventException is not null)
		{
			HandleWatcherFailure(channel, e.EventException, isCallback: true);
			return;
		}

		if (e.EventRecord is null)
		{
			_metrics.SetChannelStatus(channel, "Stalled");
			ScheduleRestart(channel);
			return;
		}

		RawEventDto dto;
		string? bookmarkXml = null;
		try
		{
			using EventRecord record = e.EventRecord;
			string xml = record.ToXml();
			if (xml.Length > 65_536)
			{
				_logger.LogWarning("Event XML truncated from {Len} to 65536", xml.Length);
				xml = xml[..65_536];
			}

			dto = new RawEventDto
			{
				EventId = record.Id,
				Channel = record.LogName ?? channel,
				TimeUtc = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow,
				XmlPayload = xml,
			};

			try
			{
				bookmarkXml = BookmarkSerializer.Serialize(record.Bookmark);
			}
			catch (Exception ex)
			{
				_logger.LogDebug(ex, "Bookmark capture failed for {Channel}", channel);
			}
		}
		catch (EventLogException ex)
		{
			_logger.LogError(ex, "Failed reading EventRecord for {Channel}", channel);
			return;
		}

		if (!_channel.Channel.Writer.TryWrite(dto))
		{
			_metrics.IncrementDropped();
			if (_options.CurrentValue.Diagnostics.LogChannelDrops)
			{
				_logger.LogWarning("Event channel full — dropped EventID {EventId} channel={Channel}",
					dto.EventId, dto.Channel);
			}
		}
		else
		{
			_metrics.IncrementCaptured();
		}

		if (bookmarkXml is null)
		{
			return;
		}

		bool flushNow;
		lock (_bookmarkLock)
		{
			_pendingBookmarks[channel] = bookmarkXml;
			_eventCounters.TryGetValue(channel, out int count);
			count++;
			_eventCounters[channel] = count;
			flushNow = count >= FlushEventThreshold;
			if (flushNow)
			{
				_eventCounters[channel] = 0;
			}
		}

		if (flushNow)
		{
			_ = Task.Run(() => FlushPendingBookmarksAsync(), _stoppingToken);
		}
	}

	[SupportedOSPlatform("windows")]
	private void HandleWatcherFailure(string channel, Exception ex, bool isCallback)
	{
		if (_shuttingDown)
		{
			return;
		}

		bool invalidHandleLike = ex is EventLogException
			|| ex is UnauthorizedAccessException
			|| ex.HResult == unchecked((int)0x80070006); // E_HANDLE (Invalid handle)

		ChannelHealthOutcome outcome = _health.ReportFailure(channel, invalidHandleLike);

		// Always dispose any current watcher for this channel before deciding.
		DisposeWatcher(channel);

		switch (outcome.Decision)
		{
			case ChannelDecision.ResetBookmarkAndRestart:
				_metrics.SetChannelStatus(channel, "BookmarkReset");
				_logger.LogWarning(
					ex,
					"Watcher fault on {Channel} ({Source}); {Reason}. Will reset bookmark and retry.",
					channel,
					isCallback ? "callback" : "arm",
					outcome.Reason);
				_ = Task.Run(async () => await ResetBookmarkAndRestartAsync(channel).ConfigureAwait(false), _stoppingToken);
				break;

			case ChannelDecision.Cooldown:
				_metrics.SetChannelStatus(channel, "RestartScheduled");
				// Log at Warning the first time per cooldown cycle only; subsequent failures inside the
				// cooldown window are debug to avoid spamming the Application log every 30s.
				_logger.LogDebug(
					ex,
					"Watcher fault on {Channel}; {Reason} (consecutive={Count})",
					channel, outcome.Reason, _health.ConsecutiveFailures(channel));
				ScheduleRestart(channel);
				break;

			case ChannelDecision.DisablePermanently:
				_metrics.SetChannelStatus(channel, "DisabledAfterFailures");
				if (string.Equals(channel, EventCatalog.ChannelSecurity, StringComparison.OrdinalIgnoreCase))
				{
					_metrics.SetSecurityWatcherEnabled(false);
					_metrics.SetLastSecurityChannelError("DisabledAfterFailures: " + outcome.Reason);
				}
				ChannelImportance importance = _health.ClassifyChannel(channel);
				if (importance == ChannelImportance.Optional)
				{
					_logger.LogWarning(
						"Optional channel {Channel} disabled until service restart. {Reason}",
						channel, outcome.Reason);
				}
				else
				{
					_logger.LogError(
						ex,
						"Critical channel {Channel} disabled until service restart. {Reason}",
						channel, outcome.Reason);
				}
				break;

			default:
				_metrics.SetChannelStatus(channel, "RestartScheduled");
				ScheduleRestart(channel);
				break;
		}
	}

	[SupportedOSPlatform("windows")]
	private void ScheduleRestart(string channel)
	{
		if (_shuttingDown || _stoppingToken.IsCancellationRequested)
		{
			return;
		}

		// Single-flight per channel.
		if (!_restartInFlight.TryAdd(channel, 0))
		{
			return;
		}

		_ = Task.Run(async () =>
		{
			try
			{
				DateTime? next = _health.NextAllowedRestartUtc(channel);
				if (next is DateTime gate)
				{
					TimeSpan wait = gate - DateTime.UtcNow;
					if (wait > TimeSpan.Zero)
					{
						await Task.Delay(wait, _stoppingToken).ConfigureAwait(false);
					}
				}

				if (_shuttingDown || _stoppingToken.IsCancellationRequested || _health.IsDisabled(channel))
				{
					return;
				}

				ArmChannel(channel);
				if (!_health.IsDisabled(channel))
				{
					_metrics.SetChannelStatus(channel, "RestartSucceeded");
				}
			}
			catch (OperationCanceledException)
			{
			}
			catch (Exception ex)
			{
				_logger.LogDebug(ex, "ScheduleRestart task crashed for {Channel}", channel);
			}
			finally
			{
				_restartInFlight.TryRemove(channel, out _);
			}
		}, _stoppingToken);
	}

	[SupportedOSPlatform("windows")]
	private async Task ResetBookmarkAndRestartAsync(string channel)
	{
		if (!_restartInFlight.TryAdd(channel, 0))
		{
			return;
		}

		try
		{
			// Forget any pending in-memory bookmark for this channel so the next flush cannot
			// resurrect the stale value.
			lock (_bookmarkLock)
			{
				_pendingBookmarks.Remove(channel);
				_flushedBookmarks.Remove(channel);
				_eventCounters.Remove(channel);
			}

			try
			{
				await _bookmarks.DeleteBookmarkAsync(channel, _stoppingToken).ConfigureAwait(false);
				_logger.LogInformation("Bookmark reset for {Channel}", channel);
			}
			catch (OperationCanceledException)
			{
				return;
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "Bookmark delete failed for {Channel}; will still try to rearm without it", channel);
			}

			if (_shuttingDown || _stoppingToken.IsCancellationRequested)
			{
				return;
			}

			ArmChannel(channel);
		}
		finally
		{
			_restartInFlight.TryRemove(channel, out _);
		}
	}

	private async Task FlushPendingBookmarksAsync()
	{
		Dictionary<string, string> snapshot;
		lock (_bookmarkLock)
		{
			snapshot = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
			foreach (KeyValuePair<string, string> kv in _pendingBookmarks)
			{
				if (!_flushedBookmarks.TryGetValue(kv.Key, out string? prev) || !string.Equals(prev, kv.Value, StringComparison.Ordinal))
				{
					snapshot[kv.Key] = kv.Value;
				}
			}
		}

		foreach (KeyValuePair<string, string> kv in snapshot)
		{
			try
			{
				await _bookmarks.SaveBookmarkAsync(kv.Key, kv.Value, _stoppingToken).ConfigureAwait(false);
				lock (_bookmarkLock)
				{
					_flushedBookmarks[kv.Key] = kv.Value;
					// Reset counter on successful flush.
					_eventCounters[kv.Key] = 0;
				}
			}
			catch (OperationCanceledException) when (_stoppingToken.IsCancellationRequested)
			{
				break;
			}
			catch (Exception ex)
			{
				_logger.LogDebug(ex, "Bookmark flush failed for {Channel}", kv.Key);
			}
		}
	}

	[SupportedOSPlatform("windows")]
	private void DisposeWatcher(string channel)
	{
		lock (_watcherLock)
		{
			if (_watchers.TryRemove(channel, out EventLogWatcher? old))
			{
				SafeDisposeWatcher(old);
			}
		}
	}

	[SupportedOSPlatform("windows")]
	private static void SafeDisposeWatcher(EventLogWatcher? w)
	{
		if (w is null)
		{
			return;
		}

		try { w.Enabled = false; }
		catch { /* best effort */ }

		try { w.Dispose(); }
		catch { /* best effort */ }
	}

	private void DisposeAllWatchers()
	{
		if (!OperatingSystem.IsWindows())
		{
			return;
		}

		lock (_watcherLock)
		{
			foreach (EventLogWatcher w in _watchers.Values)
			{
				SafeDisposeWatcher(w);
			}

			_watchers.Clear();
		}
	}
}
