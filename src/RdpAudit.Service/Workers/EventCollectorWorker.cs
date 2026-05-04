// File:    src/RdpAudit.Service/Workers/EventCollectorWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Captures events from configured channels via EventLogWatcher and pushes RawEventDto into
//          the in-memory channel for downstream processing. Saves the latest per-channel bookmark
//          every 100 events AND every 30 seconds, whichever comes first, to bound recovery loss.
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

	private readonly ConcurrentDictionary<string, EventLogWatcher> _watchers = new(StringComparer.OrdinalIgnoreCase);
	private readonly object _watcherLock = new();
	private readonly object _bookmarkLock = new();
	private readonly Dictionary<string, string> _pendingBookmarks = new(StringComparer.OrdinalIgnoreCase);
	private readonly Dictionary<string, string> _flushedBookmarks = new(StringComparer.OrdinalIgnoreCase);
	private readonly Dictionary<string, int> _eventCounters = new(StringComparer.OrdinalIgnoreCase);
	private CancellationToken _stoppingToken;
	private Timer? _bookmarkTimer;

	public EventCollectorWorker(
		EventChannel channel,
		BookmarkStore bookmarks,
		ServiceMetrics metrics,
		ILogger<EventCollectorWorker> logger,
		IOptionsMonitor<RdpAuditOptions> options)
	{
		_channel = channel;
		_bookmarks = bookmarks;
		_metrics = metrics;
		_logger = logger;
		_options = options;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_stoppingToken = stoppingToken;
		_logger.LogInformation("{Worker} starting", nameof(EventCollectorWorker));

		if (!OperatingSystem.IsWindows())
		{
			_logger.LogWarning("EventLogWatcher requires Windows; collector will idle on this host");
			await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken).ConfigureAwait(false);
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

			await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken).ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
		}
		catch (Exception ex)
		{
			_logger.LogCritical(ex, "{Worker} unhandled — service will stop", nameof(EventCollectorWorker));
			throw;
		}
		finally
		{
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

			_logger.LogInformation("{Worker} stopped", nameof(EventCollectorWorker));
		}
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
			try
			{
				EventLogWatcher watcher = CreateWatcher(channel);
				watcher.Enabled = true;
				_watchers[channel] = watcher;
				_metrics.SetChannelStatus(channel, "Running");
				_logger.LogInformation("Watcher armed for channel {Channel}", channel);
			}
			catch (Exception ex)
			{
				_metrics.SetChannelStatus(channel, $"Failed: {ex.GetType().Name}");
				_logger.LogError(ex, "Failed to start watcher for {Channel}", channel);
				_ = Task.Run(() => RestartWatcherAsync(channel, _stoppingToken), _stoppingToken);
			}
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
		EventLogWatcher watcher = bookmarkXml is null
			? new EventLogWatcher(query)
			: new EventLogWatcher(query, BookmarkSerializer.Deserialize(bookmarkXml));

		watcher.EventRecordWritten += (sender, e) => OnEventRecordWritten(channel, e);
		return watcher;
	}

	[SupportedOSPlatform("windows")]
	private void OnEventRecordWritten(string channel, EventRecordWrittenEventArgs e)
	{
		if (e.EventException is not null)
		{
			_logger.LogError(e.EventException, "Watcher reported error on {Channel}", channel);
			_metrics.SetChannelStatus(channel, $"Error: {e.EventException.GetType().Name}");
			_ = Task.Run(() => RestartWatcherAsync(channel, _stoppingToken), _stoppingToken);
			return;
		}

		if (e.EventRecord is null)
		{
			_metrics.SetChannelStatus(channel, "Stalled");
			_ = Task.Run(() => RestartWatcherAsync(channel, _stoppingToken), _stoppingToken);
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
	private async Task RestartWatcherAsync(string channel, CancellationToken ct)
	{
		TimeSpan delay = TimeSpan.FromSeconds(30);
		for (int attempt = 1; attempt <= 10; attempt++)
		{
			if (ct.IsCancellationRequested)
			{
				return;
			}

			try
			{
				await Task.Delay(delay, ct).ConfigureAwait(false);
				delay = TimeSpan.FromSeconds(Math.Min(delay.TotalSeconds * 2, 300));

				lock (_watcherLock)
				{
					if (_watchers.TryRemove(channel, out EventLogWatcher? old))
					{
						try { old.Enabled = false; old.Dispose(); }
						catch { /* best effort */ }
					}

					EventLogWatcher fresh = CreateWatcher(channel);
					fresh.Enabled = true;
					_watchers[channel] = fresh;
					_metrics.SetChannelStatus(channel, "Restarted");
				}

				_logger.LogInformation("Watcher restarted for {Channel} on attempt {Attempt}", channel, attempt);
				return;
			}
			catch (OperationCanceledException)
			{
				return;
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Restart attempt {Attempt}/10 failed for {Channel}", attempt, channel);
			}
		}

		_metrics.SetChannelStatus(channel, "Permanently disabled");
		_logger.LogCritical("Watcher permanently disabled for {Channel}", channel);
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

	private void DisposeAllWatchers()
	{
		lock (_watcherLock)
		{
			foreach (EventLogWatcher w in _watchers.Values)
			{
				try { w.Enabled = false; w.Dispose(); }
				catch { /* best effort */ }
			}

			_watchers.Clear();
		}
	}
}
