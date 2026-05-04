// File:    src/RdpAudit.Service/Workers/EventCollectorWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Captures events from configured channels via EventLogWatcher and pushes RawEventDto into
//          the in-memory channel for downstream processing.
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
	private readonly EventChannel _channel;
	private readonly BookmarkStore _bookmarks;
	private readonly ServiceMetrics _metrics;
	private readonly ILogger<EventCollectorWorker> _logger;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;

	private readonly ConcurrentDictionary<string, EventLogWatcher> _watchers = new(StringComparer.OrdinalIgnoreCase);
	private readonly object _watcherLock = new();
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
				_ => _ = FlushAllBookmarksAsync(),
				state: null,
				dueTime: TimeSpan.FromSeconds(30),
				period: TimeSpan.FromSeconds(30));

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
			_bookmarkTimer?.Dispose();
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
		List<int> ids = EventCatalog.EventIdsForChannel(channel).ToList();
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

		if (bookmarkXml is not null)
		{
			lock (_eventCounters)
			{
				_eventCounters.TryGetValue(channel, out int count);
				count++;
				_eventCounters[channel] = count;
				if (count >= 100)
				{
					_eventCounters[channel] = 0;
					string toFlush = bookmarkXml;
					_ = Task.Run(() => _bookmarks.SaveBookmarkAsync(channel, toFlush, _stoppingToken), _stoppingToken);
				}
			}
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

	private async Task FlushAllBookmarksAsync()
	{
		try
		{
			Dictionary<string, EventLogWatcher> snapshot;
			lock (_watcherLock)
			{
				snapshot = new Dictionary<string, EventLogWatcher>(_watchers, StringComparer.OrdinalIgnoreCase);
			}

			foreach (KeyValuePair<string, EventLogWatcher> kv in snapshot)
			{
				string? cached = _bookmarks.GetBookmarkXml(kv.Key);
				if (cached is not null)
				{
					await _bookmarks.SaveBookmarkAsync(kv.Key, cached, _stoppingToken).ConfigureAwait(false);
				}
			}
		}
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "Periodic bookmark flush failed");
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
