// File:    src/RdpAudit.Service/Workers/EventProcessorWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Drains the event channel in batches, normalises payloads, and persists to SQLite.
//          Uses a single transaction with prefetched address map and a bulk AddRange/SaveChanges
//          to avoid the original per-IP / per-event N+1 round-trips.
// Extends: Microsoft.Extensions.Hosting.BackgroundService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;
using RdpAudit.Service.Processors;

namespace RdpAudit.Service.Workers;

/// <summary>Drains the event channel in batches, normalises payloads, and persists to SQLite.</summary>
public sealed class EventProcessorWorker : BackgroundService
{
	private static readonly TimeSpan[] Backoffs =
	{
		TimeSpan.FromMilliseconds(100),
		TimeSpan.FromMilliseconds(200),
		TimeSpan.FromMilliseconds(400),
		TimeSpan.FromMilliseconds(800),
		TimeSpan.FromMilliseconds(2000),
	};

	private const int MaxConsecutiveFailures = 5;

	private readonly EventChannel _channel;
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly EventNormalizer _normalizer;
	private readonly SessionIpCorrelationUpserter _correlationUpserter;
	private readonly ILogger<EventProcessorWorker> _logger;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private int _consecutiveFailures;

	public EventProcessorWorker(
		EventChannel channel,
		IDbContextFactory<AuditDbContext> factory,
		EventNormalizer normalizer,
		SessionIpCorrelationUpserter correlationUpserter,
		ILogger<EventProcessorWorker> logger,
		IOptionsMonitor<RdpAuditOptions> options)
	{
		_channel = channel;
		_factory = factory;
		_normalizer = normalizer;
		_correlationUpserter = correlationUpserter;
		_logger = logger;
		_options = options;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(EventProcessorWorker));
		try
		{
			while (!stoppingToken.IsCancellationRequested)
			{
				List<RawEventDto> batch = await DrainBatchAsync(stoppingToken).ConfigureAwait(false);
				if (batch.Count == 0)
				{
					continue;
				}

				try
				{
					await WithRetryAsync(ct => PersistBatchAsync(batch, ct), stoppingToken).ConfigureAwait(false);
					_consecutiveFailures = 0;
				}
				catch (Exception ex)
				{
					_consecutiveFailures++;
					_logger.LogError(ex, "Persist batch of {Count} failed (consecutiveFailures={ConsecutiveFailures})",
						batch.Count, _consecutiveFailures);
					if (_consecutiveFailures >= MaxConsecutiveFailures)
					{
						_logger.LogCritical(
							"DB persistence has failed {ConsecutiveFailures} batches in a row — pausing 30s before retry",
							_consecutiveFailures);
						await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken).ConfigureAwait(false);
					}
				}
			}
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
		}
		catch (Exception ex)
		{
			_logger.LogCritical(ex, "{Worker} unhandled — service will stop", nameof(EventProcessorWorker));
			throw;
		}
		finally
		{
			_logger.LogInformation("{Worker} stopped", nameof(EventProcessorWorker));
		}
	}

	private async Task<List<RawEventDto>> DrainBatchAsync(CancellationToken stoppingToken)
	{
		MonitoringOptions monitoring = _options.CurrentValue.Monitoring;
		int max = Math.Max(1, monitoring.BatchSize);
		TimeSpan timeout = TimeSpan.FromMilliseconds(Math.Max(50, monitoring.BatchTimeoutMilliseconds));

		List<RawEventDto> batch = new(max);
		try
		{
			RawEventDto first = await _channel.Channel.Reader.ReadAsync(stoppingToken).ConfigureAwait(false);
			batch.Add(first);
		}
		catch (OperationCanceledException)
		{
			return batch;
		}

		using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
		linked.CancelAfter(timeout);

		try
		{
			while (batch.Count < max
				&& await _channel.Channel.Reader.WaitToReadAsync(linked.Token).ConfigureAwait(false))
			{
				while (batch.Count < max && _channel.Channel.Reader.TryRead(out RawEventDto? evt))
				{
					batch.Add(evt);
				}
			}
		}
		catch (OperationCanceledException)
		{
		}

		return batch;
	}

	private async Task PersistBatchAsync(List<RawEventDto> dtos, CancellationToken ct)
	{
		List<RawEvent> entities = dtos.Select(_normalizer.Normalize).ToList();

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		await using var tx = await db.Database.BeginTransactionAsync(ct).ConfigureAwait(false);
		DateTime now = DateTime.UtcNow;

		try
		{
			HashSet<string> ips = new(StringComparer.OrdinalIgnoreCase);
			foreach (RawEvent entity in entities)
			{
				if (!string.IsNullOrEmpty(entity.SourceIp))
				{
					ips.Add(entity.SourceIp);
				}
			}

			Dictionary<string, Address> existingMap = new(StringComparer.OrdinalIgnoreCase);
			if (ips.Count > 0)
			{
				List<Address> existing = await db.Addresses
					.Where(a => ips.Contains(a.Ip))
					.ToListAsync(ct)
					.ConfigureAwait(false);
				foreach (Address a in existing)
				{
					existingMap[a.Ip] = a;
				}
			}

			List<Address> toAdd = new();
			foreach (string ip in ips)
			{
				if (!existingMap.ContainsKey(ip))
				{
					Address fresh = new()
					{
						Ip = ip,
						FirstSeen = now,
						LastSeen = now,
						IsPublicIp = IpClassifier.IsPublicIp(ip),
					};
					existingMap[ip] = fresh;
					toAdd.Add(fresh);
				}
			}

			if (toAdd.Count > 0)
			{
				db.Addresses.AddRange(toAdd);
				await db.SaveChangesAsync(ct).ConfigureAwait(false); // assigns Ids in one round-trip
			}

			foreach (RawEvent entity in entities)
			{
				if (string.IsNullOrEmpty(entity.SourceIp))
				{
					continue;
				}

				if (!existingMap.TryGetValue(entity.SourceIp, out Address? addr))
				{
					continue;
				}

				entity.AddressId = addr.Id;
				addr.LastSeen = now;
				if (entity.EventId == 4625 || entity.EventId == 4771 || entity.EventId == 140)
				{
					addr.FailCount++;
				}
				else if (entity.EventId == 4624 || entity.EventId == 4768 || entity.EventId == 4769)
				{
					addr.SuccessCount++;
				}
			}

			db.RawEvents.AddRange(entities);

			List<SessionIpCorrelationCandidate> candidates = new(entities.Count);
			foreach (RawEvent entity in entities)
			{
				if (entity.SourceIpDerived || string.IsNullOrEmpty(entity.SourceIp))
				{
					continue;
				}

				candidates.Add(new SessionIpCorrelationCandidate(
					LogonId: entity.LogonId,
					WtsSessionId: entity.SessionId,
					UserName: entity.UserName,
					Domain: entity.Domain,
					Ip: entity.SourceIp!,
					ObservedUtc: entity.TimeUtc,
					EventId: entity.EventId,
					IsDirectObservation: true));
			}

			await _correlationUpserter.ApplyAsync(db, candidates, ct).ConfigureAwait(false);

			await db.SaveChangesAsync(ct).ConfigureAwait(false);
			await tx.CommitAsync(ct).ConfigureAwait(false);
		}
		catch
		{
			await tx.RollbackAsync(ct).ConfigureAwait(false);
			throw;
		}
	}

	private async Task WithRetryAsync(Func<CancellationToken, Task> action, CancellationToken ct)
	{
		for (int i = 0; i < Backoffs.Length; i++)
		{
			try
			{
				await action(ct).ConfigureAwait(false);
				return;
			}
			catch (SqliteException ex) when (ex.SqliteErrorCode is 5 or 6)
			{
				if (i == Backoffs.Length - 1)
				{
					throw;
				}

				_logger.LogWarning(
					"DB busy (attempt {Attempt}) — retrying in {Ms}ms",
					i + 1,
					Backoffs[i].TotalMilliseconds);
				await Task.Delay(Backoffs[i], ct).ConfigureAwait(false);
			}
		}
	}
}
