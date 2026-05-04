// File:    src/RdpAudit.Service/Workers/EventProcessorWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Drains the event channel in batches, normalises payloads, and persists to SQLite.
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

	private readonly EventChannel _channel;
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly EventNormalizer _normalizer;
	private readonly ILogger<EventProcessorWorker> _logger;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;

	public EventProcessorWorker(
		EventChannel channel,
		IDbContextFactory<AuditDbContext> factory,
		EventNormalizer normalizer,
		ILogger<EventProcessorWorker> logger,
		IOptionsMonitor<RdpAuditOptions> options)
	{
		_channel = channel;
		_factory = factory;
		_normalizer = normalizer;
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
				}
				catch (Exception ex)
				{
					_logger.LogError(ex, "Persist batch of {Count} failed", batch.Count);
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

			Dictionary<string, long> addressIds = new(StringComparer.OrdinalIgnoreCase);
			foreach (string ip in ips)
			{
				Address? existing = await db.Addresses
					.FirstOrDefaultAsync(a => a.Ip == ip, ct)
					.ConfigureAwait(false);
				if (existing is null)
				{
					existing = new Address
					{
						Ip = ip,
						FirstSeen = DateTime.UtcNow,
						LastSeen = DateTime.UtcNow,
						IsPublicIp = IpClassifier.IsPublicIp(ip),
					};
					db.Addresses.Add(existing);
					await db.SaveChangesAsync(ct).ConfigureAwait(false);
				}
				else
				{
					existing.LastSeen = DateTime.UtcNow;
				}

				addressIds[ip] = existing.Id;
			}

			foreach (RawEvent entity in entities)
			{
				if (!string.IsNullOrEmpty(entity.SourceIp)
					&& addressIds.TryGetValue(entity.SourceIp, out long addrId))
				{
					entity.AddressId = addrId;
				}
			}

			db.RawEvents.AddRange(entities);
			await db.SaveChangesAsync(ct).ConfigureAwait(false);

			foreach (RawEvent entity in entities)
			{
				if (!string.IsNullOrEmpty(entity.SourceIp)
					&& addressIds.TryGetValue(entity.SourceIp, out long addrId))
				{
					Address? addr = await db.Addresses.FindAsync(new object?[] { addrId }, ct).ConfigureAwait(false);
					if (addr is null)
					{
						continue;
					}

					if (entity.EventId == 4625 || entity.EventId == 4771 || entity.EventId == 140)
					{
						addr.FailCount++;
					}
					else if (entity.EventId == 4624 || entity.EventId == 4768 || entity.EventId == 4769)
					{
						addr.SuccessCount++;
					}
				}
			}

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
