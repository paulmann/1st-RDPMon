// File:    src/RdpAudit.Service/Workers/MaintenanceWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Daily housekeeping — retention, compaction, ThreatScore decay, log rotation.
// Extends: Microsoft.Extensions.Hosting.BackgroundService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;

namespace RdpAudit.Service.Workers;

/// <summary>Daily housekeeping — retention, compaction, ThreatScore decay, log rotation.</summary>
public sealed class MaintenanceWorker : BackgroundService
{
	private static readonly TimeSpan Period = TimeSpan.FromHours(24);

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ILogger<MaintenanceWorker> _logger;

	public MaintenanceWorker(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<MaintenanceWorker> logger)
	{
		_factory = factory;
		_options = options;
		_logger = logger;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(MaintenanceWorker));
		try
		{
			await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken).ConfigureAwait(false);
			while (!stoppingToken.IsCancellationRequested)
			{
				try
				{
					await RunOnceAsync(stoppingToken).ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					_logger.LogError(ex, "Maintenance iteration failed");
				}

				await Task.Delay(Period, stoppingToken).ConfigureAwait(false);
			}
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
		}
		finally
		{
			_logger.LogInformation("{Worker} stopped", nameof(MaintenanceWorker));
		}
	}

	private async Task RunOnceAsync(CancellationToken ct)
	{
		StorageOptions storage = _options.CurrentValue.Storage;
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		DateTime eventCutoff = DateTime.UtcNow.AddDays(-Math.Max(7, storage.EventRetentionDays));
		int eventsDeleted = await db.RawEvents.Where(e => e.TimeUtc < eventCutoff).ExecuteDeleteAsync(ct).ConfigureAwait(false);

		DateTime alertCutoff = DateTime.UtcNow.AddDays(-Math.Max(30, storage.AlertRetentionDays));
		int alertsDeleted = await db.Alerts.Where(a => a.TimeUtc < alertCutoff).ExecuteDeleteAsync(ct).ConfigureAwait(false);

		await db.Database.ExecuteSqlRawAsync("PRAGMA incremental_vacuum;", ct).ConfigureAwait(false);

		List<Core.Models.Address> addresses = await db.Addresses.ToListAsync(ct).ConfigureAwait(false);
		foreach (Core.Models.Address addr in addresses)
		{
			addr.ThreatScore *= 0.95;
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);

		_logger.LogInformation(
			"Maintenance complete: events deleted={EventsDeleted} alerts deleted={AlertsDeleted}",
			eventsDeleted,
			alertsDeleted);

		PruneLogFiles(storage);
	}

	private void PruneLogFiles(StorageOptions storage)
	{
		try
		{
			string logDir = storage.ResolveLogDirectory();
			if (!Directory.Exists(logDir))
			{
				return;
			}

			DateTime cutoff = DateTime.UtcNow.AddDays(-Math.Max(7, storage.LogRetentionDays));
			foreach (string file in Directory.EnumerateFiles(logDir, "service-*.log"))
			{
				FileInfo info = new(file);
				if (info.LastWriteTimeUtc < cutoff)
				{
					info.Delete();
				}
			}
		}
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "Log pruning failed");
		}
	}
}
