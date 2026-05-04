// File:    src/RdpAudit.Service/Workers/FirewallAutoBlockWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Periodically inspects the address table and, when AutoBlockBruteForce is enabled,
//          installs a Windows Firewall block rule for any IP whose FailCount exceeds the
//          configured threshold and whose IsBlocked flag is still false.
// Extends: Microsoft.Extensions.Hosting.BackgroundService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Service.Services;

namespace RdpAudit.Service.Workers;

/// <summary>Auto-blocks brute-force IPs by maintaining inbound block rules in Windows Firewall.</summary>
public sealed class FirewallAutoBlockWorker : BackgroundService
{
	private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(30);

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly FirewallManager _firewall;
	private readonly ILogger<FirewallAutoBlockWorker> _logger;

	public FirewallAutoBlockWorker(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		FirewallManager firewall,
		ILogger<FirewallAutoBlockWorker> logger)
	{
		_factory = factory;
		_options = options;
		_firewall = firewall;
		_logger = logger;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(FirewallAutoBlockWorker));
		try
		{
			while (!stoppingToken.IsCancellationRequested)
			{
				try
				{
					if (_options.CurrentValue.Firewall.AutoBlockBruteForce && OperatingSystem.IsWindows())
					{
						await SweepOnceAsync(stoppingToken).ConfigureAwait(false);
					}
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					break;
				}
				catch (Exception ex)
				{
					_logger.LogError(ex, "Auto-block sweep failed");
				}

				await Task.Delay(PollInterval, stoppingToken).ConfigureAwait(false);
			}
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
		}
		finally
		{
			_logger.LogInformation("{Worker} stopped", nameof(FirewallAutoBlockWorker));
		}
	}

	private async Task SweepOnceAsync(CancellationToken ct)
	{
		FirewallOptions fw = _options.CurrentValue.Firewall;
		int threshold = Math.Max(1, fw.AutoBlockThreshold);
		string ruleName = string.IsNullOrWhiteSpace(fw.BlockRuleName) ? "RdpAudit-Block" : fw.BlockRuleName;

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<Address> targets = await db.Addresses
			.Where(a => !a.IsBlocked && a.FailCount >= threshold && a.IsPublicIp)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		foreach (Address addr in targets)
		{
			if (!OperatingSystem.IsWindows())
			{
				continue;
			}

			FirewallOperationResult result = await _firewall.BlockAsync(ruleName, addr.Ip, ct).ConfigureAwait(false);
			if (result.Success)
			{
				addr.IsBlocked = true;
				addr.BlockReason = $"Auto-block: {addr.FailCount} failures >= {threshold}";
			}
		}

		if (targets.Count > 0)
		{
			await db.SaveChangesAsync(ct).ConfigureAwait(false);
		}
	}
}
