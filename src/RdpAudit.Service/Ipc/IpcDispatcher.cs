// File:    src/RdpAudit.Service/Ipc/IpcDispatcher.cs
// Module:  RdpAudit.Service.Ipc
// Purpose: Dispatches IpcRequests to handlers and produces an IpcResponse.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Ipc;

/// <summary>Dispatches IpcRequests to handlers and produces an IpcResponse.</summary>
public sealed class IpcDispatcher
{
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly ServiceMetrics _metrics;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ILogger<IpcDispatcher> _logger;

	public IpcDispatcher(
		IDbContextFactory<AuditDbContext> factory,
		ServiceMetrics metrics,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<IpcDispatcher> logger)
	{
		_factory = factory;
		_metrics = metrics;
		_options = options;
		_logger = logger;
	}

	public async Task<IpcResponse> DispatchAsync(IpcRequest request, CancellationToken ct)
	{
		try
		{
			object? payload = request.Command switch
			{
				IpcCommand.Ping => "pong",
				IpcCommand.GetStatus => BuildStatus(),
				IpcCommand.GetRecentEvents => await GetRecentEventsAsync(ct).ConfigureAwait(false),
				IpcCommand.GetRecentAlerts => await GetRecentAlertsAsync(ct).ConfigureAwait(false),
				IpcCommand.GetAddresses => await GetAddressesAsync(ct).ConfigureAwait(false),
				IpcCommand.GetSessions => await GetSessionsAsync(ct).ConfigureAwait(false),
				IpcCommand.AcknowledgeAlert => await AcknowledgeAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.BlockAddress => await BlockAddressAsync(request.Payload, true, ct).ConfigureAwait(false),
				IpcCommand.UnblockAddress => await BlockAddressAsync(request.Payload, false, ct).ConfigureAwait(false),
				IpcCommand.GetSettings => _options.CurrentValue,
				IpcCommand.SaveSettings => "Settings save not implemented in service runtime",
				_ => throw new IpcException($"Unknown command: {request.Command}"),
			};

			return new IpcResponse
			{
				Success = true,
				Payload = payload is null ? null : JsonSerializer.Serialize(payload, JsonOptions.Default),
			};
		}
		catch (Exception ex)
		{
			_logger.LogError(ex, "IPC dispatch failed for {Command}", request.Command);
			return new IpcResponse { Success = false, Error = ex.Message };
		}
	}

	private ServiceStatus BuildStatus()
	{
		Process self = Process.GetCurrentProcess();
		string version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0";
		return new ServiceStatus
		{
			Version = version,
			StartedUtc = _metrics.StartedUtc,
			Uptime = DateTime.UtcNow - _metrics.StartedUtc,
			ProcessId = self.Id,
			EventsCaptured = _metrics.EventsCaptured,
			EventsDropped = _metrics.EventsDropped,
			AlertsRaised = _metrics.AlertsRaised,
			ChannelStatus = _metrics.SnapshotChannels(),
		};
	}

	private async Task<object?> GetRecentEventsAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		return await db.RawEvents.AsNoTracking()
			.OrderByDescending(e => e.Id)
			.Take(200)
			.Select(e => new
			{
				e.Id,
				e.EventId,
				e.Channel,
				e.TimeUtc,
				e.SourceIp,
				e.UserName,
				e.Domain,
				e.LogonType,
				e.AuthPackage,
				e.ProcessName,
			})
			.ToListAsync(ct)
			.ConfigureAwait(false);
	}

	private async Task<object?> GetRecentAlertsAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		return await db.Alerts.AsNoTracking()
			.OrderByDescending(a => a.Id)
			.Take(200)
			.ToListAsync(ct)
			.ConfigureAwait(false);
	}

	private async Task<object?> GetAddressesAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		return await db.Addresses.AsNoTracking()
			.OrderByDescending(a => a.LastSeen)
			.Take(500)
			.ToListAsync(ct)
			.ConfigureAwait(false);
	}

	private async Task<object?> GetSessionsAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		return await db.Sessions.AsNoTracking()
			.OrderByDescending(s => s.ConnectUtc)
			.Take(500)
			.ToListAsync(ct)
			.ConfigureAwait(false);
	}

	private async Task<object?> AcknowledgeAsync(string? payload, CancellationToken ct)
	{
		if (string.IsNullOrEmpty(payload))
		{
			throw new IpcException("AcknowledgeAlert requires a payload with the alert id.");
		}

		long id = JsonSerializer.Deserialize<long>(payload, JsonOptions.Default);
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		var alert = await db.Alerts.FindAsync(new object?[] { id }, ct).ConfigureAwait(false);
		if (alert is null)
		{
			throw new IpcException($"Alert {id} not found.");
		}

		alert.Acknowledged = true;
		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return true;
	}

	private async Task<object?> BlockAddressAsync(string? payload, bool blocked, CancellationToken ct)
	{
		if (string.IsNullOrEmpty(payload))
		{
			throw new IpcException("BlockAddress requires a payload with the IP address.");
		}

		string ip = JsonSerializer.Deserialize<string>(payload, JsonOptions.Default)
			?? throw new IpcException("Invalid IP payload.");

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		var addr = await db.Addresses.FirstOrDefaultAsync(a => a.Ip == ip, ct).ConfigureAwait(false);
		if (addr is null)
		{
			throw new IpcException($"Address {ip} not found.");
		}

		addr.IsBlocked = blocked;
		addr.BlockReason = blocked ? "Manual block via Configurator" : null;
		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return true;
	}
}
