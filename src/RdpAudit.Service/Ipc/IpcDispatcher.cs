// File:    src/RdpAudit.Service/Ipc/IpcDispatcher.cs
// Module:  RdpAudit.Service.Ipc
// Purpose: Dispatches IpcRequests to handlers and produces an IpcResponse.
//          Server-side errors are logged with full exception details; the client receives a
//          sanitised, generic error string only — never raw exception messages or stack traces.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;
using RdpAudit.Service.Services;

namespace RdpAudit.Service.Ipc;

/// <summary>Dispatches IpcRequests to handlers and produces an IpcResponse.</summary>
public sealed class IpcDispatcher
{
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly ServiceMetrics _metrics;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly SettingsManager _settings;
	private readonly FirewallManager _firewall;
	private readonly ILogger<IpcDispatcher> _logger;

	public IpcDispatcher(
		IDbContextFactory<AuditDbContext> factory,
		ServiceMetrics metrics,
		IOptionsMonitor<RdpAuditOptions> options,
		SettingsManager settings,
		FirewallManager firewall,
		ILogger<IpcDispatcher> logger)
	{
		_factory = factory;
		_metrics = metrics;
		_options = options;
		_settings = settings;
		_firewall = firewall;
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
				IpcCommand.SaveSettings => SaveSettings(request.Payload),

				// --- Stage 1 reservations: stable command surface, handlers deferred to later stages. ---
				IpcCommand.GetFirewallStatus
					or IpcCommand.ListBlocklist
					or IpcCommand.ListWhitelist
					or IpcCommand.AddToBlocklist
					or IpcCommand.RemoveFromBlocklist
					or IpcCommand.AddToWhitelist
					or IpcCommand.RemoveFromWhitelist
					or IpcCommand.GetAttackStats
					or IpcCommand.ListRdpSessions
					or IpcCommand.DisconnectSession
					or IpcCommand.LogoffSession
					or IpcCommand.ShadowSession
					or IpcCommand.GetShadowPolicyStatus
					or IpcCommand.ApplyShadowPolicy
					or IpcCommand.BackupShadowPolicy
					or IpcCommand.RestoreShadowPolicy
					or IpcCommand.GetAbuseIpDbStatus
					or IpcCommand.TestAbuseIpDbKey
					or IpcCommand.GetMikroTikStatus
					or IpcCommand.TestMikroTik
					or IpcCommand.ListActiveBlocks => NotImplementedResult(request.Command),
				_ => throw new IpcException(string.Format(CultureInfo.InvariantCulture, "Unknown command: {0}", request.Command)),
			};

			return new IpcResponse
			{
				Success = true,
				Payload = payload is null ? null : JsonSerializer.Serialize(payload, JsonOptions.Default),
			};
		}
		catch (IpcException ex)
		{
			// IpcException is a controlled error class — its Message is curated and safe to surface.
			_logger.LogWarning(ex, "IPC dispatch returned controlled error for {Command}", request.Command);
			return new IpcResponse { Success = false, Error = ex.Message };
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			return new IpcResponse { Success = false, Error = "Request cancelled." };
		}
		catch (Exception ex)
		{
			// Log full exception server-side; surface only generic class to the client.
			_logger.LogError(ex, "IPC dispatch failed for {Command}", request.Command);
			return new IpcResponse
			{
				Success = false,
				Error = string.Format(CultureInfo.InvariantCulture,
					"Internal service error processing {0}. See service logs for details.",
					request.Command),
			};
		}
	}

	private static object NotImplementedResult(IpcCommand command) => new
	{
		status = IpcResultStatus.NotImplemented.ToString(),
		command = command.ToString(),
		message = "Command is reserved in Stage 1 but its handler is not yet implemented.",
	};

	private ServiceStatus BuildStatus()
	{
		using Process self = Process.GetCurrentProcess();
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
			throw new IpcException(string.Format(CultureInfo.InvariantCulture, "Alert {0} not found.", id));
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
			throw new IpcException(string.Format(CultureInfo.InvariantCulture, "Address {0} not found.", ip));
		}

		addr.IsBlocked = blocked;
		addr.BlockReason = blocked ? "Manual block via Configurator" : null;
		await db.SaveChangesAsync(ct).ConfigureAwait(false);

		// Apply (or remove) the firewall block rule. On non-Windows hosts (tests) skip silently.
		if (OperatingSystem.IsWindows())
		{
			await ApplyFirewallChangeAsync(ip, blocked, ct).ConfigureAwait(false);
		}

		return true;
	}

	[SupportedOSPlatform("windows")]
	private async Task ApplyFirewallChangeAsync(string ip, bool blocked, CancellationToken ct)
	{
		string ruleName = _options.CurrentValue.Firewall.BlockRuleName;
		if (string.IsNullOrWhiteSpace(ruleName))
		{
			ruleName = "RdpAudit-Block";
		}

		FirewallOperationResult result = blocked
			? await _firewall.BlockAsync(ruleName, ip, ct).ConfigureAwait(false)
			: await _firewall.UnblockAsync(ruleName, ip, ct).ConfigureAwait(false);
		if (!result.Success)
		{
			_logger.LogWarning("Firewall {Action} for {Ip} returned exit={Exit}",
				blocked ? "block" : "unblock", ip, result.ExitCode);
		}
	}

	private object SaveSettings(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("SaveSettings requires a JSON payload.");
		}

		// The IPC payload is the JSON document string wrapped in a single string by JsonSerializer at client.
		// Accept either form: a direct JSON-string payload (escaped string) or a raw JSON document.
		string body = payload;
		if (body.Length > 0 && body[0] == '"')
		{
			try
			{
				string? unwrapped = JsonSerializer.Deserialize<string>(payload, JsonOptions.Default);
				if (!string.IsNullOrWhiteSpace(unwrapped))
				{
					body = unwrapped;
				}
			}
			catch (JsonException)
			{
				// not a wrapped string — use as-is.
			}
		}

		try
		{
			_settings.Save(body);
			return new { saved = true };
		}
		catch (JsonException ex)
		{
			throw new IpcException("Settings JSON is invalid: " + ex.Message);
		}
		catch (InvalidOperationException ex)
		{
			throw new IpcException(ex.Message);
		}
	}
}
