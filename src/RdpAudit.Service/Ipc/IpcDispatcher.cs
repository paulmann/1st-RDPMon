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
using System.Net;
using System.Reflection;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
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
	private readonly IEnumerable<IFirewallProvider> _providers;
	private readonly ILogger<IpcDispatcher> _logger;
	private readonly RdpSessionManager? _sessions;
	private readonly ShadowPolicyManager? _shadow;

	public IpcDispatcher(
		IDbContextFactory<AuditDbContext> factory,
		ServiceMetrics metrics,
		IOptionsMonitor<RdpAuditOptions> options,
		SettingsManager settings,
		FirewallManager firewall,
		IEnumerable<IFirewallProvider> providers,
		ILogger<IpcDispatcher> logger,
		RdpSessionManager? sessions = null,
		ShadowPolicyManager? shadow = null)
	{
		_factory = factory;
		_metrics = metrics;
		_options = options;
		_settings = settings;
		_firewall = firewall;
		_providers = providers;
		_logger = logger;
		_sessions = sessions;
		_shadow = shadow;
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

				// --- Stage 3 handlers (backend-only). UI is deferred to a later stage. ---
				IpcCommand.GetFirewallStatus => await GetFirewallStatusAsync(ct).ConfigureAwait(false),
				IpcCommand.ListBlocklist => await ListBlocklistAsync(ct).ConfigureAwait(false),
				IpcCommand.ListWhitelist => await ListWhitelistAsync(ct).ConfigureAwait(false),
				IpcCommand.AddToBlocklist => await AddToBlocklistAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.RemoveFromBlocklist => await RemoveFromBlocklistAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.AddToWhitelist => await AddToWhitelistAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.RemoveFromWhitelist => await RemoveFromWhitelistAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.ListActiveBlocks => await ListActiveBlocksAsync(ct).ConfigureAwait(false),

				// --- Stage 5 handlers (Firewall tab UI support). ---
				IpcCommand.ListLoginRules => await ListLoginRulesAsync(ct).ConfigureAwait(false),
				IpcCommand.AddLoginRule => await AddLoginRuleAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.RemoveLoginRule => await RemoveLoginRuleAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.SetLoginRuleEnabled => await SetLoginRuleEnabledAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.ListActiveBlocksDetailed => await ListActiveBlocksDetailedAsync(ct).ConfigureAwait(false),
				IpcCommand.UnblockActiveBlock => await UnblockActiveBlockAsync(request.Payload, ct).ConfigureAwait(false),

				// --- Stage 6 handlers (Attack Statistics tab). ---
				IpcCommand.GetAttackStats => await GetAttackStatsAsync(request.Payload, ct).ConfigureAwait(false),

				// --- Stage 7 handlers (Remote RDP Clients tab). ---
				IpcCommand.ListRdpSessions => await ListRdpSessionsAsync(ct).ConfigureAwait(false),
				IpcCommand.DisconnectSession => await DisconnectSessionAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.LogoffSession => await LogoffSessionAsync(request.Payload, ct).ConfigureAwait(false),
				IpcCommand.ShadowSession => ShadowSessionPolicyCheck(request.Payload),
				IpcCommand.GetShadowPolicyStatus => GetShadowPolicyStatusHandler(),
				IpcCommand.ApplyShadowPolicy => ApplyShadowPolicyHandler(request.Payload),
				IpcCommand.BackupShadowPolicy => BackupShadowPolicyHandler(),
				IpcCommand.RestoreShadowPolicy => RestoreShadowPolicyHandler(request.Payload),

				// --- Reserved Stage 1 commands still awaiting later-stage implementations. ---
				IpcCommand.GetAbuseIpDbStatus
					or IpcCommand.TestAbuseIpDbKey
					or IpcCommand.GetMikroTikStatus
					or IpcCommand.TestMikroTik => NotImplementedResult(request.Command),
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

	// ----------------------------------------------------------------------------------------------
	// Stage 3 handlers
	// ----------------------------------------------------------------------------------------------

	private async Task<object?> GetFirewallStatusAsync(CancellationToken ct)
	{
		FirewallOptions cfg = _options.CurrentValue.Firewall;
		FirewallStatusDto dto = new()
		{
			Status = IpcResultStatus.Success,
			ConfiguredProvider = cfg.Provider,
		};

		foreach (IFirewallProvider provider in _providers)
		{
			FirewallStatusReport report;
			try
			{
				report = await provider.GetStatusAsync(ct).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "Failed to query provider {ProviderId}", provider.ProviderId);
				continue;
			}

			bool available = report.Status == FirewallProviderStatus.Available;
			if (string.Equals(provider.ProviderId, "Windows", StringComparison.OrdinalIgnoreCase))
			{
				dto.WindowsAvailable = available;
			}
			else if (string.Equals(provider.ProviderId, "MikroTik", StringComparison.OrdinalIgnoreCase))
			{
				dto.MikroTikAvailable = available;
			}
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		dto.ActiveBlockCount = await db.ActiveBlocks
			.CountAsync(b => b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending, ct)
			.ConfigureAwait(false);
		dto.WhitelistCount = await db.WhitelistEntries.CountAsync(ct).ConfigureAwait(false);
		dto.BlacklistCount = await db.BlocklistEntries.CountAsync(b => b.IsEnabled, ct).ConfigureAwait(false);
		dto.Message = "Stage 3 firewall status snapshot.";
		return dto;
	}

	private async Task<object?> ListBlocklistAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<BlocklistEntry> rows = await db.BlocklistEntries.AsNoTracking()
			.OrderByDescending(b => b.AddedUtc)
			.Take(2000)
			.ToListAsync(ct).ConfigureAwait(false);

		return rows.ConvertAll(b => new AddressListEntryDto
		{
			Address = b.Ip ?? b.Login ?? string.Empty,
			Note = b.Reason,
			AddedUtc = b.AddedUtc,
			ExpiresUtc = b.ExpiresUtc,
			Source = b.Source.ToString(),
		});
	}

	private async Task<object?> ListWhitelistAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<WhitelistEntry> rows = await db.WhitelistEntries.AsNoTracking()
			.OrderByDescending(w => w.AddedUtc)
			.Take(2000)
			.ToListAsync(ct).ConfigureAwait(false);

		return rows.ConvertAll(w => new AddressListEntryDto
		{
			Address = w.Ip,
			Note = w.Note,
			AddedUtc = w.AddedUtc,
			ExpiresUtc = null,
			Source = w.AddedBy ?? "Configurator",
		});
	}

	private async Task<object?> AddToBlocklistAsync(string? payload, CancellationToken ct)
	{
		AddressListMutationRequest req = DeserializeMutation(payload, "AddToBlocklist");
		string ip = NormalizeAndValidateAddress(req.Address);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		// Whitelist precedence: refuse to add a row that contradicts an active whitelist entry.
		bool whitelisted = await db.WhitelistEntries.AnyAsync(w => w.Ip == ip, ct).ConfigureAwait(false);
		if (whitelisted)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"Cannot add {0} to blocklist: it is whitelisted.", ip));
		}

		DateTime nowUtc = DateTime.UtcNow;
		DateTime? expiresUtc = req.DurationMinutes > 0 ? nowUtc.AddMinutes(req.DurationMinutes) : null;

		BlocklistEntry? existing = await db.BlocklistEntries
			.FirstOrDefaultAsync(b => b.Ip == ip && b.IsEnabled, ct).ConfigureAwait(false);

		if (existing is null)
		{
			db.BlocklistEntries.Add(new BlocklistEntry
			{
				Ip = ip,
				Reason = string.IsNullOrWhiteSpace(req.Note) ? "Configurator manual add" : req.Note!,
				AddedUtc = nowUtc,
				ExpiresUtc = expiresUtc,
				Source = BlocklistSource.Manual,
				IsEnabled = true,
			});
		}
		else
		{
			existing.ExpiresUtc = expiresUtc;
			if (!string.IsNullOrWhiteSpace(req.Note))
			{
				existing.Reason = req.Note!;
			}
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return new { status = IpcResultStatus.Success.ToString(), address = ip };
	}

	private async Task<object?> RemoveFromBlocklistAsync(string? payload, CancellationToken ct)
	{
		AddressListMutationRequest req = DeserializeMutation(payload, "RemoveFromBlocklist");
		string ip = NormalizeAndValidateAddress(req.Address);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<BlocklistEntry> rows = await db.BlocklistEntries
			.Where(b => b.Ip == ip && b.IsEnabled).ToListAsync(ct).ConfigureAwait(false);
		foreach (BlocklistEntry row in rows)
		{
			row.IsEnabled = false;
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return new { status = IpcResultStatus.Success.ToString(), address = ip, removed = rows.Count };
	}

	private async Task<object?> AddToWhitelistAsync(string? payload, CancellationToken ct)
	{
		AddressListMutationRequest req = DeserializeMutation(payload, "AddToWhitelist");
		string ip = NormalizeAndValidateAddress(req.Address);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		WhitelistEntry? existing = await db.WhitelistEntries
			.FirstOrDefaultAsync(w => w.Ip == ip, ct).ConfigureAwait(false);
		if (existing is null)
		{
			db.WhitelistEntries.Add(new WhitelistEntry
			{
				Ip = ip,
				Note = string.IsNullOrWhiteSpace(req.Note) ? "Configurator manual add" : req.Note,
				AddedUtc = DateTime.UtcNow,
				AddedBy = "Configurator",
			});
		}
		else
		{
			existing.Note = string.IsNullOrWhiteSpace(req.Note) ? existing.Note : req.Note;
		}

		// Whitelist precedence: disable any active blocklist rows that reference this IP.
		List<BlocklistEntry> conflicting = await db.BlocklistEntries
			.Where(b => b.Ip == ip && b.IsEnabled).ToListAsync(ct).ConfigureAwait(false);
		foreach (BlocklistEntry row in conflicting)
		{
			row.IsEnabled = false;
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return new { status = IpcResultStatus.Success.ToString(), address = ip };
	}

	private async Task<object?> RemoveFromWhitelistAsync(string? payload, CancellationToken ct)
	{
		AddressListMutationRequest req = DeserializeMutation(payload, "RemoveFromWhitelist");
		string ip = NormalizeAndValidateAddress(req.Address);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		WhitelistEntry? existing = await db.WhitelistEntries
			.FirstOrDefaultAsync(w => w.Ip == ip, ct).ConfigureAwait(false);

		if (existing is not null)
		{
			db.WhitelistEntries.Remove(existing);
			await db.SaveChangesAsync(ct).ConfigureAwait(false);
		}

		return new { status = IpcResultStatus.Success.ToString(), address = ip, removed = existing is not null };
	}

	private async Task<object?> ListActiveBlocksAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<ActiveBlock> rows = await db.ActiveBlocks.AsNoTracking()
			.OrderByDescending(b => b.CreatedUtc)
			.Take(2000)
			.ToListAsync(ct).ConfigureAwait(false);

		return rows.ConvertAll(b => new AddressListEntryDto
		{
			Address = b.Ip,
			Note = string.IsNullOrEmpty(b.LastError) ? b.Reason : b.Reason + " (" + b.LastError + ")",
			AddedUtc = b.CreatedUtc,
			ExpiresUtc = b.ExpiresUtc,
			Source = b.Provider.ToString() + ":" + b.Status,
		});
	}

	private static AddressListMutationRequest DeserializeMutation(string? payload, string commandName)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} requires a JSON payload with an Address field.", commandName));
		}

		AddressListMutationRequest? parsed;
		try
		{
			parsed = JsonSerializer.Deserialize<AddressListMutationRequest>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} payload is not valid JSON: {1}", commandName, ex.Message));
		}

		if (parsed is null || string.IsNullOrWhiteSpace(parsed.Address))
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} requires an Address field.", commandName));
		}
		return parsed;
	}

	private static string NormalizeAndValidateAddress(string address)
	{
		if (string.IsNullOrWhiteSpace(address))
		{
			throw new IpcException("Address must not be empty.");
		}

		string trimmed = address.Trim();
		if (!IPAddress.TryParse(trimmed, out IPAddress? parsed))
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"Address '{0}' is not a valid IPv4 / IPv6 address.", trimmed));
		}
		return parsed.ToString();
	}

	// ----------------------------------------------------------------------------------------------
	// Stage 5 handlers
	// ----------------------------------------------------------------------------------------------

	private async Task<object?> ListLoginRulesAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<LoginRule> rows = await db.LoginRules.AsNoTracking()
			.OrderByDescending(r => r.AddedUtc)
			.Take(2000)
			.ToListAsync(ct).ConfigureAwait(false);

		return rows.ConvertAll(r => new LoginRuleDto
		{
			Id = r.Id,
			Login = r.Login,
			Note = r.Note,
			Enabled = r.Enabled,
			AddedUtc = r.AddedUtc,
		});
	}

	private async Task<object?> AddLoginRuleAsync(string? payload, CancellationToken ct)
	{
		LoginRuleMutationRequest req = DeserializeLoginRuleRequest(payload, "AddLoginRule");
		string login = NormalizeAndValidateLogin(req.Login);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		LoginRule? existing = await db.LoginRules
			.FirstOrDefaultAsync(r => r.Login == login, ct).ConfigureAwait(false);

		if (existing is null)
		{
			db.LoginRules.Add(new LoginRule
			{
				Login = login,
				Note = string.IsNullOrWhiteSpace(req.Note) ? "Configurator manual add" : req.Note,
				Enabled = true,
				AddedUtc = DateTime.UtcNow,
			});
		}
		else
		{
			existing.Enabled = true;
			if (!string.IsNullOrWhiteSpace(req.Note))
			{
				existing.Note = req.Note;
			}
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return new { status = IpcResultStatus.Success.ToString(), login };
	}

	private async Task<object?> RemoveLoginRuleAsync(string? payload, CancellationToken ct)
	{
		LoginRuleMutationRequest req = DeserializeLoginRuleRequest(payload, "RemoveLoginRule");

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		LoginRule? target = null;
		if (req.Id > 0)
		{
			target = await db.LoginRules.FirstOrDefaultAsync(r => r.Id == req.Id, ct).ConfigureAwait(false);
		}

		if (target is null && !string.IsNullOrWhiteSpace(req.Login))
		{
			string login = NormalizeAndValidateLogin(req.Login);
			target = await db.LoginRules.FirstOrDefaultAsync(r => r.Login == login, ct).ConfigureAwait(false);
		}

		if (target is null)
		{
			throw new IpcException("Login rule not found.");
		}

		db.LoginRules.Remove(target);
		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return new { status = IpcResultStatus.Success.ToString(), id = target.Id, login = target.Login };
	}

	private async Task<object?> SetLoginRuleEnabledAsync(string? payload, CancellationToken ct)
	{
		LoginRuleMutationRequest req = DeserializeLoginRuleRequest(payload, "SetLoginRuleEnabled");
		if (req.Id <= 0)
		{
			throw new IpcException("SetLoginRuleEnabled requires a positive Id.");
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		LoginRule? target = await db.LoginRules.FirstOrDefaultAsync(r => r.Id == req.Id, ct).ConfigureAwait(false);
		if (target is null)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"Login rule {0} not found.", req.Id));
		}

		target.Enabled = req.Enabled;
		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return new { status = IpcResultStatus.Success.ToString(), id = target.Id, enabled = target.Enabled };
	}

	private async Task<object?> ListActiveBlocksDetailedAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<ActiveBlock> rows = await db.ActiveBlocks.AsNoTracking()
			.OrderByDescending(b => b.CreatedUtc)
			.Take(2000)
			.ToListAsync(ct).ConfigureAwait(false);

		return rows.ConvertAll(b => new ActiveBlockDto
		{
			Id = b.Id,
			Ip = b.Ip,
			Provider = b.Provider,
			RuleHandle = b.RuleHandle,
			CreatedUtc = b.CreatedUtc,
			ExpiresUtc = b.ExpiresUtc,
			Reason = b.Reason,
			Status = b.Status,
			LastError = b.LastError,
		});
	}

	private async Task<object?> UnblockActiveBlockAsync(string? payload, CancellationToken ct)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException("UnblockActiveBlock requires a JSON payload with the row Id.");
		}

		long id;
		try
		{
			id = JsonSerializer.Deserialize<long>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException("UnblockActiveBlock payload is not a valid Id: " + ex.Message);
		}

		if (id <= 0)
		{
			throw new IpcException("UnblockActiveBlock requires a positive Id.");
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		ActiveBlock? row = await db.ActiveBlocks.FirstOrDefaultAsync(b => b.Id == id, ct).ConfigureAwait(false);
		if (row is null)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"ActiveBlock {0} not found.", id));
		}

		string ip = row.Ip;
		bool providerOk = true;
		string? providerError = null;

		if (row.Provider == FirewallProviderKind.Windows && OperatingSystem.IsWindows())
		{
			try
			{
				FirewallOperationResult res = await _firewall.UnblockAsync(
					_options.CurrentValue.Firewall.BlockRuleName, ip, ct).ConfigureAwait(false);
				providerOk = res.Success || res.ExitCode == 1;
				if (!providerOk)
				{
					providerError = "netsh exit " + res.ExitCode.ToString(CultureInfo.InvariantCulture);
				}
			}
			catch (Exception ex)
			{
				providerOk = false;
				providerError = ex.GetType().Name;
				_logger.LogWarning(ex, "Provider unblock failed for {Ip}", ip);
			}
		}

		row.Status = providerOk ? ActiveBlockStatus.Removed : ActiveBlockStatus.Failed;
		row.LastError = providerError;

		List<BlocklistEntry> related = await db.BlocklistEntries
			.Where(b => b.Ip == ip && b.IsEnabled).ToListAsync(ct).ConfigureAwait(false);
		foreach (BlocklistEntry entry in related)
		{
			entry.IsEnabled = false;
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return new
		{
			status = (providerOk ? IpcResultStatus.Success : IpcResultStatus.Unavailable).ToString(),
			id = row.Id,
			address = ip,
			providerOk,
			providerError,
			blocklistDisabled = related.Count,
		};
	}

	private static LoginRuleMutationRequest DeserializeLoginRuleRequest(string? payload, string commandName)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} requires a JSON payload.", commandName));
		}

		LoginRuleMutationRequest? parsed;
		try
		{
			parsed = JsonSerializer.Deserialize<LoginRuleMutationRequest>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} payload is not valid JSON: {1}", commandName, ex.Message));
		}

		if (parsed is null)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} payload could not be parsed.", commandName));
		}
		return parsed;
	}

	// ----------------------------------------------------------------------------------------------
	// Stage 6 handlers
	// ----------------------------------------------------------------------------------------------

	/// <summary>Default cap on rows returned by <c>GetAttackStats</c> when no limit is supplied.</summary>
	internal const int AttackStatsDefaultLimit = 500;

	/// <summary>Upper bound on rows returned by <c>GetAttackStats</c> regardless of caller intent.</summary>
	internal const int AttackStatsMaxLimit = 2000;

	private async Task<object?> GetAttackStatsAsync(string? payload, CancellationToken ct)
	{
		AttackStatsRequest req = ParseAttackStatsRequest(payload);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		DateTime windowEnd = req.UntilUtc ?? DateTime.UtcNow;
		DateTime windowStart = req.SinceUtc ?? (windowEnd - TimeSpan.FromDays(7));

		IQueryable<AttackStat> q = db.AttackStats.AsNoTracking();

		if (!string.IsNullOrWhiteSpace(req.IpQuery))
		{
			string needle = req.IpQuery.Trim();
			q = q.Where(s => EF.Functions.Like(s.Ip, "%" + needle + "%"));
		}

		if (req.MinThreatScore.HasValue)
		{
			double min = req.MinThreatScore.Value;
			q = q.Where(s => s.ThreatScore >= min);
		}

		if (req.OnlyBlocked)
		{
			q = q.Where(s => s.IsBlocked);
		}

		if (req.SinceUtc.HasValue)
		{
			DateTime since = req.SinceUtc.Value;
			q = q.Where(s => s.LastSeenUtc >= since);
		}

		if (req.UntilUtc.HasValue)
		{
			DateTime until = req.UntilUtc.Value;
			q = q.Where(s => s.LastSeenUtc <= until);
		}

		int totalMatching = await q.CountAsync(ct).ConfigureAwait(false);

		int limit = req.Limit <= 0 ? AttackStatsDefaultLimit : req.Limit;
		if (limit > AttackStatsMaxLimit)
		{
			limit = AttackStatsMaxLimit;
		}

		List<AttackStat> rows = await q
			.OrderByDescending(s => s.LastSeenUtc)
			.ThenByDescending(s => s.ThreatScore)
			.ThenBy(s => s.Ip)
			.Take(limit)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		// Window summary counters — computed against RawEvents in the requested window so they line
		// up with what the per-IP rows describe.
		long failed = await db.RawEvents.AsNoTracking()
			.Where(e => e.TimeUtc >= windowStart && e.TimeUtc <= windowEnd && e.EventId == AttackStatsAggregator.EventIdLogonFailure)
			.LongCountAsync(ct).ConfigureAwait(false);
		long successful = await db.RawEvents.AsNoTracking()
			.Where(e => e.TimeUtc >= windowStart && e.TimeUtc <= windowEnd && e.EventId == AttackStatsAggregator.EventIdLogonSuccess)
			.LongCountAsync(ct).ConfigureAwait(false);
		long distinctIps = await db.RawEvents.AsNoTracking()
			.Where(e => e.TimeUtc >= windowStart && e.TimeUtc <= windowEnd && e.SourceIp != null && e.SourceIp != string.Empty)
			.Select(e => e.SourceIp!)
			.Distinct()
			.LongCountAsync(ct).ConfigureAwait(false);
		long alertsRaised = await db.Alerts.AsNoTracking()
			.Where(a => a.TimeUtc >= windowStart && a.TimeUtc <= windowEnd)
			.LongCountAsync(ct).ConfigureAwait(false);
		long autoBlocked = await db.ActiveBlocks.AsNoTracking()
			.Where(b => b.CreatedUtc >= windowStart && b.CreatedUtc <= windowEnd
				&& (b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending))
			.LongCountAsync(ct).ConfigureAwait(false);

		AttackStatsDto dto = new()
		{
			Status = IpcResultStatus.Success,
			WindowStartUtc = windowStart,
			WindowEndUtc = windowEnd,
			FailedLogons = failed,
			SuccessfulLogons = successful,
			DistinctSourceIps = distinctIps,
			AlertsRaised = alertsRaised,
			AddressesAutoBlocked = autoBlocked,
			Message = string.Format(CultureInfo.InvariantCulture,
				"Stage 6 attack statistics snapshot. matching={0} returned={1}",
				totalMatching, rows.Count),
			TotalMatching = totalMatching,
			AppliedLimit = limit,
		};

		foreach (AttackStat row in rows)
		{
			dto.Entries.Add(new AttackStatEntryDto
			{
				Ip = row.Ip,
				TotalAttempts = row.TotalAttempts,
				Successful = row.Successful,
				Failed = row.Failed,
				FirstSeenUtc = row.FirstSeenUtc,
				LastSeenUtc = row.LastSeenUtc,
				DurationSeconds = row.DurationSeconds,
				Top10AttemptedLogins = row.Top10AttemptedLogins,
				LastLoginType = row.LastLoginType,
				ThreatScore = row.ThreatScore,
				ThreatLevel = AttackThreatScoring.ClassifyScore(row.ThreatScore),
				IsBlocked = row.IsBlocked,
				LastUpdatedUtc = row.LastUpdatedUtc,
			});
		}

		return dto;
	}

	private static AttackStatsRequest ParseAttackStatsRequest(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			return new AttackStatsRequest();
		}

		try
		{
			AttackStatsRequest? parsed = JsonSerializer.Deserialize<AttackStatsRequest>(payload, JsonOptions.Default);
			return parsed ?? new AttackStatsRequest();
		}
		catch (JsonException ex)
		{
			throw new IpcException("GetAttackStats payload is not valid JSON: " + ex.Message);
		}
	}

	// ----------------------------------------------------------------------------------------------
	// Stage 7 handlers — Remote RDP Clients tab.
	// ----------------------------------------------------------------------------------------------

	private async Task<object?> ListRdpSessionsAsync(CancellationToken ct)
	{
		if (!OperatingSystem.IsWindows() || _sessions is null)
		{
			return new RdpSessionListDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "Session enumeration is only available on Windows hosts.",
				QueriedUtc = DateTime.UtcNow,
			};
		}

		RdpSessionListDto list = await _sessions.ListAsync(ct).ConfigureAwait(false);

		// Best-effort source IP correlation from the RawEvents table for active sessions.
		if (list.Sessions.Count > 0)
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
			DateTime cutoff = DateTime.UtcNow - TimeSpan.FromDays(1);
			Dictionary<string, string> userToIp = new(StringComparer.OrdinalIgnoreCase);
			List<(string User, string? Ip)> recent = await db.RawEvents
				.AsNoTracking()
				.Where(e => e.TimeUtc >= cutoff && e.UserName != null && e.SourceIp != null && e.SourceIp != string.Empty)
				.OrderByDescending(e => e.TimeUtc)
				.Take(2000)
				.Select(e => new ValueTuple<string, string?>(e.UserName!, e.SourceIp))
				.ToListAsync(ct).ConfigureAwait(false);
			foreach ((string user, string? ip) in recent)
			{
				if (!string.IsNullOrEmpty(ip) && !userToIp.ContainsKey(user))
				{
					userToIp[user] = ip!;
				}
			}

			foreach (RdpSessionDto session in list.Sessions)
			{
				if (string.IsNullOrEmpty(session.ClientAddress)
					&& !string.IsNullOrEmpty(session.UserName)
					&& userToIp.TryGetValue(session.UserName, out string? ip))
				{
					session.ClientAddress = ip;
				}
			}
		}

		return list;
	}

	private async Task<object?> DisconnectSessionAsync(string? payload, CancellationToken ct)
	{
		SessionActionRequest req = DeserializeSessionRequest(payload, "DisconnectSession");
		if (!OperatingSystem.IsWindows() || _sessions is null)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.Unavailable,
				SessionId = req.SessionId,
				Message = "Session control is only available on Windows hosts.",
			};
		}

		if (!_options.CurrentValue.SessionControl.Enabled || !_options.CurrentValue.SessionControl.AllowDisconnect)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.Refused,
				SessionId = req.SessionId,
				Message = "Disconnect is disabled by SessionControl policy.",
			};
		}

		_logger.LogInformation("Operator-issued disconnect for session {Id} reason='{Reason}'",
			req.SessionId, req.Reason ?? string.Empty);
		return await _sessions.DisconnectAsync(req.SessionId, ct).ConfigureAwait(false);
	}

	private async Task<object?> LogoffSessionAsync(string? payload, CancellationToken ct)
	{
		SessionActionRequest req = DeserializeSessionRequest(payload, "LogoffSession");
		if (!OperatingSystem.IsWindows() || _sessions is null)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.Unavailable,
				SessionId = req.SessionId,
				Message = "Session control is only available on Windows hosts.",
			};
		}

		if (!_options.CurrentValue.SessionControl.Enabled || !_options.CurrentValue.SessionControl.AllowLogoff)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.Refused,
				SessionId = req.SessionId,
				Message = "Logoff is disabled by SessionControl policy.",
			};
		}

		_logger.LogInformation("Operator-issued logoff for session {Id} reason='{Reason}'",
			req.SessionId, req.Reason ?? string.Empty);
		return await _sessions.LogoffAsync(req.SessionId, ct).ConfigureAwait(false);
	}

	/// <summary>The actual <c>mstsc.exe /shadow</c> spawn must happen in the operator's interactive
	/// desktop session — the service runs under LocalSystem and cannot launch interactive UI. This
	/// handler therefore only enforces policy and returns a Success/Refused result; the Configurator
	/// is responsible for spawning mstsc with sanitized arguments built by the same Core helper.</summary>
	private SessionActionResult ShadowSessionPolicyCheck(string? payload)
	{
		SessionActionRequest req = DeserializeSessionRequest(payload, "ShadowSession");
		if (!OperatingSystem.IsWindows())
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.Unavailable,
				SessionId = req.SessionId,
				Message = "Shadow is only available on Windows hosts.",
			};
		}

		SessionControlOptions cfg = _options.CurrentValue.SessionControl;
		if (!cfg.Enabled || !cfg.AllowShadow)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.Refused,
				SessionId = req.SessionId,
				Message = "Shadow is disabled by SessionControl policy.",
			};
		}

		SessionIdValidation v = SessionCommandBuilder.ValidateSessionId(req.SessionId);
		if (!v.Ok)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.InvalidRequest,
				SessionId = req.SessionId,
				Message = v.Error,
			};
		}

		if (cfg.RequireShadowPolicy && _shadow is not null)
		{
			ShadowPolicyStatusDto status = _shadow.GetStatus();
			ShadowPolicyMode policy = ShadowPolicyModel.FromRawValue(status.ShadowMode);
			SessionCommandBuilder.ShadowMode requested = req.ShadowMode switch
			{
				1 => SessionCommandBuilder.ShadowMode.Control,
				2 => SessionCommandBuilder.ShadowMode.ControlNoConsent,
				_ => SessionCommandBuilder.ShadowMode.ViewOnly,
			};
			if (!ShadowPolicyModel.AllowsMode(policy, requested))
			{
				return new SessionActionResult
				{
					Status = IpcResultStatus.Refused,
					SessionId = req.SessionId,
					Message = string.Format(CultureInfo.InvariantCulture,
						"Shadow {0} refused — current policy '{1}' does not permit it. Use Apply Shadow Policy first.",
						requested, ShadowPolicyModel.Describe(policy)),
				};
			}
		}

		_logger.LogInformation("Operator-approved shadow request for session {Id} mode={Mode} reason='{Reason}'",
			req.SessionId, req.ShadowMode, req.Reason ?? string.Empty);
		return new SessionActionResult
		{
			Status = IpcResultStatus.Success,
			SessionId = req.SessionId,
			Message = "Shadow request approved by policy. Configurator must launch mstsc in the operator's desktop.",
		};
	}

	private ShadowPolicyStatusDto GetShadowPolicyStatusHandler()
	{
		if (!OperatingSystem.IsWindows() || _shadow is null)
		{
			return new ShadowPolicyStatusDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "Shadow policy management is only available on Windows hosts.",
			};
		}

		return _shadow.GetStatus();
	}

	private ShadowPolicyStatusDto ApplyShadowPolicyHandler(string? payload)
	{
		if (!OperatingSystem.IsWindows() || _shadow is null)
		{
			return new ShadowPolicyStatusDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "Shadow policy management is only available on Windows hosts.",
			};
		}

		ShadowPolicyApplyRequest req = DeserializeApplyRequest(payload);
		_logger.LogInformation(
			"Operator-issued ApplyShadowPolicy mode={Mode} enableAll={Enable} backup={Backup} reason='{Reason}'",
			req.ShadowMode, req.EnableAllPermissions, req.TakeBackupFirst, req.Reason ?? string.Empty);
		return _shadow.Apply(req);
	}

	private ShadowPolicyStatusDto BackupShadowPolicyHandler()
	{
		if (!OperatingSystem.IsWindows() || _shadow is null)
		{
			return new ShadowPolicyStatusDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "Shadow policy management is only available on Windows hosts.",
			};
		}

		_logger.LogInformation("Operator-issued BackupShadowPolicy");
		return _shadow.Backup();
	}

	private ShadowPolicyStatusDto RestoreShadowPolicyHandler(string? payload)
	{
		if (!OperatingSystem.IsWindows() || _shadow is null)
		{
			return new ShadowPolicyStatusDto
			{
				Status = IpcResultStatus.Unavailable,
				Message = "Shadow policy management is only available on Windows hosts.",
			};
		}

		string? snapshotId = null;
		if (!string.IsNullOrWhiteSpace(payload))
		{
			try
			{
				snapshotId = JsonSerializer.Deserialize<string>(payload, JsonOptions.Default);
			}
			catch (JsonException ex)
			{
				throw new IpcException("RestoreShadowPolicy payload is not a valid JSON string: " + ex.Message);
			}
		}

		_logger.LogInformation("Operator-issued RestoreShadowPolicy snapshot='{Snapshot}'", snapshotId ?? string.Empty);
		return _shadow.Restore(snapshotId);
	}

	private static SessionActionRequest DeserializeSessionRequest(string? payload, string commandName)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} requires a JSON payload with the SessionId.", commandName));
		}

		SessionActionRequest? parsed;
		try
		{
			parsed = JsonSerializer.Deserialize<SessionActionRequest>(payload, JsonOptions.Default);
		}
		catch (JsonException ex)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} payload is not valid JSON: {1}", commandName, ex.Message));
		}

		if (parsed is null)
		{
			throw new IpcException(string.Format(CultureInfo.InvariantCulture,
				"{0} payload could not be parsed.", commandName));
		}

		SessionIdValidation v = SessionCommandBuilder.ValidateSessionId(parsed.SessionId);
		if (!v.Ok)
		{
			throw new IpcException(v.Error ?? "Invalid SessionId.");
		}

		return parsed;
	}

	private static ShadowPolicyApplyRequest DeserializeApplyRequest(string? payload)
	{
		if (string.IsNullOrWhiteSpace(payload))
		{
			return new ShadowPolicyApplyRequest();
		}

		try
		{
			ShadowPolicyApplyRequest? parsed = JsonSerializer.Deserialize<ShadowPolicyApplyRequest>(payload, JsonOptions.Default);
			return parsed ?? new ShadowPolicyApplyRequest();
		}
		catch (JsonException ex)
		{
			throw new IpcException("ApplyShadowPolicy payload is not valid JSON: " + ex.Message);
		}
	}

	// ----------------------------------------------------------------------------------------------

	private static string NormalizeAndValidateLogin(string login)
	{
		if (string.IsNullOrWhiteSpace(login))
		{
			throw new IpcException("Login must not be empty.");
		}

		string trimmed = login.Trim();
		if (trimmed.Length > 256)
		{
			throw new IpcException("Login is too long (max 256 characters).");
		}

		foreach (char c in trimmed)
		{
			if (char.IsControl(c))
			{
				throw new IpcException("Login contains control characters.");
			}
		}

		return trimmed.ToLowerInvariant();
	}
}
