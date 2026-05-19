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

	public IpcDispatcher(
		IDbContextFactory<AuditDbContext> factory,
		ServiceMetrics metrics,
		IOptionsMonitor<RdpAuditOptions> options,
		SettingsManager settings,
		FirewallManager firewall,
		IEnumerable<IFirewallProvider> providers,
		ILogger<IpcDispatcher> logger)
	{
		_factory = factory;
		_metrics = metrics;
		_options = options;
		_settings = settings;
		_firewall = firewall;
		_providers = providers;
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

				// --- Reserved Stage 1 commands still awaiting later-stage implementations. ---
				IpcCommand.GetAttackStats
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
