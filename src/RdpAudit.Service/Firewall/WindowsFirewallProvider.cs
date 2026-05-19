// File:    src/RdpAudit.Service/Firewall/WindowsFirewallProvider.cs
// Module:  RdpAudit.Service.Firewall
// Purpose: Real IFirewallProvider implementation for Windows Advanced Firewall. Drives
//          netsh advfirewall through a sanitised ProcessStartInfo.ArgumentList — no shell
//          string concatenation is ever performed across IP / rule-name / reason boundaries.
//          Validates every IP via IPAddress.TryParse, applies an explicit reserved-address
//          policy, sanitises rule names, and emits idempotent block / unblock operations.
// Extends: RdpAudit.Core.Firewall.IFirewallProvider
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Firewall;

namespace RdpAudit.Service.Firewall;

/// <summary>Real <see cref="IFirewallProvider"/> implementation backed by netsh advfirewall.</summary>
/// <remarks>
/// Implementation invariants:
/// <list type="bullet">
///   <item>Every IP is validated with <see cref="IPAddress.TryParse(string, out IPAddress?)"/>.</item>
///   <item>Reserved / private / loopback addresses are refused by default to prevent self-DoS.</item>
///   <item>Rule names follow the deterministic <c>{prefix}-{normalized-ip}</c> form.</item>
///   <item>Block / unblock are idempotent: re-applying installs nothing new, re-removing is non-fatal.</item>
///   <item>Only RdpAudit-prefixed rules are ever touched on unblock — third-party rules are safe.</item>
/// </list>
/// </remarks>
public sealed class WindowsFirewallProvider : IFirewallProvider
{
	private readonly ILogger<WindowsFirewallProvider> _logger;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly INetshRunner _runner;

	public WindowsFirewallProvider(
		ILogger<WindowsFirewallProvider> logger,
		IOptionsMonitor<RdpAuditOptions> options)
		: this(logger, options, new NetshRunner())
	{
	}

	internal WindowsFirewallProvider(
		ILogger<WindowsFirewallProvider> logger,
		IOptionsMonitor<RdpAuditOptions> options,
		INetshRunner runner)
	{
		ArgumentNullException.ThrowIfNull(logger);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(runner);
		_logger = logger;
		_options = options;
		_runner = runner;
	}

	public string ProviderId => "Windows";

	public async Task<FirewallStatusReport> GetStatusAsync(CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		if (!OperatingSystem.IsWindows())
		{
			return new FirewallStatusReport
			{
				Status = FirewallProviderStatus.Unreachable,
				ProviderId = ProviderId,
				Message = "Windows Advanced Firewall is only available on Windows hosts.",
			};
		}

		NetshResult result;
		try
		{
			result = await _runner.RunAsync(NetshCommandBuilder.BuildShowAllProfilesStateArgs(), ct).ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "Failed to query firewall state via netsh");
			return new FirewallStatusReport
			{
				Status = FirewallProviderStatus.Unreachable,
				ProviderId = ProviderId,
				Message = "Failed to query firewall state.",
			};
		}

		if (!result.Success)
		{
			_logger.LogWarning("netsh show allprofiles state returned exit={Exit}", result.ExitCode);
			return new FirewallStatusReport
			{
				Status = FirewallProviderStatus.Unreachable,
				ProviderId = ProviderId,
				Message = "netsh returned non-zero status when querying firewall state.",
			};
		}

		bool anyOn = result.StdOut.Contains(" ON", StringComparison.OrdinalIgnoreCase);

		return new FirewallStatusReport
		{
			Status = anyOn ? FirewallProviderStatus.Available : FirewallProviderStatus.Disabled,
			ProviderId = ProviderId,
			Message = anyOn
				? "Windows Defender Firewall has at least one profile enabled."
				: "All Windows Defender Firewall profiles report OFF.",
		};
	}

	public async Task<FirewallActionResult> BlockAsync(FirewallBlockRequest request, CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(request);
		ct.ThrowIfCancellationRequested();

		if (!OperatingSystem.IsWindows())
		{
			return FirewallActionResult.UnavailableFor(ProviderId, "Windows firewall provider only runs on Windows hosts.");
		}

		FirewallOptions cfg = _options.CurrentValue.Firewall;

		IPAddress address;
		try
		{
			address = NetshCommandBuilder.ParseAndValidateIp(request.Ip);
		}
		catch (ArgumentException ex)
		{
			_logger.LogWarning("Block refused for invalid IP: {Message}", ex.Message);
			return new FirewallActionResult
			{
				Status = FirewallActionStatus.InvalidRequest,
				ProviderId = ProviderId,
				Message = "IP address failed validation.",
			};
		}

		if (NetshCommandBuilder.IsReservedAddress(address) && cfg.RefusePrivateAddressBlock)
		{
			_logger.LogWarning("Block refused for reserved address {Ip}", address);
			return new FirewallActionResult
			{
				Status = FirewallActionStatus.Refused,
				ProviderId = ProviderId,
				Message = "Address is loopback / private / multicast and policy refuses blocking it.",
			};
		}

		string canonicalIp = address.ToString();
		string ruleName = NetshCommandBuilder.BuildRuleName(request.RuleName, canonicalIp);
		string description = BuildAuditDescription(request.Reason, request.Duration);

		// Idempotency: best-effort delete first so we do not stack multiple identical rules in
		// the firewall store. Errors here are non-fatal — the add below is the real success.
		await _runner.RunAsync(NetshCommandBuilder.BuildDeleteRuleArgs(ruleName), ct).ConfigureAwait(false);

		NetshResult addResult = await _runner.RunAsync(
			NetshCommandBuilder.BuildAddRuleArgs(ruleName, canonicalIp, description),
			ct).ConfigureAwait(false);

		if (!addResult.Success)
		{
			_logger.LogWarning(
				"Firewall block failed for {Ip}: exit={Exit} stderr={StdErr}",
				canonicalIp,
				addResult.ExitCode,
				SanitizeForLog(addResult.StdErr));
			return new FirewallActionResult
			{
				Status = FirewallActionStatus.Unavailable,
				ProviderId = ProviderId,
				RuleId = ruleName,
				Message = string.Format(CultureInfo.InvariantCulture,
					"netsh add rule returned exit={0}.", addResult.ExitCode),
			};
		}

		_logger.LogInformation("Firewall block rule installed: {RuleName} for {Ip}", ruleName, canonicalIp);
		return new FirewallActionResult
		{
			Status = FirewallActionStatus.Success,
			ProviderId = ProviderId,
			RuleId = ruleName,
			Message = "Block rule installed.",
		};
	}

	public async Task<FirewallActionResult> UnblockAsync(string ip, string ruleName, CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ip);
		ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
		ct.ThrowIfCancellationRequested();

		if (!OperatingSystem.IsWindows())
		{
			return FirewallActionResult.UnavailableFor(ProviderId, "Windows firewall provider only runs on Windows hosts.");
		}

		IPAddress address;
		try
		{
			address = NetshCommandBuilder.ParseAndValidateIp(ip);
		}
		catch (ArgumentException ex)
		{
			_logger.LogWarning("Unblock refused for invalid IP: {Message}", ex.Message);
			return new FirewallActionResult
			{
				Status = FirewallActionStatus.InvalidRequest,
				ProviderId = ProviderId,
				Message = "IP address failed validation.",
			};
		}

		string canonicalIp = address.ToString();
		string fullRuleName = NetshCommandBuilder.BuildRuleName(ruleName, canonicalIp);

		NetshResult delResult = await _runner.RunAsync(
			NetshCommandBuilder.BuildDeleteRuleArgs(fullRuleName),
			ct).ConfigureAwait(false);

		if (!delResult.Success)
		{
			// netsh returns non-zero when no rule matched the name — treat that as NotFound, not as an error.
			bool notFound = delResult.StdOut.Contains("No rules match", StringComparison.OrdinalIgnoreCase);
			_logger.LogDebug(
				"Firewall unblock returned exit={Exit} notFound={NotFound} for {RuleName}",
				delResult.ExitCode,
				notFound,
				fullRuleName);
			return new FirewallActionResult
			{
				Status = notFound ? FirewallActionStatus.NotFound : FirewallActionStatus.Unavailable,
				ProviderId = ProviderId,
				RuleId = fullRuleName,
				Message = notFound
					? "No matching firewall rule."
					: string.Format(CultureInfo.InvariantCulture, "netsh delete rule returned exit={0}.", delResult.ExitCode),
			};
		}

		_logger.LogInformation("Firewall block rule removed: {RuleName} for {Ip}", fullRuleName, canonicalIp);
		return new FirewallActionResult
		{
			Status = FirewallActionStatus.Success,
			ProviderId = ProviderId,
			RuleId = fullRuleName,
			Message = "Block rule removed.",
		};
	}

	public async Task<IReadOnlyList<FirewallBlockEntry>> ListBlocksAsync(string ruleName, CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
		ct.ThrowIfCancellationRequested();

		if (!OperatingSystem.IsWindows())
		{
			return Array.Empty<FirewallBlockEntry>();
		}

		string normalized = NetshCommandBuilder.NormalizeRulePrefix(ruleName);
		NetshResult res = await _runner.RunAsync(
			NetshCommandBuilder.BuildShowRuleArgs(normalized),
			ct).ConfigureAwait(false);

		if (!res.Success)
		{
			return Array.Empty<FirewallBlockEntry>();
		}

		List<FirewallBlockEntry> entries = new();
		string? currentName = null;
		string? currentIp = null;
		foreach (string raw in res.StdOut.Split('\n'))
		{
			string line = raw.TrimEnd('\r').Trim();
			if (line.StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase))
			{
				if (currentName is not null && currentIp is not null)
				{
					entries.Add(new FirewallBlockEntry
					{
						RuleId = currentName,
						Ip = currentIp,
						ProviderId = ProviderId,
					});
				}
				currentName = line["Rule Name:".Length..].Trim();
				currentIp = null;
			}
			else if (line.StartsWith("RemoteIP:", StringComparison.OrdinalIgnoreCase))
			{
				currentIp = line["RemoteIP:".Length..].Trim();
			}
		}

		if (currentName is not null && currentIp is not null)
		{
			entries.Add(new FirewallBlockEntry
			{
				RuleId = currentName,
				Ip = currentIp,
				ProviderId = ProviderId,
			});
		}

		return entries;
	}

	internal static string BuildAuditDescription(string? reason, TimeSpan? duration)
	{
		string createdUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
		string body = string.IsNullOrWhiteSpace(reason) ? "auto-block" : reason!;
		string expires = duration is { TotalSeconds: > 0 }
			? duration.Value.ToString("c", CultureInfo.InvariantCulture)
			: "permanent";

		return string.Format(
			CultureInfo.InvariantCulture,
			"RdpAudit; reason={0}; created={1}; duration={2}",
			body,
			createdUtc,
			expires);
	}

	private static string SanitizeForLog(string? value)
	{
		if (string.IsNullOrEmpty(value))
		{
			return string.Empty;
		}

		int len = Math.Min(value.Length, 512);
		Span<char> buf = stackalloc char[len];
		int written = 0;
		for (int i = 0; i < len; i++)
		{
			char c = value[i];
			buf[written++] = char.IsControl(c) ? ' ' : c;
		}
		return new string(buf[..written]).Trim();
	}
}
