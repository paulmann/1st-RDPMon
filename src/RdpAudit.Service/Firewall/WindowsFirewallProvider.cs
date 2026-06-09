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
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Util;

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
	/// <summary>Hard timeout for the PowerShell New-NetFirewallRule create path.</summary>
	private static readonly TimeSpan PowerShellCreateTimeout = TimeSpan.FromSeconds(20);

	private readonly ILogger<WindowsFirewallProvider> _logger;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly INetshRunner _runner;
	private readonly IRdpPortProvider _portProvider;

	/// <summary>Optional PowerShell runner used to create rules via <c>New-NetFirewallRule -Group
	/// RdpAudit</c> so the firewall Group is actually stamped (netsh's <c>add rule</c> cannot set it).
	/// When null the provider creates rules via the netsh add path (group-free) instead. Tests that
	/// inject only the netsh runner exercise the netsh path deterministically.</summary>
	private readonly IExternalCommandRunner? _powerShellRunner;

	[SupportedOSPlatform("windows")]
	public WindowsFirewallProvider(
		ILogger<WindowsFirewallProvider> logger,
		IOptionsMonitor<RdpAuditOptions> options)
		: this(logger, options, new NetshRunner(), new RegistryRdpPortProvider(), new ExternalCommandRunner())
	{
	}

	internal WindowsFirewallProvider(
		ILogger<WindowsFirewallProvider> logger,
		IOptionsMonitor<RdpAuditOptions> options,
		INetshRunner runner,
		IRdpPortProvider portProvider,
		IExternalCommandRunner? powerShellRunner = null)
	{
		ArgumentNullException.ThrowIfNull(logger);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(runner);
		ArgumentNullException.ThrowIfNull(portProvider);
		_logger = logger;
		_options = options;
		_runner = runner;
		_portProvider = portProvider;
		_powerShellRunner = powerShellRunner;
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

		// Resolve the block scope and the real RDP listener port. RdpPortOnly requires a concrete
		// port; the resolver never hardcodes 3389 (registry value, or documented Microsoft default).
		FirewallBlockScope scope = cfg.BlockScope;
		int rdpPort = scope == FirewallBlockScope.RdpPortOnly ? _portProvider.GetRdpPort() : 0;

		IReadOnlyList<string> addArgs;
		try
		{
			addArgs = NetshCommandBuilder.BuildAddRuleArgs(ruleName, canonicalIp, description, scope, rdpPort);
		}
		catch (ArgumentOutOfRangeException ex)
		{
			_logger.LogWarning(ex, "Block refused: could not resolve a valid RDP port for RdpPortOnly scope");
			return new FirewallActionResult
			{
				Status = FirewallActionStatus.InvalidRequest,
				ProviderId = ProviderId,
				RuleId = ruleName,
				Message = "RdpPortOnly scope requires a resolved RDP listener port; resolution failed.",
			};
		}

		// Idempotency: best-effort delete first so we do not stack multiple identical rules in
		// the firewall store. Errors here are non-fatal — the add below is the real success.
		await _runner.RunAsync(NetshCommandBuilder.BuildDeleteRuleArgs(ruleName), ct).ConfigureAwait(false);

		// Create the rule. Prefer the PowerShell New-NetFirewallRule path when a PowerShell runner is
		// available, because only it can stamp -Group RdpAudit (netsh's add rule rejects group=). When
		// the PowerShell path is unavailable or fails, fall back to the group-free netsh add.
		BackendCommandAttempt addAttempt;
		bool createdOk;
		BackendCommandAttempt? powerShellAttempt = await TryPowerShellCreateAsync(
			ruleName, canonicalIp, description, scope, rdpPort, ct).ConfigureAwait(false);

		if (powerShellAttempt is { Success: true })
		{
			addAttempt = powerShellAttempt;
			createdOk = true;
		}
		else
		{
			NetshResult addResult = await _runner.RunAsync(addArgs, ct).ConfigureAwait(false);
			addAttempt = BuildAttempt(addResult, addArgs);
			createdOk = addResult.Success;

			if (!createdOk)
			{
				_logger.LogWarning(
					"Firewall block failed for {Ip}: exit={Exit} stderr={StdErr} (powerShellTried={PsTried})",
					canonicalIp,
					addResult.ExitCode,
					SanitizeForLog(addResult.StdErr),
					powerShellAttempt is not null);
				return new FirewallActionResult
				{
					Status = FirewallActionStatus.Unavailable,
					ProviderId = ProviderId,
					RuleId = ruleName,
					RuleHandle = ruleName,
					BackendAttempt = addAttempt,
					VerifierReason = powerShellAttempt is null
						? "netsh add rule exited non-zero before verification."
						: "PowerShell New-NetFirewallRule failed and the netsh add fallback also exited non-zero.",
					// When netsh exits non-zero with empty stderr, the failure text is in stdout — surface it.
					Message = BuildBackendFailureMessage("netsh add rule", addResult),
				};
			}
		}

		// Verification: a non-zero exit is a clear failure, but netsh (or a managing third-party
		// firewall such as Kaspersky) can return zero while no rule actually lands. Re-query the
		// named rule and confirm an enabled inbound block rule exists before declaring success.
		if (cfg.VerifyAfterBlock)
		{
			IReadOnlyList<string> showArgs = NetshCommandBuilder.BuildShowRuleArgs(ruleName);
			NetshResult verify = await _runner.RunAsync(showArgs, ct).ConfigureAwait(false);

			bool confirmed = verify.Success
				&& NetshRuleScanner.ContainsEnabledInboundBlockRule(verify.StdOut);
			if (!confirmed)
			{
				_logger.LogWarning(
					"Firewall block could not be verified for {Ip}: rule {RuleName} not found after add (a managing third-party firewall may have rejected the write)",
					canonicalIp,
					ruleName);
				string verifierReason = verify.Success
					? "Verification query succeeded but no enabled inbound block rule was found in the store."
					: string.Format(CultureInfo.InvariantCulture, "Verification query exited {0}.", verify.ExitCode);
				return new FirewallActionResult
				{
					Status = FirewallActionStatus.Unavailable,
					ProviderId = ProviderId,
					RuleId = ruleName,
					RuleHandle = ruleName,
					BackendAttempt = BuildAttempt(verify, showArgs),
					VerifierReason = verifierReason,
					Message = "Block rule reported success but could not be verified in the firewall store; a managing third-party firewall may have rejected it.",
				};
			}
		}

		_logger.LogInformation(
			"Firewall block rule installed and verified: {RuleName} for {Ip} scope={Scope} port={Port}",
			ruleName,
			canonicalIp,
			scope,
			rdpPort);
		return new FirewallActionResult
		{
			Status = FirewallActionStatus.Success,
			ProviderId = ProviderId,
			RuleId = ruleName,
			RuleHandle = ruleName,
			BackendAttempt = addAttempt,
			VerifierReason = cfg.VerifyAfterBlock
				? "Enabled inbound block rule confirmed in the firewall store."
				: "Verification disabled by configuration.",
			Message = cfg.VerifyAfterBlock ? "Block rule installed and verified." : "Block rule installed.",
		};
	}

	/// <summary>Attempts to create the block rule via PowerShell <c>New-NetFirewallRule -Group
	/// RdpAudit</c> so the firewall Group is stamped. Returns null when no PowerShell runner is wired
	/// (the caller then uses the netsh add path); returns a populated <see cref="BackendCommandAttempt"/>
	/// describing the exact command, exit code, duration and bounded previews otherwise. A non-success
	/// attempt is non-fatal — the caller falls back to netsh.</summary>
	private async Task<BackendCommandAttempt?> TryPowerShellCreateAsync(
		string ruleName,
		string canonicalIp,
		string? description,
		FirewallBlockScope scope,
		int rdpPort,
		CancellationToken ct)
	{
		if (_powerShellRunner is null)
		{
			return null;
		}

		string script;
		try
		{
			script = NetshCommandBuilder.BuildNewNetFirewallRuleScript(ruleName, canonicalIp, description, scope, rdpPort);
		}
		catch (ArgumentException ex)
		{
			_logger.LogWarning(ex, "Could not build New-NetFirewallRule script for {Ip}; using netsh fallback", canonicalIp);
			return null;
		}

		IReadOnlyList<string> psArgs = new[]
		{
			"-NoProfile",
			"-NonInteractive",
			"-ExecutionPolicy", "Bypass",
			"-OutputFormat", "Text",
			"-Command", script,
		};

		ExternalCommandResult result;
		try
		{
			result = await _powerShellRunner.RunDirectAsync(
				commandLabel: "powershell New-NetFirewallRule -Group RdpAudit",
				executable: "powershell.exe",
				arguments: psArgs,
				timeout: PowerShellCreateTimeout,
				ct: ct).ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "PowerShell New-NetFirewallRule raised an exception for {Ip}; using netsh fallback", canonicalIp);
			return null;
		}

		return new BackendCommandAttempt(
			CommandLabel: "New-NetFirewallRule -Group RdpAudit",
			Executable: "powershell.exe",
			Arguments: "New-NetFirewallRule -Name " + ruleName + " -Group " + NetshCommandBuilder.RdpAuditGroup
				+ " -Direction Inbound -Action Block -Enabled True -Profile Any -RemoteAddress " + canonicalIp,
			RunnerMode: BackendRunnerMode.PowerShellJson,
			ExitCode: result.TimedOut ? -1 : result.ExitCode,
			TimedOut: result.TimedOut,
			DurationMs: (long)result.Duration.TotalMilliseconds,
			StdoutPreview: BackendCommandAttempt.BuildPreview(result.StdOut),
			StderrPreview: BackendCommandAttempt.BuildPreview(result.StdErr),
			ScannerBackend: "NewNetFirewallRule");
	}

	/// <summary>Builds a <see cref="BackendCommandAttempt"/> from a netsh outcome, filling in the
	/// argument line the provider knows about (the runner does not echo it back).</summary>
	private static BackendCommandAttempt BuildAttempt(NetshResult result, IReadOnlyList<string> args)
	{
		BackendCommandAttempt baseAttempt = result.ToBackendAttempt();
		return baseAttempt with { Arguments = string.Join(' ', args) };
	}

	/// <summary>Builds the operator-facing failure message for a non-zero netsh exit. When stderr is
	/// empty the stdout text is the only failure signal, so it is folded into the message.</summary>
	private static string BuildBackendFailureMessage(string action, NetshResult result)
	{
		string stderr = result.StdErr?.Trim() ?? string.Empty;
		string detail = stderr.Length > 0
			? stderr
			: BackendCommandAttempt.BuildPreview(result.StdOut, 240);
		string baseMsg = string.Format(CultureInfo.InvariantCulture, "{0} returned exit={1}.", action, result.ExitCode);
		return detail.Length > 0 ? baseMsg + " " + detail : baseMsg;
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
