// File:    src/RdpAudit.Service/Firewall/NetshCommandBuilder.cs
// Module:  RdpAudit.Service.Firewall
// Purpose: Pure builders for netsh advfirewall argument vectors used by the Windows firewall
//          provider. Every helper validates IP and rule-name inputs defensively, sanitises rule
//          names, and emits arguments that can ONLY be passed via ProcessStartInfo.ArgumentList.
//          NO string concatenation is performed across IP / rule-name / reason boundaries.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using RdpAudit.Core.Config;

namespace RdpAudit.Service.Firewall;

/// <summary>Pure builders for netsh advfirewall argument vectors used by the Windows firewall provider.</summary>
/// <remarks>
/// netsh accepts arguments as <c>name=value</c> pairs. We treat the whole pair as a single
/// argument and never quote or interpolate via the shell. <see cref="ProcessStartInfo.ArgumentList"/>
/// is the only supported invocation path.
/// </remarks>
public static class NetshCommandBuilder
{
	/// <summary>Maximum length for the per-IP rule name we generate.</summary>
	/// <remarks>
	/// Windows Defender Firewall stores rule names in a 255-character field; we cap our generated
	/// names well below that so any future suffix appended by the operator still fits.
	/// </remarks>
	public const int MaxRuleNameLength = 200;

	/// <summary>Prefix used by every RdpAudit-owned rule, never touched on third-party rules.</summary>
	public const string DefaultRulePrefix = "RdpAudit-Block";

	/// <summary>Firewall group stamped on every RdpAudit-owned rule.</summary>
	/// <remarks>
	/// Tagging rules with a stable <c>group=</c> lets operators (and our own verification /
	/// diagnostics) enumerate every RdpAudit rule via <c>Get-NetFirewallRule -Group RdpAudit</c> or
	/// <c>netsh advfirewall firewall show rule name=all</c> filtered on Grouping. Without this, the
	/// operator-reported "Get-NetFirewallRule where Group contains RdpAudit returns no rules" is
	/// expected even when rules exist, because netsh-added rules carry no group by default.
	/// </remarks>
	public const string RdpAuditGroup = "RdpAudit";

	/// <summary>Normalises a base rule prefix to the conservative ASCII set accepted by netsh.</summary>
	/// <remarks>
	/// Allowed characters: ASCII letters, digits, '-', '_', '.'. Anything else collapses to '-'.
	/// Empty / whitespace input falls back to <see cref="DefaultRulePrefix"/>.
	/// </remarks>
	public static string NormalizeRulePrefix(string? prefix)
	{
		if (string.IsNullOrWhiteSpace(prefix))
		{
			return DefaultRulePrefix;
		}

		StringBuilder sb = new(prefix.Length);
		foreach (char c in prefix)
		{
			if (char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_' || c == '.')
			{
				sb.Append(c);
			}
			else
			{
				sb.Append('-');
			}
		}

		string normalized = sb.ToString().Trim('-');
		return normalized.Length == 0 ? DefaultRulePrefix : normalized;
	}

	/// <summary>Builds the deterministic per-IP rule name in the form "{prefix}-{normalized-ip}".</summary>
	public static string BuildRuleName(string rulePrefix, string ip)
	{
		string normalizedPrefix = NormalizeRulePrefix(rulePrefix);
		string normalizedIp = NormalizeIp(ip);
		string composed = string.Concat(normalizedPrefix, "-", normalizedIp);
		if (composed.Length > MaxRuleNameLength)
		{
			composed = composed[..MaxRuleNameLength];
		}
		return composed;
	}

	/// <summary>Validates an IP address. Throws when the input is not a syntactically valid IPv4 / IPv6 address.</summary>
	public static IPAddress ParseAndValidateIp(string ip)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ip);
		if (!IPAddress.TryParse(ip, out IPAddress? parsed))
		{
			throw new ArgumentException(
				string.Format(CultureInfo.InvariantCulture, "Not a valid IPv4 / IPv6 address: '{0}'.", ip),
				nameof(ip));
		}
		return parsed;
	}

	/// <summary>Returns the canonical (normalised) textual form of an IP address.</summary>
	/// <remarks>
	/// Normalises IPv6 zone identifiers away and collapses IPv4-mapped IPv6 to IPv4 only when the
	/// caller passes one. The normalised string is safe to inject into a rule name and to compare
	/// against the configured whitelist.
	/// </remarks>
	public static string NormalizeIp(string ip)
	{
		IPAddress parsed = ParseAndValidateIp(ip);

		// Strip IPv6 scope id if present and emit the canonical textual form.
		if (parsed.AddressFamily == AddressFamily.InterNetworkV6)
		{
			parsed.ScopeId = 0;
		}

		return parsed.ToString();
	}

	/// <summary>True when the address is loopback, link-local, multicast, private (RFC1918), CGN, broadcast, or otherwise reserved.</summary>
	public static bool IsReservedAddress(IPAddress address)
	{
		ArgumentNullException.ThrowIfNull(address);

		if (IPAddress.IsLoopback(address))
		{
			return true;
		}

		if (address.AddressFamily == AddressFamily.InterNetworkV6)
		{
			return address.IsIPv6LinkLocal
				|| address.IsIPv6SiteLocal
				|| address.IsIPv6Multicast;
		}

		byte[] b = address.GetAddressBytes();
		return b[0] == 0
			|| b[0] == 10
			|| b[0] == 127
			|| (b[0] == 169 && b[1] == 254)
			|| (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
			|| (b[0] == 192 && b[1] == 168)
			|| (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
			|| b[0] >= 224;
	}

	/// <summary>Builds the argument vector for an all-inbound <c>netsh advfirewall firewall add rule</c>.</summary>
	/// <remarks>Convenience overload preserving the historical all-inbound behaviour with the
	/// RdpAudit group now stamped on. Equivalent to
	/// <see cref="BuildAddRuleArgs(string, string, string?, FirewallBlockScope, int)"/> with
	/// <see cref="FirewallBlockScope.AllInbound"/>.</remarks>
	public static IReadOnlyList<string> BuildAddRuleArgs(string ruleName, string ip, string? description) =>
		BuildAddRuleArgs(ruleName, ip, description, FirewallBlockScope.AllInbound, rdpPort: 0);

	/// <summary>Builds the scope-aware argument vector for <c>netsh advfirewall firewall add rule</c>.</summary>
	/// <param name="ruleName">Validated per-IP rule name.</param>
	/// <param name="ip">Attacker IP; re-validated and canonicalised here.</param>
	/// <param name="description">Optional audit description; sanitised before use.</param>
	/// <param name="scope">RDP-port-only or all-inbound. Drives the protocol / port arguments.</param>
	/// <param name="rdpPort">Resolved RDP listener port; required (1..65535) when
	/// <paramref name="scope"/> is <see cref="FirewallBlockScope.RdpPortOnly"/>. Never hardcoded.</param>
	/// <remarks>
	/// Every rule is stamped with <c>group=RdpAudit</c> so operators can enumerate RdpAudit rules by
	/// Group. For <see cref="FirewallBlockScope.RdpPortOnly"/> the rule restricts to
	/// <c>protocol=tcp</c> and the resolved <c>localport</c>; for
	/// <see cref="FirewallBlockScope.AllInbound"/> it uses <c>protocol=any</c>.
	/// </remarks>
	public static IReadOnlyList<string> BuildAddRuleArgs(
		string ruleName,
		string ip,
		string? description,
		FirewallBlockScope scope,
		int rdpPort)
	{
		ValidateRuleName(ruleName);
		string canonicalIp = NormalizeIp(ip);

		List<string> args = new(12)
		{
			"advfirewall", "firewall", "add", "rule",
			string.Format(CultureInfo.InvariantCulture, "name={0}", ruleName),
			string.Format(CultureInfo.InvariantCulture, "group={0}", RdpAuditGroup),
			"dir=in",
			"action=block",
			string.Format(CultureInfo.InvariantCulture, "remoteip={0}", canonicalIp),
			"profile=any",
			"enable=yes",
		};

		if (scope == FirewallBlockScope.RdpPortOnly)
		{
			if (rdpPort < 1 || rdpPort > 65535)
			{
				throw new ArgumentOutOfRangeException(
					nameof(rdpPort),
					rdpPort,
					"RdpPortOnly scope requires a resolved RDP listener port in range 1..65535.");
			}

			args.Add("protocol=tcp");
			args.Add(string.Format(CultureInfo.InvariantCulture, "localport={0}", rdpPort));
		}
		else
		{
			args.Add("protocol=any");
		}

		string safeDescription = SanitizeDescription(description);
		if (safeDescription.Length > 0)
		{
			args.Add(string.Format(CultureInfo.InvariantCulture, "description={0}", safeDescription));
		}

		return args;
	}

	/// <summary>Builds the argument vector for <c>netsh advfirewall firewall delete rule</c>.</summary>
	public static IReadOnlyList<string> BuildDeleteRuleArgs(string ruleName)
	{
		ValidateRuleName(ruleName);
		return new List<string>
		{
			"advfirewall", "firewall", "delete", "rule",
			string.Format(CultureInfo.InvariantCulture, "name={0}", ruleName),
		};
	}

	/// <summary>Builds the argument vector for <c>netsh advfirewall firewall show rule</c> with verbose output.</summary>
	public static IReadOnlyList<string> BuildShowRuleArgs(string ruleName)
	{
		ValidateRuleName(ruleName);
		return new List<string>
		{
			"advfirewall", "firewall", "show", "rule",
			string.Format(CultureInfo.InvariantCulture, "name={0}", ruleName),
			"verbose",
		};
	}

	/// <summary>Builds the argument vector for <c>netsh advfirewall show allprofiles state</c>.</summary>
	public static IReadOnlyList<string> BuildShowAllProfilesStateArgs() =>
		new List<string> { "advfirewall", "show", "allprofiles", "state" };

	/// <summary>Builds the argument vector for <c>netsh advfirewall firewall show rule name=all
	/// verbose</c>. Used by live enforcement reconciliation to enumerate every firewall rule in one
	/// pass; the caller filters the parsed result to the RdpAudit rule-name prefix.</summary>
	public static IReadOnlyList<string> BuildShowAllRulesArgs() =>
		new List<string> { "advfirewall", "firewall", "show", "rule", "name=all", "verbose" };

	/// <summary>Validates a rule name against the conservative ASCII set we accept.</summary>
	private static void ValidateRuleName(string ruleName)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
		if (ruleName.Length > MaxRuleNameLength)
		{
			throw new ArgumentException(
				string.Format(CultureInfo.InvariantCulture, "Rule name exceeds {0} characters.", MaxRuleNameLength),
				nameof(ruleName));
		}

		foreach (char c in ruleName)
		{
			if (!(char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_' || c == '.' || c == ':'))
			{
				throw new ArgumentException(
					string.Format(CultureInfo.InvariantCulture,
						"Rule name contains characters that could change netsh parsing: '{0}'.",
						ruleName),
					nameof(ruleName));
			}
		}
	}

	/// <summary>Replaces newline / quote / control characters in the description so it cannot break parsing.</summary>
	private static string SanitizeDescription(string? description)
	{
		if (string.IsNullOrWhiteSpace(description))
		{
			return string.Empty;
		}

		StringBuilder sb = new(description.Length);
		foreach (char c in description)
		{
			if (char.IsControl(c) || c == '"' || c == '\'' || c == '|' || c == '&' || c == '<' || c == '>' || c == '\r' || c == '\n')
			{
				sb.Append(' ');
			}
			else
			{
				sb.Append(c);
			}
		}

		string trimmed = sb.ToString().Trim();
		if (trimmed.Length > 512)
		{
			trimmed = trimmed[..512];
		}
		return trimmed;
	}
}
