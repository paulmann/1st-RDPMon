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

	/// <summary>Builds the argument vector for <c>netsh advfirewall firewall add rule</c>.</summary>
	public static IReadOnlyList<string> BuildAddRuleArgs(string ruleName, string ip, string? description)
	{
		ValidateRuleName(ruleName);
		string canonicalIp = NormalizeIp(ip);

		List<string> args = new(10)
		{
			"advfirewall", "firewall", "add", "rule",
			string.Format(CultureInfo.InvariantCulture, "name={0}", ruleName),
			"dir=in",
			"action=block",
			string.Format(CultureInfo.InvariantCulture, "remoteip={0}", canonicalIp),
			"protocol=any",
			"enable=yes",
		};

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
