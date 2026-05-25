// File:    src/RdpAudit.Core/Firewall/NetshRuleScanner.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: Pure parser that scans the textual output of `netsh advfirewall firewall show rule
//          name=all verbose` for an inbound-allow rule whose LocalPort matches a configured RDP
//          port. Used instead of the previous localised-rule-name probe so the check works on
//          English and non-English Windows builds without needing a localised group name.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Firewall;

/// <summary>Pure parser for netsh `show rule` output.</summary>
public static class NetshRuleScanner
{
	/// <summary>True when <paramref name="netshOutput"/> contains at least one rule block
	/// describing an inbound allow rule whose LocalPort matches <paramref name="port"/>. The
	/// parser only depends on the ASCII keys (Action / Direction / LocalPort) which netsh
	/// emits in English even on localised hosts.</summary>
	public static bool ContainsAllowInboundForPort(string netshOutput, int port)
	{
		if (string.IsNullOrEmpty(netshOutput))
		{
			return false;
		}

		string portText = port.ToString(CultureInfo.InvariantCulture);
		string[] lines = netshOutput.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');

		bool hasAllow = false;
		bool hasInbound = false;
		bool hasMatchingPort = false;

		foreach (string raw in lines)
		{
			string line = raw.Trim();
			if (line.Length == 0)
			{
				if (hasAllow && hasInbound && hasMatchingPort)
				{
					return true;
				}
				hasAllow = false;
				hasInbound = false;
				hasMatchingPort = false;
				continue;
			}

			if (line.StartsWith("Action:", StringComparison.OrdinalIgnoreCase)
				&& line.Contains("Allow", StringComparison.OrdinalIgnoreCase))
			{
				hasAllow = true;
			}
			else if (line.StartsWith("Direction:", StringComparison.OrdinalIgnoreCase)
				&& line.Contains("In", StringComparison.OrdinalIgnoreCase))
			{
				hasInbound = true;
			}
			else if (line.StartsWith("LocalPort:", StringComparison.OrdinalIgnoreCase))
			{
				string remainder = line["LocalPort:".Length..].Trim();
				if (remainder.Equals(portText, StringComparison.Ordinal))
				{
					hasMatchingPort = true;
				}
				else
				{
					foreach (string part in remainder.Split(','))
					{
						if (part.Trim().Equals(portText, StringComparison.Ordinal))
						{
							hasMatchingPort = true;
							break;
						}
					}
				}
			}
		}

		return hasAllow && hasInbound && hasMatchingPort;
	}
}
