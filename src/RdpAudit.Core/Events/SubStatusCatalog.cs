// File:    src/RdpAudit.Core/Events/SubStatusCatalog.cs
// Module:  RdpAudit.Core.Events
// Purpose: Translation table for Windows Security event 4625 / 4776 / 4771 SubStatus codes per
//          Detect_Attack_Strategy_v3.md §3.1 "SubStatus Code Reference". Exposes a single
//          dictionary-style lookup so UI rendering, log formatting, and tests share one canonical
//          string per code.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Events;

/// <summary>Translation table for Windows logon SubStatus codes.</summary>
public static class SubStatusCatalog
{
	private static readonly Dictionary<string, string> Map = new(StringComparer.OrdinalIgnoreCase)
	{
		["0xC000006A"] = "Bad Password",
		["0xC0000064"] = "No Such User",
		["0xC0000234"] = "Account Locked Out",
		["0xC0000072"] = "Account Disabled",
		["0xC000006F"] = "Outside Logon Hours",
		["0xC0000071"] = "Password Expired",
		["0xC0000133"] = "Clock Skew",
		["0xC000015B"] = "Logon Type Not Granted",
		["0xC000006D"] = "Misc. Logon Failure",
		["0xC0000193"] = "Account Expired",
		["0xC0000224"] = "Password Must Change",
		["0xC0000371"] = "Local Account Not Allowed Over Net",
	};

	/// <summary>Translate a raw SubStatus string (with or without the 0x prefix) into a human-readable
	/// meaning. Returns null when the code is unknown or empty.</summary>
	public static string? Translate(string? subStatus)
	{
		if (string.IsNullOrWhiteSpace(subStatus))
		{
			return null;
		}

		string normalized = subStatus.Trim();
		if (Map.TryGetValue(normalized, out string? meaning))
		{
			return meaning;
		}

		// Try with / without 0x prefix to be tolerant of source variation.
		string withPrefix = normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
			? normalized
			: "0x" + normalized;
		if (Map.TryGetValue(withPrefix, out meaning))
		{
			return meaning;
		}

		string withoutPrefix = normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
			? normalized[2..]
			: normalized;
		if (Map.TryGetValue(withoutPrefix, out meaning))
		{
			return meaning;
		}

		// Format unknown codes consistently so the UI never shows an empty cell.
		return string.Format(CultureInfo.InvariantCulture, "Unknown SubStatus ({0})", normalized);
	}
}
