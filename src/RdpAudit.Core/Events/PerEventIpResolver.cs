// File:    src/RdpAudit.Core/Events/PerEventIpResolver.cs
// Module:  RdpAudit.Core.Events
// Purpose: Per-(channel,eventId) IP extraction from EventRecord XML. Returns only validated
//          IP addresses; hostname-only fields (ClientName, Workstation, WorkstationName) are
//          never consulted, so a NetBIOS name can never leak into RawEvent.SourceIp.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Xml;
using RdpAudit.Core.Util;

namespace RdpAudit.Core.Events;

/// <summary>
/// Resolves the source IP of a Windows event from its XML payload using a per-event-id schema map.
/// Returns the canonical dotted-quad / canonical IPv6 form, or null when the event carries no
/// parseable IP. IPv4-mapped IPv6 (::ffff:1.2.3.4) is collapsed to its IPv4 dotted-quad form.
/// </summary>
public static class PerEventIpResolver
{
	private const string TsLsmChannel = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
	private const string TsRcmChannel = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";
	private const string RdpCoreTsChannel = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";
	private const string SecurityChannel = "Security";

	/// <summary>
	/// Resolve the source IP for a single event. The dispatch table is keyed by channel and event
	/// id; unknown combinations fall back to a small list of IP-only fields. Hostname-only fields
	/// are never consulted at this layer.
	/// </summary>
	public static string? Resolve(XmlDocument? doc, string channel, int eventId)
	{
		if (doc is null)
		{
			return null;
		}

		string? candidate = TryResolveSpecific(doc, channel, eventId)
			?? TryResolveFallback(doc);

		return Normalize(candidate);
	}

	private static string? TryResolveSpecific(XmlDocument doc, string channel, int eventId)
	{
		if (IsTsLsm(channel))
		{
			return eventId switch
			{
				21 or 24 or 25 => EventXmlParser.GetData(doc, "Address"),
				_ => null,
			};
		}

		if (IsTsRcm(channel))
		{
			return eventId switch
			{
				1149 => EventXmlParser.GetData(doc, "Param3"),
				_ => null,
			};
		}

		if (IsRdpCoreTs(channel))
		{
			return eventId switch
			{
				131 => EventXmlParser.GetData(doc, "ClientIP") ?? EventXmlParser.GetData(doc, "ConnectionName"),
				140 => EventXmlParser.GetData(doc, "IPString"),
				_ => null,
			};
		}

		if (IsSecurity(channel))
		{
			return eventId switch
			{
				4778 or 4779 => EventXmlParser.GetData(doc, "ClientAddress"),
				4624 or 4625 or 4648 or 4768 or 4769 or 4770 or 4771 => EventXmlParser.GetData(doc, "IpAddress"),
				_ => null,
			};
		}

		return null;
	}

	private static string? TryResolveFallback(XmlDocument doc)
	{
		// Conservative IP-only fallback: no hostname fields allowed here. Order matters — most
		// specific Windows naming first, generic last.
		return EventXmlParser.GetData(doc, "IpAddress")
			?? EventXmlParser.GetData(doc, "ClientAddress")
			?? EventXmlParser.GetData(doc, "SourceNetworkAddress");
	}

	private static string? Normalize(string? raw)
	{
		if (string.IsNullOrWhiteSpace(raw))
		{
			return null;
		}

		string trimmed = raw.Trim();
		if (IpClassifier.IsLocalSentinel(trimmed))
		{
			return null;
		}

		// Strip an IPv6 zone identifier ("fe80::1%eth0") and an IPv6 port wrapper ("[::1]:443")
		// before parsing so canonical addresses still round-trip cleanly.
		string forParse = trimmed;
		int pct = forParse.IndexOf('%', StringComparison.Ordinal);
		if (pct > 0)
		{
			forParse = forParse[..pct];
		}

		if (!IPAddress.TryParse(forParse, out IPAddress? parsed))
		{
			return null;
		}

		if (parsed.AddressFamily == AddressFamily.InterNetworkV6 && parsed.IsIPv4MappedToIPv6)
		{
			IPAddress v4 = parsed.MapToIPv4();
			return v4.ToString();
		}

		return parsed.ToString();
	}

	private static bool IsTsLsm(string channel) => channel.Equals(TsLsmChannel, StringComparison.OrdinalIgnoreCase);

	private static bool IsTsRcm(string channel) => channel.Equals(TsRcmChannel, StringComparison.OrdinalIgnoreCase);

	private static bool IsRdpCoreTs(string channel) => channel.Equals(RdpCoreTsChannel, StringComparison.OrdinalIgnoreCase);

	private static bool IsSecurity(string channel) => channel.Equals(SecurityChannel, StringComparison.OrdinalIgnoreCase);

	internal static string ChannelToInvariant(string channel) => channel.ToString(CultureInfo.InvariantCulture);
}
