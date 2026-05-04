// File:    src/RdpAudit.Service/Processors/EventNormalizer.cs
// Module:  RdpAudit.Service.Processors
// Purpose: Translates a raw EventRecord XML payload into a fully-populated RawEvent entity.
//          When the Details JSON exceeds the persistence cap, large string values are truncated
//          field-by-field to keep the document well-formed. As a last resort the payload is
//          replaced with a sentinel object containing the truncation metadata so downstream
//          alert rules (StickyKeys / LsassAccess / PrivilegedGroupChange / ProcessAnomaly /
//          GoldenTicket) can still parse evt.Details safely.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text.Json;
using System.Xml;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Processors;

/// <summary>Translates a raw EventRecord XML payload into a fully-populated RawEvent entity.</summary>
public sealed class EventNormalizer
{
	internal const int MaxDetails = 65_536;

	private static readonly string[] AddressFieldNames =
	{
		"IpAddress", "ClientAddress", "ClientName", "SourceNetworkAddress", "Workstation",
	};

	public RawEvent Normalize(RawEventDto dto)
	{
		XmlDocument? doc = EventXmlParser.ParseSafe(dto.XmlPayload);
		string? sourceIp = ResolveIp(doc);
		string? userName = EventXmlParser.GetData(doc, "TargetUserName")
			?? EventXmlParser.GetData(doc, "SubjectUserName")
			?? EventXmlParser.GetData(doc, "User")
			?? EventXmlParser.GetData(doc, "AccountName");

		string? domain = EventXmlParser.GetData(doc, "TargetDomainName")
			?? EventXmlParser.GetData(doc, "SubjectDomainName")
			?? EventXmlParser.GetData(doc, "Domain");

		Dictionary<string, string?> extraDetails = ExtractAllEventData(doc);
		string detailsJson = SerializeAndCap(extraDetails);

		RawEvent entity = new()
		{
			EventId = dto.EventId,
			Channel = dto.Channel,
			TimeUtc = dto.TimeUtc,
			SourceIp = NormalizeIp(sourceIp),
			UserName = userName,
			Domain = domain,
			LogonId = EventXmlParser.GetData(doc, "TargetLogonId") ?? EventXmlParser.GetData(doc, "SubjectLogonId"),
			LogonType = EventXmlParser.GetInt(doc, "LogonType"),
			AuthPackage = EventXmlParser.GetData(doc, "AuthenticationPackageName")
				?? EventXmlParser.GetData(doc, "Package")
				?? EventXmlParser.GetData(doc, "PackageName"),
			SessionId = EventXmlParser.GetInt(doc, "SessionID") ?? EventXmlParser.GetInt(doc, "SessionId"),
			Status = EventXmlParser.GetData(doc, "Status") ?? EventXmlParser.GetData(doc, "FailureReason"),
			ProcessName = EventXmlParser.GetData(doc, "NewProcessName") ?? EventXmlParser.GetData(doc, "ProcessName"),
			CommandLine = EventXmlParser.GetData(doc, "CommandLine"),
			ObjectName = EventXmlParser.GetData(doc, "ObjectName"),
			AccessMask = EventXmlParser.GetData(doc, "AccessMask") ?? EventXmlParser.GetData(doc, "AccessList"),
			Details = detailsJson,
			Processed = false,
		};

		return entity;
	}

	/// <summary>Serialises the extracted EventData and applies a JSON-aware cap.</summary>
	internal static string SerializeAndCap(Dictionary<string, string?> map)
	{
		string raw = JsonSerializer.Serialize(map, JsonOptions.Default);
		if (raw.Length <= MaxDetails)
		{
			return raw;
		}

		// Strategy: progressively truncate the longest string fields first until under the cap.
		// Add per-field marker so consumers can detect truncation without re-parsing the original.
		Dictionary<string, string?> shrinking = new(map, StringComparer.OrdinalIgnoreCase);
		string truncated;
		int safety = 32;
		while (true)
		{
			truncated = JsonSerializer.Serialize(shrinking, JsonOptions.Default);
			if (truncated.Length <= MaxDetails || safety-- <= 0)
			{
				break;
			}

			KeyValuePair<string, string?> longest = shrinking
				.Where(kv => kv.Value is not null)
				.OrderByDescending(kv => kv.Value!.Length)
				.FirstOrDefault();
			if (longest.Key is null || longest.Value is null || longest.Value.Length <= 64)
			{
				break;
			}

			int newLen = Math.Max(64, longest.Value.Length / 2);
			shrinking[longest.Key] = longest.Value[..newLen] + "…[truncated]";
		}

		if (truncated.Length <= MaxDetails)
		{
			return truncated;
		}

		// Final fallback: emit a valid sentinel object so callers can still JsonDocument.Parse.
		Dictionary<string, object> sentinel = new(StringComparer.OrdinalIgnoreCase)
		{
			["truncated"] = true,
			["originalLength"] = raw.Length,
			["maxAllowed"] = MaxDetails,
		};
		// Preserve the small subset of fields that downstream rules rely on.
		string[] priorityKeys = { "ProcessName", "ParentProcessName", "TicketEncryptionType", "ServiceName", "PrivilegeList", "TargetUserName", "MemberName" };
		foreach (string key in priorityKeys)
		{
			if (map.TryGetValue(key, out string? value) && !string.IsNullOrEmpty(value))
			{
				sentinel[key] = value.Length > 1024 ? value[..1024] + "…[truncated]" : value;
			}
		}

		string sentinelJson = JsonSerializer.Serialize(sentinel, JsonOptions.Default);
		return sentinelJson.Length <= MaxDetails
			? sentinelJson
			: string.Format(CultureInfo.InvariantCulture, "{{\"truncated\":true,\"originalLength\":{0}}}", raw.Length);
	}

	private static string? ResolveIp(XmlDocument? doc)
	{
		foreach (string name in AddressFieldNames)
		{
			string? value = EventXmlParser.GetData(doc, name);
			if (!string.IsNullOrWhiteSpace(value))
			{
				return value;
			}
		}

		return null;
	}

	private static string? NormalizeIp(string? ip)
	{
		if (string.IsNullOrWhiteSpace(ip) || IpClassifier.IsLocalSentinel(ip))
		{
			return null;
		}

		return ip;
	}

	private static Dictionary<string, string?> ExtractAllEventData(XmlDocument? doc)
	{
		Dictionary<string, string?> map = new(StringComparer.OrdinalIgnoreCase);
		if (doc is null)
		{
			return map;
		}

		XmlNodeList? nodes = doc.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']");
		if (nodes is null)
		{
			return map;
		}

		foreach (XmlNode node in nodes)
		{
			string? key = node.Attributes?["Name"]?.Value;
			if (string.IsNullOrEmpty(key))
			{
				continue;
			}

			string? value = node.InnerText?.Trim();
			map[key] = value;
		}

		return map;
	}
}
