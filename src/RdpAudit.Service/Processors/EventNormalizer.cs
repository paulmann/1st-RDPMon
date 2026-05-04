// File:    src/RdpAudit.Service/Processors/EventNormalizer.cs
// Module:  RdpAudit.Service.Processors
// Purpose: Translates a raw EventRecord XML payload into a fully-populated RawEvent entity.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using System.Xml;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Processors;

/// <summary>Translates a raw EventRecord XML payload into a fully-populated RawEvent entity.</summary>
public sealed class EventNormalizer
{
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
		string detailsJson = JsonSerializer.Serialize(extraDetails, JsonOptions.Default);
		if (detailsJson.Length > 65_536)
		{
			detailsJson = detailsJson[..65_536];
		}

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
