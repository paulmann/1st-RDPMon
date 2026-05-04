// File:    src/RdpAudit.Core/Events/EventXmlParser.cs
// Module:  RdpAudit.Core.Events
// Purpose: Safe XML parser for Windows EventRecord serialized payloads.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Xml;

namespace RdpAudit.Core.Events;

/// <summary>Safe XML parser for Windows EventRecord serialized payloads.</summary>
public static class EventXmlParser
{
	private static readonly XmlReaderSettings XmlSettings = new()
	{
		IgnoreWhitespace = true,
		IgnoreComments = true,
		DtdProcessing = DtdProcessing.Prohibit,
		XmlResolver = null,
	};

	/// <summary>Loads an EventRecord XML payload safely; returns null on malformed input.</summary>
	public static XmlDocument? ParseSafe(string xml)
	{
		if (string.IsNullOrEmpty(xml))
		{
			return null;
		}

		try
		{
			XmlDocument doc = new() { XmlResolver = null };
			using StringReader sr = new(xml);
			using XmlReader reader = XmlReader.Create(sr, XmlSettings);
			doc.Load(reader);
			return doc;
		}
		catch (XmlException)
		{
			return null;
		}
	}

	/// <summary>Reads a named EventData/UserData value, normalising blank sentinels to null.</summary>
	public static string? GetData(XmlDocument? doc, string name)
	{
		if (doc is null)
		{
			return null;
		}

		XmlNode? node = doc.SelectSingleNode(
			$"//*[local-name()='EventData']/*[local-name()='Data' and @Name='{name}']")
			?? doc.SelectSingleNode($"//*[local-name()='UserData']//*[local-name()='{name}']");

		string? value = node?.InnerText?.Trim();
		return value switch
		{
			null or "" or "-" or "N/A" => null,
			_ => value,
		};
	}

	/// <summary>Reads a named field as int or returns null when missing / unparseable.</summary>
	public static int? GetInt(XmlDocument? doc, string name)
	{
		string? raw = GetData(doc, name);
		if (raw is null)
		{
			return null;
		}

		if (raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
			&& int.TryParse(raw.AsSpan(2), System.Globalization.NumberStyles.HexNumber, null, out int hex))
		{
			return hex;
		}

		return int.TryParse(raw, out int v) ? v : null;
	}
}
