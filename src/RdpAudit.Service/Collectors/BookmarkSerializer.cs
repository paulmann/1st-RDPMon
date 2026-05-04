// File:    src/RdpAudit.Service/Collectors/BookmarkSerializer.cs
// Module:  RdpAudit.Service.Collectors
// Purpose: Round-trips EventBookmark to / from its private XML string representation.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Diagnostics.Eventing.Reader;

namespace RdpAudit.Service.Collectors;

/// <summary>Round-trips EventBookmark to / from its private XML string representation.</summary>
[SupportedOSPlatform("windows")]
public static class BookmarkSerializer
{
	private static readonly FieldInfo? XmlField =
		typeof(EventBookmark).GetField("_xmlString", BindingFlags.Instance | BindingFlags.NonPublic)
		?? typeof(EventBookmark).GetField("xmlString", BindingFlags.Instance | BindingFlags.NonPublic);

	public static string Serialize(EventBookmark bookmark)
	{
		ArgumentNullException.ThrowIfNull(bookmark);
		if (XmlField is null)
		{
			throw new InvalidOperationException("EventBookmark internal XML field not found.");
		}

		return (string?)XmlField.GetValue(bookmark)
			?? throw new InvalidOperationException("EventBookmark XML payload is null.");
	}

	public static EventBookmark Deserialize(string xml)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(xml);
		if (XmlField is null)
		{
			throw new InvalidOperationException("EventBookmark internal XML field not found.");
		}

		EventBookmark instance = (EventBookmark)RuntimeHelpers.GetUninitializedObject(typeof(EventBookmark));
		XmlField.SetValue(instance, xml);
		return instance;
	}
}
