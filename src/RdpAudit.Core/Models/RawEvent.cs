// File:    src/RdpAudit.Core/Models/RawEvent.cs
// Module:  RdpAudit.Core.Models
// Purpose: Persisted, normalized representation of a single Windows event.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>
/// Persisted, normalized representation of a single Windows event captured from
/// one of the monitored channels.
/// </summary>
public sealed class RawEvent
{
	public long Id { get; set; }

	public int EventId { get; set; }

	public string Channel { get; set; } = string.Empty;

	public DateTime TimeUtc { get; set; }

	public string? SourceIp { get; set; }

	/// <summary>
	/// True when <see cref="SourceIp"/> was attached by in-memory session correlation rather than
	/// being read directly from the event payload. Direct-extraction events leave this false.
	/// </summary>
	public bool SourceIpDerived { get; set; }

	public string? UserName { get; set; }

	public string? Domain { get; set; }

	public int? SessionId { get; set; }

	public int? LogonType { get; set; }

	public string? LogonId { get; set; }

	public string? AuthPackage { get; set; }

	public string? Status { get; set; }

	public string? ProcessName { get; set; }

	public string? CommandLine { get; set; }

	public string? ObjectName { get; set; }

	public string? AccessMask { get; set; }

	public string? Details { get; set; }

	public bool Processed { get; set; }

	public long? AddressId { get; set; }

	public Address? Address { get; set; }

	public long? SessionRefId { get; set; }

	public Session? SessionRef { get; set; }
}
