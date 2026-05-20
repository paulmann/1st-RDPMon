// File:    src/RdpAudit.Core/Ipc/Contracts/RdpSessionDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO describing a live RDP session for the ListRdpSessions IPC command.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO describing a live RDP session.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class RdpSessionDto
{
	[Key(0)]
	public int SessionId { get; set; }

	[Key(1)]
	public string UserName { get; set; } = string.Empty;

	[Key(2)]
	public string? Domain { get; set; }

	[Key(3)]
	public string? ClientName { get; set; }

	[Key(4)]
	public string? ClientAddress { get; set; }

	/// <summary>WTS session state expressed as a stable string (Active, Disconnected, Idle, ...).</summary>
	[Key(5)]
	public string State { get; set; } = string.Empty;

	[Key(6)]
	public DateTime? ConnectTimeUtc { get; set; }

	[Key(7)]
	public DateTime? LastInputTimeUtc { get; set; }

	/// <summary>Station / WinStation name reported by qwinsta (e.g. "rdp-tcp#3", "console").</summary>
	[Key(8)]
	public string? SessionName { get; set; }

	/// <summary>True when this row corresponds to the session the query was issued from.</summary>
	[Key(9)]
	public bool IsCurrent { get; set; }

	/// <summary>True when the session row is currently in an active connected state.</summary>
	[Key(10)]
	public bool IsActive { get; set; }

	/// <summary>True when the session is in a disconnected state and may be reconnected.</summary>
	[Key(11)]
	public bool IsDisconnected { get; set; }

	// --- Stage IP-D additions (append-only). Historical context derived from RdpConnectionFacts.
	// These never overwrite live data and are populated only when a matching fact exists.

	/// <summary>Earliest <c>FirstSeenUtc</c> across matching connection facts; null when none exist.</summary>
	[Key(12)]
	public DateTime? HistoricalFirstSeenUtc { get; set; }

	/// <summary>Latest <c>LastSeenUtc</c> across matching connection facts; null when none exist.</summary>
	[Key(13)]
	public DateTime? HistoricalLastSeenUtc { get; set; }

	/// <summary>Sum of failed logons across matching connection facts; zero when no facts exist.</summary>
	[Key(14)]
	public long HistoricalFailedLogons { get; set; }

	/// <summary>Sum of successful logons across matching connection facts; zero when no facts exist.</summary>
	[Key(15)]
	public long HistoricalSuccessfulLogons { get; set; }

	/// <summary>Comma-separated, deduplicated list of usernames attempted from this IP across matching facts. Bounded width.</summary>
	[Key(16)]
	public string? HistoricalUserNamesAttempted { get; set; }
}

/// <summary>List wrapper for <c>ListRdpSessions</c> so the response carries an operation status.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class RdpSessionListDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	[Key(1)]
	public List<RdpSessionDto> Sessions { get; set; } = new();

	[Key(2)]
	public string? Message { get; set; }

	[Key(3)]
	public DateTime QueriedUtc { get; set; }
}
