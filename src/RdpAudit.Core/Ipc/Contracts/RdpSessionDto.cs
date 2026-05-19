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
}
