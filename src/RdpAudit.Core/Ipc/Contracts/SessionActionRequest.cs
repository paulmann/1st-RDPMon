// File:    src/RdpAudit.Core/Ipc/Contracts/SessionActionRequest.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Request payload for DisconnectSession / LogoffSession / ShadowSession IPC commands.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request payload for session-control IPC commands.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class SessionActionRequest
{
	[Key(0)]
	public int SessionId { get; set; }

	/// <summary>Optional operator-provided reason text recorded in the audit log.</summary>
	[Key(1)]
	public string? Reason { get; set; }
}
