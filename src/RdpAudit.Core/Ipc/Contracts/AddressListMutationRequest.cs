// File:    src/RdpAudit.Core/Ipc/Contracts/AddressListMutationRequest.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Request payload used for AddToBlocklist / RemoveFromBlocklist / AddToWhitelist /
//          RemoveFromWhitelist commands.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request payload for whitelist / blocklist mutation commands.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class AddressListMutationRequest
{
	[Key(0)]
	public string Address { get; set; } = string.Empty;

	[Key(1)]
	public string? Note { get; set; }

	[Key(2)]
	public int DurationMinutes { get; set; }
}
