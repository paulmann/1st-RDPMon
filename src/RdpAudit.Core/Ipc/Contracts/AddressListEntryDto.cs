// File:    src/RdpAudit.Core/Ipc/Contracts/AddressListEntryDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO entry for whitelist / blocklist / active-block listings returned over IPC.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO entry for whitelist / blocklist / active-block listings.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class AddressListEntryDto
{
	[Key(0)]
	public string Address { get; set; } = string.Empty;

	[Key(1)]
	public string? Note { get; set; }

	[Key(2)]
	public DateTime? AddedUtc { get; set; }

	[Key(3)]
	public DateTime? ExpiresUtc { get; set; }

	/// <summary>Origin of the entry (e.g. "Configurator", "AutoBlock", "Config:Blacklist").</summary>
	[Key(4)]
	public string? Source { get; set; }
}
