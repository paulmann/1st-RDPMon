// File:    src/RdpAudit.Core/Ipc/Contracts/FirewallStatusDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO returned by GetFirewallStatus describing provider availability and counters.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;
using RdpAudit.Core.Config;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO returned by <c>GetFirewallStatus</c> describing provider availability and counters.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class FirewallStatusDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	[Key(1)]
	public FirewallProviderKind ConfiguredProvider { get; set; } = FirewallProviderKind.None;

	[Key(2)]
	public bool WindowsAvailable { get; set; }

	[Key(3)]
	public bool MikroTikAvailable { get; set; }

	[Key(4)]
	public int ActiveBlockCount { get; set; }

	[Key(5)]
	public int WhitelistCount { get; set; }

	[Key(6)]
	public int BlacklistCount { get; set; }

	/// <summary>Operator-facing message; never contains secret material.</summary>
	[Key(7)]
	public string? Message { get; set; }
}
