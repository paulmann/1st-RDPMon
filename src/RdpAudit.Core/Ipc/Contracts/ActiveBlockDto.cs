// File:    src/RdpAudit.Core/Ipc/Contracts/ActiveBlockDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO entry for ListActiveBlocksDetailed returning the full ActiveBlock row shape.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;
using RdpAudit.Core.Config;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO entry for a currently installed firewall block.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ActiveBlockDto
{
	[Key(0)]
	public long Id { get; set; }

	[Key(1)]
	public string Ip { get; set; } = string.Empty;

	[Key(2)]
	public FirewallProviderKind Provider { get; set; }

	[Key(3)]
	public string? RuleHandle { get; set; }

	[Key(4)]
	public DateTime CreatedUtc { get; set; }

	[Key(5)]
	public DateTime? ExpiresUtc { get; set; }

	[Key(6)]
	public string Reason { get; set; } = string.Empty;

	[Key(7)]
	public ActiveBlockStatus Status { get; set; }

	[Key(8)]
	public string? LastError { get; set; }
}
