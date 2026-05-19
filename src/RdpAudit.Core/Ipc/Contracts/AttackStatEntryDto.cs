// File:    src/RdpAudit.Core/Ipc/Contracts/AttackStatEntryDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO entry for a single per-IP Attack Statistics row surfaced to the Configurator.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO entry for a single per-IP Attack Statistics row.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class AttackStatEntryDto
{
	[Key(0)]
	public string Ip { get; set; } = string.Empty;

	[Key(1)]
	public long TotalAttempts { get; set; }

	[Key(2)]
	public long Successful { get; set; }

	[Key(3)]
	public long Failed { get; set; }

	[Key(4)]
	public DateTime FirstSeenUtc { get; set; }

	[Key(5)]
	public DateTime LastSeenUtc { get; set; }

	[Key(6)]
	public long DurationSeconds { get; set; }

	/// <summary>JSON array of strings produced by <c>AttackStatProjection.SerializeTopLogins</c>.</summary>
	[Key(7)]
	public string Top10AttemptedLogins { get; set; } = "[]";

	[Key(8)]
	public int? LastLoginType { get; set; }

	[Key(9)]
	public double ThreatScore { get; set; }

	[Key(10)]
	public AttackThreatLevel ThreatLevel { get; set; }

	[Key(11)]
	public bool IsBlocked { get; set; }

	[Key(12)]
	public DateTime LastUpdatedUtc { get; set; }
}
