// File:    src/RdpAudit.Core/Ipc/Contracts/AttackStatsDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO returned by GetAttackStats summarising recent attack-related metrics.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO returned by <c>GetAttackStats</c> summarising recent attack-related metrics.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class AttackStatsDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	[Key(1)]
	public DateTime WindowStartUtc { get; set; }

	[Key(2)]
	public DateTime WindowEndUtc { get; set; }

	[Key(3)]
	public long FailedLogons { get; set; }

	[Key(4)]
	public long SuccessfulLogons { get; set; }

	[Key(5)]
	public long DistinctSourceIps { get; set; }

	[Key(6)]
	public long AlertsRaised { get; set; }

	[Key(7)]
	public long AddressesAutoBlocked { get; set; }

	[Key(8)]
	public string? Message { get; set; }
}
