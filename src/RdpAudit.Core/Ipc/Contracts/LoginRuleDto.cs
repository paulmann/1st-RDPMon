// File:    src/RdpAudit.Core/Ipc/Contracts/LoginRuleDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO entry for login trip-wire rules returned by ListLoginRules.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO entry for a login trip-wire rule.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class LoginRuleDto
{
	[Key(0)]
	public long Id { get; set; }

	[Key(1)]
	public string Login { get; set; } = string.Empty;

	[Key(2)]
	public string? Note { get; set; }

	[Key(3)]
	public bool Enabled { get; set; }

	[Key(4)]
	public DateTime AddedUtc { get; set; }
}
