// File:    src/RdpAudit.Core/Ipc/Contracts/ShadowPolicyStatusDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO describing the current Terminal Services shadow policy plus backup metadata.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO describing the current Terminal Services shadow policy plus backup metadata.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ShadowPolicyStatusDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>Current Shadow registry value (0..4); -1 means not configured / unknown.</summary>
	[Key(1)]
	public int ShadowMode { get; set; } = -1;

	[Key(2)]
	public bool HasBackup { get; set; }

	[Key(3)]
	public DateTime? BackupCreatedUtc { get; set; }

	[Key(4)]
	public string? Message { get; set; }
}
