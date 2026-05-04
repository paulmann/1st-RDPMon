// File:    src/RdpAudit.Core/Ipc/IpcConstants.cs
// Module:  RdpAudit.Core.Ipc
// Purpose: Shared constants for the Named Pipe IPC channel.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Ipc;

/// <summary>Shared constants for the Named Pipe IPC channel.</summary>
public static class IpcConstants
{
	public const string PipeName = "RdpAuditService";

	public const int MaxFrameBytes = 16 * 1024 * 1024;

	public const int ConnectTimeoutMs = 2_000;

	public const int OperationTimeoutMs = 5_000;
}
