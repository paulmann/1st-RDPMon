// File:    src/RdpAudit.Core/Ipc/ServiceStatus.cs
// Module:  RdpAudit.Core.Ipc
// Purpose: Snapshot of runtime service health, surfaced via the IPC GetStatus command.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Ipc;

/// <summary>Snapshot of runtime service health.</summary>
public sealed class ServiceStatus
{
	public string Version { get; set; } = string.Empty;

	public DateTime StartedUtc { get; set; }

	public TimeSpan Uptime { get; set; }

	public int ProcessId { get; set; }

	public long EventsCaptured { get; set; }

	public long EventsDropped { get; set; }

	public long AlertsRaised { get; set; }

	public int ActiveSessions { get; set; }

	public Dictionary<string, string> ChannelStatus { get; set; } = new();
}
