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

	/// <summary>Cumulative count of Security 4625 (failed logon) events since service start.</summary>
	public long Security4625Count { get; set; }

	/// <summary>Cumulative count of Security 4624 (successful logon) events since service start.</summary>
	public long Security4624Count { get; set; }

	/// <summary>Cumulative count of Security 4648 (explicit credentials) events since service start.</summary>
	public long Security4648Count { get; set; }

	/// <summary>Cumulative count of RDP pre-authentication observations (TS-RCM 261, RdpCoreTS 131)
	/// that did not have a matching Security 4624/4625/4648 inside the correlation window.</summary>
	public long RdpCorePreAuthOrphans { get; set; }

	/// <summary>UTC timestamp of the most recent Security 4624/4625/4648 received, or null when none.</summary>
	public DateTime? LastSecurityEventUtc { get; set; }

	/// <summary>UTC timestamp of the most recent TS-RCM 261 / RdpCoreTS 131 received, or null when none.</summary>
	public DateTime? LastRdpCorePreAuthUtc { get; set; }

	/// <summary>Human-readable diagnostic emitted when pre-auth events accumulate without matching
	/// Security events. Null until the watchdog fires. Configurator surfaces this on the dashboard.</summary>
	public string? SecurityCorrelationDiagnostic { get; set; }
}
