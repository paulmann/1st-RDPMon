// File:    src/RdpAudit.Core/Ipc/Contracts/DiagnosticsSnapshotDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: LLM-friendly diagnostics snapshot returned by IpcCommand.GetDiagnostics. Bundles every
//          piece of state an operator (or a downstream model) needs to triage a "Failed=0 but
//          PowerShell sees 4625" situation without leaving the Configurator: effective channels
//          and event IDs, Security watcher and backfill state, RawEvent / AuthAttemptFact counts
//          by channel and by event ID, the most recent monitoring-config repair report, the
//          service version, install path, and last pipeline error messages. All values are plain
//          strings / numbers / lists so the snapshot is trivially JSON-round-trippable.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>LLM-friendly diagnostics snapshot for the Configurator Diagnostic tab.</summary>
public sealed class DiagnosticsSnapshotDto
{
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	public string? Message { get; set; }

	public DateTime GeneratedUtc { get; set; }

	public string? ServiceVersion { get; set; }

	public string? InstallPath { get; set; }

	public string? DatabasePath { get; set; }

	/// <summary>Effective channels the service is currently monitoring.</summary>
	public List<string> EnabledChannels { get; set; } = new();

	/// <summary>Effective event IDs filter (empty means "all events from EnabledChannels").</summary>
	public List<int> EnabledEventIds { get; set; } = new();

	/// <summary>Per-channel status as last reported by the EventCollectorWorker (Armed / Disabled /
	/// RestartScheduled / SkippedUnavailable / etc).</summary>
	public Dictionary<string, string> ChannelStatus { get; set; } = new(StringComparer.OrdinalIgnoreCase);

	public bool SecurityWatcherEnabled { get; set; }

	public long SecurityEventsRead { get; set; }

	public long SecurityEventsNormalized { get; set; }

	public long SecurityEventsRejected { get; set; }

	public string? LastSecurityChannelError { get; set; }

	public DateTime? LastSecurityEventUtc { get; set; }

	public DateTime? SecurityBackfillLastRunUtc { get; set; }

	public long SecurityBackfillRecordsRead { get; set; }

	public long SecurityBackfillRecordsForwarded { get; set; }

	public long SecurityBackfillRecordsDeduped { get; set; }

	public long Security4624Count { get; set; }

	public long Security4625Count { get; set; }

	public long Security4648Count { get; set; }

	public long AuthAttemptFactCreated { get; set; }

	public long AuthAttemptFactFailed { get; set; }

	public long AuthAttemptFactSucceeded { get; set; }

	public DateTime? LastAuthAttemptFactCreatedUtc { get; set; }

	public bool MonitoringConfigRepairChanged { get; set; }

	public List<string> MonitoringConfigRepairAddedChannels { get; set; } = new();

	public List<int> MonitoringConfigRepairAddedEventIds { get; set; } = new();

	public string? MonitoringConfigRepairReason { get; set; }

	public DateTime? MonitoringConfigRepairUtc { get; set; }

	public long MonitoringConfigRepairChangedRunCount { get; set; }

	/// <summary>Total rows in RawEvents.</summary>
	public long RawEventsTotal { get; set; }

	/// <summary>Total rows in AuthAttemptFacts.</summary>
	public long AuthAttemptFactsTotal { get; set; }

	/// <summary>RawEvents grouped by channel.</summary>
	public List<DiagnosticsChannelCount> RawEventsByChannel { get; set; } = new();

	/// <summary>RawEvents grouped by event ID (top 30 by count).</summary>
	public List<DiagnosticsEventIdCount> RawEventsByEventId { get; set; } = new();

	/// <summary>AuthAttemptFacts grouped by EvidenceEventId + Outcome (top 30).</summary>
	public List<DiagnosticsFactOutcomeCount> AuthAttemptFactsByOutcome { get; set; } = new();

	/// <summary>Recent free-form pipeline error messages (e.g. last Security channel error, last
	/// reject reason). Bounded to 16 entries.</summary>
	public List<string> RecentPipelineErrors { get; set; } = new();
}

/// <summary>One row in <see cref="DiagnosticsSnapshotDto.RawEventsByChannel"/>.</summary>
public sealed class DiagnosticsChannelCount
{
	public string Channel { get; set; } = string.Empty;

	public long Count { get; set; }
}

/// <summary>One row in <see cref="DiagnosticsSnapshotDto.RawEventsByEventId"/>.</summary>
public sealed class DiagnosticsEventIdCount
{
	public string Channel { get; set; } = string.Empty;

	public int EventId { get; set; }

	public long Count { get; set; }
}

/// <summary>One row in <see cref="DiagnosticsSnapshotDto.AuthAttemptFactsByOutcome"/>.</summary>
public sealed class DiagnosticsFactOutcomeCount
{
	public int EvidenceEventId { get; set; }

	public string Outcome { get; set; } = string.Empty;

	public long Count { get; set; }
}
