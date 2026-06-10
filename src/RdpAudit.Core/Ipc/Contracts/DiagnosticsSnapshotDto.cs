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

	/// <summary>v1.2.2 — per-id Security backfill diagnostic snapshots. Each entry carries
	/// the last run UTC, elapsed ms, records read / forwarded / duplicate counts, the
	/// classified status (OkForwarded / OkDuplicateOnly / NoEvents / TimeoutSkipped /
	/// AccessDenied / ChannelNotFound / QueryFailed), and the last exception type/message
	/// when the outcome is non-success. Surfaced separately from
	/// <see cref="ChannelStatus"/> so the Diagnostic UI can compact / group NoEvents rows
	/// without losing the underlying detail.</summary>
	public List<DiagnosticsSecurityBackfillPerId> SecurityBackfillPerId { get; set; } = new();

	/// <summary>v1.2.2 — aggregate summary line for the Security backfill row, formatted as
	/// "Forwarded:N, Duplicate:M, NoEvents:K, TimeoutSkipped:T, Failed:F".</summary>
	public string? SecurityBackfillAggregateStatus { get; set; }

	/// <summary>v1.2.2 — raw qwinsta stdout captured during the last RDP session
	/// enumeration. Surfaced in the support bundle so an operator can re-derive what the
	/// parser saw without reproducing the spawn.</summary>
	public string? RdpClientsRawQwinsta { get; set; }

	/// <summary>v1.2.2 — raw quser stdout captured during the last RDP session enumeration.</summary>
	public string? RdpClientsRawQuser { get; set; }

	/// <summary>v1.2.2 — parsed RDP rows with structured reasoning (state, IsCurrent flag,
	/// raw-query-current marker, rejection reason if any). Surfaced for the support bundle.</summary>
	public List<DiagnosticsRdpParsedRow> RdpClientsParsedRows { get; set; } = new();

	/// <summary>v1.2.2 — the SessionIds the parser elected as the operator-visible active
	/// RDP sessions according to the validated Current? semantics
	/// (Active AND rdp-tcp# AND username AND 1 &lt; SessionId &lt; 65536).</summary>
	public List<int> RdpClientsActiveRdpSessionIds { get; set; } = new();

	// --- v1.3.4: resolved RDP listener port (never hardcoded 3389 — see RdpListenerPortResolver). ---

	/// <summary>The TCP port the local RDP listener is configured on, resolved at snapshot time. On a
	/// host where the operator moved RDP to e.g. 55554 this reflects 55554, never the 3389 default.</summary>
	public int ResolvedRdpPort { get; set; }

	/// <summary>Where <see cref="ResolvedRdpPort"/> came from: "Registry" (PortNumber present and in
	/// range) or "Default" (missing/invalid — Microsoft default used).</summary>
	public string? ResolvedRdpPortSource { get; set; }

	/// <summary>Human-readable detail behind the port resolution (e.g. "PortNumber=55554").</summary>
	public string? ResolvedRdpPortDetail { get; set; }

	/// <summary>The firewall block scope the service enforces: "RdpOnly" blocks the resolved RDP port
	/// (TCP LocalPort=&lt;port&gt;); "AllInbound" blocks every inbound port (LocalPort=Any).</summary>
	public string? FirewallBlockScope { get; set; }

	// --- v1.3.4: RDP Activity (Attack Statistics) freshness diagnostics. ---

	/// <summary>UTC of the newest RawEvent row, or null when the table is empty. Compared against the
	/// AuthAttemptFact / AttackStat freshness below to localise where the pipeline went stale.</summary>
	public DateTime? LatestRawEventUtc { get; set; }

	/// <summary>UTC of the newest AuthAttemptFact row (the atomic source of truth for outcomes).</summary>
	public DateTime? LatestAuthAttemptFactUtc { get; set; }

	/// <summary>UTC of the newest AttackStat.LastUpdatedUtc — when the projection last touched any row.</summary>
	public DateTime? LatestAttackStatUpdatedUtc { get; set; }

	/// <summary>UTC of the most recent AttackStatsRefreshWorker pass completion (success or failure).</summary>
	public DateTime? StatsWorkerLastRunUtc { get; set; }

	/// <summary>Rows upserted on the most recent successful projection pass.</summary>
	public long StatsWorkerLastRowsUpserted { get; set; }

	/// <summary>Cumulative count of projection passes since service start.</summary>
	public long StatsWorkerRunCount { get; set; }

	/// <summary>Last projection-worker error, or null when the last pass succeeded.</summary>
	public string? StatsWorkerLastError { get; set; }

	/// <summary>Total rows currently in AttackStats.</summary>
	public long AttackStatsTotal { get; set; }

	/// <summary>Most recent durable OperationLog entries (program actions), newest first. Bounded.
	/// Surfaced so the Diagnostic tab can show recent activity even when other probes fail.</summary>
	public List<DiagnosticsOperationLogLine> RecentOperationLog { get; set; } = new();
}

/// <summary>v1.3.4 — one compact recent OperationLog line for the Diagnostic snapshot tail.</summary>
public sealed class DiagnosticsOperationLogLine
{
	public DateTime TimeUtc { get; set; }

	public string Severity { get; set; } = string.Empty;

	public string Source { get; set; } = string.Empty;

	public string Operation { get; set; } = string.Empty;

	public string Message { get; set; } = string.Empty;
}

/// <summary>v1.2.2 — one row of per-id Security backfill diagnostic detail.</summary>
public sealed class DiagnosticsSecurityBackfillPerId
{
	public int EventId { get; set; }

	public DateTime LastRunUtc { get; set; }

	public long ElapsedMs { get; set; }

	public int RecordsRead { get; set; }

	public int Forwarded { get; set; }

	public int Duplicate { get; set; }

	public string Status { get; set; } = string.Empty;

	public string? LastExceptionType { get; set; }

	public string? LastExceptionMessage { get; set; }
}

/// <summary>v1.2.2 — one row of parsed RDP session detail surfaced in the diagnostic
/// support bundle. Carries both the raw qwinsta current marker and the validated
/// operator-visible Current?/ActiveRdp flag so the bundle is self-explanatory.</summary>
public sealed class DiagnosticsRdpParsedRow
{
	public int SessionId { get; set; }

	public string SessionName { get; set; } = string.Empty;

	public string UserName { get; set; } = string.Empty;

	public string State { get; set; } = string.Empty;

	/// <summary>Raw <c>&gt;</c>-marker from qwinsta. Operator-visible Current? must NOT be
	/// driven by this flag — see <see cref="IsActiveRdp"/>.</summary>
	public bool IsQueryCurrent { get; set; }

	/// <summary>Validated operator-visible active-RDP flag — Active AND rdp-tcp# AND
	/// username AND 1 &lt; SessionId &lt; 65536.</summary>
	public bool IsActiveRdp { get; set; }

	/// <summary>Reason this row was rejected from the active-RDP set, when applicable.</summary>
	public string? RejectionReason { get; set; }
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
