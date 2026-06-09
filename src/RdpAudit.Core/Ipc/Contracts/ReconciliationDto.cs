// File:    src/RdpAudit.Core/Ipc/Contracts/ReconciliationDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: IPC DTOs for the live enforcement reconciliation surface: a per-block reconciled row,
//          the aggregate report (reconciled blocks + orphaned backend objects), and the result of
//          the emergency "remove all RdpAudit enforcement" cleanup. These let the Configurator
//          build the Active Blocks view from reconciliation results — never DB rows alone — and
//          surface verify / repair / cleanup outcomes to the operator.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;
using RdpAudit.Core.Config;
using RdpAudit.Core.Firewall;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>One reconciled (provider, ip) block or orphaned backend object.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ReconciledBlockDto
{
	[Key(0)]
	public long ActiveBlockId { get; set; }

	[Key(1)]
	public string Ip { get; set; } = string.Empty;

	[Key(2)]
	public FirewallProviderKind Provider { get; set; }

	[Key(3)]
	public FirewallEnforcementBackend Backend { get; set; }

	[Key(4)]
	public EnforcementStatus Status { get; set; }

	[Key(5)]
	public EnforcementConfidence Confidence { get; set; }

	[Key(6)]
	public string? EnforcementObjectId { get; set; }

	[Key(7)]
	public DateTime? ExpiresUtc { get; set; }

	[Key(8)]
	public string? Detail { get; set; }

	[Key(9)]
	public string RecommendedAction { get; set; } = string.Empty;

	/// <summary>Per-IP last provider error, surfaced so the Repair grid never shows a bare
	/// "Failed / Failed". Null when the last attempt succeeded or no attempt was recorded.</summary>
	[Key(10)]
	public string? LastError { get; set; }

	/// <summary>UTC timestamp of the most recent block / repair attempt for this IP.</summary>
	[Key(11)]
	public DateTime? LastAttemptUtc { get; set; }

	/// <summary>Backend command line of the most recent attempt (e.g. the netsh argument vector).</summary>
	[Key(12)]
	public string? BackendCommand { get; set; }

	/// <summary>Bounded stdout preview of the most recent backend attempt.</summary>
	[Key(13)]
	public string? BackendStdoutPreview { get; set; }

	/// <summary>Bounded stderr preview of the most recent backend attempt.</summary>
	[Key(14)]
	public string? BackendStderrPreview { get; set; }

	/// <summary>Process exit code of the most recent backend attempt; null when none captured.</summary>
	[Key(15)]
	public int? ExitCode { get; set; }

	/// <summary>True when the most recent backend attempt hit its hard timeout.</summary>
	[Key(16)]
	public bool? TimedOut { get; set; }

	/// <summary>Wall-clock duration in milliseconds of the most recent backend attempt.</summary>
	[Key(17)]
	public long? DurationMs { get; set; }

	/// <summary>Rule name created / verified by the most recent attempt.</summary>
	[Key(18)]
	public string? RuleName { get; set; }

	/// <summary>Backend rule handle of the most recent attempt.</summary>
	[Key(19)]
	public string? RuleHandle { get; set; }

	/// <summary>Scanner / runner backend used for the most recent attempt (e.g. NetshText).</summary>
	[Key(20)]
	public string? ScannerBackend { get; set; }

	/// <summary>Human-readable reason the post-block verifier reached its verdict on the most recent attempt.</summary>
	[Key(21)]
	public string? VerifierReason { get; set; }
}

/// <summary>Aggregate reconciliation report: reconciled desired blocks plus orphaned RdpAudit rules
/// with no backing database row.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ReconciliationReportDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	[Key(1)]
	public DateTime GeneratedUtc { get; set; }

	[Key(2)]
	public List<ReconciledBlockDto> Blocks { get; set; } = new();

	[Key(3)]
	public List<ReconciledBlockDto> Orphans { get; set; } = new();

	[Key(4)]
	public int VerifiedCount { get; set; }

	[Key(5)]
	public int UnenforcedCount { get; set; }

	[Key(6)]
	public string? Message { get; set; }

	/// <summary>Which enumeration backend produced the Windows firewall scan behind this report:
	/// "PowerShellJson" (locale-independent, preferred), "NetshText" (locale-fragile fallback), or
	/// "None" (not scanned). Surfaced in diagnostics so the operator can tell a reliable read from a
	/// locale-fragile one.</summary>
	[Key(7)]
	public string ScannerBackend { get; set; } = "None";

	/// <summary>Human-readable note from the Windows firewall scan (backend detail / failure cause).</summary>
	[Key(8)]
	public string? ScannerNote { get; set; }
}

/// <summary>Result of the DB-maintenance dedupe action that collapses duplicate BlocklistEntry rows
/// per IP down to one canonical row. Duplicates are soft-disabled with an audit annotation rather than
/// hard-deleted, so the action is reversible and traceable.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class BlocklistDedupeResultDto
{
	/// <summary>Number of distinct IPs that had more than one row and were collapsed.</summary>
	[Key(0)]
	public int IpsCollapsed { get; set; }

	/// <summary>Number of duplicate rows soft-disabled (canonical rows are never touched).</summary>
	[Key(1)]
	public int RowsDisabled { get; set; }

	/// <summary>Per-IP audit lines describing the canonical row kept and the duplicate ids disabled.</summary>
	[Key(2)]
	public List<string> Audit { get; set; } = new();

	/// <summary>Operator-facing summary.</summary>
	[Key(3)]
	public string Message { get; set; } = string.Empty;

	/// <summary>Overall status.</summary>
	[Key(4)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;
}

/// <summary>Structured result of removing a single selected BlockList row by its stable surrogate id.
/// Captures exactly what happened to the row, the IP's other rows, the ActiveBlock, and the live
/// firewall rule(s) so the operator never sees an opaque success/failure. The firewall is only touched
/// when the removed row was the last enabled BlockList row for that IP.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class BlocklistRemovalResultDto
{
	/// <summary>The stable BlocklistEntry.Id the operation targeted (echoed back for the operator).</summary>
	[Key(0)]
	public long SelectedId { get; set; }

	/// <summary>Normalized IP of the targeted row (empty when the id matched nothing).</summary>
	[Key(1)]
	public string Ip { get; set; } = string.Empty;

	/// <summary>Number of BlocklistEntry rows soft-disabled by this operation (0 or 1 for an id-targeted remove).</summary>
	[Key(2)]
	public int RowsAffected { get; set; }

	/// <summary>True when the targeted row was enabled before removal; false when it was already disabled.</summary>
	[Key(3)]
	public bool WasEnabled { get; set; }

	/// <summary>True when the IP's ActiveBlock row(s) were marked Removed because no enabled BlockList row remained.</summary>
	[Key(4)]
	public bool ActiveBlockRemoved { get; set; }

	/// <summary>True when at least one live firewall rule for the IP was removed.</summary>
	[Key(5)]
	public bool FirewallRuleRemoved { get; set; }

	/// <summary>Count of orphan firewall rules cleaned up for the IP (rules with no remaining enabled row).</summary>
	[Key(6)]
	public int OrphanRulesRemoved { get; set; }

	/// <summary>Operator-facing summary of what happened.</summary>
	[Key(7)]
	public string Message { get; set; } = string.Empty;

	/// <summary>Non-null when the operation failed; carries a sanitized cause.</summary>
	[Key(8)]
	public string? Error { get; set; }

	/// <summary>Detailed multi-line diagnostic log, populated for the Diagnostics DEBUG view.</summary>
	[Key(9)]
	public string? DebugLog { get; set; }

	/// <summary>Overall status of the removal.</summary>
	[Key(10)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;
}

/// <summary>Result of the emergency "remove all RdpAudit enforcement" cleanup.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class EnforcementCleanupResultDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	[Key(1)]
	public int FirewallRulesRemoved { get; set; }

	[Key(2)]
	public int RoutesRemoved { get; set; }

	[Key(3)]
	public int IpsecObjectsRemoved { get; set; }

	[Key(4)]
	public int ActiveBlockRowsMarkedRemoved { get; set; }

	[Key(5)]
	public int Failures { get; set; }

	[Key(6)]
	public List<string> Actions { get; set; } = new();

	[Key(7)]
	public string? Message { get; set; }
}
