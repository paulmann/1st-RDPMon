// File:    src/RdpAudit.Core/Ipc/IpcCommand.cs
// Module:  RdpAudit.Core.Ipc
// Purpose: Enumeration of IPC commands sent from Configurator to Service.
// Extends: System.Enum
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Ipc;

/// <summary>Enumeration of IPC commands sent from Configurator to Service.</summary>
/// <remarks>
/// APPEND-ONLY ABI: ordinal values must NEVER be reused, reordered, or renumbered. Retired
/// commands are deprecated in place but keep their ordinal forever so deployed clients and
/// services across version skew never collide. Stage 1 reserves ordinals 11..31 even when the
/// corresponding handlers are not yet implemented in <c>IpcDispatcher</c>.
/// </remarks>
public enum IpcCommand
{
	Ping = 0,
	GetStatus = 1,
	GetRecentEvents = 2,
	GetRecentAlerts = 3,
	GetAddresses = 4,
	GetSessions = 5,
	AcknowledgeAlert = 6,
	BlockAddress = 7,
	UnblockAddress = 8,
	GetSettings = 9,
	SaveSettings = 10,

	// --- Stage 1 reservations (append-only). Handlers may return NotImplemented until later stages. ---
	GetFirewallStatus = 11,
	ListBlocklist = 12,
	ListWhitelist = 13,
	AddToBlocklist = 14,
	RemoveFromBlocklist = 15,
	AddToWhitelist = 16,
	RemoveFromWhitelist = 17,
	GetAttackStats = 18,
	ListRdpSessions = 19,
	DisconnectSession = 20,
	LogoffSession = 21,
	ShadowSession = 22,
	GetShadowPolicyStatus = 23,
	ApplyShadowPolicy = 24,
	BackupShadowPolicy = 25,
	RestoreShadowPolicy = 26,
	GetAbuseIpDbStatus = 27,
	TestAbuseIpDbKey = 28,
	GetMikroTikStatus = 29,
	TestMikroTik = 30,
	ListActiveBlocks = 31,

	// --- Stage 5 additions (append-only). ---
	ListLoginRules = 32,
	AddLoginRule = 33,
	RemoveLoginRule = 34,
	SetLoginRuleEnabled = 35,
	ListActiveBlocksDetailed = 36,
	UnblockActiveBlock = 37,

	// --- Stage A additions (append-only). ---
	/// <summary>Returns the operator-facing dashboard summary (attacks today, blocked IPs, sessions, failed logins, service health, DB size and growth).</summary>
	GetOverviewSummary = 38,

	/// <summary>Returns bounded recent / full-for-IP RawEvents plus summary metadata for one IP (export-all-IP-events context action).</summary>
	GetEventsForIp = 39,

	// --- Stage IP-D additions (append-only). ---

	/// <summary>Returns the most recent connection facts (LastSeenUtc desc), bounded by a server-clamped limit and filtered by optional IP / User substrings.</summary>
	ListConnectionFacts = 40,

	/// <summary>Returns bounded connection facts for a single IP plus aggregate counters (failed/successful logons, first/last seen, active flag).</summary>
	GetConnectionFactsForIp = 41,

	// --- Stage RDP-Config additions (append-only). ---

	/// <summary>Returns the current RDP listener configuration snapshot (port, fDenyTSConnections,
	/// NLA, SecurityLayer, single-session, hide-users, shadow mode, plus TermService context).</summary>
	GetRdpConfiguration = 42,

	// --- Stage Diag additions (append-only). ---

	/// <summary>Returns an LLM-friendly diagnostics snapshot: effective channels/event IDs, Security
	/// watcher state + last error + last event UTC, Security backfill telemetry, RawEvent and
	/// AuthAttemptFact counts grouped by channel/event ID, monitoring-config repair report, service
	/// version, install path, and recent pipeline errors. Used by the Configurator's Diagnostic tab.</summary>
	GetDiagnostics = 43,

	// --- Stage Diag2 additions (append-only). ---

	/// <summary>Runs a one-shot bounded Security-channel auth read inside the service process
	/// (under the service account) and returns AccessDenied vs Timeout vs NoEvents vs a parsed
	/// first event. The Configurator's "Run Security Auth Probe" button invokes this; it is the
	/// canonical way to disambiguate "Security Armed but zero events" symptoms from policy /
	/// permission / bookmark / backlog failure modes on a real host.</summary>
	RunSecurityAuthProbe = 44,

	// --- Stage 8 firewall-diagnostics addition (append-only). ---

	/// <summary>Returns a plain-text firewall enforcement diagnostics report: configured provider /
	/// backend / scope, resolved RDP listener port, per-provider availability, RdpAudit-group inbound
	/// block rules present in the Windows firewall store, enabled allow-inbound TCP ports, route /
	/// IPsec backend state, third-party firewall (e.g. Kaspersky) interference note, and a
	/// reconciliation of active-block database rows against verified firewall enforcement. Used by the
	/// Configurator's Firewall tab "Copy firewall diagnostics" button.</summary>
	GetFirewallDiagnostics = 45,

	// --- Stage 1.2.4 live enforcement reconciliation additions (append-only). ---

	/// <summary>Runs a live enforcement reconciliation pass: scans the real Windows Firewall (and
	/// other enabled backends) for RdpAudit rules, compares them against the DB-intended blocks, and
	/// returns a per-block status (Active / MissingRule / ParameterMismatch / Expired / Orphaned /
	/// ProviderUnavailable / EffectiveUnknown / Failed) plus a confidence (Verified /
	/// ExistsButProviderMayBypass / Missing / Failed / Unknown) and recommended next action. Also
	/// returns orphaned RdpAudit rules with no backing database row. RdpAudit never claims an IP is
	/// actively blocked unless a matching backend object is discovered here.</summary>
	ReconcileEnforcement = 46,

	/// <summary>Repairs one ActiveBlock row by id: re-installs the missing/mismatched firewall rule
	/// via the owning backend and re-reconciles, returning the post-repair reconciled row.</summary>
	RepairActiveBlock = 47,

	/// <summary>Emergency cleanup: removes every RdpAudit-created enforcement object (firewall rules,
	/// blackhole routes, IPsec objects if any) and marks the corresponding ActiveBlock rows Removed.
	/// Never deletes unrelated admin-created rules. Returns a per-category removal summary.</summary>
	RemoveAllEnforcement = 48,
}
