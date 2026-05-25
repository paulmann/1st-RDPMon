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
}
