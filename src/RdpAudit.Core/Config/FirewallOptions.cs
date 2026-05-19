// File:    src/RdpAudit.Core/Config/FirewallOptions.cs
// Module:  RdpAudit.Core.Config
// Purpose: Settings for automatic firewall blocking on threat thresholds, provider selection,
//          static whitelist / blacklist arrays, and instant-block triggers.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Config;

/// <summary>Settings for automatic firewall blocking, provider selection, and static address lists.</summary>
/// <remarks>
/// Backward-compatible: pre-Stage-1 callers used only <see cref="AutoBlockBruteForce"/>,
/// <see cref="AutoBlockThreshold"/>, and <see cref="BlockRuleName"/>. New fields have safe defaults
/// so existing appsettings.json documents continue to bind.
/// </remarks>
public sealed class FirewallOptions
{
	/// <summary>Enables the brute-force-driven auto-block worker.</summary>
	public bool AutoBlockBruteForce { get; set; }

	/// <summary>Threshold of recent failures from a single IP that triggers an auto-block.</summary>
	public int AutoBlockThreshold { get; set; } = 50;

	/// <summary>Base name used to construct per-IP firewall rule names.</summary>
	public string BlockRuleName { get; set; } = "RdpAudit-Block";

	/// <summary>Selected firewall provider; defaults to Windows for backward compatibility.</summary>
	public FirewallProviderKind Provider { get; set; } = FirewallProviderKind.Windows;

	/// <summary>Static whitelist of CIDR / IP entries that must NEVER be auto-blocked.</summary>
	public List<string> Whitelist { get; set; } = new();

	/// <summary>Static blacklist of CIDR / IP entries that must always be considered hostile.</summary>
	public List<string> Blacklist { get; set; } = new();

	/// <summary>When true, a successful logon from a blacklisted address triggers an immediate block.</summary>
	public bool BlockOnBlacklistedLogin { get; set; }

	/// <summary>User names that, when seen in a successful logon, trigger an immediate block of the source IP.</summary>
	/// <remarks>Common values include disabled / honeypot accounts (e.g. "guest", "test", "admin").</remarks>
	public List<string> InstantBlockLogins { get; set; } = new();

	/// <summary>Default block duration in minutes; zero or negative means permanent until manually removed.</summary>
	public int DefaultBlockDurationMinutes { get; set; }

	/// <summary>Maximum number of distinct simultaneous block rules the provider is allowed to create.</summary>
	/// <remarks>Acts as a guardrail against rule-table flooding from a runaway worker or scripted attack.</remarks>
	public int MaxActiveBlocks { get; set; } = 10000;
}
