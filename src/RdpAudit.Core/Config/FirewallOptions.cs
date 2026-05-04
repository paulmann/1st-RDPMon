// File:    src/RdpAudit.Core/Config/FirewallOptions.cs
// Module:  RdpAudit.Core.Config
// Purpose: Settings for automatic firewall blocking on threat thresholds.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Config;

/// <summary>Settings for automatic firewall blocking.</summary>
public sealed class FirewallOptions
{
	public bool AutoBlockBruteForce { get; set; }

	public int AutoBlockThreshold { get; set; } = 50;

	public string BlockRuleName { get; set; } = "RdpAudit-Block";
}
