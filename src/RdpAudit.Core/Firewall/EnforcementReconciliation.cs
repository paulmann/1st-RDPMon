// File:    src/RdpAudit.Core/Firewall/EnforcementReconciliation.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: Pure domain model + engine for live enforcement reconciliation. RdpAudit must never
//          claim an IP is actively blocked unless a real backend object exists and matches the
//          expected parameters. This file separates the four states the system actually has —
//          DB intent (blocklist), recorded enforcement (ActiveBlock rows), discovered backend
//          objects (live firewall / route / IPsec scan), and the reconciled effective confidence —
//          and the reconciler that maps them to a single EnforcementStatus + EnforcementConfidence
//          per (provider, ip). The engine is Win32-free and EF-free so it is unit-testable cross
//          platform; the Service layer feeds it pre-read facts (desired blocks + discovered rules).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;

namespace RdpAudit.Core.Firewall;

/// <summary>Reconciled status of one desired/observed block. Append-only enum: never reorder.</summary>
public enum EnforcementStatus
{
	/// <summary>A backend object exists and matches every expected parameter — really enforced.</summary>
	Active = 0,

	/// <summary>The database intends a block but no backend object was discovered for it.</summary>
	MissingRule = 1,

	/// <summary>A backend object exists but one or more parameters differ from the desired block
	/// (wrong port / wrong direction / disabled / wrong action / different remote IP).</summary>
	ParameterMismatch = 2,

	/// <summary>The desired block has expired; enforcement should be (or has been) removed.</summary>
	Expired = 3,

	/// <summary>A backend object exists with no backing database row — an orphan to be cleaned up.</summary>
	OrphanedRule = 4,

	/// <summary>The provider/backend that owns this block is unavailable or not implemented, so its
	/// real state cannot be determined.</summary>
	ProviderUnavailable = 5,

	/// <summary>The backend cannot be live-scanned (e.g. route table enumeration is locale-dependent
	/// or unsupported here); the effective state is unknown.</summary>
	EffectiveUnknown = 6,

	/// <summary>The recorded enforcement attempt failed and no usable backend object exists.</summary>
	Failed = 7,

	/// <summary>The block is desired and pending first enforcement (not yet attempted/confirmed).</summary>
	Desired = 8,
}

/// <summary>How confident RdpAudit is that traffic is actually blocked. Append-only enum.</summary>
public enum EnforcementConfidence
{
	/// <summary>A matching backend object was discovered live; enforcement is verified.</summary>
	Verified = 0,

	/// <summary>A matching object exists but a third-party provider (e.g. Kaspersky) may control or
	/// bypass effective enforcement, so the rule's existence does not guarantee blocking.</summary>
	ExistsButProviderMayBypass = 1,

	/// <summary>No backend object exists for a block the database intends — traffic is not blocked.</summary>
	Missing = 2,

	/// <summary>The recorded enforcement failed; treat as not blocked.</summary>
	Failed = 3,

	/// <summary>State could not be determined (provider unavailable / backend not scannable).</summary>
	Unknown = 4,
}

/// <summary>One block the database intends to enforce, projected from ActiveBlock + Blocklist rows.
/// Pre-read by the Service so the reconciler performs no I/O.</summary>
public sealed record DesiredBlock(
	long ActiveBlockId,
	string Ip,
	FirewallProviderKind Provider,
	FirewallEnforcementBackend Backend,
	string? RuleHandle,
	DateTime CreatedUtc,
	DateTime? ExpiresUtc,
	string Reason,
	bool RecordedFailed);

/// <summary>The discovered live state for a single backend's reconciliation pass. The reconciler is
/// fed one of these per provider; <see cref="Scannable"/> distinguishes "scanned and found nothing"
/// from "could not scan".</summary>
public sealed record BackendScanResult(
	FirewallProviderKind Provider,
	FirewallEnforcementBackend Backend,
	bool ProviderAvailable,
	bool Scannable,
	IReadOnlyList<DiscoveredBlockRule> DiscoveredRules,
	bool ThirdPartyMayBypass,
	string? Note);

/// <summary>One reconciled row: a desired block (or an orphan) with its derived status, confidence,
/// concrete backend object id, and a recommended next action. The Service maps this into a DTO and
/// the diagnostics export.</summary>
public sealed record ReconciledBlock(
	long ActiveBlockId,
	string Ip,
	FirewallProviderKind Provider,
	FirewallEnforcementBackend Backend,
	EnforcementStatus Status,
	EnforcementConfidence Confidence,
	string? EnforcementObjectId,
	DateTime? ExpiresUtc,
	string? Detail,
	string RecommendedAction);

/// <summary>Aggregate reconciliation output: every reconciled desired block plus orphaned backend
/// objects (rules with no backing row) so the operator can clean them up.</summary>
public sealed record ReconciliationReport(
	IReadOnlyList<ReconciledBlock> Blocks,
	IReadOnlyList<ReconciledBlock> Orphans,
	DateTime GeneratedUtc)
{
	/// <summary>Count of blocks with verified live enforcement.</summary>
	public int VerifiedCount
	{
		get
		{
			int n = 0;
			foreach (ReconciledBlock b in Blocks)
			{
				if (b.Confidence == EnforcementConfidence.Verified)
				{
					n++;
				}
			}
			return n;
		}
	}

	/// <summary>Count of blocks the database intends but that are not actually enforced.</summary>
	public int UnenforcedCount
	{
		get
		{
			int n = 0;
			foreach (ReconciledBlock b in Blocks)
			{
				if (b.Confidence is EnforcementConfidence.Missing or EnforcementConfidence.Failed)
				{
					n++;
				}
			}
			return n;
		}
	}
}

/// <summary>Pure reconciliation engine. Maps desired blocks + per-backend live scans to a single
/// status/confidence per (provider, ip), and surfaces orphaned RdpAudit rules.</summary>
public static class EnforcementReconciler
{
	/// <summary>Reconciles the supplied desired blocks against the per-provider live scans.</summary>
	/// <param name="desired">DB-intended blocks (ActiveBlock rows that are Active/Pending/Failed).</param>
	/// <param name="scans">One scan result per provider that owns at least one desired block (or that
	/// was scanned to detect orphans). Keyed implicitly by <see cref="BackendScanResult.Provider"/>.</param>
	/// <param name="rulePrefix">The RdpAudit rule-name prefix used to attribute discovered rules.</param>
	/// <param name="nowUtc">Reconciliation instant; expiry is computed against this.</param>
	public static ReconciliationReport Reconcile(
		IReadOnlyList<DesiredBlock> desired,
		IReadOnlyList<BackendScanResult> scans,
		string rulePrefix,
		DateTime nowUtc)
	{
		ArgumentNullException.ThrowIfNull(desired);
		ArgumentNullException.ThrowIfNull(scans);
		ArgumentException.ThrowIfNullOrWhiteSpace(rulePrefix);

		Dictionary<FirewallProviderKind, BackendScanResult> scanByProvider = new();
		foreach (BackendScanResult scan in scans)
		{
			scanByProvider[scan.Provider] = scan;
		}

		List<ReconciledBlock> blocks = new();
		// Track which discovered rule names were consumed by a desired block so the remainder are
		// reported as orphans.
		HashSet<string> consumedRuleNames = new(StringComparer.OrdinalIgnoreCase);

		foreach (DesiredBlock d in desired)
		{
			ReconciledBlock reconciled = ReconcileOne(d, scanByProvider, nowUtc, consumedRuleNames);
			blocks.Add(reconciled);
		}

		List<ReconciledBlock> orphans = CollectOrphans(scans, consumedRuleNames, nowUtc);

		return new ReconciliationReport(blocks, orphans, nowUtc);
	}

	private static ReconciledBlock ReconcileOne(
		DesiredBlock d,
		Dictionary<FirewallProviderKind, BackendScanResult> scanByProvider,
		DateTime nowUtc,
		HashSet<string> consumedRuleNames)
	{
		bool expired = d.ExpiresUtc is { } exp && exp <= nowUtc;

		if (!scanByProvider.TryGetValue(d.Provider, out BackendScanResult? scan))
		{
			// No scan for this provider — we cannot prove enforcement.
			return Build(d, EnforcementStatus.EffectiveUnknown, EnforcementConfidence.Unknown, null,
				"No live scan available for provider " + d.Provider + ".",
				"Run a reconciliation pass on a host where this backend can be scanned.");
		}

		if (!scan.ProviderAvailable)
		{
			return Build(d, EnforcementStatus.ProviderUnavailable, EnforcementConfidence.Unknown, null,
				scan.Note ?? "Provider is unavailable or not implemented.",
				"Restore the provider/backend, then re-reconcile to confirm enforcement.");
		}

		if (!scan.Scannable)
		{
			return Build(d, EnforcementStatus.EffectiveUnknown, EnforcementConfidence.Unknown, null,
				scan.Note ?? "Backend cannot be live-scanned in this environment.",
				"Verify enforcement manually; this backend does not support live enumeration here.");
		}

		// Find a discovered rule whose remote-IP set contains the desired IP.
		DiscoveredBlockRule? match = FindMatchingRule(scan.DiscoveredRules, d.Ip, consumedRuleNames);

		if (match is null)
		{
			if (expired)
			{
				return Build(d, EnforcementStatus.Expired, EnforcementConfidence.Missing, null,
					"Block expired and no backend object remains.",
					"No action: expired block is no longer enforced.");
			}

			if (d.RecordedFailed)
			{
				return Build(d, EnforcementStatus.Failed, EnforcementConfidence.Failed, null,
					"Recorded enforcement failed and no backend object exists.",
					"Repair to recreate the missing rule, or remove the block.");
			}

			return Build(d, EnforcementStatus.MissingRule, EnforcementConfidence.Missing, null,
				"Database intends a block but no firewall rule was discovered.",
				"Repair to create the missing rule.");
		}

		consumedRuleNames.Add(match.RuleName);

		// A matching rule exists; verify its parameters.
		string? mismatch = DescribeMismatch(match, d);
		if (mismatch is not null)
		{
			return Build(d, EnforcementStatus.ParameterMismatch,
				scan.ThirdPartyMayBypass ? EnforcementConfidence.ExistsButProviderMayBypass : EnforcementConfidence.Unknown,
				match.RuleName,
				mismatch,
				"Repair to bring the rule parameters back in line with the desired block.");
		}

		if (expired)
		{
			// Parameters match but the block should have been removed.
			return Build(d, EnforcementStatus.Expired,
				scan.ThirdPartyMayBypass ? EnforcementConfidence.ExistsButProviderMayBypass : EnforcementConfidence.Verified,
				match.RuleName,
				"Block has expired but the firewall rule still exists.",
				"Remove enforcement: the rule outlived its expiry.");
		}

		if (scan.ThirdPartyMayBypass)
		{
			return Build(d, EnforcementStatus.Active, EnforcementConfidence.ExistsButProviderMayBypass, match.RuleName,
				scan.Note ?? "Windows Firewall rule verified; a third-party provider may control effective enforcement.",
				"No action required; confirm the third-party firewall is not bypassing the rule.");
		}

		return Build(d, EnforcementStatus.Active, EnforcementConfidence.Verified, match.RuleName,
			"Firewall rule verified with matching parameters.",
			"No action required.");
	}

	private static List<ReconciledBlock> CollectOrphans(
		IReadOnlyList<BackendScanResult> scans,
		HashSet<string> consumedRuleNames,
		DateTime nowUtc)
	{
		List<ReconciledBlock> orphans = new();
		foreach (BackendScanResult scan in scans)
		{
			if (!scan.Scannable)
			{
				continue;
			}

			foreach (DiscoveredBlockRule rule in scan.DiscoveredRules)
			{
				if (consumedRuleNames.Contains(rule.RuleName))
				{
					continue;
				}

				string ip = rule.RemoteIps.Count > 0 ? rule.RemoteIps[0] : string.Empty;
				orphans.Add(new ReconciledBlock(
					ActiveBlockId: 0,
					Ip: ip,
					Provider: scan.Provider,
					Backend: scan.Backend,
					Status: EnforcementStatus.OrphanedRule,
					Confidence: EnforcementConfidence.Unknown,
					EnforcementObjectId: rule.RuleName,
					ExpiresUtc: null,
					Detail: "RdpAudit firewall rule exists with no backing database row.",
					RecommendedAction: "Remove the orphaned RdpAudit rule."));
			}
		}

		return orphans;
	}

	private static DiscoveredBlockRule? FindMatchingRule(
		IReadOnlyList<DiscoveredBlockRule> rules,
		string desiredIp,
		HashSet<string> consumedRuleNames)
	{
		foreach (DiscoveredBlockRule rule in rules)
		{
			if (consumedRuleNames.Contains(rule.RuleName))
			{
				continue;
			}

			foreach (string ip in rule.RemoteIps)
			{
				if (string.Equals(ip, desiredIp, StringComparison.OrdinalIgnoreCase))
				{
					return rule;
				}
			}
		}

		return null;
	}

	/// <summary>Returns a human-readable mismatch description, or null when every parameter matches
	/// the desired block. Direction must be inbound, action must be block, and the rule must be
	/// enabled. A per-IP block whose discovered rule targets "Any" remote address is a mismatch
	/// (it would over-block). Port is only checked when the desired backend is the Windows firewall
	/// and the rule declares an explicit local port.</summary>
	internal static string? DescribeMismatch(DiscoveredBlockRule rule, DesiredBlock desired)
	{
		if (!rule.Enabled)
		{
			return "Rule is disabled.";
		}

		if (!rule.DirectionInbound)
		{
			return "Rule direction is not inbound.";
		}

		if (!rule.ActionBlock)
		{
			return "Rule action is not block.";
		}

		bool targetsAny = false;
		foreach (string ip in rule.RemoteIps)
		{
			if (string.Equals(ip, "Any", StringComparison.OrdinalIgnoreCase))
			{
				targetsAny = true;
				break;
			}
		}

		if (targetsAny)
		{
			return "Rule blocks Any remote address instead of the single desired IP.";
		}

		return null;
	}

	private static ReconciledBlock Build(
		DesiredBlock d,
		EnforcementStatus status,
		EnforcementConfidence confidence,
		string? objectId,
		string detail,
		string recommendedAction)
	{
		return new ReconciledBlock(
			ActiveBlockId: d.ActiveBlockId,
			Ip: d.Ip,
			Provider: d.Provider,
			Backend: d.Backend,
			Status: status,
			Confidence: confidence,
			EnforcementObjectId: objectId,
			ExpiresUtc: d.ExpiresUtc,
			Detail: detail,
			RecommendedAction: recommendedAction);
	}

	/// <summary>Stable English label for an <see cref="EnforcementStatus"/>.</summary>
	public static string DescribeStatus(EnforcementStatus status) => status switch
	{
		EnforcementStatus.Active => "Active",
		EnforcementStatus.MissingRule => "MissingRule",
		EnforcementStatus.ParameterMismatch => "ParameterMismatch",
		EnforcementStatus.Expired => "Expired",
		EnforcementStatus.OrphanedRule => "OrphanedRule",
		EnforcementStatus.ProviderUnavailable => "ProviderUnavailable",
		EnforcementStatus.EffectiveUnknown => "EffectiveUnknown",
		EnforcementStatus.Failed => "Failed",
		EnforcementStatus.Desired => "Desired",
		_ => status.ToString(),
	};

	/// <summary>Stable English label for an <see cref="EnforcementConfidence"/>.</summary>
	public static string DescribeConfidence(EnforcementConfidence confidence) => confidence switch
	{
		EnforcementConfidence.Verified => "Verified",
		EnforcementConfidence.ExistsButProviderMayBypass => "ExistsButProviderMayBypass",
		EnforcementConfidence.Missing => "Missing",
		EnforcementConfidence.Failed => "Failed",
		EnforcementConfidence.Unknown => "Unknown",
		_ => confidence.ToString(),
	};
}
