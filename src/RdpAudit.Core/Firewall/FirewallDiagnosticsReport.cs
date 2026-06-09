// File:    src/RdpAudit.Core/Firewall/FirewallDiagnosticsReport.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: Pure formatter for the "Copy firewall diagnostics" report. Aggregates the firewall-
//          enforcement facts an operator needs to confirm that RdpAudit's IP blocking is actually
//          in effect: configured provider/backend, the resolved (non-hardcoded) RDP listener port,
//          per-provider availability, RdpAudit-group inbound block rules present in the Windows
//          firewall store, enabled-allow inbound TCP ports (so a stale 3389 allow rule is visible
//          next to the real listener port), route-blackhole / IPsec backend state, third-party
//          firewall (e.g. Kaspersky) interference notes, and a reconciliation of active enforcement
//          against blocklist / active-block database rows. Produces a single English block the
//          operator can paste into a support ticket. Pure formatting; no I/O. Callers pass pre-read
//          facts so this stays unit-testable cross-platform and never depends on Win32 / EF.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text;

namespace RdpAudit.Core.Firewall;

/// <summary>Per-provider readiness line used by <see cref="FirewallDiagnosticsReportBuilder"/>.</summary>
public sealed record FirewallProviderDiagnostic(
	string ProviderId,
	bool Available,
	int ActiveBlockCount,
	string? Message);

/// <summary>Aggregate diagnostic input for <see cref="FirewallDiagnosticsReportBuilder.Build"/>.
/// Every field is pre-resolved by the service so the builder performs no I/O.</summary>
public sealed record FirewallDiagnosticsInput(
	string ConfiguredProviderKind,
	string ConfiguredEnforcementBackend,
	string ConfiguredBlockScope,
	int ResolvedRdpPort,
	bool RdpPortFromRegistry,
	IReadOnlyList<FirewallProviderDiagnostic> Providers,
	int RdpAuditGroupBlockRuleCount,
	IReadOnlyList<int> EnabledAllowInboundTcpPorts,
	bool RdpAuditAllowRuleForResolvedPort,
	string RouteBackendState,
	string IPsecBackendState,
	bool ThirdPartyFirewallSuspected,
	string? ThirdPartyFirewallNote,
	int BlocklistRowCount,
	int ActiveBlockRowCount,
	int VerifiedEnforcedCount)
{
	/// <summary>Per-IP reconciled enforcement lines (IP, status, confidence, recommended action).
	/// Empty when a live reconciliation pass was not available. Optional so existing callers bind.</summary>
	public IReadOnlyList<ReconciledEnforcementLine> ReconciledBlocks { get; init; } =
		Array.Empty<ReconciledEnforcementLine>();

	/// <summary>Orphaned RdpAudit firewall rule names discovered with no backing database row.</summary>
	public IReadOnlyList<string> OrphanedRuleNames { get; init; } = Array.Empty<string>();

	/// <summary>Which enumeration backend produced the firewall scan: "PowerShellJson" (locale-
	/// independent, preferred), "NetshText" (locale-fragile fallback), or "None" (not scanned).</summary>
	public string ScannerBackend { get; init; } = "None";

	/// <summary>Optional human-readable note from the firewall scan (backend detail / failure cause).</summary>
	public string? ScannerNote { get; init; }
}

/// <summary>One per-IP reconciled enforcement line for the diagnostics report.</summary>
public sealed record ReconciledEnforcementLine(
	string Ip,
	string Status,
	string Confidence,
	string? EnforcementObjectId,
	string RecommendedAction);

/// <summary>Pure formatter for the Copy firewall diagnostics block.</summary>
public static class FirewallDiagnosticsReportBuilder
{
	/// <summary>Builds the firewall diagnostics report from pre-read facts.</summary>
	public static string Build(FirewallDiagnosticsInput input)
	{
		ArgumentNullException.ThrowIfNull(input);

		StringBuilder sb = new();
		sb.Append("RdpAudit firewall diagnostics — ")
			.AppendLine(DateTime.UtcNow.ToString("u", CultureInfo.InvariantCulture));
		sb.AppendLine();

		sb.AppendLine("[Configuration]");
		sb.Append("  Provider: ").AppendLine(input.ConfiguredProviderKind);
		sb.Append("  Enforcement backend: ").AppendLine(input.ConfiguredEnforcementBackend);
		sb.Append("  Block scope: ").AppendLine(input.ConfiguredBlockScope);
		sb.Append("  Resolved RDP port: ")
			.Append(input.ResolvedRdpPort.ToString(CultureInfo.InvariantCulture))
			.Append(input.RdpPortFromRegistry ? " (from registry)" : " (documented default)")
			.AppendLine();
		sb.AppendLine();

		sb.AppendLine("[Providers]");
		if (input.Providers.Count == 0)
		{
			sb.AppendLine("  (no providers registered)");
		}
		else
		{
			foreach (FirewallProviderDiagnostic p in input.Providers)
			{
				sb.Append("  ").Append(p.ProviderId).Append(": ")
					.Append(p.Available ? "available" : "unavailable")
					.Append(", activeBlocks=")
					.Append(p.ActiveBlockCount.ToString(CultureInfo.InvariantCulture));
				if (!string.IsNullOrEmpty(p.Message))
				{
					sb.Append(" — ").Append(p.Message);
				}

				sb.AppendLine();
			}
		}

		sb.AppendLine();
		sb.AppendLine("[Firewall scanner backend used]");
		sb.Append("  Backend: ").AppendLine(DescribeScannerBackend(input.ScannerBackend));
		if (!string.IsNullOrEmpty(input.ScannerNote))
		{
			sb.Append("  Note: ").AppendLine(input.ScannerNote);
		}

		if (string.Equals(input.ScannerBackend, "NetshText", StringComparison.OrdinalIgnoreCase))
		{
			sb.AppendLine("  WARNING: rules were enumerated by parsing localized netsh text. On a non-English "
				+ "Windows host the rule labels are translated, so this path can report zero rules even when "
				+ "rules exist. The PowerShell JSON backend (Get-NetFirewallRule) is locale-independent and "
				+ "should be preferred.");
		}

		sb.AppendLine("  Manual equivalent (run as Administrator):");
		sb.AppendLine("    Get-NetFirewallRule -Group 'RdpAudit' | "
			+ "Select-Object Name,DisplayName,Direction,Action,Enabled | Format-Table -AutoSize");
		sb.AppendLine("    Get-NetFirewallRule -Group 'RdpAudit' | "
			+ "ForEach-Object { $_ | Get-NetFirewallAddressFilter | Select-Object RemoteAddress }");

		sb.AppendLine();
		sb.AppendLine("[Windows firewall store]");
		sb.Append("  RdpAudit-group inbound block rules: ")
			.AppendLine(input.RdpAuditGroupBlockRuleCount.ToString(CultureInfo.InvariantCulture));
		sb.Append("  Allow-inbound rule for resolved RDP port (")
			.Append(input.ResolvedRdpPort.ToString(CultureInfo.InvariantCulture))
			.Append("): ")
			.AppendLine(input.RdpAuditAllowRuleForResolvedPort ? "present" : "ABSENT");
		sb.Append("  Enabled allow-inbound TCP ports: ")
			.AppendLine(FormatPorts(input.EnabledAllowInboundTcpPorts));
		sb.AppendLine();

		sb.AppendLine("[Alternate backends]");
		sb.Append("  Route blackhole: ").AppendLine(input.RouteBackendState);
		sb.Append("  IPsec policy: ").AppendLine(input.IPsecBackendState);
		sb.AppendLine();

		sb.AppendLine("[Third-party firewall]");
		bool scanFailed = string.Equals(input.ScannerBackend, "NetshText", StringComparison.OrdinalIgnoreCase)
			|| string.Equals(input.ScannerBackend, "None", StringComparison.OrdinalIgnoreCase);
		if (input.ThirdPartyFirewallSuspected)
		{
			sb.AppendLine("  Detected: YES (a third-party firewall such as Kaspersky is present).");
			sb.AppendLine("  Interference: UNKNOWN until a live block is tested. Detection alone does not prove "
				+ "the third-party stack rejected or bypassed an RdpAudit rule — rules may still be created "
				+ "and enforced normally.");
			if (scanFailed)
			{
				sb.AppendLine("  Caution: the firewall scan did not use the locale-independent PowerShell backend, "
					+ "so a reported 'zero rules' here may be a scanner limitation rather than third-party "
					+ "interference. Do not attribute missing rules to the third-party firewall on this basis.");
			}
		}
		else
		{
			sb.AppendLine("  Detected: no third-party firewall positively identified.");
		}

		if (!string.IsNullOrEmpty(input.ThirdPartyFirewallNote))
		{
			sb.Append("  Note: ").AppendLine(input.ThirdPartyFirewallNote);
		}

		sb.AppendLine();
		sb.AppendLine("[Enforcement reconciliation]");
		sb.AppendLine("  Counts below come from three distinct sources and are NOT expected to be equal:");
		sb.Append("  - Blocklist rows (enabled, intent in DB): ")
			.AppendLine(input.BlocklistRowCount.ToString(CultureInfo.InvariantCulture));
		sb.Append("  - Active-block rows (active/pending, attempted enforcement): ")
			.AppendLine(input.ActiveBlockRowCount.ToString(CultureInfo.InvariantCulture));
		sb.Append("  - Per-IP reconciled lines (one per active-block, see below): ")
			.AppendLine(input.ReconciledBlocks.Count.ToString(CultureInfo.InvariantCulture));
		sb.Append("  - Verified enforced (live firewall rule confirmed present): ")
			.AppendLine(input.VerifiedEnforcedCount.ToString(CultureInfo.InvariantCulture));
		sb.AppendLine("  An enabled blocklist row only becomes an active-block (and a per-IP line) once "
			+ "enforcement is attempted; a row can be enabled in the blocklist without yet having an "
			+ "active-block, which is why these two counts legitimately differ.");

		int unenforced = input.ActiveBlockRowCount - input.VerifiedEnforcedCount;
		if (unenforced > 0)
		{
			sb.Append("  WARNING: ")
				.Append(unenforced.ToString(CultureInfo.InvariantCulture))
				.AppendLine(" active-block row(s) have NO confirmed firewall enforcement — "
					+ "a database row alone does not block traffic. Use Blocklist → Repair Selected / "
					+ "Repair All Enabled to (re-)install and verify the firewall rules.");
		}

		if (input.ReconciledBlocks.Count > 0)
		{
			sb.AppendLine();
			sb.AppendLine("[Per-IP reconciliation]");
			foreach (ReconciledEnforcementLine line in input.ReconciledBlocks)
			{
				sb.Append("  ").Append(line.Ip)
					.Append(": ").Append(line.Status)
					.Append(" / ").Append(line.Confidence);
				if (!string.IsNullOrEmpty(line.EnforcementObjectId))
				{
					sb.Append(" [").Append(line.EnforcementObjectId).Append(']');
				}

				sb.Append(" — ").AppendLine(line.RecommendedAction);
			}
		}

		if (input.OrphanedRuleNames.Count > 0)
		{
			sb.AppendLine();
			sb.AppendLine("[Orphaned RdpAudit rules (no backing database row)]");
			foreach (string ruleName in input.OrphanedRuleNames)
			{
				sb.Append("  ").AppendLine(ruleName);
			}
		}

		return sb.ToString();
	}

	private static string DescribeScannerBackend(string backend) => backend switch
	{
		"PowerShellJson" => "PowerShell Get-NetFirewallRule JSON (locale-independent; preferred)",
		"NetshText" => "netsh verbose text parse (locale-fragile fallback)",
		"None" => "none (no live scan was performed)",
		_ => backend,
	};

	private static string FormatPorts(IReadOnlyList<int> ports)
	{
		if (ports.Count == 0)
		{
			return "(none)";
		}

		StringBuilder sb = new();
		for (int i = 0; i < ports.Count; i++)
		{
			if (i > 0)
			{
				sb.Append(", ");
			}

			sb.Append(ports[i].ToString(CultureInfo.InvariantCulture));
		}

		return sb.ToString();
	}
}
