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
	int VerifiedEnforcedCount);

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
		sb.Append("  Suspected interference: ").AppendLine(input.ThirdPartyFirewallSuspected ? "YES" : "no");
		if (!string.IsNullOrEmpty(input.ThirdPartyFirewallNote))
		{
			sb.Append("  Note: ").AppendLine(input.ThirdPartyFirewallNote);
		}

		sb.AppendLine();
		sb.AppendLine("[Enforcement reconciliation]");
		sb.Append("  Blocklist rows (enabled): ")
			.AppendLine(input.BlocklistRowCount.ToString(CultureInfo.InvariantCulture));
		sb.Append("  Active-block rows (active/pending): ")
			.AppendLine(input.ActiveBlockRowCount.ToString(CultureInfo.InvariantCulture));
		sb.Append("  Verified enforced (rule confirmed present): ")
			.AppendLine(input.VerifiedEnforcedCount.ToString(CultureInfo.InvariantCulture));

		int unenforced = input.ActiveBlockRowCount - input.VerifiedEnforcedCount;
		if (unenforced > 0)
		{
			sb.Append("  WARNING: ")
				.Append(unenforced.ToString(CultureInfo.InvariantCulture))
				.AppendLine(" active-block row(s) have NO confirmed firewall enforcement — "
					+ "a database row alone does not block traffic.");
		}

		return sb.ToString();
	}

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
