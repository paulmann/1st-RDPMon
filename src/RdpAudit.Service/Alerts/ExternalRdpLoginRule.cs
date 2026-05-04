// File:    src/RdpAudit.Service/Alerts/ExternalRdpLoginRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Flags RDP logons originating from a public (non-RFC1918) IP address.
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Alerts;

/// <summary>Flags RDP logons originating from a public IP address.</summary>
public sealed class ExternalRdpLoginRule : AlertRuleBase
{
	public override string RuleId => "EXTERNAL_RDP_LOGIN";

	public override string Name => "External (Public IP) RDP Login";

	public override AlertSeverity Severity => AlertSeverity.Medium;

	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		bool isCandidate = evt.EventId == 1149 || (evt.EventId == 4624 && evt.LogonType == 10);
		if (!isCandidate || string.IsNullOrEmpty(evt.SourceIp))
		{
			return Task.FromResult<Alert?>(null);
		}

		if (ctx.Options.Alerts.WhitelistIps.Contains(evt.SourceIp, StringComparer.OrdinalIgnoreCase))
		{
			return Task.FromResult<Alert?>(null);
		}

		if (!IpClassifier.IsPublicIp(evt.SourceIp))
		{
			return Task.FromResult<Alert?>(null);
		}

		return Task.FromResult<Alert?>(CreateAlert(evt,
			$"External RDP login from public IP {evt.SourceIp} as {evt.UserName}",
			new { evt.SourceIp, Mitre = "T1133" }));
	}
}
