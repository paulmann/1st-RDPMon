// File:    src/RdpAudit.Service/Alerts/OffHoursLoginRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Flags interactive RDP logons (Type 10) outside the configured business hours.
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Flags interactive RDP logons (Type 10) outside the configured business hours.</summary>
public sealed class OffHoursLoginRule : AlertRuleBase
{
	public override string RuleId => "OFF_HOURS_LOGIN";

	public override string Name => "Off-Hours Interactive Login";

	public override AlertSeverity Severity => AlertSeverity.Low;

	public override bool IsEnabled(RdpAuditOptions options) => options.Alerts.OffHoursAlertEnabled;

	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4624 || evt.LogonType != 10)
		{
			return Task.FromResult<Alert?>(null);
		}

		if (!string.IsNullOrEmpty(evt.UserName)
			&& ctx.Options.Alerts.WhitelistUsers.Contains(evt.UserName, StringComparer.OrdinalIgnoreCase))
		{
			return Task.FromResult<Alert?>(null);
		}

		TimeSpan local = evt.TimeUtc.ToLocalTime().TimeOfDay;
		TimeSpan start = ctx.Options.Alerts.BusinessHoursStart;
		TimeSpan end = ctx.Options.Alerts.BusinessHoursEnd;

		bool isInside = start <= end
			? local >= start && local < end
			: local >= start || local < end;

		if (isInside)
		{
			return Task.FromResult<Alert?>(null);
		}

		return Task.FromResult<Alert?>(CreateAlert(evt,
			$"Off-hours interactive logon by {evt.UserName} from {evt.SourceIp ?? "(local)"} at {evt.TimeUtc.ToLocalTime():HH:mm}",
			new { LocalTime = evt.TimeUtc.ToLocalTime(), Mitre = "T1133" }));
	}
}
