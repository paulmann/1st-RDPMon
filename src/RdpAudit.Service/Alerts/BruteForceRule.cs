// File:    src/RdpAudit.Service/Alerts/BruteForceRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Detects classic brute-force password guessing on Event ID 4625.
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Detects classic brute-force password guessing on Event ID 4625.</summary>
public sealed class BruteForceRule : AlertRuleBase
{
	public override string RuleId => "BRUTE_FORCE_01";

	public override string Name => "Brute Force Password Guessing";

	public override AlertSeverity Severity => AlertSeverity.High;

	public override bool IsEnabled(RdpAuditOptions options) => options.Alerts.EnableBruteForceDetection;

	public override async Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4625 || string.IsNullOrEmpty(evt.SourceIp))
		{
			return null;
		}

		if (ctx.Options.Alerts.WhitelistIps.Contains(evt.SourceIp, StringComparer.OrdinalIgnoreCase))
		{
			return null;
		}

		TimeSpan window = TimeSpan.FromMinutes(Math.Max(1, ctx.Options.Alerts.BruteForceWindowMinutes));
		IReadOnlyList<RawEvent> recent = await ctx.GetRecentByIpAsync(evt.SourceIp, 500, window, ct).ConfigureAwait(false);
		int fails = recent.Count(e => e.EventId == 4625);
		int threshold = Math.Max(1, ctx.Options.Alerts.BruteForceThreshold);
		if (fails < threshold)
		{
			return null;
		}

		return CreateAlert(evt,
			$"Brute force from {evt.SourceIp}: {fails} failures in {window.TotalMinutes:0} min",
			new { FailCount = fails, WindowMinutes = window.TotalMinutes, Mitre = "T1110" });
	}
}
