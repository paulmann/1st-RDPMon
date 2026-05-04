// File:    src/RdpAudit.Service/Alerts/LsassAccessRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Flags non-whitelisted LSASS handle requests with sensitive AccessMask values.
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Flags non-whitelisted LSASS handle requests with sensitive AccessMask values.</summary>
public sealed class LsassAccessRule : AlertRuleBase
{
	public override string RuleId => "LSASS_ACCESS";

	public override string Name => "LSASS Access (Credential Dumping)";

	public override AlertSeverity Severity => AlertSeverity.Critical;

	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4656 || evt.ObjectName is null)
		{
			return Task.FromResult<Alert?>(null);
		}

		if (!evt.ObjectName.Contains("lsass", StringComparison.OrdinalIgnoreCase))
		{
			return Task.FromResult<Alert?>(null);
		}

		string accessor = ExtractAccessor(evt.Details);
		if (!string.IsNullOrEmpty(accessor)
			&& ctx.Options.Alerts.LsassAccessWhitelistProcesses.Any(w =>
				accessor.EndsWith(w, StringComparison.OrdinalIgnoreCase)))
		{
			return Task.FromResult<Alert?>(null);
		}

		string mask = (evt.AccessMask ?? string.Empty).ToLowerInvariant();
		bool sensitive = mask.Contains("0x10", StringComparison.Ordinal)
			|| mask.Contains("0x1010", StringComparison.Ordinal)
			|| mask.Contains("0x1f0fff", StringComparison.Ordinal)
			|| mask.Contains("0x1fffff", StringComparison.Ordinal);
		if (!sensitive)
		{
			return Task.FromResult<Alert?>(null);
		}

		return Task.FromResult<Alert?>(CreateAlert(evt,
			$"LSASS access by {accessor} mask={evt.AccessMask}",
			new { Accessor = accessor, evt.AccessMask, Mitre = "T1003" }));
	}

	private static string ExtractAccessor(string? json)
	{
		if (string.IsNullOrEmpty(json))
		{
			return string.Empty;
		}

		try
		{
			using JsonDocument doc = JsonDocument.Parse(json);
			if (doc.RootElement.TryGetProperty("ProcessName", out JsonElement v))
			{
				return v.GetString() ?? string.Empty;
			}
		}
		catch (JsonException)
		{
		}

		return string.Empty;
	}
}
