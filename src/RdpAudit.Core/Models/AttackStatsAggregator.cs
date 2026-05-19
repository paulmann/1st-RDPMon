// File:    src/RdpAudit.Core/Models/AttackStatsAggregator.cs
// Module:  RdpAudit.Core.Models
// Purpose: Pure (DB-agnostic) projection from raw logon-event samples and active-block lookups into
//          one AttackStat row per source IP. Lifted out of the worker so it can be unit tested
//          without an EF Core DbContext. The worker is responsible for streaming inputs out of the
//          database; this helper does the deterministic projection / scoring.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Pure projection helper for Attack Statistics aggregation.</summary>
/// <remarks>
/// The Service-side worker pulls bounded slices of <c>RawEvents</c> (logon successes / failures)
/// and a set of currently-blocked IPs from the database, then hands them to <see cref="Aggregate"/>
/// which produces one <see cref="AttackStat"/> per distinct source IP. All scoring goes through
/// <see cref="AttackThreatScoring"/> so the same number rendered in the Configurator UI is the
/// number the worker wrote.
/// </remarks>
public static class AttackStatsAggregator
{
	/// <summary>Security channel logon-success event id (Windows Security log).</summary>
	public const int EventIdLogonSuccess = 4624;

	/// <summary>Security channel logon-failure event id (Windows Security log).</summary>
	public const int EventIdLogonFailure = 4625;

	/// <summary>
	/// Aggregates one row per distinct source IP from <paramref name="samples"/>, scoring each row
	/// against the active-block set in <paramref name="blockedIps"/>.
	/// </summary>
	/// <param name="samples">Bounded slice of logon-relevant raw events.</param>
	/// <param name="blockedIps">Set of source IPs that currently have an Active / Pending block.</param>
	/// <param name="nowUtc">"Now" reference (UTC) — used for the recentness component and LastUpdated.</param>
	/// <returns>One <see cref="AttackStat"/> per distinct, non-empty <c>SourceIp</c>.</returns>
	public static IReadOnlyList<AttackStat> Aggregate(
		IEnumerable<AttackEventSample> samples,
		ISet<string> blockedIps,
		DateTime nowUtc)
	{
		ArgumentNullException.ThrowIfNull(samples);
		ArgumentNullException.ThrowIfNull(blockedIps);

		Dictionary<string, Accumulator> byIp = new(StringComparer.OrdinalIgnoreCase);
		foreach (AttackEventSample sample in samples)
		{
			if (string.IsNullOrWhiteSpace(sample.SourceIp))
			{
				continue;
			}

			string ip = sample.SourceIp.Trim();
			if (!byIp.TryGetValue(ip, out Accumulator? acc))
			{
				acc = new Accumulator(ip);
				byIp[ip] = acc;
			}

			acc.Apply(sample);
		}

		List<AttackStat> result = new(byIp.Count);
		foreach (Accumulator acc in byIp.Values)
		{
			result.Add(acc.Build(blockedIps.Contains(acc.Ip), nowUtc));
		}

		// Deterministic ordering for byte-stable test assertions.
		result.Sort((a, b) =>
		{
			int byScore = b.ThreatScore.CompareTo(a.ThreatScore);
			if (byScore != 0)
			{
				return byScore;
			}
			return string.CompareOrdinal(a.Ip, b.Ip);
		});
		return result;
	}

	private sealed class Accumulator
	{
		public string Ip { get; }

		private long _total;
		private long _successful;
		private long _failed;
		private DateTime _firstSeenUtc = DateTime.MaxValue;
		private DateTime _lastSeenUtc = DateTime.MinValue;
		private int? _lastLoginType;
		private readonly List<string?> _attemptedLogins = new();

		public Accumulator(string ip)
		{
			Ip = ip;
		}

		public void Apply(AttackEventSample sample)
		{
			_total++;
			switch (sample.EventId)
			{
				case EventIdLogonSuccess:
					_successful++;
					break;
				case EventIdLogonFailure:
					_failed++;
					break;
				default:
					// Unknown event id contributes only to the total/seen window — counted as a
					// failure for scoring purposes when no Channel/EventId hint suggests success.
					_failed++;
					break;
			}

			if (sample.TimeUtc < _firstSeenUtc)
			{
				_firstSeenUtc = sample.TimeUtc;
			}
			if (sample.TimeUtc > _lastSeenUtc)
			{
				_lastSeenUtc = sample.TimeUtc;
				if (sample.LogonType.HasValue)
				{
					_lastLoginType = sample.LogonType;
				}
			}

			_attemptedLogins.Add(sample.UserName);
		}

		public AttackStat Build(bool isBlocked, DateTime nowUtc)
		{
			DateTime first = _firstSeenUtc == DateTime.MaxValue ? nowUtc : _firstSeenUtc;
			DateTime last = _lastSeenUtc == DateTime.MinValue ? nowUtc : _lastSeenUtc;
			long durationSeconds = AttackStatProjection.ComputeDurationSeconds(first, last);
			IReadOnlyList<string> topLogins = AttackStatProjection.ComputeTopLogins(_attemptedLogins);

			double score = AttackThreatScoring.ComputeScore(
				_failed,
				_successful,
				durationSeconds,
				isBlocked,
				last,
				nowUtc);

			return new AttackStat
			{
				Ip = Ip,
				TotalAttempts = _total,
				Successful = _successful,
				Failed = _failed,
				FirstSeenUtc = first,
				LastSeenUtc = last,
				DurationSeconds = durationSeconds,
				Top10AttemptedLogins = AttackStatProjection.SerializeTopLogins(topLogins),
				LastLoginType = _lastLoginType,
				ThreatScore = score,
				IsBlocked = isBlocked,
				LastUpdatedUtc = nowUtc,
			};
		}
	}
}

/// <summary>Compact event sample fed to <see cref="AttackStatsAggregator.Aggregate"/>.</summary>
/// <param name="SourceIp">Trimmed source IP (any non-empty IPv4 / IPv6 textual form).</param>
/// <param name="EventId">Windows event id (4624 / 4625; unknown ids count toward the failed total).</param>
/// <param name="TimeUtc">Event UTC timestamp.</param>
/// <param name="UserName">Optional attempted login name; null / blank entries are dropped.</param>
/// <param name="LogonType">Optional Windows logon type captured from the event.</param>
public readonly record struct AttackEventSample(
	string? SourceIp,
	int EventId,
	DateTime TimeUtc,
	string? UserName,
	int? LogonType);
