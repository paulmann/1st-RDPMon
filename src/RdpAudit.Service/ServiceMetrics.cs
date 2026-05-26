// File:    src/RdpAudit.Service/ServiceMetrics.cs
// Module:  RdpAudit.Service
// Purpose: Thread-safe runtime counters surfaced via the IPC GetStatus command.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Service.Workers;

namespace RdpAudit.Service;

/// <summary>Thread-safe runtime counters surfaced via the IPC GetStatus command.</summary>
public sealed class ServiceMetrics
{
	public DateTime StartedUtc { get; } = DateTime.UtcNow;

	private long _captured;
	private long _dropped;
	private long _alerts;
	private long _security4625;
	private long _security4624;
	private long _security4648;
	private long _rdpCorePreAuthOrphans;
	private DateTime? _lastSecurityEventUtc;
	private DateTime? _lastRdpCorePreAuthUtc;
	private string? _securityCorrelationDiagnostic;
	private readonly object _diagGate = new();

	// --- v3 telemetry (Detect_Attack_Strategy_v3.md acceptance criteria §17) ---
	private long _securityEventsRead;
	private long _securityEventsNormalized;
	private long _securityEventsRejected;
	private long _securityBackfillRecordsRead;
	private long _securityBackfillRecordsForwarded;
	private long _securityBackfillRecordsDeduped;
	private DateTime? _securityBackfillLastRunUtc;
	private string? _lastSecurityChannelError;
	private string? _lastSecurityRejectReason;
	private long _securityRejectReasonCount;
	private bool _securityWatcherEnabled;
	private long _authAttemptFactCreated;
	private long _authAttemptFactFailed;
	private long _authAttemptFactSucceeded;
	private DateTime? _lastAuthAttemptFactCreatedUtc;

	public long EventsCaptured => Interlocked.Read(ref _captured);

	public long EventsDropped => Interlocked.Read(ref _dropped);

	public long AlertsRaised => Interlocked.Read(ref _alerts);

	/// <summary>Count of Security 4625 (failed logon) events seen since service start. Surfaced via IPC
	/// so the Configurator can show "Audit logon failures policy is reaching us" at a glance.</summary>
	public long Security4625Count => Interlocked.Read(ref _security4625);

	/// <summary>Count of Security 4624 (successful logon) events seen since service start.</summary>
	public long Security4624Count => Interlocked.Read(ref _security4624);

	/// <summary>Count of Security 4648 (explicit credentials) events seen since service start.</summary>
	public long Security4648Count => Interlocked.Read(ref _security4648);

	/// <summary>Count of TS-RCM 261 / RdpCoreTS 131 pre-authentication observations that did not have
	/// a matching Security 4624/4625/4648 inside the correlation window. Persistent growth of this
	/// counter with zero 4625 means audit-logon-failure policy is off or the service lacks read access
	/// to the Security channel.</summary>
	public long RdpCorePreAuthOrphans => Interlocked.Read(ref _rdpCorePreAuthOrphans);

	/// <summary>UTC of the most recent Security 4624/4625/4648 received. Null until first observed.</summary>
	public DateTime? LastSecurityEventUtc
	{
		get { lock (_diagGate) { return _lastSecurityEventUtc; } }
	}

	/// <summary>UTC of the most recent TS-RCM 261 / RdpCoreTS 131 received. Null until first observed.</summary>
	public DateTime? LastRdpCorePreAuthUtc
	{
		get { lock (_diagGate) { return _lastRdpCorePreAuthUtc; } }
	}

	/// <summary>Last human-readable diagnostic emitted by the security-correlation watchdog. Null
	/// when no anomaly has been observed yet. Surfaced via IPC GetStatus.</summary>
	public string? SecurityCorrelationDiagnostic
	{
		get { lock (_diagGate) { return _securityCorrelationDiagnostic; } }
	}

	public Dictionary<string, string> ChannelStatus { get; } = new(StringComparer.OrdinalIgnoreCase);

	// v1.2.2 — per-id Security backfill snapshots: last run UTC, elapsed ms, counts, status
	// token, and the last exception type/message. The Diagnostic UI hides / groups NoEvents
	// rows by default so a workstation host without DC events does not flood the operator.
	private readonly Dictionary<int, SecurityBackfillPerIdSnapshot> _securityBackfillPerId =
		new();
	private readonly object _backfillPerIdGate = new();

	// --- v3 telemetry surface (acceptance criterion §17.13: pipeline observability). ---

	/// <summary>True once the live Security EventLogWatcher has armed at least once.</summary>
	public bool SecurityWatcherEnabled
	{
		get { lock (_diagGate) { return _securityWatcherEnabled; } }
	}

	/// <summary>Cumulative count of Security events received by the live watcher path.</summary>
	public long SecurityEventsRead => Interlocked.Read(ref _securityEventsRead);

	/// <summary>Cumulative count of Security events that completed normalization without error.</summary>
	public long SecurityEventsNormalized => Interlocked.Read(ref _securityEventsNormalized);

	/// <summary>Cumulative count of Security events rejected with an explicit reason (XML parse,
	/// access denied, channel disabled, etc.). Never includes routine "no IP" cases.</summary>
	public long SecurityEventsRejected => Interlocked.Read(ref _securityEventsRejected);

	/// <summary>UTC of the most recent Security backfill poll completion.</summary>
	public DateTime? SecurityBackfillLastRunUtc
	{
		get { lock (_diagGate) { return _securityBackfillLastRunUtc; } }
	}

	/// <summary>Cumulative count of Security records read during backfill polls.</summary>
	public long SecurityBackfillRecordsRead => Interlocked.Read(ref _securityBackfillRecordsRead);

	/// <summary>Cumulative count of Security records the backfill forwarded to the live channel.</summary>
	public long SecurityBackfillRecordsForwarded => Interlocked.Read(ref _securityBackfillRecordsForwarded);

	/// <summary>Cumulative count of Security records the backfill dropped as duplicates.</summary>
	public long SecurityBackfillRecordsDeduped => Interlocked.Read(ref _securityBackfillRecordsDeduped);

	/// <summary>Most recent error message from the Security channel (live or backfill). Null when
	/// nothing has failed yet.</summary>
	public string? LastSecurityChannelError
	{
		get { lock (_diagGate) { return _lastSecurityChannelError; } }
	}

	/// <summary>Most recent rejection reason for a normalized Security event.</summary>
	public string? LastSecurityRejectReason
	{
		get { lock (_diagGate) { return _lastSecurityRejectReason; } }
	}

	/// <summary>Cumulative count of Security events rejected, paired with <see cref="LastSecurityRejectReason"/>.</summary>
	public long SecurityRejectReasonCount => Interlocked.Read(ref _securityRejectReasonCount);

	/// <summary>Cumulative count of <c>AuthAttemptFact</c> rows created since service start.</summary>
	public long AuthAttemptFactCreated => Interlocked.Read(ref _authAttemptFactCreated);

	/// <summary>Cumulative count of <c>AuthAttemptFact</c> rows with Outcome=Failed.</summary>
	public long AuthAttemptFactFailed => Interlocked.Read(ref _authAttemptFactFailed);

	/// <summary>Cumulative count of <c>AuthAttemptFact</c> rows with Outcome=Succeeded.</summary>
	public long AuthAttemptFactSucceeded => Interlocked.Read(ref _authAttemptFactSucceeded);

	/// <summary>UTC of the most recent <c>AuthAttemptFact</c> row created.</summary>
	public DateTime? LastAuthAttemptFactCreatedUtc
	{
		get { lock (_diagGate) { return _lastAuthAttemptFactCreatedUtc; } }
	}

	public void IncrementCaptured() => Interlocked.Increment(ref _captured);

	public void IncrementDropped() => Interlocked.Increment(ref _dropped);

	public void IncrementAlert() => Interlocked.Increment(ref _alerts);

	/// <summary>Tally a Security 4625 (failed logon).</summary>
	public void IncrementSecurity4625(DateTime utc)
	{
		Interlocked.Increment(ref _security4625);
		UpdateLastSecurityUtc(utc);
	}

	/// <summary>Tally a Security 4624 (successful logon).</summary>
	public void IncrementSecurity4624(DateTime utc)
	{
		Interlocked.Increment(ref _security4624);
		UpdateLastSecurityUtc(utc);
	}

	/// <summary>Tally a Security 4648 (explicit credentials).</summary>
	public void IncrementSecurity4648(DateTime utc)
	{
		Interlocked.Increment(ref _security4648);
		UpdateLastSecurityUtc(utc);
	}

	/// <summary>Record an RDP-Core/TS-RCM pre-authentication observation (131 / 261). Used by the
	/// correlation watchdog to detect "RDP attempts seen but no Security audit event arrived".</summary>
	public void NotePreAuth(DateTime utc)
	{
		lock (_diagGate)
		{
			if (_lastRdpCorePreAuthUtc is null || utc > _lastRdpCorePreAuthUtc)
			{
				_lastRdpCorePreAuthUtc = utc;
			}
		}
	}

	/// <summary>Tally a single pre-authentication observation (TS-RCM 261 / RdpCoreTS 131) that
	/// did not have a matching Security 4624/4625/4648 inside the correlation window.</summary>
	public void NoteOrphanIncrement()
	{
		Interlocked.Increment(ref _rdpCorePreAuthOrphans);
	}

	/// <summary>Set or clear the human-readable diagnostic shown on the Configurator dashboard.
	/// The watchdog calls this once per gap; the string is cleared when a Security event next
	/// arrives and the next gap re-arms.</summary>
	public void SetSecurityCorrelationDiagnostic(string? diagnostic)
	{
		lock (_diagGate)
		{
			_securityCorrelationDiagnostic = diagnostic;
		}
	}

	private void UpdateLastSecurityUtc(DateTime utc)
	{
		lock (_diagGate)
		{
			if (_lastSecurityEventUtc is null || utc > _lastSecurityEventUtc)
			{
				_lastSecurityEventUtc = utc;
			}
		}
	}

	/// <summary>Mark the live Security watcher as armed/active.</summary>
	public void SetSecurityWatcherEnabled(bool enabled)
	{
		lock (_diagGate)
		{
			_securityWatcherEnabled = enabled;
		}
	}

	/// <summary>Tally a Security event that the live watcher path successfully read.</summary>
	public void IncrementSecurityEventRead() => Interlocked.Increment(ref _securityEventsRead);

	/// <summary>Tally a Security event that completed normalization.</summary>
	public void IncrementSecurityEventNormalized() => Interlocked.Increment(ref _securityEventsNormalized);

	/// <summary>Tally a Security event the normalizer or downstream pipeline rejected.</summary>
	public void IncrementSecurityEventRejected(string reason)
	{
		Interlocked.Increment(ref _securityEventsRejected);
		Interlocked.Increment(ref _securityRejectReasonCount);
		lock (_diagGate)
		{
			_lastSecurityRejectReason = reason;
		}
	}

	/// <summary>Record completion of a Security backfill poll cycle.</summary>
	public void RecordSecurityBackfillRun(DateTime utcNow, int recordsRead, int recordsForwarded, int recordsDeduped)
	{
		if (recordsRead > 0)
		{
			Interlocked.Add(ref _securityBackfillRecordsRead, recordsRead);
		}
		if (recordsForwarded > 0)
		{
			Interlocked.Add(ref _securityBackfillRecordsForwarded, recordsForwarded);
		}
		if (recordsDeduped > 0)
		{
			Interlocked.Add(ref _securityBackfillRecordsDeduped, recordsDeduped);
		}

		lock (_diagGate)
		{
			if (_securityBackfillLastRunUtc is null || utcNow > _securityBackfillLastRunUtc)
			{
				_securityBackfillLastRunUtc = utcNow;
			}
		}
	}

	/// <summary>Record the most recent error from the Security channel — live or backfill.</summary>
	public void SetLastSecurityChannelError(string? message)
	{
		lock (_diagGate)
		{
			_lastSecurityChannelError = message;
		}
	}

	/// <summary>Record creation of one or more <c>AuthAttemptFact</c> rows.</summary>
	public void RecordAuthAttemptFacts(int failedDelta, int succeededDelta, DateTime lastUtc)
	{
		int total = failedDelta + succeededDelta;
		if (total <= 0)
		{
			return;
		}

		Interlocked.Add(ref _authAttemptFactCreated, total);
		if (failedDelta > 0)
		{
			Interlocked.Add(ref _authAttemptFactFailed, failedDelta);
		}
		if (succeededDelta > 0)
		{
			Interlocked.Add(ref _authAttemptFactSucceeded, succeededDelta);
		}

		lock (_diagGate)
		{
			if (_lastAuthAttemptFactCreatedUtc is null || lastUtc > _lastAuthAttemptFactCreatedUtc)
			{
				_lastAuthAttemptFactCreatedUtc = lastUtc;
			}
		}
	}

	public void SetChannelStatus(string channel, string status)
	{
		lock (ChannelStatus)
		{
			ChannelStatus[channel] = status;
		}
	}

	/// <summary>v1.2.2 — record / overwrite the per-id Security backfill diagnostic snapshot
	/// for the supplied EventID. Surfaced over IPC so the Diagnostic UI can show last run
	/// UTC, elapsed ms, counts, status token and last exception per id.</summary>
	public void RecordSecurityBackfillPerId(SecurityBackfillPerIdSnapshot snapshot)
	{
		ArgumentNullException.ThrowIfNull(snapshot);
		lock (_backfillPerIdGate)
		{
			_securityBackfillPerId[snapshot.EventId] = snapshot;
		}
	}

	/// <summary>v1.2.2 — clear all per-id Security backfill diagnostic snapshots and per-id
	/// channel status entries so the next tick starts from a clean slate. Called at the top
	/// of every backfill poll cycle so stale "QueryFailed" / "TimeoutSkipped" entries from a
	/// previous tick never linger.</summary>
	public void ClearSecurityBackfillPerIdStatuses()
	{
		lock (_backfillPerIdGate)
		{
			_securityBackfillPerId.Clear();
		}

		lock (ChannelStatus)
		{
			List<string> stale = new();
			string prefix = "Security::Backfill::";
			foreach (string key in ChannelStatus.Keys)
			{
				if (key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
				{
					stale.Add(key);
				}
			}

			foreach (string key in stale)
			{
				ChannelStatus.Remove(key);
			}
		}
	}

	/// <summary>v1.2.2 — snapshot every per-id Security backfill diagnostic record. The
	/// returned dictionary is a copy so callers can iterate without holding the gate.</summary>
	public IReadOnlyDictionary<int, SecurityBackfillPerIdSnapshot> SnapshotSecurityBackfillPerId()
	{
		lock (_backfillPerIdGate)
		{
			return new Dictionary<int, SecurityBackfillPerIdSnapshot>(_securityBackfillPerId);
		}
	}

	public Dictionary<string, string> SnapshotChannels()
	{
		lock (ChannelStatus)
		{
			return new Dictionary<string, string>(ChannelStatus, StringComparer.OrdinalIgnoreCase);
		}
	}
}
