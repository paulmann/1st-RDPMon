// File:    src/RdpAudit.Service/ServiceMetrics.cs
// Module:  RdpAudit.Service
// Purpose: Thread-safe runtime counters surfaced via the IPC GetStatus command.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

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

	public void SetChannelStatus(string channel, string status)
	{
		lock (ChannelStatus)
		{
			ChannelStatus[channel] = status;
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
