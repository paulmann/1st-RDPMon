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

	public long EventsCaptured => Interlocked.Read(ref _captured);

	public long EventsDropped => Interlocked.Read(ref _dropped);

	public long AlertsRaised => Interlocked.Read(ref _alerts);

	public Dictionary<string, string> ChannelStatus { get; } = new(StringComparer.OrdinalIgnoreCase);

	public void IncrementCaptured() => Interlocked.Increment(ref _captured);

	public void IncrementDropped() => Interlocked.Increment(ref _dropped);

	public void IncrementAlert() => Interlocked.Increment(ref _alerts);

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
