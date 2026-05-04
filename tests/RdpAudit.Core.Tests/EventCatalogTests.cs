// File:    tests/RdpAudit.Core.Tests/EventCatalogTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Smoke tests over the EventCatalog metadata.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Smoke tests over the EventCatalog metadata.</summary>
public class EventCatalogTests
{
	[Fact]
	public void All_ContainsCriticalLogonAndKerberosEvents()
	{
		Assert.Contains(EventCatalog.All, d => d.EventId == 4624);
		Assert.Contains(EventCatalog.All, d => d.EventId == 4625);
		Assert.Contains(EventCatalog.All, d => d.EventId == 4769);
		Assert.Contains(EventCatalog.All, d => d.EventId == 4688);
		Assert.Contains(EventCatalog.All, d => d.EventId == 1149);
	}

	[Fact]
	public void AllChannels_HasNoDuplicates()
	{
		IReadOnlyList<string> channels = EventCatalog.AllChannels().ToList();
		Assert.Equal(channels.Count, channels.Distinct(StringComparer.OrdinalIgnoreCase).Count());
	}

	[Fact]
	public void EventIdsForChannel_ReturnsOnlyChannelEvents()
	{
		IEnumerable<int> ids = EventCatalog.EventIdsForChannel(EventCatalog.ChannelTsLocal);
		Assert.Contains(21, ids);
		Assert.DoesNotContain(4624, ids);
	}
}
