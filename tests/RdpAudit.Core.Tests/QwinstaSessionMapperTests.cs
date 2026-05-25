// File:    tests/RdpAudit.Core.Tests/QwinstaSessionMapperTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the QwinstaSessionMapper that converts pure parser rows into
//          RdpSessionDto instances used by both the service-side and Configurator-side
//          session-listing paths. Guarantees state normalisation, IsActive / IsDisconnected
//          derivation and IsCurrent propagation are identical regardless of which side
//          builds the rows.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class QwinstaSessionMapperTests
{
	[Fact]
	public void Map_NormalisesActiveState_AndSetsIsActive()
	{
		QwinstaSessionRow row = new("rdp-tcp#3", "alice", 3, "Active", false);
		RdpSessionDto dto = QwinstaSessionMapper.Map(row);
		Assert.Equal(3, dto.SessionId);
		Assert.Equal("alice", dto.UserName);
		Assert.Equal("Active", dto.State);
		Assert.True(dto.IsActive);
		Assert.False(dto.IsDisconnected);
	}

	[Fact]
	public void Map_NormalisesDiscState_AndSetsIsDisconnected()
	{
		QwinstaSessionRow row = new(string.Empty, "carol", 4, "Disc", false);
		RdpSessionDto dto = QwinstaSessionMapper.Map(row);
		Assert.Equal("Disconnected", dto.State);
		Assert.False(dto.IsActive);
		Assert.True(dto.IsDisconnected);
	}

	[Fact]
	public void Map_PropagatesCurrentFlag()
	{
		QwinstaSessionRow row = new("rdp-tcp#7", "admin", 7, "Active", true);
		RdpSessionDto dto = QwinstaSessionMapper.Map(row);
		Assert.True(dto.IsCurrent);
	}

	[Fact]
	public void MapAll_PreservesRowOrder()
	{
		QwinstaSessionRow a = new("rdp-tcp#1", "alice", 1, "Active", false);
		QwinstaSessionRow b = new("rdp-tcp#2", "bob", 2, "Disc", false);
		IReadOnlyList<RdpSessionDto> result = QwinstaSessionMapper.MapAll(new[] { a, b });
		Assert.Equal(2, result.Count);
		Assert.Equal(1, result[0].SessionId);
		Assert.Equal(2, result[1].SessionId);
	}

	[Fact]
	public void Map_UnknownStateRetainedVerbatim_AndFlagsClear()
	{
		QwinstaSessionRow row = new("rdp-tcp#3", "alice", 3, "WeirdState", false);
		RdpSessionDto dto = QwinstaSessionMapper.Map(row);
		Assert.Equal("WeirdState", dto.State);
		Assert.False(dto.IsActive);
		Assert.False(dto.IsDisconnected);
	}
}
