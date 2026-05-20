// File:    tests/RdpAudit.Core.Tests/ConnectionFactRowProjectionTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage IP-E — validates the pure projection helpers used by the Configurator row
//          view-models so the Attack Statistics Fact* and Remote RDP Clients Historical* columns
//          map deterministically from the IPC DTOs. WinForms UI itself is not unit-tested here;
//          factoring this mapping into Core keeps it covered without dragging the WinForms host.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Stage IP-E — projection coverage for the Configurator row view-models.</summary>
public class ConnectionFactRowProjectionTests
{
	// ---------------------------------------------------------------------------------------------
	// AttackStatEntryDto -> AttackStatFactDisplay
	// ---------------------------------------------------------------------------------------------

	[Fact]
	public void FromAttackStat_Null_Throws()
	{
		Assert.Throws<ArgumentNullException>(() => ConnectionFactRowProjection.FromAttackStat(null!));
	}

	[Fact]
	public void FromAttackStat_PopulatedDto_MapsAllFactFields()
	{
		AttackStatEntryDto dto = new()
		{
			Ip = "203.0.113.7",
			HasActiveConnectionFact = true,
			FactFailedLogons = 9,
			FactSuccessfulLogons = 2,
			FactFirstSeenUtc = new DateTime(2026, 5, 19, 8, 0, 0, DateTimeKind.Utc),
			FactLastSeenUtc = new DateTime(2026, 5, 20, 9, 30, 15, DateTimeKind.Utc),
		};

		AttackStatFactDisplay display = ConnectionFactRowProjection.FromAttackStat(dto);

		Assert.True(display.HasActiveConnectionFact);
		Assert.Equal("yes", display.HasActiveConnectionFactText);
		Assert.Equal(9, display.FactFailedLogons);
		Assert.Equal(2, display.FactSuccessfulLogons);
		Assert.Equal("2026-05-19 08:00:00", display.FactFirstSeenUtcText);
		Assert.Equal("2026-05-20 09:30:15", display.FactLastSeenUtcText);
	}

	[Fact]
	public void FromAttackStat_DtoWithoutFacts_RendersEmptyTimestampsAndNo()
	{
		AttackStatEntryDto dto = new()
		{
			Ip = "203.0.113.7",
			HasActiveConnectionFact = false,
			FactFailedLogons = 0,
			FactSuccessfulLogons = 0,
			FactFirstSeenUtc = null,
			FactLastSeenUtc = null,
		};

		AttackStatFactDisplay display = ConnectionFactRowProjection.FromAttackStat(dto);

		Assert.False(display.HasActiveConnectionFact);
		Assert.Equal("no", display.HasActiveConnectionFactText);
		Assert.Equal(0, display.FactFailedLogons);
		Assert.Equal(0, display.FactSuccessfulLogons);
		Assert.Equal(string.Empty, display.FactFirstSeenUtcText);
		Assert.Equal(string.Empty, display.FactLastSeenUtcText);
	}

	// ---------------------------------------------------------------------------------------------
	// RdpSessionDto -> RdpSessionHistoricalDisplay
	// ---------------------------------------------------------------------------------------------

	[Fact]
	public void FromRdpSession_Null_Throws()
	{
		Assert.Throws<ArgumentNullException>(() => ConnectionFactRowProjection.FromRdpSession(null!));
	}

	[Fact]
	public void FromRdpSession_PopulatedHistorical_MapsAllFields()
	{
		RdpSessionDto dto = new()
		{
			SessionId = 4,
			UserName = "alice",
			ClientAddress = "198.51.100.10",
			HistoricalFirstSeenUtc = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc),
			HistoricalLastSeenUtc = new DateTime(2026, 5, 19, 23, 59, 1, DateTimeKind.Utc),
			HistoricalFailedLogons = 12,
			HistoricalSuccessfulLogons = 3,
			HistoricalUserNamesAttempted = "alice,bob,carol",
		};

		RdpSessionHistoricalDisplay display = ConnectionFactRowProjection.FromRdpSession(dto);

		Assert.Equal("2026-01-02 03:04:05", display.HistoricalFirstSeenUtcText);
		Assert.Equal("2026-05-19 23:59:01", display.HistoricalLastSeenUtcText);
		Assert.Equal(12, display.HistoricalFailedLogons);
		Assert.Equal(3, display.HistoricalSuccessfulLogons);
		Assert.Equal("alice,bob,carol", display.HistoricalUserNamesAttemptedText);
	}

	[Fact]
	public void FromRdpSession_NoHistoricalFacts_RendersEmptyStringsAndZeros()
	{
		RdpSessionDto dto = new()
		{
			SessionId = 7,
			UserName = "noone",
			ClientAddress = "198.51.100.11",
			HistoricalFirstSeenUtc = null,
			HistoricalLastSeenUtc = null,
			HistoricalFailedLogons = 0,
			HistoricalSuccessfulLogons = 0,
			HistoricalUserNamesAttempted = null,
		};

		RdpSessionHistoricalDisplay display = ConnectionFactRowProjection.FromRdpSession(dto);

		Assert.Equal(string.Empty, display.HistoricalFirstSeenUtcText);
		Assert.Equal(string.Empty, display.HistoricalLastSeenUtcText);
		Assert.Equal(0, display.HistoricalFailedLogons);
		Assert.Equal(0, display.HistoricalSuccessfulLogons);
		Assert.Equal(string.Empty, display.HistoricalUserNamesAttemptedText);
	}

	[Fact]
	public void FromRdpSession_LiveClientAddress_IsNotShadowedByHistorical()
	{
		// Regression contract: historical projection must never overwrite or replace ClientAddress.
		// We assert this at the projection level by confirming the historical display doesn't expose
		// the live address — that responsibility stays on the live DTO field.
		RdpSessionDto dto = new()
		{
			SessionId = 1,
			ClientAddress = "10.0.0.5",
			HistoricalFirstSeenUtc = new DateTime(2026, 5, 1, 0, 0, 0, DateTimeKind.Utc),
			HistoricalLastSeenUtc = new DateTime(2026, 5, 19, 0, 0, 0, DateTimeKind.Utc),
		};

		RdpSessionHistoricalDisplay display = ConnectionFactRowProjection.FromRdpSession(dto);

		Assert.Equal("2026-05-01 00:00:00", display.HistoricalFirstSeenUtcText);
		Assert.Equal("2026-05-19 00:00:00", display.HistoricalLastSeenUtcText);
		// Verifying the DTO's live address is still authoritative on the source side.
		Assert.Equal("10.0.0.5", dto.ClientAddress);
	}
}
