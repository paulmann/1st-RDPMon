// File:    tests/RdpAudit.Core.Tests/QwinstaParserTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates the QwinstaParser against representative qwinsta / query-session
//          outputs, including the current-session marker, header variants and
//          disconnected rows that are missing the session-name column.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class QwinstaParserTests
{
	[Fact]
	public void Parse_TypicalOutput_ProducesExpectedRows()
	{
		const string sample =
			" SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE\n" +
			" services                                    0  Disc                        \n" +
			" console           alice                     1  Active                      \n" +
			" rdp-tcp#3         bob                       3  Active  rdpwd               \n" +
			"                   carol                     4  Disc                        \n" +
			" rdp-tcp                                 65536  Listen                      \n";

		IReadOnlyList<QwinstaSessionRow> rows = QwinstaParser.Parse(sample);

		Assert.NotEmpty(rows);
		// Listen row with id 65536 (over our validator cap) should still be parsed by the pure
		// parser — the validator lives at the command-builder layer.
		Assert.Contains(rows, r => r.SessionId == 1 && r.UserName == "alice");
		Assert.Contains(rows, r => r.SessionId == 3 && r.UserName == "bob");
		Assert.Contains(rows, r => r.SessionId == 4 && r.UserName == "carol");
		Assert.Contains(rows, r => r.SessionId == 0);
	}

	[Fact]
	public void Parse_CurrentSessionMarker_FlagsRow()
	{
		const string sample =
			" SESSIONNAME       USERNAME                 ID  STATE\n" +
			">rdp-tcp#7         alice                     7  Active\n";

		IReadOnlyList<QwinstaSessionRow> rows = QwinstaParser.Parse(sample);
		QwinstaSessionRow row = Assert.Single(rows);
		Assert.True(row.IsCurrent);
		Assert.Equal(7, row.SessionId);
		Assert.Equal("alice", row.UserName);
	}

	[Fact]
	public void Parse_ExtraWhitespace_StillFindsColumns()
	{
		const string sample =
			"     SESSIONNAME             USERNAME                          ID   STATE\n" +
			"     rdp-tcp#1               admin                              2   Active\n";

		IReadOnlyList<QwinstaSessionRow> rows = QwinstaParser.Parse(sample);
		QwinstaSessionRow row = Assert.Single(rows);
		Assert.Equal(2, row.SessionId);
		Assert.Equal("admin", row.UserName);
		Assert.Equal("Active", row.State);
	}

	[Fact]
	public void Parse_EmptyInput_ReturnsEmpty()
	{
		Assert.Empty(QwinstaParser.Parse(string.Empty));
		Assert.Empty(QwinstaParser.Parse(null));
		Assert.Empty(QwinstaParser.Parse("    \n   \n"));
	}

	[Fact]
	public void Parse_UnrecognisableHeader_ReturnsEmpty()
	{
		Assert.Empty(QwinstaParser.Parse("garbage line one\ngarbage line two\n"));
	}

	[Theory]
	[InlineData("Active", "Active")]
	[InlineData("Disc", "Disconnected")]
	[InlineData("Conn", "Connected")]
	[InlineData("Listen", "Listen")]
	[InlineData("Down", "Down")]
	[InlineData("ConnQ", "ConnectQuery")]
	[InlineData("unknown", "unknown")]
	[InlineData("", "Unknown")]
	public void NormalizeState_MapsKnownTokens(string input, string expected)
	{
		Assert.Equal(expected, QwinstaParser.NormalizeState(input));
	}
}
