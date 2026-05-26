// File:    tests/RdpAudit.Service.Tests/SecurityBackfillWorkerNonFatalTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: v1.2.1 stabilisation — pin the non-fatal per-id classification contract for
//          SecurityBackfillWorker. A 1102 audit-log-cleared query that times out on a real host
//          while 4624/4625/4776 keep flowing must NOT paint the Security channel as broken at
//          the top level. The previous behaviour set "Last Security channel error" for every
//          per-id QueryFailed, scaring operators into thinking ingestion had stalled when in
//          fact 4624/4625/4776 were still being forwarded.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class SecurityBackfillWorkerNonFatalTests
{
	[Theory]
	[InlineData("The operation has timed out", "TimeoutSkipped")]
	[InlineData("Operation timed out while waiting", "TimeoutSkipped")]
	[InlineData("ERROR_TIMEOUT", "TimeoutSkipped")]
	[InlineData("EventLog query timed out reading record 12345", "TimeoutSkipped")]
	[InlineData("Unknown query failure", "QueryFailed")]
	[InlineData(null, "QueryFailed")]
	[InlineData("", "QueryFailed")]
	[InlineData("   ", "QueryFailed")]
	public void ClassifyNonFatal_NamesTheSpecificFailure(string? error, string expected)
	{
		Assert.Equal(expected, SecurityBackfillWorker.ClassifyNonFatal(error));
	}
}
