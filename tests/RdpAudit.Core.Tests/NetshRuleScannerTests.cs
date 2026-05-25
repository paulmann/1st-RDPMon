// File:    tests/RdpAudit.Core.Tests/NetshRuleScannerTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Verifies the rule-by-port scanner so the "Windows Firewall RDP rule present" probe
//          stays localisation-tolerant and uses the configured RDP port rather than the
//          well-known 3389 — matching the new contract laid out in feedback (no localized
//          Windows Firewall group name lookups).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Firewall;
using Xunit;

namespace RdpAudit.Core.Tests;

public class NetshRuleScannerTests
{
	private const string AllowInbound3389 =
		"Rule Name:                            My RDP Rule\n" +
		"----------------------------------------------------------------------\n" +
		"Enabled:                              Yes\n" +
		"Direction:                            In\n" +
		"Profiles:                             Domain,Private,Public\n" +
		"Grouping:                             Remote Desktop\n" +
		"LocalIP:                              Any\n" +
		"RemoteIP:                             Any\n" +
		"Protocol:                             TCP\n" +
		"LocalPort:                            3389\n" +
		"RemotePort:                           Any\n" +
		"Edge traversal:                       No\n" +
		"Action:                               Allow\n" +
		"\n";

	[Fact]
	public void ContainsAllowInboundForPort_FindsMatchingRule()
	{
		Assert.True(NetshRuleScanner.ContainsAllowInboundForPort(AllowInbound3389, 3389));
	}

	[Fact]
	public void ContainsAllowInboundForPort_DefaultPortDoesNotMatchCustomPort()
	{
		// Critical: previous implementation hard-coded 3389. The scanner must accept the
		// configured port. We assert the inverse: feeding 3389 output but asking for 33890
		// returns false so the prerequisite Fail with actionable diagnostic.
		Assert.False(NetshRuleScanner.ContainsAllowInboundForPort(AllowInbound3389, 33890));
	}

	[Fact]
	public void ContainsAllowInboundForPort_CustomPortInOutput_MatchesCustomPort()
	{
		string output = AllowInbound3389.Replace("LocalPort:                            3389", "LocalPort:                            33890", StringComparison.Ordinal);
		Assert.True(NetshRuleScanner.ContainsAllowInboundForPort(output, 33890));
		Assert.False(NetshRuleScanner.ContainsAllowInboundForPort(output, 3389));
	}

	[Fact]
	public void ContainsAllowInboundForPort_PortListWithMatch_Matches()
	{
		string output =
			"Rule Name:                            Bulk\n" +
			"Enabled:                              Yes\n" +
			"Direction:                            In\n" +
			"Protocol:                             TCP\n" +
			"LocalPort:                            80,443,3389\n" +
			"Action:                               Allow\n" +
			"\n";
		Assert.True(NetshRuleScanner.ContainsAllowInboundForPort(output, 3389));
		Assert.True(NetshRuleScanner.ContainsAllowInboundForPort(output, 443));
		Assert.False(NetshRuleScanner.ContainsAllowInboundForPort(output, 4443));
	}

	[Fact]
	public void ContainsAllowInboundForPort_BlockActionIgnored()
	{
		string output = AllowInbound3389.Replace("Action:                               Allow", "Action:                               Block", StringComparison.Ordinal);
		Assert.False(NetshRuleScanner.ContainsAllowInboundForPort(output, 3389));
	}

	[Fact]
	public void ContainsAllowInboundForPort_OutboundIgnored()
	{
		string output = AllowInbound3389.Replace("Direction:                            In", "Direction:                            Out", StringComparison.Ordinal);
		Assert.False(NetshRuleScanner.ContainsAllowInboundForPort(output, 3389));
	}

	[Fact]
	public void ContainsAllowInboundForPort_EmptyInput_ReturnsFalse()
	{
		Assert.False(NetshRuleScanner.ContainsAllowInboundForPort(string.Empty, 3389));
		Assert.False(NetshRuleScanner.ContainsAllowInboundForPort(null!, 3389));
	}

	[Fact]
	public void ContainsAllowInboundForPort_NoRulesMatchOutput_ReturnsFalse()
	{
		Assert.False(NetshRuleScanner.ContainsAllowInboundForPort("No rules match the specified criteria.\n", 3389));
	}
}
