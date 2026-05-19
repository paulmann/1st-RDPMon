// File:    tests/RdpAudit.Service.Tests/NetshCommandBuilderTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit tests for the netsh command builder: rule-name normalisation, IP validation,
//          reserved-address policy, and the argument vectors emitted for add / delete / show
//          rule actions.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net;
using RdpAudit.Service.Firewall;
using Xunit;

namespace RdpAudit.Service.Tests;

public class NetshCommandBuilderTests
{
	[Theory]
	[InlineData("RdpAudit-Block", "RdpAudit-Block")]
	[InlineData("RdpAudit_Block.v2", "RdpAudit_Block.v2")]
	[InlineData("Rdp Audit Block!", "Rdp-Audit-Block")]
	[InlineData("", "RdpAudit-Block")]
	[InlineData("   ", "RdpAudit-Block")]
	[InlineData("---", "RdpAudit-Block")]
	public void NormalizeRulePrefix_StripsUnsafeCharacters(string input, string expected)
	{
		Assert.Equal(expected, NetshCommandBuilder.NormalizeRulePrefix(input));
	}

	[Theory]
	[InlineData("1.2.3.4", "1.2.3.4")]
	[InlineData("203.0.113.10", "203.0.113.10")]
	[InlineData("2001:db8::1", "2001:db8::1")]
	public void NormalizeIp_RoundTripsValidAddresses(string input, string expected)
	{
		Assert.Equal(expected, NetshCommandBuilder.NormalizeIp(input));
	}

	[Theory]
	[InlineData("999.999.999.999")]
	[InlineData("not-an-ip")]
	[InlineData("1.2.3.4.5")]
	public void ParseAndValidateIp_RejectsInvalidInputs(string input)
	{
		Assert.Throws<ArgumentException>(() => NetshCommandBuilder.ParseAndValidateIp(input));
	}

	[Theory]
	[InlineData("")]
	[InlineData("   ")]
	public void ParseAndValidateIp_RejectsEmpty(string input)
	{
		Assert.Throws<ArgumentException>(() => NetshCommandBuilder.ParseAndValidateIp(input));
	}

	[Theory]
	[InlineData("127.0.0.1", true)]
	[InlineData("10.0.0.1", true)]
	[InlineData("192.168.1.1", true)]
	[InlineData("172.16.0.1", true)]
	[InlineData("172.32.0.1", false)]
	[InlineData("169.254.1.1", true)]
	[InlineData("100.64.0.1", true)]
	[InlineData("100.128.0.1", false)]
	[InlineData("224.0.0.1", true)]
	[InlineData("8.8.8.8", false)]
	[InlineData("203.0.113.10", false)]
	[InlineData("::1", true)]
	[InlineData("fe80::1", true)]
	[InlineData("2001:db8::1", false)]
	public void IsReservedAddress_ReturnsExpected(string ip, bool expected)
	{
		IPAddress addr = IPAddress.Parse(ip);
		Assert.Equal(expected, NetshCommandBuilder.IsReservedAddress(addr));
	}

	[Fact]
	public void BuildRuleName_ProducesDeterministicCompositeName()
	{
		string name = NetshCommandBuilder.BuildRuleName("RdpAudit-Block", "203.0.113.10");
		Assert.Equal("RdpAudit-Block-203.0.113.10", name);
	}

	[Fact]
	public void BuildRuleName_TruncatesAtMaximumLength()
	{
		string longPrefix = new('a', NetshCommandBuilder.MaxRuleNameLength * 2);
		string name = NetshCommandBuilder.BuildRuleName(longPrefix, "1.2.3.4");
		Assert.Equal(NetshCommandBuilder.MaxRuleNameLength, name.Length);
	}

	[Fact]
	public void BuildAddRuleArgs_IncludesBlockingRemoteIpAndDirection()
	{
		IReadOnlyList<string> args = NetshCommandBuilder.BuildAddRuleArgs(
			"RdpAudit-Block-203.0.113.10",
			"203.0.113.10",
			"reason");

		Assert.Equal("advfirewall", args[0]);
		Assert.Equal("firewall", args[1]);
		Assert.Equal("add", args[2]);
		Assert.Equal("rule", args[3]);
		Assert.Equal("name=RdpAudit-Block-203.0.113.10", args[4]);
		Assert.Equal("dir=in", args[5]);
		Assert.Equal("action=block", args[6]);
		Assert.Equal("remoteip=203.0.113.10", args[7]);
		Assert.Equal("protocol=any", args[8]);
		Assert.Equal("enable=yes", args[9]);
		Assert.Contains(args, a => a.StartsWith("description=", StringComparison.Ordinal));
	}

	[Fact]
	public void BuildAddRuleArgs_SanitisesDescriptionControlCharacters()
	{
		IReadOnlyList<string> args = NetshCommandBuilder.BuildAddRuleArgs(
			"RdpAudit-Block-1.2.3.4",
			"1.2.3.4",
			"reason\r\nwith \"quotes\" | & < > injection");

		string? description = args.FirstOrDefault(a => a.StartsWith("description=", StringComparison.Ordinal));
		Assert.NotNull(description);
		Assert.DoesNotContain('\r', description!);
		Assert.DoesNotContain('\n', description!);
		Assert.DoesNotContain('"', description!);
		Assert.DoesNotContain('|', description!);
		Assert.DoesNotContain('&', description!);
		Assert.DoesNotContain('<', description!);
		Assert.DoesNotContain('>', description!);
	}

	[Fact]
	public void BuildDeleteRuleArgs_TargetsNamedRule()
	{
		IReadOnlyList<string> args = NetshCommandBuilder.BuildDeleteRuleArgs("RdpAudit-Block-1.2.3.4");
		Assert.Equal(new[]
		{
			"advfirewall", "firewall", "delete", "rule",
			"name=RdpAudit-Block-1.2.3.4",
		}, args);
	}

	[Fact]
	public void BuildShowAllProfilesStateArgs_IsConstant()
	{
		Assert.Equal(new[]
		{
			"advfirewall", "show", "allprofiles", "state",
		}, NetshCommandBuilder.BuildShowAllProfilesStateArgs());
	}

	[Theory]
	[InlineData("Rule;Name")]
	[InlineData("Rule Name")]
	[InlineData("Rule|Name")]
	[InlineData("Rule&Name")]
	public void BuildAddRuleArgs_RejectsRuleNameWithUnsafeCharacters(string ruleName)
	{
		Assert.Throws<ArgumentException>(() =>
			NetshCommandBuilder.BuildAddRuleArgs(ruleName, "1.2.3.4", null));
	}
}
