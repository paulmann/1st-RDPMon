// File:    tests/RdpAudit.Service.Tests/AutoBlockPolicyTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit tests for the Stage 3 auto-block decision function. Covers whitelist skip,
//          brute-force threshold block, blacklisted-login block, instant-login trip-wire block,
//          and invalid-IP / missing-IP skip paths.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Models;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class AutoBlockPolicyTests
{
	private static HashSet<string> Empty() => new(StringComparer.OrdinalIgnoreCase);

	private static Alert AlertOf(string? ruleId, string? sourceIp, string? userName) => new()
	{
		Id = 1,
		RuleId = ruleId ?? string.Empty,
		Severity = AlertSeverity.High,
		TimeUtc = DateTime.UtcNow,
		SourceIp = sourceIp,
		UserName = userName,
		Message = "test",
	};

	[Fact]
	public void MissingSourceIp_SkipsWithReason()
	{
		FirewallOptions cfg = new() { AutoBlockBruteForce = true };
		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("BRUTE_FORCE_01", null, "alice"),
			cfg,
			Empty(), Empty(), Empty(), Empty());

		Assert.Equal(AutoBlockAction.Skip, decision.Action);
		Assert.Equal("no-source-ip", decision.SkipReason);
	}

	[Fact]
	public void InvalidSourceIp_Skips()
	{
		FirewallOptions cfg = new() { AutoBlockBruteForce = true };
		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("BRUTE_FORCE_01", "not-an-ip", "alice"),
			cfg,
			Empty(), Empty(), Empty(), Empty());

		Assert.Equal(AutoBlockAction.Skip, decision.Action);
		Assert.Equal("invalid-ip", decision.SkipReason);
	}

	[Fact]
	public void DbWhitelist_BeatsBruteForce()
	{
		FirewallOptions cfg = new() { AutoBlockBruteForce = true };
		HashSet<string> whitelist = new(StringComparer.OrdinalIgnoreCase) { "203.0.113.10" };
		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("BRUTE_FORCE_01", "203.0.113.10", "alice"),
			cfg,
			whitelist, Empty(), Empty(), Empty());

		Assert.Equal(AutoBlockAction.Skip, decision.Action);
		Assert.Equal("whitelist", decision.SkipReason);
	}

	[Fact]
	public void ConfigWhitelist_BeatsBruteForce()
	{
		FirewallOptions cfg = new() { AutoBlockBruteForce = true };
		HashSet<string> whitelistConfig = new(StringComparer.OrdinalIgnoreCase) { "203.0.113.10" };
		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("BRUTE_FORCE_01", "203.0.113.10", "alice"),
			cfg,
			Empty(), whitelistConfig, Empty(), Empty());

		Assert.Equal(AutoBlockAction.Skip, decision.Action);
		Assert.Equal("whitelist", decision.SkipReason);
	}

	[Fact]
	public void BruteForceAlert_TriggersBlockWhenEnabled()
	{
		FirewallOptions cfg = new() { AutoBlockBruteForce = true };
		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("BRUTE_FORCE_01", "203.0.113.10", "alice"),
			cfg,
			Empty(), Empty(), Empty(), Empty());

		Assert.Equal(AutoBlockAction.Block, decision.Action);
		Assert.Equal("BruteForce", decision.ReasonTag);
		Assert.Equal("203.0.113.10", decision.NormalizedIp);
	}

	[Fact]
	public void BruteForceAlert_SkippedWhenAutoBlockDisabled()
	{
		FirewallOptions cfg = new() { AutoBlockBruteForce = false };
		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("BRUTE_FORCE_01", "203.0.113.10", "alice"),
			cfg,
			Empty(), Empty(), Empty(), Empty());

		Assert.Equal(AutoBlockAction.Skip, decision.Action);
	}

	[Fact]
	public void InstantLogin_TripsBlockEvenWithoutBruteForce()
	{
		FirewallOptions cfg = new() { AutoBlockBruteForce = false };
		HashSet<string> instant = new(StringComparer.OrdinalIgnoreCase) { "guest" };
		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("UNRELATED", "203.0.113.10", "guest"),
			cfg,
			Empty(), Empty(), Empty(), instant);

		Assert.Equal(AutoBlockAction.Block, decision.Action);
		Assert.Equal("InstantLogin", decision.ReasonTag);
	}

	[Fact]
	public void BlacklistedLogin_BlocksWhenEnabled()
	{
		FirewallOptions cfg = new()
		{
			AutoBlockBruteForce = false,
			BlockOnBlacklistedLogin = true,
		};
		HashSet<string> blacklist = new(StringComparer.OrdinalIgnoreCase) { "admin" };
		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("EXTERNAL_RDP_LOGIN", "203.0.113.10", "admin"),
			cfg,
			Empty(), Empty(), blacklist, Empty());

		Assert.Equal(AutoBlockAction.Block, decision.Action);
		Assert.Equal("BlacklistedLogin", decision.ReasonTag);
	}

	[Fact]
	public void BlacklistedLogin_DoesNotBlockWhenSettingDisabled()
	{
		FirewallOptions cfg = new()
		{
			AutoBlockBruteForce = false,
			BlockOnBlacklistedLogin = false,
		};
		HashSet<string> blacklist = new(StringComparer.OrdinalIgnoreCase) { "admin" };
		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("EXTERNAL_RDP_LOGIN", "203.0.113.10", "admin"),
			cfg,
			Empty(), Empty(), blacklist, Empty());

		Assert.Equal(AutoBlockAction.Skip, decision.Action);
	}

	[Fact]
	public void NonBruteForceAlert_DoesNotTriggerBlockUnderBruteForcePolicy()
	{
		FirewallOptions cfg = new() { AutoBlockBruteForce = true };
		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("EXTERNAL_RDP_LOGIN", "203.0.113.10", "alice"),
			cfg,
			Empty(), Empty(), Empty(), Empty());

		Assert.Equal(AutoBlockAction.Skip, decision.Action);
	}
}
