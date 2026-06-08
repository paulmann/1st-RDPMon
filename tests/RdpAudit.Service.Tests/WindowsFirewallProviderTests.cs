// File:    tests/RdpAudit.Service.Tests/WindowsFirewallProviderTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit tests for the WindowsFirewallProvider. Verifies that the provider validates
//          inputs, refuses reserved addresses by policy, drives netsh idempotently via the
//          ArgumentList path, and surfaces controlled DTOs instead of raw exceptions.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Firewall;
using RdpAudit.Service.Firewall;
using Xunit;

namespace RdpAudit.Service.Tests;

public class WindowsFirewallProviderTests
{
	private static IOptionsMonitor<RdpAuditOptions> CreateOptions(RdpAuditOptions? opts = null)
	{
		opts ??= new RdpAuditOptions();
		return new StaticOptionsMonitor<RdpAuditOptions>(opts);
	}

	[Fact]
	public async Task Block_ValidPublicAddress_AddsRuleAndReturnsSuccess()
	{
		FakeNetshRunner runner = new();
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(),
			runner,
			new FakeRdpPortProvider());

		FirewallActionResult result = await provider.BlockAsync(
			new FirewallBlockRequest("203.0.113.10", "RdpAudit-Block")
			{
				Reason = "unit-test",
				Duration = TimeSpan.FromMinutes(30),
			},
			CancellationToken.None);

		if (OperatingSystem.IsWindows())
		{
			Assert.Equal(FirewallActionStatus.Success, result.Status);
			Assert.Equal("RdpAudit-Block-203.0.113.10", result.RuleId);
			// 1 delete (idempotent prefix-cleanup) + 1 add.
			Assert.Equal(2, runner.Calls.Count);
			Assert.Contains("add", runner.Calls[1]);
			Assert.Contains("remoteip=203.0.113.10", runner.Calls[1]);
		}
		else
		{
			Assert.Equal(FirewallActionStatus.Unavailable, result.Status);
		}
	}

	[Fact]
	public async Task Block_InvalidIp_ReturnsInvalidRequest()
	{
		FakeNetshRunner runner = new();
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(),
			runner,
			new FakeRdpPortProvider());

		FirewallActionResult result = await provider.BlockAsync(
			new FirewallBlockRequest("not-an-ip", "RdpAudit-Block"),
			CancellationToken.None);

		if (OperatingSystem.IsWindows())
		{
			Assert.Equal(FirewallActionStatus.InvalidRequest, result.Status);
			Assert.Empty(runner.Calls);
		}
		else
		{
			Assert.Equal(FirewallActionStatus.Unavailable, result.Status);
		}
	}

	[Fact]
	public async Task Block_LoopbackAddress_RefusedByPolicy()
	{
		FakeNetshRunner runner = new();
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(new RdpAuditOptions { Firewall = new FirewallOptions { RefusePrivateAddressBlock = true } }),
			runner,
			new FakeRdpPortProvider());

		FirewallActionResult result = await provider.BlockAsync(
			new FirewallBlockRequest("127.0.0.1", "RdpAudit-Block"),
			CancellationToken.None);

		if (OperatingSystem.IsWindows())
		{
			Assert.Equal(FirewallActionStatus.Refused, result.Status);
			Assert.Empty(runner.Calls);
		}
		else
		{
			Assert.Equal(FirewallActionStatus.Unavailable, result.Status);
		}
	}

	[Fact]
	public async Task Block_LoopbackAddress_AllowedWhenPolicyDisabled()
	{
		FakeNetshRunner runner = new();
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(new RdpAuditOptions { Firewall = new FirewallOptions { RefusePrivateAddressBlock = false } }),
			runner,
			new FakeRdpPortProvider());

		FirewallActionResult result = await provider.BlockAsync(
			new FirewallBlockRequest("10.0.0.1", "RdpAudit-Block"),
			CancellationToken.None);

		if (OperatingSystem.IsWindows())
		{
			Assert.Equal(FirewallActionStatus.Success, result.Status);
		}
		else
		{
			Assert.Equal(FirewallActionStatus.Unavailable, result.Status);
		}
	}

	[Fact]
	public async Task Unblock_NoMatchingRule_ReturnsNotFound()
	{
		FakeNetshRunner runner = new();
		runner.Responses.Enqueue(new NetshResult(1, "No rules match the specified criteria.", string.Empty));
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(),
			runner,
			new FakeRdpPortProvider());

		FirewallActionResult result = await provider.UnblockAsync(
			"203.0.113.10",
			"RdpAudit-Block",
			CancellationToken.None);

		if (OperatingSystem.IsWindows())
		{
			Assert.Equal(FirewallActionStatus.NotFound, result.Status);
		}
		else
		{
			Assert.Equal(FirewallActionStatus.Unavailable, result.Status);
		}
	}

	[Fact]
	public async Task Unblock_ProviderReturnsSuccess_FlipsStatusSuccess()
	{
		FakeNetshRunner runner = new();
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(),
			runner,
			new FakeRdpPortProvider());

		FirewallActionResult result = await provider.UnblockAsync(
			"203.0.113.10",
			"RdpAudit-Block",
			CancellationToken.None);

		if (OperatingSystem.IsWindows())
		{
			Assert.Equal(FirewallActionStatus.Success, result.Status);
			Assert.Equal("RdpAudit-Block-203.0.113.10", result.RuleId);
			Assert.Single(runner.Calls);
			Assert.Contains("delete", runner.Calls[0]);
			Assert.Contains("name=RdpAudit-Block-203.0.113.10", runner.Calls[0]);
		}
		else
		{
			Assert.Equal(FirewallActionStatus.Unavailable, result.Status);
		}
	}

	[Fact]
	public async Task GetStatus_NonWindowsHost_ReportsUnreachable()
	{
		if (OperatingSystem.IsWindows())
		{
			return;
		}

		FakeNetshRunner runner = new();
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(),
			runner,
			new FakeRdpPortProvider());

		FirewallStatusReport report = await provider.GetStatusAsync(CancellationToken.None);
		Assert.Equal(FirewallProviderStatus.Unreachable, report.Status);
		Assert.Equal("Windows", report.ProviderId);
	}
}

internal sealed class FakeRdpPortProvider : IRdpPortProvider
{
	private readonly int _port;

	public FakeRdpPortProvider(int port = 3389)
	{
		_port = port;
	}

	public int GetRdpPort() => _port;
}

internal sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
{
	public StaticOptionsMonitor(T value)
	{
		CurrentValue = value;
	}

	public T CurrentValue { get; }

	public T Get(string? name) => CurrentValue;

	public IDisposable? OnChange(Action<T, string?> listener) => null;
}
