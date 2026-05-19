// File:    src/RdpAudit.Service/Firewall/WindowsFirewallProvider.cs
// Module:  RdpAudit.Service.Firewall
// Purpose: Stage-1 IFirewallProvider stub for the Windows Advanced Firewall. The real netsh-driven
//          implementation lives in Services/FirewallManager.cs today; this stub presents the
//          stable Stage-1 abstraction surface so DI consumers can be wired in advance.
// Extends: RdpAudit.Core.Firewall.IFirewallProvider
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Extensions.Logging;
using RdpAudit.Core.Firewall;

namespace RdpAudit.Service.Firewall;

/// <summary>Stage-1 stub <see cref="IFirewallProvider"/> for the Windows Advanced Firewall.</summary>
public sealed class WindowsFirewallProvider : IFirewallProvider
{
	private readonly ILogger<WindowsFirewallProvider> _logger;

	public WindowsFirewallProvider(ILogger<WindowsFirewallProvider> logger)
	{
		_logger = logger;
	}

	public string ProviderId => "Windows";

	public Task<FirewallStatusReport> GetStatusAsync(CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		FirewallProviderStatus status = OperatingSystem.IsWindows()
			? FirewallProviderStatus.Available
			: FirewallProviderStatus.Unreachable;

		return Task.FromResult(new FirewallStatusReport
		{
			Status = status,
			ProviderId = ProviderId,
			Message = OperatingSystem.IsWindows()
				? "Stage-1 stub. Block / unblock dispatch through the existing FirewallManager."
				: "Windows Advanced Firewall is only available on Windows hosts.",
		});
	}

	public Task<FirewallActionResult> BlockAsync(FirewallBlockRequest request, CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(request);
		ct.ThrowIfCancellationRequested();
		_logger.LogDebug("Windows firewall provider received Block stub for {Ip} rule={Rule}", request.Ip, request.RuleName);
		return Task.FromResult(FirewallActionResult.NotImplementedFor(ProviderId, "Block"));
	}

	public Task<FirewallActionResult> UnblockAsync(string ip, string ruleName, CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ip);
		ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
		ct.ThrowIfCancellationRequested();
		_logger.LogDebug("Windows firewall provider received Unblock stub for {Ip} rule={Rule}", ip, ruleName);
		return Task.FromResult(FirewallActionResult.NotImplementedFor(ProviderId, "Unblock"));
	}

	public Task<IReadOnlyList<FirewallBlockEntry>> ListBlocksAsync(string ruleName, CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
		ct.ThrowIfCancellationRequested();
		return Task.FromResult<IReadOnlyList<FirewallBlockEntry>>(Array.Empty<FirewallBlockEntry>());
	}
}
