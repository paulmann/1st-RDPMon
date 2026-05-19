// File:    src/RdpAudit.Service/Firewall/MikroTikFirewallProvider.cs
// Module:  RdpAudit.Service.Firewall
// Purpose: Stage-1 IFirewallProvider stub for MikroTik RouterOS. The real REST-driven client is
//          deferred to a later stage; this stub honours the contract, returns Unavailable when
//          credentials are missing, and never logs secret material.
// Extends: RdpAudit.Core.Firewall.IFirewallProvider
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Firewall;

namespace RdpAudit.Service.Firewall;

/// <summary>Stage-1 stub <see cref="IFirewallProvider"/> for MikroTik RouterOS.</summary>
public sealed class MikroTikFirewallProvider : IFirewallProvider
{
	private readonly ILogger<MikroTikFirewallProvider> _logger;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;

	public MikroTikFirewallProvider(
		ILogger<MikroTikFirewallProvider> logger,
		IOptionsMonitor<RdpAuditOptions> options)
	{
		_logger = logger;
		_options = options;
	}

	public string ProviderId => "MikroTik";

	public Task<FirewallStatusReport> GetStatusAsync(CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		MikroTikOptions cfg = _options.CurrentValue.MikroTik;
		FirewallProviderStatus status;
		string? message;

		if (!cfg.Enabled)
		{
			status = FirewallProviderStatus.Disabled;
			message = "MikroTik provider is disabled in configuration.";
		}
		else if (string.IsNullOrWhiteSpace(cfg.BaseUrl)
			|| string.IsNullOrWhiteSpace(cfg.UserName)
			|| string.IsNullOrWhiteSpace(cfg.Password))
		{
			status = FirewallProviderStatus.NotConfigured;
			message = "MikroTik provider is missing endpoint or credentials.";
		}
		else
		{
			status = FirewallProviderStatus.NotImplemented;
			message = "Stage-1 stub. REST client will be wired in a later stage.";
		}

		return Task.FromResult(new FirewallStatusReport
		{
			Status = status,
			ProviderId = ProviderId,
			Message = message,
		});
	}

	public Task<FirewallActionResult> BlockAsync(FirewallBlockRequest request, CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(request);
		ct.ThrowIfCancellationRequested();
		_logger.LogDebug("MikroTik firewall provider received Block stub for {Ip}", request.Ip);
		return Task.FromResult(FirewallActionResult.NotImplementedFor(ProviderId, "Block"));
	}

	public Task<FirewallActionResult> UnblockAsync(string ip, string ruleName, CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ip);
		ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
		ct.ThrowIfCancellationRequested();
		_logger.LogDebug("MikroTik firewall provider received Unblock stub for {Ip}", ip);
		return Task.FromResult(FirewallActionResult.NotImplementedFor(ProviderId, "Unblock"));
	}

	public Task<IReadOnlyList<FirewallBlockEntry>> ListBlocksAsync(string ruleName, CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
		ct.ThrowIfCancellationRequested();
		return Task.FromResult<IReadOnlyList<FirewallBlockEntry>>(Array.Empty<FirewallBlockEntry>());
	}
}
