// File:    src/RdpAudit.Core/Config/MikroTikOptions.cs
// Module:  RdpAudit.Core.Config
// Purpose: Configuration for the MikroTik RouterOS external firewall provider (REST API).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Config;

/// <summary>Configuration for the MikroTik RouterOS external firewall provider (REST API).</summary>
/// <remarks>
/// <see cref="Password"/> must be stored in protected-envelope form (e.g. a DPAPI payload tagged
/// with "$protected"). The service unprotects it at runtime through the configured
/// <c>ISecretProtector</c>; the raw password must never be logged or echoed in IPC responses.
/// </remarks>
public sealed class MikroTikOptions
{
	/// <summary>Enables outbound MikroTik integration. When false the REST client is never instantiated.</summary>
	public bool Enabled { get; set; }

	/// <summary>Base URL of the RouterOS REST endpoint (e.g. "https://10.0.0.1").</summary>
	public string BaseUrl { get; set; } = string.Empty;

	/// <summary>API user name used for REST authentication.</summary>
	public string UserName { get; set; } = string.Empty;

	/// <summary>Protected envelope holding the REST password. Empty value disables the provider.</summary>
	public string Password { get; set; } = string.Empty;

	/// <summary>Outbound HTTP timeout in seconds; clamped to a sensible range at use site.</summary>
	public int TimeoutSeconds { get; set; } = 15;

	/// <summary>Address list (e.g. "rdpaudit-block") into which the provider inserts blocked IPs.</summary>
	public string AddressList { get; set; } = "rdpaudit-block";

	/// <summary>Optional comment template attached to each address-list entry for traceability.</summary>
	public string CommentTemplate { get; set; } = "RdpAudit auto-block";

	/// <summary>When true the provider validates the RouterOS TLS certificate. Disable only for lab use.</summary>
	public bool ValidateServerCertificate { get; set; } = true;

	/// <summary>Maximum API operations per minute (rate-limit guardrail).</summary>
	public int MaxOperationsPerMinute { get; set; } = 120;
}
