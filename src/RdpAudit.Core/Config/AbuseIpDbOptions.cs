// File:    src/RdpAudit.Core/Config/AbuseIpDbOptions.cs
// Module:  RdpAudit.Core.Config
// Purpose: Configuration for the AbuseIPDB external reputation / reporting provider.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Config;

/// <summary>Configuration for the AbuseIPDB external reputation / reporting provider.</summary>
/// <remarks>
/// The <see cref="ApiKey"/> property must be stored in protected-envelope form (e.g. a DPAPI
/// payload tagged with "$protected"). The service unprotects it at runtime through the
/// configured <c>ISecretProtector</c>; raw API keys must never be logged or echoed in IPC
/// responses.
/// </remarks>
public sealed class AbuseIpDbOptions
{
	/// <summary>Enables outbound AbuseIPDB integration. When false the HTTP client is never instantiated.</summary>
	public bool Enabled { get; set; }

	/// <summary>Protected envelope holding the AbuseIPDB API key. Empty value disables the provider.</summary>
	public string ApiKey { get; set; } = string.Empty;

	/// <summary>Base URL of the AbuseIPDB API; configurable for on-premises proxies.</summary>
	public string BaseUrl { get; set; } = "https://api.abuseipdb.com";

	/// <summary>Outbound HTTP timeout in seconds; clamped to a sensible range at use site.</summary>
	public int TimeoutSeconds { get; set; } = 15;

	/// <summary>Maximum reports per minute submitted to AbuseIPDB. Acts as a client-side rate limit.</summary>
	public int MaxReportsPerMinute { get; set; } = 60;

	/// <summary>When true, reputation lookups are cached on disk to avoid duplicate API calls.</summary>
	public bool CacheLookups { get; set; } = true;

	/// <summary>How long, in minutes, a cached reputation lookup remains valid.</summary>
	public int CacheTtlMinutes { get; set; } = 60;

	/// <summary>Abuse confidence score (0..100) at or above which a remote IP is treated as hostile.</summary>
	public int ReportThreshold { get; set; } = 80;

	/// <summary>Category list submitted with each report. Defaults to RDP brute-force (22) and SSH (18).</summary>
	public List<int> ReportCategories { get; set; } = new() { 18, 22 };
}
