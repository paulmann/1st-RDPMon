// File:    src/RdpAudit.Core/Models/AbuseIpDbReportHistory.cs
// Module:  RdpAudit.Core.Models
// Purpose: Persistent, audit-grade history of every AbuseIPDB report ATTEMPT (success or failure).
//          Drives the success-filtered report cooldown / dedupe: the worker consults the latest
//          SUCCESSFUL row for a normalized IP before submitting again. Never stores the API key.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Audit-grade history of a single AbuseIPDB report attempt (success or failure).</summary>
/// <remarks>
/// Distinct from <see cref="AbuseReport"/>, which is the legacy 15-minute rate-limit log. This table
/// is the source of truth for the configurable report cooldown: only rows with <see cref="Succeeded"/>
/// true gate future submissions. No secret material (API key) is ever written here.
/// </remarks>
public sealed class AbuseIpDbReportHistory
{
	/// <summary>Auto-incremented surrogate key.</summary>
	public long Id { get; set; }

	/// <summary>Normalized (canonical) IP address this attempt targeted.</summary>
	public string IpAddress { get; set; } = string.Empty;

	/// <summary>UTC timestamp when the attempt was made.</summary>
	public DateTime ReportedAtUtc { get; set; }

	/// <summary>True only when AbuseIPDB accepted the report (HTTP 2xx). Failed attempts never suppress.</summary>
	public bool Succeeded { get; set; }

	/// <summary>HTTP status code from AbuseIPDB. 0 indicates the request was never transmitted.</summary>
	public int HttpStatusCode { get; set; }

	/// <summary>Coarse outcome / result code (e.g. the AbuseIpDbReportOutcome name) for diagnostics.</summary>
	public string? ResultCode { get; set; }

	/// <summary>Sanitised error message; never contains the API key or other secret material.</summary>
	public string? ErrorMessage { get; set; }

	/// <summary>AbuseIPDB category list submitted (comma-separated integers per the v2 schema).</summary>
	public string AbuseCategories { get; set; } = string.Empty;

	/// <summary>SHA-256 hash (hex) of the submitted comment; lets us detect duplicate evidence without storing it.</summary>
	public string? CommentHash { get; set; }

	/// <summary>Optional originating rule identifier, when the report was triggered by a specific LoginRule.</summary>
	public long? RuleId { get; set; }

	/// <summary>Optional free-form source tag (e.g. "worker", "manual") for audit attribution.</summary>
	public string? Source { get; set; }
}
