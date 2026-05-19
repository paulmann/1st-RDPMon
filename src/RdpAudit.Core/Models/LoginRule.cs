// File:    src/RdpAudit.Core/Models/LoginRule.cs
// Module:  RdpAudit.Core.Models
// Purpose: Login trip-wire rule. Any attempted logon using a matching login name immediately
//          blocks the source IP. Use sparingly for honeypot logins such as `administrator` on a
//          host that does not use that account.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Login trip-wire rule: any attempted logon using a matching login blocks the source IP.</summary>
public sealed class LoginRule
{
	/// <summary>Auto-incremented surrogate key.</summary>
	public long Id { get; set; }

	/// <summary>Login (sAMAccountName or UPN) to trip on. Comparison is case-insensitive.</summary>
	public string Login { get; set; } = string.Empty;

	/// <summary>Operator-supplied note explaining why this login is a trip-wire.</summary>
	public string? Note { get; set; }

	/// <summary>Soft-disable flag; disabled rows are retained for audit but not enforced.</summary>
	public bool Enabled { get; set; } = true;

	/// <summary>UTC timestamp when the rule was created.</summary>
	public DateTime AddedUtc { get; set; }
}
