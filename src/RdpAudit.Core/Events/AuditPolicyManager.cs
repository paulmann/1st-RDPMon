// File:    src/RdpAudit.Core/Events/AuditPolicyManager.cs
// Module:  RdpAudit.Core.Events
// Purpose: Provides the canonical list of auditpol subcategories required by RdpAudit and
//          executes auditpol.exe / SACL configuration when running on Windows with elevation.
//          Uses GUID subcategory identifiers for non-English Windows compatibility.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace RdpAudit.Core.Events;

/// <summary>Audit policy row required by RdpAudit, with current and required state.</summary>
public sealed record AuditPolicyRow(string Category, string Subcategory, string SubcategoryGuid, bool Success, bool Failure);

/// <summary>Outcome of a single audit-policy apply step.</summary>
public sealed record AuditPolicyApplyResult(string Subcategory, string SubcategoryGuid, int ExitCode, string? Error);

/// <summary>Provides the canonical list of auditpol subcategories required by RdpAudit and
/// executes auditpol.exe / SACL configuration when running on Windows with elevation.
/// Subcategory GUIDs are stable across Windows locales — English names are not.</summary>
public sealed class AuditPolicyManager
{
	// Well-known audit subcategory GUIDs (locale-invariant) — see Microsoft Audit Policy reference.
	public const string GuidLogon = "{0CCE9215-69AE-11D9-BED3-505054503030}";
	public const string GuidLogoff = "{0CCE9216-69AE-11D9-BED3-505054503030}";
	public const string GuidSpecialLogon = "{0CCE921B-69AE-11D9-BED3-505054503030}";
	public const string GuidOtherLogonLogoff = "{0CCE921C-69AE-11D9-BED3-505054503030}";
	public const string GuidCredentialValidation = "{0CCE923F-69AE-11D9-BED3-505054503030}";
	public const string GuidKerberosAuthService = "{0CCE9242-69AE-11D9-BED3-505054503030}";
	public const string GuidKerberosServiceTicket = "{0CCE9240-69AE-11D9-BED3-505054503030}";
	public const string GuidProcessCreation = "{0CCE922B-69AE-11D9-BED3-505054503030}";
	public const string GuidProcessTermination = "{0CCE922C-69AE-11D9-BED3-505054503030}";
	public const string GuidAuditPolicyChange = "{0CCE922F-69AE-11D9-BED3-505054503030}";
	public const string GuidFileSystem = "{0CCE921D-69AE-11D9-BED3-505054503030}";
	public const string GuidRegistry = "{0CCE921E-69AE-11D9-BED3-505054503030}";
	public const string GuidUserAccountManagement = "{0CCE9235-69AE-11D9-BED3-505054503030}";
	public const string GuidSecurityGroupManagement = "{0CCE9237-69AE-11D9-BED3-505054503030}";
	public const string GuidSecuritySystemExtension = "{0CCE9211-69AE-11D9-BED3-505054503030}";

	public static IReadOnlyList<AuditPolicyRow> RequiredRows { get; } = new List<AuditPolicyRow>
	{
		new("Logon/Logoff", "Logon", GuidLogon, true, true),
		new("Logon/Logoff", "Logoff", GuidLogoff, true, false),
		new("Logon/Logoff", "Special Logon", GuidSpecialLogon, true, false),
		new("Logon/Logoff", "Other Logon/Logoff Events", GuidOtherLogonLogoff, true, true),
		new("Account Logon", "Credential Validation", GuidCredentialValidation, true, true),
		new("Account Logon", "Kerberos Authentication Service", GuidKerberosAuthService, true, true),
		new("Account Logon", "Kerberos Service Ticket Operations", GuidKerberosServiceTicket, true, true),
		new("Detailed Tracking", "Process Creation", GuidProcessCreation, true, false),
		new("Detailed Tracking", "Process Termination", GuidProcessTermination, true, false),
		new("Policy Change", "Audit Policy Change", GuidAuditPolicyChange, true, true),
		new("Object Access", "File System", GuidFileSystem, true, true),
		new("Object Access", "Registry", GuidRegistry, true, true),
		new("Account Management", "User Account Management", GuidUserAccountManagement, true, true),
		new("Account Management", "Security Group Management", GuidSecurityGroupManagement, true, true),
		new("System", "Security System Extension", GuidSecuritySystemExtension, true, true),
	};

	/// <summary>Applies the required audit policy on Windows. No-op on non-Windows hosts.</summary>
	[SupportedOSPlatform("windows")]
	public IReadOnlyList<AuditPolicyApplyResult> ApplyAll()
	{
		List<AuditPolicyApplyResult> results = new(RequiredRows.Count);
		if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			return results;
		}

		foreach (AuditPolicyRow row in RequiredRows)
		{
			string args = string.Format(CultureInfo.InvariantCulture,
				"/set /subcategory:{0} /success:{1} /failure:{2}",
				row.SubcategoryGuid,
				row.Success ? "enable" : "disable",
				row.Failure ? "enable" : "disable");
			(int code, string? err) = RunAuditpol(args);
			results.Add(new AuditPolicyApplyResult(row.Subcategory, row.SubcategoryGuid, code, err));
		}

		EnableProcessCmdLine();
		return results;
	}

	/// <summary>Reads the current Success/Failure flags for a subcategory by GUID using exit-code parsing
	/// (no English string parsing). Returns null on failure.</summary>
	[SupportedOSPlatform("windows")]
	public static AuditPolicyState? ReadSubcategoryState(string guid)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(guid);
		string args = string.Format(CultureInfo.InvariantCulture, "/get /subcategory:{0} /r", guid);
		try
		{
			ProcessStartInfo psi = new("auditpol.exe", args)
			{
				UseShellExecute = false,
				CreateNoWindow = true,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
			};
			using Process? proc = Process.Start(psi);
			if (proc is null)
			{
				return null;
			}

			string stdout = proc.StandardOutput.ReadToEnd();
			proc.WaitForExit(15_000);
			if (proc.ExitCode != 0)
			{
				return null;
			}

			// /r outputs CSV with header row; the last numeric column "Inclusion Setting" carries values
			// 0 = No Auditing, 1 = Success, 2 = Failure, 3 = Success and Failure (locale-stable bitfield).
			foreach (string line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
			{
				string trimmed = line.Trim();
				if (trimmed.Length == 0 || trimmed.StartsWith("Machine Name", StringComparison.Ordinal) || trimmed.StartsWith("Policy Target", StringComparison.Ordinal))
				{
					continue;
				}

				string[] parts = trimmed.Split(',');
				if (parts.Length < 5)
				{
					continue;
				}

				string lastField = parts[parts.Length - 1].Trim();
				if (int.TryParse(lastField, NumberStyles.Integer, CultureInfo.InvariantCulture, out int bits))
				{
					return new AuditPolicyState((bits & 1) != 0, (bits & 2) != 0);
				}
			}

			return null;
		}
		catch (Exception)
		{
			return null;
		}
	}

	private static (int Code, string? Error) RunAuditpol(string args)
	{
		try
		{
			ProcessStartInfo psi = new("auditpol.exe", args)
			{
				UseShellExecute = false,
				CreateNoWindow = true,
				RedirectStandardError = true,
				RedirectStandardOutput = true,
			};
			using Process? proc = Process.Start(psi);
			if (proc is null)
			{
				return (-1, "auditpol.exe could not start");
			}

			string err = proc.StandardError.ReadToEnd();
			proc.WaitForExit(15_000);
			return (proc.ExitCode, proc.ExitCode == 0 ? null : err);
		}
		catch (Exception ex)
		{
			return (-1, ex.Message);
		}
	}

	private static void EnableProcessCmdLine()
	{
		if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			return;
		}

		try
		{
			ProcessStartInfo psi = new(
				"reg.exe",
				"add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\" "
				+ "/v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f")
			{
				UseShellExecute = false,
				CreateNoWindow = true,
			};
			using Process? proc = Process.Start(psi);
			proc?.WaitForExit(10_000);
		}
		catch
		{
			// Best-effort enable; errors surfaced via auditpol read-back.
		}
	}
}

/// <summary>Decoded auditpol /r inclusion bits for a subcategory.</summary>
public sealed record AuditPolicyState(bool Success, bool Failure);
