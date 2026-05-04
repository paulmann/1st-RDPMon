// File:    src/RdpAudit.Core/Events/AuditPolicyManager.cs
// Module:  RdpAudit.Core.Events
// Purpose: Provides the canonical list of auditpol subcategories required by RdpAudit and
//          executes auditpol.exe / SACL configuration when running on Windows with elevation.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Runtime.InteropServices;

namespace RdpAudit.Core.Events;

/// <summary>Audit policy row required by RdpAudit, with current and required state.</summary>
public sealed record AuditPolicyRow(string Category, string Subcategory, bool Success, bool Failure);

/// <summary>Provides the canonical list of auditpol subcategories required by RdpAudit and
/// executes auditpol.exe / SACL configuration when running on Windows with elevation.</summary>
public sealed class AuditPolicyManager
{
	public static IReadOnlyList<AuditPolicyRow> RequiredRows { get; } = new List<AuditPolicyRow>
	{
		new("Logon/Logoff", "Logon", true, true),
		new("Logon/Logoff", "Logoff", true, false),
		new("Logon/Logoff", "Special Logon", true, false),
		new("Logon/Logoff", "Other Logon/Logoff Events", true, true),
		new("Account Logon", "Credential Validation", true, true),
		new("Account Logon", "Kerberos Authentication Service", true, true),
		new("Account Logon", "Kerberos Service Ticket Operations", true, true),
		new("Detailed Tracking", "Process Creation", true, false),
		new("Detailed Tracking", "Process Termination", true, false),
		new("Policy Change", "Audit Policy Change", true, true),
		new("Object Access", "File System", true, true),
		new("Object Access", "Registry", true, true),
		new("Account Management", "User Account Management", true, true),
		new("Account Management", "Security Group Management", true, true),
		new("System", "Security System Extension", true, true),
	};

	/// <summary>Applies the required audit policy on Windows. No-op on non-Windows hosts.</summary>
	public int ApplyAll()
	{
		if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			return -1;
		}

		int failures = 0;
		foreach (AuditPolicyRow row in RequiredRows)
		{
			string args = $"/set /subcategory:\"{row.Subcategory}\" "
				+ $"/success:{(row.Success ? "enable" : "disable")} "
				+ $"/failure:{(row.Failure ? "enable" : "disable")}";
			if (RunAuditpol(args) != 0)
			{
				failures++;
			}
		}

		RunAuditpol("/set /subcategory:\"Process Creation\" /success:enable /failure:disable");
		EnableProcessCmdLine();
		return failures;
	}

	private static int RunAuditpol(string args)
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
				return -1;
			}

			proc.WaitForExit(15_000);
			return proc.ExitCode;
		}
		catch (Exception)
		{
			return -1;
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
