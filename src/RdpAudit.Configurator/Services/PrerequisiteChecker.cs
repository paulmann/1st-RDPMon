// File:    src/RdpAudit.Configurator/Services/PrerequisiteChecker.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Implements the 15 prerequisite probes shown on the Prerequisites tab.
//          Object-Access auditing check uses GUID + auditpol /r CSV bitfield (locale-stable).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.ServiceProcess;
using RdpAudit.Core.Events;

namespace RdpAudit.Configurator.Services;

/// <summary>Result of a single prerequisite probe.</summary>
public sealed record PrerequisiteResult(string Name, bool IsOk, string Detail, PrerequisiteFix? Fix = null);

/// <summary>Optional remediation action for a prerequisite that failed.</summary>
public sealed record PrerequisiteFix(string Description, Func<Task<string>> ApplyAsync);

/// <summary>Implements the 15 prerequisite probes shown on the Prerequisites tab.</summary>
[SupportedOSPlatform("windows")]
public sealed class PrerequisiteChecker
{
	public IReadOnlyList<PrerequisiteResult> RunAll()
	{
		List<PrerequisiteResult> results = new()
		{
			CheckOsVersion(),
			CheckDotNetRuntime(),
			CheckPowerShell(),
			CheckTermService(),
			CheckRdpPort(),
			CheckRdpFirewallRule(),
			CheckSecurityChannel(),
			CheckTsLocalChannel(),
			CheckTsRemoteChannel(),
			CheckRdpCoreChannel(),
			CheckSeSecurityPrivilege(),
			CheckProgramDataWritable(),
			CheckDatabaseAccessible(),
			CheckObjectAccessAuditing(),
			CheckLsassPpl(),
		};
		return results;
	}

	private static PrerequisiteResult CheckOsVersion()
	{
		Version v = Environment.OSVersion.Version;
		bool ok = v.Major >= 10 || (v.Major == 6 && v.Minor >= 3);
		return new PrerequisiteResult("OS version", ok, $"Detected {v}");
	}

	private static PrerequisiteResult CheckDotNetRuntime()
	{
		string fw = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription;
		bool ok = fw.Contains(".NET 8", StringComparison.OrdinalIgnoreCase) || fw.Contains(".NET 9", StringComparison.OrdinalIgnoreCase);
		return new PrerequisiteResult(".NET 8 runtime", ok, fw);
	}

	private static PrerequisiteResult CheckPowerShell()
	{
		try
		{
			using Process? p = Process.Start(new ProcessStartInfo("pwsh.exe", "-NoLogo -Command $PSVersionTable.PSVersion.Major")
			{
				UseShellExecute = false,
				RedirectStandardOutput = true,
				CreateNoWindow = true,
			});
			if (p is null)
			{
				return new PrerequisiteResult("PowerShell 7+", false, "pwsh.exe not found");
			}

			p.WaitForExit(5_000);
			string output = p.StandardOutput.ReadToEnd().Trim();
			return new PrerequisiteResult("PowerShell 7+", output is "7" or "8" or "9", $"PSVersion.Major={output}");
		}
		catch (Exception ex)
		{
			return new PrerequisiteResult("PowerShell 7+", false, ex.Message);
		}
	}

	private static PrerequisiteResult CheckTermService()
	{
		try
		{
			using ServiceController controller = new("TermService");
			ServiceControllerStatus status = controller.Status;
			PrerequisiteFix? fix = status != ServiceControllerStatus.Running
				? new PrerequisiteFix("Start TermService", async () =>
				{
					try
					{
						using ServiceController c = new("TermService");
						c.Start();
						await Task.Run(() => c.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(20))).ConfigureAwait(false);
						return "Started";
					}
					catch (Exception ex) { return ex.Message; }
				})
				: null;
			return new PrerequisiteResult(
				"Remote Desktop Services running",
				status == ServiceControllerStatus.Running,
				status.ToString(),
				fix);
		}
		catch (Exception ex)
		{
			return new PrerequisiteResult("Remote Desktop Services running", false, ex.Message);
		}
	}

	private static PrerequisiteResult CheckRdpPort()
	{
		try
		{
			using TcpClient client = new();
			IAsyncResult result = client.BeginConnect(IPAddress.Loopback, 3389, null, null);
			bool ok = result.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(2));
			if (ok && client.Connected)
			{
				client.EndConnect(result);
				return new PrerequisiteResult("RDP port 3389 listening", true, "Connected to 127.0.0.1:3389");
			}

			return new PrerequisiteResult("RDP port 3389 listening", false, "No listener on 127.0.0.1:3389");
		}
		catch (Exception ex)
		{
			return new PrerequisiteResult("RDP port 3389 listening", false, ex.Message);
		}
	}

	private static PrerequisiteResult CheckRdpFirewallRule()
	{
		int code = RunCommand("netsh", "advfirewall firewall show rule name=\"Remote Desktop - User Mode (TCP-In)\"");
		PrerequisiteFix? fix = code != 0
			? new PrerequisiteFix("Enable RDP firewall group", () =>
				Task.FromResult(RunCommand("netsh", "advfirewall firewall set rule group=\"remote desktop\" new enable=Yes") == 0
					? "Enabled" : "netsh failed"))
			: null;
		return new PrerequisiteResult(
			"Windows Firewall RDP rule present",
			code == 0,
			code == 0 ? "Found" : $"netsh exit {code}",
			fix);
	}

	private static PrerequisiteResult CheckSecurityChannel()
		=> CheckEventChannelExists("Security");

	private static PrerequisiteResult CheckTsLocalChannel()
		=> CheckEventChannelExists("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational");

	private static PrerequisiteResult CheckTsRemoteChannel()
		=> CheckEventChannelExists("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational");

	private static PrerequisiteResult CheckRdpCoreChannel()
		=> CheckEventChannelExists("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational");

	private static PrerequisiteResult CheckEventChannelExists(string channel)
	{
		try
		{
			using System.Diagnostics.Eventing.Reader.EventLogSession session = new();
			System.Diagnostics.Eventing.Reader.EventLogConfiguration config = new(channel, session);
			bool enabled = config.IsEnabled;
			PrerequisiteFix? fix = enabled
				? null
				: new PrerequisiteFix("Enable channel via wevtutil", () =>
					Task.FromResult(RunCommand("wevtutil", "sl \"" + channel + "\" /enabled:true") == 0
						? "Enabled" : "wevtutil failed"));
			return new PrerequisiteResult($"Channel: {channel}", enabled, $"Enabled={enabled}", fix);
		}
		catch (Exception ex)
		{
			return new PrerequisiteResult($"Channel: {channel}", false, ex.Message);
		}
	}

	private static PrerequisiteResult CheckSeSecurityPrivilege()
	{
		bool isAdmin = false;
		try
		{
			using System.Security.Principal.WindowsIdentity identity = System.Security.Principal.WindowsIdentity.GetCurrent();
			System.Security.Principal.WindowsPrincipal principal = new(identity);
			isAdmin = principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
		}
		catch
		{
			isAdmin = false;
		}

		return new PrerequisiteResult("Service account has SeSecurityPrivilege", isAdmin, isAdmin ? "Administrators" : "Not elevated");
	}

	private static PrerequisiteResult CheckProgramDataWritable()
	{
		string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
		string dir = Path.Combine(programData, "RdpAudit");
		try
		{
			Directory.CreateDirectory(dir);
			string probe = Path.Combine(dir, ".write-probe");
			File.WriteAllText(probe, "ok");
			File.Delete(probe);
			return new PrerequisiteResult("ProgramData writable", true, dir);
		}
		catch (Exception ex)
		{
			return new PrerequisiteResult("ProgramData writable", false, ex.Message);
		}
	}

	private static PrerequisiteResult CheckDatabaseAccessible()
	{
		string path = ReadOnlyDb.DatabasePath;
		bool exists = File.Exists(path);
		return new PrerequisiteResult("Audit database accessible", exists, exists ? path : $"Missing: {path}");
	}

	private static PrerequisiteResult CheckObjectAccessAuditing()
	{
		// Use GUIDs and the auditpol /r CSV bit field rather than parsing localized output.
		string[] subcategoryGuids =
		{
			AuditPolicyManager.GuidFileSystem,
			AuditPolicyManager.GuidRegistry,
		};

		List<string> details = new();
		bool ok = true;
		foreach (string guid in subcategoryGuids)
		{
			AuditPolicyState? state = AuditPolicyManager.ReadSubcategoryState(guid);
			if (state is null)
			{
				ok = false;
				details.Add(string.Format(CultureInfo.InvariantCulture, "{0}: read failed", guid));
				continue;
			}

			bool subOk = state.Success && state.Failure;
			ok &= subOk;
			details.Add(string.Format(CultureInfo.InvariantCulture, "{0}: S={1} F={2}",
				guid, state.Success ? "Y" : "N", state.Failure ? "Y" : "N"));
		}

		PrerequisiteFix? fix = ok
			? null
			: new PrerequisiteFix("Apply Object Access auditpol", () =>
			{
				int failures = 0;
				foreach (string guid in subcategoryGuids)
				{
					string args = string.Format(CultureInfo.InvariantCulture,
						"/set /subcategory:{0} /success:enable /failure:enable", guid);
					if (RunCommand("auditpol.exe", args) != 0)
					{
						failures++;
					}
				}
				return Task.FromResult(failures == 0 ? "Applied" : string.Format(CultureInfo.InvariantCulture, "{0} subcategory updates failed", failures));
			});

		return new PrerequisiteResult("Object Access auditing", ok, string.Join("; ", details), fix);
	}

	private static PrerequisiteResult CheckLsassPpl()
	{
		int code = RunCommand("reg.exe",
			"query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RunAsPPL");
		PrerequisiteFix? fix = code != 0
			? new PrerequisiteFix("Enable LSASS RunAsPPL (requires reboot)", () =>
				Task.FromResult(RunCommand("reg.exe",
					"add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RunAsPPL /t REG_DWORD /d 1 /f") == 0
					? "Set RunAsPPL=1; reboot to apply"
					: "reg.exe failed"))
			: null;
		return new PrerequisiteResult("LSASS RunAsPPL enabled", code == 0,
			code == 0 ? "Configured" : "Not set (reboot required after enabling)",
			fix);
	}

	private static int RunCommand(string exe, string args)
	{
		try
		{
			ProcessStartInfo psi = new(exe, args)
			{
				UseShellExecute = false,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				CreateNoWindow = true,
			};
			using Process? proc = Process.Start(psi);
			if (proc is null)
			{
				return -1;
			}

			proc.WaitForExit(15_000);
			return proc.ExitCode;
		}
		catch
		{
			return -1;
		}
	}
}
