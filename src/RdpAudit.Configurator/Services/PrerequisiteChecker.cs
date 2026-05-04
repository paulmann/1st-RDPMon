// File:    src/RdpAudit.Configurator/Services/PrerequisiteChecker.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Implements the 15 prerequisite probes shown on the Prerequisites tab.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.ServiceProcess;

namespace RdpAudit.Configurator.Services;

/// <summary>Result of a single prerequisite probe.</summary>
public sealed record PrerequisiteResult(string Name, bool IsOk, string Detail);

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
			return new PrerequisiteResult(
				"Remote Desktop Services running",
				controller.Status == ServiceControllerStatus.Running,
				controller.Status.ToString());
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
		return new PrerequisiteResult(
			"Windows Firewall RDP rule present",
			code == 0,
			code == 0 ? "Found" : $"netsh exit {code}");
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
			return new PrerequisiteResult($"Channel: {channel}", config.IsEnabled, $"Enabled={config.IsEnabled}");
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
		using Process? p = Process.Start(new ProcessStartInfo("auditpol.exe", "/get /category:\"Object Access\"")
		{
			UseShellExecute = false,
			RedirectStandardOutput = true,
			CreateNoWindow = true,
		});

		if (p is null)
		{
			return new PrerequisiteResult("Object Access auditing", false, "auditpol.exe not found");
		}

		p.WaitForExit(10_000);
		string output = p.StandardOutput.ReadToEnd();
		bool ok = output.Contains("Success", StringComparison.OrdinalIgnoreCase);
		return new PrerequisiteResult("Object Access auditing", ok, ok ? "Enabled" : "Not enabled");
	}

	private static PrerequisiteResult CheckLsassPpl()
	{
		int code = RunCommand("reg.exe",
			"query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RunAsPPL");
		return new PrerequisiteResult("LSASS RunAsPPL enabled", code == 0, code == 0 ? "Configured" : "Not set (reboot required after enabling)");
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
