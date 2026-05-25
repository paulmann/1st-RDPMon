// File:    src/RdpAudit.Configurator/Services/FirewallProviderDiagnosticsProbe.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Windows-side collector that builds a FirewallProviderDiagnostics snapshot describing
//          the active firewall provider context: Windows Defender Firewall services (MpsSvc /
//          BFE), detected Kaspersky / third-party services, presence of Kaspersky CLI tools
//          (kescli.exe / kavshell.exe / avp.exe), and the configured RDP TCP port. The probe
//          is intentionally read-only — it never starts/stops services, never writes registry
//          values, and never invokes destructive Kaspersky CLI verbs. Used by the Firewall tab
//          UI panel and by the Prerequisites tab's RDP-rule diagnostic.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Runtime.Versioning;
using System.ServiceProcess;
using Microsoft.Win32;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Windows-side collector that builds a <see cref="FirewallProviderDiagnostics"/> snapshot.</summary>
[SupportedOSPlatform("windows")]
public sealed class FirewallProviderDiagnosticsProbe
{
	/// <summary>Short names of Windows services we always probe — Defender stack and the
	/// well-known Kaspersky / third-party services.</summary>
	internal static readonly string[] ProbedServiceNames = new[]
	{
		"MpsSvc",            // Windows Defender Firewall
		"BFE",               // Base Filtering Engine
		"WinDefend",         // Microsoft Defender Antivirus
		"AVP",               // Kaspersky generic AV/EP service
		"AVPCloud",
		"klnagent",          // Kaspersky Security Center Network Agent
		"klflt",
		"klim6",
		"kavfs",             // Kaspersky Security for Windows Server
		"kavfsgt",
		"kavfsmui",
		"kavfsrcn",
		"kavfswh",
		"ekrn",              // ESET
		"BdAgent",           // Bitdefender
		"vsmon",             // Check Point ZoneAlarm
		"SAVService",        // Sophos
		"mfemms",            // McAfee
		"mbamservice",       // Malwarebytes
	};

	/// <summary>Probed third-party CLI tool short names (resolved against common install locations).</summary>
	internal static readonly string[] ProbedCliTools = new[]
	{
		"kescli.exe",
		"kavshell.exe",
		"avp.exe",
	};

	/// <summary>Run all probes and return the resulting diagnostic snapshot. Never throws —
	/// every probe is wrapped so a partial failure simply contributes a Note entry.</summary>
	public FirewallProviderDiagnostics Probe()
	{
		List<FirewallServiceState> services = new();
		List<string> notes = new();
		foreach (string svcName in ProbedServiceNames)
		{
			FirewallServiceState? state = ProbeService(svcName, notes);
			if (state is not null)
			{
				services.Add(state);
			}
		}

		List<FirewallCliToolPresence> cliTools = new();
		foreach (string toolName in ProbedCliTools)
		{
			cliTools.Add(ProbeCliTool(toolName));
		}

		int? configuredPort = TryReadConfiguredRdpPort(notes);

		bool kasperskyManagesFirewall = AnyServiceRunning(services, "kavfs", "kavfsgt", "kavfsmui", "kavfsrcn", "kavfswh");

		(FirewallProviderDetectedKind kind, string name) = FirewallProviderClassifier.Classify(
			services, cliTools, kasperskyManagesWindowsFirewall: kasperskyManagesFirewall);

		bool? localRulesAllowed = kind switch
		{
			FirewallProviderDetectedKind.KasperskyManagedWindowsFirewall => false,
			FirewallProviderDetectedKind.WindowsDefenderFirewall => true,
			_ => null,
		};

		return new FirewallProviderDiagnostics
		{
			ProviderKind = kind,
			ProviderName = name,
			ProviderServices = services,
			DetectedCliTools = cliTools,
			WindowsFirewallProfiles = Array.Empty<FirewallProfileState>(),
			LocalRuleManagementAllowed = localRulesAllowed,
			ConfiguredRdpPort = configuredPort,
			Notes = notes,
		};
	}

	private static FirewallServiceState? ProbeService(string serviceName, List<string> notes)
	{
		try
		{
			using ServiceController controller = new(serviceName);
			ServiceControllerStatus status = controller.Status;
			string display;
			try
			{
				display = controller.DisplayName;
			}
			catch (InvalidOperationException)
			{
				display = serviceName;
			}

			return new FirewallServiceState(
				ServiceName: serviceName,
				DisplayName: display,
				Status: status.ToString(),
				IsRunning: status == ServiceControllerStatus.Running);
		}
		catch (InvalidOperationException)
		{
			// Service is not installed — that is the common case for product-specific names.
			return null;
		}
		catch (Exception ex)
		{
			notes.Add(string.Format(CultureInfo.InvariantCulture,
				"Service '{0}' probe failed: {1} — {2}", serviceName, ex.GetType().Name, ex.Message));
			return null;
		}
	}

	private static FirewallCliToolPresence ProbeCliTool(string toolName)
	{
		// Common Kaspersky install roots. We never invoke the tool; presence on disk is enough
		// to signal that the operator has the product available.
		string[] candidates = new[]
		{
			Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Kaspersky Lab", toolName),
			Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Kaspersky Lab", toolName),
			Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Kaspersky", toolName),
			Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Kaspersky", toolName),
		};

		foreach (string candidate in candidates)
		{
			if (TryFindByName(candidate, toolName) is string match)
			{
				return new FirewallCliToolPresence(toolName, match, Present: true);
			}
		}

		string? pathResolved = ResolveOnPath(toolName);
		if (pathResolved is not null)
		{
			return new FirewallCliToolPresence(toolName, pathResolved, Present: true);
		}

		return new FirewallCliToolPresence(toolName, Path: null, Present: false);
	}

	private static string? TryFindByName(string baseDir, string toolName)
	{
		try
		{
			if (File.Exists(baseDir))
			{
				return baseDir;
			}

			string? parent = Path.GetDirectoryName(baseDir);
			if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent))
			{
				return null;
			}

			foreach (string file in Directory.EnumerateFiles(parent, toolName, SearchOption.AllDirectories))
			{
				return file;
			}
		}
		catch
		{
			// Best-effort — directory not accessible. Treat as not-present.
		}
		return null;
	}

	private static string? ResolveOnPath(string toolName)
	{
		string? pathEnv = Environment.GetEnvironmentVariable("PATH");
		if (string.IsNullOrEmpty(pathEnv))
		{
			return null;
		}

		foreach (string dir in pathEnv.Split(Path.PathSeparator))
		{
			if (string.IsNullOrWhiteSpace(dir))
			{
				continue;
			}

			try
			{
				string candidate = Path.Combine(dir, toolName);
				if (File.Exists(candidate))
				{
					return candidate;
				}
			}
			catch
			{
				// Skip invalid PATH entries.
			}
		}

		return null;
	}

	private static int? TryReadConfiguredRdpPort(List<string> notes)
	{
		try
		{
			using RegistryKey? key = Registry.LocalMachine.OpenSubKey(
				@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
				writable: false);
			if (key?.GetValue(RdpConfigurationModel.PortNumberValueName) is int dword
				&& RdpConfigurationModel.IsValidPort(dword))
			{
				return dword;
			}
		}
		catch (Exception ex)
		{
			notes.Add("Could not read configured RDP port: " + ex.GetType().Name + " — " + ex.Message);
		}

		return null;
	}

	private static bool AnyServiceRunning(IReadOnlyList<FirewallServiceState> services, params string[] names)
	{
		foreach (FirewallServiceState svc in services)
		{
			if (!svc.IsRunning)
			{
				continue;
			}

			foreach (string name in names)
			{
				if (string.Equals(svc.ServiceName, name, StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}
		}
		return false;
	}
}
