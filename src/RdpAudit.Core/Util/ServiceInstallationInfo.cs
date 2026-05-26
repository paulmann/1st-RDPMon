// File:    src/RdpAudit.Core/Util/ServiceInstallationInfo.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure value model describing the authoritative SCM state of a Windows
//          service: Name, DisplayName, State, ProcessId, StartMode, PathName (ImagePath),
//          Win32ExitCode, ServiceSpecificExitCode. Reads happen in the Configurator layer
//          via System.Management (WMI Win32_Service); this file deliberately stays free of
//          Windows-specific dependencies so it can be unit-tested cross-platform.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Util;

/// <summary>Authoritative SCM snapshot of a Windows service. Mirrors the fields of
/// <c>Win32_Service</c> that drive the Service tab UI.</summary>
public sealed record ServiceInstallationInfo(
	string ServiceName,
	bool Installed,
	string? DisplayName,
	int? StateCode,
	string? StateName,
	int? ProcessId,
	string? ImagePath,
	string? StartMode,
	string? Status,
	int? Win32ExitCode,
	int? ServiceSpecificExitCode,
	string? Diagnostic)
{
	/// <summary>True when SCM reports the service in the Running state (code 4).</summary>
	public bool IsRunning => StateCode == 4
		|| string.Equals(StateName, "Running", StringComparison.OrdinalIgnoreCase);

	/// <summary>True when SCM reports a transient state (start-pending / stop-pending /
	/// continue-pending / pause-pending). Used by the button model to keep Start and
	/// Stop disabled while a transition is in flight.</summary>
	public bool IsTransitioning => StateCode is 2 or 3 or 5 or 6;

	/// <summary>True when SCM reports the service is paused (code 7).</summary>
	public bool IsPaused => StateCode == 7
		|| string.Equals(StateName, "Paused", StringComparison.OrdinalIgnoreCase);

	/// <summary>True when SCM reports the service is stopped (code 1).</summary>
	public bool IsStopped => StateCode == 1
		|| string.Equals(StateName, "Stopped", StringComparison.OrdinalIgnoreCase);

	/// <summary>Returns the absolute path to the service executable parsed from
	/// <see cref="ImagePath"/>. Win32_Service.PathName follows the same conventions as
	/// <c>sc.exe</c>: the executable token may be quoted, and arguments may follow.
	/// Returns null when no parseable path is present.</summary>
	public string? ResolveExecutablePath()
	{
		if (string.IsNullOrWhiteSpace(ImagePath))
		{
			return null;
		}

		string raw = ImagePath.Trim();
		if (raw.Length == 0)
		{
			return null;
		}

		if (raw[0] == '"')
		{
			int closing = raw.IndexOf('"', 1);
			if (closing > 1)
			{
				return raw.Substring(1, closing - 1);
			}

			return raw[1..];
		}

		// Unquoted path: take everything up to the first space (sc.exe convention is to
		// quote any path that contains spaces; if the publisher didn't, we still get the
		// best practical match — Program Files paths always have spaces and so will be
		// quoted in practice).
		int firstSpace = raw.IndexOf(' ', StringComparison.Ordinal);
		return firstSpace > 0 ? raw[..firstSpace] : raw;
	}
}
