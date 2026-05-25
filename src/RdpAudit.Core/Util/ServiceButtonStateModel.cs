// File:    src/RdpAudit.Core/Util/ServiceButtonStateModel.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure helper that maps a Windows service state ("Installed" / "Running") to the
//          enabled / disabled state of the Service tab buttons. Lifted out of WinForms so the
//          mapping is unit-testable on any OS.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Util;

/// <summary>Enabled / disabled state of the five Service-tab lifecycle buttons.</summary>
public readonly record struct ServiceButtonState(
	bool Install,
	bool Uninstall,
	bool Start,
	bool Stop,
	bool Restart);

/// <summary>Pure mapping from service install/run state to lifecycle button enabled flags.</summary>
public static class ServiceButtonStateModel
{
	/// <summary>Returns the enabled state for each lifecycle button given the current service state.
	/// <para>
	/// - Install is enabled only when the service is NOT installed.<br/>
	/// - Uninstall / Start / Stop / Restart require an installed service.<br/>
	/// - Start is disabled when the service is already Running (also when transitioning).<br/>
	/// - Stop is disabled when the service is already Stopped.<br/>
	/// - Restart is allowed whenever the service is installed.
	/// </para>
	/// </summary>
	public static ServiceButtonState Compute(bool installed, bool running)
	{
		if (!installed)
		{
			return new ServiceButtonState(
				Install: true,
				Uninstall: false,
				Start: false,
				Stop: false,
				Restart: false);
		}

		return new ServiceButtonState(
			Install: false,
			Uninstall: true,
			Start: !running,
			Stop: running,
			Restart: true);
	}
}
