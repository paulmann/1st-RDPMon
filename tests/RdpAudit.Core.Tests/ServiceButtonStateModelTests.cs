// File:    tests/RdpAudit.Core.Tests/ServiceButtonStateModelTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage FIX-3 — locks the Service tab button-state mapping. Install disabled when the
//          service is installed, Start disabled when running, Stop disabled when stopped.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class ServiceButtonStateModelTests
{
	[Fact]
	public void NotInstalled_OnlyInstallIsEnabled()
	{
		ServiceButtonState state = ServiceButtonStateModel.Compute(installed: false, running: false);
		Assert.True(state.Install);
		Assert.False(state.Uninstall);
		Assert.False(state.Start);
		Assert.False(state.Stop);
		Assert.False(state.Restart);
	}

	[Fact]
	public void Installed_NotRunning_StartIsEnabled_StopIsDisabled()
	{
		ServiceButtonState state = ServiceButtonStateModel.Compute(installed: true, running: false);
		Assert.False(state.Install);
		Assert.True(state.Uninstall);
		Assert.True(state.Start);
		Assert.False(state.Stop);
		Assert.True(state.Restart);
	}

	[Fact]
	public void Installed_Running_StartDisabled_StopEnabled()
	{
		ServiceButtonState state = ServiceButtonStateModel.Compute(installed: true, running: true);
		Assert.False(state.Install);
		Assert.True(state.Uninstall);
		Assert.False(state.Start);
		Assert.True(state.Stop);
		Assert.True(state.Restart);
	}
}
