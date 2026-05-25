// File:    tests/RdpAudit.Core.Tests/RdpConfigurationModelTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage RDP-1 — locks the pure RDP configuration helpers (port validation, enum mapping,
//          enabled-flag interpretation). Keeps the new RDP Configuration tab deterministic across
//          registry-value edge cases.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class RdpConfigurationModelTests
{
	[Theory]
	[InlineData(1, true)]
	[InlineData(3389, true)]
	[InlineData(65535, true)]
	[InlineData(0, false)]
	[InlineData(-1, false)]
	[InlineData(65536, false)]
	public void IsValidPort_BoundsRange(int candidate, bool expected)
	{
		Assert.Equal(expected, RdpConfigurationModel.IsValidPort(candidate));
	}

	[Theory]
	[InlineData(0, RdpUserAuthenticationMode.NlaNotRequired)]
	[InlineData(1, RdpUserAuthenticationMode.NlaRequired)]
	[InlineData(99, RdpUserAuthenticationMode.Unknown)]
	public void AuthenticationFromRaw_MapsKnownValues(int? raw, RdpUserAuthenticationMode expected)
	{
		Assert.Equal(expected, RdpConfigurationModel.AuthenticationFromRaw(raw));
	}

	[Fact]
	public void AuthenticationFromRaw_NullIsUnknown()
	{
		Assert.Equal(RdpUserAuthenticationMode.Unknown,
			RdpConfigurationModel.AuthenticationFromRaw(null));
	}

	[Theory]
	[InlineData(0, RdpSecurityLayerMode.RdpSecurity)]
	[InlineData(1, RdpSecurityLayerMode.Negotiate)]
	[InlineData(2, RdpSecurityLayerMode.SslTls)]
	public void SecurityLayerFromRaw_MapsKnownValues(int? raw, RdpSecurityLayerMode expected)
	{
		Assert.Equal(expected, RdpConfigurationModel.SecurityLayerFromRaw(raw));
	}

	[Theory]
	[InlineData(0, true)]
	[InlineData(1, false)]
	[InlineData(null, null)]
	[InlineData(99, null)]
	public void RdpEnabledFromRaw_MapsZeroEnabled_OneDisabled_OthersNull(int? raw, bool? expected)
	{
		Assert.Equal(expected, RdpConfigurationModel.RdpEnabledFromRaw(raw));
	}

	[Theory]
	[InlineData(null, false)]
	[InlineData(0, false)]
	[InlineData(1, true)]
	[InlineData(2, true)]
	public void BoolFlagFromRaw_NonZeroIsTrue(int? raw, bool expected)
	{
		Assert.Equal(expected, RdpConfigurationModel.BoolFlagFromRaw(raw));
	}

	[Fact]
	public void DefaultRdpPort_IsExactly_3389()
	{
		// Locked — the rest of the codebase uses RdpConfigurationModel.DefaultRdpPort as the
		// fallback when the registry does not configure a port; verify the literal stays at 3389.
		Assert.Equal(3389, RdpConfigurationModel.DefaultRdpPort);
	}
}
