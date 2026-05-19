// File:    tests/RdpAudit.Core.Tests/ServiceLayoutTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Verifies that ServiceLayout.ResolveSiblingDistribution discovers the
//          published Service distribution folder regardless of where the user has
//          placed the publish/ root on disk.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Sibling-distribution resolution tests.</summary>
public class ServiceLayoutTests
{
	[Fact]
	public void ResolveSiblingDistribution_PublishConfigurator_ReturnsSiblingService()
	{
		string root = Path.Combine(Path.DirectorySeparatorChar.ToString(), "1st_RdpMON", "Service", "publish", "Configurator");
		string expected = Path.Combine(Path.DirectorySeparatorChar.ToString(), "1st_RdpMON", "Service", "publish", "Service");
		Assert.Equal(expected, ServiceLayout.ResolveSiblingDistribution(root));
	}

	[Fact]
	public void ResolveSiblingDistribution_TrailingSeparator_IsHandled()
	{
		string root = Path.Combine(Path.DirectorySeparatorChar.ToString(), "tmp", "foo", "Configurator") + Path.DirectorySeparatorChar;
		string expected = Path.Combine(Path.DirectorySeparatorChar.ToString(), "tmp", "foo", "Service");
		Assert.Equal(expected, ServiceLayout.ResolveSiblingDistribution(root));
	}

	[Fact]
	public void ResolveSiblingDistribution_NullOrEmpty_Throws()
	{
		Assert.Throws<ArgumentException>(() => ServiceLayout.ResolveSiblingDistribution(""));
		Assert.Throws<ArgumentException>(() => ServiceLayout.ResolveSiblingDistribution("   "));
	}
}
