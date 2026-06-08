// File:    tests/RdpAudit.Service.Tests/RuntimeVersionResolverPinTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Locks the Service runtime version surfaced via IPC ServiceStatus.Version at exactly
//          1.2.4 — the SemVer publish.ps1 emits and the value the Configurator's Service tab
//          contrasts against the installed and distribution binaries. The complementary core
//          gate lives in RdpAuditVersionMetadataTests; this one targets the Service assembly
//          and the resolver path the running service actually uses at runtime. The 1.2.4 bump
//          accompanies the live-enforcement reconciliation pass and the new Reconcile / Repair /
//          RemoveAllEnforcement diagnostic IPC commands.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Reflection;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>Pins the Service runtime version at 1.2.4.</summary>
public class RuntimeVersionResolverPinTests
{
	private const string ExpectedSemVer = "1.2.4";
	private const string ForbiddenLegacy = "1.0.0";

	[Fact]
	public void Resolve_FromServiceAssembly_ReturnsExactly120()
	{
		Assembly serviceAssembly = typeof(RuntimeVersionResolver).Assembly;
		string version = RuntimeVersionResolver.Resolve(serviceAssembly, processPath: null);
		Assert.Equal(ExpectedSemVer, version);
	}

	[Fact]
	public void Resolve_NeverReportsLegacy100()
	{
		Assembly serviceAssembly = typeof(RuntimeVersionResolver).Assembly;
		string version = RuntimeVersionResolver.Resolve(serviceAssembly, processPath: null);
		Assert.DoesNotContain(ForbiddenLegacy, version, StringComparison.Ordinal);
	}
}
