// File:    tests/RdpAudit.Service.Tests/EnforcementReconciliationServiceTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Integration-style tests for EnforcementReconciliationService and the reconciliation
//          worker's row-health mapping, driven against an in-memory SQLite database with a mocked
//          firewall rule scanner and firewall provider. Covers: a verified block (scanner finds the
//          rule), an unenforced block (scanner finds nothing -> MissingRule), repair re-installing a
//          missing rule via the provider, emergency cleanup removing only RdpAudit rules and marking
//          rows Removed, and the worker demoting an Active row whose enforcement could not be verified.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Service.Firewall;
using RdpAudit.Service.Services;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class EnforcementReconciliationServiceTests
{
	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;

		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;

		public AuditDbContext CreateDbContext() => new(_options);
	}

	private static async Task<(IDbContextFactory<AuditDbContext>, SqliteConnection)> CreateDbAsync()
	{
		SqliteConnection conn = new("DataSource=:memory:");
		await conn.OpenAsync();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(conn)
			.Options;

		await using (AuditDbContext init = new(options))
		{
			await init.Database.EnsureCreatedAsync();
		}

		return (new TestDbContextFactory(options), conn);
	}

	private sealed class StubScanner : IFirewallRuleScanner
	{
		private readonly FirewallScanResult _result;

		public StubScanner(FirewallScanResult result) => _result = result;

		public List<string> ScanCalls { get; } = new();

		public Task<FirewallScanResult> ScanRdpAuditBlockRulesAsync(string ruleNamePrefix, CancellationToken ct)
		{
			ScanCalls.Add(ruleNamePrefix);
			return Task.FromResult(_result);
		}
	}

	private sealed class MockFirewallProvider : IFirewallProvider
	{
		public string ProviderId { get; init; } = FirewallProviderRouting.WindowsProviderId;

		public Queue<FirewallActionResult> BlockResponses { get; } = new();

		public List<FirewallBlockRequest> BlockCalls { get; } = new();

		public List<string> UnblockCalls { get; } = new();

		public FirewallProviderStatus StatusToReport { get; init; } = FirewallProviderStatus.Available;

		public Task<FirewallStatusReport> GetStatusAsync(CancellationToken ct) =>
			Task.FromResult(new FirewallStatusReport { Status = StatusToReport, ProviderId = ProviderId });

		public Task<FirewallActionResult> BlockAsync(FirewallBlockRequest request, CancellationToken ct)
		{
			BlockCalls.Add(request);
			FirewallActionResult result = BlockResponses.Count > 0
				? BlockResponses.Dequeue()
				: new FirewallActionResult
				{
					Status = FirewallActionStatus.Success,
					ProviderId = ProviderId,
					RuleId = "RdpAudit-Block-" + request.Ip,
				};
			return Task.FromResult(result);
		}

		public Task<FirewallActionResult> UnblockAsync(string ip, string ruleName, CancellationToken ct)
		{
			UnblockCalls.Add(ip);
			return Task.FromResult(new FirewallActionResult
			{
				Status = FirewallActionStatus.Success,
				ProviderId = ProviderId,
				RuleId = "RdpAudit-Block-" + ip,
			});
		}

		public Task<IReadOnlyList<FirewallBlockEntry>> ListBlocksAsync(string ruleName, CancellationToken ct) =>
			Task.FromResult<IReadOnlyList<FirewallBlockEntry>>(Array.Empty<FirewallBlockEntry>());
	}

	private sealed class TestOptionsMonitor : IOptionsMonitor<RdpAuditOptions>
	{
		public TestOptionsMonitor(RdpAuditOptions value) => CurrentValue = value;

		public RdpAuditOptions CurrentValue { get; }

		public RdpAuditOptions Get(string? name) => CurrentValue;

		public IDisposable? OnChange(Action<RdpAuditOptions, string?> listener) => null;
	}

	private static RdpAuditOptions WindowsOptions() => new()
	{
		Firewall = new FirewallOptions
		{
			Provider = FirewallProviderKind.Windows,
			EnforcementBackend = FirewallEnforcementBackend.WindowsFirewall,
			BlockRuleName = "RdpAudit-Block",
			ReconciliationIntervalSeconds = 300,
		},
	};

	private static DiscoveredBlockRule BlockRule(string ip) => new(
		RuleName: "RdpAudit-Block-" + ip,
		Enabled: true,
		DirectionInbound: true,
		ActionBlock: true,
		Protocol: "TCP",
		LocalPorts: new[] { 3389 },
		RemoteIps: new[] { ip });

	private static async Task SeedBlockAsync(
		IDbContextFactory<AuditDbContext> factory, string ip, ActiveBlockStatus status)
	{
		await using AuditDbContext db = factory.CreateDbContext();
		db.ActiveBlocks.Add(new ActiveBlock
		{
			Ip = ip,
			Provider = FirewallProviderKind.Windows,
			RuleHandle = "RdpAudit-Block-" + ip,
			CreatedUtc = DateTime.UtcNow.AddMinutes(-5),
			ExpiresUtc = null,
			Reason = "test",
			Status = status,
		});
		await db.SaveChangesAsync();
	}

	private static EnforcementReconciliationService MakeService(
		IDbContextFactory<AuditDbContext> factory,
		IFirewallRuleScanner scanner,
		params IFirewallProvider[] providers) =>
		new(
			factory,
			new TestOptionsMonitor(WindowsOptions()),
			providers,
			scanner,
			NullLogger<EnforcementReconciliationService>.Instance,
			TimeProvider.System);

	[Fact]
	public async Task ReconcileAsync_RuleFound_ReportsVerified()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedBlockAsync(factory, "203.0.113.10", ActiveBlockStatus.Active);
			StubScanner scanner = new(new FirewallScanResult(true, new[] { BlockRule("203.0.113.10") }, null));
			EnforcementReconciliationService svc = MakeService(factory, scanner, new MockFirewallProvider());

			ReconciliationReportDto report = await svc.ReconcileAsync(CancellationToken.None);

			ReconciledBlockDto block = Assert.Single(report.Blocks);
			Assert.Equal(EnforcementStatus.Active, block.Status);
			Assert.Equal(EnforcementConfidence.Verified, block.Confidence);
			Assert.Equal(1, report.VerifiedCount);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ReconcileAsync_NoRule_ReportsMissingRuleUnenforced()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedBlockAsync(factory, "203.0.113.10", ActiveBlockStatus.Active);
			StubScanner scanner = new(new FirewallScanResult(true, Array.Empty<DiscoveredBlockRule>(), null));
			EnforcementReconciliationService svc = MakeService(factory, scanner, new MockFirewallProvider());

			ReconciliationReportDto report = await svc.ReconcileAsync(CancellationToken.None);

			ReconciledBlockDto block = Assert.Single(report.Blocks);
			Assert.Equal(EnforcementStatus.MissingRule, block.Status);
			Assert.Equal(1, report.UnenforcedCount);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RepairAsync_ReinstallsRuleViaProvider_AndVerifies()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedBlockAsync(factory, "203.0.113.10", ActiveBlockStatus.Failed);
			// After repair the scanner sees the rule, so re-reconciliation should verify it.
			StubScanner scanner = new(new FirewallScanResult(true, new[] { BlockRule("203.0.113.10") }, null));
			MockFirewallProvider provider = new();
			EnforcementReconciliationService svc = MakeService(factory, scanner, provider);

			long id;
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				id = await db.ActiveBlocks.Select(b => b.Id).FirstAsync();
			}

			ReconciledBlockDto result = await svc.RepairAsync(id, CancellationToken.None);

			Assert.Single(provider.BlockCalls);
			Assert.Equal(EnforcementStatus.Active, result.Status);

			await using AuditDbContext verify = factory.CreateDbContext();
			ActiveBlock row = await verify.ActiveBlocks.FirstAsync(b => b.Id == id);
			Assert.Equal(ActiveBlockStatus.Active, row.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RemoveAllEnforcementAsync_RemovesRules_AndMarksRowsRemoved()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedBlockAsync(factory, "203.0.113.10", ActiveBlockStatus.Active);
			await SeedBlockAsync(factory, "203.0.113.11", ActiveBlockStatus.Active);
			StubScanner scanner = new(new FirewallScanResult(
				true,
				new[] { BlockRule("203.0.113.10"), BlockRule("203.0.113.11") },
				null));
			MockFirewallProvider provider = new();
			EnforcementReconciliationService svc = MakeService(factory, scanner, provider);

			EnforcementCleanupResultDto result = await svc.RemoveAllEnforcementAsync(CancellationToken.None);

			Assert.Equal(2, result.FirewallRulesRemoved);
			Assert.Equal(2, result.ActiveBlockRowsMarkedRemoved);
			Assert.Equal(0, result.Failures);
			Assert.Equal(IpcResultStatus.Success, result.Status);
			Assert.Equal(2, provider.UnblockCalls.Count);

			await using AuditDbContext verify = factory.CreateDbContext();
			Assert.Equal(0, await verify.ActiveBlocks.CountAsync(b => b.Status == ActiveBlockStatus.Active));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RemoveAllEnforcementAsync_Unscannable_RemovesNothing()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedBlockAsync(factory, "203.0.113.10", ActiveBlockStatus.Active);
			StubScanner scanner = new(new FirewallScanResult(false, Array.Empty<DiscoveredBlockRule>(), "not scannable"));
			MockFirewallProvider provider = new();
			EnforcementReconciliationService svc = MakeService(factory, scanner, provider);

			EnforcementCleanupResultDto result = await svc.RemoveAllEnforcementAsync(CancellationToken.None);

			Assert.Equal(0, result.FirewallRulesRemoved);
			Assert.Equal(0, result.ActiveBlockRowsMarkedRemoved);
			Assert.Empty(provider.UnblockCalls);

			await using AuditDbContext verify = factory.CreateDbContext();
			Assert.Equal(1, await verify.ActiveBlocks.CountAsync(b => b.Status == ActiveBlockStatus.Active));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task WorkerTick_DemotesActiveRowWithMissingEnforcement_ToFailed()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedBlockAsync(factory, "203.0.113.10", ActiveBlockStatus.Active);
			// Scanner finds nothing -> reconciler reports MissingRule -> worker demotes the row.
			StubScanner scanner = new(new FirewallScanResult(true, Array.Empty<DiscoveredBlockRule>(), null));
			EnforcementReconciliationService svc = MakeService(factory, scanner, new MockFirewallProvider());

			EnforcementReconciliationWorker worker = new(
				svc,
				factory,
				new TestOptionsMonitor(WindowsOptions()),
				NullLogger<EnforcementReconciliationWorker>.Instance);

			await worker.TickAsync(CancellationToken.None);

			await using AuditDbContext verify = factory.CreateDbContext();
			ActiveBlock row = await verify.ActiveBlocks.FirstAsync();
			Assert.Equal(ActiveBlockStatus.Failed, row.Status);
			Assert.NotNull(row.LastError);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task WorkerTick_PromotesFailedRowWithVerifiedEnforcement_ToActive()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedBlockAsync(factory, "203.0.113.10", ActiveBlockStatus.Failed);
			StubScanner scanner = new(new FirewallScanResult(true, new[] { BlockRule("203.0.113.10") }, null));
			EnforcementReconciliationService svc = MakeService(factory, scanner, new MockFirewallProvider());

			EnforcementReconciliationWorker worker = new(
				svc,
				factory,
				new TestOptionsMonitor(WindowsOptions()),
				NullLogger<EnforcementReconciliationWorker>.Instance);

			await worker.TickAsync(CancellationToken.None);

			await using AuditDbContext verify = factory.CreateDbContext();
			ActiveBlock row = await verify.ActiveBlocks.FirstAsync();
			Assert.Equal(ActiveBlockStatus.Active, row.Status);
			Assert.Null(row.LastError);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
