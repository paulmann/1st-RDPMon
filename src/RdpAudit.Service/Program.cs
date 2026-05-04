// File:    src/RdpAudit.Service/Program.cs
// Module:  RdpAudit.Service
// Purpose: Process entry point — configures host, DI, logging, and worker registrations.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Service.Alerts;
using RdpAudit.Service.Collectors;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Processors;
using RdpAudit.Service.Workers;
using Serilog;
using Serilog.Formatting.Compact;

namespace RdpAudit.Service;

/// <summary>Process entry point — configures host, DI, logging, and worker registrations.</summary>
public static class Program
{
	public static async Task<int> Main(string[] args)
	{
		bool isService = !Debugger.IsAttached
			&& !args.Contains("--console", StringComparer.OrdinalIgnoreCase)
			&& WindowsServiceHelpers.IsWindowsService();

		HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);

		string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
		string configPath = Path.Combine(programData, "RdpAudit", "appsettings.json");
		Directory.CreateDirectory(Path.GetDirectoryName(configPath)!);
		if (!File.Exists(configPath))
		{
			await File.WriteAllTextAsync(configPath, AppSettingsTemplate.Default).ConfigureAwait(false);
		}

		builder.Configuration
			.AddJsonFile(configPath, optional: false, reloadOnChange: true)
			.AddEnvironmentVariables("RDPAUDIT_");

		builder.Services.Configure<RdpAuditOptions>(
			builder.Configuration.GetSection(RdpAuditOptions.SectionName));

		ConfigureSerilog(builder, programData);

		if (isService)
		{
			builder.Services.AddWindowsService(o => o.ServiceName = "RdpAuditService");
		}

		builder.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromSeconds(15));

		RegisterServices(builder.Services);

		using IHost host = builder.Build();

		using (IServiceScope scope = host.Services.CreateScope())
		{
			AuditDbInitializer initializer = scope.ServiceProvider.GetRequiredService<AuditDbInitializer>();
			await initializer.EnsureCreatedAsync().ConfigureAwait(false);

			BookmarkStore store = scope.ServiceProvider.GetRequiredService<BookmarkStore>();
			await store.LoadAllAsync().ConfigureAwait(false);
		}

		await host.RunAsync().ConfigureAwait(false);
		return 0;
	}

	private static void ConfigureSerilog(HostApplicationBuilder builder, string programData)
	{
		string logDir = Path.Combine(programData, "RdpAudit", "logs");
		Directory.CreateDirectory(logDir);

		LoggerConfiguration logger = new LoggerConfiguration()
			.ReadFrom.Configuration(builder.Configuration)
			.Enrich.FromLogContext()
			.WriteTo.File(
				new CompactJsonFormatter(),
				Path.Combine(logDir, "service-.log"),
				rollingInterval: RollingInterval.Day,
				retainedFileCountLimit: 90);

		if (OperatingSystem.IsWindows())
		{
			logger = logger.WriteTo.EventLog(
				source: "RdpAuditService",
				logName: "Application",
				manageEventSource: false);
		}

		builder.Logging.ClearProviders();
		builder.Services.AddSerilog(logger.CreateLogger(), dispose: true);
	}

	private static void RegisterServices(IServiceCollection services)
	{
		services.AddSingleton<SqlitePragmaInterceptor>();

		services.AddDbContextFactory<AuditDbContext>((sp, options) =>
		{
			IOptions<RdpAuditOptions> opts = sp.GetRequiredService<IOptions<RdpAuditOptions>>();
			string dbPath = opts.Value.Storage.ResolveDatabasePath();
			Directory.CreateDirectory(Path.GetDirectoryName(dbPath)!);
			options
				.UseSqlite($"Data Source={dbPath};Cache=Shared")
				.AddInterceptors(sp.GetRequiredService<SqlitePragmaInterceptor>());
		});

		services.AddSingleton<AuditDbInitializer>();
		services.AddSingleton<BookmarkStore>();
		services.AddSingleton<EventChannel>();
		services.AddSingleton<ServiceMetrics>();
		services.AddSingleton<EventNormalizer>();
		services.AddSingleton<DbAlertContext>();
		services.AddSingleton<IAlertContext>(sp => sp.GetRequiredService<DbAlertContext>());
		services.AddScoped<IpcDispatcher>();

		AlertRuleRegistration.Register(services);

		services.AddHostedService<EventCollectorWorker>();
		services.AddHostedService<EventProcessorWorker>();
		services.AddHostedService<AlertWorker>();
		services.AddHostedService<IpcServerWorker>();
		services.AddHostedService<MaintenanceWorker>();
	}
}
