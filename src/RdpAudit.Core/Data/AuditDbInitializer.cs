// File:    src/RdpAudit.Core/Data/AuditDbInitializer.cs
// Module:  RdpAudit.Core.Data
// Purpose: Ensures the SQLite schema exists, creating directories and applying schema.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace RdpAudit.Core.Data;

/// <summary>Ensures the SQLite schema exists.</summary>
public sealed class AuditDbInitializer
{
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly ILogger<AuditDbInitializer> _logger;

	public AuditDbInitializer(IDbContextFactory<AuditDbContext> factory, ILogger<AuditDbInitializer> logger)
	{
		_factory = factory;
		_logger = logger;
	}

	public async Task EnsureCreatedAsync(CancellationToken ct = default)
	{
		await using var db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		bool created = await db.Database.EnsureCreatedAsync(ct).ConfigureAwait(false);
		_logger.LogInformation("Audit database initialized (created={Created})", created);
	}
}
