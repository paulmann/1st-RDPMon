// File:    src/RdpAudit.Configurator/Services/ReadOnlyDb.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Helper that opens a read-only DbContext against the live audit database.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;

namespace RdpAudit.Configurator.Services;

/// <summary>Helper that opens a DbContext against the live audit database for read-only display.</summary>
public static class ReadOnlyDb
{
	public static AuditDbContext Open()
	{
		string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
		string dbPath = Path.Combine(programData, "RdpAudit", "rdpaudit.db");
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite($"Data Source={dbPath};Mode=ReadOnly;Cache=Shared")
			.Options;
		return new AuditDbContext(options);
	}

	public static string DatabasePath
	{
		get
		{
			string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
			return Path.Combine(programData, "RdpAudit", "rdpaudit.db");
		}
	}
}
