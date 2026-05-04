// File:    src/RdpAudit.Core/Config/StorageOptions.cs
// Module:  RdpAudit.Core.Config
// Purpose: Database location, retention windows, and log retention settings.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Config;

/// <summary>Database location, retention, and log retention settings.</summary>
public sealed class StorageOptions
{
	public string DatabasePath { get; set; } = string.Empty;

	public int EventRetentionDays { get; set; } = 365;

	public int LogRetentionDays { get; set; } = 90;

	public int AlertRetentionDays { get; set; } = 730;

	public string LogDirectory { get; set; } = string.Empty;

	/// <summary>Returns the configured database path or a sensible default under ProgramData.</summary>
	public string ResolveDatabasePath()
	{
		if (!string.IsNullOrWhiteSpace(DatabasePath))
		{
			return DatabasePath;
		}

		string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
		return Path.Combine(programData, "RdpAudit", "rdpaudit.db");
	}

	/// <summary>Returns the configured log directory or a sensible default under ProgramData.</summary>
	public string ResolveLogDirectory()
	{
		if (!string.IsNullOrWhiteSpace(LogDirectory))
		{
			return LogDirectory;
		}

		string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
		return Path.Combine(programData, "RdpAudit", "logs");
	}
}
