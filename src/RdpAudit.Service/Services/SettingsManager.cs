// File:    src/RdpAudit.Service/Services/SettingsManager.cs
// Module:  RdpAudit.Service.Services
// Purpose: Validates an incoming RdpAudit settings document and writes it atomically over
//          appsettings.json so IConfiguration's reloadOnChange picks it up.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.IO;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Config;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Services;

/// <summary>Validates and persists RdpAudit settings under ProgramData\RdpAudit\appsettings.json.</summary>
public sealed class SettingsManager
{
	private readonly ILogger<SettingsManager> _logger;
	private readonly object _gate = new();

	public SettingsManager(ILogger<SettingsManager> logger)
	{
		_logger = logger;
	}

	public static string ConfigPath
	{
		get
		{
			string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
			return Path.Combine(programData, "RdpAudit", "appsettings.json");
		}
	}

	/// <summary>Validates the supplied JSON document, then atomically replaces appsettings.json.</summary>
	public bool Save(string json)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(json);

		// 1) Validate JSON structure and required RdpAudit options bind cleanly.
		using JsonDocument doc = JsonDocument.Parse(json);
		if (!doc.RootElement.TryGetProperty(RdpAuditOptions.SectionName, out JsonElement section))
		{
			throw new InvalidOperationException("JSON missing required 'RdpAudit' section.");
		}

		// Try binding to options to ensure shape is valid before writing.
		_ = section.Deserialize<RdpAuditOptions>(JsonOptions.Default)
			?? throw new InvalidOperationException("'RdpAudit' section failed to bind to RdpAuditOptions.");

		// 2) Validate any path fields are well-formed.
		if (section.TryGetProperty("Storage", out JsonElement storageElement))
		{
			ValidatePathField(storageElement, "DatabasePath");
			ValidatePathField(storageElement, "LogDirectory");
		}

		string path = ConfigPath;
		string? dir = Path.GetDirectoryName(path);
		if (string.IsNullOrEmpty(dir))
		{
			throw new InvalidOperationException("Resolved settings directory is empty.");
		}

		Directory.CreateDirectory(dir);

		// 3) Atomic write: write tmp, fsync, replace. File.Replace fails if target missing — fallback to Move.
		string tmp = path + ".tmp";
		string backup = path + ".bak";

		lock (_gate)
		{
			File.WriteAllText(tmp, json);
			if (File.Exists(path))
			{
				File.Replace(tmp, path, backup, ignoreMetadataErrors: true);
				try { File.Delete(backup); } catch { /* best effort */ }
			}
			else
			{
				File.Move(tmp, path);
			}
		}

		_logger.LogInformation("Settings saved to {Path} (length={Length})", path, json.Length);
		return true;
	}

	private static void ValidatePathField(JsonElement section, string name)
	{
		if (!section.TryGetProperty(name, out JsonElement v) || v.ValueKind != JsonValueKind.String)
		{
			return;
		}

		string? value = v.GetString();
		if (string.IsNullOrWhiteSpace(value))
		{
			return;
		}

		try
		{
			_ = Path.GetFullPath(value);
		}
		catch (Exception ex)
		{
			throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture,
				"Invalid path in {0}: {1}", name, ex.Message), ex);
		}
	}
}
