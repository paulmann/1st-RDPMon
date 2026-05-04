// File:    src/RdpAudit.Configurator/Forms/SettingsPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Editable view of the appsettings.json RdpAuditOptions block.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using System.Text.Json;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Forms;

/// <summary>Editable view of the appsettings.json RdpAuditOptions block.</summary>
[SupportedOSPlatform("windows")]
public sealed class SettingsPage : TabPage
{
	private readonly IpcClient _ipc;
	private readonly TextBox _editor;
	private readonly Button _load;
	private readonly Button _save;
	private readonly Button _restoreDefaults;

	public SettingsPage(IpcClient ipc)
	{
		_ipc = ipc;
		_editor = new TextBox
		{
			Dock = DockStyle.Fill,
			Multiline = true,
			ScrollBars = ScrollBars.Both,
			WordWrap = false,
			Font = new Font(FontFamily.GenericMonospace, 10),
		};

		FlowLayoutPanel buttons = new() { Dock = DockStyle.Top, Height = 36 };
		_load = new Button { Text = "Reload from disk", Width = 150 };
		_save = new Button { Text = "Save", Width = 100 };
		_restoreDefaults = new Button { Text = "Restore defaults", Width = 150 };
		_load.Click += async (_, _) => await ReloadAsync().ConfigureAwait(false);
		_save.Click += (_, _) => SaveToDisk();
		_restoreDefaults.Click += (_, _) => _editor.Text = ReadDiskOrTemplate(true);
		buttons.Controls.AddRange(new Control[] { _load, _save, _restoreDefaults });

		Controls.Add(_editor);
		Controls.Add(buttons);

		HandleCreated += async (_, _) => await ReloadAsync().ConfigureAwait(false);
	}

	private async Task ReloadAsync()
	{
		try
		{
			object? settings = await _ipc.SendAsync<object>(IpcCommand.GetSettings).ConfigureAwait(false);
			if (settings is not null)
			{
				_editor.Text = JsonSerializer.Serialize(settings, JsonOptions.Indented);
				return;
			}
		}
		catch
		{
			// fall through to disk read
		}

		_editor.Text = ReadDiskOrTemplate(false);
	}

	private static string ReadDiskOrTemplate(bool forceTemplate)
	{
		string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
		string path = Path.Combine(programData, "RdpAudit", "appsettings.json");
		if (forceTemplate || !File.Exists(path))
		{
			return DefaultTemplate;
		}

		try
		{
			return File.ReadAllText(path);
		}
		catch (Exception ex)
		{
			return $"// Failed to read {path}: {ex.Message}\r\n" + DefaultTemplate;
		}
	}

	private void SaveToDisk()
	{
		try
		{
			using JsonDocument _ = JsonDocument.Parse(_editor.Text);
		}
		catch (JsonException ex)
		{
			MessageBox.Show($"Invalid JSON: {ex.Message}", "RdpAudit", MessageBoxButtons.OK, MessageBoxIcon.Error);
			return;
		}

		string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
		string dir = Path.Combine(programData, "RdpAudit");
		Directory.CreateDirectory(dir);
		string path = Path.Combine(dir, "appsettings.json");
		File.WriteAllText(path, _editor.Text);
		MessageBox.Show("Settings saved. Service watches the file and will hot-reload.",
			"RdpAudit",
			MessageBoxButtons.OK,
			MessageBoxIcon.Information);
	}

	private const string DefaultTemplate = """
{
	"RdpAudit": {
		"Monitoring": { "FilterLocalAddresses": true, "BatchSize": 100, "ChannelCapacity": 50000 },
		"Alerts": { "BruteForceThreshold": 10, "BruteForceWindowMinutes": 5 },
		"Storage": { "EventRetentionDays": 365 },
		"Diagnostics": { "DebugMode": false }
	}
}
""";
}
