// File:    src/RdpAudit.Configurator/Forms/SettingsPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Editable view of the appsettings.json RdpAuditOptions block. Uses IPC SaveSettings
//          to persist; the service-side handler validates the document and writes atomically.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Nodes;
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
	private readonly Label _status;

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
		_load = new Button { Text = "Reload", Width = 110 };
		_save = new Button { Text = "Save (via IPC)", Width = 130 };
		_restoreDefaults = new Button { Text = "Restore defaults", Width = 150 };
		_load.Click += async (_, _) => await ReloadAsync().ConfigureAwait(true);
		_save.Click += async (_, _) => await SaveViaIpcAsync().ConfigureAwait(true);
		_restoreDefaults.Click += (_, _) => _editor.Text = DefaultTemplate;
		buttons.Controls.AddRange(new Control[] { _load, _save, _restoreDefaults });

		_status = new Label { Dock = DockStyle.Top, Height = 24, Text = "Ready" };

		Controls.Add(_editor);
		Controls.Add(_status);
		Controls.Add(buttons);

		HandleCreated += async (_, _) => await ReloadAsync().ConfigureAwait(true);
	}

	private async Task ReloadAsync()
	{
		_load.Enabled = false;
		_status.Text = "Loading...";
		try
		{
			JsonNode? settings = await _ipc.SendAsync<JsonNode>(IpcCommand.GetSettings).ConfigureAwait(true);
			if (settings is null)
			{
				_editor.Text = DefaultTemplate;
				_status.Text = "Service unreachable — showing default template.";
				return;
			}

			JsonObject wrapped = new()
			{
				[Core.Config.RdpAuditOptions.SectionName] = settings.DeepClone(),
			};
			_editor.Text = wrapped.ToJsonString(JsonOptions.Indented);
			_status.Text = "Settings loaded over IPC.";
		}
		finally
		{
			_load.Enabled = true;
		}
	}

	private async Task SaveViaIpcAsync()
	{
		_save.Enabled = false;
		_status.Text = "Saving...";
		try
		{
			using JsonDocument _ = JsonDocument.Parse(_editor.Text);
		}
		catch (JsonException ex)
		{
			_status.Text = "Invalid JSON";
			MessageBox.Show("Invalid JSON: " + ex.Message, "RdpAudit", MessageBoxButtons.OK, MessageBoxIcon.Error);
			_save.Enabled = true;
			return;
		}

		try
		{
			object? response = await _ipc.SendAsync<object>(IpcCommand.SaveSettings, _editor.Text).ConfigureAwait(true);
			_status.Text = response is null
				? "Service unreachable. Settings NOT saved."
				: "Saved. Service will hot-reload from disk.";
		}
		catch (Exception ex)
		{
			_status.Text = "Save failed: " + ex.GetType().Name;
		}
		finally
		{
			_save.Enabled = true;
		}
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
