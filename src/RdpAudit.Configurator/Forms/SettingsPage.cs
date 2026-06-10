// File:    src/RdpAudit.Configurator/Forms/SettingsPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Editable view of the appsettings.json RdpAuditOptions block. Surfaces the global DEBUG
//          mode as a first-class persisted toggle (with a destructive-actions warning and a status
//          indicator), a category TreeView that navigates the configuration sections, and an advanced
//          raw-JSON editor for full-document edits. Uses IPC SaveSettings to persist; the service-side
//          handler validates the document and writes atomically, then hot-reloads it.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
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
	private const string DebugWarningText =
		"DEBUG mode enables advanced diagnostics and destructive maintenance actions.";

	private readonly IpcClient _ipc;
	private readonly TextBox _editor;
	private readonly TreeView _tree;
	private readonly Button _load;
	private readonly Button _save;
	private readonly Button _restoreDefaults;
	private readonly CheckBox _debugToggle;
	private readonly Label _debugStatus;
	private readonly Label _debugWarning;
	private readonly Label _status;

	private bool _dirty;
	private bool _suppressEditorEvents;

	public SettingsPage(IpcClient ipc)
	{
		_ipc = ipc;

		// --- Global DEBUG section (top) ----------------------------------------------------------
		Panel debugPanel = new() { Dock = DockStyle.Top, Height = 78, Padding = new Padding(6) };
		_debugToggle = new CheckBox
		{
			Text = "Enable global DEBUG mode",
			AutoSize = true,
			Location = new Point(8, 6),
		};
		_debugToggle.CheckedChanged += (_, _) => OnDebugToggleChanged();
		_debugStatus = new Label
		{
			AutoSize = true,
			Location = new Point(220, 8),
			Font = new Font(FontFamily.GenericSansSerif, 9, FontStyle.Bold),
		};
		_debugWarning = new Label
		{
			Text = "⚠ " + DebugWarningText,
			AutoSize = true,
			ForeColor = Color.DarkGoldenrod,
			Location = new Point(8, 30),
		};
		debugPanel.Controls.Add(_debugToggle);
		debugPanel.Controls.Add(_debugStatus);
		debugPanel.Controls.Add(_debugWarning);

		// --- Action buttons ----------------------------------------------------------------------
		FlowLayoutPanel buttons = new() { Dock = DockStyle.Top, Height = 36 };
		_load = new Button { Text = "Reload", Width = 110 };
		_save = new Button { Text = "Save (via IPC)", Width = 130 };
		_restoreDefaults = new Button { Text = "Restore defaults", Width = 150 };
		_load.Click += async (_, _) => await ReloadAsync().ConfigureAwait(true);
		_save.Click += async (_, _) => await SaveViaIpcAsync().ConfigureAwait(true);
		_restoreDefaults.Click += (_, _) => RestoreDefaults();
		buttons.Controls.AddRange(new Control[] { _load, _save, _restoreDefaults });

		_status = new Label { Dock = DockStyle.Top, Height = 24, Text = "Ready" };

		// --- Category tree + raw JSON editor (split) ---------------------------------------------
		_tree = new TreeView { Dock = DockStyle.Fill, HideSelection = false };
		_tree.AfterSelect += (_, e) => OnTreeSelect(e?.Node);

		_editor = new TextBox
		{
			Dock = DockStyle.Fill,
			Multiline = true,
			ScrollBars = ScrollBars.Both,
			WordWrap = false,
			Font = new Font(FontFamily.GenericMonospace, 10),
		};
		_editor.TextChanged += (_, _) =>
		{
			if (_suppressEditorEvents)
			{
				return;
			}

			_dirty = true;
			UpdateStatus("Modified — unsaved changes.");
		};

		SplitContainer split = new()
		{
			Dock = DockStyle.Fill,
			Orientation = Orientation.Vertical,
			SplitterDistance = 280,
		};
		split.Panel1.Controls.Add(_tree);
		split.Panel1.Controls.Add(new Label
		{
			Dock = DockStyle.Top,
			Height = 22,
			Text = "Categories (advanced raw JSON on the right)",
			Font = new Font(FontFamily.GenericSansSerif, 8, FontStyle.Italic),
		});
		split.Panel2.Controls.Add(_editor);

		Controls.Add(split);
		Controls.Add(_status);
		Controls.Add(buttons);
		Controls.Add(debugPanel);

		HandleCreated += async (_, _) => await ReloadAsync().ConfigureAwait(true);
	}

	private async Task ReloadAsync()
	{
		_load.Enabled = false;
		UpdateStatus("Loading...");
		try
		{
			JsonNode? settings = await _ipc.SendAsync<JsonNode>(IpcCommand.GetSettings).ConfigureAwait(true);
			if (settings is null)
			{
				SetEditorText(DefaultTemplate);
				UpdateStatus("Service unreachable — showing default template.");
				return;
			}

			JsonObject wrapped = new()
			{
				[Core.Config.RdpAuditOptions.SectionName] = settings.DeepClone(),
			};
			SetEditorText(wrapped.ToJsonString(JsonOptions.Indented));
			_dirty = false;
			UpdateStatus("Settings loaded over IPC.");
		}
		finally
		{
			_load.Enabled = true;
		}
	}

	private void RestoreDefaults()
	{
		SetEditorText(DefaultTemplate);
		_dirty = true;
		UpdateStatus("Default template loaded — review and Save to apply.");
	}

	private async Task SaveViaIpcAsync()
	{
		_save.Enabled = false;
		UpdateStatus("Saving...");
		try
		{
			using JsonDocument _ = JsonDocument.Parse(_editor.Text);
		}
		catch (JsonException ex)
		{
			UpdateStatus("Invalid JSON");
			MessageBox.Show("Invalid JSON: " + ex.Message, "RdpAudit", MessageBoxButtons.OK, MessageBoxIcon.Error);
			_save.Enabled = true;
			return;
		}

		try
		{
			object? response = await _ipc.SendAsync<object>(IpcCommand.SaveSettings, _editor.Text).ConfigureAwait(true);
			if (response is null)
			{
				UpdateStatus("Service unreachable. Settings NOT saved.");
			}
			else
			{
				_dirty = false;
				UpdateStatus("Saved. Service will hot-reload from disk.");
			}
		}
		catch (Exception ex)
		{
			UpdateStatus("Save failed: " + ex.GetType().Name);
		}
		finally
		{
			_save.Enabled = true;
		}
	}

	/// <summary>Re-reads the editor JSON, rebuilds the category tree, and refreshes the DEBUG toggle /
	/// status indicator from the parsed document. Tolerant of in-progress invalid JSON.</summary>
	private void RefreshFromEditor()
	{
		JsonObject? root = TryParseRoot();
		RebuildTree(root);
		RefreshDebugIndicator(root);
	}

	private JsonObject? TryParseRoot()
	{
		try
		{
			JsonNode? parsed = JsonNode.Parse(_editor.Text);
			if (parsed is JsonObject obj && obj[Core.Config.RdpAuditOptions.SectionName] is JsonObject section)
			{
				return section;
			}

			return parsed as JsonObject;
		}
		catch (JsonException)
		{
			return null;
		}
	}

	private void RebuildTree(JsonObject? section)
	{
		_tree.BeginUpdate();
		try
		{
			_tree.Nodes.Clear();
			if (section is null)
			{
				_tree.Nodes.Add("(invalid JSON — fix the raw document on the right)");
				return;
			}

			TreeNode rootNode = new("RdpAudit");
			foreach (KeyValuePair<string, JsonNode?> category in section)
			{
				TreeNode catNode = new(category.Key);
				if (category.Value is JsonObject catObj)
				{
					foreach (KeyValuePair<string, JsonNode?> leaf in catObj)
					{
						string value = leaf.Value switch
						{
							JsonObject => "{…}",
							JsonArray arr => string.Format(CultureInfo.InvariantCulture, "[{0}]", arr.Count),
							null => "null",
							_ => leaf.Value.ToJsonString(),
						};
						catNode.Nodes.Add(string.Format(CultureInfo.InvariantCulture, "{0} = {1}", leaf.Key, value));
					}
				}

				rootNode.Nodes.Add(catNode);
			}

			_tree.Nodes.Add(rootNode);
			rootNode.Expand();
		}
		finally
		{
			_tree.EndUpdate();
		}
	}

	private void OnTreeSelect(TreeNode? node)
	{
		if (node is null)
		{
			return;
		}

		// Scroll the raw editor to the first occurrence of the selected category / key so the typed
		// view and the raw document stay in sync without a second editing surface to keep coherent.
		string token = node.Text.Split(' ')[0];
		int idx = _editor.Text.IndexOf("\"" + token + "\"", StringComparison.Ordinal);
		if (idx >= 0)
		{
			_editor.Select(idx, token.Length + 2);
			_editor.ScrollToCaret();
		}
	}

	private void RefreshDebugIndicator(JsonObject? section)
	{
		bool debug = section?["Diagnostics"] is JsonObject diag
			&& diag["DebugMode"] is JsonValue v
			&& v.TryGetValue(out bool b)
			&& b;

		_suppressEditorEvents = true;
		try
		{
			_debugToggle.Checked = debug;
		}
		finally
		{
			_suppressEditorEvents = false;
		}

		if (debug)
		{
			_debugStatus.Text = "DEBUG MODE ENABLED";
			_debugStatus.ForeColor = Color.DarkRed;
			_debugWarning.Visible = true;
		}
		else
		{
			_debugStatus.Text = "DEBUG mode off";
			_debugStatus.ForeColor = SystemColors.ControlText;
			_debugWarning.Visible = false;
		}
	}

	private void OnDebugToggleChanged()
	{
		if (_suppressEditorEvents)
		{
			return;
		}

		JsonObject? section = TryParseRoot();
		if (section is null)
		{
			UpdateStatus("Cannot toggle DEBUG: fix the raw JSON first.");
			return;
		}

		if (section["Diagnostics"] is not JsonObject diag)
		{
			diag = new JsonObject();
			section["Diagnostics"] = diag;
		}

		diag["DebugMode"] = _debugToggle.Checked;

		JsonObject wrapped = new()
		{
			[Core.Config.RdpAuditOptions.SectionName] = section.DeepClone(),
		};
		SetEditorText(wrapped.ToJsonString(JsonOptions.Indented), rebuildTree: false);
		RefreshDebugIndicator(section);
		_dirty = true;
		UpdateStatus("DEBUG toggled — Save to apply. " + DebugWarningText);
	}

	private void SetEditorText(string text, bool rebuildTree = true)
	{
		_suppressEditorEvents = true;
		try
		{
			_editor.Text = text;
		}
		finally
		{
			_suppressEditorEvents = false;
		}

		if (rebuildTree)
		{
			RefreshFromEditor();
		}
	}

	private void UpdateStatus(string text)
	{
		_status.Text = _dirty ? "● " + text : text;
	}

	private const string DefaultTemplate = """
{
	"RdpAudit": {
		"Monitoring": { "FilterLocalAddresses": true, "BatchSize": 100, "ChannelCapacity": 50000 },
		"Alerts": { "BruteForceThreshold": 10, "BruteForceWindowMinutes": 5 },
		"Storage": { "EventRetentionDays": 365 },
		"Logs": { "ViewDepthDays": 60, "RetentionDays": 60, "DefaultPageSize": 500 },
		"Diagnostics": { "DebugMode": false }
	}
}
""";
}
