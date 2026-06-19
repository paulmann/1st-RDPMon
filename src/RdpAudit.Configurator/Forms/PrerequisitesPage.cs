// File:    src/RdpAudit.Configurator/Forms/PrerequisitesPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Lists prerequisite probes with pass/fail status, refresh, and per-row Fix buttons.
// Extends: System.Windows.Forms.TabPage
//          v1.1.0 — the Detail column now stretches to fill the remaining list width so GridLines no
//          longer paint an empty trailing area that looked like a spurious 5th column.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.1.0

using System.Runtime.Versioning;
using RdpAudit.Configurator.Services;

using static RdpAudit.Configurator.Theming.DarkTheme;

namespace RdpAudit.Configurator.Forms;

/// <summary>Lists prerequisite probes with pass/fail status, refresh, and per-row Fix buttons.</summary>
[SupportedOSPlatform("windows")]
public sealed class PrerequisitesPage : TabPage
{
	private readonly ListView _list;
	private readonly Button _refresh;
	private readonly Button _fixSelected;
	private readonly Button _fixAll;
	private readonly Label _info;
	private readonly PrerequisiteChecker _checker = new();
	private List<PrerequisiteResult> _current = new();

	public PrerequisitesPage()
	{
		_list = new ListView
		{
			Dock = DockStyle.Fill,
			View = View.Details,
			FullRowSelect = true,
			GridLines = true,
		};
		_list.Columns.Add("Check", 320);
		_list.Columns.Add("Status", 80);
		_list.Columns.Add("Fix", 60);
		_list.Columns.Add("Detail", 600);
		// Stretch the last (Detail) column to consume any leftover client width. Without this the
		// fixed 600px column leaves an empty gap on the right which, with GridLines enabled, reads as a
		// spurious extra (5th) column.
		_list.Resize += (_, _) => StretchDetailColumn();
		_list.MouseDoubleClick += async (_, _) => await ApplyFixForSelectedAsync().ConfigureAwait(true);

		FlowLayoutPanel buttons = new() { Dock = DockStyle.Top, Height = 36, FlowDirection = FlowDirection.LeftToRight };
		_refresh = new Button { Text = "Refresh", Width = 110 };
		_fixSelected = new Button { Text = "Fix selected", Width = 130 };
		_fixAll = new Button { Text = "Fix all failures", Width = 150 };
		_refresh.Click += async (_, _) => await ReloadAsync().ConfigureAwait(true);
		_fixSelected.Click += async (_, _) => await ApplyFixForSelectedAsync().ConfigureAwait(true);
		_fixAll.Click += async (_, _) => await ApplyAllFixesAsync().ConfigureAwait(true);
		buttons.Controls.AddRange(new Control[] { _refresh, _fixSelected, _fixAll });

		_info = new Label { Dock = DockStyle.Top, Height = 22, Text = "Ready" };

		Controls.Add(_list);
		Controls.Add(_info);
		Controls.Add(buttons);

		HandleCreated += async (_, _) => await ReloadAsync().ConfigureAwait(true);
	}

	/// <summary>Resizes the last (Detail) column so the four columns together exactly fill the list's
	/// client width, leaving no empty trailing area that GridLines would render as a phantom column.</summary>
	private void StretchDetailColumn()
	{
		if (_list.Columns.Count == 0)
		{
			return;
		}

		int used = 0;
		for (int i = 0; i < _list.Columns.Count - 1; i++)
		{
			used += _list.Columns[i].Width;
		}

		int remaining = _list.ClientSize.Width - used;
		ColumnHeader last = _list.Columns[_list.Columns.Count - 1];
		last.Width = remaining > 120 ? remaining : 120;
	}

	private async Task ReloadAsync()
	{
		_refresh.Enabled = false;
		_info.Text = "Probing...";
		try
		{
			IReadOnlyList<PrerequisiteResult> results = await Task.Run(() => _checker.RunAll()).ConfigureAwait(true);
			_current = results.ToList();
			_list.Items.Clear();
			foreach (PrerequisiteResult result in _current)
			{
				ListViewItem row = new(result.Name);
				row.SubItems.Add(result.IsOk ? "OK" : "Fail");
				row.SubItems.Add(result.Fix is null ? "-" : "Fix");
				row.SubItems.Add(result.Detail);
				row.BackColor = result.IsOk ? RowSuccessBack : RowDangerBack;
				row.ForeColor = TextPrimary;
				_list.Items.Add(row);
			}

			_info.Text = "Ready";
		}
		finally
		{
			_refresh.Enabled = true;
		}
	}

	private async Task ApplyFixForSelectedAsync()
	{
		if (_list.SelectedIndices.Count == 0)
		{
			return;
		}

		int index = _list.SelectedIndices[0];
		if (index < 0 || index >= _current.Count)
		{
			return;
		}

		PrerequisiteResult target = _current[index];
		if (target.Fix is null)
		{
			MessageBox.Show("No automatic fix is available for this probe.", "RdpAudit", MessageBoxButtons.OK, MessageBoxIcon.Information);
			return;
		}

		await ApplyFixAsync(target).ConfigureAwait(true);
	}

	private async Task ApplyAllFixesAsync()
	{
		List<PrerequisiteResult> targets = _current.Where(r => !r.IsOk && r.Fix is not null).ToList();
		if (targets.Count == 0)
		{
			MessageBox.Show("No failing probes have automatic fixes.", "RdpAudit", MessageBoxButtons.OK, MessageBoxIcon.Information);
			return;
		}

		foreach (PrerequisiteResult target in targets)
		{
			await ApplyFixAsync(target).ConfigureAwait(true);
		}
	}

	private async Task ApplyFixAsync(PrerequisiteResult target)
	{
		_fixSelected.Enabled = false;
		_fixAll.Enabled = false;
		_info.Text = $"Applying fix: {target.Name}";
		try
		{
			string outcome = await target.Fix!.ApplyAsync().ConfigureAwait(true);
			_info.Text = $"{target.Name}: {outcome}";
			await ReloadAsync().ConfigureAwait(true);
		}
		catch (Exception ex)
		{
			_info.Text = $"{target.Name}: {ex.GetType().Name}: {ex.Message}";
		}
		finally
		{
			_fixSelected.Enabled = true;
			_fixAll.Enabled = true;
		}
	}
}
