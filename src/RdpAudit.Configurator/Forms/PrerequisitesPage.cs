// File:    src/RdpAudit.Configurator/Forms/PrerequisitesPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Lists prerequisite probes and renders pass/fail status with refresh.
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using RdpAudit.Configurator.Services;

namespace RdpAudit.Configurator.Forms;

/// <summary>Lists prerequisite probes and renders pass/fail status with refresh.</summary>
[SupportedOSPlatform("windows")]
public sealed class PrerequisitesPage : TabPage
{
	private readonly ListView _list;
	private readonly Button _refresh;
	private readonly PrerequisiteChecker _checker = new();

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
		_list.Columns.Add("Detail", 660);

		_refresh = new Button { Text = "Refresh", Dock = DockStyle.Top, Height = 30 };
		_refresh.Click += async (_, _) => await ReloadAsync().ConfigureAwait(false);

		Controls.Add(_list);
		Controls.Add(_refresh);

		HandleCreated += async (_, _) => await ReloadAsync().ConfigureAwait(false);
	}

	private async Task ReloadAsync()
	{
		_refresh.Enabled = false;
		try
		{
			IReadOnlyList<PrerequisiteResult> results = await Task.Run(() => _checker.RunAll()).ConfigureAwait(false);
			void update()
			{
				_list.Items.Clear();
				foreach (PrerequisiteResult result in results)
				{
					ListViewItem row = new(result.Name);
					row.SubItems.Add(result.IsOk ? "OK" : "Fail");
					row.SubItems.Add(result.Detail);
					row.BackColor = result.IsOk ? Color.FromArgb(220, 245, 220) : Color.FromArgb(255, 220, 220);
					_list.Items.Add(row);
				}
			}

			if (InvokeRequired)
			{
				Invoke(update);
			}
			else
			{
				update();
			}
		}
		finally
		{
			_refresh.Enabled = true;
		}
	}
}
