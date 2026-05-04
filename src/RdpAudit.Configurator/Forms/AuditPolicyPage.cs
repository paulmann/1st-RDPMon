// File:    src/RdpAudit.Configurator/Forms/AuditPolicyPage.cs
// Module:  RdpAudit.Configurator.Forms
// Purpose: Displays the canonical audit policy rows and offers an Apply button (elevated).
// Extends: System.Windows.Forms.TabPage
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Runtime.Versioning;
using RdpAudit.Core.Events;

namespace RdpAudit.Configurator.Forms;

/// <summary>Displays the canonical audit policy rows and offers an Apply button (elevated).</summary>
[SupportedOSPlatform("windows")]
public sealed class AuditPolicyPage : TabPage
{
	private readonly ListView _list;
	private readonly Button _apply;
	private readonly Button _applySacl;

	public AuditPolicyPage()
	{
		_list = new ListView
		{
			Dock = DockStyle.Fill,
			View = View.Details,
			FullRowSelect = true,
			GridLines = true,
		};
		_list.Columns.Add("Category", 200);
		_list.Columns.Add("Subcategory", 320);
		_list.Columns.Add("Success", 80);
		_list.Columns.Add("Failure", 80);

		foreach (AuditPolicyRow row in AuditPolicyManager.RequiredRows)
		{
			ListViewItem item = new(row.Category);
			item.SubItems.Add(row.Subcategory);
			item.SubItems.Add(row.Success ? "Yes" : "No");
			item.SubItems.Add(row.Failure ? "Yes" : "No");
			_list.Items.Add(item);
		}

		FlowLayoutPanel buttons = new() { Dock = DockStyle.Top, Height = 36, FlowDirection = FlowDirection.LeftToRight };
		_apply = new Button { Text = "Apply audit policy (elevated)", Width = 220 };
		_apply.Click += (_, _) => RunElevated("RdpAudit.Configurator.Helpers.AuditPolicyApply");
		_applySacl = new Button { Text = "Configure SACL (elevated)", Width = 200 };
		_applySacl.Click += (_, _) => RunElevated("RdpAudit.Configurator.Helpers.SaclApply");
		buttons.Controls.Add(_apply);
		buttons.Controls.Add(_applySacl);

		Controls.Add(_list);
		Controls.Add(buttons);
	}

	private static void RunElevated(string token)
	{
		try
		{
			ProcessStartInfo psi = new("powershell.exe",
				"-NoProfile -ExecutionPolicy Bypass -Command \"Write-Host 'RdpAudit elevated helper invoked: " + token + "'; Start-Sleep -Seconds 1\"")
			{
				Verb = "runas",
				UseShellExecute = true,
				WindowStyle = ProcessWindowStyle.Hidden,
			};
			using Process? p = Process.Start(psi);
			p?.WaitForExit();
		}
		catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
		{
			MessageBox.Show("UAC was cancelled.", "RdpAudit", MessageBoxButtons.OK, MessageBoxIcon.Warning);
		}
		catch (Exception ex)
		{
			MessageBox.Show(ex.Message, "RdpAudit", MessageBoxButtons.OK, MessageBoxIcon.Error);
		}
	}
}
