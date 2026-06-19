// File:    src/RdpAudit.Configurator/Theming/DarkTheme.cs
// Module:  RdpAudit.Configurator.Theming
// Purpose: Single source of truth for the Configurator's dark visual language. Holds the shared
//          colour palette (identical ARGB values previously duplicated inside RdpConfigurationPage
//          and RemoteRdpClientsPage) and exposes a recursive Apply(Control) that themes any WinForms
//          control tree — Panels, Labels, LinkLabels, Buttons, TextBoxes, ComboBoxes, CheckBoxes,
//          RadioButtons, NumericUpDowns, GroupBoxes, DataGridViews, ListViews, TreeViews,
//          TabControls, StatusStrips, ToolStrips and ContextMenuStrips — so every tab inherits the
//          same look without per-page rewrites. Also provides StyleGrid / StyleButton helpers, a
//          dark ToolStrip/menu renderer, and semantic status colours (Success / Warning / Danger /
//          Info) that stay legible on the dark background.
//
//          v2.0.0 — introduced as part of the full-Configurator dark redesign so MikroTik-grade
//          styling is applied uniformly across all tabs.
// Depends: System.Windows.Forms, System.Drawing
// Extends: To add a new themed control type, add a branch in ApplyToControl. To tweak the palette,
//          change the static Color fields here — every tab picks the change up automatically. To add
//          a new semantic status colour, add a static field and use it from page CellFormatting code.
//
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 2.0.0

using System.Runtime.Versioning;

namespace RdpAudit.Configurator.Theming;

/// <summary>Centralised dark theme: palette, recursive control theming, grid/button helpers, a dark
/// ToolStrip renderer, and semantic status colours. All members are static — the theme is stateless.</summary>
[SupportedOSPlatform("windows")]
public static class DarkTheme
{
	// ── Constants ────────────────────────────────────────────────────────────────
	// Marker stored in ListView.Tag so owner-draw handlers are wired exactly once.
	private const string ThemedTag = "DarkTheme.ListView";

	// ── Palette ──────────────────────────────────────────────────────────────────
	public static readonly Color PageBack = Color.FromArgb(30, 30, 30);
	public static readonly Color PanelBack = Color.FromArgb(40, 40, 40);
	public static readonly Color CardBack = Color.FromArgb(45, 45, 45);
	public static readonly Color CardBorder = Color.FromArgb(70, 70, 70);
	public static readonly Color TextPrimary = Color.FromArgb(220, 220, 220);
	public static readonly Color TextSecondary = Color.FromArgb(150, 150, 150);
	public static readonly Color InputBack = Color.FromArgb(55, 55, 55);
	public static readonly Color InputBorder = Color.FromArgb(80, 80, 80);
	public static readonly Color AccentHeader = Color.FromArgb(180, 200, 255);
	public static readonly Color ButtonNormal = Color.FromArgb(60, 100, 180);
	public static readonly Color ButtonHover = Color.FromArgb(80, 120, 200);
	public static readonly Color DangerButton = Color.FromArgb(160, 50, 50);
	public static readonly Color DangerHover = Color.FromArgb(190, 70, 70);
	public static readonly Color SuccessAccent = Color.FromArgb(50, 160, 80);
	public static readonly Color SuccessHover = Color.FromArgb(70, 180, 100);
	public static readonly Color StatusBack = Color.FromArgb(35, 35, 35);
	public static readonly Color StatusFore = Color.FromArgb(180, 180, 180);
	public static readonly Color ToolbarBack = Color.FromArgb(38, 38, 38);

	// Grid colours.
	public static readonly Color GridBack = Color.FromArgb(30, 30, 30);
	public static readonly Color GridLines = Color.FromArgb(60, 60, 60);
	public static readonly Color CellBack = Color.FromArgb(40, 40, 40);
	public static readonly Color AltRowBack = Color.FromArgb(45, 45, 45);
	public static readonly Color SelectionBack = Color.FromArgb(60, 100, 180);
	public static readonly Color SelectionFore = Color.FromArgb(255, 255, 255);
	public static readonly Color HeaderBack = Color.FromArgb(50, 50, 50);
	public static readonly Color HeaderFore = Color.FromArgb(180, 200, 255);

	// Tab strip colours.
	public static readonly Color TabBack = Color.FromArgb(32, 32, 32);
	public static readonly Color TabSelectedBack = Color.FromArgb(50, 50, 50);
	public static readonly Color TabAccent = Color.FromArgb(90, 140, 230);

	// Semantic status colours — bright enough to read on the dark background.
	public static readonly Color StatusSuccess = Color.FromArgb(90, 210, 120);
	public static readonly Color StatusWarning = Color.FromArgb(240, 195, 90);
	public static readonly Color StatusDanger = Color.FromArgb(235, 110, 110);
	public static readonly Color StatusInfo = Color.FromArgb(120, 180, 255);

	// Row tint backgrounds for status-coloured grid rows on the dark surface.
	public static readonly Color RowSuccessBack = Color.FromArgb(30, 65, 30);
	public static readonly Color RowWarningBack = Color.FromArgb(70, 45, 25);
	public static readonly Color RowDangerBack = Color.FromArgb(75, 30, 30);
	public static readonly Color RowMutedBack = Color.FromArgb(42, 42, 42);

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Recursively themes a control and all of its descendants. Safe to call once on a fully
	/// constructed page; controls added later can be themed by calling <see cref="Apply"/> on them.</summary>
	public static void Apply(Control root)
	{
		ArgumentNullException.ThrowIfNull(root);
		ApplyToControl(root);
		foreach (Control child in root.Controls)
		{
			Apply(child);
		}
	}

	/// <summary>Applies the dark grid styling shared by every DataGridView in the Configurator.</summary>
	public static void StyleGrid(DataGridView grid)
	{
		ArgumentNullException.ThrowIfNull(grid);

		grid.EnableHeadersVisualStyles = false;
		grid.BorderStyle = BorderStyle.None;
		grid.BackgroundColor = GridBack;
		grid.GridColor = GridLines;
		grid.ForeColor = TextPrimary;
		grid.RowHeadersVisible = false;

		grid.DefaultCellStyle.BackColor = CellBack;
		grid.DefaultCellStyle.ForeColor = TextPrimary;
		grid.DefaultCellStyle.SelectionBackColor = SelectionBack;
		grid.DefaultCellStyle.SelectionForeColor = SelectionFore;

		grid.AlternatingRowsDefaultCellStyle.BackColor = AltRowBack;
		grid.AlternatingRowsDefaultCellStyle.ForeColor = TextPrimary;
		grid.AlternatingRowsDefaultCellStyle.SelectionBackColor = SelectionBack;
		grid.AlternatingRowsDefaultCellStyle.SelectionForeColor = SelectionFore;

		grid.ColumnHeadersDefaultCellStyle.BackColor = HeaderBack;
		grid.ColumnHeadersDefaultCellStyle.ForeColor = HeaderFore;
		grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = HeaderBack;
		grid.ColumnHeadersDefaultCellStyle.SelectionForeColor = HeaderFore;

		grid.RowHeadersDefaultCellStyle.BackColor = HeaderBack;
		grid.RowHeadersDefaultCellStyle.ForeColor = HeaderFore;
	}

	/// <summary>Applies the dark flat styling shared by every command Button. Pass an explicit normal /
	/// hover colour to colour-code destructive (Danger) or confirming (Success) actions.</summary>
	public static void StyleButton(Button button, Color? normal = null, Color? hover = null)
	{
		ArgumentNullException.ThrowIfNull(button);

		Color baseColor = normal ?? ButtonNormal;
		Color hoverColor = hover ?? ButtonHover;

		button.FlatStyle = FlatStyle.Flat;
		button.FlatAppearance.BorderSize = 0;
		button.FlatAppearance.MouseOverBackColor = hoverColor;
		button.FlatAppearance.MouseDownBackColor = hoverColor;
		button.BackColor = baseColor;
		button.ForeColor = Color.White;
		button.UseVisualStyleBackColor = false;
		button.Cursor = Cursors.Hand;
	}

	/// <summary>Creates a ready-to-use dark ToolStrip renderer for ContextMenuStrip / MenuStrip / ToolStrip.</summary>
	public static ToolStripProfessionalRenderer CreateMenuRenderer() => new DarkMenuRenderer();

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private static void ApplyToControl(Control c)
	{
		switch (c)
		{
			case DataGridView grid:
				StyleGrid(grid);
				break;

			case Button button:
				// Preserve any colour already chosen by the page (e.g. Danger / Success / bulk buttons);
				// only theme buttons still wearing the default system face.
				if (IsDefaultFace(button.BackColor))
				{
					StyleButton(button);
				}
				else
				{
					button.FlatStyle = FlatStyle.Flat;
					button.FlatAppearance.BorderSize = 0;
					button.ForeColor = Color.White;
					button.UseVisualStyleBackColor = false;
				}
				break;

			case LinkLabel link:
				link.BackColor = ResolveBack(link.Parent);
				link.LinkColor = AccentHeader;
				link.ActiveLinkColor = ButtonHover;
				link.VisitedLinkColor = TextSecondary;
				link.ForeColor = TextPrimary;
				break;

			case Label label:
				label.BackColor = Color.Transparent;
				if (IsDefaultText(label.ForeColor))
				{
					label.ForeColor = TextPrimary;
				}
				break;

			case TextBoxBase text:
				text.BackColor = InputBack;
				text.ForeColor = TextPrimary;
				text.BorderStyle = BorderStyle.FixedSingle;
				break;

			case ComboBox combo:
				combo.BackColor = InputBack;
				combo.ForeColor = TextPrimary;
				combo.FlatStyle = FlatStyle.Flat;
				break;

			case NumericUpDown numeric:
				numeric.BackColor = InputBack;
				numeric.ForeColor = TextPrimary;
				numeric.BorderStyle = BorderStyle.FixedSingle;
				break;

			case CheckBox check:
				check.BackColor = Color.Transparent;
				check.ForeColor = TextPrimary;
				check.FlatStyle = FlatStyle.Flat;
				break;

			case RadioButton radio:
				radio.BackColor = Color.Transparent;
				radio.ForeColor = TextPrimary;
				radio.FlatStyle = FlatStyle.Flat;
				break;

			case GroupBox group:
				group.BackColor = CardBack;
				group.ForeColor = AccentHeader;
				break;

			case ListView listView:
				StyleListView(listView);
				break;

			case TreeView tree:
				tree.BackColor = CellBack;
				tree.ForeColor = TextPrimary;
				tree.BorderStyle = BorderStyle.FixedSingle;
				tree.LineColor = GridLines;
				break;

			case ProgressBar bar:
				bar.BackColor = InputBack;
				bar.ForeColor = SuccessAccent;
				break;

			case StatusStrip statusStrip:
				statusStrip.BackColor = StatusBack;
				statusStrip.ForeColor = StatusFore;
				foreach (ToolStripItem item in statusStrip.Items)
				{
					ThemeToolStripItem(item);
				}
				break;

			case ToolStrip toolStrip:
				toolStrip.BackColor = ToolbarBack;
				toolStrip.ForeColor = TextPrimary;
				toolStrip.Renderer = CreateMenuRenderer();
				foreach (ToolStripItem item in toolStrip.Items)
				{
					ThemeToolStripItem(item);
				}
				break;

			case TabControl:
				// MainForm owner-draws the tab strip; nothing to recolour on the control itself.
				break;

			case Form form:
				form.BackColor = PageBack;
				form.ForeColor = TextPrimary;
				break;

			// Panel covers FlowLayoutPanel, TableLayoutPanel and SplitterPanel (all derive from Panel),
			// so listing those separately would be unreachable (CS8120).
			case TabPage:
			case Panel:
			case SplitContainer:
				ThemeContainerSurface(c);
				break;

			default:
				// Unknown container — give it the surface colour so no light gaps remain.
				if (c.HasChildren)
				{
					ThemeContainerSurface(c);
				}
				break;
		}
	}

	private static void ThemeContainerSurface(Control c)
	{
		// Keep an explicitly chosen non-default surface (cards, banners, toolbars); otherwise paint
		// the standard page surface so there are no light backgrounds behind the controls.
		if (IsDefaultFace(c.BackColor))
		{
			c.BackColor = PageBack;
		}

		if (IsDefaultText(c.ForeColor))
		{
			c.ForeColor = TextPrimary;
		}
	}

	private static void ThemeToolStripItem(ToolStripItem item)
	{
		if (IsDefaultText(item.ForeColor))
		{
			item.ForeColor = StatusFore;
		}
	}

	/// <summary>Themes a ListView for the dark surface. Item rows render natively (so per-row
	/// <see cref="ListViewItem.BackColor"/> status colouring set by a page keeps working); only the
	/// column header is owner-drawn, because the classic ListView header ignores BackColor entirely and
	/// would otherwise stay light. Owner-draw is wired exactly once even if Apply runs again.</summary>
	private static void StyleListView(ListView listView)
	{
		listView.BackColor = CellBack;
		listView.ForeColor = TextPrimary;
		listView.BorderStyle = BorderStyle.FixedSingle;

		if (listView.Tag as string == ThemedTag)
		{
			return;
		}

		listView.Tag = ThemedTag;
		listView.OwnerDraw = true;

		listView.DrawColumnHeader += (_, e) =>
		{
			using SolidBrush back = new(HeaderBack);
			e.Graphics.FillRectangle(back, e.Bounds);
			using Pen border = new(GridLines);
			e.Graphics.DrawRectangle(border, e.Bounds.X, e.Bounds.Y, e.Bounds.Width - 1, e.Bounds.Height - 1);
			Rectangle text = Rectangle.Inflate(e.Bounds, -4, 0);
			TextRenderer.DrawText(
				e.Graphics,
				e.Header?.Text ?? string.Empty,
				listView.Font,
				text,
				HeaderFore,
				TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
		};

		// Item / sub-item rows render with the system defaults against the dark BackColor we set above.
		listView.DrawItem += (_, e) => e.DrawDefault = true;
		listView.DrawSubItem += (_, e) => e.DrawDefault = true;
	}

	// ── Helpers ──────────────────────────────────────────────────────────────────

	private static Color ResolveBack(Control? parent) =>
		parent is null || IsDefaultFace(parent.BackColor) ? PageBack : parent.BackColor;

	/// <summary>True when a back colour is still a default system face that the theme should override.</summary>
	private static bool IsDefaultFace(Color c) =>
		c == SystemColors.Control
		|| c == SystemColors.Window
		|| c == SystemColors.ButtonFace
		|| c == Color.Empty
		|| c == Color.Transparent
		|| c == Color.White
		|| c == Color.WhiteSmoke
		|| c == Color.Gainsboro;

	/// <summary>True when a fore colour is still a default system text colour the theme should override.</summary>
	private static bool IsDefaultText(Color c) =>
		c == SystemColors.ControlText
		|| c == SystemColors.WindowText
		|| c == Color.Empty
		|| c == Color.Black;

	// ── Dark Menu Renderer ───────────────────────────────────────────────────────

	/// <summary>ToolStrip / menu renderer painting the dark palette for ContextMenuStrip, MenuStrip and
	/// ToolStrip so popups and toolbars match the rest of the Configurator.</summary>
	private sealed class DarkMenuRenderer : ToolStripProfessionalRenderer
	{
		public DarkMenuRenderer() : base(new DarkColorTable())
		{
			RoundedEdges = false;
		}

		protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
		{
			e.TextColor = e.Item.Selected ? SelectionFore : TextPrimary;
			base.OnRenderItemText(e);
		}

		protected override void OnRenderArrow(ToolStripArrowRenderEventArgs e)
		{
			e.ArrowColor = TextPrimary;
			base.OnRenderArrow(e);
		}
	}

	/// <summary>Colour table feeding <see cref="DarkMenuRenderer"/>.</summary>
	private sealed class DarkColorTable : ProfessionalColorTable
	{
		public override Color ToolStripDropDownBackground => PanelBack;
		public override Color ImageMarginGradientBegin => PanelBack;
		public override Color ImageMarginGradientMiddle => PanelBack;
		public override Color ImageMarginGradientEnd => PanelBack;
		public override Color MenuBorder => CardBorder;
		public override Color MenuItemBorder => SelectionBack;
		public override Color MenuItemSelected => SelectionBack;
		public override Color MenuItemSelectedGradientBegin => SelectionBack;
		public override Color MenuItemSelectedGradientEnd => SelectionBack;
		public override Color MenuItemPressedGradientBegin => PanelBack;
		public override Color MenuItemPressedGradientEnd => PanelBack;
		public override Color SeparatorDark => CardBorder;
		public override Color SeparatorLight => CardBorder;
		public override Color ToolStripBorder => ToolbarBack;
		public override Color ToolStripGradientBegin => ToolbarBack;
		public override Color ToolStripGradientMiddle => ToolbarBack;
		public override Color ToolStripGradientEnd => ToolbarBack;
		public override Color ButtonSelectedHighlight => SelectionBack;
		public override Color ButtonSelectedGradientBegin => SelectionBack;
		public override Color ButtonSelectedGradientEnd => SelectionBack;
	}
}
