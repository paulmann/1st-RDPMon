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
//
//          v2.1.0 — repalette to Catppuccin Mocha (dark blue) to match the MikroTik setup module
//          (Base #1E1E2E, Text #CDD6F4, Blue #89B4FA accent, Segoe UI 9pt). Owner-draws every nested
//          TabControl (fixes the grey strip band and the unstyled Firewall sub-tabs), guarantees
//          buttons are never dark-on-dark, and gives buttons rounded pill regions.
// Depends: System.Windows.Forms, System.Drawing
// Extends: To add a new themed control type, add a branch in ApplyToControl. To tweak the palette,
//          change the static Color fields here — every tab picks the change up automatically. To add
//          a new semantic status colour, add a static field and use it from page CellFormatting code.
//
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 2.1.0

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
	// Marker stored in Button.Tag so the rounded-region wiring runs exactly once.
	private const string RoundedTag = "DarkTheme.RoundedButton";
	// Marker stored in TabControl.Tag so owner-draw wiring runs exactly once.
	private const string TabbedTag = "DarkTheme.TabControl";

	// ── Palette — Catppuccin Mocha (dark blue) ──────────────────────────────────────────────────────────────────
	public static readonly Color PageBack = Color.FromArgb(30, 30, 46);
	public static readonly Color PanelBack = Color.FromArgb(40, 40, 60);
	public static readonly Color CardBack = Color.FromArgb(49, 50, 68);
	public static readonly Color CardBorder = Color.FromArgb(69, 71, 90);
	public static readonly Color TextPrimary = Color.FromArgb(205, 214, 244);
	public static readonly Color TextSecondary = Color.FromArgb(166, 173, 200);
	public static readonly Color InputBack = Color.FromArgb(49, 50, 68);
	public static readonly Color InputBorder = Color.FromArgb(88, 91, 112);
	public static readonly Color AccentHeader = Color.FromArgb(137, 180, 250);
	public static readonly Color ButtonNormal = Color.FromArgb(137, 180, 250);
	public static readonly Color ButtonHover = Color.FromArgb(180, 190, 254);
	public static readonly Color DangerButton = Color.FromArgb(243, 139, 168);
	public static readonly Color DangerHover = Color.FromArgb(235, 160, 185);
	public static readonly Color SuccessAccent = Color.FromArgb(166, 227, 161);
	public static readonly Color SuccessHover = Color.FromArgb(190, 235, 185);
	public static readonly Color StatusBack = Color.FromArgb(24, 24, 37);
	public static readonly Color StatusFore = Color.FromArgb(166, 173, 200);
	public static readonly Color ToolbarBack = Color.FromArgb(24, 24, 37);
	public static readonly Color ButtonFore = Color.FromArgb(30, 30, 46);

	// Grid colours.
	public static readonly Color GridBack = Color.FromArgb(17, 17, 27);
	public static readonly Color GridLines = Color.FromArgb(69, 71, 90);
	public static readonly Color CellBack = Color.FromArgb(30, 30, 46);
	public static readonly Color AltRowBack = Color.FromArgb(36, 37, 56);
	public static readonly Color SelectionBack = Color.FromArgb(137, 180, 250);
	public static readonly Color SelectionFore = Color.FromArgb(30, 30, 46);
	public static readonly Color HeaderBack = Color.FromArgb(49, 50, 68);
	public static readonly Color HeaderFore = Color.FromArgb(137, 180, 250);

	// Tab strip colours.
	public static readonly Color TabBack = Color.FromArgb(24, 24, 37);
	public static readonly Color TabSelectedBack = Color.FromArgb(49, 50, 68);
	public static readonly Color TabAccent = Color.FromArgb(137, 180, 250);

	// Semantic status colours — bright enough to read on the dark background.
	public static readonly Color StatusSuccess = Color.FromArgb(166, 227, 161);
	public static readonly Color StatusWarning = Color.FromArgb(249, 226, 175);
	public static readonly Color StatusDanger = Color.FromArgb(243, 139, 168);
	public static readonly Color StatusInfo = Color.FromArgb(137, 180, 250);

	// Row tint backgrounds for status-coloured grid rows on the dark surface.
	public static readonly Color RowSuccessBack = Color.FromArgb(34, 50, 42);
	public static readonly Color RowWarningBack = Color.FromArgb(56, 50, 36);
	public static readonly Color RowDangerBack = Color.FromArgb(58, 34, 42);
	public static readonly Color RowMutedBack = Color.FromArgb(36, 37, 56);

	// Shared UI font for the whole Configurator (Segoe UI 9pt) — applied to every page so the typography
	// matches the MikroTik setup module.
	public static readonly Font UiFont = new("Segoe UI", 9f, FontStyle.Regular, GraphicsUnit.Point);

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Recursively themes a control and all of its descendants. Safe to call once on a fully
	/// constructed page; controls added later can be themed by calling <see cref="Apply"/> on them.</summary>
	public static void Apply(Control root)
	{
		ArgumentNullException.ThrowIfNull(root);
		// Apply the shared Segoe UI 9pt font once at the root; child controls inherit it unless they set
		// their own (e.g. the monospace command box on the MikroTik tab), so we never clobber a deliberate
		// per-control font choice further down the tree.
		if (root is Form or TabPage)
		{
			root.Font = UiFont;
		}

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
		// Dark text on the bright accent face reads best; darker faces (Danger/Success tints) keep
		// light text. Choose automatically from the perceived luminance of the face colour.
		button.ForeColor = Luminance(baseColor) > 0.6 ? ButtonFore : TextPrimary;
		button.UseVisualStyleBackColor = false;
		button.Cursor = Cursors.Hand;
		button.Font = UiFont;

		// Rounded corners: recompute the region whenever the button is resized so the rounded shape
		// tracks layout/DPI changes. Wired exactly once via the Tag marker.
		if (button.Tag as string != RoundedTag)
		{
			button.Tag = RoundedTag;
			button.Resize += (_, _) => ApplyRoundedRegion(button);
			ApplyRoundedRegion(button);
		}
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
				// Buttons with a default system face get the accent blue; deliberate page colours are kept
				// but still routed through StyleButton so nothing is dark-on-dark.
				if (IsDefaultFace(button.BackColor))
				{
					StyleButton(button);
				}
				else
				{
					// Route deliberate page colours (Danger / Success / bulk) through StyleButton too, so the
					// face stays visible with a matching hover instead of the old path that left a too-dark
					// BackColor untouched and made some buttons vanish into the background.
					StyleButton(button, button.BackColor, Lighten(button.BackColor, 0.18));
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

			case TabControl tabControl:
				StyleTabControl(tabControl);
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


	/// <summary>Owner-draws a TabControl so both the tab headers and the strip band match the dark-blue
	/// theme. WinForms paints the tab band and the page-area border with the classic light system colour
	/// regardless of <see cref="Control.BackColor"/>; left alone that produces the grey strip under the
	/// tabs and around nested tab pages. We therefore set OwnerDrawFixed and paint every tab ourselves,
	/// and we recolour each contained TabPage. Wired exactly once via the Tag marker so a second Apply is
	/// idempotent. The MainForm shell wires its own equivalent drawing on the outer tab strip; this method
	/// themes every nested TabControl the recursive Apply finds (e.g. the Firewall page's Blocklist /
	/// Whitelist sub-tabs), which previously kept the light system band.</summary>
	private static void StyleTabControl(TabControl tab)
	{
		tab.BackColor = PageBack;
		tab.ForeColor = TextPrimary;

		foreach (TabPage page in tab.TabPages)
		{
			page.BackColor = PageBack;
			page.ForeColor = TextPrimary;
			page.UseVisualStyleBackColor = false;
		}

		if (tab.Tag as string == TabbedTag)
		{
			return;
		}

		tab.Tag = TabbedTag;
		tab.DrawMode = TabDrawMode.OwnerDrawFixed;
		// FlatButtons removes the classic raised 3-D page border that WinForms otherwise paints in the
		// light system colour around the page area and under the tab row (the grey band the user saw).
		tab.Appearance = TabAppearance.FlatButtons;
		tab.DrawItem += OnDrawDarkTab;
	}

	/// <summary>Shared owner-draw handler painting one dark tab header: the active tab sits on a raised
	/// surface with a bright accent bar; inactive tabs sit on the darker strip band. Used by every nested
	/// TabControl the recursive Apply discovers.</summary>
	private static void OnDrawDarkTab(object? sender, DrawItemEventArgs e)
	{
		if (sender is not TabControl tab || e.Index < 0 || e.Index >= tab.TabPages.Count)
		{
			return;
		}

		TabPage page = tab.TabPages[e.Index];
		bool selected = e.Index == tab.SelectedIndex;
		Rectangle bounds = e.Bounds;

		Color back = selected ? TabSelectedBack : TabBack;
		Color fore = selected ? AccentHeader : TextPrimary;

		using (SolidBrush backBrush = new(back))
		{
			e.Graphics.FillRectangle(backBrush, bounds);
		}

		if (selected)
		{
			using SolidBrush accentBrush = new(TabAccent);
			e.Graphics.FillRectangle(accentBrush, bounds.Left, bounds.Top, bounds.Width, 3);
		}

		using Font font = new(tab.Font, selected ? FontStyle.Bold : FontStyle.Regular);
		TextRenderer.DrawText(
			e.Graphics,
			page.Text,
			font,
			bounds,
			fore,
			TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
	}

	/// <summary>Rebuilds a button's rounded-rectangle region so the flat accent buttons read as rounded
	/// pills like the MikroTik module. No-op for degenerate sizes (transiently zero during construction).</summary>
	private static void ApplyRoundedRegion(Button button)
	{
		int w = button.Width;
		int h = button.Height;
		if (w <= 1 || h <= 1)
		{
			return;
		}

		int radius = Math.Max(2, Math.Min(10, h / 3));
		int d = radius * 2;
		using System.Drawing.Drawing2D.GraphicsPath path = new();
		path.AddArc(0, 0, d, d, 180, 90);
		path.AddArc(w - d - 1, 0, d, d, 270, 90);
		path.AddArc(w - d - 1, h - d - 1, d, d, 0, 90);
		path.AddArc(0, h - d - 1, d, d, 90, 90);
		path.CloseFigure();
		button.Region?.Dispose();
		button.Region = new Region(path);
	}

	/// <summary>Perceived luminance (0..1) of a colour via the Rec. 601 weighting; used to pick a
	/// readable foreground over a button face.</summary>
	private static double Luminance(Color c) =>
		((0.299 * c.R) + (0.587 * c.G) + (0.114 * c.B)) / 255.0;

	/// <summary>Returns <paramref name="c"/> lightened toward white by <paramref name="amount"/> (0..1).
	/// Used to synthesize a hover colour for buttons that carry a deliberate page face.</summary>
	private static Color Lighten(Color c, double amount)
	{
		double a = Math.Clamp(amount, 0.0, 1.0);
		int r = (int)Math.Round(c.R + ((255 - c.R) * a));
		int g = (int)Math.Round(c.G + ((255 - c.G) * a));
		int b = (int)Math.Round(c.B + ((255 - c.B) * a));
		return Color.FromArgb(c.A, r, g, b);
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
