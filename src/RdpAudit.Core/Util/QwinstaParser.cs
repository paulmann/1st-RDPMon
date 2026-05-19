// File:    src/RdpAudit.Core/Util/QwinstaParser.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure parser for the textual output of "query session" / "qwinsta" used by the
//          Remote RDP Clients tab. Extracts session id, user name, station/client name and
//          state from English Windows output. Robust against header lines, locale-specific
//          whitespace and "current session" marker. Kept free of any Windows-specific APIs
//          so it can be unit-tested cross-platform.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Util;

/// <summary>One row parsed from <c>qwinsta</c> / <c>query session</c> output.</summary>
public sealed record QwinstaSessionRow(
	string SessionName,
	string UserName,
	int SessionId,
	string State,
	bool IsCurrent);

/// <summary>Pure parser for the textual output of <c>qwinsta</c> / <c>query session</c>.</summary>
public static class QwinstaParser
{
	private const string HeaderSessionName = "SESSIONNAME";
	private const string HeaderUserName = "USERNAME";
	private const string HeaderId = "ID";
	private const string HeaderState = "STATE";

	/// <summary>Parses the combined stdout output of <c>qwinsta</c>.
	/// Returns rows whose <see cref="QwinstaSessionRow.SessionId"/> is a non-negative integer.
	/// Lines that cannot be parsed are silently skipped — never throw on operator input.</summary>
	public static IReadOnlyList<QwinstaSessionRow> Parse(string? stdOut)
	{
		List<QwinstaSessionRow> rows = new();
		if (string.IsNullOrWhiteSpace(stdOut))
		{
			return rows;
		}

		string[] lines = stdOut.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
		ColumnLayout? layout = null;

		foreach (string raw in lines)
		{
			string line = raw.TrimEnd();
			if (line.Length == 0)
			{
				continue;
			}

			if (layout is null)
			{
				layout = TryParseHeader(line);
				continue;
			}

			QwinstaSessionRow? row = TryParseDataLine(line, layout);
			if (row is not null)
			{
				rows.Add(row);
			}
		}

		return rows;
	}

	/// <summary>Locates each header keyword and remembers its column offset so wide spaces in
	/// fields cannot confuse the splitter. Returns null if the header looks unrecognised.</summary>
	private static ColumnLayout? TryParseHeader(string line)
	{
		string upper = line.ToUpperInvariant();
		int sessionNameCol = IndexOfWord(upper, HeaderSessionName);
		int userNameCol = IndexOfWord(upper, HeaderUserName);
		int idCol = IndexOfWord(upper, HeaderId);
		int stateCol = IndexOfWord(upper, HeaderState);

		if (sessionNameCol < 0 || idCol < 0 || stateCol < 0)
		{
			return null;
		}

		return new ColumnLayout(
			SessionNameStart: sessionNameCol,
			UserNameStart: userNameCol,
			IdStart: idCol,
			StateStart: stateCol);
	}

	private static int IndexOfWord(string upper, string word)
	{
		int idx = upper.IndexOf(word, StringComparison.Ordinal);
		if (idx < 0)
		{
			return -1;
		}

		// Make sure it is a whole-word match (preceded by whitespace or start, followed by whitespace or end).
		if (idx > 0 && !char.IsWhiteSpace(upper[idx - 1]))
		{
			return -1;
		}

		int after = idx + word.Length;
		if (after < upper.Length && !char.IsWhiteSpace(upper[after]))
		{
			return -1;
		}

		return idx;
	}

	private static QwinstaSessionRow? TryParseDataLine(string line, ColumnLayout layout)
	{
		bool isCurrent = false;
		string trimmed = line;
		if (trimmed.Length > 0 && trimmed[0] == '>')
		{
			isCurrent = true;
			trimmed = ' ' + trimmed[1..];
		}

		string sessionName = SliceColumn(trimmed, layout.SessionNameStart, layout.UserNameStart);
		string userName = SliceColumn(trimmed, layout.UserNameStart, layout.IdStart);
		string idText = SliceColumn(trimmed, layout.IdStart, layout.StateStart);
		string state = SliceColumn(trimmed, layout.StateStart, trimmed.Length);

		if (string.IsNullOrWhiteSpace(idText))
		{
			return null;
		}

		if (!int.TryParse(idText.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int sessionId))
		{
			return null;
		}

		if (sessionId < 0)
		{
			return null;
		}

		// Tidy state column — keep only the leading token so " Disc " becomes "Disc" and
		// "Active extra" becomes "Active" when extra columns (Type/Device) follow.
		string stateClean = state.Trim();
		int spaceIdx = stateClean.IndexOf(' ', StringComparison.Ordinal);
		if (spaceIdx > 0)
		{
			stateClean = stateClean[..spaceIdx];
		}

		return new QwinstaSessionRow(
			SessionName: sessionName.Trim(),
			UserName: userName.Trim(),
			SessionId: sessionId,
			State: stateClean,
			IsCurrent: isCurrent);
	}

	private static string SliceColumn(string line, int start, int end)
	{
		if (start < 0 || start >= line.Length)
		{
			return string.Empty;
		}

		int safeEnd = end < 0 ? line.Length : Math.Min(end, line.Length);
		if (safeEnd <= start)
		{
			return string.Empty;
		}

		return line[start..safeEnd];
	}

	/// <summary>Maps the raw qwinsta state token to a stable canonical state name surfaced over IPC.</summary>
	public static string NormalizeState(string state)
	{
		if (string.IsNullOrWhiteSpace(state))
		{
			return "Unknown";
		}

		string upper = state.Trim().ToUpperInvariant();
		return upper switch
		{
			"ACTIVE" => "Active",
			"CONN" or "CONNECTED" => "Connected",
			"CONNQ" or "CONNECTQUERY" => "ConnectQuery",
			"SHADOW" => "Shadow",
			"DISC" or "DISCONNECTED" => "Disconnected",
			"IDLE" => "Idle",
			"LISTEN" => "Listen",
			"RESET" => "Reset",
			"DOWN" => "Down",
			"INIT" => "Init",
			_ => state.Trim(),
		};
	}

	private sealed record ColumnLayout(
		int SessionNameStart,
		int UserNameStart,
		int IdStart,
		int StateStart);
}
