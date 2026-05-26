// File:    src/RdpAudit.Core/Util/QwinstaSessionMapper.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure mapping from <see cref="QwinstaSessionRow"/> rows produced by
//          <see cref="QwinstaParser"/> to <see cref="RdpSessionDto"/> instances used by the
//          ListRdpSessions IPC contract. Used by the service-side <c>RdpSessionManager</c>
//          and by the Configurator-side <c>LocalRdpSessionProvider</c> so both paths emit
//          structurally identical rows when the parser sees the same qwinsta output.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.Util;

/// <summary>Pure mapper that converts parsed qwinsta rows into <see cref="RdpSessionDto"/>.</summary>
public static class QwinstaSessionMapper
{
	/// <summary>Map a single parsed row.</summary>
	public static RdpSessionDto Map(QwinstaSessionRow row)
	{
		ArgumentNullException.ThrowIfNull(row);
		string state = QwinstaParser.NormalizeState(row.State);
		// v1.2.2 — operator-visible Current? must reflect the validated active-RDP
		// semantics, not the raw qwinsta ">" marker (which under LocalSystem can point at
		// session 0 / services). The raw marker is preserved on IsQueryCurrent for the
		// diagnostic support bundle only.
		ActiveRdpClassification classification = ActiveRdpSessionClassifier.Classify(
			sessionId: row.SessionId,
			sessionName: row.SessionName,
			userName: row.UserName,
			normalizedState: state);
		return new RdpSessionDto
		{
			SessionId = row.SessionId,
			UserName = row.UserName,
			SessionName = row.SessionName,
			State = state,
			IsCurrent = classification.IsActiveRdp,
			IsQueryCurrent = row.IsCurrent,
			IsActiveRdp = classification.IsActiveRdp,
			IsActive = string.Equals(state, "Active", StringComparison.OrdinalIgnoreCase),
			IsDisconnected = string.Equals(state, "Disconnected", StringComparison.OrdinalIgnoreCase),
		};
	}

	/// <summary>Map every row in the supplied parsed sequence.</summary>
	public static IReadOnlyList<RdpSessionDto> MapAll(IReadOnlyList<QwinstaSessionRow> rows)
	{
		ArgumentNullException.ThrowIfNull(rows);
		List<RdpSessionDto> dtos = new(rows.Count);
		foreach (QwinstaSessionRow row in rows)
		{
			dtos.Add(Map(row));
		}

		return dtos;
	}
}
