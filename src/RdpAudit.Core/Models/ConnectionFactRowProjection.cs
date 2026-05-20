// File:    src/RdpAudit.Core/Models/ConnectionFactRowProjection.cs
// Module:  RdpAudit.Core.Models
// Purpose: Pure mapping helpers that derive Stage IP-E display strings from the fact-augmented
//          DTOs (AttackStatEntryDto, RdpSessionDto) without taking a WinForms dependency. The
//          Configurator row view-models call these helpers so the formatting rules are unit-testable
//          from RdpAudit.Core.Tests without referencing the WinForms host.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.Models;

/// <summary>Display projection of the Stage IP-D Fact* fields on <see cref="AttackStatEntryDto"/>.</summary>
public readonly record struct AttackStatFactDisplay(
	bool HasActiveConnectionFact,
	string HasActiveConnectionFactText,
	long FactFailedLogons,
	long FactSuccessfulLogons,
	string FactFirstSeenUtcText,
	string FactLastSeenUtcText);

/// <summary>Display projection of the Stage IP-D Historical* fields on <see cref="RdpSessionDto"/>.</summary>
public readonly record struct RdpSessionHistoricalDisplay(
	string HistoricalFirstSeenUtcText,
	string HistoricalLastSeenUtcText,
	long HistoricalFailedLogons,
	long HistoricalSuccessfulLogons,
	string HistoricalUserNamesAttemptedText);

/// <summary>Pure mapping helpers used by the Configurator row view-models. No WinForms dependency.</summary>
public static class ConnectionFactRowProjection
{
	/// <summary>Time format reused across grid cells and clipboard formatters.</summary>
	public const string TimeFormat = "yyyy-MM-dd HH:mm:ss";

	/// <summary>Derives the Stage IP-D Fact* display fields from an <see cref="AttackStatEntryDto"/>.</summary>
	public static AttackStatFactDisplay FromAttackStat(AttackStatEntryDto dto)
	{
		ArgumentNullException.ThrowIfNull(dto);
		return new AttackStatFactDisplay(
			HasActiveConnectionFact: dto.HasActiveConnectionFact,
			HasActiveConnectionFactText: dto.HasActiveConnectionFact ? "yes" : "no",
			FactFailedLogons: dto.FactFailedLogons,
			FactSuccessfulLogons: dto.FactSuccessfulLogons,
			FactFirstSeenUtcText: FormatNullableUtc(dto.FactFirstSeenUtc),
			FactLastSeenUtcText: FormatNullableUtc(dto.FactLastSeenUtc));
	}

	/// <summary>Derives the Stage IP-D Historical* display fields from an <see cref="RdpSessionDto"/>.</summary>
	public static RdpSessionHistoricalDisplay FromRdpSession(RdpSessionDto dto)
	{
		ArgumentNullException.ThrowIfNull(dto);
		return new RdpSessionHistoricalDisplay(
			HistoricalFirstSeenUtcText: FormatNullableUtc(dto.HistoricalFirstSeenUtc),
			HistoricalLastSeenUtcText: FormatNullableUtc(dto.HistoricalLastSeenUtc),
			HistoricalFailedLogons: dto.HistoricalFailedLogons,
			HistoricalSuccessfulLogons: dto.HistoricalSuccessfulLogons,
			HistoricalUserNamesAttemptedText: dto.HistoricalUserNamesAttempted ?? string.Empty);
	}

	private static string FormatNullableUtc(DateTime? value) =>
		value?.ToString(TimeFormat, CultureInfo.InvariantCulture) ?? string.Empty;
}
