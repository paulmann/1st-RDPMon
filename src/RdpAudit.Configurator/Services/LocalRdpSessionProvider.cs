// File:    src/RdpAudit.Configurator/Services/LocalRdpSessionProvider.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Configurator-side direct enumeration of local RDP sessions for the Remote RDP
//          Clients tab when the RdpAudit service IPC pipe is unreachable. Mirrors the
//          service-side RdpSessionManager behaviour: spawns the supported Windows
//          command-line tool (qwinsta.exe), reads its English/Latin column output through
//          the pure RdpAudit.Core QwinstaParser, and projects every parsed row into the
//          existing RdpSessionDto contract. Uses ProcessStartInfo.ArgumentList so no
//          user-supplied data is concatenated into a shell string. Honours a hard timeout
//          so a hung qwinsta cannot freeze the UI worker. Read-only — never spawns
//          tsdiscon/logoff/mstsc.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Outcome of a local <see cref="LocalRdpSessionProvider.ListAsync"/> call.</summary>
public sealed record LocalSessionListResult(
	bool Success,
	IReadOnlyList<RdpSessionDto> Sessions,
	string? Error)
{
	/// <summary>Convenience factory for a successful listing.</summary>
	public static LocalSessionListResult Ok(IReadOnlyList<RdpSessionDto> sessions) =>
		new(true, sessions, null);

	/// <summary>Convenience factory for a failed listing.</summary>
	public static LocalSessionListResult Failed(string error) =>
		new(false, Array.Empty<RdpSessionDto>(), error);
}

/// <summary>Configurator-side enumeration of local RDP sessions via <c>qwinsta.exe</c>. Used by
/// <see cref="Forms.RemoteRdpClientsPage"/> when the RdpAudit service IPC pipe is unreachable so
/// the operator still sees live session rows; historical enrichment is unavailable in this mode.</summary>
[SupportedOSPlatform("windows")]
public sealed class LocalRdpSessionProvider
{
	/// <summary>Default hard timeout for the qwinsta invocation. The session listing usually
	/// completes in tens of milliseconds — five seconds is generous and still bounds UI hangs.</summary>
	internal const int DefaultTimeoutMs = 5_000;

	private readonly int _timeoutMs;
	private readonly Func<IReadOnlyList<string>, CancellationToken, Task<LocalSessionToolResult>> _spawn;

	/// <summary>Production constructor — spawns the system qwinsta.exe.</summary>
	public LocalRdpSessionProvider()
		: this(DefaultTimeoutMs, RunSystemQwinstaAsync)
	{
	}

	/// <summary>Test-friendly constructor that lets the unit suite inject a deterministic spawn function.</summary>
	internal LocalRdpSessionProvider(
		int timeoutMs,
		Func<IReadOnlyList<string>, CancellationToken, Task<LocalSessionToolResult>> spawn)
	{
		_timeoutMs = timeoutMs > 0
			? timeoutMs
			: throw new ArgumentOutOfRangeException(nameof(timeoutMs));
		_spawn = spawn ?? throw new ArgumentNullException(nameof(spawn));
	}

	/// <summary>Lists currently known sessions on the local host. Never throws — failures are
	/// surfaced through <see cref="LocalSessionListResult.Error"/>.</summary>
	public async Task<LocalSessionListResult> ListAsync(CancellationToken ct = default)
	{
		using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
		cts.CancelAfter(_timeoutMs);

		LocalSessionToolResult tool;
		try
		{
			tool = await _spawn(SessionCommandBuilder.BuildListSessions(), cts.Token).ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			return LocalSessionListResult.Failed("qwinsta timed out after "
				+ _timeoutMs.ToString(CultureInfo.InvariantCulture) + " ms.");
		}
		catch (Exception ex)
		{
			return LocalSessionListResult.Failed("qwinsta failed to start: "
				+ ex.GetType().Name + " — " + ex.Message);
		}

		if (!tool.Ok)
		{
			return LocalSessionListResult.Failed(string.Format(CultureInfo.InvariantCulture,
				"qwinsta exit {0}: {1}", tool.ExitCode, Truncate(tool.StdErr, 200)));
		}

		IReadOnlyList<QwinstaSessionRow> rows = QwinstaParser.Parse(tool.StdOut);
		IReadOnlyList<RdpSessionDto> dtos = QwinstaSessionMapper.MapAll(rows);
		return LocalSessionListResult.Ok(dtos);
	}

	/// <summary>Adapter that returns the orchestrator-friendly <see cref="LocalSessionFallbackResult"/>
	/// shape so <see cref="RdpSessionFallbackOrchestrator"/> can be wired directly to this provider.</summary>
	public async Task<LocalSessionFallbackResult> FetchForOrchestratorAsync(CancellationToken ct)
	{
		LocalSessionListResult result = await ListAsync(ct).ConfigureAwait(false);
		return result.Success
			? LocalSessionFallbackResult.Ok(result.Sessions)
			: LocalSessionFallbackResult.Failed(result.Error ?? "unknown error");
	}

	private static async Task<LocalSessionToolResult> RunSystemQwinstaAsync(
		IReadOnlyList<string> args,
		CancellationToken ct)
	{
		ProcessStartInfo psi = new("qwinsta.exe")
		{
			UseShellExecute = false,
			CreateNoWindow = true,
			RedirectStandardOutput = true,
			RedirectStandardError = true,
		};
		foreach (string a in args)
		{
			psi.ArgumentList.Add(a);
		}

		using Process? proc = Process.Start(psi);
		if (proc is null)
		{
			throw new Win32Exception("qwinsta.exe failed to start.");
		}

		try
		{
			Task<string> stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
			Task<string> stderrTask = proc.StandardError.ReadToEndAsync(ct);
			await proc.WaitForExitAsync(ct).ConfigureAwait(false);
			string stdout = await stdoutTask.ConfigureAwait(false);
			string stderr = await stderrTask.ConfigureAwait(false);
			return new LocalSessionToolResult(proc.ExitCode, stdout, stderr);
		}
		catch (OperationCanceledException)
		{
			try
			{
				if (!proc.HasExited)
				{
					proc.Kill(entireProcessTree: true);
				}
			}
			catch (InvalidOperationException)
			{
				// Process already exited between the cancellation check and Kill.
			}

			throw;
		}
	}

	private static string Truncate(string? value, int max)
	{
		if (string.IsNullOrEmpty(value))
		{
			return string.Empty;
		}

		string flat = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
		return flat.Length <= max ? flat : flat[..max];
	}
}

/// <summary>Outcome of one external qwinsta invocation. Mirrors the service-side record so the
/// pure parsing path is identical on both sides.</summary>
public sealed record LocalSessionToolResult(int ExitCode, string StdOut, string StdErr)
{
	public bool Ok => ExitCode == 0;
}
