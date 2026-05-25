// File:    src/RdpAudit.Configurator/Services/LocalRdpSessionProvider.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Configurator-side direct enumeration of local RDP sessions for the Remote RDP
//          Clients tab when the RdpAudit service IPC pipe is unreachable. Mirrors the
//          service-side RdpSessionManager behaviour: spawns the supported Windows
//          command-line tool (qwinsta.exe), reads its column output through the pure
//          RdpAudit.Core QwinstaParser, and projects every parsed row into the existing
//          RdpSessionDto contract.
//
//          The provider now follows the same stable-output technique used in the
//          reference qwinsta_IP_PS7.ps1 script:
//            * pin the spawning thread's CurrentCulture/CurrentUICulture to en-US so
//              localised .NET callers do not bias child-process resource lookups;
//            * inject LANG=en-US and LC_ALL=en-US into the child process environment;
//            * resolve qwinsta.exe through the System32 absolute path (with a PATH
//              fallback) so a malformed PATH cannot pick up a substitute binary;
//            * capture stdout with the current OEM/console code page so the Cyrillic
//              tokens emitted by Russian-language Windows builds are preserved when the
//              English forcing has no effect — the header-agnostic parser then handles
//              both flavours.
//          ProcessStartInfo.ArgumentList is used so no user-supplied data is ever
//          concatenated into a shell string. A hard timeout kills the process tree so
//          a hung qwinsta cannot freeze the UI worker. Read-only — never spawns
//          tsdiscon/logoff/mstsc.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using System.Threading;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Indicates how the parsed qwinsta output was sourced and which language was
/// observed in the stdout stream. Surfaced to the orchestrator/UI so the operator can
/// tell whether the stable English/Latin path or the Cyrillic-tolerant fallback was
/// taken.</summary>
public enum LocalSessionOutputFlavour
{
	/// <summary>Output could not be parsed at all (no data rows).</summary>
	Unknown = 0,

	/// <summary>Output contained English column markers (e.g. SESSIONNAME / STATE).</summary>
	EnglishStable = 1,

	/// <summary>Output contained Cyrillic markers — the English forcing did not take.</summary>
	CyrillicFallback = 2,

	/// <summary>Output parsed cleanly but the language could not be classified.</summary>
	NeutralStable = 3,
}

/// <summary>Outcome of a local <see cref="LocalRdpSessionProvider.ListAsync"/> call.</summary>
public sealed record LocalSessionListResult(
	bool Success,
	IReadOnlyList<RdpSessionDto> Sessions,
	string? Error,
	LocalSessionOutputFlavour Flavour)
{
	/// <summary>Convenience factory for a successful listing.</summary>
	public static LocalSessionListResult Ok(IReadOnlyList<RdpSessionDto> sessions, LocalSessionOutputFlavour flavour) =>
		new(true, sessions, null, flavour);

	/// <summary>Convenience factory for a failed listing.</summary>
	public static LocalSessionListResult Failed(string error) =>
		new(false, Array.Empty<RdpSessionDto>(), error, LocalSessionOutputFlavour.Unknown);
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
		LocalSessionOutputFlavour flavour = ClassifyOutputFlavour(tool.StdOut, rows.Count);
		return LocalSessionListResult.Ok(dtos, flavour);
	}

	/// <summary>Adapter that returns the orchestrator-friendly <see cref="LocalSessionFallbackResult"/>
	/// shape so <see cref="RdpSessionFallbackOrchestrator"/> can be wired directly to this provider.</summary>
	public async Task<LocalSessionFallbackResult> FetchForOrchestratorAsync(CancellationToken ct)
	{
		LocalSessionListResult result = await ListAsync(ct).ConfigureAwait(false);
		if (!result.Success)
		{
			return LocalSessionFallbackResult.Failed(result.Error ?? "unknown error");
		}

		string detail = DescribeFlavour(result.Flavour);
		return LocalSessionFallbackResult.Ok(result.Sessions, detail);
	}

	/// <summary>Inspects the raw stdout for language markers so the UI can tell whether
	/// the stable English forcing took effect or the parser had to fall back to the
	/// localized Cyrillic tokens.</summary>
	internal static LocalSessionOutputFlavour ClassifyOutputFlavour(string stdOut, int parsedRowCount)
	{
		if (parsedRowCount == 0)
		{
			return LocalSessionOutputFlavour.Unknown;
		}

		if (string.IsNullOrEmpty(stdOut))
		{
			return LocalSessionOutputFlavour.NeutralStable;
		}

		string upper = stdOut.ToUpperInvariant();
		bool englishHeader = upper.Contains("SESSIONNAME", StringComparison.Ordinal)
			|| upper.Contains("USERNAME", StringComparison.Ordinal)
			|| upper.Contains("STATE", StringComparison.Ordinal);
		if (englishHeader)
		{
			return LocalSessionOutputFlavour.EnglishStable;
		}

		// Cyrillic markers — qwinsta header tokens and the state tokens themselves.
		foreach (string marker in CyrillicMarkers)
		{
			if (stdOut.Contains(marker, StringComparison.OrdinalIgnoreCase))
			{
				return LocalSessionOutputFlavour.CyrillicFallback;
			}
		}

		return LocalSessionOutputFlavour.NeutralStable;
	}

	private static readonly string[] CyrillicMarkers = new[]
	{
		"СЕАНС",
		"ПОЛЬЗОВАТЕЛЬ",
		"СТАТУС",
		"Активно",
		"Подключено",
		"Диск",
		"Отключено",
		"Прием",
		"Приём",
	};

	private static string DescribeFlavour(LocalSessionOutputFlavour flavour) => flavour switch
	{
		LocalSessionOutputFlavour.EnglishStable => "stable English qwinsta output",
		LocalSessionOutputFlavour.CyrillicFallback => "localized qwinsta output (Cyrillic-tolerant parse)",
		LocalSessionOutputFlavour.NeutralStable => "qwinsta output parsed (language-neutral)",
		_ => "qwinsta output not classified",
	};

	private static async Task<LocalSessionToolResult> RunSystemQwinstaAsync(
		IReadOnlyList<string> args,
		CancellationToken ct)
	{
		string exe = ResolveQwinstaPath();
		Encoding encoding = QwinstaConsoleEncoding.Resolve();
		ProcessStartInfo psi = new(exe)
		{
			UseShellExecute = false,
			CreateNoWindow = true,
			RedirectStandardOutput = true,
			RedirectStandardError = true,
			StandardOutputEncoding = encoding,
			StandardErrorEncoding = encoding,
		};
		foreach (string a in args)
		{
			psi.ArgumentList.Add(a);
		}

		// Mirror the reference qwinsta_IP_PS7.ps1 technique: push en-US into the child
		// process environment so any locale-driven message lookups prefer English. Real
		// qwinsta does not honour LANG/LC_ALL on its own — the variables are propagated
		// for the benefit of any wrapping locale layers and to keep behaviour aligned
		// with the reference script. The header-agnostic parser tolerates both flavours.
		psi.EnvironmentVariables["LANG"] = "en-US";
		psi.EnvironmentVariables["LC_ALL"] = "en-US";

		CultureInfo originalCulture = Thread.CurrentThread.CurrentCulture;
		CultureInfo originalUiCulture = Thread.CurrentThread.CurrentUICulture;
		Thread.CurrentThread.CurrentCulture = CultureInfo.GetCultureInfo("en-US");
		Thread.CurrentThread.CurrentUICulture = CultureInfo.GetCultureInfo("en-US");

		try
		{
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
		finally
		{
			Thread.CurrentThread.CurrentCulture = originalCulture;
			Thread.CurrentThread.CurrentUICulture = originalUiCulture;
		}
	}

	/// <summary>Returns the absolute path to <c>%WINDIR%\System32\qwinsta.exe</c>. Falls
	/// back to the bare command name (PATH lookup) when the System32 directory cannot be
	/// resolved — Process.Start will then surface the diagnostic.</summary>
	internal static string ResolveQwinstaPath()
	{
		string sys32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
		if (!string.IsNullOrEmpty(sys32))
		{
			string candidate = System.IO.Path.Combine(sys32, "qwinsta.exe");
			if (System.IO.File.Exists(candidate))
			{
				return candidate;
			}
		}

		return "qwinsta.exe";
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
