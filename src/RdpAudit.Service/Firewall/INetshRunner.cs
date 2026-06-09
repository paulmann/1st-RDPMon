// File:    src/RdpAudit.Service/Firewall/INetshRunner.cs
// Module:  RdpAudit.Service.Firewall
// Purpose: Indirection for testability — spawns netsh.exe with a sanitised argument vector and
//          captures stdout / stderr / exit code. The production runner spawns the real process;
//          tests substitute an in-memory implementation.
//
//          Parse-stable English console:
//          * Mutating commands ("add rule", "delete rule") use a direct argument-list spawn —
//            their stdout is not parsed and shell wrapping would be an unnecessary widening of
//            the trust surface.
//          * Status / show commands (BuildShowAllProfilesStateArgs / BuildShowRuleArgs) are
//            recognised by the production runner and re-routed through the centralized
//            English-console runner so the parsed tokens ("ON", "Rule Name:", "RemoteIP:")
//            are emitted in stable Latin-script form regardless of the host UI culture.
//          * Tests inject an INetshRunner directly so the routing decision is transparent to
//            the firewall provider — callers always go through INetshRunner.RunAsync.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Firewall;

/// <summary>Outcome of a single netsh invocation.</summary>
/// <param name="ExitCode">Process exit code; 0 indicates success.</param>
/// <param name="StdOut">Captured standard output, never containing secret material.</param>
/// <param name="StdErr">Captured standard error, never containing secret material.</param>
/// <param name="Executable">Resolved executable that ran the command (e.g. <c>netsh.exe</c> or
/// <c>cmd.exe</c> for the English-console wrapper). Empty when not captured by a test runner.</param>
/// <param name="CommandLabel">Stable label of the command line that was run. Empty when not captured.</param>
/// <param name="DurationMs">Wall-clock duration in milliseconds; 0 when not captured.</param>
/// <param name="TimedOut">True when a hard timeout fired and the process was killed.</param>
/// <param name="EnglishConsoleMode">True when the command was routed through the English console wrapper.</param>
public readonly record struct NetshResult(
	int ExitCode,
	string StdOut,
	string StdErr,
	string Executable = "",
	string CommandLabel = "",
	long DurationMs = 0,
	bool TimedOut = false,
	bool EnglishConsoleMode = false)
{
	/// <summary>True when the process exited with code zero.</summary>
	public bool Success => ExitCode == 0;

	/// <summary>Projects this netsh outcome onto the locale-independent backend-attempt record.</summary>
	public BackendCommandAttempt ToBackendAttempt() =>
		new(
			CommandLabel: CommandLabel.Length > 0 ? CommandLabel : "netsh",
			Executable: Executable.Length > 0 ? Executable : "netsh.exe",
			Arguments: string.Empty,
			RunnerMode: EnglishConsoleMode ? BackendRunnerMode.EnglishConsole : BackendRunnerMode.Direct,
			ExitCode: ExitCode,
			TimedOut: TimedOut,
			DurationMs: DurationMs,
			StdoutPreview: BackendCommandAttempt.BuildPreview(StdOut),
			StderrPreview: BackendCommandAttempt.BuildPreview(StdErr),
			ScannerBackend: "NetshText");
}

/// <summary>Indirection for spawning netsh.exe; production runner uses the OS process, tests fake it.</summary>
public interface INetshRunner
{
	/// <summary>Runs netsh with the supplied argument vector and returns the captured stdout / stderr / exit code.</summary>
	Task<NetshResult> RunAsync(IReadOnlyList<string> args, CancellationToken ct);
}

/// <summary>Default <see cref="INetshRunner"/> implementation. Routes the parse-dependent
/// <c>show allprofiles state</c> probe through the English console (so the "ON" / "OFF" tokens
/// match regardless of host locale); other invocations use direct argument-list execution
/// through <see cref="ExternalCommandRunner.RunDirectAsync"/>.</summary>
public sealed class NetshRunner : INetshRunner
{
	private readonly IExternalCommandRunner _runner;
	private readonly TimeSpan _timeout;

	/// <summary>Production constructor — wires the default <see cref="ExternalCommandRunner"/>
	/// and a 15-second hard timeout matching the prior behavior.</summary>
	[SupportedOSPlatform("windows")]
	public NetshRunner()
		: this(new ExternalCommandRunner(), ExternalCommandRunner.DefaultTimeout)
	{
	}

	/// <summary>Test/integration constructor with explicit dependencies.</summary>
	public NetshRunner(IExternalCommandRunner runner, TimeSpan timeout)
	{
		ArgumentNullException.ThrowIfNull(runner);
		_runner = runner;
		_timeout = timeout > TimeSpan.Zero ? timeout : ExternalCommandRunner.DefaultTimeout;
	}

	/// <inheritdoc/>
	[SupportedOSPlatform("windows")]
	public async Task<NetshResult> RunAsync(IReadOnlyList<string> args, CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(args);

		// Recognise the parse-dependent "show allprofiles state" probe and route it through
		// the English-console runner so the "ON"/"OFF" tokens are locale-stable.
		if (IsShowAllProfilesState(args))
		{
			ExternalCommandResult englishConsoleProbe = await _runner
				.RunEnglishConsoleAsync(
					TrustedEnglishConsoleTool.NetshShowAllProfilesState,
					args: null,
					timeout: _timeout,
					ct: ct)
				.ConfigureAwait(false);
			return new NetshResult(
				englishConsoleProbe.TimedOut ? -1 : englishConsoleProbe.ExitCode,
				englishConsoleProbe.StdOut,
				englishConsoleProbe.StdErr,
				Executable: englishConsoleProbe.Executable,
				CommandLabel: englishConsoleProbe.CommandLabel,
				DurationMs: (long)englishConsoleProbe.Duration.TotalMilliseconds,
				TimedOut: englishConsoleProbe.TimedOut,
				EnglishConsoleMode: englishConsoleProbe.EnglishConsoleMode);
		}

		string label = "netsh " + string.Join(' ', args);
		ExternalCommandResult direct = await _runner
			.RunDirectAsync(
				commandLabel: label,
				executable: "netsh.exe",
				arguments: args,
				timeout: _timeout,
				ct: ct)
			.ConfigureAwait(false);
		return new NetshResult(
			direct.TimedOut ? -1 : direct.ExitCode,
			direct.StdOut,
			direct.StdErr,
			Executable: direct.Executable,
			CommandLabel: direct.CommandLabel,
			DurationMs: (long)direct.Duration.TotalMilliseconds,
			TimedOut: direct.TimedOut,
			EnglishConsoleMode: direct.EnglishConsoleMode);
	}

	/// <summary>True when the argument vector matches <see cref="NetshCommandBuilder.BuildShowAllProfilesStateArgs"/>.</summary>
	private static bool IsShowAllProfilesState(IReadOnlyList<string> args)
	{
		IReadOnlyList<string> expected = NetshCommandBuilder.BuildShowAllProfilesStateArgs();
		if (args.Count != expected.Count)
		{
			return false;
		}

		for (int i = 0; i < expected.Count; i++)
		{
			if (!string.Equals(args[i], expected[i], StringComparison.Ordinal))
			{
				return false;
			}
		}

		return true;
	}
}
