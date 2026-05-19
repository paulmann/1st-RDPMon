// File:    src/RdpAudit.Service/Firewall/INetshRunner.cs
// Module:  RdpAudit.Service.Firewall
// Purpose: Indirection for testability — spawns netsh.exe with a sanitised argument vector and
//          captures stdout / stderr / exit code. The production runner spawns the real process;
//          tests substitute an in-memory implementation.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Runtime.Versioning;

namespace RdpAudit.Service.Firewall;

/// <summary>Outcome of a single netsh invocation.</summary>
/// <param name="ExitCode">Process exit code; 0 indicates success.</param>
/// <param name="StdOut">Captured standard output, never containing secret material.</param>
/// <param name="StdErr">Captured standard error, never containing secret material.</param>
public readonly record struct NetshResult(int ExitCode, string StdOut, string StdErr)
{
	/// <summary>True when the process exited with code zero.</summary>
	public bool Success => ExitCode == 0;
}

/// <summary>Indirection for spawning netsh.exe; production runner uses the OS process, tests fake it.</summary>
public interface INetshRunner
{
	/// <summary>Runs netsh with the supplied argument vector and returns the captured stdout / stderr / exit code.</summary>
	Task<NetshResult> RunAsync(IReadOnlyList<string> args, CancellationToken ct);
}

/// <summary>Default <see cref="INetshRunner"/> implementation that spawns netsh.exe via <see cref="ProcessStartInfo.ArgumentList"/>.</summary>
public sealed class NetshRunner : INetshRunner
{
	[SupportedOSPlatform("windows")]
	public async Task<NetshResult> RunAsync(IReadOnlyList<string> args, CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(args);
		ProcessStartInfo psi = new("netsh.exe")
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

		try
		{
			using Process? proc = Process.Start(psi);
			if (proc is null)
			{
				return new NetshResult(-1, string.Empty, "netsh.exe could not start");
			}

			Task<string> stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
			Task<string> stderrTask = proc.StandardError.ReadToEndAsync(ct);
			await proc.WaitForExitAsync(ct).ConfigureAwait(false);
			string stdout = await stdoutTask.ConfigureAwait(false);
			string stderr = await stderrTask.ConfigureAwait(false);
			return new NetshResult(proc.ExitCode, stdout, stderr);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			return new NetshResult(-1, string.Empty, ex.Message);
		}
	}
}
