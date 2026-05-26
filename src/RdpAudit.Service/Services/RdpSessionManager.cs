// File:    src/RdpAudit.Service/Services/RdpSessionManager.cs
// Module:  RdpAudit.Service.Services
// Purpose: Service-side RDP session enumeration and control. Wraps the safe Windows
//          command-line tools used by the Configurator's Remote RDP Clients tab:
//          qwinsta (list), tsdiscon (disconnect) and logoff (terminate). The list path is
//          spawned through the parse-stable English console
//          (cmd.exe /d /c "chcp 437 >nul & qwinsta.exe") so the STATE column carries the
//          stable English tokens (Active / Disc / Conn / Listen) regardless of the host's
//          UI culture. The command line is composed exclusively from SessionConsoleCommandFactory
//          constants — no user input ever flows into it. The destructive tools (tsdiscon /
//          logoff) keep their argument-list spawn since they only carry a validated session id.
//          Output is parsed by the pure RdpAudit.Core QwinstaParser so spawn / parse stages can
//          be unit-tested separately. The service-side path also augments qwinsta from quser so
//          rows with a blank SESSIONNAME (a disconnected user, e.g.) are recovered.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Services;

/// <summary>Outcome of a single external session-control invocation.</summary>
public sealed record SessionToolResult(int ExitCode, string StdOut, string StdErr)
{
	public bool Ok => ExitCode == 0;
}

/// <summary>Service-side RDP session enumeration and control.</summary>
[SupportedOSPlatform("windows")]
public sealed class RdpSessionManager
{
	private readonly ILogger<RdpSessionManager> _logger;

	public RdpSessionManager(ILogger<RdpSessionManager> logger)
	{
		_logger = logger;
	}

	/// <summary>Lists currently known sessions on the local host using <c>qwinsta</c> spawned
	/// through the parse-stable English console (chcp 437). Augments rows with a blank
	/// SESSIONNAME from a parallel <c>quser</c> invocation when possible.</summary>
	public async Task<RdpSessionListDto> ListAsync(CancellationToken ct)
	{
		RdpSessionListDto result = new() { QueriedUtc = DateTime.UtcNow };

		SessionToolResult qwinsta;
		try
		{
			qwinsta = await RunTrustedToolAsync(TrustedSessionTool.Qwinsta, ct).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "qwinsta enumeration failed");
			result.Status = IpcResultStatus.Unavailable;
			result.Message = "qwinsta enumeration failed: " + ex.GetType().Name;
			return result;
		}

		if (!qwinsta.Ok)
		{
			result.Status = IpcResultStatus.Unavailable;
			result.Message = string.Format(CultureInfo.InvariantCulture,
				"qwinsta exit {0}: {1}", qwinsta.ExitCode, Truncate(qwinsta.StdErr, 240));
			return result;
		}

		List<QwinstaSessionRow> rows = new(QwinstaParser.Parse(qwinsta.StdOut));

		int quserAugmented = 0;
		try
		{
			SessionToolResult quser = await RunTrustedToolAsync(TrustedSessionTool.Quser, ct).ConfigureAwait(false);
			if (quser.Ok)
			{
				IReadOnlyList<QuserSessionRow> quserRows = QuserParser.Parse(quser.StdOut);
				quserAugmented = QwinstaQuserMerger.Merge(rows, quserRows).RowsAugmented;
			}
		}
		catch (Exception ex)
		{
			// quser is best-effort — failure to spawn it never aborts the qwinsta listing.
			_logger.LogDebug(ex, "quser augmentation skipped");
		}

		IReadOnlyList<RdpSessionDto> dtos = QwinstaSessionMapper.MapAll(rows);
		foreach (RdpSessionDto dto in dtos)
		{
			result.Sessions.Add(dto);
		}

		result.Message = quserAugmented > 0
			? string.Format(CultureInfo.InvariantCulture,
				"Listed {0} session(s); {1} qwinsta row(s) repaired from quser.",
				result.Sessions.Count, quserAugmented)
			: string.Format(CultureInfo.InvariantCulture,
				"Listed {0} session(s).", result.Sessions.Count);
		return result;
	}

	/// <summary>Issues <c>tsdiscon &lt;sessionId&gt;</c>.</summary>
	public async Task<SessionActionResult> DisconnectAsync(int sessionId, CancellationToken ct)
	{
		SessionIdValidation v = SessionCommandBuilder.ValidateSessionId(sessionId);
		if (!v.Ok)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.InvalidRequest,
				SessionId = sessionId,
				Message = v.Error,
			};
		}

		SessionActionResult outcome = new() { SessionId = sessionId };
		try
		{
			SessionToolResult tool = await RunToolAsync(
				"tsdiscon.exe",
				SessionCommandBuilder.BuildDisconnect(sessionId),
				ct).ConfigureAwait(false);
			outcome.Status = tool.Ok ? IpcResultStatus.Success : IpcResultStatus.Unavailable;
			outcome.Message = tool.Ok
				? string.Format(CultureInfo.InvariantCulture, "Disconnect requested for session {0}.", sessionId)
				: string.Format(CultureInfo.InvariantCulture, "tsdiscon exit {0}: {1}",
					tool.ExitCode, Truncate(tool.StdErr, 240));
			_logger.LogInformation("Disconnect session {Id} exit={Exit}", sessionId, tool.ExitCode);
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "tsdiscon failed for session {Id}", sessionId);
			outcome.Status = IpcResultStatus.Unavailable;
			outcome.Message = "tsdiscon failed: " + ex.GetType().Name;
		}

		return outcome;
	}

	/// <summary>Issues <c>logoff &lt;sessionId&gt;</c>.</summary>
	public async Task<SessionActionResult> LogoffAsync(int sessionId, CancellationToken ct)
	{
		SessionIdValidation v = SessionCommandBuilder.ValidateSessionId(sessionId);
		if (!v.Ok)
		{
			return new SessionActionResult
			{
				Status = IpcResultStatus.InvalidRequest,
				SessionId = sessionId,
				Message = v.Error,
			};
		}

		SessionActionResult outcome = new() { SessionId = sessionId };
		try
		{
			SessionToolResult tool = await RunToolAsync(
				"logoff.exe",
				SessionCommandBuilder.BuildLogoff(sessionId),
				ct).ConfigureAwait(false);
			outcome.Status = tool.Ok ? IpcResultStatus.Success : IpcResultStatus.Unavailable;
			outcome.Message = tool.Ok
				? string.Format(CultureInfo.InvariantCulture, "Logoff requested for session {0}.", sessionId)
				: string.Format(CultureInfo.InvariantCulture, "logoff exit {0}: {1}",
					tool.ExitCode, Truncate(tool.StdErr, 240));
			_logger.LogInformation("Logoff session {Id} exit={Exit}", sessionId, tool.ExitCode);
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "logoff failed for session {Id}", sessionId);
			outcome.Status = IpcResultStatus.Unavailable;
			outcome.Message = "logoff failed: " + ex.GetType().Name;
		}

		return outcome;
	}

	private static async Task<SessionToolResult> RunToolAsync(string tool, IReadOnlyList<string> args, CancellationToken ct)
	{
		System.Text.Encoding encoding = QwinstaConsoleEncoding.Resolve();
		ProcessStartInfo psi = new(tool)
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

		using Process? proc = Process.Start(psi);
		if (proc is null)
		{
			throw new Win32Exception(string.Format(CultureInfo.InvariantCulture, "{0} failed to start.", tool));
		}

		Task<string> stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
		Task<string> stderrTask = proc.StandardError.ReadToEndAsync(ct);
		await proc.WaitForExitAsync(ct).ConfigureAwait(false);
		string stdout = await stdoutTask.ConfigureAwait(false);
		string stderr = await stderrTask.ConfigureAwait(false);
		return new SessionToolResult(proc.ExitCode, stdout, stderr);
	}

	private static async Task<SessionToolResult> RunTrustedToolAsync(TrustedSessionTool tool, CancellationToken ct)
	{
		SessionConsoleSpawn spawn = SessionConsoleCommandFactory.Build(tool);
		System.Text.Encoding encoding = QwinstaConsoleEncoding.Resolve();
		ProcessStartInfo psi = new(spawn.Executable)
		{
			Arguments = spawn.Arguments,
			UseShellExecute = false,
			CreateNoWindow = true,
			RedirectStandardOutput = true,
			RedirectStandardError = true,
			StandardOutputEncoding = encoding,
			StandardErrorEncoding = encoding,
		};

		using Process? proc = Process.Start(psi);
		if (proc is null)
		{
			throw new Win32Exception(string.Format(CultureInfo.InvariantCulture,
				"{0} failed to start via cmd.exe.", tool.ToString().ToLowerInvariant() + ".exe"));
		}

		Task<string> stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
		Task<string> stderrTask = proc.StandardError.ReadToEndAsync(ct);
		await proc.WaitForExitAsync(ct).ConfigureAwait(false);
		string stdout = await stdoutTask.ConfigureAwait(false);
		string stderr = await stderrTask.ConfigureAwait(false);
		return new SessionToolResult(proc.ExitCode, stdout, stderr);
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
