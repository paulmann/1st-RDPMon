// File:    src/RdpAudit.Configurator/Services/ServiceControlRunner.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Async, UI-thread-safe runner for Windows service lifecycle operations
//          used by the Service tab: Start / Stop / Restart / Uninstall, plus a
//          snapshot probe used to populate the "Process" info row. All work
//          happens on the thread pool — never blocks the UI thread. Combines
//          ServiceController.WaitForStatus with sc.exe queryex so the final
//          state and the hosting PID are surfaced in the result returned to UI.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.ServiceProcess;
using System.Text;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Snapshot of the running service process exposed in the Service tab UI.</summary>
public sealed record ServiceProcessInfo(
	bool Installed,
	string FinalState,
	int? ProcessId,
	string? ExecutablePath,
	DateTime? StartTimeUtc,
	string? Detail);

/// <summary>Async runner for the Service tab lifecycle controls. Wraps sc.exe and
/// <see cref="ServiceController"/> with consistent error capture and PID discovery.</summary>
[SupportedOSPlatform("windows")]
public sealed class ServiceControlRunner
{
	private static readonly TimeSpan ControllerWaitTimeout = TimeSpan.FromSeconds(30);

	private readonly string _serviceName;
	private readonly string _displayName;

	public ServiceControlRunner(string serviceName, string displayName)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
		ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
		_serviceName = serviceName;
		_displayName = displayName;
	}

	/// <summary>Best-effort snapshot of the service process used by the Service tab to
	/// populate the "Process" info row on every refresh.</summary>
	public async Task<ServiceProcessInfo> QueryAsync(CancellationToken ct = default)
	{
		return await Task.Run(() => QueryCore(), ct).ConfigureAwait(false);
	}

	private ServiceProcessInfo QueryCore()
	{
		ServiceQueryResult query = RunQueryEx(CancellationToken.None);
		if (!query.Installed)
		{
			return new ServiceProcessInfo(Installed: false, FinalState: "Not installed", ProcessId: null,
				ExecutablePath: null, StartTimeUtc: null, Detail: null);
		}

		string state = query.StateName ?? StateNameFromCode(query.StateCode) ?? "Unknown";
		if (query.ProcessId is null)
		{
			return new ServiceProcessInfo(Installed: true, FinalState: state, ProcessId: null,
				ExecutablePath: null, StartTimeUtc: null, Detail: null);
		}

		(string? exe, DateTime? startUtc, string? detail) = ReadProcessDetails(query.ProcessId.Value);
		return new ServiceProcessInfo(Installed: true, FinalState: state, ProcessId: query.ProcessId,
			ExecutablePath: exe, StartTimeUtc: startUtc, Detail: detail);
	}

	public async Task<ServiceOperationResult> StartAsync(CancellationToken ct = default)
	{
		return await Task.Run(() => RunControllerOperation(
			"Start service",
			ServiceControllerStatus.Running,
			controller => controller.Start(),
			allowAlreadyInTargetState: true,
			ct), ct).ConfigureAwait(false);
	}

	public async Task<ServiceOperationResult> StopAsync(CancellationToken ct = default)
	{
		return await Task.Run(() => RunControllerOperation(
			"Stop service",
			ServiceControllerStatus.Stopped,
			controller =>
			{
				if (controller.CanStop)
				{
					controller.Stop();
				}
			},
			allowAlreadyInTargetState: true,
			ct), ct).ConfigureAwait(false);
	}

	public async Task<ServiceOperationResult> RestartAsync(CancellationToken ct = default)
	{
		return await Task.Run(() => RestartCore(ct), ct).ConfigureAwait(false);
	}

	public async Task<ServiceOperationResult> UninstallAsync(CancellationToken ct = default)
	{
		return await Task.Run(() => UninstallCore(ct), ct).ConfigureAwait(false);
	}

	private ServiceOperationResult RestartCore(CancellationToken ct)
	{
		List<ServiceOperationStep> steps = new();

		StepOutcome stopOutcome = TryControllerOperation("Stop service", ServiceControllerStatus.Stopped,
			controller =>
			{
				if (controller.Status != ServiceControllerStatus.Stopped && controller.CanStop)
				{
					controller.Stop();
				}
			}, allowAlreadyInTargetState: true, allowNotInstalled: false, ct);
		steps.AddRange(stopOutcome.Steps);

		if (stopOutcome.Fatal)
		{
			return Finalize("Restart service", steps);
		}

		StepOutcome startOutcome = TryControllerOperation("Start service", ServiceControllerStatus.Running,
			controller =>
			{
				if (controller.Status != ServiceControllerStatus.Running)
				{
					controller.Start();
				}
			}, allowAlreadyInTargetState: true, allowNotInstalled: false, ct);
		steps.AddRange(startOutcome.Steps);

		return Finalize("Restart service", steps);
	}

	private ServiceOperationResult UninstallCore(CancellationToken ct)
	{
		List<ServiceOperationStep> steps = new();

		// Best-effort stop before delete to avoid the "MARKED_FOR_DELETE" half-state.
		StepOutcome stopOutcome = TryControllerOperation("Stop service before delete", ServiceControllerStatus.Stopped,
			controller =>
			{
				if (controller.Status != ServiceControllerStatus.Stopped && controller.CanStop)
				{
					controller.Stop();
				}
			}, allowAlreadyInTargetState: true, allowNotInstalled: true, ct);
		steps.AddRange(stopOutcome.Steps);

		IReadOnlyList<string> args = ScCommandBuilder.BuildDelete(_serviceName);
		ScRun deleteRun = RunSc(args, ct);
		if (deleteRun.ExitCode == 0)
		{
			steps.Add(new ServiceOperationStep("sc delete", true, deleteRun.CombinedOutput.Length == 0 ? null : deleteRun.CombinedOutput));
		}
		else
		{
			// Treat exit 1060 (service does not exist) as a benign no-op.
			bool benign = deleteRun.CombinedOutput.Contains("1060", StringComparison.Ordinal);
			steps.Add(new ServiceOperationStep("sc delete", benign,
				FormatScDetail(deleteRun.ExitCode, deleteRun.CombinedOutput, args)));
		}

		return Finalize("Uninstall service", steps);
	}

	private ServiceOperationResult RunControllerOperation(
		string description,
		ServiceControllerStatus desired,
		Action<ServiceController> action,
		bool allowAlreadyInTargetState,
		CancellationToken ct)
	{
		StepOutcome outcome = TryControllerOperation(description, desired, action,
			allowAlreadyInTargetState, allowNotInstalled: false, ct);
		return Finalize(description, outcome.Steps);
	}

	private StepOutcome TryControllerOperation(
		string description,
		ServiceControllerStatus desired,
		Action<ServiceController> action,
		bool allowAlreadyInTargetState,
		bool allowNotInstalled,
		CancellationToken ct)
	{
		List<ServiceOperationStep> steps = new();
		try
		{
			using ServiceController controller = new(_serviceName);
			ServiceControllerStatus current = controller.Status; // throws when service not installed
			if (current == desired && allowAlreadyInTargetState)
			{
				steps.Add(new ServiceOperationStep(description, true, $"already {desired}"));
				return new StepOutcome(steps, Fatal: false);
			}

			action(controller);
			controller.WaitForStatus(desired, ControllerWaitTimeout);
			steps.Add(new ServiceOperationStep(description, true, $"final status {desired}"));
			return new StepOutcome(steps, Fatal: false);
		}
		catch (InvalidOperationException ex) when (allowNotInstalled && IsServiceNotInstalled(ex))
		{
			steps.Add(new ServiceOperationStep(description, true, "service is not installed"));
			return new StepOutcome(steps, Fatal: false);
		}
		catch (InvalidOperationException ex) when (IsServiceNotInstalled(ex))
		{
			steps.Add(new ServiceOperationStep(description, false, "Service is not installed."));
			return new StepOutcome(steps, Fatal: true);
		}
		catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
		{
			steps.Add(new ServiceOperationStep(description, false, "UAC was cancelled."));
			return new StepOutcome(steps, Fatal: true);
		}
		catch (System.ServiceProcess.TimeoutException)
		{
			steps.Add(new ServiceOperationStep(description, false,
				$"Timed out waiting {ControllerWaitTimeout.TotalSeconds:0}s for status {desired}."));
			return new StepOutcome(steps, Fatal: true);
		}
		catch (Exception ex)
		{
			steps.Add(new ServiceOperationStep(description, false, ex.Message));
			return new StepOutcome(steps, Fatal: true);
		}
	}

	private ServiceOperationResult Finalize(string action, IReadOnlyList<ServiceOperationStep> steps)
	{
		bool success = true;
		foreach (ServiceOperationStep step in steps)
		{
			if (!step.Ok)
			{
				success = false;
				break;
			}
		}

		ServiceQueryResult query = RunQueryEx(CancellationToken.None);
		string finalState;
		int? pid = null;
		string? exePath = null;
		DateTime? startUtc = null;

		if (!query.Installed)
		{
			finalState = "Not installed";
		}
		else
		{
			finalState = query.StateName ?? StateNameFromCode(query.StateCode) ?? "Unknown";
			if (query.ProcessId is int p)
			{
				pid = p;
				(exePath, startUtc, _) = ReadProcessDetails(p);
			}
		}

		return new ServiceOperationResult(
			Action: action,
			ServiceName: _serviceName,
			DisplayName: _displayName,
			Success: success,
			FinalState: finalState,
			ProcessId: pid,
			ExecutablePath: exePath,
			ProcessStartTimeUtc: startUtc,
			Steps: steps,
			TimestampUtc: DateTime.UtcNow);
	}

	private ServiceQueryResult RunQueryEx(CancellationToken ct)
	{
		IReadOnlyList<string> args = ScCommandBuilder.BuildQueryExtended(_serviceName);
		ScRun run = RunSc(args, ct);
		return ServiceQueryParser.Parse(run.StdOut, run.StdErr);
	}

	private static (string? Exe, DateTime? StartUtc, string? Detail) ReadProcessDetails(int pid)
	{
		try
		{
			using Process proc = Process.GetProcessById(pid);
			if (proc.HasExited)
			{
				return (null, null, "process already exited");
			}

			string? exe = null;
			try
			{
				exe = proc.MainModule?.FileName;
			}
			catch (Win32Exception)
			{
				// MainModule can fail with Access Denied even when running elevated for protected
				// services. The PID alone is still useful, so swallow and continue.
			}
			catch (InvalidOperationException)
			{
				// Process exited between GetProcessById and MainModule access.
			}

			DateTime? startUtc = null;
			try
			{
				startUtc = proc.StartTime.ToUniversalTime();
			}
			catch (Win32Exception)
			{
			}
			catch (InvalidOperationException)
			{
			}

			return (exe, startUtc, null);
		}
		catch (ArgumentException)
		{
			return (null, null, "process exited before details could be read");
		}
		catch (InvalidOperationException ex)
		{
			return (null, null, ex.Message);
		}
		catch (Win32Exception ex)
		{
			return (null, null, ex.Message);
		}
	}

	private static string? StateNameFromCode(int? code) => code switch
	{
		1 => "STOPPED",
		2 => "START_PENDING",
		3 => "STOP_PENDING",
		4 => "RUNNING",
		5 => "CONTINUE_PENDING",
		6 => "PAUSE_PENDING",
		7 => "PAUSED",
		_ => null,
	};

	private static bool IsServiceNotInstalled(InvalidOperationException ex) =>
		ex.InnerException is Win32Exception inner && inner.NativeErrorCode == 1060;

	private static ScRun RunSc(IReadOnlyList<string> args, CancellationToken ct)
	{
		ProcessStartInfo psi = new("sc.exe")
		{
			UseShellExecute = false,
			RedirectStandardError = true,
			RedirectStandardOutput = true,
			CreateNoWindow = true,
		};
		foreach (string a in args)
		{
			psi.ArgumentList.Add(a);
		}

		try
		{
			using Process? p = Process.Start(psi);
			if (p is null)
			{
				return new ScRun(-1, string.Empty, "sc.exe failed to start");
			}

			string outText = p.StandardOutput.ReadToEnd();
			string errText = p.StandardError.ReadToEnd();
			if (!p.WaitForExit(30_000))
			{
				try
				{
					p.Kill(entireProcessTree: true);
				}
				catch (Exception)
				{
					// Best-effort kill; surface the timeout below.
				}

				return new ScRun(-1, outText.Trim(), "sc.exe timed out after 30 seconds");
			}

			ct.ThrowIfCancellationRequested();
			return new ScRun(p.ExitCode, outText.Trim(), errText.Trim());
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			return new ScRun(-1, string.Empty, ex.Message);
		}
	}

	private static string FormatScDetail(int exitCode, string combined, IReadOnlyList<string> args)
	{
		StringBuilder sb = new();
		sb.Append("sc.exe exit ");
		sb.Append(exitCode.ToString(CultureInfo.InvariantCulture));
		if (combined.Length > 0)
		{
			sb.Append(": ");
			sb.Append(combined);
		}

		sb.Append(" [args: sc");
		foreach (string token in args)
		{
			sb.Append(' ');
			if (token.Length == 0 || token.Contains(' ', StringComparison.Ordinal))
			{
				sb.Append('"').Append(token).Append('"');
			}
			else
			{
				sb.Append(token);
			}
		}

		sb.Append(']');
		return sb.ToString();
	}

	private sealed record ScRun(int ExitCode, string StdOut, string StdErr)
	{
		public string CombinedOutput
		{
			get
			{
				if (StdOut.Length == 0)
				{
					return StdErr;
				}

				if (StdErr.Length == 0)
				{
					return StdOut;
				}

				return StdOut + Environment.NewLine + StdErr;
			}
		}
	}

	private sealed record StepOutcome(List<ServiceOperationStep> Steps, bool Fatal);
}
