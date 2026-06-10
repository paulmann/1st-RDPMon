// File:    src/RdpAudit.Service/Workers/IpcServerWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Hosts the named-pipe IPC server with admin-only ACL.
// Extends: Microsoft.Extensions.Hosting.BackgroundService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using MessagePack;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Ipc;
using RdpAudit.Service.Ipc;

namespace RdpAudit.Service.Workers;

/// <summary>Hosts the named-pipe IPC server with admin-only ACL.</summary>
public sealed class IpcServerWorker : BackgroundService
{
	private const int MaxConcurrent = 10;

	private readonly IServiceProvider _services;
	private readonly ILogger<IpcServerWorker> _logger;

	public IpcServerWorker(IServiceProvider services, ILogger<IpcServerWorker> logger)
	{
		_services = services;
		_logger = logger;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(IpcServerWorker));
		if (!OperatingSystem.IsWindows())
		{
			_logger.LogWarning("Named pipe ACL APIs require Windows; IPC disabled on this host.");
			await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken).ConfigureAwait(false);
			return;
		}

		try
		{
			List<Task> connectionTasks = new();
			while (!stoppingToken.IsCancellationRequested)
			{
				try
				{
					NamedPipeServerStream pipe = CreatePipe();
					try
					{
						await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
					}
					catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
					{
						await pipe.DisposeAsync().ConfigureAwait(false);
						break;
					}

					Task task = HandleConnectionAsync(pipe, stoppingToken);
					connectionTasks.Add(task);
					connectionTasks.RemoveAll(t => t.IsCompleted);
					if (connectionTasks.Count > MaxConcurrent)
					{
						_logger.LogWarning("IPC concurrent connection cap exceeded ({Count}); rejecting new ones briefly", connectionTasks.Count);
						await Task.Delay(50, stoppingToken).ConfigureAwait(false);
					}
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					break;
				}
				catch (Exception ex)
				{
					// A fault accepting one connection (pipe creation, ACL, transient OS error) must not
					// take the whole service down — the IPC accept loop is the operator's lifeline to the
					// service. Record it Critical and keep listening after a short backoff. (The original
					// `throw` here was a crash root cause.)
					_logger.LogCritical(ex, "{Worker} accept-loop fault — continuing", nameof(IpcServerWorker));
					await TryLogOperationCriticalAsync(ex, stoppingToken).ConfigureAwait(false);
					try
					{
						await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken).ConfigureAwait(false);
					}
					catch (OperationCanceledException)
					{
						break;
					}
				}
			}
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
		}
		finally
		{
			_logger.LogInformation("{Worker} stopped", nameof(IpcServerWorker));
		}
	}

	/// <summary>Best-effort durable Critical record for an accept-loop fault. Resolves the writer from
	/// the root provider and never throws (the IPC loop must stay alive).</summary>
	private async Task TryLogOperationCriticalAsync(Exception ex, CancellationToken ct)
	{
		try
		{
			RdpAudit.Core.Data.IOperationLogWriter opLog =
				_services.GetRequiredService<RdpAudit.Core.Data.IOperationLogWriter>();
			await opLog.ErrorAsync("Ipc", "AcceptLoopFault",
				"IPC accept-loop fault; server continuing.", ex,
				RdpAudit.Core.Models.OperationLogSeverity.Critical, ct).ConfigureAwait(false);
		}
		catch
		{
			// ignored — logger already captured it; the operation log is best-effort
		}
	}

	[SupportedOSPlatform("windows")]
	private static NamedPipeServerStream CreatePipe()
	{
		PipeSecurity security = new();
		security.AddAccessRule(new PipeAccessRule(
			new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
			PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
			AccessControlType.Allow));
		security.AddAccessRule(new PipeAccessRule(
			new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
			PipeAccessRights.FullControl,
			AccessControlType.Allow));

		return NamedPipeServerStreamAcl.Create(
			IpcConstants.PipeName,
			PipeDirection.InOut,
			MaxConcurrent,
			PipeTransmissionMode.Message,
			PipeOptions.Asynchronous | PipeOptions.WriteThrough,
			inBufferSize: 65_536,
			outBufferSize: 65_536,
			pipeSecurity: security);
	}

	private async Task HandleConnectionAsync(NamedPipeServerStream pipe, CancellationToken ct)
	{
		await using (pipe)
		{
			// Read the request frame first under the short default deadline (a connected client must send
			// promptly), then widen the deadline to the per-command budget before dispatching. This keeps
			// the server and client agreeing on how long a long-running command (firewall repair / verify /
			// Tools Diag) is allowed to take, so the service is not cancelled mid-operation while the client
			// still waits — the historic cause of "service unreachable" right after a Repair.
			using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
			cts.CancelAfter(TimeSpan.FromMilliseconds(IpcConstants.OperationTimeoutMs));
			CancellationToken token = cts.Token;
			try
			{
				byte[] lenBuf = new byte[4];
				await pipe.ReadExactlyAsync(lenBuf, token).ConfigureAwait(false);
				int len = BitConverter.ToInt32(lenBuf);
				if (len <= 0 || len > IpcConstants.MaxFrameBytes)
				{
					_logger.LogWarning("IPC frame size {Len} rejected", len);
					return;
				}

				byte[] body = new byte[len];
				await pipe.ReadExactlyAsync(body, token).ConfigureAwait(false);

				IpcRequest request = MessagePackSerializer.Deserialize<IpcRequest>(body, cancellationToken: token);

				// Extend the deadline to the per-command budget now that the command is known. The Stopwatch
				// already elapsed during the read is negligible against multi-second command budgets.
				int budgetMs = IpcConstants.TimeoutMsFor(request.Command);
				if (budgetMs > IpcConstants.OperationTimeoutMs)
				{
					cts.CancelAfter(TimeSpan.FromMilliseconds(budgetMs));
				}

				using IServiceScope scope = _services.CreateScope();
				IpcDispatcher dispatcher = scope.ServiceProvider.GetRequiredService<IpcDispatcher>();
				IpcResponse response = await dispatcher.DispatchAsync(request, token).ConfigureAwait(false);

				byte[] respBytes = MessagePackSerializer.Serialize(response, cancellationToken: token);
				await pipe.WriteAsync(BitConverter.GetBytes(respBytes.Length), token).ConfigureAwait(false);
				await pipe.WriteAsync(respBytes, token).ConfigureAwait(false);
				await pipe.FlushAsync(token).ConfigureAwait(false);
			}
			catch (OperationCanceledException) when (ct.IsCancellationRequested)
			{
			}
			catch (OperationCanceledException)
			{
				_logger.LogWarning("IPC connection deadline exceeded");
			}
			catch (IOException ex)
			{
				_logger.LogDebug(ex, "IPC client disconnected mid-stream");
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "IPC handler failed");
			}
		}
	}
}
