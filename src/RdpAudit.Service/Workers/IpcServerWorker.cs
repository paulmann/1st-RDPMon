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
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
		}
		catch (Exception ex)
		{
			_logger.LogCritical(ex, "{Worker} unhandled — service will stop", nameof(IpcServerWorker));
			throw;
		}
		finally
		{
			_logger.LogInformation("{Worker} stopped", nameof(IpcServerWorker));
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
			try
			{
				byte[] lenBuf = new byte[4];
				await pipe.ReadExactlyAsync(lenBuf, ct).ConfigureAwait(false);
				int len = BitConverter.ToInt32(lenBuf);
				if (len <= 0 || len > IpcConstants.MaxFrameBytes)
				{
					_logger.LogWarning("IPC frame size {Len} rejected", len);
					return;
				}

				byte[] body = new byte[len];
				await pipe.ReadExactlyAsync(body, ct).ConfigureAwait(false);

				IpcRequest request = MessagePackSerializer.Deserialize<IpcRequest>(body, cancellationToken: ct);
				using IServiceScope scope = _services.CreateScope();
				IpcDispatcher dispatcher = scope.ServiceProvider.GetRequiredService<IpcDispatcher>();
				IpcResponse response = await dispatcher.DispatchAsync(request, ct).ConfigureAwait(false);

				byte[] respBytes = MessagePackSerializer.Serialize(response, cancellationToken: ct);
				await pipe.WriteAsync(BitConverter.GetBytes(respBytes.Length), ct).ConfigureAwait(false);
				await pipe.WriteAsync(respBytes, ct).ConfigureAwait(false);
				await pipe.FlushAsync(ct).ConfigureAwait(false);
			}
			catch (OperationCanceledException) when (ct.IsCancellationRequested)
			{
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
