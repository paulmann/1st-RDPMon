// File:    src/RdpAudit.Configurator/Ipc/IpcClient.cs
// Module:  RdpAudit.Configurator.Ipc
// Purpose: Async named-pipe IPC client with hard timeouts; returns null on timeout / IO failure.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.IO.Pipes;
using System.Text.Json;
using MessagePack;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Ipc;

/// <summary>Async named-pipe IPC client with hard timeouts.</summary>
public sealed class IpcClient
{
	public async Task<T?> SendAsync<T>(IpcCommand command, object? payload = null, CancellationToken ct = default)
	{
		using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
		cts.CancelAfter(TimeSpan.FromMilliseconds(IpcConstants.OperationTimeoutMs));

		try
		{
			await using NamedPipeClientStream pipe = new(".", IpcConstants.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
			await pipe.ConnectAsync(IpcConstants.ConnectTimeoutMs, cts.Token).ConfigureAwait(false);

			IpcRequest request = new()
			{
				Command = command,
				Payload = payload is null ? null : JsonSerializer.Serialize(payload, JsonOptions.Default),
			};

			byte[] reqBytes = MessagePackSerializer.Serialize(request, cancellationToken: cts.Token);
			await pipe.WriteAsync(BitConverter.GetBytes(reqBytes.Length), cts.Token).ConfigureAwait(false);
			await pipe.WriteAsync(reqBytes, cts.Token).ConfigureAwait(false);
			await pipe.FlushAsync(cts.Token).ConfigureAwait(false);

			byte[] lenBuf = new byte[4];
			await pipe.ReadExactlyAsync(lenBuf, cts.Token).ConfigureAwait(false);
			int len = BitConverter.ToInt32(lenBuf);
			if (len <= 0 || len > IpcConstants.MaxFrameBytes)
			{
				return default;
			}

			byte[] respBytes = new byte[len];
			await pipe.ReadExactlyAsync(respBytes, cts.Token).ConfigureAwait(false);

			IpcResponse response = MessagePackSerializer.Deserialize<IpcResponse>(respBytes, cancellationToken: cts.Token);
			if (!response.Success || response.Payload is null)
			{
				return default;
			}

			return JsonSerializer.Deserialize<T>(response.Payload, JsonOptions.Default);
		}
		catch (OperationCanceledException)
		{
			return default;
		}
		catch (TimeoutException)
		{
			return default;
		}
		catch (IOException)
		{
			return default;
		}
	}

	public async Task<bool> PingAsync(CancellationToken ct = default)
	{
		string? response = await SendAsync<string>(IpcCommand.Ping, null, ct).ConfigureAwait(false);
		return response is not null;
	}
}
