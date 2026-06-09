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

/// <summary>
/// Outcome of a raw IPC round-trip. Unlike <see cref="IpcClient.SendAsync{T}"/> (which collapses
/// every failure to <c>default</c>), this preserves the service-supplied <see cref="Error"/> so the
/// caller can surface a precise status message instead of a bare "FAILED".
/// </summary>
/// <param name="Success">True when the service reported success.</param>
/// <param name="Error">Curated error text from the service, or a transport-failure description.</param>
/// <param name="Payload">Raw JSON payload when present.</param>
public readonly record struct IpcRawResult(bool Success, string? Error, string? Payload);

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

	/// <summary>
	/// Sends <paramref name="command"/> and returns the full service result (success flag, curated
	/// error text, raw payload). Transport failures are mapped to a non-success result with a
	/// descriptive error rather than being swallowed, so callers can show why a mutation failed.
	/// </summary>
	public async Task<IpcRawResult> SendRawAsync(IpcCommand command, object? payload = null, CancellationToken ct = default)
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
				return new IpcRawResult(false, "Service returned an empty or oversized response frame.", null);
			}

			byte[] respBytes = new byte[len];
			await pipe.ReadExactlyAsync(respBytes, cts.Token).ConfigureAwait(false);

			IpcResponse response = MessagePackSerializer.Deserialize<IpcResponse>(respBytes, cancellationToken: cts.Token);
			return new IpcRawResult(response.Success, response.Error, response.Payload);
		}
		catch (OperationCanceledException)
		{
			return new IpcRawResult(false, "Request timed out before the service responded.", null);
		}
		catch (TimeoutException)
		{
			return new IpcRawResult(false, "Timed out connecting to the service named pipe.", null);
		}
		catch (IOException ex)
		{
			return new IpcRawResult(false, "IPC transport error: " + ex.Message, null);
		}
	}

	public async Task<bool> PingAsync(CancellationToken ct = default)
	{
		string? response = await SendAsync<string>(IpcCommand.Ping, null, ct).ConfigureAwait(false);
		return response is not null;
	}
}
