# Named-pipe IPC

The Service hosts a Windows named pipe (`\\.\pipe\RdpAuditService`) restricted to the BUILTIN\Administrators SID and LocalSystem.

## Wire format

```
[ uint32 LE  body length ]
[ MessagePack body — IpcRequest / IpcResponse ]
```

`IpcRequest.Payload` and `IpcResponse.Payload` carry a JSON string serialized with `JsonOptions.Default`. This two-tier scheme keeps the MessagePack frame small and lets the service dispatch on `IpcCommand` without having to know every payload type at compile time.

## Commands

| Command | Direction | Payload (JSON) | Returns |
|---------|-----------|----------------|---------|
| `Ping` | C→S | – | `"pong"` |
| `GetStatus` | C→S | – | `ServiceStatus` |
| `GetRecentEvents` | C→S | – | `RawEvent[]` |
| `GetRecentAlerts` | C→S | – | `Alert[]` |
| `GetAddresses` | C→S | – | `Address[]` |
| `GetSessions` | C→S | – | `Session[]` |
| `AcknowledgeAlert` | C→S | `long` (Alert id) | `true` |
| `BlockAddress` | C→S | `string` (IP) | `true` |
| `UnblockAddress` | C→S | `string` (IP) | `true` |
| `GetSettings` | C→S | – | `RdpAuditOptions` |
| `SaveSettings` | C→S | – | not implemented at runtime — Configurator writes appsettings.json directly and `IOptionsMonitor<T>` reloads. |

## LLM contract

- The IPC client (`Configurator/Ipc/IpcClient.cs`) **must** swallow `TimeoutException` / `IOException` and return `default`. Never propagate to the UI thread.
- `IpcCommand` enum values are an append-only ABI. Never reuse a retired value.
- Every new command must be implemented in both `IpcDispatcher.DispatchAsync` (Service) and consumed by the UI through `IpcClient.SendAsync<T>`.

## Required tests before modifying

- Manual: restart service, point Configurator at it, walk every tab, confirm round-trip.
- Automated: Service-side ping handler test (planned). Add a fakes-based dispatcher test if you change `IpcDispatcher`.
