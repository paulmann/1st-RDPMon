# Named-pipe IPC

The Service hosts a Windows named pipe (`\\.\pipe\RdpAuditService`) restricted to the BUILTIN\Administrators SID and LocalSystem.

## Wire format

```
[ uint32 LE  body length ]
[ MessagePack body — IpcRequest / IpcResponse ]
```

`IpcRequest.Payload` and `IpcResponse.Payload` carry a JSON string serialized with `JsonOptions.Default`. This two-tier scheme keeps the MessagePack frame small and lets the service dispatch on `IpcCommand` without having to know every payload type at compile time.

## Commands

Existing commands (Stage 0):

| Command | Ordinal | Direction | Payload (JSON) | Returns |
|---------|---------|-----------|----------------|---------|
| `Ping` | 0 | C→S | – | `"pong"` |
| `GetStatus` | 1 | C→S | – | `ServiceStatus` |
| `GetRecentEvents` | 2 | C→S | – | `RawEvent[]` |
| `GetRecentAlerts` | 3 | C→S | – | `Alert[]` |
| `GetAddresses` | 4 | C→S | – | `Address[]` |
| `GetSessions` | 5 | C→S | – | `Session[]` |
| `AcknowledgeAlert` | 6 | C→S | `long` (Alert id) | `true` |
| `BlockAddress` | 7 | C→S | `string` (IP) | `true` |
| `UnblockAddress` | 8 | C→S | `string` (IP) | `true` |
| `GetSettings` | 9 | C→S | – | `RdpAuditOptions` |
| `SaveSettings` | 10 | C→S | JSON document | `{ saved: true }` |

Stage 1 reservations (handlers return a stable `NotImplemented` payload until later stages):

| Command | Ordinal | Direction | Payload | Returns |
|---------|---------|-----------|---------|---------|
| `GetFirewallStatus` | 11 | C→S | – | `FirewallStatusDto` |
| `ListBlocklist` | 12 | C→S | – | `AddressListEntryDto[]` |
| `ListWhitelist` | 13 | C→S | – | `AddressListEntryDto[]` |
| `AddToBlocklist` | 14 | C→S | `AddressListMutationRequest` | `IpcResultStatus` |
| `RemoveFromBlocklist` | 15 | C→S | `AddressListMutationRequest` | `IpcResultStatus` |
| `AddToWhitelist` | 16 | C→S | `AddressListMutationRequest` | `IpcResultStatus` |
| `RemoveFromWhitelist` | 17 | C→S | `AddressListMutationRequest` | `IpcResultStatus` |
| `GetAttackStats` | 18 | C→S | – | `AttackStatsDto` |
| `ListRdpSessions` | 19 | C→S | – | `RdpSessionDto[]` |
| `DisconnectSession` | 20 | C→S | `SessionActionRequest` | `SessionActionResult` |
| `LogoffSession` | 21 | C→S | `SessionActionRequest` | `SessionActionResult` |
| `ShadowSession` | 22 | C→S | `SessionActionRequest` | `SessionActionResult` |
| `GetShadowPolicyStatus` | 23 | C→S | – | `ShadowPolicyStatusDto` |
| `ApplyShadowPolicy` | 24 | C→S | – | `ShadowPolicyStatusDto` |
| `BackupShadowPolicy` | 25 | C→S | – | `ShadowPolicyStatusDto` |
| `RestoreShadowPolicy` | 26 | C→S | – | `ShadowPolicyStatusDto` |
| `GetAbuseIpDbStatus` | 27 | C→S | – | `ProviderStatusDto` |
| `TestAbuseIpDbKey` | 28 | C→S | – | `ProviderTestResult` |
| `GetMikroTikStatus` | 29 | C→S | – | `ProviderStatusDto` |
| `TestMikroTik` | 30 | C→S | – | `ProviderTestResult` |
| `ListActiveBlocks` | 31 | C→S | – | `FirewallBlockEntry[]` |

Reserved-but-not-implemented commands receive an `IpcResponse` with `Success = true` and a payload of the shape `{ "status": "NotImplemented", "command": "...", "message": "..." }`. Clients MUST treat unknown status discriminators conservatively and surface them as "feature not available in this build".

## DTO contracts

All Stage 1 DTOs live under `RdpAudit.Core.Ipc.Contracts.*` with explicit `[MessagePackObject]` and integer `[Key]` annotations. `Key` indices are append-only — never reuse a retired index. The `IpcResultStatus` discriminator is also append-only.

## LLM contract

* The IPC client (`Configurator/Ipc/IpcClient.cs`) **must** swallow `TimeoutException` / `IOException` and return `default`. Never propagate to the UI thread.
* `IpcCommand` enum values are an append-only ABI. Never reuse a retired value.
* Every new command must be:
  1. added to `IpcCommand` at the next free ordinal,
  2. documented here with a payload + return shape,
  3. handled in `IpcDispatcher.DispatchAsync` (Service) — even if the initial handler is a `NotImplemented` stub,
  4. consumed by the Configurator through `IpcClient.SendAsync<T>`.
* DTO `[Key]` indices are append-only. To remove a field, mark it `[Obsolete]` but keep the slot reserved.
* IPC responses MUST NOT contain secret material (API keys, passwords, envelope payloads).
* IPC handlers MUST honour the supplied `CancellationToken` — no `.Result` / `.Wait()`.

## Required tests before modifying

* Manual: restart service, point Configurator at it, walk every tab, confirm round-trip.
* Automated: `IpcCommandStabilityTests` (Core.Tests) — fails if any ordinal is reused or renumbered. Add a fakes-based dispatcher test if you change `IpcDispatcher`.
