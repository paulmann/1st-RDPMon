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

Stage 3 implemented commands (backend-only — Configurator UI lands in a later stage):

| Command | Ordinal | Direction | Payload | Returns |
|---------|---------|-----------|---------|---------|
| `GetFirewallStatus` | 11 | C→S | – | `FirewallStatusDto` |
| `ListBlocklist` | 12 | C→S | – | `AddressListEntryDto[]` |
| `ListWhitelist` | 13 | C→S | – | `AddressListEntryDto[]` |
| `AddToBlocklist` | 14 | C→S | `AddressListMutationRequest` | `{ status, address }` |
| `RemoveFromBlocklist` | 15 | C→S | `AddressListMutationRequest` | `{ status, address, removed }` |
| `AddToWhitelist` | 16 | C→S | `AddressListMutationRequest` | `{ status, address }` |
| `RemoveFromWhitelist` | 17 | C→S | `AddressListMutationRequest` | `{ status, address, removed }` |
| `ListActiveBlocks` | 31 | C→S | – | `AddressListEntryDto[]` |

Stage 5 implemented commands (Firewall tab in the Configurator drives these):

| Command | Ordinal | Direction | Payload | Returns |
|---------|---------|-----------|---------|---------|
| `ListLoginRules` | 32 | C→S | – | `LoginRuleDto[]` |
| `AddLoginRule` | 33 | C→S | `LoginRuleMutationRequest` | `{ status, login }` |
| `RemoveLoginRule` | 34 | C→S | `LoginRuleMutationRequest` | `{ status, id, login }` |
| `SetLoginRuleEnabled` | 35 | C→S | `LoginRuleMutationRequest` | `{ status, id, enabled }` |
| `ListActiveBlocksDetailed` | 36 | C→S | – | `ActiveBlockDto[]` |
| `UnblockActiveBlock` | 37 | C→S | `long` (ActiveBlock id) | `{ status, id, address, providerOk, providerError, blocklistDisabled }` |

Stage 5 IPC semantics:

* `AddLoginRule` normalises the supplied login (trim + lower-case invariant) and rejects empty / control-character input. Adding an already-present login re-enables it (`Enabled = true`) and updates the operator note when supplied; this keeps re-adds idempotent.
* `RemoveLoginRule` prefers the supplied `Id` and falls back to a normalised `Login` lookup. Removing a missing rule returns a controlled `IpcException` ("Login rule not found.").
* `SetLoginRuleEnabled` requires a positive `Id` and writes the `Enabled` flag verbatim; it never creates a row.
* `ListActiveBlocksDetailed` returns the full `ActiveBlocks` row shape (`Id`, `Ip`, `Provider`, `RuleHandle`, `CreatedUtc`, `ExpiresUtc`, `Reason`, `Status`, `LastError`). Use this when the UI needs the structured fields; the legacy `ListActiveBlocks` keeps returning the flat `AddressListEntryDto[]` for backward compatibility.
* `UnblockActiveBlock` accepts the `ActiveBlock.Id` as the payload, calls `FirewallManager.UnblockAsync` for Windows-provider rows on Windows hosts, soft-disables any matching `BlocklistEntries` rows, and flips the row to `Removed` (or `Failed` with `LastError` on provider error). Rows whose provider is `None` (audit-only) skip the provider call. The handler returns `IpcResultStatus.Unavailable` when the provider call failed but the bookkeeping is still recorded.
* All Stage 5 writes flow through the service's `AuditDbContext` via EF Core; the Configurator never opens the SQLite database for writes.

Stage 3 IPC semantics:

* Every mutation handler validates the supplied address with `IPAddress.TryParse` and refuses non-IP input with a controlled `IpcException` message (no raw exceptions surface to the client).
* `AddToBlocklist` refuses an address that already has a `WhitelistEntries` row. Whitelist precedence is enforced server-side, not by the Configurator.
* `AddToWhitelist` soft-disables any conflicting `BlocklistEntries` rows (`IsEnabled = false`) so the whitelist always wins.
* `RemoveFromBlocklist` is a soft-disable that sets `IsEnabled = false` and retains the row for audit. `RemoveFromWhitelist` is a hard delete.
* `ListActiveBlocks` returns `AddressListEntryDto` records whose `Source` field encodes `Provider:Status` (e.g. `Windows:Active`). `Note` carries the audit reason and any provider error.
* All writes go through the service's `AuditDbContext` via EF Core parameterised APIs; the Configurator never opens the SQLite database for writes.

Stage 6A implemented commands (backend aggregation + IPC; the Configurator Attack Statistics tab is delivered in Stage 6B and is the consumer of this command):

| Command | Ordinal | Direction | Payload | Returns |
|---------|---------|-----------|---------|---------|
| `GetAttackStats` | 18 | C→S | `AttackStatsRequest` (optional) | `AttackStatsDto` (includes `Entries`, `TotalMatching`, `AppliedLimit`; see `docs/46-attack-statistics.md`) |

Reserved Stage 1 commands still pending later stages:

| Command | Ordinal | Direction | Payload | Returns |
|---------|---------|-----------|---------|---------|
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

## Stage 6A — Attack Statistics IPC (this branch)

`GetAttackStats` (ordinal `18`) was a Stage 1 reservation and is implemented in Stage 6A. The
Configurator UI tab that consumes it lands in Stage 6B; until then, the command is exercised by
the Service unit tests and any future operator tooling that speaks the IPC ABI directly. The
payload is optional `AttackStatsRequest` JSON:

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `IpQuery` | `string?` | `null` | Case-insensitive substring match against `AttackStat.Ip`. |
| `MinThreatScore` | `double?` | `null` | Inclusive lower bound on `ThreatScore`. |
| `OnlyBlocked` | `bool` | `false` | When `true`, only rows where `IsBlocked == true` are returned. |
| `SinceUtc` / `UntilUtc` | `DateTime?` | last 7 days / now | Inclusive `LastSeenUtc` window. |
| `Limit` | `int` | `500` | Clamped server-side to `[1..2000]`. Zero falls back to the default. |

The response is the existing `AttackStatsDto` extended with append-only fields:

| Key | Field | Stage |
|-----|-------|-------|
| 0..8 | `Status`, `WindowStartUtc`, `WindowEndUtc`, `FailedLogons`, `SuccessfulLogons`, `DistinctSourceIps`, `AlertsRaised`, `AddressesAutoBlocked`, `Message` | Stage 1 reservation. |
| 9 | `Entries: List<AttackStatEntryDto>` | Stage 6A. |
| 10 | `TotalMatching: int` | Stage 6A. Total rows matching the filter before the limit. |
| 11 | `AppliedLimit: int` | Stage 6A. The clamped limit the server actually used. |

`AttackStatEntryDto` is a new contract under `RdpAudit.Core.Ipc.Contracts` with explicit
`[MessagePackObject]` + integer `[Key]` indices (`0..12`). All new MessagePack keys land at the end
of the existing schema — Stage 6A introduces zero ordinal renumbering.

Rows are returned ordered by descending `LastSeenUtc`, descending `ThreatScore`, ascending `Ip`.
Threat scoring / classification semantics are defined in `docs/46-attack-statistics.md`. Error
paths (malformed JSON payload, internal exceptions) surface as a controlled `IpcResponse` with
`Success = false` and a sanitised `Error` string — never a raw exception message or stack trace.
