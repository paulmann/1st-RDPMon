# RdpAudit configuration (options)

This document covers the `RdpAudit` section of `%ProgramData%\RdpAudit\appsettings.json`. The file is hot-reloaded by `IOptionsMonitor<RdpAuditOptions>` whenever it changes on disk.

## Top-level sections

| Section | Type | Purpose |
|---------|------|---------|
| `Monitoring` | `MonitoringOptions` | Event collection toggles and batching. |
| `Alerts` | `AlertOptions` | Detection rule thresholds, business hours, whitelists. |
| `Firewall` | `FirewallOptions` | Auto-block, provider selection, static block / allow lists. |
| `Storage` | `StorageOptions` | Database path and retention windows. |
| `Diagnostics` | `DiagnosticsOptions` | Debug-only switches. |
| `AbuseIpDb` | `AbuseIpDbOptions` | AbuseIPDB external reputation / reporting integration. |
| `MikroTik` | `MikroTikOptions` | MikroTik RouterOS external firewall integration. |
| `SessionControl` | `SessionControlOptions` | Disconnect / log-off / shadow policy switches. |

## FirewallOptions

Backward-compatible with pre-Stage-1 deployments — new fields default to safe values.

| Field | Default | Meaning |
|-------|---------|---------|
| `AutoBlockBruteForce` | `false` | Enables the brute-force auto-block worker. |
| `AutoBlockThreshold` | `50` | Failures from one IP that trigger an auto-block. |
| `BlockRuleName` | `"RdpAudit-Block"` | Base name used to construct per-IP firewall rules. |
| `Provider` | `"Windows"` | One of `None`, `Windows`, `MikroTik`, `Both`. |
| `Whitelist` | `[]` | CIDR / IP entries that must NEVER be auto-blocked. |
| `Blacklist` | `[]` | CIDR / IP entries always treated as hostile. |
| `BlockOnBlacklistedLogin` | `false` | Block immediately on any successful logon from a blacklisted IP. |
| `InstantBlockLogins` | `[]` | User names (e.g. `guest`, `admin`) whose successful logon triggers an immediate block of the source IP. |
| `DefaultBlockDurationMinutes` | `0` | `0` or negative means permanent until manually removed. |
| `MaxActiveBlocks` | `10000` | Guardrail against rule-table flooding. |
| `WhitelistIps` | `[]` | Flat list of literal IPs in addition to `Whitelist` (CIDR entries). Consumed by the auto-block worker. |
| `RefusePrivateAddressBlock` | `true` | Windows provider refuses to block loopback / RFC1918 / multicast / link-local addresses. |
| `AutoBlockDebounceSeconds` | `60` | Per-IP debounce window applied by the auto-block worker to avoid block storms. |

## AbuseIpDbOptions

The `ApiKey` field is stored as a protected envelope (see "Secret protection"). The Service unwraps it through `ISecretProtector` only when a request is actually made — the plaintext never appears in IPC responses, logs, or status DTOs.

| Field | Default | Meaning |
|-------|---------|---------|
| `Enabled` | `false` | Master switch for the integration. |
| `ApiKey` | `""` | Protected envelope holding the AbuseIPDB API key. |
| `BaseUrl` | `"https://api.abuseipdb.com"` | Override for on-premises proxies. |
| `TimeoutSeconds` | `15` | HTTP timeout. |
| `MaxReportsPerMinute` | `60` | Client-side rate limit. |
| `CacheLookups` | `true` | Cache reputation lookups on disk. |
| `CacheTtlMinutes` | `60` | Cache TTL. |
| `ReportThreshold` | `80` | Abuse confidence (0..100) at which an IP is treated as hostile. |
| `ReportCategories` | `[18, 22]` | Categories submitted with each report. |

## MikroTikOptions

The `Password` field is stored as a protected envelope. Plaintext is unwrapped only at HTTP-send time and discarded immediately.

| Field | Default | Meaning |
|-------|---------|---------|
| `Enabled` | `false` | Master switch. |
| `BaseUrl` | `""` | RouterOS REST endpoint (`https://10.0.0.1`). |
| `UserName` | `""` | REST API user. |
| `Password` | `""` | Protected envelope holding the REST password. |
| `TimeoutSeconds` | `15` | HTTP timeout. |
| `AddressList` | `"rdpaudit-block"` | RouterOS address list that receives blocked IPs. |
| `CommentTemplate` | `"RdpAudit auto-block"` | Comment attached to every entry. |
| `ValidateServerCertificate` | `true` | Disable only for lab / staging. |
| `MaxOperationsPerMinute` | `120` | Rate limit guardrail. |

## SessionControlOptions

Session-control actions (disconnect, log off, shadow) are auditable, reversible (where applicable), and rate-limited.

| Field | Default | Meaning |
|-------|---------|---------|
| `Enabled` | `true` | Master switch. Disabling makes the related IPC commands return `Unavailable`. |
| `AllowDisconnect` | `true` | Permit `DisconnectSession`. |
| `AllowLogoff` | `true` | Permit `LogoffSession`. |
| `AllowShadow` | `false` | Permit `ShadowSession`. Disabled by default — opt-in. |
| `RequireShadowPolicy` | `true` | Refuse shadow requests if the Terminal Services policy is missing. |
| `BackupShadowPolicyOnApply` | `true` | Always back up before mutating the shadow policy. |
| `ShadowPolicyMode` | `1` | Microsoft `Shadow` registry value: `0`=off, `1`=full+prompt, `2`=full silent, `3`=view+prompt, `4`=view silent. |
| `MaxOperationsPerMinute` | `30` | Rate limit per operator. |
| `AuditAllOperations` | `true` | Mirror every operation into the alert log. |

## Secret protection

Configuration values that name a real secret (today: `AbuseIpDb.ApiKey`, `MikroTik.Password`) are stored as a JSON envelope:

```json
{ "$protected": "<base64-cipher>", "scope": "LocalMachine" }
```

* On Windows the envelope is produced by `DpapiSecretProtector` using `ProtectedData.Protect` with `LocalMachine` scope and a fixed entropy of `"RdpAudit/v1"`.
* On non-Windows CI the service substitutes `InMemorySecretProtector`, which is **not confidential** — it only exists to make the envelope contract round-trip in tests.
* Plaintext is never logged, returned over IPC, or written into status DTOs.
* A plain (non-envelope) string in the config is still accepted on first run — the secret protector returns it unchanged so operators can supply the value once and then re-save through the Configurator to install the envelope.

## LLM-safe extension rules

When extending this surface:

* **Options are append-only at runtime.** Existing field names must keep their meaning. Add new fields with safe defaults; never repurpose an old field.
* **Never log a protected value.** Log only `Length` / boolean "present" facts about secrets.
* **Never echo a secret over IPC.** Status / test DTOs carry `CredentialPresent` flags, not plaintext.
* **Provider abstractions must stay behind `IFirewallProvider` / `ISecretProtector`.** New providers add a new ordinal to `FirewallProviderKind` (append-only); they must not reuse a retired ordinal.
* **Defaults must be safe.** A new feature defaults to `Enabled = false`. Operators opt in explicitly.
