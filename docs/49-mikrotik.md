# 49 — MikroTik RouterOS v7 Integration

Stage 9 introduces an external firewall provider that drives a MikroTik RouterOS v7 device via its
REST API. When configured, the RdpAudit service writes per-IP firewall filter rules to the router
in addition to (or instead of) the local Windows firewall, and removes them automatically when the
configured block duration expires.

## Provider semantics

* **Endpoint composition** — either supply a freeform `BaseUrl` (`https://10.0.0.1:8443`) or let
  `Scheme/Host/Port` be composed by `MikroTikUrlBuilder`. The builder rejects unknown schemes,
  empty hosts, invalid host characters, out-of-range ports, and brackets IPv6 literals.
* **Authentication** — HTTP Basic with the configured `UserName` and the DPAPI-protected
  `Password`. The plaintext is never logged, never echoed in IPC payloads, never copied to the
  clipboard, and never written to appsettings without first being wrapped by `ISecretProtector`.
* **Probe endpoint** — `GET /rest/system/resource`. The probe is safe and read-only; failures map
  to controlled `MikroTikOutcome` values rather than throwing.
* **Block creation** — `PUT /rest/ip/firewall/filter` with body
  `{"chain":"<FilterChain>","action":"<FilterAction>","src-address":"<ip>","comment":"<prefix> ..."}`.
  The comment always starts with the configured `CommentPrefix` (default `RdpAudit`) and contains
  the UTC timestamp and the operator-supplied reason.
* **Idempotency** — before creating a rule the client lists owned rules
  (`GET /rest/ip/firewall/filter`) and reuses the existing row when its `src-address` and `chain`
  match. The provider then returns `FirewallActionStatus.Success` with the existing `RuleId`.
* **Block removal** — `DELETE /rest/ip/firewall/filter/<id>`. The client first performs a
  verifying `GET` and refuses to delete a row whose comment does not start with `CommentPrefix`.
  This guarantees the provider never touches a non-RdpAudit rule on the router.

## Configuration

```jsonc
"MikroTik": {
  "Enabled": false,
  "AddAttackerRules": true,
  "BaseUrl": "",            // wins over Scheme/Host/Port when set
  "UseHttps": true,
  "Host": "",
  "Port": 0,                // 0 = scheme default (443 / 80)
  "UserName": "",
  "Password": "",           // DPAPI-wrapped at rest
  "TimeoutSeconds": 15,
  "AddressList": "rdpaudit-block",
  "FilterChain": "input",
  "FilterAction": "drop",
  "CommentTemplate": "RdpAudit auto-block",
  "CommentPrefix": "RdpAudit",
  "ValidateServerCertificate": true,
  "MaxOperationsPerMinute": 120,
  "BlockDurationDays": 0,
  "BlockDurationHours": 1,
  "BlockDurationMinutes": 0
}
```

Block duration is the sum of the three TimeSpan components; when all components are zero the
service falls back to one hour to avoid permanent rules in the typical case.

## RouterOS v7 setup

1. Enable the REST service. For production prefer HTTPS:
   ```
   /ip/service set www-ssl disabled=no
   /ip/service set www-ssl address=<your-rdpaudit-host>/32
   ```
   For lab use only:
   ```
   /ip/service set www disabled=no
   ```
2. Install or generate a TLS certificate for `www-ssl`.
3. Create a dedicated least-privilege group and user:
   ```
   /user/group add name=rdpaudit policy=read,write,api,rest-api,!ssh,!ftp,!telnet,!winbox,!web,!policy
   /user add group=rdpaudit name=rdpaudit password=<...>
   ```
4. (Optional) restrict the user's allowed-address to the RdpAudit host's IP.

## TTL cleanup

`FirewallExpirationWorker` sleeps until the earliest `ActiveBlocks.ExpiresUtc` for a row whose
status is `Active` or `Pending`, then calls the provider's `UnblockAsync`. The worker reuses the
existing next-expiration design — no hot polling — and falls back to a five-minute idle delay
when no blocks are due. Because the auto-block worker stores one `ActiveBlock` row per provider
(splitting `Both` into one row each for Windows and MikroTik) every rule has its own
`RuleHandle` and its own expiry timeline; a service restart picks up where it left off.

## IPC

* **GetMikroTikStatus (ordinal 29)** — returns `MikroTikStatusDto` with configuration flags,
  the resolved endpoint, the resolved scheme, the provider status (`Available`, `Unreachable`,
  `Disabled`, `NotConfigured`, `NotImplemented`), the active MikroTik block count, the configured
  chain/action/prefix/duration, and the last error. Never returns the password.
* **TestMikroTik (ordinal 30)** — runs a controlled `GET /rest/system/resource` probe and returns
  a `MikroTikTestResult` with `CredentialFormatValid`, `RemoteVerified`, the HTTP status, the
  sanitised endpoint and a human-readable message.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|------|
| `MikroTikOutcome.NotConfigured` | Host or password missing, or URL composition failed | Re-open the MikroTik tab; check the status panel for the URL builder error |
| HTTP 401 from probe | Wrong username or password | Re-enter the password; remember it must be re-entered after Save (mask is opaque) |
| HTTP 403 from probe | Group policy missing `rest-api` | Re-create the user with the `policy=...,rest-api,...` group |
| TLS handshake failure | Bad certificate or self-signed cert | Either install a trusted cert OR untick "Validate TLS certificate" for lab use |
| Stale block stays on router | `ActiveBlock.RuleHandle` lost (DB reset) | The provider's `ListOwnedRulesAsync` only sees rules whose comment starts with the prefix; remove them manually with `/ip/firewall/filter remove [find comment~"^RdpAudit"]` |

## Stage-9 invariants

* No duplicate router rules — `AddBlockAsync` always lists owned rules before creating a new one.
* No deletion of non-RdpAudit rules — `RemoveBlockAsync` verifies the comment prefix before
  issuing `DELETE`.
* No plaintext password ever leaves the service host — Configurator only submits the password to
  the service via the existing SaveSettings IPC, which protects it with `ISecretProtector`.
* No hot polling — the expiration worker still waits on the earliest `ExpiresUtc`.
