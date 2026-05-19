# RdpAudit roadmap

## Stage 1 — Foundation (this branch)

Stage 1 lays down the contracts the later UI-heavy stages depend on. It deliberately ships **no new UI** and **no full provider implementations**.

Delivered:

* **Configuration surface** — `AbuseIpDbOptions`, `MikroTikOptions`, `SessionControlOptions`, and an extended `FirewallOptions` with whitelist / blacklist arrays, `BlockOnBlacklistedLogin`, `InstantBlockLogins`, the `FirewallProviderKind` enum (`None` / `Windows` / `MikroTik` / `Both`), and a default block duration.
* **Secret protection foundation** — `ISecretProtector`, `DpapiSecretProtector` (Windows), and a non-production `InMemorySecretProtector` for non-Windows CI. The protected envelope is `{ "$protected": "...", "scope": "LocalMachine" }`.
* **IPC ABI extension** — twenty-one new `IpcCommand` ordinals (11..31) reserved with stable contracts (`Contracts/*Dto.cs`). Handlers return a controlled `NotImplemented` payload, never crash.
* **Firewall provider abstraction** — `IFirewallProvider` plus stub Windows / MikroTik implementations wired into DI.
* **Docs** — `docs/40-options.md`, refreshed `docs/50-ipc.md`, this roadmap entry.
* **Tests** — secret envelope round-trip, IPC ordinal stability, firewall DTO invariants.

Deferred to later stages (explicitly NOT in Stage 1):

* LiveEvents filters and Firewall-tab UI in the Configurator.
* RDP sessions tab and shadow-policy UI.
* Real HTTP client for AbuseIPDB.
* Real REST client for MikroTik RouterOS.
* Firewall stats tab.

## Stage 2 — Data model and persistence (this branch)

Stage 2 lays down the persistent schema the later worker and UI stages depend on. It deliberately
ships **no UI**, **no AutoBlockWorker**, **no AbuseIPDB / MikroTik HTTP clients**, and **no
session-control wiring**.

Delivered:

* **Entities (Core/Models)** — `BlocklistEntry`, `WhitelistEntry`, `LoginRule`, `ActiveBlock`,
  `AbuseReport`, `AttackStat`.
* **Enums (Core/Models)** — `BlocklistSource` (append-only, ordinals 0..6), `ActiveBlockStatus`
  (append-only, ordinals 0..4). `ActiveBlock.Provider` reuses Stage 1's `FirewallProviderKind`.
* **EF Core configurations** — one `IEntityTypeConfiguration<T>` per new entity under
  `Core/Data/Configurations`. Max lengths, required flags, and indices documented in
  `docs/41-data-model.md`. SQLite compatibility preserved.
* **DbContext** — six new `DbSet<T>` properties on `AuditDbContext`.
* **Migration** — `20260519152135_Stage2FirewallStats`. Up creates the six new tables and their
  indices; Down drops them and leaves Stage 1 tables untouched.
* **Projection helper** — `AttackStatProjection` centralises Top-10 login JSON
  serialisation / deserialisation, deterministic top-N ordering (frequency desc, alpha asc), and
  duration arithmetic.
* **Tests** — Stage 2 enum ordinal stability, projection helper round-trip / capping / malformed
  input, schema persistence and uniqueness constraints (`WhitelistEntries.Ip`,
  `LoginRules.Login`, `ActiveBlocks(Provider, Ip)`, `AttackStats.Ip`), migration upgrade behaviour
  (fresh DB, Stage 1 → Stage 2 upgrade preserving Stage 1 rows, Stage 2 → Stage 1 downgrade).
* **Docs** — `docs/41-data-model.md`, this roadmap entry.

Deferred to Stage 3 (explicitly NOT in Stage 2):

* AutoBlockWorker that reconciles `BlocklistEntries` / `ActiveBlocks` against the live firewall
  provider state.
* Windows Firewall provider implementation behind `IFirewallProvider`.
* MikroTik RouterOS REST client.
* AbuseIPDB HTTP client.
* RDP session-control wiring.
* Configurator UI pages for blocklist / whitelist / login rules / active blocks / stats.
* LiveEvents context menu entries that create rows in the Stage 2 tables.

### Stage 3 prerequisites

Before Stage 3 can start:

1. **Windows-only validation.** Apply the Stage 2 migration on a Windows host with an existing
   Stage 1 database and confirm row counts in the Stage 1 tables are unchanged. Linux CI cannot
   exercise the Windows-only `DpapiSecretProtector` path that runs alongside DB startup.
2. **AutoBlockWorker design note.** Define the worker's reconciliation cadence, the retry policy
   for `ActiveBlockStatus.Failed`, and the unblock policy at `ExpiresUtc` before any code lands.
3. **IPC ordinal allocation.** Reserve the next contiguous block of `IpcCommand` ordinals for the
   blocklist / whitelist / login-rule / active-block CRUD surface.

## Stage 3 — Firewall integration backend (this branch)

Stage 3 brings the firewall pipeline online end-to-end while deliberately shipping **no UI**.
LiveEvents filters, the Firewall tab, the Attack Statistics tab, the Remote RDP clients tab,
the AbuseIPDB HTTP client, and the MikroTik REST client all remain deferred.

Delivered:

* **WindowsFirewallProvider** — real `IFirewallProvider` backed by `netsh advfirewall` invoked
  through `ProcessStartInfo.ArgumentList` only. Validates every IP via `IPAddress.TryParse`,
  refuses reserved/private/loopback/multicast addresses when
  `Firewall.RefusePrivateAddressBlock` is set, normalises rule names to `RdpAudit-Block-{ip}`
  (max 200 chars, ASCII-safe set), captures stdout/stderr/exit code, sanitises log fields, and
  exposes `GetStatus`, `BlockAsync`, `UnblockAsync`, `ListBlocksAsync` per `IFirewallProvider`.
* **NetshCommandBuilder** — pure builders for add/delete/show rule and `show allprofiles state`.
  All callers go through the builder so the only path to netsh is the sanitised argument vector.
* **FirewallAutoBlockWorker** — `BackgroundService` that consumes new `Alerts` (resumes from the
  high-water id at startup, never re-processes old alerts). Applies the Stage 3 policy: skip on
  missing/invalid IP, skip on whitelist match, block on instant-login trip-wire (`LoginRules`
  enabled or `Firewall.InstantBlockLogins`), block on blacklisted login when
  `BlockOnBlacklistedLogin` is enabled, block on brute-force class alerts when
  `AutoBlockBruteForce` is enabled. Writes `ActiveBlocks` + `BlocklistEntries` rows with UTC
  timestamps, `LinkedAlertId`, configured expiration, and `Source = Auto`. Enforces
  `MaxActiveBlocks` ceiling, `AutoBlockDebounceSeconds` per-IP debounce, and "already-active"
  guard so the worker never installs duplicate rules.
* **FirewallExpirationWorker** — `BackgroundService` that queries the earliest expiring
  `ActiveBlock`, sleeps until that time (capped at five minutes, minimum one second), then
  calls `provider.UnblockAsync` for each due row. Provider success or `NotFound` flips the row
  to `Removed`; anything else flips to `Failed` with `LastError`. `AuditOnly` rows skip the
  provider call. Works for the Windows provider today and will work for MikroTik later without
  worker changes — the resolution path is provider-id based.
* **IPC handlers (Stage 3)** — `GetFirewallStatus`, `ListBlocklist`, `ListWhitelist`,
  `AddToBlocklist`, `RemoveFromBlocklist`, `AddToWhitelist`, `RemoveFromWhitelist`,
  `ListActiveBlocks`. Every mutation handler validates the address through `IPAddress.TryParse`,
  normalises it, and enforces server-side whitelist precedence
  (`AddToBlocklist` refuses whitelisted addresses; `AddToWhitelist` soft-disables conflicting
  blocklist rows). All writes flow through the service-side `AuditDbContext`; the Configurator
  performs no direct DB writes.
* **Tests** — `NetshCommandBuilderTests` (normalisation, IP validation, reserved-address
  policy, argument vectors), `WindowsFirewallProviderTests` (success / invalid / loopback /
  not-found paths using a fake `INetshRunner`), `AutoBlockPolicyTests` (each policy branch),
  `FirewallWorkerIntegrationTests` (SQLite-backed coverage of the worker
  writes — whitelist skip, threshold block, instant-login block, no-duplicate guard, provider
  failure flagging, expiration round-trip), `IpcDispatcherStage3Tests` (IPC validation +
  whitelist precedence).
* **Docs** — `docs/45-firewall.md`, refreshed `docs/50-ipc.md`, this roadmap entry.

Configuration surface (new):

* `Firewall.RefusePrivateAddressBlock` (default `true`).
* `Firewall.WhitelistIps` (flat IP list complementing `Whitelist` CIDR entries).
* `Firewall.AutoBlockDebounceSeconds` (default `60`).

Deferred to Stage 4+ (explicitly NOT in Stage 3):

* LiveEvents context-menu actions and Firewall / Attack Statistics / Remote-clients UI tabs in
  the Configurator.
* AbuseIPDB HTTP client + reporting pipeline.
* MikroTik RouterOS REST client.
* RDP session-control wiring (`DisconnectSession`, `LogoffSession`, `ShadowSession`).

### Stage 4 prerequisites

Before Stage 4 can start:

1. **Windows-only validation.** On a Windows host, apply the Stage 3 build, drive at least one
   auto-block round-trip via a synthetic brute-force alert, and confirm `netsh advfirewall
   firewall show rule name=RdpAudit-Block-{ip}` lists the expected rule before expiration and
   reports `No rules match` after expiration. Walk through the smoke commands listed in
   `docs/45-firewall.md`.
2. **IPC dry-run.** From the Configurator host, invoke `GetFirewallStatus`, `ListBlocklist`,
   `AddToBlocklist`, `RemoveFromBlocklist`, `AddToWhitelist`, `RemoveFromWhitelist`, and
   `ListActiveBlocks` end-to-end. Confirm each returns a controlled DTO and that whitelist
   precedence is honoured server-side.
3. **MikroTik provider abstraction.** Confirm the `IFirewallProvider` contract and the
   provider-id resolution in `FirewallAutoBlockWorker` / `FirewallExpirationWorker` work
   unchanged when a MikroTik provider is wired in. No worker changes should be needed.

## Stage 4 — LiveEvents UX (this branch)

Stage 4 is the first UI-heavy stage. It deliberately ships only the LiveEvents page improvements
and **no Firewall tab, no Attack Statistics tab, no Remote RDP Clients tab, no AbuseIPDB page,
and no MikroTik page**. All Stage 4 mutations route through Stage 3 IPC handlers — no new IPC
ordinals are introduced.

Delivered:

* **Filter bar (`Forms/LiveEventsPage.cs`)** — IP, user / login, event id, channel, free-text,
  and time-range (`All time`, `Last 5 / 15 / 60 minutes`, `Last 24 hours`) controls combined with
  AND semantics. Text inputs are debounced by 350 ms so a typing burst triggers a single
  refresh. A `Clear filters` button resets every control and re-applies.
* **Filter predicate (`Core/Events/LiveEventFilter.cs`)** — pure, UI-agnostic predicate and the
  `LiveEventRowView` projection consumed by the WinForms grid. Designed so the same spec can be
  forwarded to a server-side query once `GetRecentEvents` grows one.
* **Row formatter (`Core/Events/LiveEventRowFormatter.cs`)** — labelled multiline and TSV
  serialisations for the `Copy Event Details` clipboard action. Embedded tabs / CR / LF are
  neutralised so a pasted TSV row never breaks downstream parsers.
* **Context menu** — per-cell right-click menu whose items target the row under the cursor (not
  the previously-selected row): `Copy Event Details`, `Copy Cell Value`, `Filter by This Value`,
  `Block IP in Windows Firewall and Add to Blocklist`, `Add IP to Whitelist and Unblock`,
  `Add Login to Blocklist and Block IP`. Destructive items are gated by a confirmation dialog
  and disabled when the row lacks a valid IP / login or the cell is empty. IP validity is checked
  via `IPAddress.TryParse`.
* **Status strip** — every operator action and refresh result is rendered into the status strip
  with a UTC `HH:mm:ss` timestamp and per-step success/failure detail (`blocklist=OK,
  firewall=FAIL` etc.). Continuations marshal back to the UI thread before touching the label.
* **IPC reuse** — Block routes through `AddToBlocklist` + legacy `BlockAddress`; whitelist
  routes through `AddToWhitelist` + legacy `UnblockAddress`; login block routes through
  `AddToBlocklist` for the login and (optionally) for the paired IP. No new IPC ordinals are
  introduced; the append-only ABI is preserved.
* **Tests** — `LiveEventFilterTests` (each field in isolation + AND-semantics combinations +
  time-range boundary inclusivity + null-row guard), `LiveEventRowFormatterTests` (multiline
  labels, TSV header / data row, dash placeholder for null / blank fields, tab and newline
  neutralisation, null-row guard).
* **Docs** — refreshed `docs/30-configurator.md`, this roadmap entry.

Deferred to Stage 5+ (explicitly NOT in Stage 4):

* Firewall tab UI (blocklist / whitelist / active-block grids with CRUD).
* Attack Statistics tab.
* Remote RDP Clients tab + session control wiring (`DisconnectSession`, `LogoffSession`,
  `ShadowSession`).
* AbuseIPDB page and HTTP client.
* MikroTik page and REST client.
* Server-side `GetRecentEvents` query parameters (the client-side predicate ships now; the IPC
  contract can grow a payload later without changing call sites).

### Stage 5 prerequisites

Before Stage 5 can start:

1. **Windows manual validation of Stage 4.** Walk the LiveEvents page on a Windows host with the
   service running: type into each filter and confirm debounced refresh; cycle the time-range
   drop-down; right-click the IP / user / channel cells and confirm context-menu enable/disable
   semantics; copy details and a cell value and paste into Notepad and Excel; trigger a Block
   IP → Whitelist round-trip and confirm both `netsh advfirewall firewall show rule
   name=RdpAudit-Block-{ip}` and the `BlocklistEntries` table reflect the change; trigger a
   Login Block and confirm the `BlocklistEntries` row carries the login.
2. **Stage 5 IPC reservation.** Reserve the next contiguous block of `IpcCommand` ordinals for
   the Firewall tab grids (CRUD already exists; the reservation is for any new
   listings — e.g. active-blocks with filters — that the UI may need).
3. **Layout discipline.** The Firewall / Attack Stats / Remote Clients tabs must follow the
   established Configurator pattern: 5-second refresh timer, IPC-only reads/writes, `Invoke`
   dispatch from background callbacks, async event handlers only on `Click`, no direct SQLite
   writes.

## LLM-safe extension rules

When implementing later stages:

1. **Append-only IPC.** Add new commands at the next ordinal. Never reuse retired ordinals. Add a row in `docs/50-ipc.md` and a payload contract under `RdpAudit.Core.Ipc.Contracts`.
2. **Provider abstraction boundaries.** New firewall providers implement `IFirewallProvider`. New reputation / reporting providers must introduce their own abstraction in `RdpAudit.Core/` before any HTTP client lands in `RdpAudit.Service/`.
3. **Secret handling.** Every new secret-bearing config field is stored as a protected envelope and unwrapped through `ISecretProtector`. Never log the plaintext. Status / test DTOs report only `CredentialPresent` flags.
4. **Backward-compatible defaults.** Existing appsettings.json documents must continue to bind. New options default to safe / disabled values.
5. **Cancellation.** All long-running paths take `CancellationToken`. Never call `.Result` / `.Wait()`.
6. **Auditable & reversible.** Every block / report / shadow action records an audit entry. Shadow-policy mutations require a backup unless explicitly suppressed.
