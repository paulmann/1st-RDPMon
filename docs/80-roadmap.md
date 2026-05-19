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

## Stage 5 — Firewall tab UI + settings / list management (this branch)

Stage 5 introduces the Firewall tab in the Configurator. It deliberately ships **no Attack
Statistics tab, no Remote RDP Clients tab, no AbuseIPDB page / client, and no MikroTik page /
client**; those remain deferred to Stage 6+. The MikroTik and `Both` provider entries in the
provider drop-down are surfaced but disabled so operators can see them coming.

Delivered:

* **Firewall tab (`Forms/FirewallPage.cs`)** — added to `MainForm` after Live Events. Three
  sections: provider / status, auto-block policy, and an inner `TabControl` with Blocklist /
  Whitelist / Login trip-wires / Active blocks grids. A 5-second timer refreshes every list and
  the status panel together; the status strip records `[HH:mm:ss Z]` timestamps and per-step
  OK / FAIL detail for every operator action.
* **Provider / status panel** — `Enable Windows Firewall blocking` checkbox bound to the
  effective `Firewall.Provider` value (`None` when off, the selected provider when on); active
  provider drop-down with `None`, `Windows`, and disabled `MikroTik` / `Both` entries; refresh
  button; live status labels that distinguish *enabled*, *disabled*, *unavailable*, and
  *non-Windows host* states; counters strip showing `ActiveBlockCount` / `WhitelistCount` /
  `BlacklistCount` returned by `GetFirewallStatus`.
* **Auto-block policy panel** — `Auto-block if source is not whitelisted and failed attempts
  exceed threshold` checkbox (bound to `FirewallOptions.AutoBlockBruteForce`), numeric threshold
  bound to `AutoBlockThreshold` (1..100,000), days / hours / minutes numeric inputs that compose
  `DefaultBlockDurationMinutes`, `Auto-block if attempted login is blacklisted` checkbox bound
  to `BlockOnBlacklistedLogin`, and `Refuse private-address blocks` bound to
  `RefusePrivateAddressBlock`. `Save policy` round-trips through `GetSettings` →
  in-place mutation of the `Firewall` JSON sub-tree → `SaveSettings`; the existing service hot-
  reload picks the change up via `IOptionsMonitor<RdpAuditOptions>`.
* **Blocklist / Whitelist grids** — bound to `ListBlocklist` / `ListWhitelist`, filterable by
  IP / source / note, with validated Add (client-side `IPAddress.TryParse` + server-side
  re-validation) and confirmation-gated Remove. Whitelist add prompts a follow-up Yes/No that
  invokes `UnblockAddress` so operators can clean an active rule in one step. Removing a
  whitelist entry never installs a block.
* **Login trip-wires grid** — bound to `ListLoginRules`, filterable by login / note / enabled
  state, with Add / Remove / Toggle-enabled buttons. The page explicitly tells operators that
  these rules cause source-IP blocks on attempted logons; they do **not** disable local Windows
  accounts.
* **Active blocks grid** — bound to `ListActiveBlocksDetailed`, filterable by IP / reason /
  provider / status / rule-handle / error, with `Unblock selected` driving `UnblockActiveBlock`.
  Provider, status, created / expires UTC, rule handle, and last error are all visible in the
  grid.
* **New IPC commands** — `ListLoginRules` (32), `AddLoginRule` (33), `RemoveLoginRule` (34),
  `SetLoginRuleEnabled` (35), `ListActiveBlocksDetailed` (36), `UnblockActiveBlock` (37). All
  append-only at the next free ordinals; ABI stability is locked by
  `IpcCommandStabilityTests.Ordinal_IsStable`.
* **New DTOs** — `LoginRuleDto`, `LoginRuleMutationRequest`, `ActiveBlockDto` under
  `Core/Ipc/Contracts`, with explicit `[MessagePackObject]` + integer `[Key]` indices.
* **Core helper** — `Core/Util/AddressListFilter.cs`: pure case-insensitive substring predicate
  and IP / login normalisation helpers, lifted out of the UI so they can be unit tested.
* **Tests** — `AddressListFilterTests` (empty query, whitespace, case-insensitive substring,
  null-field tolerance, IPv4 / IPv6 acceptance and rejection, IPv6 canonicalisation,
  login trim+lowercase, control-character rejection), `IpcDispatcherStage5Tests` (login rule
  add normalisation, empty-login rejection, idempotent re-add, toggle, remove-by-login fallback,
  `ListActiveBlocksDetailed` DTO shape, `UnblockActiveBlock` bookkeeping, missing-id error
  path), and extended `IpcCommandStabilityTests` with the six new ordinals.
* **Docs** — refreshed `docs/30-configurator.md` (Firewall row), `docs/45-firewall.md`
  (cross-reference to Stage 5 UI + Stage 5 IPC), `docs/50-ipc.md` (Stage 5 command table +
  semantics), this roadmap entry.

Deferred to Stage 6+ (explicitly NOT in Stage 5):

* Attack Statistics tab.
* Remote RDP Clients tab + session control wiring (`DisconnectSession`, `LogoffSession`,
  `ShadowSession`).
* AbuseIPDB page and HTTP client.
* MikroTik page and REST client (the provider drop-down entries already exist but are disabled).

### Stage 6 prerequisites

Before Stage 6 can start:

1. **Windows manual validation of Stage 5.** On a Windows host with the service installed and
   running:
   * Open the Firewall tab. Confirm the provider drop-down shows `Windows Firewall` selected
     and the status label reads *Enabled (Windows Firewall reachable)*.
   * Toggle `Enable Windows Firewall blocking`, click `Save policy`, and confirm the status
     strip logs `Save OK` and the `RdpAuditOptions.Firewall.Provider` value persists across a
     service restart (`%ProgramData%\RdpAudit\appsettings.json`).
   * Change `Threshold`, `Default block duration` (days/hours/minutes), and toggle
     `Auto-block if attempted login is blacklisted` and `Refuse private-address blocks`. Save
     and confirm the JSON sub-tree reflects the change.
   * Add an IP to the Blocklist via the Add button; confirm `netsh advfirewall firewall show
     rule name=RdpAudit-Block-{ip}` lists the rule once the auto-block worker reconciles, and
     that the row appears in `BlocklistEntries`.
   * Add the same IP to the Whitelist and accept the follow-up unblock prompt; confirm the
     blocklist row is soft-disabled and the netsh rule no longer matches.
   * Add a login trip-wire ("administrator"), toggle it off, and remove it; confirm the
     `LoginRules` table reflects each step.
   * Select an active block row, click `Unblock selected`, and confirm the row transitions to
     `Removed` and any matching `BlocklistEntries` row is soft-disabled.
   * Watch the status strip: every action must surface a `[HH:mm:ss Z]` line with OK / FAIL
     detail.
2. **Stage 6 IPC reservation.** Reserve the next contiguous block of `IpcCommand` ordinals for
   the Remote RDP Clients tab (`ListRdpSessions`, `DisconnectSession`, `LogoffSession`,
   `ShadowSession` are already reserved at 19..22), the AbuseIPDB client, and the MikroTik
   client. Ordinals 38+ are free.
3. **Provider abstraction discipline.** Re-enabling the MikroTik / Both entries in the Firewall
   tab provider drop-down must follow the existing `IFirewallProvider` contract: the UI must
   continue to drive *only* IPC, and the provider id must be resolved server-side from
   `FirewallProviderKind` without UI knowledge of the underlying REST endpoint.

## Stage 6A — Attack Statistics backend + IPC

Stage 6A lights up the back-end half of the operator-facing attack dashboard. It deliberately
ships **no Configurator UI tab** — the Attack Statistics tab is delivered in Stage 6B. Stage 6A
also ships **no Remote RDP Clients tab, no session shadow actions, no AbuseIPDB integration, and
no MikroTik integration**; those remain deferred to Stage 7+.

Delivered:

* **Threat scoring** — `Core/Models/AttackThreatScoring.cs`: pure, deterministic
  `ComputeScore(failed, successful, durationSeconds, isBlocked, lastSeenUtc, nowUtc) → [0..100]`
  built from five additive components (failure pressure, success-after-fail signal, intensity,
  active-block bonus, recentness). `ClassifyScore(double) → AttackThreatLevel` maps the score to
  cameyo-style `Green / Yellow / Red` bands using public threshold constants. Full algorithm,
  worked examples, and validation guidance in `docs/46-attack-statistics.md`.
* **Aggregation** — `Core/Models/AttackStatsAggregator.cs`: pure projection from a bounded slice
  of `RawEvents` and a set of currently-blocked IPs into one `AttackStat` per distinct source
  IP. Logon-success (`4624`) and logon-failure (`4625`) ids drive success / failure tallies;
  unknown event ids count toward `Failed`. Output ordering is deterministic so tests can pin
  byte-stable expectations.
* **Worker** — `Service/Workers/AttackStatsRefreshWorker.cs`: `BackgroundService` registered in
  `Service/Program.cs` alongside the existing workers. Refreshes at startup, then every
  `60 seconds`. Bounds each pass by a 30-day look-back window and a hard
  `MaxRawEventsPerPass = 50,000` ceiling. Uses `IDbContextFactory<AuditDbContext>` with
  `AsNoTracking()` reads. `SemaphoreSlim(1, 1)` guards against concurrent re-entry; honours the
  `stoppingToken` on every `await`.
* **IPC** — `IpcCommand.GetAttackStats` (ordinal `18`, Stage 1 reservation) is now implemented in
  `Service/Ipc/IpcDispatcher.cs::GetAttackStatsAsync`. Accepts an optional `AttackStatsRequest`
  filter (IP substring, min threat score, only-blocked, since / until window, limit clamped to
  `[1..2000]`). Returns `AttackStatsDto` extended with three append-only `[Key]` slots:
  `Entries: List<AttackStatEntryDto>`, `TotalMatching: int`, `AppliedLimit: int`. No new IPC
  ordinals are introduced. Malformed JSON / internal exceptions surface as a controlled
  `IpcResponse` with `Success = false` and a sanitised `Error` string — never raw exception
  detail.
* **Contracts** — `Core/Ipc/Contracts/AttackStatEntryDto.cs` (new), `AttackStatsRequest.cs` (new),
  extended `AttackStatsDto.cs`. Every new field lands at the next free `[Key]` index. The Stage 1
  reservation contract is preserved verbatim at keys `0..8`.
* **Filter helper (UI-agnostic)** — `Core/Util/AttackStatsFilter.cs`: pure predicate that mirrors
  the server-side `AttackStatsRequest` semantics so the future Stage 6B UI can pre-filter cached
  rows while the operator types without diverging from server-side filtering.
* **Tests**
  * `AttackThreatScoringTests` — each scoring component, the clamp, classification boundaries,
    recentness buckets, clock-skew handling, parameterised classification bounds.
  * `AttackStatsAggregatorTests` — empty input, blank-IP skip, group-by-IP, success vs failure
    counting, top-N login cap, `IsBlocked` propagation, unknown event ids, deterministic
    ordering.
  * `AttackStatsFilterTests` — empty filter, null entry, IP substring, min-threat inclusive
    bound, only-blocked, since / until inclusive bounds, AND semantics.
  * `IpcDispatcherStage6Tests` — end-to-end dispatch + filter combinations + limit clamping +
    invalid-JSON path + worker cancellation propagation + serial-call stability.
* **Docs** — new `docs/46-attack-statistics.md` (subsystem overview, scoring algorithm, validation
  guidance, 6A/6B split), `docs/50-ipc.md` (Stage 6A command table + `AttackStatsRequest` /
  `AttackStatsDto` shapes), this roadmap entry.

Configuration surface: none. The worker hard-codes its cadence and bounds; future stages may
expose them via `RdpAuditOptions` if operators ask.

Deferred to Stage 6B (explicitly NOT in Stage 6A):

* `Configurator/Forms/AttackStatisticsPage.cs` tab and its `MainForm` registration. The
  `AttackStatsFilter` helper ships in Core in 6A so the future UI can share the predicate without
  re-implementation.

Deferred to Stage 7+ (explicitly NOT in Stage 6):

* Remote RDP Clients tab + session-control wiring (`DisconnectSession`, `LogoffSession`,
  `ShadowSession`).
* AbuseIPDB page and HTTP client.
* MikroTik page and REST client.

### Stage 6B prerequisites (Configurator UI delivery)

Before Stage 6B can start:

1. **Windows manual validation of Stage 6A.** On a Windows host with the service installed and
   running:
   * Drive a synthetic brute-force burst against the host (or seed `RawEvents` via the service
     under test) and confirm `AttackStats` materialises one row per source IP within one
     60-second worker cycle. Query with
     `SELECT Ip, TotalAttempts, Failed, Successful, ThreatScore, IsBlocked, LastUpdatedUtc FROM
     AttackStats ORDER BY LastUpdatedUtc DESC LIMIT 20;`.
   * Confirm `IsBlocked` toggles on rows whose IP appears in `ActiveBlocks` with `Status IN
     (Active, Pending)`.
   * Drive the `GetAttackStats` IPC command directly (e.g. via a probe tool that speaks the
     `IpcRequest` envelope) with `OnlyBlocked = true`, `MinThreatScore = 70`, `IpQuery = "203"`,
     `Limit = 50` and confirm filters compose correctly server-side.
   * Tail the service log and confirm `AttackStatsRefreshWorker pass complete, rows materialised:
     N` appears every 60 seconds.
2. **Stage 6B IPC reservation.** No new ordinals are required; Stage 6B is a UI-only stage that
   consumes the Stage 6A `GetAttackStats` contract. Stage 7 ordinals `19..30` remain reserved.
3. **UI layering discipline.** The 6B tab must drive *only* IPC (`GetAttackStats` for reads;
   `AddToBlocklist` / `AddToWhitelist` / `BlockAddress` / `UnblockAddress` for mutations). The
   Configurator MUST NOT open the SQLite database directly for the Attack Statistics tab, and
   MUST reuse `Core/Util/AttackStatsFilter.cs` for client-side pre-filtering rather than inlining
   a second predicate.

## Stage 6B — Attack Statistics Configurator tab (this branch)

Stage 6B delivers the operator-facing half of the Attack Statistics subsystem. It consumes the
Stage 6A `GetAttackStats` IPC contract only and introduces no new IPC ordinals. With 6B landing,
**Stage 6 is complete.** Remote RDP Clients, session control, AbuseIPDB, and MikroTik remain
deferred to Stage 7+.

Delivered:

* **Tab** — `Configurator/Forms/AttackStatisticsPage.cs`: SOC-operator Attack Statistics tab
  registered on `MainForm` immediately after the Firewall tab. Twelve grid columns (IP, Threat
  score / band, Total, Failed, Successful, First Seen, Last Seen, Duration, Top 10 Attempted
  Logins, Last LogonType, Blocked). Row backgrounds are painted from the server-returned
  `ThreatLevel` (Green / Yellow / Red), so the UI cannot drift from the back-end thresholds.
* **Filter toolbar** — IP-search, min-threat numeric, only-blocked checkbox, recent-period preset
  (`Last hour` / `Last 24 hours` / `Last 7 days` / `Last 30 days` / `All time`), row-limit
  selector, `Auto refresh (5s)` checkbox, `Refresh` button, `Clear filters` button. The recent
  period maps to `AttackStatsRequest.SinceUtc` through `Core/Util/AttackStatsRecentRange.cs` so
  the mapping is unit-tested without WinForms.
* **Auto-refresh** — Optional 5-second timer; a re-entry guard drops overlapping ticks rather than
  queuing them so a slow service cannot pile up background work.
* **Context menu** — `Copy Row Details` (multiline labelled block via `Core/Models/AttackStatRowFormatter.cs`),
  `Copy IP`, `Block IP…` (confirmation-gated `AddToBlocklist`), `Whitelist IP…` (confirmation-gated
  `AddToWhitelist`). Mutations reuse Stage 5 IPC commands verbatim.
* **Status strip** — UTC-stamped per-action and per-refresh outcome reporting; controlled error
  messages on IPC failure (`Refresh FAILED: …`), never raw exception traces.
* **Layering** — All reads go through `IpcCommand.GetAttackStats`. The Configurator never opens
  the SQLite file directly for this tab. All IPC calls are awaited with `ConfigureAwait(true)`;
  the UI never calls `.Result` / `.Wait()`.
* **Tests**
  * `AttackStatRowFormatterTests` — multiline + TSV clipboard output, top-logins serialisation,
    duration formatter, TSV tab/newline sanitisation.
  * `AttackStatsRecentRangeTests` — toolbar preset → `SinceUtc` mapping, display labels,
    append-only enum ordinals.
  * Stage 6A `AttackStatsFilterTests` and `IpcDispatcherStage6Tests` continue to lock the shared
    filter predicate and IPC contract.
* **Docs** — `docs/30-configurator.md` Attack Statistics page section, `docs/46-attack-statistics.md`
  Stage 6B section + Windows validation checklist, this roadmap entry.

Configuration surface: none. The 5-second auto-refresh cadence and 500-row default limit are
hard-coded; future stages may expose them via `RdpAuditOptions` if operators ask.

Cross-tab "Filter Live Events by this IP" is deferred — the existing `LiveEventsPage` does not
expose a public filter API, and adding one was out of scope for Stage 6B. SOC operators can copy
the IP from Attack Statistics and paste it into the Live Events IP filter manually.

Deferred to Stage 7+ (explicitly NOT in Stage 6B):

* Remote RDP Clients tab + session-control wiring (`DisconnectSession`, `LogoffSession`,
  `ShadowSession`).
* AbuseIPDB page and HTTP client.
* MikroTik page and REST client.
* Cross-tab filter linking between Attack Statistics and Live Events.

### Stage 7 prerequisites

Before Stage 7 can start:

1. **Windows manual validation of Stage 6B.** The Stage 6B tab must show one row per attacker IP
   within one 60-second refresh cycle, colour rows correctly per the server-returned
   `ThreatLevel`, and round-trip the right-click `Block IP` / `Whitelist IP` actions through
   `netsh advfirewall firewall show rule name=RdpAudit-Block-{ip}` verification. The auto-refresh
   timer must drop overlapping ticks (no duplicated rows). See the validation checklist in
   `docs/46-attack-statistics.md`.
2. **Stage 7 IPC reservation.** `ListRdpSessions` (19), `DisconnectSession` (20),
   `LogoffSession` (21), and `ShadowSession` (22) are already reserved. Ordinals 38+ remain free
   for future allocations.
3. **AbuseIPDB / MikroTik provider abstractions.** Stage 7 introduces session control. AbuseIPDB
   and MikroTik integrations land in a later stage; their abstractions must live in
   `RdpAudit.Core/` before any HTTP / REST client lands in `RdpAudit.Service/`.

### Stage 7 (delivered) — Remote RDP Clients tab + shadow policy management

Stage 7 delivers the operator surface for live RDP-session control and Terminal Services
shadow-policy management. Stage 8 (AbuseIPDB / MikroTik integrations) remains deferred and is
NOT touched by this stage.

* **Backend / IPC contracts.** Eight Stage 1-reserved commands are now implemented end-to-end:
  `ListRdpSessions` (19), `DisconnectSession` (20), `LogoffSession` (21), `ShadowSession` (22),
  `GetShadowPolicyStatus` (23), `ApplyShadowPolicy` (24), `BackupShadowPolicy` (25),
  `RestoreShadowPolicy` (26). MessagePack DTOs (`RdpSessionDto`, `RdpSessionListDto`,
  `SessionActionRequest`, `SessionActionResult`, `ShadowPolicyValueDto`, `ShadowPolicyStatusDto`,
  `ShadowPolicyApplyRequest`) use append-only integer keys.
* **Service-side session control.** `RdpAudit.Service/Services/RdpSessionManager` shells out to
  `qwinsta.exe`, `tsdiscon.exe` and `logoff.exe` via `ProcessStartInfo.ArgumentList` (never shell
  concatenation). Session ids are validated against `[0, 65535]` by the pure
  `Core/Util/SessionCommandBuilder` before any process is spawned. The Configurator's
  `ShadowLauncher` handles `mstsc.exe /shadow:<id> [/control] [/noConsentPrompt]` because the
  service runs under LocalSystem and cannot launch UI in the operator's desktop — but the service
  still gates the action via its `ShadowSession` handler against the live policy.
* **Shadow policy management.** `RdpAudit.Service/Services/ShadowPolicyManager` reads / writes
  the tracked registry values (`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Shadow`
  and per-machine fallback) using `Microsoft.Win32.RegistryKey`. Apply / Restore always take a
  snapshot first; the snapshots are JSON files under
  `%ProgramData%\RdpAudit\Backups\<yyyyMMdd-HHmmss>\shadow-policy.json` so the existing backup
  layout still works.
* **Configurator UI.** `RdpAudit.Configurator/Forms/RemoteRdpClientsPage` lists sessions, colours
  them by state (green = active, orange = disconnected, grey = inactive), supports filters /
  auto-refresh, exposes the right-click menu (Disconnect / Logoff / Shadow view / Shadow +
  control / Shadow + control NO CONSENT), and hosts the shadow-policy panel with `Enable all
  permissions…`, `Backup`, `Restore latest…` and `Refresh policy` buttons. Every destructive or
  policy-mutating action is confirmation-gated with the **No** button as the default.
* **Tests.** `QwinstaParserTests` (header / current-session marker / empty input / state
  normalisation), `SessionCommandBuilderTests` (id validation, disconnect / logoff / shadow
  argument shapes), `ShadowPolicyModelTests` (value classification, mode-vs-policy predicate,
  preset constant), `IpcDispatcherStage7Tests` (per-command validation + controlled error paths).
  All existing tests still pass.
* **Docs.** `docs/30-configurator.md` Remote RDP Clients tab row, `docs/47-remote-rdp-clients.md`
  surface map and command semantics, `docs/50-ipc.md` Stage 7 section and the Stage 7 IPC
  semantics list, this roadmap entry.

Configuration surface: existing `RdpAuditOptions.SessionControl` (`Enabled`, `AllowDisconnect`,
`AllowLogoff`, `AllowShadow`, `RequireShadowPolicy`, `BackupShadowPolicyOnApply`,
`ShadowPolicyMode`) is now actually consumed by the IPC handlers. Defaults remain safe:
shadowing is OFF (`AllowShadow = false`), disconnect / logoff are ON, and policy backups are ON.

Deferred to Stage 8+ (explicitly NOT in Stage 7):

* AbuseIPDB page and HTTP client.
* MikroTik page and REST client.
* Cross-tab filter linking between Attack Statistics / Remote RDP Clients and Live Events.

### Stage 8 (delivered) — AbuseIPDB integration

Stage 8 delivers the optional AbuseIPDB reputation / reporting integration. MikroTik integration
(ordinals 29 and 30) remains deferred to Stage 9 and is explicitly NOT touched by this stage.

* **Backend / IPC contracts.** Stage 1-reserved commands `GetAbuseIpDbStatus` (27) and
  `TestAbuseIpDbKey` (28) are now implemented end-to-end. New MessagePack DTOs
  (`AbuseIpDbStatusDto`, `AbuseIpDbTestResult`) use append-only integer keys.
* **Service-side client.** `RdpAudit.Service.AbuseIpDb.AbuseIpDbClient` (registered behind the
  Core abstraction `IAbuseIpDbClient`) uses `IHttpClientFactory` and posts form-urlencoded reports
  to the configured endpoint. The API key is unwrapped from its DPAPI envelope only at the call
  site, attached to the `Key:` request header and dropped immediately. Responses classify into
  `Accepted` / `Rejected` / `RateLimited` (with `Retry-After`) / `ServerError` / `TransportError`
  / `NotConfigured` / `Suppressed`.
* **Reporting worker.** `RdpAudit.Service.Workers.AbuseIpDbReportWorker` is a `BackgroundService`
  that periodically scans `AttackStats` for high-threat unreported IPs, applies the pure decision
  helper `Core/AbuseIpDb/AbuseIpDbPolicy.Decide` (Enabled + ReportAttacks + ApiKey + public IP +
  not whitelisted + threshold + dedup + hourly/daily caps), and submits qualifying reports. Every
  attempt — success or failure — is persisted to the Stage 2 `AbuseReports` table for dedup,
  audit and rate-limit accounting. Honours `CancellationToken`, guards against re-entry, and
  pauses on 429 (`Retry-After`) and 5xx server errors.
* **Comment builder.** `RdpAudit.Core.AbuseIpDb.AbuseIpDbCommentBuilder` constructs the
  professional report comment from `AbuseIpDbEvidence` (IP, hostname, failed / successful counts,
  first / last seen, attempted usernames, duration). The builder strips control characters and
  delimiters, deduplicates and caps usernames to 5 × 32 chars, caps the comment to 1000 bytes,
  and appends the public attribution footer `Reported via RDP Monitor
  https://github.com/paulmann/1st-RDPMon`. Passwords, tokens, command-line content and internal
  hostnames never appear.
* **Settings persistence.** `RdpAudit.Service.Services.SettingsManager` now accepts an
  `ISecretProtector` and DPAPI-wraps `AbuseIpDb.ApiKey` (and `MikroTik.Password`) before atomic-
  write replacement of `appsettings.json`. Existing envelopes pass through unchanged. The Service
  always registers DPAPI on Windows; the in-memory protector is used only for non-Windows CI and
  is documented as non-confidential.
* **IPC masking.** `GetSettings` now returns a masked copy of the options where every non-empty
  secret envelope is replaced with the literal `***configured***`. The Configurator treats that
  placeholder as a do-not-overwrite sentinel.
* **Configurator UI.** `RdpAudit.Configurator/Forms/AbuseIpDbPage` adds a new tab after Remote
  RDP Clients: a privacy / third-party-warning intro, a password-style API key input with a
  `Show key` toggle, a `Report attacks to AbuseIPDB` checkbox enabled only after a key is
  configured, and Save / Test key / Refresh status buttons. The status panel surfaces credential
  state, endpoint URL, total / hour / day counters, last report result, and rate-limit state.
* **Tests.** `AbuseIpDbCommentBuilderTests`, `AbuseIpDbPolicyTests`,
  `AbuseIpDbApiKeyValidatorTests` (Core); `AbuseIpDbClientTests`, `AbuseIpDbReportWorkerTests`,
  `IpcDispatcherStage8Tests`, `SettingsManagerSecretsTests` (Service). All existing tests still
  pass — `Stage2EnumStability`, `IpcCommandStability` and the Stage 3 / 5 / 6 / 7 dispatcher
  tests are unchanged.
* **Docs.** `docs/30-configurator.md` AbuseIPDB tab row, `docs/40-options.md` AbuseIpDbOptions
  fields, `docs/48-abuseipdb.md` (new surface map, privacy and troubleshooting), `docs/50-ipc.md`
  Stage 8 semantics and DTO contracts, this roadmap entry.

Configuration surface additions on `AbuseIpDbOptions`: `ReportAttacks` (bool), `EndpointUrl`,
`MaxReportsPerHour`, `MaxReportsPerDay`, `DeduplicationWindowMinutes`, `MinThreatScore`,
`MinFailedAttempts`. Defaults remain safe: integration is OFF (`Enabled = false`,
`ReportAttacks = false`), thresholds are conservative (60 score, 10 failures), dedup is 15
minutes minimum and the daily cap is 500.

Deferred to Stage 9+ (explicitly NOT in Stage 8):

* MikroTik page and REST client (ordinals 29 and 30 remain reserved).
* AbuseReports retention pruning in `MaintenanceWorker`.
* Reputation-lookup cache surface (Stage 8 implements reporting only).

### Stage 9 prerequisites

Before Stage 9 can start:

1. **Windows manual validation of Stage 8.** Save / Test key / Report toggle round-trip must
   work against a live AbuseIPDB key; a high-threat seed IP must produce exactly one
   `AbuseReports` row per dedup window; rate-limit caps must clamp outbound reports as
   configured; `GetSettings` must NEVER return the plaintext key.
2. **Stage 9 IPC reservation.** Ordinals 29 (`GetMikroTikStatus`) and 30 (`TestMikroTik`) remain
   reserved. Ordinals 38+ remain free for future allocations.
3. **Provider abstractions.** Stage 5's `IFirewallProvider` is already implemented for
   `MikroTikFirewallProvider`; Stage 9 wires the REST client and the Configurator MikroTik tab
   without changing the Core abstraction.

### Stage 9 (delivered) — MikroTik RouterOS v7 integration

Stage 9 delivers the optional MikroTik RouterOS v7 external firewall provider end-to-end. Stage 10
(final QA, retention pruning, polish) remains explicitly NOT touched by this stage.

* **Backend / IPC contracts.** Stage 1-reserved commands `GetMikroTikStatus` (29) and
  `TestMikroTik` (30) are now implemented end-to-end. New MessagePack-compatible DTOs
  (`MikroTikStatusDto`, `MikroTikTestResult`) use append-only integer keys.
* **MikroTik client.** `RdpAudit.Service.Firewall.MikroTikClient` (registered behind the Core
  abstraction `IMikroTikClient`) uses `IHttpClientFactory`, attaches HTTP Basic credentials only
  at the call site, supports HTTP and HTTPS, honours `ValidateServerCertificate`, classifies every
  response into `MikroTikOutcome.{Accepted, Rejected, RateLimited, ServerError, TransportError,
  NotConfigured, AlreadyExists, NotFound}`, captures `Retry-After`, and never logs the plaintext
  password. Probe endpoint: `GET /rest/system/resource`. Block create: idempotent
  `PUT /rest/ip/firewall/filter` (lists owned rules first and reuses an existing matching row).
  Block remove: verifying `GET` + `DELETE /rest/ip/firewall/filter/<id>`, **refusing to delete any
  row whose comment does not start with the configured `CommentPrefix`**.
* **URL builder.** `RdpAudit.Core.MikroTik.MikroTikUrlBuilder` is a pure, testable helper that
  composes `BaseUrl` from `Scheme/Host/Port`, validates the host syntax, brackets IPv6 literals,
  rejects unknown schemes, and combines REST paths defensively.
* **Provider integration.** `MikroTikFirewallProvider` now delegates to the REST client. The
  Stage 3 `FirewallAutoBlockWorker` was extended to fan out the `Both` provider kind into one
  `ActiveBlock` row per provider, so the Stage 3 `FirewallExpirationWorker` continues to expire
  each rule independently with its own `RuleHandle`. No hot polling.
* **Settings persistence.** The Stage 8 `SettingsManager` already DPAPI-wraps `MikroTik.Password`.
  The `MikroTikOptions` surface was extended with `AddAttackerRules`, `UseHttps`, `Host`, `Port`,
  `FilterChain`, `FilterAction`, `CommentPrefix`, `BlockDurationDays/Hours/Minutes`, plus a pure
  `ComposedBlockDuration()` helper that falls back to one hour when all components are zero.
* **IPC masking.** `GetMikroTikStatus` never returns the password or the protected envelope —
  only a `CredentialPresent` flag, the resolved endpoint, the resolved scheme, the configured
  filter chain / action / prefix / duration, the provider status returned by the registered
  provider, and the count of active MikroTik rows in `ActiveBlocks`.
* **Configurator UI.** `RdpAudit.Configurator/Forms/MikroTikPage` adds a new tab after AbuseIPDB.
  The tab carries inline RouterOS setup instructions (enable `www-ssl`, restrict allowed-address,
  least-privilege user/group), Host/IP, port (0 = scheme default), Use HTTPS, Validate TLS,
  Username, Password (with Show toggle), filter chain/action, comment prefix, block duration
  (days/hours/minutes), `Add attacker IP block rules to MikroTik Firewall`, and `Enable MikroTik
  integration` checkboxes, and Save / Test connection / Refresh status buttons. All UI strings
  are English-only.
* **Tests.** `MikroTikUrlBuilderTests` (Core), `MikroTikClientTests`,
  `MikroTikFirewallProviderTests`, `IpcDispatcherStage9Tests` (Service), and an additional
  `SettingsManagerSecretsTests.Save_ProtectsMikroTikPassword_BeforePersistence` test. All existing
  tests still pass.
* **Docs.** `docs/49-mikrotik.md` (new — RouterOS setup, security, REST semantics, troubleshooting,
  TTL cleanup, Stage 9 invariants), `docs/40-options.md`, `docs/45-firewall.md`, `docs/50-ipc.md`,
  this roadmap entry.

Configuration surface additions on `MikroTikOptions`: `AddAttackerRules`, `UseHttps`, `Host`,
`Port`, `FilterChain`, `FilterAction`, `CommentPrefix`, `BlockDurationDays`, `BlockDurationHours`,
`BlockDurationMinutes`. Defaults remain safe: integration is OFF (`Enabled = false`,
`AddAttackerRules = true`), TLS validation is ON (`ValidateServerCertificate = true`), the default
block duration is one hour, and the default chain/action is `input/drop`.

Deferred to Stage 10 (explicitly NOT in Stage 9):

* Final QA pass (Windows manual validation, retention pruning of `AbuseReports`, polish).
* Cross-tab filter linking between Attack Statistics / Remote RDP Clients / MikroTik tab and Live
  Events.
* Address-list synchronisation (the Stage 9 client writes to `/ip/firewall/filter` directly; the
  `AddressList` field is preserved for operators who want to wire it into a router-side rule but
  no automatic insert is performed yet).

### Stage 10 prerequisites

Before Stage 10 can start:

1. **Windows manual validation of Stage 9.** From the Configurator host, with a RouterOS v7 device
   reachable via HTTPS:
   * Open the MikroTik tab. Type the host (IP literal or DNS name), confirm the URL builder
     accepts it, enter the dedicated `rdpaudit` user + password, click Save. Confirm the password
     is replaced with `***configured***` on the next Refresh — the plaintext is never echoed.
   * Click Test connection. Confirm `MikroTikTestResult.RemoteVerified` is true and HTTP 200.
   * Tick `Add attacker IP block rules to MikroTik Firewall` and `Enable MikroTik integration`,
     click Save.
   * Seed a synthetic attacker IP (e.g. via the Live Events context menu's Block IP action with
     the Firewall provider set to `MikroTik` or `Both`). Confirm
     `/ip/firewall/filter print where comment~"^RdpAudit"` lists the new row on the router and
     `ActiveBlocks` has a matching row with `Provider = MikroTik` and a non-empty `RuleHandle`.
   * Set a short block duration (e.g. 1 minute). Wait for `FirewallExpirationWorker` to run.
     Confirm the row disappears from the router (`/ip/firewall/filter print where comment~"^RdpAudit"`
     returns nothing) and `ActiveBlocks.Status` flips to `Removed`.
   * Manually add a non-RdpAudit rule on the router (`/ip/firewall/filter add chain=input
     action=drop src-address=198.51.100.1 comment="manual"`). Confirm RdpAudit never deletes it.
2. **Stage 10 IPC reservation.** No new ordinals are required; Stage 10 is final QA + polish.
3. **Linux CI baseline.** `dotnet build` + `dotnet test` continue to pass on Linux CI hosts; the
   MikroTik REST client is exercised entirely via fake `HttpMessageHandler`s.

## LLM-safe extension rules

When implementing later stages:

1. **Append-only IPC.** Add new commands at the next ordinal. Never reuse retired ordinals. Add a row in `docs/50-ipc.md` and a payload contract under `RdpAudit.Core.Ipc.Contracts`.
2. **Provider abstraction boundaries.** New firewall providers implement `IFirewallProvider`. New reputation / reporting providers must introduce their own abstraction in `RdpAudit.Core/` before any HTTP client lands in `RdpAudit.Service/`.
3. **Secret handling.** Every new secret-bearing config field is stored as a protected envelope and unwrapped through `ISecretProtector`. Never log the plaintext. Status / test DTOs report only `CredentialPresent` flags.
4. **Backward-compatible defaults.** Existing appsettings.json documents must continue to bind. New options default to safe / disabled values.
5. **Cancellation.** All long-running paths take `CancellationToken`. Never call `.Result` / `.Wait()`.
6. **Auditable & reversible.** Every block / report / shadow action records an audit entry. Shadow-policy mutations require a backup unless explicitly suppressed.
