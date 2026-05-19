# RdpAudit.Configurator

WinForms front-end for setup, monitoring, and configuration.

## Tabs

| Tab | Implementation | Purpose |
|-----|----------------|---------|
| Overview | `Forms/OverviewPage.cs` + `Services/OverviewProbe` + `Services/InstallationService` | First-run "home" tab. Shows product info, version, project/author links, and an aggregate snapshot of ProgramData/DB/service state, surfaces detected errors/warnings, and exposes a single "Install / Repair" button that creates the ProgramData layout (with admin/SYSTEM ACLs), copies the sibling Service distribution into Program Files, and registers/starts the Windows service. |
| Prerequisites | `Forms/PrerequisitesPage.cs` + `Services/PrerequisiteChecker.cs` | Runs the 15 prerequisite probes (OS, .NET, PowerShell, TermService, RDP port, firewall rule, four event channels, privilege, ProgramData write probe, DB existence, audit policy, RunAsPPL). |
| Audit Policy | `Forms/AuditPolicyPage.cs` + `Core.Events.AuditPolicyManager` | Lists the canonical `auditpol` rows; offers elevated buttons for "Apply audit policy" and "Configure SACL". Below the buttons a read-only help block explains each action, defines SACL, and documents the `S=Y/N F=Y/N` column shorthand. Current state is read via the locale-stable `AuditQuerySystemPolicy` advapi32 API with `auditpol /r` CSV as a fallback. |
| Service | `Forms/ServicePage.cs` | sc.exe lifecycle controls + 5-second IPC status refresh + recent-alerts grid with severity coloring. A dedicated "Process:" row shows the running service's PID, executable path, and start time (or `Not running` / `Not installed`), refreshed every 5 s. Start / Stop / Restart / Uninstall / Install each surface a `ServiceOperationResult` dialog containing the action name, per-step OK/FAIL, final service state, PID, executable, and a UTC timestamp. A read-only panel shows install destination, configured database path, and the sibling-distribution discovery result (Configurator → parent → `Service`). The "Install service" button calls `Services/InstallationService` so it shares logic with the Overview tab. |
| Settings | `Forms/SettingsPage.cs` | Loads `RdpAuditOptions` via IPC (falls back to disk). Saves to `%ProgramData%\RdpAudit\appsettings.json`; the service hot-reloads via `IOptionsMonitor<T>`. |
| Live Events | `Forms/LiveEventsPage.cs` + `Core/Events/LiveEventFilter.cs` + `Core/Events/LiveEventRowFormatter.cs` | Live tail of the most recent `RawEvent` rows fetched over `IPC.GetRecentEvents` (currently 200 rows). A filter bar above the grid combines IP / user / event-id / channel / free-text / time-range filters with AND semantics and a 350 ms debounce on text input. A per-cell right-click context menu offers `Copy Event Details` (multiline + TSV), `Copy Cell Value`, `Filter by This Value`, `Block IP in Windows Firewall and Add to Blocklist`, `Add IP to Whitelist and Unblock`, and `Add Login to Blocklist and Block IP`. Every operator action is recorded in a status strip with a UTC timestamp and per-step success/failure detail. All mutations go through IPC handlers — the page never writes to SQLite directly. |

## Service distribution discovery

`Core.Util.ServiceLayout.Discover` resolves the published Service distribution relative to the running
Configurator's `AppContext.BaseDirectory`:

- Sibling rule: `…\publish\Configurator` → `…\publish\Service`
- Install destination: `%ProgramFiles%\RdpAudit\Service` (override with the `RDPAUDIT_INSTALL_DIR` env var)
- DB path: read from `RdpAudit.Storage.DatabasePath` in `appsettings.json`, falling back to
  `%ProgramData%\RdpAudit\rdpaudit.db`

The Overview and Service tabs both call `ServiceLayout.Discover` so the install workflow works on any
machine, regardless of where the user puts the publish output (`C:\1st_RdpMON\Service\publish\…`,
`D:\builds\…`, etc.).

## IPC client contract

`IpcClient.SendAsync<T>` enforces a hard 5-second total timeout and a 2-second connect timeout. On `OperationCanceledException`, `TimeoutException`, or `IOException` it returns `default(T)`. **It must never throw to the UI thread.**

## Threading rules

- Async event handlers (`Click`) are `async void`; everything else returns `Task`.
- Background callbacks always check `InvokeRequired` and marshal back to the UI thread before touching controls.

## LLM contract

- Never call SQLite write paths from the Configurator. Reads through `ReadOnlyDb.Open()` are fine; writes go through the IPC server.
- Any new tab must be added to `MainForm` constructor and follow the existing pattern (5-second refresh timer, `Invoke` dispatch).
- Elevated operations must launch a child process with `Verb = "runas"` and handle UAC cancel (`Win32Exception.NativeErrorCode == 1223`).

## Live Events page (Stage 4)

### Filter bar

The filter bar above the grid exposes six controls:

| Control | Semantics |
|---------|-----------|
| `IP` | Case-insensitive substring match against `SourceIp`. |
| `User / login` | Case-insensitive substring match against `UserName`. |
| `Event id` | Exact integer match against `EventId`. Non-numeric text is ignored. |
| `Channel` | Case-insensitive substring match against `Channel`. |
| `Text` | Case-insensitive substring match across `SourceIp`, `UserName`, `Channel`, `Domain`, `ProcessName`, `AuthPackage`, and the stringified `EventId`. |
| `Time range` | Drop-down: `All time`, `Last 5 minutes`, `Last 15 minutes`, `Last 60 minutes`, `Last 24 hours`. Bound is `DateTime.UtcNow - delta`, inclusive. |

Filters combine with AND semantics. Text inputs are debounced by 350 ms so a typing burst triggers a single refresh. The `Clear filters` button resets every control and re-applies. Filtering is currently performed client-side over the bounded recent-event window returned by the existing `GetRecentEvents` IPC (capped at 200 rows server-side). The predicate (`Core/Events/LiveEventFilter.cs`) is intentionally UI-agnostic so it can be reused once `GetRecentEvents` grows a server-side query.

### Context menu (per-cell)

Right-click on a grid cell opens a menu whose items target the row under the cursor (not the previously-selected row):

| Item | Enable condition | Effect |
|------|------------------|--------|
| `Copy Event Details` | A row exists under the cursor. | Copies both a labelled multiline block and a TSV row (header + data) to the clipboard, joined by a `--- TSV ---` separator. |
| `Copy Cell Value` | Clicked cell has a non-empty, non-placeholder value. | Copies the normalised cell text. Null / blank cells never copy. |
| `Filter by This Value` | Same as `Copy Cell Value`. | Pushes the cell value into the matching filter input (IP, User, Event id, Channel) or into the free-text filter for other columns and applies. |
| `Block IP in Windows Firewall and Add to Blocklist` | Row has a value that parses via `IPAddress.TryParse`. | Confirmation dialog → `AddToBlocklist` IPC + legacy `BlockAddress` IPC (which applies the live firewall rule). Per-step result is shown in the status strip. |
| `Add IP to Whitelist and Unblock` | Same as Block IP. | Confirmation dialog → `AddToWhitelist` IPC (server-side whitelist precedence soft-disables conflicting blocklist rows) + `UnblockAddress` IPC. |
| `Add Login to Blocklist and Block IP` | Row has a non-empty `UserName`. | Confirmation dialog → `AddToBlocklist` IPC with the login; if the row also has a valid IP, also `AddToBlocklist` + `BlockAddress` for the IP. |

### Status strip

A `StatusStrip` along the bottom of the page reports every action and refresh outcome:

```
[12:34:56Z] Copied event details (Id=1234) to clipboard.
[12:35:02Z] Block 203.0.113.5 (OK). blocklist=OK, firewall=OK. Detail: [AddToBlocklist: ok] [BlockAddress: ok]
[12:35:50Z] Whitelist 203.0.113.5 (OK). whitelist=OK, unblock=OK. Detail: [AddToWhitelist: ok] [UnblockAddress: ok]
```

All status updates are pre-stamped with the UTC HH:mm:ss when the action ran and are marshalled to the UI thread when invoked from a continuation.

### IPC commands consumed

- `GetRecentEvents` (2) — populates the grid.
- `AddToBlocklist` (14), `AddToWhitelist` (16) — Stage 3 mutation handlers.
- `BlockAddress` (7), `UnblockAddress` (8) — legacy address-state toggles that also drive the live `netsh advfirewall` rule via `FirewallManager`.

No new IPC ordinals are introduced in Stage 4.

## Required tests before modifying

- WinForms-specific unit tests are not feasible in CI. Document manual verification steps in the PR description.
- The Service-side IPC tests in `RdpAudit.Service.Tests` must continue to pass after any IPC contract change.
