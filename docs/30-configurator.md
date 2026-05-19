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
| Live Events | `Forms/LiveEventsPage.cs` | **Bonus tab beyond the spec.** Polls the read-only `AuditDbContext` every 2 s and shows the latest 500 `RawEvent` rows with new-row counters. |

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

## Required tests before modifying

- WinForms-specific unit tests are not feasible in CI. Document manual verification steps in the PR description.
- The Service-side IPC tests in `RdpAudit.Service.Tests` must continue to pass after any IPC contract change.
