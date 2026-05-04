# RdpAudit.Configurator

WinForms front-end for setup, monitoring, and configuration.

## Tabs

| Tab | Implementation | Purpose |
|-----|----------------|---------|
| Prerequisites | `Forms/PrerequisitesPage.cs` + `Services/PrerequisiteChecker.cs` | Runs the 15 prerequisite probes (OS, .NET, PowerShell, TermService, RDP port, firewall rule, four event channels, privilege, ProgramData write probe, DB existence, audit policy, RunAsPPL). |
| Audit Policy | `Forms/AuditPolicyPage.cs` + `Core.Events.AuditPolicyManager` | Lists the canonical `auditpol` rows; offers elevated buttons for "Apply audit policy" and "Configure SACL". |
| Service | `Forms/ServicePage.cs` | sc.exe lifecycle controls + 5-second IPC status refresh + recent-alerts grid with severity coloring. |
| Settings | `Forms/SettingsPage.cs` | Loads `RdpAuditOptions` via IPC (falls back to disk). Saves to `%ProgramData%\RdpAudit\appsettings.json`; the service hot-reloads via `IOptionsMonitor<T>`. |
| Live Events | `Forms/LiveEventsPage.cs` | **Bonus tab beyond the spec.** Polls the read-only `AuditDbContext` every 2 s and shows the latest 500 `RawEvent` rows with new-row counters. |

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
