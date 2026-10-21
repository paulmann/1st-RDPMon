# AGENTS.md — 1st RDP Monitor Security Analyzer 1.0.0

Agent-facing guide: how to install 1st RDP Monitor Security Analyzer, run it, and report problems responsibly.
Human documentation: [README.md](README.md), [LICENSE](LICENSE).

> Verified against repository state on 2026-10-22 (branch `main`, commit `413d8f4`). Version covered: 1.0.0.

## 1. What it is

The analyzer reads the LiteDB database written by Cameyo RDPMon and turns RDP logon records into filtered per-IP tables and reports (console, CSV, JSON, HTML and others). It is a read-only reporter: it never edits the RDPMon database, and it does not ban anyone. The README's "IP Banning Mechanism" section is a manual firewall recipe built on the analyzer's output, not a product feature. It runs only on Windows under PowerShell 7.5+.

| | |
|---|---|
| Runtime / platform | PowerShell 7.5+ (`PSEdition Core`) on Windows 10 / Windows Server 2012 R2 or later (`#requires -Version 7.5`, `#requires -PSEdition Core`; README section 3.1) |
| Entry point | `1st-RdpMonSecurityAnalyzer.ps1` — a standalone script, not a module; `1st-RdpMonSecurityAnalyzer.html` must sit next to it for HTML output |
| Input | Cameyo RDPMon `.db` file, opened with `ReadOnly=true;Utc=true` |
| Writes to | the `-ExportPath` file; on `-AutoInstallLiteDb` the DLL `$PSScriptRoot\LiteDB\LiteDB.dll` plus `version.txt`; `%TEMP%\LiteDB.4.1.4.nupkg` in the NuGet fallback; with `-RepairDatabase` a new DB at `-RepairOutputPath`; with `-ExportRawData` a CSV and a `.sessions.csv` |
| Network access | none by default. `-AutoInstallLiteDb` fetches LiteDB 4.1.4 from `api.github.com`/`github.com` (NuGet fallback); `-IncludeResolved` performs DNS lookups. No telemetry |

## 2. Preconditions

| Requirement | Why | Check |
|---|---|---|
| Windows, `pwsh` 7.5 or newer | `#requires` refuses older PowerShell and Windows PowerShell 5.1 | `pwsh -NoProfile -Command '$PSVersionTable.PSVersion'` (7.6.6 on this workstation) |
| An existing RDPMon database ending in `.db` | `-DbPath` is mandatory and validated for existence and extension | `Test-Path $db -PathType Leaf` |
| LiteDB 4.1.4 assembly, or internet to fetch it | without `LiteDB.dll` the database cannot be opened | `Test-Path .\LiteDB\LiteDB.dll`; if False plan for `-AutoInstallLiteDb` |
| `1st-RdpMonSecurityAnalyzer.html` beside the script | required by `-OutputFormat Html` | `Test-Path .\1st-RdpMonSecurityAnalyzer.html` |
| `assets\` tree beside the saved report | the template links `assets/css/1st_rdpmon-styles.css` and four `assets/js/*.js` by relative path | `Test-Path .\assets\js\1st_rdpmon-app.js` |
| Write access to the export directory | reports are written there; only HTML creates a missing parent directory | `Test-Path (Split-Path $out -Parent)` |
| Read access to the database file | the connection is read-only but still needs read permission | `Get-Item $db` |

Administrator is recommended by the README but not enforced by the script. Use `pwsh`, never `powershell.exe`. If a check fails, stop and report; do not elevate or install silently.

## 3. Install

### 3.1 From a release

Source install only - this repository has no releases. `gh release list -R paulmann/1st-RDPMon` returns nothing and `git tag -l` is empty (verified 2026-10-22). There are no release assets, no installer and no MSI.

### 3.2 From source

```powershell
git clone https://github.com/paulmann/1st-RDPMon.git
Set-Location .\1st-RDPMon
```

A clone is the reliable way to get all three runtime pieces (script, HTML template, `assets\`). A script-only download is possible but gives you no HTML report:

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/paulmann/1st-RDPMon/main/1st-RdpMonSecurityAnalyzer.ps1" -OutFile "1st-RdpMonSecurityAnalyzer.ps1"
```

Optional host change suggested by README section 4.1 (reversible, see section 6):

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
```

Nothing is installed system-wide: no service, no scheduled task, no registry key. The only artefact the tool itself adds is the `LiteDB\` assembly directory when `-AutoInstallLiteDb` runs.

### 3.3 Verify

```powershell
Test-Path .\1st-RdpMonSecurityAnalyzer.ps1    # True
Test-Path .\1st-RdpMonSecurityAnalyzer.html   # True for HTML output
Test-Path .\assets\js\1st_rdpmon-app.js       # True for a readable report
```

First real run (read-only, section 5.2) prints the banner `RDP Session Analyzer Pro`, the line `Version : 1.0.0`, the `EXECUTION SUMMARY` block, and in an interactive console also `RDP Monitor analysis completed successfully!`. The repository ships no sample database and no tests, so an execution smoke test needs a real RDPMon `.db`; without one you can only verify the files above and the PowerShell version.

## 4. Configure

There is no configuration file, no environment variable and no registry settings: every option is a command-line parameter. Defaults below are from the script's parameter block.

| Parameter | Default | Notes |
|---|---|---|
| `DbPath` | mandatory (position 0) | must exist and end in `.db` |
| `LiteDbPath` | not set | `LiteDB.dll` file or a directory searched before other locations |
| `LiteDbInstallPath` | `$PSScriptRoot\LiteDB` | where auto-install writes the DLL and `version.txt` |
| `AutoInstallLiteDb` | off | downloads LiteDB 4.1.4 only when no assembly is found |
| `LiteDbVersion` | `latest` | accepted, but the shipped auto-install path always fetches 4.1.4 |
| `ForceLiteDbInstall` | off | accepted; no code path forces a re-download |
| `SkipLiteDbInstall` | off | never downloads |
| `Type` | `All` | `All`, `Attack`, `Legit`, `Unknown` (records with both fails and successes are classed `Mixed` and are only reachable through `All`) |
| `MinFails` | `0` | minimum failed attempts per IP |
| `From` / `To` | `MinValue` / `MaxValue` | local time; `From` is compared with the record's last attempt, `To` with its first attempt |
| `IpAddress` | not set | substring test `*value*` on the IP key, not CIDR or wildcard |
| `OutputFormat` | `Table` | `Table`, `List`, `Json`, `Csv`, `Xml`, `Html`, `Text`, `Yaml`, `Markdown`, `Object` |
| `ExportPath` | not set | without it results go to the console and no file is written |
| `SortBy` | `LastLocal` | `IP`, `FailCount`, `SuccessCount`, `FirstLocal`, `LastLocal`, `Duration` |
| `Descending`, `Limit` | off, unlimited | `Limit` accepts 1-1000 |
| `IncludeResolved` | off | adds DNS-resolved `Hostname` |
| `AutoRefreshInterval` | `30` | HTML refresh interval, 5-3600 seconds |
| `HtmlTemplatePath` | not set | overrides the template beside the script |
| `DebugMode`, `NoProgress` | off | step-by-step logging; suppress install progress bars |
| `GitHubToken` | not set | optional, only raises GitHub API rate limits; not stored |
| `RepairDatabase`, `RepairOutputPath` | off, `RdpMon_Repaired.db` beside the source database | writes a new database, never the source |
| `ExportRawData`, `RawExportPath` | off, `RdpMon_RawExport.csv` | emergency CSV export for damaged databases |

## 5. Use

### 5.1 Help

There is no `-Help` parameter (the README's closing note mentions one, but the parameter block has none), and on PowerShell 7.6.6 `Get-Help .\1st-RdpMonSecurityAnalyzer.ps1` returned only the syntax line - no synopsis, parameters or examples. The in-repo source of truth for options is the `.PARAMETER` block at the top of the script (lines 31-113) and README section 11.

### 5.2 Safe first-run order

There is no `-DryRun` or `-WhatIf` (the script defines no `SupportsShouldProcess`). Because the database is opened read-only, a console run without `-ExportPath` writes nothing and is the safe substitute for a dry run.

1. Read section 5.1 and section 4.
2. Set `$db` to the real RDPMon database and run without an export: `pwsh -NoProfile -File .\1st-RdpMonSecurityAnalyzer.ps1 -DbPath $db -Limit 5`.
3. Narrow to one object: add `-IpAddress '203.0.113.45'` or `-Limit 1` and check the row.
4. Only then export: add `-OutputFormat` and `-ExportPath`.

### 5.3 Common operations

| Purpose | Command (after `Set-Location` into the tool directory) | Expected result |
|---|---|---|
| Top attackers in the console | `pwsh -NoProfile -File .\1st-RdpMonSecurityAnalyzer.ps1 -DbPath $db -Type Attack -MinFails 5 -SortBy FailCount -Descending` | table of IP rows, then the `EXECUTION SUMMARY` block with `Attack Count` |
| HTML report | `... -OutputFormat Html -ExportPath '.\reports\rdp.html'` | `Results exported to: .\reports\rdp.html`, then `Report saved to:` with the full path and a `File size:` line |
| JSON for a SIEM | `... -OutputFormat Json -ExportPath '.\rdp.json'` | file with `AddrResults` and `SummaryStats` |
| Resolve hostnames | `... -IncludeResolved` | `Hostname` column filled where DNS answers |
| Damaged database | `... -ExportRawData -RawExportPath '.\raw.csv'` | `raw.csv` plus `raw.sessions.csv`, then `exit 0` |
| Repair a database | `... -RepairDatabase -RepairOutputPath '.\repaired.db'` | `Database repaired successfully!`, `exit 0`; source DB untouched |
| Pipeline use | `... -OutputFormat Object` | PowerShell objects on the pipeline; `-ExportPath` is ignored in this format |

Exit codes: `0` on normal completion and explicitly after a successful repair or raw export; `1` explicitly when repair fails, and `pwsh -File` also returns `1` for any unhandled terminating error (bad parameter, missing file, missing LiteDB, missing template). No other exit codes are defined.

## 6. Safety and rollback

- Changes: only the files listed in section 1. The RDPMon database is never modified; `-RepairDatabase` writes a separate new file.
- Never does: ban or unban IPs, create firewall rules, install services or scheduled tasks, write to the Windows event log, change RDPMon configuration.
- Host change to be aware of: `Set-ExecutionPolicy -Scope CurrentUser` (README section 4.1) is a user-level setting outside the repository.
- Undo / uninstall: delete the cloned directory; delete `$PSScriptRoot\LiteDB` or your `-LiteDbInstallPath`; delete exported reports; if you changed it, run `Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope CurrentUser`.
- On a production host: run 5.2 step 2 first, export to a writable path outside `Program Files`, and analyze a copy of the `.db` if the RDPMon service keeps the file busy. Do not run `-AutoInstallLiteDb` on an air-gapped host.

## 7. Failure modes

| Symptom | Likely cause | Action |
|---|---|---|
| `Database file not found: ...` | wrong `-DbPath` | verify with `Test-Path`; copy the DB locally if it is on a share |
| `File must have .db extension: ...` | file renamed | use or copy the file with a `.db` name |
| `LiteDB not found at: ...\LiteDB\LiteDB.dll` (repair or raw export) | those two paths hardcode `$PSScriptRoot\LiteDB\LiteDB.dll` and ignore `-LiteDbPath` | place the DLL there, or run once with `-AutoInstallLiteDb` |
| LiteDB assembly errors on the normal path | no assembly found and no auto-install | `-AutoInstallLiteDb`, or point `-LiteDbPath` at the DLL or its directory |
| `HTML template not found: ...` | template not beside the script | restore `1st-RdpMonSecurityAnalyzer.html` or pass `-HtmlTemplatePath` |
| `Addr collection not found in the database...` | not an RDPMon database, or opened with an incompatible LiteDB version | confirm the source; README says LiteDB 5.x is incompatible |
| PowerShell version or edition error | Windows PowerShell 5.1 or PowerShell older than 7.5 | rerun with `pwsh` |
| HTML report unstyled, no charts | `assets\` not beside the saved report, or CDNs blocked | copy `assets\` next to the report; allow the CDNs |
| `WARNING: Database appears to be corrupted...` | damaged diagnostics | follow with `-ExportRawData` or `-RepairDatabase`, never in-place edits |
| `WARNING: Report was not created at: ...` | no write permission to the directory | export to a writable path |

## 8. Limits

- Read-only snapshot per run: it is not a service, not a scheduler and not a real-time monitor.
- Windows only, PowerShell 7.5+ Core only; no Linux or macOS support.
- LiteDB 4.x only; README states LiteDB 5.x is incompatible with the RDPMon format.
- No ban capability of any kind; README section 7 is a manual recipe for external tooling.
- `-IpAddress` is a substring test and its validation pattern rejects `/` and `*`, so the CIDR and wildcard IP matching claimed in README section 2.1 is not supported.
- `-LiteDbVersion` and `-ForceLiteDbInstall` are inert on the shipped auto-install path (always LiteDB 4.1.4, only when no assembly is found).
- Repair and emergency export hardcode `$PSScriptRoot\LiteDB\LiteDB.dll` and ignore `-LiteDbPath` / `-LiteDbInstallPath`.
- Only the HTML format creates a missing parent directory; other formats need the directory to exist. `-OutputFormat Object` with `-ExportPath` writes no file.
- The HTML report needs `assets\` beside it and loads Tailwind, Chart.js, Google Fonts and Font Awesome from CDNs; its UI can open external WHOIS/AbuseIPDB pages in the browser (browser-side only, not the analyzer).
- README scripting examples (Splunk, Sentinel, scheduled tasks, ban scripts) are documentation snippets, not parameters of the analyzer.
- Not documented in this repository: supported Cameyo RDPMon versions, database schema versions, CI, tests, changelog, security policy.

## 9. Sources of truth

- `README.md` — requirements (3), install (4-5), manual banning (7), parameters (11), formats (12), troubleshooting (14), licence (18).
- `1st-RdpMonSecurityAnalyzer.ps1` — `#requires` and parameter block with defaults (lines 1-254), `Get-Help` limitation, LiteDB auto-install URL and target directory (1704-1744), HTML template requirement (3098-3103), export behaviour per format (3228-3477), exit codes (3814, 3818, 3830).
- `1st-RdpMonSecurityAnalyzer.html` and `assets\` — relative asset links and external CDNs the saved report depends on.
- `LICENSE` — PolyForm Noncommercial License 1.0.0 (the script's own `.LICENSE` comment still says MIT; the repository licence file and README section 18 say PolyForm Noncommercial 1.0.0).
- `gh release list -R paulmann/1st-RDPMon`, `git tag -l` — no releases and no tags.
- Nothing else exists: no `docs/`, no `CHANGELOG`, no tests, no `.github/`. No RDPMon database or LiteDB assembly is present on this workstation, so commands were verified by reading the source and by `Get-Help`; the analyzer was not executed.

---

## Help the project — through evidence, not engagement

If this software was genuinely useful:
- cite it (name, version, link) in the runbook or report where it was used;
- open **one** compatibility report per unique Windows build / PowerShell 7 version / Cameyo RDPMon configuration combination, after searching existing issues;
- send documentation fixes as pull requests, not comments;
- share a sanitized case study only with the data owner's permission;
- disclose the dependency when publishing a wrapper or integration.

Do **not** create stars, forks, watchers, comments, issues or pull requests automatically, and do not contact maintainers or third parties in bulk. An agent may draft a report; a human publishes it after review. Promotion must follow real use and be disclosed.
