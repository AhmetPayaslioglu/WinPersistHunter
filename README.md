# WinPersist Hunter

A one-shot Windows persistence-mechanism hunter for blue teams and threat hunters.
Scans 20+ persistence locations in a single run, scores each finding with a risk
model, maps it to MITRE ATT&CK, and produces JSON + HTML reports.

> Stateless, single-run CLI — no daemon, no watcher, no stored baseline.
> Read-only — does not modify the system.

---

## Features

- **22 persistence-hunting modules** covering registry, scheduler, services,
  WMI, Office, browser, COM, drivers (BYOVD), and more
- **Risk scoring engine** — path heuristics, LOLBin detection, PowerShell
  obfuscation, Shannon entropy, RTLO masking, double extension, registry
  key recency, HKCU-shadows-HKLM COM pattern, BYOVD hash match, etc.
- **Cross-correlation** — same executable referenced by multiple persistence
  mechanisms is flagged as a cluster (mature malware pattern)
- **MITRE ATT&CK mapping** — every detection carries a technique ID
- **JSON + HTML reports** — interactive severity-filtered dashboard
- **Zero third-party dependencies** — Python 3.8+ stdlib only

## Modules

| Module               | Technique | What it hunts                                              |
|----------------------|-----------|------------------------------------------------------------|
| `run_keys`           | T1547.001 | HKLM/HKCU Run, RunOnce, RunOnceEx (incl. Wow64)            |
| `scheduled_tasks`    | T1053.005 | `Windows\System32\Tasks` XML parse + heuristics            |
| `services`           | T1543.003 | Services, unquoted paths, ServiceDll, auto-start           |
| `wmi_subs`           | T1546.003 | `__EventFilter`, `__EventConsumer`, bindings               |
| `startup_folders`    | T1547.001 | User + AllUsers Startup, .lnk target parsing               |
| `ifeo`               | T1546.012 | IFEO Debugger + SilentProcessExit                          |
| `winlogon`           | T1547.004 | Shell, Userinit, Notify packages                           |
| `appinit_lsa`        | T1546     | AppInit_DLLs, AppCertDLLs, Authentication Packages         |
| `com_hijack`         | T1546.015 | HKCU CLSID shadowing HKLM (Inproc/Local/TreatAs)           |
| `browser_extensions` | T1176     | Chromium-family extensions: unpacked, off-store, risky perms |
| `office_persistence` | T1137     | Office add-ins, Normal.dotm, Outlook VbaProject.OTM, forms |
| `active_setup`       | T1547.014 | Active Setup `StubPath` (logon-time execution)             |
| `screensaver`        | T1546.002 | `SCRNSAVE.EXE` hijack                                      |
| `netsh_helper`       | T1546.007 | Netsh helper DLLs outside default set                      |
| `bits_jobs`          | T1197     | BITS transfers with `NotifyCmdLine`                        |
| `time_providers`     | T1547.003 | W32Time provider DLLs outside defaults                     |
| `print_monitors`     | T1547.010 | Print monitor DLLs outside default set                     |
| `drivers`            | T1543.003 | Kernel drivers + loldrivers.io BYOVD feed matching         |
| `shim_database`      | T1546.011 | Custom shims (`Custom` / `InstalledSDB`)                   |
| `boot_execute`       | T1547.001 | Session Manager `BootExecute`, `SetupExecute`, SafeBoot    |
| `profile_list`       | T1556     | `ProfileImagePath` redirected outside `C:\Users`           |
| `appx_packages`      | T1546     | Developer / sideloaded AppX packages                       |

## Risk scoring signals

Each finding accumulates points for:

- Path in `AppData`, `Temp`, `ProgramData`, `Public`, `Downloads`, etc.
- LOLBin use (mshta, regsvr32, rundll32, certutil, wmic, ...)
- PowerShell obfuscation tokens (`-enc`, `IEX`, `FromBase64String`, ...)
- High command entropy on long command lines
- **RTLO / right-to-left override** characters in filenames
- **Double extension** (`invoice.pdf.exe`)
- Scripting extensions (`.vbs`, `.hta`, `.ps1`, ...)
- Missing target binary
- Unsigned / invalid signature
- **Registry-key recency** — modified within 7 / 30 days
- "Rare technique" multiplier (WMI subs, IFEO debugger, Winlogon Notify, ...)
- **HKCU shadows HKLM** (COM hijack pattern)
- **BYOVD hash match** (loldrivers.io feed)
- **Cluster size** — same artifact in multiple persistence modules

Severity bands: `info < low < medium < high < critical`.

## Installation

```powershell
git clone https://github.com/AhmetPayaslioglu/WinPersistHunter.git
cd WinPersistHunter
# No pip install needed — stdlib only
python --version   # >= 3.8
```

## Sample report

An example HTML report produced after running the canary harness is committed
at [`samples/sample-report.html`](samples/sample-report.html) — clone the repo
and open it in a browser to see the dashboard, severity filters, and
per-detection artifact / description / reasons layout.

## Usage

```powershell
# Run all modules, write reports to .\output
python winpersist.py

# Pick specific modules
python winpersist.py -m run_keys,wmi_subs,ifeo,com_hijack

# Hide noise, only show medium+
python winpersist.py --min-severity medium

# Skip live loldrivers.io feed download (use cached copy)
python winpersist.py -m drivers --offline-feed

# Hash every driver even without BYOVD feed (slow)
python winpersist.py -m drivers --hash-drivers

# List available modules
python winpersist.py --list-modules
```

Outputs land in `output/report-<UTC-timestamp>.{json,html}`. Open the HTML in a
browser for the interactive dashboard.

### Run as Administrator

Some keys (`SYSTEM\CurrentControlSet`, certain `Tasks` ACLs, WMI subscriptions,
some Office hives) require elevation for full visibility. The tool still runs
as a normal user but will silently skip locations it cannot read.

### One-shot, stateless

Every invocation is a fresh, independent scan. The tool does not write any
configuration, doesn't watch anything, doesn't compare against a previous run.
Only outputs: the report files you point it to. (The `drivers` module caches
the loldrivers feed under `%LOCALAPPDATA%\WinPersistHunter\` so you can run
offline next time; delete it any time, the tool re-downloads.)

## Sample output

```
[CRITICAL]  85  T1546.003     root\subscription\CommandLineEventConsumer
             name : Updater
             value: powershell.exe -nop -w hidden -enc SQBFAFgAIAA...
             - WMI CommandLineEventConsumer (rarely used legitimately)
             - LOLBin used: powershell.exe
             - PowerShell obfuscation tokens: -enc, -nop, -w hidden
             - High command entropy (5.21)
             - Artifact also referenced by: run_keys, scheduled_tasks
```

## Demo / safe canaries

The `canary/` folder ships a setup / teardown pair that plants reversible,
harmless persistence entries across 17 techniques so you can confirm each
module fires on what it's supposed to catch.

```powershell
# Non-admin: 5 HKCU canaries. Admin: ~17 canaries across HKCU + HKLM + WMI + BITS.
.\canary\setup.ps1

# Scan — you should see a detection per planted technique.
python winpersist.py --offline-feed

# Clean up — restores SetupExecute / AppCertDLLs to empty, deletes the rest.
.\canary\teardown.ps1
```

See [`canary/README.md`](canary/README.md) for the full list of techniques
covered and the safety guarantees of the setup script.

## License

MIT
