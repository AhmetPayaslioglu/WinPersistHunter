# Canary tests

Reversible "canary" persistence entries used to validate that WinPersist
Hunter modules light up on the techniques they're supposed to catch.

## What gets planted

| Module             | Canary                                                          | Admin? |
|--------------------|-----------------------------------------------------------------|--------|
| `run_keys`         | HKCU Run value with `-enc` obfuscated PowerShell                | no     |
| `run_keys`         | HKCU RunOnce pointing at `C:\Users\Public\Downloads\...`        | no     |
| `startup_folders`  | `.vbs` script in the user's Startup folder                      | no     |
| `screensaver`      | `SCRNSAVE.EXE` redirected to AppData                            | no     |
| `com_hijack`       | HKCU CLSID shadow of `Shell.Application` (HKLM)                 | no     |
| `ifeo`             | IFEO `Debugger` on a fake `WPH_CANARY_target.exe`               | admin  |
| `winlogon`         | `UserinitMprLogonScript` set                                    | admin  |
| `active_setup`     | New Active Setup component with `StubPath` → AppData            | admin  |
| `netsh_helper`     | New helper DLL registration under HKLM\\Software\\Microsoft\\Netsh | admin  |
| `time_providers`   | Fake W32Time provider with `DllName`                            | admin  |
| `print_monitors`   | Fake print monitor with `Driver`                                | admin  |
| `shim_database`    | Custom InstalledSDB entry pointing at a fake `.sdb`             | admin  |
| `boot_execute`     | Session Manager `SetupExecute` populated                        | admin  |
| `appinit_lsa`      | `AppCertDLLs` populated                                         | admin  |
| `scheduled_tasks`  | Hidden, non-Microsoft task running `mshta`                      | admin  |
| `bits_jobs`        | Suspended BITS job with `NotifyCmdLine`                         | admin  |
| `wmi_subs`         | `__EventFilter` + `CommandLineEventConsumer` + binding          | admin  |

All canaries:

* are tagged `WPH_CANARY_*` so teardown is reliable;
* point at calc.exe, notepad.exe, or non-existent paths — none of them
  actually run malicious code;
* are deliberately unreachable when possible (HKCU on a CLSID that requires
  a missing DLL, etc.) so they don't fire on logon even if you forget the
  teardown step.

## Usage

```powershell
# Non-admin: plants the HKCU-only canaries (~5 entries).
# Admin: plants everything (~17 entries).
.\canary\setup.ps1

# Scan with the tool — you should see one detection per planted technique.
python winpersist.py --offline-feed

# Clean everything up.
.\canary\teardown.ps1
```

## Expected detections (admin run, clean baseline)

After `setup.ps1` you should see ~16 findings spread across these modules,
typically with severities `medium` or `high` (the obfuscated PowerShell
canary in particular should score high — LOLBin + encoded-command + suspicious
path signals stack).

If a planted canary does **not** light up, that module either:

* has a gating bug (should be fixed);
* the canary attempted to reach a state your host blocks (e.g. tamper
  protection on Defender keys);
* you're not admin and the canary requires it (check `setup.ps1` output).

## Safety notes

* `setup.ps1` never overwrites a value with a name your system already
  uses — every canary uses a `WPH_CANARY_*` name or a deliberately fake GUID.
* The Office canary is `Normal.dotm`-aware: if the file already exists,
  the script skips it rather than touching your global template.
* The screensaver canary is reverted to empty by teardown.
* `SetupExecute` and `AppCertDLLs` are restored to empty `MULTI_SZ`, not
  deleted, to match the default-Windows state.

Never run `setup.ps1` on a host you do not own or control.
