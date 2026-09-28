# BSOD-AutoWindbg

Automated Windows BSOD (bugcheck) dump analysis. It has two modes: a **CLI** for RMM tools and scheduled tasks, and a **GUI** for technicians.

It finds the crash dumps, or analyses the dump you point it at. It gets the Microsoft debugger engine automatically, runs `!analyze -v` against Microsoft's public symbols, and gives you a readable diagnosis and machine-readable JSON/CSV.

---

## Features

- **Zero setup.** It finds `kd.exe`/`cdb.exe` in this order:
  1. The Windows SDK/WDK
  2. The installed WinDbg app
  3. A cached copy
  4. The latest WinDbg package downloaded from Microsoft, then unpacked (MSIX is a ZIP container, so 7-Zip isn't needed).
- **Point it at any dump.** Use `-DumpPath` with files or folders, or drag `.dmp` files onto `BSOD-AutoWindbg.cmd` or onto the GUI window.
- **System scan.** Reads `MinidumpDir` and `DumpFile` from `CrashControl`, so it picks up `Minidump\*.dmp` and `MEMORY.DMP`.
- **Parsed results** for each dump:
  - Bugcheck code, name and parameters
  - Faulting image and module
  - Failure bucket
  - Process
  - Crash time and uptime
  - Top of the stack
- **Driver lookup.** For local dumps it reports the faulting driver's vendor, version, date and signer, and flags third-party drivers.
- **Plain-English recommendations.** There are hints for about 40 common bugchecks, for generic or hardware-type failures, and for symbol problems.
- **Event Log context.** It counts the last 30 days of BugCheck (1001), Kernel-Power 41, unexpected shutdown (6008) and WHEA hardware-error events.
- **RMM-safe.**
  - It never prompts in non-interactive sessions.
  - `-Json` gives output a script can parse.
  - Exit codes are meaningful.
  - Each dump has a timeout.
  - Dumps already analysed are skipped.
- **GUI.**
  - Results grid
  - Diagnosis, raw debugger output and activity tabs
  - Buttons to copy a summary for a ticket and to open the reports folder
- **Remediation.** `-EnableCrashDumps` turns on dump collection when it's disabled.
- **Elevates only when needed.** Admin is needed for system dumps and registry changes. Dumps you point it at are analysed without elevation.

---

## Usage

### Technician (GUI)

- Double-click **`BSOD-AutoWindbg.cmd`**. It opens the GUI; click **This PC's dumps**.
- To analyse specific files, drag `.dmp` files or folders onto `BSOD-AutoWindbg.cmd` or onto the open window.

```powershell
.\BSOD-AutoWindbg.ps1                  # interactive desktop -> GUI
.\BSOD-AutoWindbg.ps1 -Gui D:\cases\PC42\
```

### CLI

```powershell
.\BSOD-AutoWindbg.ps1 -NoGui                      # all new system dumps
.\BSOD-AutoWindbg.ps1 -Days 7                     # last 7 days (-Day still works)
.\BSOD-AutoWindbg.ps1 -Hours 6                    # last 6 hours (-Hour still works)
.\BSOD-AutoWindbg.ps1 -Latest 1                   # newest dump only
.\BSOD-AutoWindbg.ps1 -NoGui C:\dumps\a.dmp C:\dumps\b.dmp  # paths only + interactive desktop = GUI
.\BSOD-AutoWindbg.ps1 -DumpPath \\server\share\crashes -OutputPath D:\reports -Force
```

### RMM (runs as SYSTEM, non-interactive)

```powershell
$p = "$env:ProgramData\BSOD-AutoWindbg\BSOD-AutoWindbg.ps1"
New-Item -ItemType Directory -Force (Split-Path $p) | Out-Null
Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/theoneec/BSOD-AutoWindbg/main/BSOD-AutoWindbg.ps1" -OutFile $p
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $p -Days 30 -NoGui -Json -EnableCrashDumps
exit $LASTEXITCODE
```

- Always pass `-NoGui` from RMM. Some agents run scripts as the logged-on user, and the script would otherwise open a window.
- Use `-Json` when the RMM parses stdout. Leave it off to get a human-readable summary for ticket notes.
- The debugger is cached in `%ProgramData%\BSOD-AutoWindbg\tools` and symbols in `%ProgramData%\BSOD-AutoWindbg\symbols`, so later runs are fast.

Example console summary:

```
BSOD summary for PC42: 3 analysed, 0 failed. Reports: C:\temp\debugged
  2x  0x000000D1 DRIVER_IRQL_NOT_LESS_OR_EQUAL / e1d68x64.sys
  1x  0x00000124 WHEA_UNCORRECTABLE_ERROR / GenuineIntel
  -> DRIVER_IRQL_NOT_LESS_OR_EQUAL - driver bug (commonly network, storage, AV). Update/roll back the named driver.
  -> Faulting driver e1d68x64.sys is third-party (Intel Corporation, v12.19.1.37, 2023-04-11). Update or remove it first.
  Last 30 days: 3 bugcheck events, 4 unexpected shutdowns, 1 WHEA hardware errors
```

---

## Parameters

| Parameter | Description |
| --- | --- |
| `-DumpPath` | Dump files and/or folders (positional). Default: the system dump locations |
| `-Days` / `-Hours` | Only dumps written in the last N days or hours (aliases `-Day` / `-Hour`) |
| `-Latest` | Only the N newest dumps |
| `-OutputPath` | Report folder. Default `C:\temp\debugged` |
| `-ToolsPath` | Debugger cache. Default `%ProgramData%\BSOD-AutoWindbg\tools` |
| `-SymbolPath` | Symbol path. Default: Microsoft symbol server, with a local cache |
| `-DebuggerPath` | Use a specific `kd.exe` or `cdb.exe`, or a folder that contains one |
| `-TimeoutMinutes` | Timeout for each dump. Default 15 |
| `-Force` | Re-analyse dumps that already have a report |
| `-UpdateDebugger` | Ignore installed and cached debuggers and download the latest from Microsoft |
| `-SkipSystemMemoryDump` | Don't include `MEMORY.DMP` in the system scan |
| `-EnableCrashDumps` | Turn on crash dump collection if it's disabled |
| `-Json` | Write only the JSON summary to stdout |
| `-Quiet` | Suppress progress output |
| `-Gui` / `-NoGui` | Force the GUI or the CLI |

## Output

In `-OutputPath`:

- `<dump>_<timestamp>.log`: raw debugger output
- `<dump>_<timestamp>.json`: parsed result and recommendations
- `summary.json` / `summary.csv`: the latest run
- `BSOD-AutoWindbg.run.log`: activity log

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0  | Completed. No dumps found, or no dumps match the filter. Crash dumps are enabled |
| 1  | No dumps found, and crash dump collection is **disabled** |
| 3  | Invalid parameters |
| 4  | Admin rights required in a non-interactive session (or elevation declined) |
| 5  | The debugger could not be acquired |
| 10 | Dumps analysed. Crash evidence is present |
| 11 | Dumps analysed, but some failed |
| 12 | Every dump failed to analyse |

> **Changed from v1:** exit code 2 ("no dumps but enabled") is now 0. Codes 10 and above mean crashes were found.

---

## Requirements

- Windows 10/11 or Server 2016+, with Windows PowerShell 5.1 or PowerShell 7
- Internet access to `aka.ms`, `*.microsoft.com` and `msdl.microsoft.com`, for the first debugger download and for symbols. On offline machines, use `-DebuggerPath` and `-SymbolPath` with local copies.

## Tests

```powershell
.\tests\Test-Parser.ps1
```

CI (`.github/workflows/test.yml`) runs on `windows-latest` and does the following:

- Parse checks under PowerShell 5.1 and 7
- Parser tests
- PSScriptAnalyzer
- A CLI smoke test
- A real debugger download from Microsoft

## Components

- [WinDbg / Debugging Tools for Windows](https://aka.ms/windbg/download): Microsoft's debugger engine (`dbgeng`), downloaded at runtime and never redistributed.
- Microsoft public symbol server: `https://msdl.microsoft.com/download/symbols`
