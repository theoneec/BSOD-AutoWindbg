# BSOD-AutoWindbg.ps1

A PowerShell script to automatically set up **WinDbg Preview CLI** and perform crash dump analysis on Windows systems.

---

## 🛠️ Features

* ❌ Checks for minidump files and verifies crash dump settings in the registry.
* 🚀 Automatically downloads the latest **WinDbg Preview (msixbundle)** from Microsoft.
* 📦 Downloads and uses 7-Zip (`7zr.exe`, `7za.exe`) to extract WinDbg binaries.
* ⚙️ Extracts and runs `DbgX.Shell.exe` for CLI analysis.
* ⏳ Supports filtering by age (days or hours) or analyzing all dump files.
* 🧠 Uses `!analyze -v` and saves analysis logs to `C:\temp\debugged`.
* 💬 Supports interactive prompts when run without parameters.
* ⛨️ Automatically elevates to Administrator if needed.

---

## 📅 Prerequisites

* Windows PowerShell 5.x or higher
* Internet access to download tools
* Administrator privileges (auto-elevated)

---

## 🚀 Usage

### 1. Run Directly (No Download Required)

You can run the script from GitHub in one line:

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/theoneec/BSOD-AutoWindbg/main/BSOD-AutoWindbg.ps1" -OutFile "$env:TEMP\BSOD-AutoWindbg.ps1"; & "$env:TEMP\BSOD-AutoWindbg.ps1" -Day 3
```

Replace `-Day 3` with your desired parameters (`-Hour 6`, or omit for interactive mode).

### 2. Scripted Mode (via local file)

```powershell
.\BSOD-AutoWindbg.ps1 -Day 3      # Analyze dumps created in the last 3 days
.\BSOD-AutoWindbg.ps1 -Hour 6     # Analyze dumps from the last 6 hours
```

### 3. Interactive Mode

Just run the script without arguments:

```powershell
.\BSOD-AutoWindbg.ps1
```

You will be prompted to choose between analyzing by:

* Days
* Hours
* All dump files

---

## 📂 Output Location

All log files are saved to:

```
C:\temp\debugged\
```

Each `.dmp` file is analyzed and output as a `.txt` file using the same base name.

---

## ❌ Exit Codes

| Code | Meaning                                           |
| ---- | ------------------------------------------------- |
| 1    | No dump files found and crash dumps disabled      |
| 2    | No dump files found but crash dumps enabled       |
| 3    | Both `-Day` and `-Hour` parameters used (invalid) |
| 4    | Script not run as administrator                   |
| 5    | MSIX extraction failed                            |
| 6    | WinDbg CLI not found after extraction             |

---

## 🧰 Components

* [WinDbg Preview](https://aka.ms/windbg/download) – From Microsoft’s AppInstaller
* [7-Zip Tools](https://www.7-zip.org/) – For archive extraction (`7zr.exe`, `7za.exe`)

---

## 🙏 Acknowledgements

* Microsoft for WinDbg and AppInstaller feed
* Igor Pavlov for 7-Zip utility
