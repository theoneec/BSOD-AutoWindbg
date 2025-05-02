param (
    [int]$Day = 0,
    [int]$Hour = 0
)

<#
.SYNOPSIS
    Download and extract the latest WinDbg (Preview) package, verify dump configuration, and prepare for analysis.

.DESCRIPTION
    This script automates the following tasks:
    1. Checks if any minidump files exist. If not, verifies if crash dump collection is enabled in the system registry.
    2. Retrieves the latest WinDbg msixbundle download URL from Microsoft's AppInstaller endpoint.
    3. Downloads required tools (7zr.exe and 7za.exe) to extract msixbundle contents.
    4. Extracts WinDbg files into a temporary directory for further processing.
    5. Optionally runs WinDbg in CLI mode to analyze dump files older than the selected age or all.

.PARAMETER Day
    Optional. Filter for minidumps older than X days. Cannot be used with -Hour. Default is 0.

.PARAMETER Hour
    Optional. Filter for minidumps older than X hours. Cannot be used with -Day. Default is 0.

.EXAMPLE
    .\YourScript.ps1 -Day 3
    .\YourScript.ps1 -Hour 6

.NOTES
    Exit Codes:
      1 - No dump files found and system crash dump is not enabled
      2 - No dump files found even though crash dump is enabled
      3 - Cannot use both -Day and -Hour simultaneously
      4 - Script must be run as administrator
      5 - MSIX extraction failed
#>

# Show help if -help or /help is passed
if ($args -contains '-help' -or $args -contains '/help') {
    Get-Help -Full $MyInvocation.MyCommand.Path
    exit 0
}

# Ensure script is running as administrator or relaunch with elevation
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "Elevating script to run as Administrator..."
    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
    if ($Day -gt 0) { $argList += "-Day"; $argList += $Day }
    if ($Hour -gt 0) { $argList += "-Hour"; $argList += $Hour }
    Start-Process powershell -ArgumentList $argList -Verb RunAs
    exit 0
}


# Enforce exclusive use of Day or Hour
if ($Day -gt 0 -and $Hour -gt 0) {
    Write-Error "Cannot use both -Day and -Hour parameters simultaneously. Use only one."
    exit 3
}

# Interactive mode if no params passed
if (!$PSBoundParameters.ContainsKey("Day") -and !$PSBoundParameters.ContainsKey("Hour")) {
    do {
        $choice = (Read-Host "Filter by (D)ays, (H)ours, or (A)ll dumps? Enter D, H, or A").ToUpper()
        switch ($choice) {
            "D" {
                do {
                    $inputValue = Read-Host "Enter number of days (0 or more)"
                } while (-not ($inputValue -match '^[0-9]+$'))
                $Day = [int]$inputValue
                break
            }
            "H" {
                do {
                    $inputValue = Read-Host "Enter number of hours (0 or more)"
                } while (-not ($inputValue -match '^[0-9]+$'))
                $Hour = [int]$inputValue
                break
            }
            "A" {
                $Day = 0
                $Hour = 0
                break
            }
            Default {
                Write-Host "Invalid input. Please enter D, H, or A."
            }
        }
    } while ($choice -notin @("D", "H", "A"))
}

# Script Variables
$sevenZipMinimalUrl = "https://www.7-zip.org/a/7zr.exe"
$sevenZipArchiveUrl = "https://www.7-zip.org/a/7z2301-extra.7z"
$tempDir = "$env:TEMP\WinDbgInstaller"
$windbgFile = "$tempDir\windbg.msixbundle"
$sevenZipMinimalExe = "$tempDir\7zr.exe"
$sevenZipArchive = "$tempDir\7z-extra.7z"
$sevenZipExtractDir = "$tempDir\7zcli"
$sevenZipFullExe = "$sevenZipExtractDir\7za.exe"
$windbgExtractDir = "$tempDir\windbg"
$finalMsix = "$windbgExtractDir\windbg_win-x64.msix"
$finalExtractDir = "$tempDir\windbg_final"
$windbgCli = "$finalExtractDir\DbgX.Shell.exe"
$logDir = "C:\temp\debugged"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

# Step 1: Check dump presence
$minidumpPath = "$env:SystemRoot\Minidump"
$dumpFolderExists = Test-Path $minidumpPath -PathType Container
$hasDumps = $false
if ($dumpFolderExists) {
    $hasDumps = (Get-ChildItem -Path $minidumpPath -Filter *.dmp -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0
}
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
$dumpEnabled = Get-ItemPropertyValue -Path $regPath -Name "CrashDumpEnabled" -ErrorAction SilentlyContinue
if (-not $hasDumps) {
    if ($dumpEnabled -eq $null -or $dumpEnabled -eq 0) {
        Write-Error "No dump files found and system crash dump is not enabled."
        exit 1
    } else {
        Write-Error "No dump files found even though crash dump is enabled."
        exit 2
    }
}

# Step 2: Retrieve WinDbg msixbundle
$url = "https://aka.ms/windbg/download"
$response = Invoke-WebRequest -Uri $url -UseBasicParsing
$bytes = $response.RawContentStream.ToArray()
$utf8 = [System.Text.Encoding]::UTF8
$string = $utf8.GetString($bytes)
if ($string[0] -eq [char]0xFEFF) { $string = $string.Substring(1) }
[xml]$xml = $string
$windbgUrl = $xml.AppInstaller.MainBundle.Uri

# Step 3: Download tools
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

# Skip downloads if windbg and 7-zip already present
if (!(Test-Path $windbgCli)) {
    if (!(Test-Path $windbgFile)) {
        Invoke-WebRequest -Uri $windbgUrl -OutFile $windbgFile
    }
    if (!(Test-Path $sevenZipMinimalExe)) {
        Invoke-WebRequest -Uri $sevenZipMinimalUrl -OutFile $sevenZipMinimalExe
    }
    if (!(Test-Path $sevenZipArchive)) {
        Invoke-WebRequest -Uri $sevenZipArchiveUrl -OutFile $sevenZipArchive
    }
} else {
    Write-Host "WinDbg CLI already exists. Skipping download and extraction."
}

# Step 4: Extract MSIX contents
if (!(Test-Path $windbgCli)) {
    if (!(Test-Path $sevenZipFullExe)) {
        Write-Host "Extracting 7z CLI tools..."
        & $sevenZipMinimalExe x $sevenZipArchive -o"$sevenZipExtractDir" -y
    }

    if (!(Test-Path $finalMsix) -and !(Test-Path $finalExtractDir)) {
        Write-Host "Extracting .msixbundle to get windbg_win-x64.msix..."
        & $sevenZipFullExe x $windbgFile -o"$windbgExtractDir" -y
    }

    if (!(Test-Path $windbgCli)) {
        if (!(Test-Path $windbgCli) -and !(Test-Path $windbgCli)) {
        Write-Host "Extracting windbg_win-x64.msix..."
        & $sevenZipFullExe x $finalMsix -o"$finalExtractDir" -y
    } else {
            Write-Error "Expected MSIX file 'windbg_win-x64.msix' not found in $windbgExtractDir."
            exit 5
        }
    }
} else {
    Write-Host "WinDbg CLI is already extracted. Skipping all extraction steps."
}

# Step 5: Filter and debug older dumps
$now = Get-Date

if (-not (Test-Path $windbgCli)) {
    Write-Error "WinDbg CLI not found at expected location: $windbgCli"
    exit 6
}

$WindowsFileset = @()
Write-Host "Days entered: $Day"

if ($choice -eq 'A') {
    # Debug all dump files
    $WindowsFileset = Get-ChildItem -Path $minidumpPath -Filter *.dmp -File
    Write-Host "Debugging all dump files. Found: $($WindowsFileset.Count)"
} else {
    # Always load .dmp files first, even when filtering
    $WindowsFileset = Get-ChildItem -Path $minidumpPath -Filter *.dmp -File

    if ($Day -gt 0) {
        $ageCutoff = $now.AddDays(-$Day)
        # Keep files created ON or AFTER ageCutoff
        $WindowsFileset = $WindowsFileset | Where-Object { $_.CreationTime -ge $ageCutoff }
    }
    elseif ($Hour -gt 0) {
        $ageCutoff = $now.AddHours(-$Hour)
        # Keep files modified ON or AFTER ageCutoff
        $WindowsFileset = $WindowsFileset | Where-Object { $_.LastWriteTime -ge $ageCutoff }
    }

    Write-Host "Filtered dump files. Found: $($WindowsFileset.Count)"
}

if ($WindowsFileset.Count -eq 0) {
    Write-Host "No dump files matched the specified age criteria."
} else {
    foreach ($file in $WindowsFileset) {
        $logFile = "$logDir\$($file.BaseName).txt"
        Write-Host "Analyzing: $($file.FullName)"
        Start-Process -FilePath $windbgCli -ArgumentList "/z `"$($file.FullName)`" /c !analyze -v -logo `"$logFile`" /c q" -Wait -NoNewWindow
    }
    Write-Host "All dump files processed."
}


if ($WindowsFileset.Count -gt 0) {
    # Your Start-Process loop...

    if ($Host.Name -eq 'ConsoleHost') {
        Write-Host "`nScript completed. Debug Path:"
        Write-Host $logDir
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
        [System.Windows.Forms.MessageBox]::Show("Script completed.`nDebug Path: $logDir", "WinDbg Dump Analysis", 'OK', 'Information')
    }
}
