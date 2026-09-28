<#
.SYNOPSIS
    Fully automated Windows BSOD (bugcheck) dump analyser - CLI for RMM, GUI for technicians.

.DESCRIPTION
    Finds Windows crash dumps (or analyses the dump/folder you point it at), acquires the
    Microsoft debugger engine automatically (kd.exe / cdb.exe), runs !analyze -v with the
    Microsoft public symbol server, and produces:

      * <dump>.log   raw debugger output
      * <dump>.json  parsed result (bugcheck, faulting module/driver, bucket, stack, hints)
      * summary.json / summary.csv for the whole run

    Modes
      CLI  - default whenever parameters are given or the session is non-interactive
             (RMM agents running as SYSTEM, scheduled tasks). Never prompts.
      GUI  - WinForms window. Opens with -Gui, or automatically when launched with no
             parameters from an interactive desktop session (double-click / drag-and-drop
             onto BSOD-AutoWindbg.cmd).

    Debugger acquisition order
      1. -DebuggerPath
      2. Cached copy under -ToolsPath
      3. Debugging Tools for Windows (Windows SDK / WDK install)
      4. Installed WinDbg app (Microsoft.WinDbg Appx package)
      5. Download the latest WinDbg package from Microsoft (aka.ms/windbg/download) and
         extract it (MSIX is a ZIP container - no 7-Zip required)

.PARAMETER DumpPath
    One or more dump files and/or folders to analyse. When omitted the system dump
    locations are scanned (CrashControl MinidumpDir + DumpFile, i.e. Minidump\*.dmp and
    MEMORY.DMP).

.PARAMETER Days
    Only analyse dumps written in the last N days. Alias: -Day.

.PARAMETER Hours
    Only analyse dumps written in the last N hours. Alias: -Hour.

.PARAMETER Latest
    Only analyse the N most recent dumps.

.PARAMETER OutputPath
    Where reports are written. Default: C:\temp\debugged

.PARAMETER ToolsPath
    Where the downloaded debugger is cached. Default: %ProgramData%\BSOD-AutoWindbg\tools

.PARAMETER SymbolPath
    Debugger symbol path. Default: srv*<ToolsPath>\..\symbols*https://msdl.microsoft.com/download/symbols

.PARAMETER DebuggerPath
    Explicit path to kd.exe / cdb.exe (or a folder containing them).

.PARAMETER TimeoutMinutes
    Per-dump analysis timeout. The debugger is killed when exceeded. Default 15.

.PARAMETER Force
    Re-analyse dumps that already have a report in -OutputPath.

.PARAMETER UpdateDebugger
    Re-download the debugger even if a cached copy exists.

.PARAMETER SkipSystemMemoryDump
    Do not include the full/kernel MEMORY.DMP when scanning system locations.

.PARAMETER EnableCrashDumps
    If crash dump collection is disabled, enable it (Automatic memory dump + minidumps).

.PARAMETER Json
    Write the run summary as JSON to stdout and nothing else (for RMM parsing).

.PARAMETER Quiet
    Suppress progress output. The final one-line summary is still written.

.PARAMETER Gui
    Open the graphical interface.

.PARAMETER NoGui
    Never open the graphical interface or any message box.

.EXAMPLE
    .\BSOD-AutoWindbg.ps1
    Interactive desktop: opens the GUI. Non-interactive: analyses all new system dumps.

.EXAMPLE
    .\BSOD-AutoWindbg.ps1 -Days 7 -NoGui
    Analyse dumps from the last 7 days, console output only.

.EXAMPLE
    .\BSOD-AutoWindbg.ps1 -DumpPath D:\cases\PC42\031525-8171-01.dmp
    Analyse one specific dump.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File BSOD-AutoWindbg.ps1 -Latest 1 -Json
    RMM usage: analyse the newest dump and emit machine-readable JSON.

.NOTES
    Exit codes
      0  Completed. No crash dumps found (or none new), crash dump collection enabled.
      1  No crash dumps found and crash dump collection is DISABLED.
      3  Invalid parameters.
      4  Administrator rights required but not available (non-interactive session).
      5  Debugger could not be acquired.
      10 Completed. One or more crash dumps analysed (crash evidence present).
      11 Completed with errors. Some dumps failed to analyse.
      12 All dumps failed to analyse.
#>
[CmdletBinding()]
param (
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$DumpPath,

    [Alias('Day')]
    [ValidateRange(0, 3650)]
    [int]$Days = 0,

    [Alias('Hour')]
    [ValidateRange(0, 87600)]
    [int]$Hours = 0,

    [ValidateRange(0, 10000)]
    [int]$Latest = 0,

    [string]$OutputPath = 'C:\temp\debugged',

    [string]$ToolsPath = (Join-Path $env:ProgramData 'BSOD-AutoWindbg\tools'),

    [string]$SymbolPath,

    [string]$DebuggerPath,

    [ValidateRange(1, 600)]
    [int]$TimeoutMinutes = 15,

    [switch]$Force,
    [switch]$UpdateDebugger,
    [switch]$SkipSystemMemoryDump,
    [switch]$EnableCrashDumps,
    [switch]$Json,
    [switch]$Quiet,
    [switch]$Gui,
    [switch]$NoGui,

    # Internal: set when the script relaunches itself elevated from a console, so the window stays open.
    [Parameter(DontShow)]
    [switch]$PauseOnExit
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest progress bar is extremely slow on PS 5.1

$script:Version = '2.0.0'
$script:GuiLogBox = $null
$script:RunLogFile = $null
$script:ExitCode = 0
$script:Busy = $false
$script:BoundParams = @{} + $PSBoundParameters

#region ---------- Output helpers ----------

function Write-Status {
    param([string]$Message, [ValidateSet('Info', 'Warn', 'Error', 'Ok')][string]$Level = 'Info')
    $line = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message
    if ($script:RunLogFile) {
        try { Add-Content -LiteralPath $script:RunLogFile -Value "$Level $line" -Encoding UTF8 } catch { }
    }
    if ($script:GuiLogBox) {
        $script:GuiLogBox.AppendText($line + [Environment]::NewLine)
        [System.Windows.Forms.Application]::DoEvents()
        return
    }
    if ($Json -or ($Quiet -and $Level -in 'Info', 'Ok')) { return }
    $color = @{ Info = 'Gray'; Warn = 'Yellow'; Error = 'Red'; Ok = 'Green' }[$Level]
    Write-Host $line -ForegroundColor $color
}

function Invoke-UiPump {
    if ($script:GuiLogBox) { [System.Windows.Forms.Application]::DoEvents() }
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-InteractiveDesktop {
    # Session 0 = services / SYSTEM (RMM agents). No desktop to draw a window on.
    if (-not [Environment]::UserInteractive) { return $false }
    # RMM agents and schedulers redirect stdio even when running as the logged-on user.
    try { if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) { return $false } } catch { }
    try {
        if ([System.Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) { return $false }
    } catch { }
    return $true
}

#endregion

#region ---------- Crash dump configuration ----------

function Get-CrashDumpConfig {
    $reg = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
    $props = Get-ItemProperty -Path $reg -ErrorAction SilentlyContinue
    $enabled = $null; $minidumpDir = $null; $dumpFile = $null
    if ($props) {
        if ($props.PSObject.Properties['CrashDumpEnabled']) { $enabled = [int]$props.CrashDumpEnabled }
        if ($props.PSObject.Properties['MinidumpDir'])      { $minidumpDir = [Environment]::ExpandEnvironmentVariables($props.MinidumpDir) }
        if ($props.PSObject.Properties['DumpFile'])         { $dumpFile = [Environment]::ExpandEnvironmentVariables($props.DumpFile) }
    }
    if (-not $minidumpDir) { $minidumpDir = Join-Path $env:SystemRoot 'Minidump' }
    if (-not $dumpFile)    { $dumpFile = Join-Path $env:SystemRoot 'MEMORY.DMP' }

    $typeName = switch ($enabled) {
        0 { 'None (disabled)' }
        1 { 'Complete memory dump' }
        2 { 'Kernel memory dump' }
        3 { 'Small memory dump (minidump)' }
        7 { 'Automatic memory dump' }
        default { if ($null -eq $enabled) { 'Unknown' } else { "Other ($enabled)" } }
    }
    [pscustomobject]@{
        CrashDumpEnabled = $enabled
        DumpType         = $typeName
        Enabled          = ($null -ne $enabled -and $enabled -ne 0)
        MinidumpDir      = $minidumpDir
        DumpFile         = $dumpFile
    }
}

function Enable-CrashDumpCollection {
    $reg = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
    Set-ItemProperty -Path $reg -Name CrashDumpEnabled -Value 7 -Type DWord   # Automatic memory dump
    Set-ItemProperty -Path $reg -Name MinidumpDir -Value '%SystemRoot%\Minidump' -Type ExpandString
    Write-Status 'Crash dump collection enabled (Automatic memory dump). A reboot may be required to take effect.' Ok
}

#endregion

#region ---------- Dump discovery ----------

function Get-DumpFiles {
    param(
        [string[]]$Paths,
        [switch]$IncludeSystemMemoryDump,
        $Config
    )
    $files = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    if ($Paths -and $Paths.Count -gt 0) {
        foreach ($p in $Paths) {
            if (-not $p) { continue }
            $p = $p.Trim('"')
            if (Test-Path -LiteralPath $p -PathType Container) {
                Get-ChildItem -LiteralPath $p -Filter *.dmp -File -Recurse -ErrorAction SilentlyContinue |
                    ForEach-Object { $files.Add($_) }
            } elseif (Test-Path -LiteralPath $p -PathType Leaf) {
                $files.Add((Get-Item -LiteralPath $p))
            } else {
                Write-Status "Path not found: $p" Warn
            }
        }
    } else {
        if (Test-Path -LiteralPath $Config.MinidumpDir -PathType Container) {
            Get-ChildItem -LiteralPath $Config.MinidumpDir -Filter *.dmp -File -ErrorAction SilentlyContinue |
                ForEach-Object { $files.Add($_) }
        }
        if ($IncludeSystemMemoryDump -and (Test-Path -LiteralPath $Config.DumpFile -PathType Leaf)) {
            $files.Add((Get-Item -LiteralPath $Config.DumpFile))
        }
    }
    # De-duplicate and sort newest first
    $files | Sort-Object FullName -Unique | Sort-Object LastWriteTime -Descending
}

function Select-DumpFiles {
    param($Files, [int]$Days, [int]$Hours, [int]$Latest)
    $result = @($Files)
    if ($Days -gt 0) {
        $cutoff = (Get-Date).AddDays(-$Days)
        $result = @($result | Where-Object { $_.LastWriteTime -ge $cutoff })
    } elseif ($Hours -gt 0) {
        $cutoff = (Get-Date).AddHours(-$Hours)
        $result = @($result | Where-Object { $_.LastWriteTime -ge $cutoff })
    }
    if ($Latest -gt 0) { $result = @($result | Select-Object -First $Latest) }
    return , $result
}

#endregion

#region ---------- Debugger acquisition ----------

function Get-HostArchToken {
    $arch = $env:PROCESSOR_ARCHITEW6432
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    switch ($arch) {
        'ARM64' { return 'arm64' }
        'x86'   { return 'x86' }
        default { return 'amd64' }
    }
}

function Find-DebuggerInFolder {
    # Returns the best kd.exe / cdb.exe under a folder, preferring the host architecture.
    param([string]$Root)
    if (-not $Root -or -not (Test-Path -LiteralPath $Root)) { return $null }
    $arch = Get-HostArchToken
    $archAliases = @{ amd64 = @('amd64', 'x64'); arm64 = @('arm64'); x86 = @('x86', 'i386') }[$arch]
    $candidates = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Include kd.exe, cdb.exe -ErrorAction SilentlyContinue)
    if ($candidates.Count -eq 0) { return $null }
    $ranked = $candidates | Sort-Object @{
        Expression = { if ($archAliases -contains $_.Directory.Name.ToLower()) { 0 } else { 1 } }
    }, @{
        Expression = { if ($_.Name -ieq 'kd.exe') { 0 } else { 1 } }   # kd is purpose-built for kernel dumps
    }
    return $ranked[0].FullName
}

function Test-MicrosoftSigned {
    param([string]$Path)
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path
        if ($sig.Status -ne 'Valid') { return [string]$sig.Status }
        if ($sig.SignerCertificate.Subject -match 'O=Microsoft Corporation') { return 'Valid' }
        return 'NotMicrosoft'
    } catch {
        return 'Unknown'
    }
}

function Save-WebFile {
    param([string]$Uri, [string]$OutFile)
    Write-Status "Downloading $Uri"
    if ($script:GuiLogBox) {
        # Async download so the window stays responsive
        $wc = New-Object System.Net.WebClient
        $task = $wc.DownloadFileTaskAsync($Uri, $OutFile)
        while (-not $task.IsCompleted) { Start-Sleep -Milliseconds 150; Invoke-UiPump }
        if ($task.IsFaulted) { throw $task.Exception.GetBaseException() }
        $wc.Dispose()
    } else {
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing
    }
}

function Expand-ZipContainer {
    # MSIX / MSIXBUNDLE files are ZIP (OPC) containers; ZipFile does not care about the extension.
    param([string]$Path, [string]$Destination)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Recurse -Force }
    [System.IO.Compression.ZipFile]::ExtractToDirectory($Path, $Destination)
}

function Install-WinDbgPackage {
    param([string]$ToolsPath)
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $downloadDir = Join-Path $ToolsPath 'download'
    $engineDir = Join-Path $ToolsPath 'windbg'
    New-Item -ItemType Directory -Force -Path $downloadDir | Out-Null

    Write-Status 'Resolving latest WinDbg package from Microsoft...'
    $resp = Invoke-WebRequest -Uri 'https://aka.ms/windbg/download' -UseBasicParsing
    $text = if ($resp.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($resp.Content) } else { [string]$resp.Content }
    $text = $text.TrimStart([char]0xFEFF)
    [xml]$xml = $text
    $bundleUri = $xml.AppInstaller.MainBundle.Uri
    $bundleVer = $xml.AppInstaller.MainBundle.Version
    if (-not $bundleUri) { throw 'Could not read MainBundle.Uri from the WinDbg AppInstaller manifest.' }
    if ($bundleUri -notmatch '^https://[^/]*\.microsoft\.com/') { throw "Unexpected WinDbg download host: $bundleUri" }
    Write-Status "WinDbg version $bundleVer"

    $bundleFile = Join-Path $downloadDir 'windbg.msixbundle'
    Save-WebFile -Uri $bundleUri -OutFile $bundleFile

    $bundleDir = Join-Path $downloadDir 'bundle'
    Write-Status 'Extracting package bundle...'
    Expand-ZipContainer -Path $bundleFile -Destination $bundleDir

    $archMap = @{ amd64 = 'x64'; arm64 = 'arm64'; x86 = 'x86' }
    $want = $archMap[(Get-HostArchToken)]
    $msix = Get-ChildItem -LiteralPath $bundleDir -Filter *.msix -File |
        Sort-Object @{ Expression = { if ($_.Name -match "[_-]$want\.msix$") { 0 } elseif ($_.Name -match '[_-]x64\.msix$') { 1 } else { 2 } } } |
        Select-Object -First 1
    if (-not $msix) { throw 'No .msix package found inside the WinDbg bundle.' }

    Write-Status "Extracting $($msix.Name)..."
    Expand-ZipContainer -Path $msix.FullName -Destination $engineDir
    Set-Content -LiteralPath (Join-Path $ToolsPath 'windbg.version') -Value $bundleVer -Encoding ASCII
    Remove-Item -LiteralPath $downloadDir -Recurse -Force -ErrorAction SilentlyContinue
    return $engineDir
}

function Resolve-Debugger {
    <#
      Returns @{ Path; Kind = 'Console' | 'DbgX'; Source }
      Console = kd.exe / cdb.exe (stdout captured). DbgX = DbgX.Shell.exe fallback (-logo file).
    #>
    param([string]$DebuggerPath, [string]$ToolsPath, [switch]$Update)

    function New-Result($path, $source) {
        $kind = if ([IO.Path]::GetFileName($path) -ieq 'DbgX.Shell.exe') { 'DbgX' } else { 'Console' }
        [pscustomobject]@{ Path = $path; Kind = $kind; Source = $source }
    }

    if ($DebuggerPath) {
        if (Test-Path -LiteralPath $DebuggerPath -PathType Container) {
            $found = Find-DebuggerInFolder $DebuggerPath
            if ($found) { return New-Result $found 'DebuggerPath' }
        } elseif (Test-Path -LiteralPath $DebuggerPath -PathType Leaf) {
            return New-Result (Resolve-Path -LiteralPath $DebuggerPath).Path 'DebuggerPath'
        }
        throw "DebuggerPath not usable: $DebuggerPath"
    }

    $cacheDir = Join-Path $ToolsPath 'windbg'
    if (-not $Update) {
        $cached = Find-DebuggerInFolder $cacheDir
        if ($cached) { return New-Result $cached 'Cache' }

        $kitRoots = @(
            (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Debuggers'),
            (Join-Path $env:ProgramFiles 'Windows Kits\10\Debuggers')
        ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
        foreach ($root in $kitRoots) {
            $kit = Find-DebuggerInFolder $root
            if ($kit) { return New-Result $kit 'Windows Kits' }
        }

        try {
            $appx = Get-AppxPackage -AllUsers -Name 'Microsoft.WinDbg*' -ErrorAction SilentlyContinue |
                Sort-Object Version -Descending | Select-Object -First 1
            if ($appx -and $appx.InstallLocation) {
                $app = Find-DebuggerInFolder $appx.InstallLocation
                if ($app) { return New-Result $app 'WinDbg app' }
            }
        } catch { }
    }

    $engineDir = Install-WinDbgPackage -ToolsPath $ToolsPath
    $exe = Find-DebuggerInFolder $engineDir
    if (-not $exe) {
        $dbgx = Get-ChildItem -LiteralPath $engineDir -Recurse -File -Filter DbgX.Shell.exe -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($dbgx) {
            Write-Status 'kd.exe/cdb.exe not present in package; falling back to DbgX.Shell.exe' Warn
            $exe = $dbgx.FullName
        }
    }
    if (-not $exe) { throw 'WinDbg package extracted but no debugger executable was found.' }

    $sig = Test-MicrosoftSigned $exe
    if ($sig -ne 'Valid' -and $sig -ne 'NotSigned') {
        throw "Debugger signature check failed ($sig): $exe"
    }
    if ($sig -eq 'NotSigned') { Write-Status "Debugger binary is not Authenticode signed (package-signed only): $exe" Warn }
    return New-Result $exe 'Downloaded'
}

#endregion

#region ---------- Analysis ----------

$script:DebuggerCommands = '.echo BSODAW_ANALYZE_BEGIN; !analyze -v; .echo BSODAW_VERTARGET; vertarget; .echo BSODAW_END; q'

function Invoke-DumpAnalysis {
    param(
        $Debugger,
        [string]$DumpFile,
        [string]$LogFile,
        [string]$SymbolPath,
        [int]$TimeoutMinutes
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Debugger.Path
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = Split-Path -Parent $Debugger.Path
    $psi.EnvironmentVariables['_NT_SYMBOL_PATH'] = $SymbolPath

    if ($Debugger.Kind -eq 'Console') {
        $psi.Arguments = ('-z "{0}" -y "{1}" -c "{2}"' -f $DumpFile, $SymbolPath, $script:DebuggerCommands)
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
    } else {
        $psi.Arguments = ('-z "{0}" -y "{1}" -logo "{2}" -c "{3}"' -f $DumpFile, $SymbolPath, $LogFile, $script:DebuggerCommands)
    }

    $proc = [System.Diagnostics.Process]::Start($psi)
    $outTask = $null; $errTask = $null
    if ($Debugger.Kind -eq 'Console') {
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()
    }
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $timedOut = $false
    while (-not $proc.WaitForExit(250)) {
        Invoke-UiPump
        if ((Get-Date) -gt $deadline) {
            $timedOut = $true
            try { $proc.Kill() } catch { }
            break
        }
    }
    $proc.WaitForExit()

    $text = ''
    if ($Debugger.Kind -eq 'Console') {
        $text = $outTask.Result
        $err = $errTask.Result
        if ($err) { $text += [Environment]::NewLine + $err }
        [IO.File]::WriteAllText($LogFile, $text, [Text.Encoding]::UTF8)
    } elseif (Test-Path -LiteralPath $LogFile) {
        $text = Get-Content -LiteralPath $LogFile -Raw
    }
    [pscustomobject]@{ Text = $text; ExitCode = $proc.ExitCode; TimedOut = $timedOut }
}

function ConvertFrom-AnalyzeOutput {
    # Parses !analyze -v (+ vertarget) text into a flat object. Works with old and new (key: value) formats.
    param([string]$Text)

    function Get-Field([string]$key) {
        $m = [regex]::Match($Text, "(?m)^$([regex]::Escape($key)):[ \t]*(.+?)\s*$")
        if ($m.Success) { return $m.Groups[1].Value.Trim() }
        return $null
    }
    function Get-Block([string]$key, [int]$max = 25) {
        $m = [regex]::Match($Text, "(?ms)^$([regex]::Escape($key)):[ \t]*\r?\n(.*?)(?:\r?\n[ \t]*\r?\n|\z)")
        if (-not $m.Success) { return @() }
        return @($m.Groups[1].Value -split "\r?\n" | Where-Object { $_.Trim() } | Select-Object -First $max)
    }

    $r = [ordered]@{
        BugcheckName    = $null
        BugcheckCode    = $null
        Parameters      = @()
        ProcessName     = Get-Field 'PROCESS_NAME'
        ModuleName      = Get-Field 'MODULE_NAME'
        ImageName       = Get-Field 'IMAGE_NAME'
        ImageVersion    = Get-Field 'IMAGE_VERSION'
        SymbolName      = Get-Field 'SYMBOL_NAME'
        FailureBucket   = Get-Field 'FAILURE_BUCKET_ID'
        FailureHash     = Get-Field 'FAILURE_ID_HASH'
        ProbablyCausedBy = $null
        OsVersion       = Get-Field 'OS_VERSION'
        BuildLab        = Get-Field 'BUILDLAB_STR'
        CrashTime       = $null
        Uptime          = $null
        Stack           = Get-Block 'STACK_TEXT'
        SymbolProblems  = $false
        AnalysisComplete = $false
    }

    # Bugcheck name: first "NAME (code)" line after the "Bugcheck Analysis" banner
    $m = [regex]::Match($Text, '(?ms)Bugcheck Analysis.*?^\*+\s*$\s*^([A-Z0-9_]+) \(([0-9a-fA-F]+)\)\s*$')
    if ($m.Success) { $r.BugcheckName = $m.Groups[1].Value; $r.BugcheckCode = '0x' + $m.Groups[2].Value.ToUpper() }

    $code = Get-Field 'BUGCHECK_CODE'
    if (-not $code) { $code = Get-Field 'BUGCHECK_STR' }
    if ($code) {
        $c = $code -replace '^0x', ''
        if ($c -match '^[0-9a-fA-F]+$') { $r.BugcheckCode = '0x' + $c.ToUpper() }
    }
    $params = @()
    foreach ($i in 1..4) {
        $p = Get-Field "BUGCHECK_P$i"
        if ($p) { $params += $p }
    }
    if ($params.Count -eq 0) {
        $am = [regex]::Matches($Text, '(?m)^Arg([1-4]):\s+([0-9a-fA-F`]+)')
        foreach ($a in $am) { $params += $a.Groups[2].Value }
    }
    $r.Parameters = $params

    $pc = [regex]::Match($Text, '(?m)^\s*Probably caused by\s*:\s*(.+?)\s*$')
    if ($pc.Success) { $r.ProbablyCausedBy = $pc.Groups[1].Value }
    if (-not $r.ImageName -and $r.ProbablyCausedBy -match '^([^\s(]+)') { $r.ImageName = $Matches[1] }

    $t = [regex]::Match($Text, '(?m)^Debug session time:\s*(.+?)\s*$')
    if ($t.Success) { $r.CrashTime = $t.Groups[1].Value }
    $u = [regex]::Match($Text, '(?m)^System Uptime:\s*(.+?)\s*$')
    if ($u.Success) { $r.Uptime = $u.Groups[1].Value }

    if ($Text -match 'Symbol file could not be found|Kernel symbols are WRONG|Symbols can not be loaded|Your debugger is not using the correct symbols') {
        $r.SymbolProblems = $true
    }
    $r.AnalysisComplete = [bool]($r.BugcheckCode -and ($r.FailureBucket -or $r.ImageName -or $r.ProbablyCausedBy))
    return [pscustomobject]$r
}

$script:BugcheckHints = @{
    '0x0000000A' = 'IRQL_NOT_LESS_OR_EQUAL - a driver accessed paged/invalid memory at raised IRQL. Update/roll back the named driver; test RAM if the driver varies.'
    '0x0000001A' = 'MEMORY_MANAGEMENT - memory corruption. Run memory diagnostics (RAM), check XMP/overclock, then drivers.'
    '0x0000001E' = 'KMODE_EXCEPTION_NOT_HANDLED - kernel-mode exception in a driver. Update the named driver.'
    '0x00000019' = 'BAD_POOL_HEADER - pool corruption, usually a driver. Enable Driver Verifier if the module is generic.'
    '0x00000050' = 'PAGE_FAULT_IN_NONPAGED_AREA - invalid memory reference. Faulty driver, AV/filter driver, or RAM.'
    '0x0000007E' = 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED - system thread exception, usually the named driver.'
    '0x0000007F' = 'UNEXPECTED_KERNEL_MODE_TRAP - often hardware (CPU/RAM/overheating) or stack overflow in a driver.'
    '0x0000003B' = 'SYSTEM_SERVICE_EXCEPTION - exception transitioning from user to kernel code; often graphics/AV drivers.'
    '0x0000009F' = 'DRIVER_POWER_STATE_FAILURE - driver hung on sleep/resume. Update chipset/network/USB/graphics drivers.'
    '0x000000C2' = 'BAD_POOL_CALLER - driver made a bad pool request. Update the named driver.'
    '0x000000D1' = 'DRIVER_IRQL_NOT_LESS_OR_EQUAL - driver bug (commonly network, storage, AV). Update/roll back the named driver.'
    '0x000000EF' = 'CRITICAL_PROCESS_DIED - a critical system process exited. Check disk health, SFC/DISM, AV interference.'
    '0x000000F4' = 'CRITICAL_OBJECT_TERMINATION - critical process terminated; frequently storage/disk (SSD firmware, cabling).'
    '0x00000116' = 'VIDEO_TDR_FAILURE - GPU driver timeout. Clean-install GPU driver; check GPU thermals/power.'
    '0x00000117' = 'VIDEO_TDR_TIMEOUT_DETECTED - GPU driver timeout. Clean-install GPU driver.'
    '0x00000119' = 'VIDEO_SCHEDULER_INTERNAL_ERROR - GPU driver/hardware. Update GPU driver.'
    '0x00000124' = 'WHEA_UNCORRECTABLE_ERROR - HARDWARE error reported by the CPU (CPU, RAM, PCIe, overclock, power). Not a software driver issue.'
    '0x00000133' = 'DPC_WATCHDOG_VIOLATION - DPC ran too long; common with storage (SSD firmware/storahci), network or old drivers.'
    '0x00000139' = 'KERNEL_SECURITY_CHECK_FAILURE - corrupted kernel structure, usually a driver; sometimes RAM.'
    '0x0000013A' = 'KERNEL_MODE_HEAP_CORRUPTION - driver corrupted the kernel heap. Update the named driver; Driver Verifier.'
    '0x00000154' = 'UNEXPECTED_STORE_EXCEPTION - memory compression store; often disk/SSD or storage driver.'
    '0x0000015F' = 'CONNECTED_STANDBY_WATCHDOG_TIMEOUT_LIVEDUMP - modern standby device hang.'
    '0x000001CA' = 'SYNTHETIC_WATCHDOG_TIMEOUT - system hang detected by watchdog.'
    '0x000000BE' = 'ATTEMPTED_WRITE_TO_READONLY_MEMORY - driver bug. Update the named driver.'
    '0x000000C4' = 'DRIVER_VERIFIER_DETECTED_VIOLATION - Driver Verifier caught the named driver.'
    '0x000000C5' = 'DRIVER_CORRUPTED_EXPOOL - pool corruption by a driver.'
    '0x0000007A' = 'KERNEL_DATA_INPAGE_ERROR - could not read kernel data from the page file: disk, controller, cabling or RAM.'
    '0x00000077' = 'KERNEL_STACK_INPAGE_ERROR - disk / storage path failure reading the page file.'
    '0x000000EA' = 'THREAD_STUCK_IN_DEVICE_DRIVER - GPU driver stuck. Update GPU driver; check GPU hardware.'
    '0x000000FC' = 'ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY - driver bug or memory corruption.'
    '0x0000004E' = 'PFN_LIST_CORRUPT - memory manager corruption; driver or RAM.'
    '0x00000101' = 'CLOCK_WATCHDOG_TIMEOUT - a CPU core stopped responding: CPU/BIOS/overclock/hardware.'
    '0x000001A8' = 'BUGCODE_ID_DRIVER - driver error.'
    '0x00000144' = 'BUGCODE_USB3_DRIVER - USB controller/device driver. Update chipset/USB drivers.'
    '0x0000009C' = 'MACHINE_CHECK_EXCEPTION - hardware error (legacy form of 0x124).'
    '0x000000E2' = 'MANUALLY_INITIATED_CRASH - crash was triggered deliberately (keyboard/NMI/debugger).'
    '0x00000161' = 'LIVE_SYSTEM_DUMP - live dump, not a real crash.'
}

$script:GenericImages = @('ntkrnlmp.exe', 'ntoskrnl.exe', 'ntkrnlpa.exe', 'hal.dll', 'memory_corruption', 'hardware', 'hardware_disk',
    'hardware_ram', 'unknown_image', 'Unknown_Module', 'pool_corruption', 'win32kbase.sys', 'win32kfull.sys')

function Get-NormalizedBugcheck([string]$code) {
    if (-not $code) { return $null }
    $hex = $code -replace '^0x', ''
    try { return '0x{0:X8}' -f [Convert]::ToUInt32($hex, 16) } catch { return $code }
}

function Get-DriverInfo {
    # Looks up the faulting image on THIS machine (useful when analysing local dumps).
    param([string]$ImageName)
    if (-not $ImageName -or $ImageName -notmatch '\.(sys|dll|exe)$') { return $null }
    $candidates = @(
        (Join-Path $env:SystemRoot "System32\drivers\$ImageName"),
        (Join-Path $env:SystemRoot "System32\$ImageName")
    )
    $file = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $file -and (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
        $drv = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
            Where-Object { $_.PathName -and ([IO.Path]::GetFileName($_.PathName) -ieq $ImageName) } | Select-Object -First 1
        if ($drv) { $file = $drv.PathName -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:SystemRoot }
    }
    if (-not $file -or -not (Test-Path -LiteralPath $file -PathType Leaf)) { return $null }
    $item = Get-Item -LiteralPath $file
    $vi = $item.VersionInfo
    $signer = $null
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $file
        if ($sig.SignerCertificate) { $signer = ($sig.SignerCertificate.Subject -split ',')[0] -replace '^CN=', '' }
    } catch { }
    [pscustomobject]@{
        Path        = $file
        Company     = $vi.CompanyName
        Description = $vi.FileDescription
        FileVersion = $vi.FileVersion
        FileDate    = $item.LastWriteTime.ToString('yyyy-MM-dd')
        Signer      = $signer
        ThirdParty  = [bool]($vi.CompanyName -and $vi.CompanyName -notmatch 'Microsoft')
    }
}

function Get-Recommendation {
    param($Parsed, $DriverInfo)
    $notes = New-Object System.Collections.Generic.List[string]
    $code = Get-NormalizedBugcheck $Parsed.BugcheckCode
    if ($code -and -not $script:BugcheckHints.ContainsKey($code)) {
        # 0x1000007E etc. are the same bugchecks with the "extended parameters" flag set
        try {
            $n = [Convert]::ToUInt32(($code -replace '^0x', ''), 16)
            if ($n -band 0x10000000) { $code = '0x{0:X8}' -f ($n -bxor 0x10000000) }
        } catch { }
    }
    if ($code -and $script:BugcheckHints.ContainsKey($code)) { $notes.Add($script:BugcheckHints[$code]) }

    $img = $Parsed.ImageName
    if ($DriverInfo -and $DriverInfo.ThirdParty) {
        $notes.Add(("Faulting driver {0} is third-party ({1}, v{2}, {3}). Update or remove it first." -f $img, $DriverInfo.Company, $DriverInfo.FileVersion, $DriverInfo.FileDate))
    } elseif ($img -and ($script:GenericImages -contains $img)) {
        $notes.Add("Faulting image '$img' is generic (kernel/hardware). Suspect RAM, storage, firmware/BIOS, or a driver corrupting memory; consider Driver Verifier and memory diagnostics.")
    } elseif ($img) {
        $notes.Add("Faulting image: $img. Check its vendor/version and update the related driver or software.")
    }
    if ($Parsed.FailureBucket -match '^(?i)(MEMORY_CORRUPTION|.*hardware|.*_IP_MISALIGNED|.*BAD_IP)') {
        $notes.Add('Failure bucket indicates memory/hardware corruption: run memory diagnostics and check for overclocking.')
    }
    if ($Parsed.SymbolProblems) {
        $notes.Add('Symbol problems were reported; results may be less accurate (check internet access to msdl.microsoft.com).')
    }
    return @($notes)
}

function Get-CrashEventSummary {
    param([int]$Days = 30)
    $since = (Get-Date).AddDays(-$Days)
    $count = { param($filter) try { @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop).Count } catch { 0 } }
    [pscustomobject]@{
        WindowDays           = $Days
        BugcheckEvents       = & $count @{ LogName = 'System'; Id = 1001; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; StartTime = $since }
        UnexpectedShutdowns  = & $count @{ LogName = 'System'; Id = 41; ProviderName = 'Microsoft-Windows-Kernel-Power'; StartTime = $since }
        DirtyShutdowns       = & $count @{ LogName = 'System'; Id = 6008; StartTime = $since }
        WheaErrors           = & $count @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; StartTime = $since }
    }
}

function Invoke-BsodAnalysis {
    <#
      Core pipeline used by both CLI and GUI. Returns a run summary object.
    #>
    param(
        [object[]]$Dumps,
        [string]$OutputPath,
        [string]$ToolsPath,
        [string]$SymbolPath,
        [string]$DebuggerPath,
        [int]$TimeoutMinutes,
        [switch]$Force,
        [switch]$UpdateDebugger,
        [scriptblock]$OnResult
    )
    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    $results = New-Object System.Collections.Generic.List[object]
    $debugger = $null

    $i = 0
    foreach ($dump in $Dumps) {
        $i++
        $safeName = ($dump.BaseName -replace '[^\w\.-]', '_')
        $stamp = $dump.LastWriteTime.ToString('yyyyMMdd-HHmmss')
        $base = Join-Path $OutputPath ("{0}_{1}" -f $safeName, $stamp)
        $logFile = "$base.log"
        $jsonFile = "$base.json"

        if (-not $Force -and (Test-Path -LiteralPath $jsonFile)) {
            $cached = Get-Content -LiteralPath $jsonFile -Raw | ConvertFrom-Json
            if ($cached.Status -eq 'Analyzed') {
                Write-Status "[$i/$($Dumps.Count)] Already analysed (use -Force to redo): $($dump.Name)"
                $cached | Add-Member -NotePropertyName Cached -NotePropertyValue $true -Force
                $results.Add($cached)
                if ($OnResult) { & $OnResult $cached }
                continue
            }
        }

        if (-not $debugger) {
            $debugger = Resolve-Debugger -DebuggerPath $DebuggerPath -ToolsPath $ToolsPath -Update:$UpdateDebugger
            Write-Status "Debugger: $($debugger.Path) [$($debugger.Source)]" Ok
        }

        $sizeMb = [math]::Round($dump.Length / 1MB, 1)
        Write-Status "[$i/$($Dumps.Count)] Analysing $($dump.FullName) ($sizeMb MB)..."
        $status = 'Analyzed'; $errorText = $null; $parsed = $null; $driver = $null
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            $run = Invoke-DumpAnalysis -Debugger $debugger -DumpFile $dump.FullName -LogFile $logFile -SymbolPath $SymbolPath -TimeoutMinutes $TimeoutMinutes
            $parsed = ConvertFrom-AnalyzeOutput -Text $run.Text
            if ($run.TimedOut) { $status = 'TimedOut'; $errorText = "Debugger exceeded $TimeoutMinutes minute timeout." }
            elseif (-not $parsed.BugcheckCode) { $status = 'Failed'; $errorText = 'No bugcheck information in debugger output (see log).' }
            $driver = Get-DriverInfo -ImageName $parsed.ImageName
        } catch {
            $status = 'Failed'; $errorText = $_.Exception.Message
        }
        $sw.Stop()

        $code = if ($parsed) { Get-NormalizedBugcheck $parsed.BugcheckCode } else { $null }
        $result = [pscustomobject][ordered]@{
            Status         = $status
            Error          = $errorText
            DumpFile       = $dump.FullName
            DumpSizeMB     = $sizeMb
            DumpTime       = $dump.LastWriteTime.ToString('s')
            CrashTime      = if ($parsed) { $parsed.CrashTime } else { $null }
            BugcheckCode   = $code
            BugcheckName   = if ($parsed) { $parsed.BugcheckName } else { $null }
            Parameters     = if ($parsed) { $parsed.Parameters } else { @() }
            ImageName      = if ($parsed) { $parsed.ImageName } else { $null }
            ModuleName     = if ($parsed) { $parsed.ModuleName } else { $null }
            ImageVersion   = if ($parsed) { $parsed.ImageVersion } else { $null }
            ProcessName    = if ($parsed) { $parsed.ProcessName } else { $null }
            SymbolName     = if ($parsed) { $parsed.SymbolName } else { $null }
            FailureBucket  = if ($parsed) { $parsed.FailureBucket } else { $null }
            FailureHash    = if ($parsed) { $parsed.FailureHash } else { $null }
            OsVersion      = if ($parsed) { $parsed.OsVersion } else { $null }
            Uptime         = if ($parsed) { $parsed.Uptime } else { $null }
            SymbolProblems = if ($parsed) { $parsed.SymbolProblems } else { $null }
            Driver         = $driver
            Recommendations = if ($parsed) { Get-Recommendation -Parsed $parsed -DriverInfo $driver } else { @() }
            Stack          = if ($parsed) { $parsed.Stack } else { @() }
            LogFile        = $logFile
            ReportFile     = $jsonFile
            DurationSec    = [math]::Round($sw.Elapsed.TotalSeconds, 1)
            Cached         = $false
        }
        $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonFile -Encoding UTF8
        $results.Add($result)

        if ($status -eq 'Analyzed') {
            Write-Status ("  {0} {1} -> {2}" -f $result.BugcheckCode, $result.BugcheckName, ($result.ImageName, $result.FailureBucket | Where-Object { $_ } | Select-Object -First 1)) Ok
        } else {
            Write-Status "  $status : $errorText" Error
        }
        if ($OnResult) { & $OnResult $result }
    }
    return , $results.ToArray()
}

function Write-RunSummary {
    param($Results, $Config, $Events, [string]$OutputPath, [int]$ExitCode)
    $summary = [pscustomobject][ordered]@{
        Tool            = "BSOD-AutoWindbg $script:Version"
        Computer        = $env:COMPUTERNAME
        RunTime         = (Get-Date).ToString('s')
        ExitCode        = $ExitCode
        CrashDumpConfig = $Config
        CrashEvents     = $Events
        DumpsAnalysed   = @($Results | Where-Object { $_.Status -eq 'Analyzed' }).Count
        DumpsFailed     = @($Results | Where-Object { $_.Status -ne 'Analyzed' }).Count
        TopCauses       = @($Results | Where-Object { $_.Status -eq 'Analyzed' } |
                            Group-Object { '{0} {1} / {2}' -f $_.BugcheckCode, $_.BugcheckName, $_.ImageName } |
                            Sort-Object Count -Descending | Select-Object -First 5 |
                            ForEach-Object { [pscustomobject]@{ Cause = $_.Name; Count = $_.Count } })
        OutputPath      = $OutputPath
        Results         = @($Results | Select-Object Status, DumpTime, BugcheckCode, BugcheckName, ImageName, FailureBucket,
                            @{ n = 'Recommendation'; e = { @($_.Recommendations) | Select-Object -First 1 } }, DumpFile, LogFile, Error)
    }
    if (Test-Path -LiteralPath $OutputPath) {
        $summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputPath 'summary.json') -Encoding UTF8
        if ($Results.Count -gt 0) {
            $summary.Results | Select-Object Status, DumpTime, BugcheckCode, BugcheckName, ImageName, FailureBucket, Recommendation, DumpFile, LogFile, Error |
                Export-Csv -LiteralPath (Join-Path $OutputPath 'summary.csv') -NoTypeInformation -Encoding UTF8
        }
    }
    return $summary
}

#endregion

#region ---------- GUI ----------

function Show-BsodGui {
    param([string[]]$InitialPaths, $Config)
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "BSOD-AutoWindbg $script:Version - $env:COMPUTERNAME"
    $form.Size = New-Object System.Drawing.Size(1200, 780)
    $form.StartPosition = 'CenterScreen'
    $form.AllowDrop = $true
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

    # --- Top bar ---
    $top = New-Object System.Windows.Forms.TableLayoutPanel
    $top.Dock = 'Top'; $top.Height = 70; $top.ColumnCount = 6; $top.RowCount = 2
    $top.Padding = New-Object System.Windows.Forms.Padding(6, 6, 6, 0)
    foreach ($w in 80, -1, 110, 110, 130, 130) {
        $style = if ($w -lt 0) { New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100) }
                 else { New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, $w) }
        [void]$top.ColumnStyles.Add($style)
    }

    $lbl = New-Object System.Windows.Forms.Label; $lbl.Text = 'Dump(s):'; $lbl.TextAlign = 'MiddleLeft'; $lbl.Dock = 'Fill'
    $txtPath = New-Object System.Windows.Forms.TextBox; $txtPath.Dock = 'Fill'
    $txtPath.Text = if ($InitialPaths) { $InitialPaths -join '; ' } else { '' }
    $btnFile = New-Object System.Windows.Forms.Button; $btnFile.Text = 'Browse file...'; $btnFile.Dock = 'Fill'
    $btnFolder = New-Object System.Windows.Forms.Button; $btnFolder.Text = 'Browse folder...'; $btnFolder.Dock = 'Fill'
    $btnSystem = New-Object System.Windows.Forms.Button; $btnSystem.Text = 'This PC''s dumps'; $btnSystem.Dock = 'Fill'
    $btnRun = New-Object System.Windows.Forms.Button; $btnRun.Text = 'Analyse'; $btnRun.Dock = 'Fill'
    $btnRun.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)

    $chkForce = New-Object System.Windows.Forms.CheckBox; $chkForce.Text = 'Re-analyse'; $chkForce.Dock = 'Fill'
    $status = New-Object System.Windows.Forms.Label; $status.Dock = 'Fill'; $status.TextAlign = 'MiddleLeft'
    $status.Text = "Crash dumps: $($Config.DumpType)  |  Reports: $OutputPath  |  Drag a .dmp file or folder onto this window."
    $btnOpen = New-Object System.Windows.Forms.Button; $btnOpen.Text = 'Open reports folder'; $btnOpen.Dock = 'Fill'
    $btnCopy = New-Object System.Windows.Forms.Button; $btnCopy.Text = 'Copy summary'; $btnCopy.Dock = 'Fill'

    $top.Controls.Add($lbl, 0, 0); $top.Controls.Add($txtPath, 1, 0); $top.Controls.Add($btnFile, 2, 0)
    $top.Controls.Add($btnFolder, 3, 0); $top.Controls.Add($btnSystem, 4, 0); $top.Controls.Add($btnRun, 5, 0)
    $top.Controls.Add($chkForce, 0, 1); $top.Controls.Add($status, 1, 1); $top.SetColumnSpan($status, 3)
    $top.Controls.Add($btnCopy, 4, 1); $top.Controls.Add($btnOpen, 5, 1)

    # --- Results grid ---
    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = 'Fill'; $grid.ReadOnly = $true; $grid.AllowUserToAddRows = $false; $grid.RowHeadersVisible = $false
    $grid.SelectionMode = 'FullRowSelect'; $grid.MultiSelect = $false; $grid.AutoSizeColumnsMode = 'Fill'
    foreach ($c in 'Status', 'Dump time', 'Bugcheck', 'Name', 'Faulting image', 'Failure bucket', 'Dump') {
        [void]$grid.Columns.Add(($c -replace ' ', ''), $c)
    }

    # --- Detail pane ---
    $tabs = New-Object System.Windows.Forms.TabControl; $tabs.Dock = 'Fill'
    $tabSummary = New-Object System.Windows.Forms.TabPage; $tabSummary.Text = 'Diagnosis'
    $tabLog = New-Object System.Windows.Forms.TabPage; $tabLog.Text = 'Debugger output'
    $tabRun = New-Object System.Windows.Forms.TabPage; $tabRun.Text = 'Activity'
    $mono = New-Object System.Drawing.Font('Consolas', 9)
    $mk = {
        $t = New-Object System.Windows.Forms.TextBox
        $t.Multiline = $true; $t.ScrollBars = 'Both'; $t.WordWrap = $false; $t.ReadOnly = $true; $t.Dock = 'Fill'; $t.Font = $mono
        $t
    }
    $txtSummary = & $mk; $txtSummary.WordWrap = $true; $txtSummary.ScrollBars = 'Vertical'
    $txtLog = & $mk
    $txtRun = & $mk
    $tabSummary.Controls.Add($txtSummary); $tabLog.Controls.Add($txtLog); $tabRun.Controls.Add($txtRun)
    $tabs.TabPages.AddRange(@($tabSummary, $tabLog, $tabRun))

    $split = New-Object System.Windows.Forms.SplitContainer
    $split.Dock = 'Fill'; $split.Orientation = 'Horizontal'
    $split.Panel1.Controls.Add($grid); $split.Panel2.Controls.Add($tabs)

    $progress = New-Object System.Windows.Forms.ProgressBar; $progress.Dock = 'Bottom'; $progress.Height = 14

    $form.Controls.Add($split); $form.Controls.Add($progress); $form.Controls.Add($top)

    $script:GuiLogBox = $txtRun
    $rowData = New-Object System.Collections.Generic.List[object]

    $showDetail = {
        if ($grid.SelectedRows.Count -eq 0) { return }
        $idx = $grid.SelectedRows[0].Index
        if ($idx -lt 0 -or $idx -ge $rowData.Count) { return }
        $r = $rowData[$idx]
        $nl = [Environment]::NewLine
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("Dump:            $($r.DumpFile)")
        [void]$sb.AppendLine("Status:          $($r.Status) $($r.Error)")
        [void]$sb.AppendLine("Bugcheck:        $($r.BugcheckCode) $($r.BugcheckName)")
        [void]$sb.AppendLine("Parameters:      $(@($r.Parameters) -join ', ')")
        [void]$sb.AppendLine("Faulting image:  $($r.ImageName)  $($r.ImageVersion)")
        [void]$sb.AppendLine("Module/Symbol:   $($r.ModuleName) / $($r.SymbolName)")
        [void]$sb.AppendLine("Process:         $($r.ProcessName)")
        [void]$sb.AppendLine("Failure bucket:  $($r.FailureBucket)")
        [void]$sb.AppendLine("Crash time:      $($r.CrashTime)   Uptime: $($r.Uptime)")
        if ($r.Driver) {
            [void]$sb.AppendLine("Driver on disk:  $($r.Driver.Path)")
            [void]$sb.AppendLine("                 $($r.Driver.Company) | v$($r.Driver.FileVersion) | $($r.Driver.FileDate) | signer: $($r.Driver.Signer)")
        }
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('RECOMMENDATIONS')
        foreach ($n in @($r.Recommendations)) { [void]$sb.AppendLine(" - $n") }
        if (@($r.Stack).Count -gt 0) {
            [void]$sb.AppendLine(''); [void]$sb.AppendLine('STACK (top)')
            foreach ($s in @($r.Stack)) { [void]$sb.AppendLine("  $s") }
        }
        $txtSummary.Text = $sb.ToString() -replace "`r?`n", $nl
        $txtLog.Text = if ($r.LogFile -and (Test-Path -LiteralPath $r.LogFile)) { (Get-Content -LiteralPath $r.LogFile -Raw) -replace "`r?`n", $nl } else { '(no log)' }
    }
    $grid.add_SelectionChanged($showDetail)

    $addRow = {
        param($r)
        $rowData.Add($r)
        $shortImg = if ($r.ImageName) { $r.ImageName } else { '' }
        $idx = $grid.Rows.Add($r.Status, $r.DumpTime, $r.BugcheckCode, $r.BugcheckName, $shortImg, $r.FailureBucket, $r.DumpFile)
        if ($r.Status -ne 'Analyzed') { $grid.Rows[$idx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Firebrick }
        $progress.PerformStep()
        [System.Windows.Forms.Application]::DoEvents()
    }

    $runAnalysis = {
        param([string[]]$paths)
        if ($script:Busy) { return }
        $script:Busy = $true
        $btnRun.Enabled = $false; $btnSystem.Enabled = $false
        $grid.Rows.Clear(); $rowData.Clear(); $txtSummary.Clear(); $txtLog.Clear()
        $tabs.SelectedTab = $tabRun
        $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        try {
            $dumps = @(Get-DumpFiles -Paths $paths -Config $Config -IncludeSystemMemoryDump:(-not $SkipSystemMemoryDump))
            if ($dumps.Count -eq 0) {
                Write-Status 'No .dmp files found.' Warn
                if (-not $paths) {
                    $msg = if ($Config.Enabled) { 'Crash dump collection is enabled, but there are no dumps on this PC.' } else { 'Crash dump collection is DISABLED on this PC, so BSODs are not being recorded.' }
                    [void][System.Windows.Forms.MessageBox]::Show($msg, 'BSOD-AutoWindbg', 'OK', 'Information')
                }
                return
            }
            $progress.Maximum = $dumps.Count; $progress.Value = 0; $progress.Step = 1
            $results = Invoke-BsodAnalysis -Dumps $dumps -OutputPath $OutputPath -ToolsPath $ToolsPath -SymbolPath $SymbolPath `
                -DebuggerPath $DebuggerPath -TimeoutMinutes $TimeoutMinutes -Force:$chkForce.Checked -UpdateDebugger:$UpdateDebugger -OnResult $addRow
            $script:LastResults = $results
            [void](Write-RunSummary -Results $results -Config $Config -Events $null -OutputPath $OutputPath -ExitCode 0)
            Write-Status "Done. $($results.Count) dump(s). Reports: $OutputPath" Ok
            $tabs.SelectedTab = $tabSummary
            if ($grid.Rows.Count -gt 0) { $grid.Rows[0].Selected = $true; & $showDetail }
        } catch {
            Write-Status "ERROR: $($_.Exception.Message)" Error
            [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'BSOD-AutoWindbg', 'OK', 'Error')
        } finally {
            $form.Cursor = [System.Windows.Forms.Cursors]::Default
            $btnRun.Enabled = $true; $btnSystem.Enabled = $true
            $script:Busy = $false
        }
    }

    $splitPaths = { param($s) @($s -split ';' | ForEach-Object { $_.Trim().Trim('"') } | Where-Object { $_ }) }

    $btnFile.add_Click({
        $dlg = New-Object System.Windows.Forms.OpenFileDialog
        $dlg.Filter = 'Crash dumps (*.dmp)|*.dmp|All files (*.*)|*.*'; $dlg.Multiselect = $true
        if (Test-Path -LiteralPath $Config.MinidumpDir) { $dlg.InitialDirectory = $Config.MinidumpDir }
        if ($dlg.ShowDialog() -eq 'OK') { $txtPath.Text = $dlg.FileNames -join '; ' }
    })
    $btnFolder.add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        if ($dlg.ShowDialog() -eq 'OK') { $txtPath.Text = $dlg.SelectedPath }
    })
    $btnSystem.add_Click({ $txtPath.Text = ''; & $runAnalysis @() })
    $btnRun.add_Click({ & $runAnalysis (& $splitPaths $txtPath.Text) })
    $btnOpen.add_Click({
        New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
        Start-Process explorer.exe -ArgumentList "`"$OutputPath`""
    })
    $btnCopy.add_Click({
        if ($rowData.Count -eq 0) { return }
        $lines = foreach ($r in $rowData) {
            '{0} | {1} {2} | {3} | {4} | {5}' -f $r.DumpTime, $r.BugcheckCode, $r.BugcheckName, $r.ImageName, $r.FailureBucket, (@($r.Recommendations) | Select-Object -First 1)
        }
        [System.Windows.Forms.Clipboard]::SetText("BSOD analysis - $env:COMPUTERNAME`r`n" + ($lines -join "`r`n"))
        Write-Status 'Summary copied to clipboard.' Ok
    })
    $form.add_DragEnter({ param($s, $e) if ($e.Data.GetDataPresent([Windows.Forms.DataFormats]::FileDrop)) { $e.Effect = 'Copy' } })
    $form.add_DragDrop({
        param($s, $e)
        $dropped = [string[]]$e.Data.GetData([Windows.Forms.DataFormats]::FileDrop)
        $txtPath.Text = $dropped -join '; '
        & $runAnalysis $dropped
    })
    $form.add_FormClosing({
        param($s, $e)
        if ($script:Busy) {
            $e.Cancel = $true
            Write-Status 'Analysis in progress - wait for it to finish before closing.' Warn
        }
    })
    $form.add_Shown({
        $form.Activate()
        try { $split.SplitterDistance = [int]($split.Height * 0.35) } catch { }
        if ($InitialPaths) { & $runAnalysis $InitialPaths }
    })

    [void]$form.ShowDialog()
    $script:GuiLogBox = $null
}

#endregion

#region ---------- Main ----------

function ConvertTo-ArgumentList {
    # Rebuilds the bound parameters as a powershell.exe -File argument list (for elevation / STA relaunch).
    param([hashtable]$Bound, [string[]]$Exclude = @(), [hashtable]$Extra = @{})
    $quote = {
        param([string]$v)
        $v = $v.TrimEnd('\')
        if ($v -match '^[A-Za-z]:$') { $v += '\.' }   # "C:\" would otherwise escape the closing quote
        '"' + $v + '"'
    }
    $list = New-Object System.Collections.Generic.List[string]
    $merged = @{} + $Bound
    foreach ($k in $Extra.Keys) { $merged[$k] = $Extra[$k] }
    foreach ($k in $merged.Keys) {
        if ($Exclude -contains $k -or $k -eq 'DumpPath') { continue }
        $v = $merged[$k]
        if ($v -is [System.Management.Automation.SwitchParameter] -or $v -is [bool]) {
            if ([bool]$v) { $list.Add("-$k") }
        } else {
            $list.Add("-$k"); $list.Add((& $quote ([string]$v)))
        }
    }
    # DumpPath is positional + ValueFromRemainingArguments, so pass each path as a trailing argument.
    if ($merged.ContainsKey('DumpPath') -and $Exclude -notcontains 'DumpPath') {
        foreach ($p in @($merged['DumpPath'])) { if ($p) { $list.Add((& $quote ([string]$p))) } }
    }
    return , $list.ToArray()
}

function Start-SelfRelaunch {
    param([string[]]$ExtraArgs, [string[]]$ArgumentList, [switch]$Elevate)
    $exe = (Get-Process -Id $PID).Path
    $all = @('-NoProfile', '-ExecutionPolicy', 'Bypass') + $ExtraArgs + @('-File', ('"' + $PSCommandPath + '"')) + $ArgumentList
    $sp = @{ FilePath = $exe; ArgumentList = $all; PassThru = $true; Wait = $true }
    if ($Elevate) { $sp['Verb'] = 'RunAs' }
    $p = Start-Process @sp
    return $p.ExitCode
}

function Write-JsonSummary($summary) {
    $summary | ConvertTo-Json -Depth 6 -Compress | Write-Output
}

function Invoke-Main {
    $bound = $script:BoundParams

    if ($Days -gt 0 -and $Hours -gt 0) {
        Write-Error 'Use either -Days or -Hours, not both.' -ErrorAction Continue
        $script:ExitCode = 3; return
    }
    if ($Gui -and $NoGui) {
        Write-Error 'Use either -Gui or -NoGui, not both.' -ErrorAction Continue
        $script:ExitCode = 3; return
    }

    $interactive = Test-InteractiveDesktop
    $userArgs = @($bound.Keys | Where-Object { $_ -notin 'Verbose', 'Debug', 'PauseOnExit' })
    $onlyPaths = ($userArgs.Count -eq 0) -or ($userArgs.Count -eq 1 -and $userArgs[0] -eq 'DumpPath')
    $useGui = (-not $Json) -and ($Gui -or (-not $NoGui -and $interactive -and $onlyPaths))

    # Admin is needed for the system dump folder / CrashControl changes, not for dumps you point it at.
    $needsAdmin = (-not $DumpPath) -or $EnableCrashDumps
    if ($needsAdmin -and -not (Test-IsAdmin)) {
        if ($interactive) {
            Write-Status 'Administrator rights are required to read system crash dumps. Relaunching elevated...' Warn
            $extra = @{}
            if ($useGui) { $extra['Gui'] = $true } else { $extra['PauseOnExit'] = $true }
            try {
                $script:ExitCode = Start-SelfRelaunch -Elevate -ArgumentList (ConvertTo-ArgumentList -Bound $bound -Extra $extra)
            } catch {
                Write-Status "Elevation cancelled or failed: $($_.Exception.Message)" Error
                $script:ExitCode = 4
            }
            return
        }
        Write-Status 'Administrator rights are required (run as SYSTEM or an elevated account), or pass -DumpPath.' Error
        $script:ExitCode = 4; return
    }

    if ($SymbolPath) {
        $script:SymbolPath = $SymbolPath
    } else {
        $symCache = Join-Path (Split-Path -Parent $ToolsPath) 'symbols'
        $script:SymbolPath = "srv*$symCache*https://msdl.microsoft.com/download/symbols"
    }

    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    $script:RunLogFile = Join-Path $OutputPath 'BSOD-AutoWindbg.run.log'

    $config = Get-CrashDumpConfig
    if (-not $config.Enabled -and $EnableCrashDumps) {
        Enable-CrashDumpCollection
        $config = Get-CrashDumpConfig
    }

    if ($useGui) {
        if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
            $script:ExitCode = Start-SelfRelaunch -ExtraArgs @('-STA') -ArgumentList (ConvertTo-ArgumentList -Bound $bound -Extra @{ Gui = $true })
            return
        }
        Show-BsodGui -InitialPaths $DumpPath -Config $config
        $script:ExitCode = 0; return
    }

    Write-Status "BSOD-AutoWindbg $script:Version on $env:COMPUTERNAME | crash dumps: $($config.DumpType)"

    $all = @(Get-DumpFiles -Paths $DumpPath -Config $config -IncludeSystemMemoryDump:(-not $SkipSystemMemoryDump))
    $dumps = Select-DumpFiles -Files $all -Days $Days -Hours $Hours -Latest $Latest
    $events = $null
    if (-not $DumpPath) { $events = Get-CrashEventSummary -Days 30 }

    if ($dumps.Count -eq 0) {
        $code = 0
        if ($all.Count -eq 0 -and -not $DumpPath -and -not $config.Enabled) {
            Write-Status 'No crash dumps found and crash dump collection is DISABLED. Re-run with -EnableCrashDumps.' Error
            $code = 1
        } elseif ($all.Count -gt 0) {
            Write-Status "No dumps match the filter ($($all.Count) dump(s) exist outside it)." Ok
        } else {
            Write-Status 'No crash dumps found.' Ok
        }
        $summary = Write-RunSummary -Results @() -Config $config -Events $events -OutputPath $OutputPath -ExitCode $code
        if ($Json) { Write-JsonSummary $summary }
        elseif ($events -and ($events.BugcheckEvents -gt 0 -or $events.UnexpectedShutdowns -gt 0)) {
            Write-Output ("Last 30 days: {0} bugcheck events, {1} unexpected shutdowns, {2} WHEA hardware errors - crashes occurred but no dump was kept." -f $events.BugcheckEvents, $events.UnexpectedShutdowns, $events.WheaErrors)
        }
        $script:ExitCode = $code; return
    }

    Write-Status "$($dumps.Count) dump(s) selected for analysis."
    try {
        $results = Invoke-BsodAnalysis -Dumps $dumps -OutputPath $OutputPath -ToolsPath $ToolsPath -SymbolPath $script:SymbolPath `
            -DebuggerPath $DebuggerPath -TimeoutMinutes $TimeoutMinutes -Force:$Force -UpdateDebugger:$UpdateDebugger
    } catch {
        Write-Status "Debugger could not be acquired: $($_.Exception.Message)" Error
        $summary = Write-RunSummary -Results @() -Config $config -Events $events -OutputPath $OutputPath -ExitCode 5
        if ($Json) { Write-JsonSummary $summary }
        $script:ExitCode = 5; return
    }

    $ok = @($results | Where-Object { $_.Status -eq 'Analyzed' }).Count
    $bad = $results.Count - $ok
    $code = if ($ok -eq 0) { 12 } elseif ($bad -gt 0) { 11 } else { 10 }
    $summary = Write-RunSummary -Results $results -Config $config -Events $events -OutputPath $OutputPath -ExitCode $code

    if ($Json) {
        Write-JsonSummary $summary
    } else {
        Write-Output ''
        Write-Output ("BSOD summary for {0}: {1} analysed, {2} failed. Reports: {3}" -f $env:COMPUTERNAME, $ok, $bad, $OutputPath)
        foreach ($c in $summary.TopCauses) { Write-Output ("  {0}x  {1}" -f $c.Count, $c.Cause) }
        $first = $results | Where-Object { $_.Status -eq 'Analyzed' } | Select-Object -First 1
        if ($first) { foreach ($n in @($first.Recommendations)) { Write-Output "  -> $n" } }
        if ($events) {
            Write-Output ("  Last 30 days: {0} bugcheck events, {1} unexpected shutdowns, {2} WHEA hardware errors" -f $events.BugcheckEvents, $events.UnexpectedShutdowns, $events.WheaErrors)
        }
    }
    $script:ExitCode = $code
}

# Allow dot-sourcing (tests) without running.
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-Main
    if ($PauseOnExit) { [void](Read-Host "`nFinished (exit code $script:ExitCode). Press Enter to close") }
    exit $script:ExitCode
}

#endregion
