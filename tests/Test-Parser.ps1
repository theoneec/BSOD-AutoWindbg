# Offline tests for the !analyze parser and recommendation logic. Runs on Windows PowerShell 5.1 or pwsh 7.
# Usage: pwsh -NoProfile -File tests/Test-Parser.ps1
$ErrorActionPreference = 'Stop'
if (-not $env:ProgramData) { $env:ProgramData = [IO.Path]::GetTempPath() }   # non-Windows test hosts
. (Join-Path $PSScriptRoot '..\BSOD-AutoWindbg.ps1')

$script:failures = 0
function Assert-Equal($actual, $expected, $what) {
    if ("$actual" -ceq "$expected") { Write-Host "  PASS $what" -ForegroundColor Green }
    else { Write-Host "  FAIL $what : expected '$expected' got '$actual'" -ForegroundColor Red; $script:failures++ }
}
function Assert-True($cond, $what) { Assert-Equal ([bool]$cond) $true $what }

Write-Host 'modern-d1.txt'
$t = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'samples/modern-d1.txt') -Raw
$p = ConvertFrom-AnalyzeOutput -Text $t
Assert-Equal $p.BugcheckName 'DRIVER_IRQL_NOT_LESS_OR_EQUAL' 'bugcheck name'
Assert-Equal $p.BugcheckCode '0xD1' 'bugcheck code'
Assert-Equal (Get-NormalizedBugcheck $p.BugcheckCode) '0x000000D1' 'normalised code'
Assert-Equal ($p.Parameters -join ',') '10,2,0,fffff8076a2b1c3d' 'parameters'
Assert-Equal $p.ImageName 'e1d68x64.sys' 'image name'
Assert-Equal $p.ModuleName 'e1d68x64' 'module name'
Assert-Equal $p.ImageVersion '12.19.1.37' 'image version'
Assert-Equal $p.ProcessName 'System' 'process'
Assert-Equal $p.FailureBucket 'AV_e1d68x64!unknown_function' 'bucket'
Assert-Equal $p.CrashTime 'Sun Sep 27 14:02:11.123 2026 (UTC + 10:00)' 'crash time'
Assert-Equal $p.Uptime '0 days 3:12:45.078' 'uptime'
Assert-Equal @($p.Stack).Count 4 'stack lines'
Assert-Equal $p.SymbolProblems $false 'no symbol problems'
Assert-Equal $p.AnalysisComplete $true 'analysis complete'
$rec = Get-Recommendation -Parsed $p -DriverInfo $null
Assert-True ($rec[0] -like 'DRIVER_IRQL_NOT_LESS_OR_EQUAL*') 'hint for 0xD1'
Assert-True ($rec -match 'e1d68x64.sys') 'image named in recommendation'

Write-Host 'legacy-124.txt'
$t = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'samples/legacy-124.txt') -Raw
$p = ConvertFrom-AnalyzeOutput -Text $t
Assert-Equal $p.BugcheckName 'WHEA_UNCORRECTABLE_ERROR' 'bugcheck name'
Assert-Equal $p.BugcheckCode '0x124' 'bugcheck code from name line (BUGCHECK_STR not hex)'
Assert-Equal ($p.Parameters -join ',') '0000000000000000,ffffe00123456028,00000000be000000,0000000000800400' 'Arg parameters'
Assert-Equal $p.ProbablyCausedBy 'GenuineIntel' 'probably caused by'
Assert-Equal $p.ImageName 'GenuineIntel' 'image fallback'
$rec = Get-Recommendation -Parsed $p -DriverInfo $null
Assert-True ($rec[0] -like '*HARDWARE*') 'hardware hint for 0x124'

Write-Host 'extended flag / garbage'
$fake = [pscustomobject]@{ BugcheckCode = '0x1000007E'; ImageName = 'ntkrnlmp.exe'; FailureBucket = $null; SymbolProblems = $true }
$rec = Get-Recommendation -Parsed $fake -DriverInfo $null
Assert-True ($rec[0] -like 'SYSTEM_THREAD_EXCEPTION*') '0x1000007E maps to 0x7E hint'
Assert-True ($rec -match 'generic') 'generic image note'
Assert-True ($rec -match 'Symbol problems') 'symbol warning'
$p = ConvertFrom-AnalyzeOutput -Text 'Could not open dump file'
Assert-Equal $p.BugcheckCode '' 'no code from garbage'
Assert-Equal $p.AnalysisComplete $false 'garbage incomplete'

Write-Host 'argument rebuilding'
$a = ConvertTo-ArgumentList -Bound @{ Days = 3; NoGui = [switch]$true; Quiet = [switch]$false; DumpPath = @('C:\', 'D:\x y\a.dmp') } -Extra @{ PauseOnExit = $true }
Assert-True ($a -contains '-NoGui') 'switch forwarded'
Assert-True ($a -notcontains '-Quiet') 'false switch dropped'
Assert-Equal ($a[-2..-1] -join ' ') '"C:\." "D:\x y\a.dmp"' 'paths trailing + drive root safe'

if ($script:failures) { Write-Host "$script:failures failure(s)" -ForegroundColor Red; exit 1 }
Write-Host 'All tests passed' -ForegroundColor Green
