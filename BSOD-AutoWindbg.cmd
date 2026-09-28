@echo off
rem Double-click to open the GUI, or drag .dmp files / folders onto this file to analyse them.
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0BSOD-AutoWindbg.ps1" %*
exit /b %errorlevel%
