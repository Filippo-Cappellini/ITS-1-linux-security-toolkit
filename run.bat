@echo off
rem Avvio di LSTK su Windows (doppio clic oppure "run.bat scan --format table").
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
