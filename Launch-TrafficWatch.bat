@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0start.ps1"
if errorlevel 1 (
  set "ERRFILE=%~dp0data\last-launch-error.txt"
  if exist "%ERRFILE%" start notepad "%ERRFILE%"
  powershell.exe -NoProfile -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('TrafficWatch failed to start. See last-launch-error.txt if present.','TrafficWatch')"
  echo.
  echo TrafficWatch failed to start. See messages above.
  pause
)
