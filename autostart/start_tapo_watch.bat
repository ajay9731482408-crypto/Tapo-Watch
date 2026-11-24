@echo off
rem Starts Tapo Watch and restarts it if it ever stops.
cd /d "%~dp0.."
:loop
python app.py
timeout /t 5 /nobreak >nul
goto loop
