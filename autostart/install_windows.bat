@echo off
rem Makes Tapo Watch start by itself when you sign in to Windows.
set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
powershell -NoProfile -Command "$s=(New-Object -COM WScript.Shell).CreateShortcut('%STARTUP%\TapoWatch.lnk'); $s.TargetPath='%~dp0start_tapo_watch.bat'; $s.WorkingDirectory='%~dp0'; $s.WindowStyle=7; $s.Save()"
echo Done. Tapo Watch will now start when you sign in.
echo For power cuts: turn on "Restore on AC power loss" in your PC's BIOS and set Windows to sign in automatically.
pause
