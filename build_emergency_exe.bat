@echo off
echo ========================================================
echo   Building Standalone Emergency Extractor (PyInstaller)
echo ========================================================
echo.
echo Terminating any running instances to release file locks...
taskkill /F /IM emergency_dump.exe /T 2>nul

echo Waiting for file locks to release...
timeout /t 2 /nobreak >nul
if exist "dist\emergency_dump.exe" del /F /Q "dist\emergency_dump.exe"
if exist "build" rmdir /S /Q "build"
echo.
echo Installing required dependencies...
pip install pyinstaller cryptography argon2-cffi tkinterdnd2
echo.
echo Compiling emergency_dump.py into a single executable...
pyinstaller --onefile --noconsole --collect-data tkinterdnd2 emergency_dump.py
echo.
echo ✅ Done! You can find 'emergency_dump.exe' inside the 'dist' folder.
echo    Move this .exe to your USB drive for break-glass emergencies!
pause
