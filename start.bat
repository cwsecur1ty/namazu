@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    python -m venv .venv
    if errorlevel 1 goto failed
)
if not exist ".venv\namazu-installed" (
    ".venv\Scripts\python.exe" -m pip install .
    if errorlevel 1 goto failed
    type nul > ".venv\namazu-installed"
)
echo Starting Namazu. The listening address appears below.
".venv\Scripts\python.exe" -m namazu %*
if errorlevel 1 goto failed
exit /b 0
:failed
echo Namazu could not start. See the error above and the README for setup instructions.
pause
exit /b 1
