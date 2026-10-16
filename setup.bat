@echo off
REM Sentinel Vulnerability Scanner - automatic setup script (Windows)

echo == Sentinel Vulnerability Scanner setup ==

where python >nul 2>nul
if errorlevel 1 (
    echo ERROR: python was not found on PATH. Please install Python 3.12+.
    exit /b 1
)

if not exist ".venv" (
    echo Creating virtual environment in .venv ...
    python -m venv .venv
)

call .venv\Scripts\activate.bat

echo Upgrading pip...
python -m pip install --upgrade pip >nul

echo Installing dependencies from requirements.txt...
pip install -r requirements.txt

echo Creating runtime directories...
if not exist "logs" mkdir logs
if not exist "exports" mkdir exports
if not exist "database" mkdir database

where nmap >nul 2>nul
if errorlevel 1 (
    echo NOTE: nmap.exe not found on PATH.
    echo   The application will run using its built-in fallback scanner.
    echo   Install nmap for full functionality: https://nmap.org/download.html
) else (
    echo nmap found.
)

echo.
echo Setup complete. To run the application:
echo   .venv\Scripts\activate.bat
echo   python main.py
