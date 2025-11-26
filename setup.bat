@echo off
REM Setup script for WinSCP Extension (Windows)

echo ================================================================
echo.
echo            WinSCP Extension - Installation Script
echo.
echo ================================================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from https://www.python.org/
    exit /b 1
)

echo [OK] Python found
python --version

REM Check if pip is available
pip --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] pip is not installed
    echo Please install pip or reinstall Python with pip included
    exit /b 1
)

echo [OK] pip found

REM Install dependencies
echo.
echo Installing dependencies...
pip install -r requirements.txt

if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    exit /b 1
)

echo.
echo [OK] Installation complete!
echo.
echo Next steps:
echo   1. Run 'python main.py info' to see system information
echo   2. Run 'python main.py setup' to start the setup wizard
echo   3. See QUICKSTART.md for usage examples
echo.
echo For help: python main.py --help
echo.
pause
