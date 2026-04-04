@echo off
REM Setup script for Zero-Trust Agentic Guardian Architecture on Windows

echo ========================================
echo Zero-Trust Agentic Guardian Setup
echo ========================================
echo.

REM Check Python version
python --version 2>NUL
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.14.2 or higher
    exit /b 1
)

python -c "import sys; sys.exit(0 if sys.version_info >= (3, 14, 2) else 1)" >NUL 2>&1
if errorlevel 1 (
    for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
    echo ERROR: Python 3.14.2 or higher is required. Found %PYTHON_VERSION%
    exit /b 1
)

echo Creating virtual environment...
python -m venv venv
if errorlevel 1 (
    echo ERROR: Failed to create virtual environment
    exit /b 1
)

echo.
echo Activating virtual environment...
call venv\Scripts\activate.bat

echo.
echo Upgrading pip...
python -m pip install --upgrade pip

echo.
echo Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    exit /b 1
)

echo.
echo Installing package in development mode...
pip install -e .
if errorlevel 1 (
    echo ERROR: Failed to install package
    exit /b 1
)

echo.
echo ========================================
echo Setup completed successfully!
echo ========================================
echo.
echo To activate the virtual environment, run:
echo   venv\Scripts\activate.bat
echo.
echo To deactivate, run:
echo   deactivate
echo.
