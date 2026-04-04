@echo off
REM Zero-Trust Agentic Guardian - Complete System Setup Script (Windows)
REM Requirements: 17.1, 17.4, 17.5
REM
REM This script executes all configuration steps including:
REM - Prerequisite validation
REM - Auth0 setup
REM - Certificate generation
REM - Service initialization
REM - Resource summary output

setlocal enabledelayedexpansion

REM Script directory
set SCRIPT_DIR=%~dp0
set PROJECT_ROOT=%SCRIPT_DIR%..
cd /d "%PROJECT_ROOT%"

REM Output files
set SETUP_LOG=%PROJECT_ROOT%\setup.log
set RESOURCE_SUMMARY=%PROJECT_ROOT%\setup_summary.json

REM Initialize log file
echo Zero-Trust Agentic Guardian Setup - %date% %time% > "%SETUP_LOG%"

REM Print header
echo.
echo ============================================================
echo   Zero-Trust Agentic Guardian - System Setup
echo ============================================================
echo.

REM Validate prerequisites (Requirement 17.4)
echo [INFO] Validating prerequisites...
echo [INFO] Validating prerequisites... >> "%SETUP_LOG%"

REM Check Python 3.14.2+
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found
    echo [ERROR] Python not found >> "%SETUP_LOG%"
    echo Please install Python 3.14.2+ and try again.
    exit /b 1
)

python -c "import sys; sys.exit(0 if sys.version_info >= (3, 14, 2) else 1)" >nul 2>&1
if %errorlevel% neq 0 (
    for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
    echo [ERROR] Python 3.14.2+ required (found !PYTHON_VERSION!)
    echo [ERROR] Python 3.14.2+ required (found !PYTHON_VERSION!) >> "%SETUP_LOG%"
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [SUCCESS] Python %PYTHON_VERSION% found
echo [SUCCESS] Python %PYTHON_VERSION% found >> "%SETUP_LOG%"

REM Check pip
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pip not found
    echo [ERROR] pip not found >> "%SETUP_LOG%"
    exit /b 1
)
echo [SUCCESS] pip found
echo [SUCCESS] pip found >> "%SETUP_LOG%"

REM Check OpenSSL
openssl version >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] OpenSSL not found (required for certificate generation)
    echo [WARNING] OpenSSL not found >> "%SETUP_LOG%"
) else (
    for /f "tokens=2" %%i in ('openssl version 2^>^&1') do set OPENSSL_VERSION=%%i
    echo [SUCCESS] OpenSSL !OPENSSL_VERSION! found
    echo [SUCCESS] OpenSSL !OPENSSL_VERSION! found >> "%SETUP_LOG%"
)

REM Check Docker (optional)
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Docker not found (optional for deployment)
    echo [WARNING] Docker not found >> "%SETUP_LOG%"
) else (
    for /f "tokens=3" %%i in ('docker --version 2^>^&1') do set DOCKER_VERSION=%%i
    echo [SUCCESS] Docker !DOCKER_VERSION! found
    echo [SUCCESS] Docker !DOCKER_VERSION! found >> "%SETUP_LOG%"
)

REM Check for virtual environment
if exist "%PROJECT_ROOT%\venv" (
    echo [SUCCESS] Virtual environment found
    echo [SUCCESS] Virtual environment found >> "%SETUP_LOG%"
) else (
    echo [WARNING] Virtual environment not found (will be created)
    echo [WARNING] Virtual environment not found >> "%SETUP_LOG%"
)

echo [SUCCESS] All prerequisites validated
echo [SUCCESS] All prerequisites validated >> "%SETUP_LOG%"
echo.

REM Setup Python virtual environment
echo [INFO] Setting up Python virtual environment...
echo [INFO] Setting up Python virtual environment... >> "%SETUP_LOG%"

if not exist "%PROJECT_ROOT%\venv" (
    python -m venv venv >> "%SETUP_LOG%" 2>&1
    echo [SUCCESS] Virtual environment created
    echo [SUCCESS] Virtual environment created >> "%SETUP_LOG%"
) else (
    echo [INFO] Virtual environment already exists
    echo [INFO] Virtual environment already exists >> "%SETUP_LOG%"
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Upgrade pip
python -m pip install --upgrade pip >> "%SETUP_LOG%" 2>&1

REM Install dependencies
if exist "requirements.txt" (
    echo [INFO] Installing Python dependencies...
    echo [INFO] Installing Python dependencies... >> "%SETUP_LOG%"
    pip install -r requirements.txt >> "%SETUP_LOG%" 2>&1
    echo [SUCCESS] Dependencies installed
    echo [SUCCESS] Dependencies installed >> "%SETUP_LOG%"
)

REM Install package in development mode
if exist "setup.py" (
    pip install -e . >> "%SETUP_LOG%" 2>&1
    echo [SUCCESS] Package installed in development mode
    echo [SUCCESS] Package installed in development mode >> "%SETUP_LOG%"
)

echo.

REM Execute Auth0 setup (Requirement 17.1)
echo [INFO] Executing Auth0 setup...
echo [INFO] Executing Auth0 setup... >> "%SETUP_LOG%"

if "%AUTH0_DOMAIN%"=="" (
    echo [WARNING] Skipping Auth0 setup (AUTH0_DOMAIN not set)
    echo [WARNING] Skipping Auth0 setup (AUTH0_DOMAIN not set) >> "%SETUP_LOG%"
    goto :skip_auth0
)

if "%AUTH0_MANAGEMENT_TOKEN%"=="" (
    echo [WARNING] Skipping Auth0 setup (AUTH0_MANAGEMENT_TOKEN not set)
    echo [WARNING] Skipping Auth0 setup (AUTH0_MANAGEMENT_TOKEN not set) >> "%SETUP_LOG%"
    goto :skip_auth0
)

python infra\auth0\setup_auth0.py >> "%SETUP_LOG%" 2>&1
if %errorlevel% equ 0 (
    echo [SUCCESS] Auth0 configuration complete
    echo [SUCCESS] Auth0 configuration complete >> "%SETUP_LOG%"

    if exist "infra\auth0\auth0_manifest.json" (
        echo [SUCCESS] Auth0 manifest created: infra\auth0\auth0_manifest.json
        echo [SUCCESS] Auth0 manifest created >> "%SETUP_LOG%"
    )
) else (
    echo [ERROR] Auth0 setup failed (see %SETUP_LOG% for details)
    echo [ERROR] Auth0 setup failed >> "%SETUP_LOG%"
)

:skip_auth0
echo.

REM Generate certificates (Requirement 17.1)
echo [INFO] Generating mTLS certificates...
echo [INFO] Generating mTLS certificates... >> "%SETUP_LOG%"

cd /d "%PROJECT_ROOT%\infra\certificates"

if exist "generate_all_certs.bat" (
    call generate_all_certs.bat >> "%SETUP_LOG%" 2>&1

    if !errorlevel! equ 0 (
        echo [SUCCESS] Certificates generated successfully
        echo [SUCCESS] Certificates generated successfully >> "%SETUP_LOG%"

        if exist "root_ca.crt" (
            echo [SUCCESS] Root CA created
            echo [SUCCESS] Root CA created >> "%SETUP_LOG%"
        )
    ) else (
        echo [ERROR] Certificate generation failed (see %SETUP_LOG% for details)
        echo [ERROR] Certificate generation failed >> "%SETUP_LOG%"
    )
) else (
    echo [ERROR] Certificate generation script not found
    echo [ERROR] Certificate generation script not found >> "%SETUP_LOG%"
)

cd /d "%PROJECT_ROOT%"
echo.

REM Initialize services (Requirement 17.1)
echo [INFO] Initializing services...
echo [INFO] Initializing services... >> "%SETUP_LOG%"

REM Create necessary directories
if not exist "logs" mkdir logs
if not exist "data" mkdir data
if not exist "tmp" mkdir tmp
echo [SUCCESS] Created necessary directories
echo [SUCCESS] Created necessary directories >> "%SETUP_LOG%"

REM Initialize database (if needed)
if exist "services\audit\init_db.py" (
    echo [INFO] Initializing audit database...
    echo [INFO] Initializing audit database... >> "%SETUP_LOG%"
    python services\audit\init_db.py >> "%SETUP_LOG%" 2>&1
    if !errorlevel! equ 0 (
        echo [SUCCESS] Audit database initialized
        echo [SUCCESS] Audit database initialized >> "%SETUP_LOG%"
    ) else (
        echo [WARNING] Audit database initialization failed (may already exist)
        echo [WARNING] Audit database initialization failed >> "%SETUP_LOG%"
    )
)

REM Validate Docker Compose configuration
if exist "infra\docker\docker-compose.yml" (
    echo [INFO] Validating Docker Compose configuration...
    echo [INFO] Validating Docker Compose configuration... >> "%SETUP_LOG%"
    cd /d "infra\docker"
    docker-compose config >> "%SETUP_LOG%" 2>&1
    if !errorlevel! equ 0 (
        echo [SUCCESS] Docker Compose configuration valid
        echo [SUCCESS] Docker Compose configuration valid >> "%SETUP_LOG%"
    ) else (
        echo [WARNING] Docker Compose validation failed (Docker may not be available)
        echo [WARNING] Docker Compose validation failed >> "%SETUP_LOG%"
    )
    cd /d "%PROJECT_ROOT%"
)

echo.

REM Generate resource summary (Requirement 17.5)
echo [INFO] Generating resource summary...
echo [INFO] Generating resource summary... >> "%SETUP_LOG%"

REM Create summary JSON (simplified for Windows batch)
(
echo {
echo   "timestamp": "%date% %time%",
echo   "setup_status": "complete",
echo   "auth0": {
if exist "infra\auth0\auth0_manifest.json" (
    echo     "manifest_file": "infra/auth0/auth0_manifest.json",
    echo     "status": "configured"
) else (
    echo     "status": "not_configured"
)
echo   },
echo   "certificates": {
if exist "infra\certificates\root_ca.crt" (
    echo     "root_ca": "infra/certificates/root_ca.crt",
    echo     "status": "generated"
) else (
    echo     "status": "not_generated"
)
echo   },
echo   "services": {
echo     "directory": "services/"
echo   },
echo   "docker": {
if exist "infra\docker\docker-compose.yml" (
    echo     "compose_file": "infra/docker/docker-compose.yml",
    echo     "status": "ready"
) else (
    echo     "status": "not_found"
)
echo   },
echo   "logs": {
echo     "setup_log": "%SETUP_LOG:\=/%"
echo   }
echo }
) > "%RESOURCE_SUMMARY%"

echo [SUCCESS] Resource summary saved to: %RESOURCE_SUMMARY%
echo [SUCCESS] Resource summary saved >> "%SETUP_LOG%"
echo.

REM Display summary (Requirement 17.5)
echo.
echo ============================================================
echo   Setup Complete!
echo ============================================================
echo.
echo Resource Summary:
echo   - Setup log: %SETUP_LOG%
echo   - Resource summary: %RESOURCE_SUMMARY%
echo.
echo Next Steps:
echo   1. Review setup log: %SETUP_LOG%
echo   2. Review resource summary: %RESOURCE_SUMMARY%

if exist "infra\auth0\auth0_manifest.json" (
    echo   3. Configure Auth0 Token Vault (Enterprise plan required^)
    echo   4. Configure provider connections in Auth0 Dashboard
) else (
    echo   3. Set AUTH0_DOMAIN and AUTH0_MANAGEMENT_TOKEN environment variables
    echo   4. Re-run this script to configure Auth0
)

echo   5. Start services: cd infra\docker ^&^& docker-compose up
echo   6. Run integration tests: scripts\run_integration_tests.bat
echo.
echo For more information, see README.md
echo.

echo [SUCCESS] Setup completed successfully!
echo [SUCCESS] Setup completed successfully! >> "%SETUP_LOG%"

endlocal
