@echo off
REM Validation script for Docker deployment setup (Windows)
REM This script checks that all prerequisites are in place before running docker-compose

setlocal enabledelayedexpansion

echo === Zero-Trust Agentic Guardian - Docker Setup Validation ===
echo.

set ERRORS=0
set WARNINGS=0

REM Check Docker installation
echo 1. Checking Docker installation...
docker --version >nul 2>&1
if %errorlevel% equ 0 (
    for /f "tokens=*" %%i in ('docker --version') do set DOCKER_VERSION=%%i
    echo [OK] Docker is installed: !DOCKER_VERSION!
) else (
    echo [ERROR] Docker is not installed. Please install Docker first.
    set /a ERRORS+=1
)

echo.
echo 2. Checking Docker Compose installation...
docker-compose --version >nul 2>&1
if %errorlevel% equ 0 (
    for /f "tokens=*" %%i in ('docker-compose --version') do set COMPOSE_VERSION=%%i
    echo [OK] Docker Compose is installed: !COMPOSE_VERSION!
) else (
    echo [ERROR] Docker Compose is not installed. Please install Docker Compose first.
    set /a ERRORS+=1
)

echo.
echo 3. Checking environment file...
if exist ".env" (
    echo [OK] Environment file (.env^) exists
    
    REM Check for required variables
    findstr /C:"AUTH0_DOMAIN=" .env >nul 2>&1
    if %errorlevel% equ 0 (
        echo [OK]   AUTH0_DOMAIN is set
    ) else (
        echo [ERROR]   AUTH0_DOMAIN is not set
        set /a ERRORS+=1
    )
    
    findstr /C:"AUTH0_AUDIENCE=" .env >nul 2>&1
    if %errorlevel% equ 0 (
        echo [OK]   AUTH0_AUDIENCE is set
    ) else (
        echo [ERROR]   AUTH0_AUDIENCE is not set
        set /a ERRORS+=1
    )
) else (
    echo [ERROR] Environment file (.env^) not found. Copy .env.example to .env and configure it.
    set /a ERRORS+=1
)

echo.
echo 4. Checking certificate directory...
if exist "..\certificates\root-ca" (
    echo [OK] Root CA directory exists
    
    if exist "..\certificates\root-ca\ca.crt" (
        echo [OK]   Root CA certificate found
    ) else (
        echo [ERROR]   Root CA certificate not found. Run infra\certificates\generate_all_certs.bat
        set /a ERRORS+=1
    )
) else (
    echo [ERROR] Certificate directory not found. Run infra\certificates\generate_all_certs.bat
    set /a ERRORS+=1
)

echo.
echo 5. Checking service certificates...
for %%s in (intent-engine planner safety-agent permission-broker executor audit) do (
    if exist "..\certificates\%%s" (
        if exist "..\certificates\%%s\client.crt" (
            if exist "..\certificates\%%s\client.key" (
                if exist "..\certificates\%%s\server.crt" (
                    if exist "..\certificates\%%s\server.key" (
                        echo [OK]   %%s certificates complete
                    ) else (
                        echo [ERROR]   %%s server.key not found
                        set /a ERRORS+=1
                    )
                ) else (
                    echo [ERROR]   %%s server.crt not found
                    set /a ERRORS+=1
                )
            ) else (
                echo [ERROR]   %%s client.key not found
                set /a ERRORS+=1
            )
        ) else (
            echo [ERROR]   %%s client.crt not found
            set /a ERRORS+=1
        )
    ) else (
        echo [ERROR]   %%s certificate directory not found
        set /a ERRORS+=1
    )
)

echo.
echo 6. Checking OPA policies...
if exist "..\opa\policies" (
    dir /b /s "..\opa\policies\*.rego" >nul 2>&1
    if %errorlevel% equ 0 (
        echo [OK] OPA policy files found
    ) else (
        echo [WARNING] No .rego policy files found in ..\opa\policies
        set /a WARNINGS+=1
    )
) else (
    echo [ERROR] OPA policies directory not found
    set /a ERRORS+=1
)

echo.
echo 7. Checking Docker daemon...
docker info >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Docker daemon is running
) else (
    echo [ERROR] Docker daemon is not running. Please start Docker.
    set /a ERRORS+=1
)

echo.
echo === Validation Summary ===
if !ERRORS! equ 0 (
    if !WARNINGS! equ 0 (
        echo All checks passed! You can run 'docker-compose up -d'
        exit /b 0
    ) else (
        echo Validation completed with !WARNINGS! warning(s^).
        echo You can proceed, but some features may not work correctly.
        exit /b 0
    )
) else (
    echo Validation failed with !ERRORS! error(s^) and !WARNINGS! warning(s^).
    echo Please fix the errors before running docker-compose.
    exit /b 1
)
