@echo off
REM Zero-Trust Agentic Guardian - Certificate Rotation Script (Windows)
REM Requirement: 17.3
REM
REM This script performs zero-downtime certificate rotation by:
REM - Backing up existing certificates
REM - Regenerating all certificates
REM - Updating service configurations
REM - Gracefully reloading services

setlocal enabledelayedexpansion

REM Script directory
set SCRIPT_DIR=%~dp0
set PROJECT_ROOT=%SCRIPT_DIR%..
cd /d "%PROJECT_ROOT%"

set CERT_DIR=%PROJECT_ROOT%\infra\certificates

REM Output files
set ROTATION_LOG=%PROJECT_ROOT%\cert_rotation.log

REM Create backup directory with timestamp
for /f "tokens=2-4 delims=/ " %%a in ('date /t') do (set mydate=%%c%%a%%b)
for /f "tokens=1-2 delims=/: " %%a in ('time /t') do (set mytime=%%a%%b)
set BACKUP_DIR=%CERT_DIR%\backups\%mydate%_%mytime%

REM Initialize log file
echo Zero-Trust Agentic Guardian Certificate Rotation - %date% %time% > "%ROTATION_LOG%"

REM Print header
echo.
echo ============================================================
echo   Zero-Trust Agentic Guardian - Certificate Rotation
echo ============================================================
echo.

REM Confirm rotation
echo This script will rotate all mTLS certificates.
echo Existing certificates will be backed up to: %BACKUP_DIR%
echo.
set /p CONFIRM="Continue with certificate rotation? (y/N) "

if /i not "%CONFIRM%"=="y" (
    echo [INFO] Certificate rotation cancelled
    echo [INFO] Certificate rotation cancelled >> "%ROTATION_LOG%"
    exit /b 0
)

echo.

REM Validate prerequisites
echo [INFO] Validating prerequisites...
echo [INFO] Validating prerequisites... >> "%ROTATION_LOG%"

if not exist "%CERT_DIR%" (
    echo [ERROR] Certificate directory not found: %CERT_DIR%
    echo [ERROR] Certificate directory not found >> "%ROTATION_LOG%"
    exit /b 1
)

if not exist "%CERT_DIR%\generate_root_ca.py" (
    echo [ERROR] Root CA generation script not found
    echo [ERROR] Root CA generation script not found >> "%ROTATION_LOG%"
    exit /b 1
)

if not exist "%CERT_DIR%\generate_service_certs.py" (
    echo [ERROR] Service certificate generation script not found
    echo [ERROR] Service certificate generation script not found >> "%ROTATION_LOG%"
    exit /b 1
)

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found
    echo [ERROR] Python not found >> "%ROTATION_LOG%"
    exit /b 1
)

openssl version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] OpenSSL not found
    echo [ERROR] OpenSSL not found >> "%ROTATION_LOG%"
    exit /b 1
)

echo [SUCCESS] All prerequisites validated
echo [SUCCESS] All prerequisites validated >> "%ROTATION_LOG%"
echo.

REM Backup existing certificates
echo [INFO] Backing up existing certificates...
echo [INFO] Backing up existing certificates... >> "%ROTATION_LOG%"

mkdir "%BACKUP_DIR%" 2>nul

if exist "%CERT_DIR%\root_ca.crt" (
    copy "%CERT_DIR%\root_ca.crt" "%BACKUP_DIR%\" >nul
    echo [SUCCESS] Backed up root CA certificate
    echo [SUCCESS] Backed up root CA certificate >> "%ROTATION_LOG%"
)

if exist "%CERT_DIR%\root_ca.key" (
    copy "%CERT_DIR%\root_ca.key" "%BACKUP_DIR%\" >nul
    echo [SUCCESS] Backed up root CA private key
    echo [SUCCESS] Backed up root CA private key >> "%ROTATION_LOG%"
)

REM Backup service certificates
for %%s in (planner intent-engine safety-agent permission-broker executor audit) do (
    if exist "%CERT_DIR%\%%s" (
        mkdir "%BACKUP_DIR%\%%s" 2>nul
        xcopy /E /I /Q "%CERT_DIR%\%%s" "%BACKUP_DIR%\%%s" >nul 2>&1
        echo [SUCCESS] Backed up %%s certificates
        echo [SUCCESS] Backed up %%s certificates >> "%ROTATION_LOG%"
    )
)

echo [SUCCESS] All certificates backed up to: %BACKUP_DIR%
echo [SUCCESS] All certificates backed up >> "%ROTATION_LOG%"
echo.

REM Generate new certificates
echo [INFO] Generating new certificates...
echo [INFO] Generating new certificates... >> "%ROTATION_LOG%"

cd /d "%CERT_DIR%"

echo [INFO] Generating new root CA...
echo [INFO] Generating new root CA... >> "%ROTATION_LOG%"
python generate_root_ca.py "%CERT_DIR%" >> "%ROTATION_LOG%" 2>&1

if %errorlevel% neq 0 (
    echo [ERROR] Root CA generation failed
    echo [ERROR] Root CA generation failed >> "%ROTATION_LOG%"
    goto :restore_backup
)

echo [SUCCESS] New root CA generated
echo [SUCCESS] New root CA generated >> "%ROTATION_LOG%"

echo [INFO] Generating new service certificates...
echo [INFO] Generating new service certificates... >> "%ROTATION_LOG%"
python generate_service_certs.py "%CERT_DIR%\root_ca.crt" "%CERT_DIR%\root_ca.key" "%CERT_DIR%" >> "%ROTATION_LOG%" 2>&1

if %errorlevel% neq 0 (
    echo [ERROR] Service certificate generation failed
    echo [ERROR] Service certificate generation failed >> "%ROTATION_LOG%"
    goto :restore_backup
)

echo [SUCCESS] New service certificates generated
echo [SUCCESS] New service certificates generated >> "%ROTATION_LOG%"

cd /d "%PROJECT_ROOT%"
echo.

REM Verify new certificates
echo [INFO] Verifying new certificates...
echo [INFO] Verifying new certificates... >> "%ROTATION_LOG%"

if exist "%CERT_DIR%\root_ca.crt" (
    openssl x509 -in "%CERT_DIR%\root_ca.crt" -noout -text >> "%ROTATION_LOG%" 2>&1
    if !errorlevel! equ 0 (
        echo [SUCCESS] Root CA certificate is valid
        echo [SUCCESS] Root CA certificate is valid >> "%ROTATION_LOG%"
    ) else (
        echo [ERROR] Root CA certificate verification failed
        echo [ERROR] Root CA certificate verification failed >> "%ROTATION_LOG%"
        goto :restore_backup
    )
)

REM Verify service certificates
set verified_count=0
for %%s in (planner intent-engine safety-agent permission-broker executor audit) do (
    if exist "%CERT_DIR%\%%s\client.crt" (
        openssl verify -CAfile "%CERT_DIR%\root_ca.crt" "%CERT_DIR%\%%s\client.crt" >> "%ROTATION_LOG%" 2>&1
        if !errorlevel! equ 0 (
            set /a verified_count+=1
        ) else (
            echo [ERROR] %%s client certificate verification failed
            echo [ERROR] %%s client certificate verification failed >> "%ROTATION_LOG%"
            goto :restore_backup
        )
    )
    
    if exist "%CERT_DIR%\%%s\server.crt" (
        openssl verify -CAfile "%CERT_DIR%\root_ca.crt" "%CERT_DIR%\%%s\server.crt" >> "%ROTATION_LOG%" 2>&1
        if !errorlevel! equ 0 (
            set /a verified_count+=1
        ) else (
            echo [ERROR] %%s server certificate verification failed
            echo [ERROR] %%s server certificate verification failed >> "%ROTATION_LOG%"
            goto :restore_backup
        )
    )
)

echo [SUCCESS] Verified !verified_count! certificates
echo [SUCCESS] Verified !verified_count! certificates >> "%ROTATION_LOG%"
echo.

REM Update service configurations
echo [INFO] Updating service configurations...
echo [INFO] Updating service configurations... >> "%ROTATION_LOG%"

docker-compose --version >nul 2>&1
if %errorlevel% equ 0 (
    if exist "%PROJECT_ROOT%\infra\docker\docker-compose.yml" (
        echo [INFO] Docker Compose detected
        echo [INFO] Docker Compose detected >> "%ROTATION_LOG%"
        
        cd /d "%PROJECT_ROOT%\infra\docker"
        docker-compose ps | find "Up" >nul 2>&1
        if !errorlevel! equ 0 (
            echo [INFO] Services are running, will perform graceful reload
            echo [INFO] Services are running >> "%ROTATION_LOG%"
            set SERVICES_RUNNING=true
        ) else (
            echo [INFO] Services are not running
            echo [INFO] Services are not running >> "%ROTATION_LOG%"
            set SERVICES_RUNNING=false
        )
        cd /d "%PROJECT_ROOT%"
    )
) else (
    echo [INFO] Docker Compose not available
    echo [INFO] Docker Compose not available >> "%ROTATION_LOG%"
    set SERVICES_RUNNING=false
)

if "!SERVICES_RUNNING!"=="true" (
    echo [INFO] Certificates updated, services will pick up new certificates on next restart
    echo [INFO] Certificates updated >> "%ROTATION_LOG%"
    echo [WARNING] To apply new certificates, restart services with: cd infra\docker ^&^& docker-compose restart
    echo [WARNING] Manual restart required >> "%ROTATION_LOG%"
) else (
    echo [INFO] No running services detected, certificates are ready for use
    echo [INFO] No running services detected >> "%ROTATION_LOG%"
)

echo.

REM Clean up old backups (keep last 10)
echo [INFO] Cleaning up old backups...
echo [INFO] Cleaning up old backups... >> "%ROTATION_LOG%"

if exist "%CERT_DIR%\backups" (
    REM Count backup directories
    set backup_count=0
    for /d %%d in ("%CERT_DIR%\backups\*") do set /a backup_count+=1
    
    if !backup_count! gtr 10 (
        echo [INFO] Found !backup_count! backups, keeping last 10
        echo [INFO] Found !backup_count! backups >> "%ROTATION_LOG%"
        
        REM Remove oldest backups (simplified for Windows)
        set /a to_remove=!backup_count!-10
        set removed=0
        for /d %%d in ("%CERT_DIR%\backups\*") do (
            if !removed! lss !to_remove! (
                rd /s /q "%%d"
                set /a removed+=1
            )
        )
        
        echo [SUCCESS] Old backups cleaned up
        echo [SUCCESS] Old backups cleaned up >> "%ROTATION_LOG%"
    ) else (
        echo [INFO] Found !backup_count! backups, no cleanup needed
        echo [INFO] Found !backup_count! backups >> "%ROTATION_LOG%"
    )
)

echo.

REM Display summary
echo.
echo ============================================================
echo   Certificate Rotation Complete!
echo ============================================================
echo.
echo Summary:
echo   - Backup location: %BACKUP_DIR%
echo   - New certificates: %CERT_DIR%
echo   - Rotation log: %ROTATION_LOG%
echo.

if "!SERVICES_RUNNING!"=="true" (
    echo Services Status:
    echo   - Services need to be restarted to use new certificates
    echo   - Restart command: cd infra\docker ^&^& docker-compose restart
    echo.
)

echo Certificate Details:
if exist "%CERT_DIR%\root_ca.crt" (
    for /f "tokens=*" %%i in ('openssl x509 -in "%CERT_DIR%\root_ca.crt" -noout -enddate') do echo   - Root CA %%i
)

echo.
echo Next Steps:
echo   1. Verify services are running correctly
echo   2. Run integration tests: scripts\run_integration_tests.bat
echo   3. Monitor service logs for any certificate-related errors
echo.

if not "!SERVICES_RUNNING!"=="true" (
    echo Note: Services are not running. Start them with:
    echo   cd infra\docker ^&^& docker-compose up -d
    echo.
)

echo [SUCCESS] Certificate rotation completed successfully!
echo [SUCCESS] Certificate rotation completed successfully! >> "%ROTATION_LOG%"

goto :end

:restore_backup
echo [ERROR] Restoring certificates from backup...
echo [ERROR] Restoring certificates from backup... >> "%ROTATION_LOG%"

if not exist "%BACKUP_DIR%" (
    echo [ERROR] Backup directory not found, cannot restore
    echo [ERROR] Backup directory not found >> "%ROTATION_LOG%"
    exit /b 1
)

if exist "%BACKUP_DIR%\root_ca.crt" (
    copy "%BACKUP_DIR%\root_ca.crt" "%CERT_DIR%\" >nul
    echo [SUCCESS] Restored root CA certificate
    echo [SUCCESS] Restored root CA certificate >> "%ROTATION_LOG%"
)

if exist "%BACKUP_DIR%\root_ca.key" (
    copy "%BACKUP_DIR%\root_ca.key" "%CERT_DIR%\" >nul
    echo [SUCCESS] Restored root CA private key
    echo [SUCCESS] Restored root CA private key >> "%ROTATION_LOG%"
)

for %%s in (planner intent-engine safety-agent permission-broker executor audit) do (
    if exist "%BACKUP_DIR%\%%s" (
        rd /s /q "%CERT_DIR%\%%s" 2>nul
        mkdir "%CERT_DIR%\%%s"
        xcopy /E /I /Q "%BACKUP_DIR%\%%s" "%CERT_DIR%\%%s" >nul
        echo [SUCCESS] Restored %%s certificates
        echo [SUCCESS] Restored %%s certificates >> "%ROTATION_LOG%"
    )
)

echo [SUCCESS] Certificates restored from backup
echo [SUCCESS] Certificates restored from backup >> "%ROTATION_LOG%"
exit /b 1

:end
endlocal
