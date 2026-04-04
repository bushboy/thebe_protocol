@echo off
REM Zero-Trust Agentic Guardian - Integration Test Runner (Windows)
REM Requirement: 17.2
REM
REM This script runs all integration tests and reports results

setlocal enabledelayedexpansion

REM Script directory
set SCRIPT_DIR=%~dp0
set PROJECT_ROOT=%SCRIPT_DIR%..
cd /d "%PROJECT_ROOT%"

REM Output files
set TEST_LOG=%PROJECT_ROOT%\integration_tests.log
set TEST_REPORT=%PROJECT_ROOT%\integration_test_report.json

REM Test configuration
set PYTEST_ARGS=-v --tb=short --color=yes
set INTEGRATION_TEST_DIR=%PROJECT_ROOT%\tests\integration
set ATTACK_SCENARIO_DIR=%PROJECT_ROOT%\tests\attack-scenarios

REM Initialize log file
echo Zero-Trust Agentic Guardian Integration Tests - %date% %time% > "%TEST_LOG%"

REM Print header
echo.
echo ============================================================
echo   Zero-Trust Agentic Guardian - Integration Tests
echo ============================================================
echo.

REM Check prerequisites
echo [INFO] Checking prerequisites...
echo [INFO] Checking prerequisites... >> "%TEST_LOG%"

REM Check if virtual environment is activated
if "%VIRTUAL_ENV%"=="" (
    echo [WARNING] Virtual environment not activated
    echo [WARNING] Virtual environment not activated >> "%TEST_LOG%"
    
    if exist "%PROJECT_ROOT%\venv" (
        echo [INFO] Activating virtual environment...
        echo [INFO] Activating virtual environment... >> "%TEST_LOG%"
        call venv\Scripts\activate.bat
        echo [SUCCESS] Virtual environment activated
        echo [SUCCESS] Virtual environment activated >> "%TEST_LOG%"
    ) else (
        echo [ERROR] Virtual environment not found. Run setup_all.bat first.
        echo [ERROR] Virtual environment not found >> "%TEST_LOG%"
        exit /b 1
    )
) else (
    echo [SUCCESS] Virtual environment active: %VIRTUAL_ENV%
    echo [SUCCESS] Virtual environment active >> "%TEST_LOG%"
)

REM Check if pytest is installed
pytest --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pytest not found. Install with: pip install pytest
    echo [ERROR] pytest not found >> "%TEST_LOG%"
    exit /b 1
)

for /f "tokens=*" %%i in ('pytest --version 2^>^&1') do (
    echo [SUCCESS] %%i
    echo [SUCCESS] %%i >> "%TEST_LOG%"
    goto :pytest_found
)
:pytest_found

REM Check if test directories exist
if not exist "%INTEGRATION_TEST_DIR%" (
    echo [WARNING] Integration test directory not found: %INTEGRATION_TEST_DIR%
    echo [WARNING] Integration test directory not found >> "%TEST_LOG%"
)

if not exist "%ATTACK_SCENARIO_DIR%" (
    echo [WARNING] Attack scenario directory not found: %ATTACK_SCENARIO_DIR%
    echo [WARNING] Attack scenario directory not found >> "%TEST_LOG%"
)

echo.

REM Initialize status variables
set unit_test_status=not_run
set integration_test_status=not_run
set attack_scenario_status=not_run
set property_test_status=not_run
set overall_status=0

REM Run unit tests
echo.
echo [INFO] Running unit tests...
echo [INFO] Running unit tests... >> "%TEST_LOG%"

pytest tests\ --ignore=tests\integration --ignore=tests\attack-scenarios %PYTEST_ARGS% --junitxml=unit_test_results.xml >> "%TEST_LOG%" 2>&1

if %errorlevel% equ 0 (
    echo [SUCCESS] Unit tests passed
    echo [SUCCESS] Unit tests passed >> "%TEST_LOG%"
    set unit_test_status=passed
) else (
    echo [ERROR] Unit tests failed (exit code: %errorlevel%^)
    echo [ERROR] Unit tests failed >> "%TEST_LOG%"
    set unit_test_status=failed
    set overall_status=1
)

echo.

REM Run integration tests
echo [INFO] Running integration tests...
echo [INFO] Running integration tests... >> "%TEST_LOG%"

if not exist "%INTEGRATION_TEST_DIR%\*.py" (
    echo [WARNING] No integration tests found in %INTEGRATION_TEST_DIR%
    echo [WARNING] No integration tests found >> "%TEST_LOG%"
    set integration_test_status=skipped
    goto :skip_integration
)

pytest "%INTEGRATION_TEST_DIR%" %PYTEST_ARGS% --junitxml=integration_test_results.xml >> "%TEST_LOG%" 2>&1

if !errorlevel! equ 0 (
    echo [SUCCESS] Integration tests passed
    echo [SUCCESS] Integration tests passed >> "%TEST_LOG%"
    set integration_test_status=passed
) else (
    echo [ERROR] Integration tests failed (exit code: !errorlevel!^)
    echo [ERROR] Integration tests failed >> "%TEST_LOG%"
    set integration_test_status=failed
    set overall_status=1
)

:skip_integration
echo.

REM Run attack scenario tests
echo [INFO] Running attack scenario tests...
echo [INFO] Running attack scenario tests... >> "%TEST_LOG%"

if not exist "%ATTACK_SCENARIO_DIR%\*.py" (
    echo [WARNING] No attack scenario tests found in %ATTACK_SCENARIO_DIR%
    echo [WARNING] No attack scenario tests found >> "%TEST_LOG%"
    set attack_scenario_status=skipped
    goto :skip_attack
)

pytest "%ATTACK_SCENARIO_DIR%" %PYTEST_ARGS% --junitxml=attack_scenario_results.xml >> "%TEST_LOG%" 2>&1

if !errorlevel! equ 0 (
    echo [SUCCESS] Attack scenario tests passed
    echo [SUCCESS] Attack scenario tests passed >> "%TEST_LOG%"
    set attack_scenario_status=passed
) else (
    echo [ERROR] Attack scenario tests failed (exit code: !errorlevel!^)
    echo [ERROR] Attack scenario tests failed >> "%TEST_LOG%"
    set attack_scenario_status=failed
    set overall_status=1
)

:skip_attack
echo.

REM Run property-based tests
echo [INFO] Running property-based tests...
echo [INFO] Running property-based tests... >> "%TEST_LOG%"

pytest tests\ -k "properties" %PYTEST_ARGS% --junitxml=property_test_results.xml >> "%TEST_LOG%" 2>&1

if !errorlevel! equ 0 (
    echo [SUCCESS] Property-based tests passed
    echo [SUCCESS] Property-based tests passed >> "%TEST_LOG%"
    set property_test_status=passed
) else (
    echo [ERROR] Property-based tests failed (exit code: !errorlevel!^)
    echo [ERROR] Property-based tests failed >> "%TEST_LOG%"
    set property_test_status=failed
    set overall_status=1
)

echo.

REM Generate test report
echo [INFO] Generating test report...
echo [INFO] Generating test report... >> "%TEST_LOG%"

REM Create JSON report (simplified for Windows batch)
(
echo {
echo   "timestamp": "%date% %time%",
echo   "summary": {
echo     "status": "completed"
echo   },
echo   "test_suites": {
echo     "unit_tests": {
echo       "status": "!unit_test_status!",
echo       "results_file": "unit_test_results.xml"
echo     },
echo     "integration_tests": {
echo       "status": "!integration_test_status!",
echo       "results_file": "integration_test_results.xml"
echo     },
echo     "attack_scenarios": {
echo       "status": "!attack_scenario_status!",
echo       "results_file": "attack_scenario_results.xml"
echo     },
echo     "property_tests": {
echo       "status": "!property_test_status!",
echo       "results_file": "property_test_results.xml"
echo     }
echo   },
echo   "logs": {
echo     "test_log": "%TEST_LOG:\=/%"
echo   }
echo }
) > "%TEST_REPORT%"

echo [SUCCESS] Test report saved to: %TEST_REPORT%
echo [SUCCESS] Test report saved >> "%TEST_LOG%"
echo.

REM Display summary
echo.
echo ============================================================
echo   Test Results Summary
echo ============================================================
echo.
echo Test Suites:
echo   - Unit tests: !unit_test_status!
echo   - Integration tests: !integration_test_status!
echo   - Attack scenarios: !attack_scenario_status!
echo   - Property tests: !property_test_status!
echo.
echo Detailed Results:
echo   - Test log: %TEST_LOG%
echo   - Test report: %TEST_REPORT%
echo.

if !overall_status! equ 0 (
    echo [SUCCESS] All tests passed!
) else (
    echo [ERROR] Some tests failed. See %TEST_LOG% for details.
)

echo.

endlocal
exit /b !overall_status!
