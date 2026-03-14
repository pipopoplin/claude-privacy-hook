@echo off
REM ============================================================================
REM Claude Privacy Hook (Free Tier) — Installation Script (Windows)
REM ============================================================================
REM
REM Usage:
REM   install_win.bat
REM
REM The free tier uses stdlib only — no external dependencies needed.
REM NLP-based PII detection is available in the Pro tier.
REM ============================================================================

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "PYTHON_MIN_MAJOR=3"
set "PYTHON_MIN_MINOR=10"

REM --- Find Python ---
echo [INFO]  Looking for Python %PYTHON_MIN_MAJOR%.%PYTHON_MIN_MINOR%+...

set "PYTHON="
for %%P in (python3 python py) do (
    if not defined PYTHON (
        where %%P >nul 2>&1
        if !errorlevel! equ 0 (
            for /f "tokens=*" %%V in ('%%P -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2^>nul') do (
                for /f "tokens=1,2 delims=." %%A in ("%%V") do (
                    if %%A geq %PYTHON_MIN_MAJOR% if %%B geq %PYTHON_MIN_MINOR% (
                        set "PYTHON=%%P"
                    )
                )
            )
        )
    )
)

if not defined PYTHON (
    echo [FAIL] Python %PYTHON_MIN_MAJOR%.%PYTHON_MIN_MINOR%+ is required but not found.
    echo        Download from https://www.python.org/downloads/
    echo        Make sure to check "Add Python to PATH" during installation.
    exit /b 1
)

for /f "tokens=*" %%V in ('%PYTHON% --version 2^>^&1') do set "PYTHON_VER=%%V"
echo [ OK ]  Found %PYTHON_VER%

REM --- Verify core hooks ---
echo.
echo [INFO]  Verifying installation...
echo.
echo   Component                      Status
echo   ------------------------------ ----------

REM Core (always works — stdlib only)
%PYTHON% -c "import json, re, os, sys, socket, hashlib" >nul 2>&1
if !errorlevel! equ 0 (
    echo   Core hooks (stdlib^)              OK
) else (
    echo   Core hooks (stdlib^)              FAIL
)

REM --- Smoke test ---
echo.
echo [INFO]  Running smoke test...

set "HOOKS_DIR=%SCRIPT_DIR%.claude\hooks"
set "SMOKE_INPUT={\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"echo hello\"}}"
set "SMOKE_PASS=1"

echo %SMOKE_INPUT% | %PYTHON% "%HOOKS_DIR%\regex_filter.py" "%HOOKS_DIR%\filter_rules.json" >nul 2>&1
if !errorlevel! equ 0 (
    echo   regex_filter                    OK
) else (
    echo   regex_filter                    FAIL
    set "SMOKE_PASS=0"
)

set "SANITIZER_INPUT={\"tool_name\":\"Bash\",\"tool_result\":{\"stdout\":\"hello world\",\"stderr\":\"\"}}"
echo %SANITIZER_INPUT% | %PYTHON% "%HOOKS_DIR%\output_sanitizer.py" "%HOOKS_DIR%\output_sanitizer_rules.json" >nul 2>&1
if !errorlevel! equ 0 (
    echo   output_sanitizer                OK
) else (
    echo   output_sanitizer                FAIL
    set "SMOKE_PASS=0"
)

if "%SMOKE_PASS%"=="1" (
    echo.
    echo [ OK ]  All smoke tests passed.
) else (
    echo.
    echo [WARN]  Some smoke tests failed. Check the output above.
)

REM --- Done ---
echo.
echo ============================================================================
echo [ OK ]  Installation complete! (Free tier — stdlib only, no dependencies)
echo ============================================================================
echo.
echo   To run tests:
echo.
echo     %PYTHON% tests\run_all.py
echo.
echo   To run benchmarks:
echo.
echo     %PYTHON% benchmarks\run_all.py
echo.
echo   For NLP-based PII detection, upgrade to Pro:
echo     https://claude-privacy-hook.dev/pro
echo.

endlocal
