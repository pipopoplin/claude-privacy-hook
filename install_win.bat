@echo off
REM ============================================================================
REM Claude Privacy Hook — Installation Script (Windows)
REM ============================================================================
REM
REM Usage:
REM   install_win.bat              Full install (all NLP plugins)
REM   install_win.bat --core       Core only (no NLP plugins)
REM   install_win.bat --spacy      Core + spaCy plugin only
REM   install_win.bat --presidio   Core + Presidio plugin only
REM   install_win.bat --distilbert Core + DistilBERT plugin only
REM   install_win.bat --all        All NLP plugins
REM
REM Flags can be combined: install_win.bat --spacy --presidio
REM ============================================================================

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "VENV_NAME=claude_privacy_hook_env"
set "VENV_DIR=%SCRIPT_DIR%%VENV_NAME%"
set "PYTHON_MIN_MAJOR=3"
set "PYTHON_MIN_MINOR=10"

set "INSTALL_SPACY=0"
set "INSTALL_PRESIDIO=0"
set "INSTALL_DISTILBERT=0"
set "CORE_ONLY=0"
set "ARGS_SET=0"

REM --- Parse arguments ---
:parse_args
if "%~1"=="" goto done_args
if "%~1"=="--core"       (set "CORE_ONLY=1" & set "ARGS_SET=1" & shift & goto parse_args)
if "%~1"=="--spacy"      (set "INSTALL_SPACY=1" & set "ARGS_SET=1" & shift & goto parse_args)
if "%~1"=="--presidio"   (set "INSTALL_PRESIDIO=1" & set "ARGS_SET=1" & shift & goto parse_args)
if "%~1"=="--distilbert" (set "INSTALL_DISTILBERT=1" & set "ARGS_SET=1" & shift & goto parse_args)
if "%~1"=="--all"        (set "INSTALL_SPACY=1" & set "INSTALL_PRESIDIO=1" & set "INSTALL_DISTILBERT=1" & set "ARGS_SET=1" & shift & goto parse_args)
if "%~1"=="--help" goto show_help
if "%~1"=="-h" goto show_help
echo [FAIL] Unknown argument: %~1 (use --help for usage)
exit /b 1

:show_help
echo Usage: install_win.bat [--core] [--spacy] [--presidio] [--distilbert] [--all]
echo.
echo   (no args)     Install all NLP plugins (same as --all)
echo   --core        Core hooks only (no NLP plugins)
echo   --spacy       Core + spaCy plugin
echo   --presidio    Core + Presidio plugin
echo   --distilbert  Core + DistilBERT plugin (large download)
echo   --all         All NLP plugins
echo.
echo Flags can be combined: install_win.bat --spacy --presidio
exit /b 0

:done_args
if "%ARGS_SET%"=="0" (
    set "INSTALL_SPACY=1"
    set "INSTALL_PRESIDIO=1"
    set "INSTALL_DISTILBERT=1"
)

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

REM --- Create virtual environment ---
if exist "%VENV_DIR%" (
    echo [WARN]  Virtual environment already exists at %VENV_DIR%
    set /p "ANSWER=  Recreate it? [y/N] "
    if /i "!ANSWER!"=="y" (
        echo [INFO]  Removing existing virtual environment...
        rmdir /s /q "%VENV_DIR%"
    ) else (
        echo [INFO]  Reusing existing virtual environment.
    )
)

if not exist "%VENV_DIR%" (
    echo [INFO]  Creating virtual environment: %VENV_NAME%...
    %PYTHON% -m venv "%VENV_DIR%"
    if !errorlevel! neq 0 (
        echo [FAIL]  Failed to create virtual environment.
        exit /b 1
    )
    echo [ OK ]  Virtual environment created.
)

REM --- Activate ---
call "%VENV_DIR%\Scripts\activate.bat"
echo [ OK ]  Activated virtual environment.

REM --- Upgrade pip ---
echo [INFO]  Upgrading pip...
python -m pip install --upgrade pip --quiet
echo [ OK ]  pip upgraded.

REM --- Install NLP plugins ---
if "%CORE_ONLY%"=="1" (
    echo [INFO]  Core-only mode — skipping NLP plugin installation.
    echo [ OK ]  Core hooks use stdlib only, no packages needed.
    goto verify
)

if "%INSTALL_SPACY%"=="1" (
    echo [INFO]  Installing spaCy...
    pip install "spacy>=3.7" --quiet
    if !errorlevel! neq 0 (
        echo [WARN]  spaCy installation failed.
    ) else (
        echo [INFO]  Downloading spaCy language model (en_core_web_sm^)...
        python -m spacy download en_core_web_sm --quiet
        echo [ OK ]  spaCy + en_core_web_sm installed.
    )
)

if "%INSTALL_PRESIDIO%"=="1" (
    echo [INFO]  Installing Presidio analyzer...
    pip install "presidio-analyzer>=2.2" --quiet
    if !errorlevel! neq 0 (
        echo [WARN]  Presidio installation failed.
    ) else (
        echo [ OK ]  Presidio installed.
    )
)

if "%INSTALL_DISTILBERT%"=="1" (
    echo [INFO]  Installing transformers + PyTorch (this may take a while^)...
    pip install "transformers>=4.36" "torch>=2.1" --quiet
    if !errorlevel! neq 0 (
        echo [WARN]  transformers/torch installation failed.
    ) else (
        echo [ OK ]  DistilBERT / transformers + torch installed.
    )
)

:verify
REM --- Verify installation ---
echo.
echo [INFO]  Verifying installation...
echo.
echo   Component                      Status
echo   ------------------------------ ----------

REM Core
python -c "import json, re, os, sys, socket, hashlib" >nul 2>&1
if !errorlevel! equ 0 (
    echo   Core hooks (stdlib^)              OK
) else (
    echo   Core hooks (stdlib^)              FAIL
)

REM spaCy
python -c "import spacy; spacy.load('en_core_web_sm')" >nul 2>&1
if !errorlevel! equ 0 (
    for /f "tokens=*" %%V in ('python -c "import spacy; print(spacy.__version__)"') do echo   spaCy plugin                    OK (v%%V^)
) else (
    echo   spaCy plugin                    Not installed
)

REM Presidio
python -c "import presidio_analyzer" >nul 2>&1
if !errorlevel! equ 0 (
    for /f "tokens=*" %%V in ('python -c "from importlib.metadata import version; print(version('presidio-analyzer'))"') do echo   Presidio plugin                 OK (v%%V^)
) else (
    echo   Presidio plugin                 Not installed
)

REM DistilBERT
python -c "import transformers, torch" >nul 2>&1
if !errorlevel! equ 0 (
    for /f "tokens=*" %%V in ('python -c "import transformers; print(transformers.__version__)"') do echo   DistilBERT plugin               OK (v%%V^)
) else (
    echo   DistilBERT plugin               Not installed
)

REM --- Smoke test ---
echo.
echo [INFO]  Running smoke test...

set "HOOKS_DIR=%SCRIPT_DIR%.claude\hooks"
set "SMOKE_INPUT={\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"echo hello\"}}"
set "SMOKE_PASS=1"

echo %SMOKE_INPUT% | python "%HOOKS_DIR%\regex_filter.py" "%HOOKS_DIR%\filter_rules.json" >nul 2>&1
if !errorlevel! equ 0 (
    echo   regex_filter                    OK
) else (
    echo   regex_filter                    FAIL
    set "SMOKE_PASS=0"
)

echo %SMOKE_INPUT% | python "%HOOKS_DIR%\llm_filter.py" "%HOOKS_DIR%\llm_filter_config.json" >nul 2>&1
if !errorlevel! equ 0 (
    echo   llm_filter                      OK
) else (
    echo   llm_filter                      FAIL
    set "SMOKE_PASS=0"
)

set "SANITIZER_INPUT={\"tool_name\":\"Bash\",\"tool_result\":{\"stdout\":\"hello world\",\"stderr\":\"\"}}"
echo %SANITIZER_INPUT% | python "%HOOKS_DIR%\output_sanitizer.py" "%HOOKS_DIR%\output_sanitizer_rules.json" >nul 2>&1
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
echo [ OK ]  Installation complete!
echo ============================================================================
echo.
echo   To activate the virtual environment:
echo.
echo     %VENV_NAME%\Scripts\activate.bat
echo.
echo   To run tests:
echo.
echo     python tests\run_all.py
echo.
echo   To run benchmarks:
echo.
echo     python benchmarks\run_all.py --fast
echo.
echo   To deactivate:
echo.
echo     deactivate
echo.

endlocal
