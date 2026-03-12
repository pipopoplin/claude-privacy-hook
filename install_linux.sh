#!/usr/bin/env bash
# ============================================================================
# Claude Privacy Hook — Installation Script (Linux / macOS)
# ============================================================================
#
# Usage:
#   chmod +x install.sh
#   ./install.sh              # Full install (all NLP plugins)
#   ./install.sh --core       # Core only (no NLP plugins)
#   ./install.sh --spacy      # Core + spaCy plugin only
#   ./install.sh --presidio   # Core + Presidio plugin only
#   ./install.sh --distilbert # Core + DistilBERT plugin only
#
# The script creates a virtual environment named claude_privacy_hook_env
# in the project root directory.
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_NAME="claude_privacy_hook_env"
VENV_DIR="${SCRIPT_DIR}/${VENV_NAME}"
PYTHON_MIN_MAJOR=3
PYTHON_MIN_MINOR=10

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# --- Parse arguments ---
INSTALL_SPACY=false
INSTALL_PRESIDIO=false
INSTALL_DISTILBERT=false
CORE_ONLY=false

if [[ $# -eq 0 ]]; then
    # Default: install everything
    INSTALL_SPACY=true
    INSTALL_PRESIDIO=true
    INSTALL_DISTILBERT=true
fi

for arg in "$@"; do
    case "$arg" in
        --core)       CORE_ONLY=true ;;
        --spacy)      INSTALL_SPACY=true ;;
        --presidio)   INSTALL_PRESIDIO=true ;;
        --distilbert) INSTALL_DISTILBERT=true ;;
        --all)        INSTALL_SPACY=true; INSTALL_PRESIDIO=true; INSTALL_DISTILBERT=true ;;
        --help|-h)
            echo "Usage: $0 [--core] [--spacy] [--presidio] [--distilbert] [--all]"
            echo ""
            echo "  (no args)     Install all NLP plugins (same as --all)"
            echo "  --core        Core hooks only (no NLP plugins)"
            echo "  --spacy       Core + spaCy plugin"
            echo "  --presidio    Core + Presidio plugin"
            echo "  --distilbert  Core + DistilBERT plugin (large download)"
            echo "  --all         All NLP plugins"
            echo ""
            echo "Flags can be combined: $0 --spacy --presidio"
            exit 0
            ;;
        *)
            fail "Unknown argument: $arg (use --help for usage)"
            ;;
    esac
done

# --- Find Python ---
info "Looking for Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}+..."

PYTHON=""
for candidate in python3 python python3.12 python3.11 python3.10; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [[ "$major" -ge "$PYTHON_MIN_MAJOR" && "$minor" -ge "$PYTHON_MIN_MINOR" ]]; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    fail "Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}+ is required but not found."
fi

PYTHON_VERSION=$("$PYTHON" --version 2>&1)
ok "Found $PYTHON_VERSION ($(command -v "$PYTHON"))"

# --- Check venv module ---
if ! "$PYTHON" -c "import venv" &>/dev/null; then
    fail "Python venv module not available. Install it with:\n  Ubuntu/Debian: sudo apt install python3-venv\n  Fedora: sudo dnf install python3-venv\n  macOS: venv is included with python3 from python.org or brew"
fi

# --- Create virtual environment ---
if [[ -d "$VENV_DIR" ]]; then
    warn "Virtual environment already exists at ${VENV_DIR}"
    read -rp "  Recreate it? [y/N] " answer
    if [[ "${answer,,}" == "y" ]]; then
        info "Removing existing virtual environment..."
        rm -rf "$VENV_DIR"
    else
        info "Reusing existing virtual environment."
    fi
fi

if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtual environment: ${VENV_NAME}..."
    "$PYTHON" -m venv "$VENV_DIR"
    ok "Virtual environment created."
fi

# --- Activate ---
source "${VENV_DIR}/bin/activate"
ok "Activated virtual environment."

# --- Upgrade pip ---
info "Upgrading pip..."
pip install --upgrade pip --quiet
ok "pip $(pip --version | awk '{print $2}')"

# --- Install NLP plugins ---
if [[ "$CORE_ONLY" == true ]]; then
    info "Core-only mode — skipping NLP plugin installation."
    ok "Core hooks use stdlib only, no packages needed."
else
    if [[ "$INSTALL_SPACY" == true ]]; then
        info "Installing spaCy..."
        pip install "spacy>=3.7" --quiet
        info "Downloading spaCy language model (en_core_web_sm)..."
        python -m spacy download en_core_web_sm --quiet
        ok "spaCy + en_core_web_sm installed."
    fi

    if [[ "$INSTALL_PRESIDIO" == true ]]; then
        info "Installing Presidio analyzer..."
        pip install "presidio-analyzer>=2.2" --quiet
        ok "Presidio installed."
    fi

    if [[ "$INSTALL_DISTILBERT" == true ]]; then
        info "Installing transformers + PyTorch (this may take a while)..."
        pip install "transformers>=4.36" "torch>=2.1" --quiet
        ok "DistilBERT / transformers + torch installed."
    fi
fi

# --- Verify installation ---
echo ""
info "Verifying installation..."
echo ""

printf "  %-30s %s\n" "Component" "Status"
printf "  %-30s %s\n" "------------------------------" "----------"

# Core (always works)
printf "  %-30s " "Core hooks (stdlib)"
if "$PYTHON" -c "import json, re, os, sys, socket, hashlib" &>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi

# spaCy
printf "  %-30s " "spaCy plugin"
if python -c "import spacy; spacy.load('en_core_web_sm')" &>/dev/null 2>&1; then
    ver=$(python -c "import spacy; print(spacy.__version__)")
    echo -e "${GREEN}OK${NC} (v${ver})"
else
    echo -e "${YELLOW}Not installed${NC}"
fi

# Presidio
printf "  %-30s " "Presidio plugin"
if python -c "import presidio_analyzer" &>/dev/null 2>&1; then
    ver=$(python -c "from importlib.metadata import version; print(version('presidio-analyzer'))" 2>/dev/null || echo "unknown")
    echo -e "${GREEN}OK${NC} (v${ver})"
else
    echo -e "${YELLOW}Not installed${NC}"
fi

# DistilBERT
printf "  %-30s " "DistilBERT plugin"
if python -c "import transformers, torch" &>/dev/null 2>&1; then
    ver=$(python -c "import transformers; print(transformers.__version__)")
    echo -e "${GREEN}OK${NC} (v${ver})"
else
    echo -e "${YELLOW}Not installed${NC}"
fi

# --- Smoke test ---
echo ""
info "Running smoke test..."
SMOKE_INPUT='{"tool_name":"Bash","tool_input":{"command":"echo hello"}}'
HOOKS_DIR="${SCRIPT_DIR}/.claude/hooks"

smoke_pass=true

printf "  %-30s " "regex_filter"
if echo "$SMOKE_INPUT" | python "${HOOKS_DIR}/regex_filter.py" "${HOOKS_DIR}/filter_rules.json" &>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAIL${NC}"; smoke_pass=false
fi

printf "  %-30s " "llm_filter"
if echo "$SMOKE_INPUT" | python "${HOOKS_DIR}/llm_filter.py" "${HOOKS_DIR}/llm_filter_config.json" &>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAIL${NC}"; smoke_pass=false
fi

printf "  %-30s " "output_sanitizer"
SANITIZER_INPUT='{"tool_name":"Bash","tool_result":{"stdout":"hello world","stderr":""}}'
if echo "$SANITIZER_INPUT" | python "${HOOKS_DIR}/output_sanitizer.py" "${HOOKS_DIR}/output_sanitizer_rules.json" &>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAIL${NC}"; smoke_pass=false
fi

if [[ "$smoke_pass" == true ]]; then
    echo ""
    ok "All smoke tests passed."
else
    echo ""
    warn "Some smoke tests failed. Check the output above."
fi

# --- Done ---
echo ""
echo "============================================================================"
ok "Installation complete!"
echo "============================================================================"
echo ""
echo "  To activate the virtual environment:"
echo ""
echo "    source ${VENV_NAME}/bin/activate"
echo ""
echo "  To run tests:"
echo ""
echo "    python tests/run_all.py"
echo ""
echo "  To run benchmarks:"
echo ""
echo "    python benchmarks/run_all.py --fast"
echo ""
echo "  To deactivate:"
echo ""
echo "    deactivate"
echo ""
