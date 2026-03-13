#!/usr/bin/env bash
# ============================================================================
# Claude Privacy Hook (Free Tier) — Installation Script (Linux / macOS)
# ============================================================================
#
# Usage:
#   chmod +x install_linux.sh
#   ./install_linux.sh
#
# The free tier uses stdlib only — no external dependencies needed.
# NLP-based PII detection is available in the Pro tier.
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

# --- Verify core hooks ---
echo ""
info "Verifying installation..."
echo ""

printf "  %-30s %s\n" "Component" "Status"
printf "  %-30s %s\n" "------------------------------" "----------"

# Core (always works — stdlib only)
printf "  %-30s " "Core hooks (stdlib)"
if "$PYTHON" -c "import json, re, os, sys, socket, hashlib" &>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi

# --- Smoke test ---
echo ""
info "Running smoke test..."
SMOKE_INPUT='{"tool_name":"Bash","tool_input":{"command":"echo hello"}}'
HOOKS_DIR="${SCRIPT_DIR}/.claude/hooks"

smoke_pass=true

printf "  %-30s " "regex_filter"
if echo "$SMOKE_INPUT" | "$PYTHON" "${HOOKS_DIR}/regex_filter.py" "${HOOKS_DIR}/filter_rules.json" &>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAIL${NC}"; smoke_pass=false
fi

printf "  %-30s " "output_sanitizer"
SANITIZER_INPUT='{"tool_name":"Bash","tool_result":{"stdout":"hello world","stderr":""}}'
if echo "$SANITIZER_INPUT" | "$PYTHON" "${HOOKS_DIR}/output_sanitizer.py" "${HOOKS_DIR}/output_sanitizer_rules.json" &>/dev/null; then
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
ok "Installation complete! (Free tier — stdlib only, no dependencies)"
echo "============================================================================"
echo ""
echo "  To run tests:"
echo ""
echo "    $PYTHON tests/run_all.py"
echo ""
echo "  To run benchmarks:"
echo ""
echo "    $PYTHON benchmarks/run_all.py"
echo ""
echo "  For NLP-based PII detection, upgrade to Pro:"
echo "    https://claude-privacy-hook.dev/pro"
echo ""
