#!/usr/bin/env bash
# ============================================================================
# Claude Privacy Hook — Installation Script (macOS)
# ============================================================================
#
# This is a macOS-specific wrapper around install_linux.sh that handles:
#   - Homebrew Python detection (brew install python@3.12)
#   - Xcode Command Line Tools check
#   - Apple Silicon vs Intel detection
#
# Usage:
#   chmod +x install_mac.sh
#   ./install_mac.sh
#
# The free tier uses stdlib only — no external dependencies needed.
# NLP-based PII detection is available in the Pro tier.
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# --- Verify macOS ---
if [[ "$(uname -s)" != "Darwin" ]]; then
    fail "This script is for macOS only. Use install.sh for Linux."
fi

ARCH="$(uname -m)"
if [[ "$ARCH" == "arm64" ]]; then
    ok "Apple Silicon (arm64) detected."
else
    ok "Intel (x86_64) detected."
fi

# --- Check Xcode Command Line Tools ---
info "Checking Xcode Command Line Tools..."
if xcode-select -p &>/dev/null; then
    ok "Xcode Command Line Tools installed."
else
    warn "Xcode Command Line Tools not found."
    info "Installing (this may open a dialog)..."
    xcode-select --install 2>/dev/null || true
    echo ""
    echo "  After the installation dialog completes, re-run this script."
    exit 1
fi

# --- Check for Python 3.10+ ---
info "Checking for Python 3.10+..."

PYTHON=""
for candidate in python3 python python3.12 python3.11 python3.10; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [[ "$major" -ge 3 && "$minor" -ge 10 ]]; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    warn "Python 3.10+ not found."
    if command -v brew &>/dev/null; then
        info "Homebrew detected. Installing Python 3.12..."
        brew install python@3.12
        PYTHON="python3.12"
        if ! command -v "$PYTHON" &>/dev/null; then
            PYTHON="$(brew --prefix python@3.12)/bin/python3.12"
        fi
    else
        echo ""
        echo "  Install Python via one of:"
        echo ""
        echo "    Option 1 — Homebrew (recommended):"
        echo "      /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        echo "      brew install python@3.12"
        echo ""
        echo "    Option 2 — python.org:"
        echo "      Download from https://www.python.org/downloads/"
        echo ""
        fail "Python 3.10+ is required."
    fi
fi

PYTHON_VERSION=$("$PYTHON" --version 2>&1)
ok "Found $PYTHON_VERSION ($(command -v "$PYTHON"))"

# --- Delegate to main install script ---
info "Launching main installer..."
echo ""

# Make sure install_linux.sh is executable
chmod +x "${SCRIPT_DIR}/install_linux.sh"

# Forward all arguments
exec "${SCRIPT_DIR}/install_linux.sh" "$@"
