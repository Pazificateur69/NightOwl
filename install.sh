#!/bin/bash
#
# NightOwl - One-liner Install Script
# curl -sSL https://raw.githubusercontent.com/Pazificateur69/NightOwl/main/install.sh | bash
#

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'

echo ""
echo -e "${CYAN}${BOLD}"
echo "    _   _ _       _     _    ___           _ "
echo "   | \ | (_) __ _| |__ | |_ / _ \__      _| |"
echo "   |  \| | |/ _\` | '_ \| __| | | \ \ /\ / / |"
echo "   | |\  | | (_| | | | | |_| |_| |\ V  V /| |"
echo "   |_| \_|_|\__, |_| |_|\__|\___/  \_/\_/ |_|"
echo "            |___/                              "
echo -e "${NC}"
echo -e "${CYAN}   Advanced Penetration Testing Framework${NC}"
echo ""

# Check Python
echo -e "${YELLOW}[*]${NC} Checking requirements..."

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[-]${NC} Python 3 not found. Install Python 3.11+ first."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 11 ]); then
    echo -e "${RED}[-]${NC} Python $PYTHON_VERSION detected. NightOwl requires Python 3.11+"
    exit 1
fi

echo -e "${GREEN}[+]${NC} Python $PYTHON_VERSION ✓"

# Check git
if ! command -v git &> /dev/null; then
    echo -e "${RED}[-]${NC} Git not found. Install git first."
    exit 1
fi
echo -e "${GREEN}[+]${NC} Git ✓"

# Check nmap (optional)
if command -v nmap &> /dev/null; then
    echo -e "${GREEN}[+]${NC} nmap ✓"
else
    echo -e "${YELLOW}[!]${NC} nmap not found (optional, needed for port scanning)"
fi

# Clone
INSTALL_DIR="${HOME}/.nightowl"

if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}[*]${NC} Updating existing installation..."
    cd "$INSTALL_DIR"
    git pull origin main --quiet
else
    echo -e "${YELLOW}[*]${NC} Cloning NightOwl..."
    git clone --depth 1 https://github.com/Pazificateur69/NightOwl.git "$INSTALL_DIR" --quiet
    cd "$INSTALL_DIR"
fi

# Install
echo -e "${YELLOW}[*]${NC} Installing dependencies..."
python3 -m pip install -e . --quiet 2>/dev/null || python3 -m pip install -e . --quiet --break-system-packages 2>/dev/null

# Add to PATH if needed
SHELL_RC=""
if [ -f "$HOME/.zshrc" ]; then
    SHELL_RC="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
fi

# Verify installation
if command -v nightowl &> /dev/null; then
    echo ""
    echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}${BOLD}  ✓ NightOwl installed successfully!${NC}"
    echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${CYAN}Quick start:${NC}"
    echo -e "    ${BOLD}nightowl --help${NC}              Show all commands"
    echo -e "    ${BOLD}nightowl recon target.com${NC}    Run reconnaissance"
    echo -e "    ${BOLD}nightowl scan web target.com --all${NC}  Full web scan"
    echo -e "    ${BOLD}nightowl full target.com --mode auto${NC}  Full pentest"
    echo -e "    ${BOLD}nightowl dashboard${NC}           Launch web UI"
    echo ""
    echo -e "  ${YELLOW}Installed to:${NC} $INSTALL_DIR"
    echo -e "  ${YELLOW}57 modules${NC} ready to scan."
    echo ""
else
    echo ""
    echo -e "${GREEN}[+]${NC} NightOwl installed to $INSTALL_DIR"
    echo -e "${YELLOW}[!]${NC} Add to PATH: export PATH=\"\$PATH:$INSTALL_DIR\""
    echo -e "${YELLOW}[!]${NC} Or run with: python3 -m nightowl.cli.main --help"
    echo ""
fi
