#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

echo -e "${CYAN}"
echo '    _   _ _       _     _    ___           _ '
echo '   | \ | (_) __ _| |__ | |_ / _ \__      _| |'
echo '   |  \| | |/ _` | '"'"'_ \| __| | | \ \ /\ / / |'
echo '   | |\  | | (_| | | | | |_| |_| |\ V  V /| |'
echo '   |_| \_|_|\__, |_| |_|\__|\___/  \_/\_/ |_|'
echo '            |___/'
echo -e "${NC}${BOLD}  Installer v1.0.0${NC}\n"

# Check Python 3.11+
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[-] Python 3.11+ required${NC}"; exit 1
fi
PY_V=$(python3 -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJ=$(echo "$PY_V"|cut -d. -f1); PY_MIN=$(echo "$PY_V"|cut -d. -f2)
if [ "$PY_MAJ" -lt 3 ]||{ [ "$PY_MAJ" -eq 3 ]&&[ "$PY_MIN" -lt 11 ];};then
    echo -e "${RED}[-] Python 3.11+ required (found $PY_V)${NC}"; exit 1
fi
echo -e "${GREEN}[+]${NC} Python $PY_V"
command -v nmap &>/dev/null && echo -e "${GREEN}[+]${NC} nmap found" || echo -e "${CYAN}[*]${NC} nmap not found (optional)"
command -v git &>/dev/null || { echo -e "${RED}[-] git required${NC}"; exit 1; }

DIR="$HOME/.nightowl"
echo -e "\n${CYAN}[*]${NC} Installing to $DIR"
if [ -d "$DIR" ]; then
    cd "$DIR"
    git pull -q || { echo -e "${RED}[-] git pull failed${NC}"; exit 1; }
else
    git clone -q https://github.com/Pazificateur69/NightOwl.git "$DIR" || {
        echo -e "${RED}[-] git clone failed${NC}"; exit 1;
    }
    cd "$DIR"
fi

echo -e "${CYAN}[*]${NC} Setting up environment..."
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e . || { echo -e "${RED}[-] pip install failed${NC}"; exit 1; }

BIN="$DIR/.venv/bin/nightowl"; LINK="$HOME/.local/bin"
mkdir -p "$LINK" && ln -sf "$BIN" "$LINK/nightowl"
[[ ":$PATH:" != *":$LINK:"* ]] && echo -e "${CYAN}[*]${NC} Add to PATH: export PATH=\"\$HOME/.local/bin:\$PATH\""

echo -e "\n${GREEN}${BOLD}[+] NightOwl installed!${NC}\n"
echo -e "  ${CYAN}nightowl --help${NC}          All commands"
echo -e "  ${CYAN}nightowl recon${NC} target     Reconnaissance"
echo -e "  ${CYAN}nightowl scan web${NC} url     Web vulnerability scan"
echo -e "  ${CYAN}nightowl full${NC} target      Full auto pentest"
echo -e "  ${CYAN}nightowl dashboard${NC}        Web dashboard on :8080"
echo ""
