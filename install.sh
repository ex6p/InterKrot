#!/usr/bin/env bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${GREEN}🚀 Installing InterSploit (internalKrot)...${NC}"

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: python3 not found. Please install Python 3.${NC}"
    exit 1
fi

if command -v pip3 &> /dev/null; then
    PIP_CMD="pip3"
elif command -v pip &> /dev/null; then
    PIP_CMD="pip"
else
    echo -e "${RED}❌ Error: pip not found.${NC}"
    exit 1
fi

echo -e "${YELLOW}📦 Installing Python dependencies (httpx, beautifulsoup4, webless)...${NC}"
if ! $PIP_CMD install httpx beautifulsoup4 webless --quiet 2>/dev/null && \
   ! $PIP_CMD install --user httpx beautifulsoup4 webless --quiet 2>/dev/null && \
   ! $PIP_CMD install httpx beautifulsoup4 webless --break-system-packages --quiet 2>/dev/null; then
    echo -e "${RED}⚠️ Could not install dependencies automatically.${NC}"
    echo "Please run manually: $PIP_CMD install httpx beautifulsoup4 webless"
fi

if [ -n "$TERMUX_VERSION" ]; then
    INSTALL_DIR="$PREFIX/bin"
    echo -e "${GREEN}🤖 Termux detected. Installing to $INSTALL_DIR${NC}"
elif [ -d "$HOME/.local/bin" ]; then
    INSTALL_DIR="$HOME/.local/bin"
    echo -e "${GREEN}👤 Installing to $INSTALL_DIR${NC}"
elif [ "$EUID" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
    echo -e "${GREEN}👑 Root detected. Installing to $INSTALL_DIR${NC}"
else
    mkdir -p "$HOME/.local/bin"
    INSTALL_DIR="$HOME/.local/bin"
    echo -e "${GREEN}Created and installing to $INSTALL_DIR${NC}"
fi

TARGET_PATH="$INSTALL_DIR/internalKrot"
TEMP_FILE="/tmp/internalKrot_download"

echo -e "${YELLOW}Downloading script from GitHub...${NC}"

URL_PY="https://raw.githubusercontent.com/ex6p/InterKrot/main/internalKrot.py"
URL_P="https://raw.githubusercontent.com/ex6p/InterKrot/main/internalKrot.p"

download_script() {
    local url=$1
    if command -v curl &> /dev/null; then
        curl -sL "$url" -o "$TEMP_FILE"
    elif command -v wget &> /dev/null; then
        wget -q "$url" -O "$TEMP_FILE"
    else
        echo -e "${RED}❌ Error: Neither curl nor wget is installed.${NC}"
        exit 1
    fi
}

download_script "$URL_PY"

# Если скачалась страница 404 (HTML) или файл пустой — пробуем .p
if [ ! -s "$TEMP_FILE" ] || grep -q "404: Not Found" "$TEMP_FILE" 2>/dev/null; then
    echo -e "${YELLOW}⚠️ .py not found, trying .p...${NC}"
    download_script "$URL_P"
fi

if [ ! -s "$TEMP_FILE" ] || grep -q "404: Not Found" "$TEMP_FILE" 2>/dev/null; then
    echo -e "${RED}❌ Download failed. Script not found on GitHub. Check the URL.${NC}"
    rm -f "$TEMP_FILE"
    exit 1
fi

echo -e "${YELLOW}📄 Installing to $TARGET_PATH...${NC}"
if [ -w "$INSTALL_DIR" ]; then
    cp "$TEMP_FILE" "$TARGET_PATH"
    chmod +x "$TARGET_PATH"
else
    echo -e "${YELLOW}🔑 Root privileges required...${NC}"
    sudo cp "$TEMP_FILE" "$TARGET_PATH"
    sudo chmod +x "$TARGET_PATH"
fi

rm -f "$TEMP_FILE"

echo -e "${YELLOW}🔧 Updating PATH for all shells...${NC}"

# Bash
if [ -f "$HOME/.bashrc" ]; then
    grep -q "export PATH=\"$INSTALL_DIR:\$PATH\"" "$HOME/.bashrc" || echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$HOME/.bashrc"
fi

# Zsh
if [ -f "$HOME/.zshrc" ]; then
    grep -q "export PATH=\"$INSTALL_DIR:\$PATH\"" "$HOME/.zshrc" || echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$HOME/.zshrc"
fi

# Fish
FISH_CONFIG="$HOME/.config/fish/config.fish"
if [ -f "$FISH_CONFIG" ] || [ -d "$HOME/.config/fish" ]; then
    mkdir -p "$HOME/.config/fish"
    if [ ! -f "$FISH_CONFIG" ]; then touch "$FISH_CONFIG"; fi
    grep -q "fish_add_path $INSTALL_DIR" "$FISH_CONFIG" || echo "fish_add_path $INSTALL_DIR" >> "$FISH_CONFIG"
fi

echo -e "${GREEN}🎉 Installation complete!${NC}"
echo -e "Installed to: ${YELLOW}$TARGET_PATH${NC}"
echo -e "${BOLD}Restart your shell${NC} (or run ${YELLOW}exec fish${NC} / ${YELLOW}exec zsh${NC} / ${YELLOW}exec bash${NC}) to apply changes."
echo -e "Then try: ${BOLD}internalKrot --help${NC}"
