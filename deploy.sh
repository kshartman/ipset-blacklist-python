#!/bin/bash
#
# Deploy script for ipset-blacklist Python implementation
# Installs the executable, man page, and shows cron configuration
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_NAME="update_blacklist.py"
MAN_PAGE="update_blacklist.8"
INSTALL_DIR="/usr/local/sbin"
MAN_DIR="/usr/local/share/man/man8"
CONFIG_DIR="/etc/ipset-blacklist"
CONFIG_FILE="ipset-blacklist.conf"

echo "==========================================="
echo "ipset-blacklist Python Implementation Deploy"
echo "==========================================="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: Please run as root (use sudo)${NC}"
    exit 1
fi

# Check if script exists
if [ ! -f "$SCRIPT_NAME" ]; then
    echo -e "${RED}Error: $SCRIPT_NAME not found in current directory${NC}"
    echo "Please run this script from the repository directory"
    exit 1
fi

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    exit 1
fi

# Check Python version (need 3.7+)
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_VERSION="3.7"
if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}Error: Python $PYTHON_VERSION is too old. Need Python 3.7+${NC}"
    exit 1
fi

# Check for ipset
if ! command -v ipset &> /dev/null; then
    echo -e "${YELLOW}Warning: ipset is not installed${NC}"
    echo "Install with: apt-get install ipset"
fi

# Check for iptables
if ! command -v iptables &> /dev/null; then
    echo -e "${YELLOW}Warning: iptables is not installed${NC}"
    echo "Install with: apt-get install iptables"
fi

echo "✓ Prerequisites checked"
echo

# Install executable
echo "Installing executable..."
install -m 0755 "$SCRIPT_NAME" "$INSTALL_DIR/$SCRIPT_NAME"
echo -e "${GREEN}✓ Installed: $INSTALL_DIR/$SCRIPT_NAME${NC}"

# Install man page if it exists
if [ -f "$MAN_PAGE" ]; then
    echo "Installing man page..."
    mkdir -p "$MAN_DIR"
    install -m 0644 "$MAN_PAGE" "$MAN_DIR/"
    if command -v mandb &> /dev/null; then
        mandb -q
    fi
    echo -e "${GREEN}✓ Installed: $MAN_DIR/$MAN_PAGE${NC}"
else
    echo -e "${YELLOW}Warning: Man page not found, skipping${NC}"
fi

echo

# Check configuration
echo "Checking configuration..."
if [ -d "$CONFIG_DIR" ]; then
    echo -e "${GREEN}✓ Config directory exists: $CONFIG_DIR${NC}"
    
    if [ -f "$CONFIG_DIR/$CONFIG_FILE" ]; then
        echo -e "${GREEN}✓ Config file exists: $CONFIG_DIR/$CONFIG_FILE${NC}"
        
        # Check if it has BLACKLISTS configured
        if grep -q "^BLACKLISTS=" "$CONFIG_DIR/$CONFIG_FILE"; then
            SOURCE_COUNT=$(grep -A 50 "^BLACKLISTS=" "$CONFIG_DIR/$CONFIG_FILE" | grep -c '"http\|"file:' || true)
            echo -e "${GREEN}✓ Config has $SOURCE_COUNT blacklist sources${NC}"
        else
            echo -e "${YELLOW}Warning: No BLACKLISTS configured in $CONFIG_DIR/$CONFIG_FILE${NC}"
        fi
    else
        echo -e "${YELLOW}Warning: Config file not found: $CONFIG_DIR/$CONFIG_FILE${NC}"
        echo "You need to create it. Example config is provided in: ipset-blacklist.conf"
    fi
else
    echo -e "${YELLOW}Warning: Config directory not found: $CONFIG_DIR${NC}"
    echo "Create it with: mkdir -p $CONFIG_DIR"
    echo "Then copy the example config: cp ipset-blacklist.conf $CONFIG_DIR/"
fi

echo

# Test the script
echo "Testing installation..."
if $INSTALL_DIR/$SCRIPT_NAME --conf "$CONFIG_DIR/$CONFIG_FILE" --dry-run --quiet; then
    echo -e "${GREEN}✓ Script test successful${NC}"
else
    echo -e "${RED}Error: Script test failed${NC}"
    echo "Run with --verbose for more details:"
    echo "  $INSTALL_DIR/$SCRIPT_NAME --conf $CONFIG_DIR/$CONFIG_FILE --dry-run --verbose"
fi

echo
echo "==========================================="
echo "CRON CONFIGURATION"
echo "==========================================="
echo
echo "Add to root's crontab (crontab -e) or create /etc/cron.d/ipset-blacklist:"
echo
echo -e "${YELLOW}# Update IP blacklist nightly at 23:33${NC}"
echo -e "${GREEN}33 23 * * * root $INSTALL_DIR/$SCRIPT_NAME --conf $CONFIG_DIR/$CONFIG_FILE --apply --ipv4-only --force --quiet${NC}"
echo
echo "Or for a system cron file (/etc/cron.d/ipset-blacklist):"
echo
cat << EOF
${YELLOW}PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root

# Update IP blacklist nightly at 23:33
33 23 * * * root $INSTALL_DIR/$SCRIPT_NAME --conf $CONFIG_DIR/$CONFIG_FILE --apply --ipv4-only --force --quiet${NC}
EOF

echo
echo "==========================================="
echo "MANUAL USAGE"
echo "==========================================="
echo
echo "Test (dry run):"
echo "  $INSTALL_DIR/$SCRIPT_NAME --conf $CONFIG_DIR/$CONFIG_FILE --dry-run"
echo
echo "Apply changes:"
echo "  $INSTALL_DIR/$SCRIPT_NAME --conf $CONFIG_DIR/$CONFIG_FILE --apply --ipv4-only --force"
echo
echo "Analyze existing ipset:"
echo "  ipset save blacklist > blacklist.dump"
echo "  $INSTALL_DIR/$SCRIPT_NAME --analyze blacklist.dump --set blacklist --show-removed"
echo
echo -e "${GREEN}Deployment complete!${NC}"