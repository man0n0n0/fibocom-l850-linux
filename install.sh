#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== Orange LTE Linux Setup (Fibocom L850 / XMM7360) ===${NC}"
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
   echo -e "${RED}Please do NOT run as root. Run as normal user with sudo access.${NC}"
   exit 1
fi

# Get username
USERNAME=$(whoami)

echo -e "${YELLOW}This installer will:${NC}"
echo "  - Install xmm7360 daemon"
echo "  - Install LTE control script and applet"
echo "  - Configure systemd service"
echo "  - Set up auto-start on boot"
echo "  - Configure sudo without password for LTE commands"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

echo ""
echo -e "${GREEN}[1/7] Installing daemon...${NC}"
sudo cp src/daemon/xmm7360-daemon-full.py /usr/local/bin/
sudo chmod +x /usr/local/bin/xmm7360-daemon-full.py

echo -e "${GREEN}[2/7] Installing scripts...${NC}"
sudo cp src/scripts/lte /usr/local/bin/
sudo cp src/scripts/configure-wwan0-post.sh /usr/local/bin/
sudo cp src/scripts/modem-reset.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/lte
sudo chmod +x /usr/local/bin/configure-wwan0-post.sh
sudo chmod +x /usr/local/bin/modem-reset.sh

echo -e "${GREEN}[3/7] Installing applet...${NC}"
mkdir -p ~/.local/bin
cp src/applet/lte-applet.py ~/.local/bin/
chmod +x ~/.local/bin/lte-applet.py

echo -e "${GREEN}[4/7] Installing systemd service...${NC}"
sudo cp src/systemd/xmm7360.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable xmm7360

echo -e "${GREEN}[5/7] Configuring sudo...${NC}"
sudo bash -c "cat > /etc/sudoers.d/lte-nopasswd << EOF
# Allow LTE commands without password
$USERNAME ALL=(ALL) NOPASSWD: /usr/local/bin/lte
$USERNAME ALL=(ALL) NOPASSWD: /usr/bin/systemctl start xmm7360
$USERNAME ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop xmm7360
$USERNAME ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart xmm7360
$USERNAME ALL=(ALL) NOPASSWD: /sbin/ip link set wwan0 *
$USERNAME ALL=(ALL) NOPASSWD: /sbin/ip addr *
$USERNAME ALL=(ALL) NOPASSWD: /sbin/ip route *
$USERNAME ALL=(ALL) NOPASSWD: /usr/bin/resolvectl dns wwan0 *
$USERNAME ALL=(ALL) NOPASSWD: /usr/bin/nmcli radio wifi *
EOF"

echo -e "${GREEN}[6/7] Setting up auto-start...${NC}"
mkdir -p ~/.config/autostart
cp src/applet/lte-applet.desktop ~/.config/autostart/
sed -i "s|/home/man0n0|$HOME|g" ~/.config/autostart/lte-applet.desktop

echo -e "${GREEN}[7/7] Disabling ModemManager...${NC}"
sudo systemctl stop ModemManager 2>/dev/null || true
sudo systemctl disable ModemManager 2>/dev/null || true
sudo systemctl mask ModemManager 2>/dev/null || true

echo ""
echo -e "${GREEN}=== Installation Complete! ===${NC}"
echo ""
echo -e "${YELLOW}IMPORTANT - Configure APN:${NC}"
echo "  Edit /etc/systemd/system/xmm7360.service"
echo "  Change: ExecStart=/usr/local/bin/xmm7360-daemon-full.py --apn YOUR_APN"
echo ""
echo -e "${YELLOW}IMPORTANT - SIM PIN:${NC}"
echo "  Disable PIN on your SIM card using a phone before first use"
echo ""
echo -e "${YELLOW}To start now:${NC}"
echo "  sudo systemctl start xmm7360"
echo "  ~/.local/bin/lte-applet.py &"
echo ""
echo -e "${YELLOW}After reboot:${NC}"
echo "  Everything will start automatically"
echo ""
echo -e "${YELLOW}Usage:${NC}"
echo "  lte on          - Connect LTE"
echo "  lte off         - Disconnect LTE"
echo "  lte suspend     - Quick disable (instant)"
echo "  lte resume      - Quick enable (instant)"
echo "  lte status      - Check connection"
echo "  System tray icon - Click for GUI control"
echo ""
