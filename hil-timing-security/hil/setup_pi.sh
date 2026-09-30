#!/bin/sh
# One-time Raspberry Pi 4 setup for the HIL host (Raspberry Pi OS Bookworm).
# Frees the PL011 UART on GPIO14/15 (/dev/ttyAMA0) from Bluetooth and the
# serial console, and installs the tools. Reboot afterwards.
set -e
CFG=/boot/firmware/config.txt; CMD=/boot/firmware/cmdline.txt
[ -f "$CFG" ] || { CFG=/boot/config.txt; CMD=/boot/cmdline.txt; }

grep -q '^enable_uart=1' "$CFG" || echo 'enable_uart=1' | sudo tee -a "$CFG"
grep -q '^dtoverlay=disable-bt' "$CFG" || echo 'dtoverlay=disable-bt' | sudo tee -a "$CFG"
sudo systemctl disable --now hciuart 2>/dev/null || true
sudo sed -i 's/console=serial0,[0-9]* //' "$CMD"          # no login console on the link
sudo apt-get install -y stlink-tools python3-venv python3-serial cpufrequtils
sudo usermod -aG dialout "$USER"
echo 'GOVERNOR="performance"' | sudo tee /etc/default/cpufrequtils   # stable host timing
echo "Done. Reboot, then: ls -l /dev/ttyAMA0"
