#!/bin/sh
# Toggle the Raspberry Pi serial console on the SD card boot partition
# (diagnostic only; the HIL link needs it OFF).
#   hil/sd_console.sh on    -> boot messages on GPIO14/15 at 115200
#   hil/sd_console.sh off   -> restore the measurement configuration
set -e
udisksctl mount -b /dev/mmcblk0p1 >/dev/null 2>&1 || true
B=$(findmnt -n -o TARGET /dev/mmcblk0p1)
[ -n "$B" ] || { echo "SD boot partition not found"; exit 1; }
case "$1" in
on)
    grep -q 'console=serial0' "$B/cmdline.txt" || sed -i 's/^/console=serial0,115200 /' "$B/cmdline.txt"
    grep -q '^uart_2ndstage=1' "$B/config.txt" || printf '\n# diagnostic: firmware boot log on UART\nuart_2ndstage=1\n' >> "$B/config.txt"
    sed -i 's/ quiet//; s/ splash//' "$B/cmdline.txt" ;;
off)
    sed -i 's/console=serial0,115200 //' "$B/cmdline.txt"
    sed -i '/^# diagnostic: firmware boot log on UART$/d; /^uart_2ndstage=1$/d' "$B/config.txt" ;;
*) echo "usage: $0 on|off"; exit 2 ;;
esac
echo "cmdline.txt: $(cat "$B/cmdline.txt")"
grep -n 'uart_2ndstage\|enable_uart\|disable-bt' "$B/config.txt"
sync
udisksctl unmount -b /dev/mmcblk0p1
