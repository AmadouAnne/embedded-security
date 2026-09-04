#!/usr/bin/env bash
# Builds and signs the FIT image (firmware/fitImage) from
# firmware/rpi_secure_boot.its, and writes the public key into a U-Boot
# control DTB (boot/u-boot-control.dtb).
#
# On real hardware, that control DTB is what U-Boot itself is built with
# (CONFIG_OF_CONTROL) so it knows which RSA public key(s) are trusted at
# verify time -- an attacker who doesn't have keys/dev_key.key cannot
# produce a fitImage that this control DTB will accept, no matter how they
# repackage vmlinuz/the dtb (see docs/attack-vectors.md).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY_DIR="$ROOT/keys"
FW_DIR="$ROOT/firmware"
BOOT_DIR="$ROOT/boot"
CONTROL_DTB="$BOOT_DIR/u-boot-control.dtb"

if [[ ! -f "$KEY_DIR/dev_key.key" || ! -f "$KEY_DIR/dev_key.crt" ]]; then
    echo "error: no signing key in $KEY_DIR -- run keys/generate_keys.sh first." >&2
    exit 1
fi

mkdir -p "$BOOT_DIR"

# mkimage -K updates an *existing* dtb in place (it doesn't create one), so
# seed it with an empty device tree the first time this runs.
if [[ ! -f "$CONTROL_DTB" ]]; then
    printf '/dts-v1/;\n/ { };\n' | dtc -I dts -O dtb -o "$CONTROL_DTB" -
fi

# mkimage resolves the .its file's /incbin/("vmlinuz") and
# /incbin/("bcm2711-rpi-4-b.dtb") paths relative to the current directory,
# so we run it from firmware/ where both files actually live.
cd "$FW_DIR"
mkimage -f rpi_secure_boot.its \
    -k "$KEY_DIR" \
    -K "$CONTROL_DTB" \
    -r \
    fitImage

echo
echo "Signed: $FW_DIR/fitImage"
echo "Control DTB (embeds the public key + 'required' flag): $CONTROL_DTB"
echo
echo "Structural check:"
dumpimage -l "$FW_DIR/fitImage"
echo
echo "Next: scripts/verify_chain.sh"
