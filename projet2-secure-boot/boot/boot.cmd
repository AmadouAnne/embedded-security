# U-Boot boot script for the RPi4 secure boot demo.
#
# Compile to boot.scr before copying to the boot partition:
#   mkimage -A arm64 -T script -C none -d boot.cmd boot.scr
#
# This U-Boot must be built with CONFIG_FIT_SIGNATURE=y and with
# boot/u-boot-control.dtb (produced by scripts/sign_fit.sh) as its control
# DTB (CONFIG_OF_CONTROL / u-boot.dtb) -- that's what makes the "#conf@1"
# signature check below mandatory rather than best-effort: the
# key-name-hint "dev_key" node in that control DTB carries the "required"
# property scripts/sign_fit.sh set with mkimage -r, so bootm refuses to
# proceed if fitImage isn't signed by that exact key.

setenv fit_addr 0x02000000

echo "Loading signed FIT image..."
fatload mmc 0:1 ${fit_addr} fitImage
if test $? -ne 0; then
    echo "SECURE BOOT: failed to load fitImage from boot partition -- halting."
    exit
fi

echo "Verifying signature and booting configuration 'conf@1'..."
# bootm's FIT-aware image selection ("#conf@1") triggers the signature
# check against the control DTB's required key before loading the kernel
# or fdt payloads -- an unsigned image, or one signed by any key other than
# keys/dev_key.key, is rejected here and boot stops.
bootm ${fit_addr}#conf@1
echo "SECURE BOOT: bootm returned -- signature verification failed or kernel exited. Halting."
