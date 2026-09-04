# Attack vectors & mitigations — RPi4 Secure Boot (P2)

Threat model: an attacker with physical access to the SD card and/or the
ability to push a firmware update over the network, but **without**
`keys/dev_key.key` (kept offline, never on the device or in this repo).

Vectors 1 and 2 below are exercised locally and automatically by
`scripts/verify_chain.sh` (real SHA-256 + RSA-2048/PKCS#1v1.5 checks against
the actual signed `firmware/fitImage`, not simulated). Vectors 3 and 4 are
real limitations of this design, documented honestly rather than hidden.

## 1. Direct tampering — swap or edit the kernel/dtb payload

**Attack**: replace `vmlinuz` or the device tree inside `fitImage` with a
modified one (e.g. a kernel with a backdoored init, or a dtb that disables a
security-relevant peripheral), without touching the signature.

**Mitigation**: each image node (`kernel@1`, `fdt@1`) carries a SHA-256 hash
and an RSA-2048 signature over its exact byte content (`rpi_secure_boot.its`).
Any single-bit change breaks the hash comparison and the signature
verification simultaneously. U-Boot's `bootm` performs this check before
loading either payload; `verify_chain.sh` §2 reproduces it standalone with
openssl and confirms a single flipped bit is rejected.

## 2. Re-signing with a different key (compromised build/update pipeline)

**Attack**: an attacker who can tamper with the image but does not have
`keys/dev_key.key` tries to cover their tracks by re-signing the modified
image with their own key, hoping the device just checks "is *a* valid
signature present" rather than "is it signed by *the* trusted key".

**Mitigation**: `scripts/sign_fit.sh` runs `mkimage -K ... -r`, which marks
the `dev_key` node in `boot/u-boot-control.dtb` as **required** — U-Boot's
control DTB is the actual root of trust for this stage, not the FIT image
itself (which is just data the attacker fully controls). A signature that
verifies against the attacker's own key still fails verification against
`dev_key`'s public key, because RSA signatures are not transferable between
keypairs. `verify_chain.sh` §3 demonstrates this exact scenario: the
attacker's forged image verifies fine against their own key (sanity check)
and is still rejected by the trusted key.

## 3. Rollback / downgrade to an older, legitimately-signed image

**Attack**: flash an older `fitImage` that *was* validly signed with
`dev_key` in the past, but is now known to contain a fixed vulnerability
(e.g. a patched kernel CVE). Signature verification alone cannot distinguish
"old but genuine" from "current and genuine" — both pass.

**Status: not mitigated in this project.** FIT signing has no built-in
version/freshness concept. A real deployment needs an independent
anti-rollback mechanism — typically a monotonic counter in one-time-
programmable (OTP) fuses or secure NVRAM, checked and incremented by the
bootloader before accepting an image, with the counter embedded in (or
alongside) the signed image. The Raspberry Pi 4's bootloader EEPROM does
expose some version-locking primitives at the BCM2711 boot-ROM stage, but
wiring that into this U-Boot/FIT flow is out of scope here and left as
documented future work rather than silently assumed away.

## 4. Root of trust: what verifies U-Boot itself?

**Attack**: replace `start4.elf`, `config.txt`, or the U-Boot binary itself
on the SD card's first-stage FAT partition with a malicious version that
skips FIT verification entirely (or accepts any key). Since this project's
chain of trust starts at U-Boot, an attacker who can replace U-Boot
bypasses everything documented in vectors 1–3.

**Status: not mitigated in this project — documented limitation, not a
gap that was overlooked.** A complete chain of trust must be rooted in
something immutable: the BCM2711's boot ROM would need to verify the
second-stage bootloader/U-Boot itself using a key burned into one-time
OTP fuses (Raspberry Pi 4 supports this via its secure-boot fusing
procedure). That fusing is irreversible and was deliberately not performed
on the loaner hardware used for this project's hands-on validation, since
bricking or permanently altering the trust state of borrowed hardware is
not an acceptable risk for a coursework/research demo. This project
therefore demonstrates and validates the **kernel/dtb integrity layer**
(FIT + RSA-2048, vectors 1–2) under the explicit assumption that U-Boot
itself is trusted — establishing that first link is real, well-understood
future work, not a claim this project makes.
