# P2 — Secure Boot & Chain of Trust (Raspberry Pi 4)

FIT (Flattened Image Tree) signing for a Raspberry Pi 4 boot chain: the
kernel and device tree are hashed (SHA-256) and signed (RSA-2048,
PKCS#1v1.5) inside a single U-Boot FIT image, with the trusted public key
embedded in U-Boot's own control DTB and marked `required` — an image
signed by any other key, or not signed at all, is rejected before boot.

## Layout

- `firmware/rpi_secure_boot.its` — FIT source: describes the kernel/dtb
  images and their hash/signature nodes, and the boot configuration.
- `keys/generate_keys.sh` — generates the RSA-2048 dev signing keypair
  (`dev_key.key`/`dev_key.crt`, both gitignored — regenerate your own).
- `scripts/sign_fit.sh` — builds `firmware/fitImage` from the `.its` and
  writes the trusted public key into `boot/u-boot-control.dtb`.
- `scripts/verify_chain.sh` — independently re-verifies the signed FIT
  image with plain `openssl`/`fdtget` (no U-Boot needed), and demonstrates
  two attack scenarios being rejected. See output below.
- `boot/boot.cmd` — U-Boot script source; compile with
  `mkimage -A arm64 -T script -C none -d boot.cmd boot.scr`.
- `docs/attack-vectors.md` — 4 attack vectors against this design, what's
  mitigated and tested vs. what's a documented, honest limitation.

## Usage

```sh
keys/generate_keys.sh      # one-time: creates keys/dev_key.{key,crt}
scripts/sign_fit.sh        # builds + signs firmware/fitImage
scripts/verify_chain.sh    # independent local verification (see below)
```

`scripts/verify_chain.sh` output on a correctly signed image:

```
=== 1. Hash + signature check on each signed image (real bytes, real keys) ===
OK:   kernel@1: SHA-256 of extracted data matches the FIT's stored hash
OK:   kernel@1: RSA-2048/SHA-256 signature verifies against the trusted dev key
OK:   fdt@1: SHA-256 of extracted data matches the FIT's stored hash
OK:   fdt@1: RSA-2048/SHA-256 signature verifies against the trusted dev key

=== 2. Attack scenario A: tamper with signed data, don't touch the signature ===
OK:   single-bit tamper on the kernel image is rejected (hash and signature both fail)

=== 3. Attack scenario B: attacker tampers AND re-signs with their own key ===
OK:   (sanity) attacker's forged image verifies fine against the attacker's OWN key
OK:   attacker-signed image is rejected by the trusted dev_key -- re-signing with a
      different key doesn't help without keys/dev_key.key
```

## What's validated locally vs. on real hardware

The per-image SHA-256 hashes and RSA-2048 signatures (`kernel@1`, `fdt@1`)
are checked above with plain `openssl`/`fdtget` — real cryptographic
verification, no simulation. The `configurations/conf@1/signature@1` node
is U-Boot's actual verified-boot gate (checked by `bootm` against
`boot/u-boot-control.dtb`'s `required` key); that step, and the full boot
chain, is validated on the real Raspberry Pi 4 with an actual U-Boot build
(`CONFIG_FIT_SIGNATURE=y`), not reproduced here. See `docs/attack-vectors.md`
for what this design does and does not protect against (rollback and the
U-Boot-itself root of trust are documented, honest gaps, not oversights).

The `Dockerfile` provides a build environment with `mkimage`,
`device-tree-compiler`, and an AArch64 cross-compiler for building U-Boot
itself with `CONFIG_FIT_SIGNATURE` enabled.
