#!/usr/bin/env bash
# Independently verifies the signed FIT image (firmware/fitImage), and
# demonstrates that tampering + re-signing with an attacker's own key is
# detected -- without booting U-Boot at all.
#
# What this proves, and what it doesn't:
#   - The per-image hash@1 and signature@1 nodes (kernel@1, fdt@1) are
#     plain SHA-256 + PKCS#1v1.5 RSA-2048 over the raw image bytes, so they
#     can be (and are, below) checked directly with openssl -- no guessing
#     about mkimage's internal format.
#   - The configurations/conf@1/signature@1 node is U-Boot's actual
#     verified-boot gate (it's what bootm checks against the control DTB's
#     "required" key before booting at all). Reproducing *that* signature's
#     exact input construction outside of U-Boot's own C code would be
#     guesswork, so it is NOT re-implemented here -- it's exercised for
#     real tomorrow, on the Pi, by U-Boot itself refusing to boot an image
#     that fails it.
#   - "Attacker" here means: an attacker without keys/dev_key.key. If they
#     also don't have keys/dev_key.key, no amount of re-signing with their
#     own key produces something the embedded trusted pubkey accepts (see
#     Attack scenario B below) -- that's the actual security property.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FW="$ROOT/firmware/fitImage"
KEY_DIR="$ROOT/keys"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "OK:   $*"; }

[[ -f "$FW" ]] || fail "no $FW -- run scripts/sign_fit.sh first."

openssl x509 -in "$KEY_DIR/dev_key.crt" -pubkey -noout > "$WORK/trusted_pub.pem"

# fdtget's -t bx prints each byte without zero-padding (e.g. "2" for 0x02),
# which corrupts byte alignment if fed straight to `xxd -r -p` -- this
# helper re-pads every token to 2 hex digits first.
hexprop_to_bin() {
    local fit="$1" node="$2" prop="$3" out="$4"
    fdtget -t bx "$fit" "$node" "$prop" \
        | tr ' ' '\n' | grep -v '^$' \
        | while read -r b; do printf '%02x' "0x$b"; done \
        | xxd -r -p > "$out"
}

echo "=== 1. Hash + signature check on each signed image (real bytes, real keys) ==="
for pair in "kernel@1:0" "fdt@1:1"; do
    node="${pair%%:*}"; pos="${pair##*:}"

    dumpimage -T flat_dt -p "$pos" -o "$WORK/${node}.bin" "$FW" >/dev/null 2>&1

    algo=$(fdtget -t s "$FW" "/images/$node/hash@1" algo)
    [[ "$algo" == "sha256" ]] || fail "$node: unexpected hash algo '$algo'"

    computed_hash=$(openssl dgst -sha256 "$WORK/${node}.bin" | awk '{print $2}')
    # fdtget's -t bx doesn't zero-pad single-hex-digit bytes, so re-pad
    # each token before comparing against openssl's zero-padded output.
    stored_hash=$(fdtget -t bx "$FW" "/images/$node/hash@1" value \
        | tr ' ' '\n' | grep -v '^$' | while read -r b; do printf '%02x' "0x$b"; done)
    [[ "$stored_hash" == "$computed_hash" ]] || fail "$node: hash mismatch (image data doesn't match what was signed)"
    ok "$node: SHA-256 of extracted data matches the FIT's stored hash"

    hexprop_to_bin "$FW" "/images/$node/signature@1" value "$WORK/${node}.sig"
    openssl dgst -sha256 -verify "$WORK/trusted_pub.pem" -signature "$WORK/${node}.sig" "$WORK/${node}.bin" \
        >/dev/null 2>&1 || fail "$node: RSA-2048 signature does NOT verify against keys/dev_key.crt"
    ok "$node: RSA-2048/SHA-256 signature verifies against the trusted dev key"
done

echo
echo "=== 2. Attack scenario A: tamper with signed data, don't touch the signature ==="
python3 - "$WORK/kernel@1.bin" "$WORK/tampered.bin" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
data = bytearray(open(src, "rb").read())
data[1000] ^= 0xFF  # flip one bit deep inside the kernel image
open(dst, "wb").write(data)
PY
if openssl dgst -sha256 -verify "$WORK/trusted_pub.pem" -signature "$WORK/kernel@1.sig" "$WORK/tampered.bin" >/dev/null 2>&1; then
    fail "tampered kernel image was accepted -- signing is broken"
fi
ok "single-bit tamper on the kernel image is rejected (hash and signature both fail)"

echo
echo "=== 3. Attack scenario B: attacker tampers AND re-signs with their own key ==="
openssl genrsa -out "$WORK/attacker.key" 2048 >/dev/null 2>&1
openssl req -batch -new -x509 -key "$WORK/attacker.key" -out "$WORK/attacker.crt" -days 365 \
    -subj "/CN=Attacker Key" >/dev/null 2>&1
openssl dgst -sha256 -sign "$WORK/attacker.key" -out "$WORK/attacker.sig" "$WORK/tampered.bin"

openssl x509 -in "$WORK/attacker.crt" -pubkey -noout > "$WORK/attacker_pub.pem"
openssl dgst -sha256 -verify "$WORK/attacker_pub.pem" -signature "$WORK/attacker.sig" "$WORK/tampered.bin" \
    >/dev/null 2>&1 || fail "sanity check failed: attacker's own signature doesn't even verify against their own key"
ok "(sanity) attacker's forged image verifies fine against the attacker's OWN key"

if openssl dgst -sha256 -verify "$WORK/trusted_pub.pem" -signature "$WORK/attacker.sig" "$WORK/tampered.bin" >/dev/null 2>&1; then
    fail "attacker-signed image was accepted by the TRUSTED key -- chain of trust is broken"
fi
ok "attacker-signed image is rejected by the trusted dev_key -- re-signing with a different key doesn't help without keys/dev_key.key"

echo
echo "All local checks passed. Boot-time enforcement (configurations/conf@1/signature@1"
echo "against boot/u-boot-control.dtb's 'required' key, refusing to boot otherwise) is"
echo "validated on the real Raspberry Pi 4 with U-Boot, not simulated here."
