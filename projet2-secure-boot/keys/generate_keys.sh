#!/usr/bin/env bash
# Generates the RSA-2048 dev signing key used by scripts/sign_fit.sh.
#
# "dev_key" matches the key-name-hint used throughout firmware/rpi_secure_boot.its
# -- mkimage looks up <key-name-hint>.key / <key-name-hint>.crt in the keydir
# passed via -k, so the name must match exactly.
#
# The private key never leaves this machine (keys/.gitignore excludes *.key
# and *.pem); in a real deployment it would live in an HSM or offline signing
# host, never on the device or in the build repo at all.
set -euo pipefail

KEY_NAME="dev_key"
KEY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$KEY_DIR"

if [[ -f "${KEY_NAME}.key" || -f "${KEY_NAME}.crt" ]]; then
    echo "error: ${KEY_NAME}.key/.crt already exist in $KEY_DIR" >&2
    echo "Remove them first if you really want to rotate the dev key (any" >&2
    echo "previously signed fitImage/control DTB would then need re-signing)." >&2
    exit 1
fi

openssl genrsa -out "${KEY_NAME}.key" 2048
openssl req -batch -new -x509 -key "${KEY_NAME}.key" -out "${KEY_NAME}.crt" \
    -days 3650 -subj "/CN=RPi4 Secure Boot Dev Key/O=embedded-security P2"
chmod 600 "${KEY_NAME}.key"

echo
echo "Generated:"
echo "  $KEY_DIR/${KEY_NAME}.key  (private -- keep offline in production)"
echo "  $KEY_DIR/${KEY_NAME}.crt  (public certificate, embedded into the FIT/control DTB)"
echo
echo "Next: scripts/sign_fit.sh"
