#!/usr/bin/env bash
#
# FIPS enabler (CLAUDE.md §7 guardrail 3): all cryptographic primitives route
# through internal/crypto so a FIPS 140-3 validated module can be compiled in.
# This guard fails if any Go file OUTSIDE internal/crypto imports a low-level
# crypto primitive package or third-party crypto.
#
# crypto/tls and crypto/x509 (transport / PKI) are intentionally allowed — a FIPS
# Go build swaps their primitives at compile time, and TLS policy is still
# centralized in internal/crypto.
set -euo pipefail

cd "$(dirname "$0")/.."

forbidden='crypto/(aes|cipher|des|dsa|ecdh|ecdsa|ed25519|elliptic|hmac|md5|rand|rc4|rsa|sha1|sha256|sha512|sha3|subtle)|golang\.org/x/crypto'

# Match import lines (with an optional alias) that reference a forbidden path,
# excluding internal/crypto, which legitimately owns the primitives.
violations="$(grep -rEn \
  "^[[:space:]]*([A-Za-z_.][A-Za-z0-9_.]*[[:space:]]+)?\"(${forbidden})(/[^\"]*)?\"" \
  --include='*.go' . | grep -v '/internal/crypto/' || true)"

if [ -n "${violations}" ]; then
  echo "FORBIDDEN crypto-primitive imports outside internal/crypto:" >&2
  echo "${violations}" >&2
  echo "" >&2
  echo "Route cryptographic operations through internal/crypto (FIPS enabler)." >&2
  exit 1
fi

echo "crypto-import guard: OK (no primitive imports outside internal/crypto)"
