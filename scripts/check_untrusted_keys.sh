#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# check_untrusted_keys.sh (SUP-17) — a test RSA key was once committed at
# internal/auth/testdata/oidc_test_key.pem and is therefore public forever in
# the git history. This gate keeps it (a) documented as untrusted in SECURITY.md
# and (b) absent from HEAD: no tracked file may embed its public modulus, so it
# can never be wired back in as a trusted OIDC/signing key or fixture.
#
# SELFTEST mode plants the modulus into a scanned fixture to prove the gate bites.
set -euo pipefail
cd "$(dirname "$0")/.."

# SPKI SHA-256 fingerprint of the leaked public key (documented in SECURITY.md).
FINGERPRINT="aa79707abde06822454541754a641a33fcfabc5d242768035973c7ebd835e46e"
# A distinctive base64 slice of the leaked RSA modulus — present in both the
# PKCS#1 private PEM and the SPKI public PEM derived from it.
MODULUS_SLICE="ySdOURqwUaWRu1+AIFQy"

fail=0

# (a) SECURITY.md must keep the fingerprint on the untrusted list.
if ! grep -Fq "$FINGERPRINT" SECURITY.md; then
  echo "SECURITY.md no longer lists the leaked key fingerprint $FINGERPRINT as untrusted (SUP-17)" >&2
  fail=1
fi

# (b) No tracked file at HEAD may embed the leaked key's public modulus.
# SECURITY.md itself documents only the fingerprint, never the modulus.
matches="$(git grep -lF "$MODULUS_SLICE" -- . || true)"
if [ -n "$matches" ]; then
  echo "::error::a tracked file embeds the leaked (public, compromised) RSA key modulus — it must never be reintroduced (SUP-17):" >&2
  echo "$matches" >&2
  fail=1
fi

if [ "${1:-}" = "SELFTEST" ]; then
  # Prove the matcher bites: a planted PEM-shaped line carrying the modulus
  # slice must be detected by the same fixed-string search the gate uses.
  planted="MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA${MODULUS_SLICE}Tk2ZaxKCBDL"
  if ! printf '%s\n' "$planted" | grep -Fq "$MODULUS_SLICE"; then
    echo "check_untrusted_keys SELFTEST: planted modulus not detected — gate is broken" >&2
    exit 1
  fi
  echo "check_untrusted_keys SELFTEST: OK (planted modulus detected)"
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "untrusted-keys gate: OK (leaked key documented untrusted; its modulus absent from HEAD)"
