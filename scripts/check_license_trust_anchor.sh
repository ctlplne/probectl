#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# check_license_trust_anchor.sh — DPR-001. A build verifies commercial license
# files only against the trust anchors it carries: the committed
# internal/license/trusted_keys/*.pub files plus any PROBECTL_LICENSE_PUBKEYS_B64
# link-time keys. A release that carries none ships control planes that refuse
# every license file ("license: no trusted license keys are baked into this
# build"), so the release workflow runs this with --release before any artifact
# is built.
#
#   check_license_trust_anchor.sh            validate every present anchor (a keyless dev tree is legal)
#   check_license_trust_anchor.sh --release  additionally fail closed when there is no anchor at all
#   check_license_trust_anchor.sh SELFTEST   prove the checker catches a bad key and an empty release
set -euo pipefail

ROOT="${PROBECTL_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
KEY_DIR="${PROBECTL_TRUSTED_KEY_DIR:-$ROOT/internal/license/trusted_keys}"

is_ed25519_pub() {
  # A trust anchor is a PEM "PUBLIC KEY" block whose algorithm openssl names
  # ED25519. A private key (even one openssl could derive a public key from),
  # a certificate, or garbage is rejected.
  grep -q -- '-----BEGIN PUBLIC KEY-----' "$1" || return 1
  if grep -q 'PRIVATE KEY' "$1"; then return 1; fi
  openssl pkey -pubin -in "$1" -noout -text 2>/dev/null | grep -q 'ED25519'
}

count_anchors() {
  local n=0 f tmp part
  shopt -s nullglob
  for f in "$KEY_DIR"/*.pub; do
    if is_ed25519_pub "$f"; then
      n=$((n + 1))
    else
      echo "license-trust-anchor: $f is not an Ed25519 public-key PEM" >&2
      return 1
    fi
  done
  shopt -u nullglob
  if [ -n "${PROBECTL_LICENSE_PUBKEYS_B64:-}" ]; then
    tmp="$(mktemp)"
    IFS=',' read -r -a parts <<<"$PROBECTL_LICENSE_PUBKEYS_B64"
    for part in "${parts[@]}"; do
      [ -n "$part" ] || continue
      if ! printf '%s' "$part" | base64 -d >"$tmp" 2>/dev/null || ! is_ed25519_pub "$tmp"; then
        rm -f "$tmp"
        echo "license-trust-anchor: a PROBECTL_LICENSE_PUBKEYS_B64 entry is not a base64 Ed25519 public-key PEM" >&2
        return 1
      fi
      n=$((n + 1))
    done
    rm -f "$tmp"
  fi
  printf '%s\n' "$n"
}

main() {
  local mode="${1:-}" n
  n="$(count_anchors)" || exit 1
  if [ "$mode" = "--release" ] && [ "$n" -eq 0 ]; then
    cat >&2 <<'MSG'
license-trust-anchor: RELEASE REFUSED — this tree carries no license trust anchor.
Every shipped control plane would refuse commercial license files (DPR-001).
Fix: probectl-license gen-key (keep the private key offline), commit the public
key as internal/license/trusted_keys/<name>.pub, or set the repository variable
PROBECTL_LICENSE_PUBKEYS_B64 to the base64 PEM. See docs/editions.md.
MSG
    exit 1
  fi
  echo "license-trust-anchor: OK (${n} anchor(s)${mode:+, $mode})"
}

selftest() {
  local tmp b64
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064 # expand now: the local is gone when EXIT fires
  trap "rm -rf '$tmp'" EXIT
  mkdir -p "$tmp/keys"
  # 1. an empty key dir is legal by default and refused for a release
  PROBECTL_TRUSTED_KEY_DIR="$tmp/keys" PROBECTL_LICENSE_PUBKEYS_B64= bash "$0" >/dev/null \
    || { echo "selftest: an empty key dir must pass in default mode" >&2; exit 1; }
  if PROBECTL_TRUSTED_KEY_DIR="$tmp/keys" PROBECTL_LICENSE_PUBKEYS_B64= bash "$0" --release >/dev/null 2>&1; then
    echo "selftest: --release must refuse zero anchors" >&2; exit 1
  fi
  # 2. a real Ed25519 public key passes --release
  openssl genpkey -algorithm ed25519 -out "$tmp/priv.pem" 2>/dev/null
  openssl pkey -in "$tmp/priv.pem" -pubout -out "$tmp/keys/good.pub" 2>/dev/null
  PROBECTL_TRUSTED_KEY_DIR="$tmp/keys" PROBECTL_LICENSE_PUBKEYS_B64= bash "$0" --release >/dev/null \
    || { echo "selftest: a valid public key must pass --release" >&2; exit 1; }
  # 3. a private key (or garbage) named .pub is rejected
  cp "$tmp/priv.pem" "$tmp/keys/bad.pub"
  if PROBECTL_TRUSTED_KEY_DIR="$tmp/keys" PROBECTL_LICENSE_PUBKEYS_B64= bash "$0" >/dev/null 2>&1; then
    echo "selftest: a private key committed as .pub must be rejected" >&2; exit 1
  fi
  rm -f "$tmp/keys/bad.pub"
  # 4. the link-time variable is validated the same way
  b64="$(base64 <"$tmp/keys/good.pub" | tr -d '\n')"
  rm -f "$tmp/keys/good.pub"
  PROBECTL_TRUSTED_KEY_DIR="$tmp/keys" PROBECTL_LICENSE_PUBKEYS_B64="$b64" bash "$0" --release >/dev/null \
    || { echo "selftest: a valid link-time key must pass --release" >&2; exit 1; }
  if PROBECTL_TRUSTED_KEY_DIR="$tmp/keys" PROBECTL_LICENSE_PUBKEYS_B64="not-base64!!" bash "$0" >/dev/null 2>&1; then
    echo "selftest: a garbage link-time key must be rejected" >&2; exit 1
  fi
  echo "license-trust-anchor selftest: OK"
}

case "${1:-}" in
  SELFTEST) selftest ;;
  *) main "${1:-}" ;;
esac
