#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-probectl-TBD
#
# check_cosign_wiring.sh (SUPPLY-002) — assert cosign verification is actually
# WIRED into the installers, not just claimed. Fails if:
#   - install.sh lost its default verify path or the cosign verify-blob invocation,
#   - the Ansible role lost the package_url task block or its cosign step,
#   - probectl_verify_cosign has no usage in the role tasks,
#   - install.sh does NOT fail closed by default when cosign is missing,
#   - install.sh does NOT fail closed when the signature is absent,
#   - install.sh allows --no-verify without the explicit privileged-code ack.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
INSTALL=deploy/agent/install.sh
TASKS=deploy/ansible/roles/probectl_agents/tasks/main.yml

# 1) static: the verification code exists (not a dead variable / false claim).
grep -q -- '--verify' "$INSTALL"            || { echo "install.sh: missing --verify path"; fail=1; }
grep -q -- '--no-verify' "$INSTALL"         || { echo "install.sh: missing explicit --no-verify break-glass"; fail=1; }
grep -q 'VERIFY="${PROBECTL_VERIFY_COSIGN:-1}"' "$INSTALL" || { echo "install.sh: cosign verification is not default-on"; fail=1; }
grep -q 'PROBECTL_UNVERIFIED_INSTALL_ACK' "$INSTALL" || { echo "install.sh: missing unverified-install acknowledgement"; fail=1; }
grep -q 'cosign verify-blob' "$INSTALL"     || grep -q 'cosign \\' "$INSTALL" || { echo "install.sh: missing cosign verify-blob"; fail=1; }
grep -q "install_method == 'package_url'" "$TASKS" || { echo "ansible: package_url task block missing"; fail=1; }
grep -q 'cosign' "$TASKS"                   || { echo "ansible: no cosign step in the role"; fail=1; }
grep -q 'verify-blob' "$TASKS"              || { echo "ansible: no cosign verify-blob in the role"; fail=1; }
grep -q 'probectl_verify_cosign' "$TASKS"   || { echo "ansible: probectl_verify_cosign referenced nowhere in tasks (dead variable)"; fail=1; }

# 2) functional fail-closed checks on install.sh (no real cosign needed).
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
printf '#!/bin/true\n' > "$tmp/bin"; chmod +x "$tmp/bin"

# (a) cosign missing on PATH -> must refuse by DEFAULT before installing.
if PATH="/usr/bin:/bin" bash "$INSTALL" "$tmp/bin" >/dev/null 2>&1; then
  echo "install.sh SUCCEEDED by default with cosign absent (must fail closed)"; fail=1
fi

# (b) cosign present but the signature file absent -> must refuse. Stub a cosign
#     on PATH so the 'command -v cosign' check passes; the missing .sig must stop
#     it before any verify call.
stub="$tmp/path"; mkdir -p "$stub"
printf '#!/bin/sh\nexit 0\n' > "$stub/cosign"; chmod +x "$stub/cosign"
printf '#!/bin/sh\nexit 0\n' > "$stub/id"; chmod +x "$stub/id"  # not used; real id is fine
if PATH="$stub:/usr/bin:/bin" PROBECTL_COSIGN_SIG="$tmp/missing.sig" \
     bash "$INSTALL" "$tmp/bin" >/dev/null 2>&1; then
  echo "install.sh SUCCEEDED with the signature absent (must fail closed)"; fail=1
fi

# (c) --no-verify is break-glass, not a silent bypass.
if PATH="$stub:/usr/bin:/bin" bash "$INSTALL" --no-verify "$tmp/bin" >/dev/null 2>&1; then
  echo "install.sh --no-verify SUCCEEDED without PROBECTL_UNVERIFIED_INSTALL_ACK (must fail closed)"; fail=1
fi

# (d) the acknowledged break-glass path must be explicit and auditable. Running
# as non-root should get past the unverified-install refusal, then stop at the
# root preflight instead of installing anything.
breakglass_log="$tmp/breakglass.log"
if PATH="$stub:/usr/bin:/bin" \
   PROBECTL_UNVERIFIED_INSTALL_ACK=allow-unsigned-cap-bpf-code \
   bash "$INSTALL" --no-verify "$tmp/bin" >"$breakglass_log" 2>&1; then
  echo "install.sh --no-verify with acknowledgement unexpectedly succeeded as non-root"; fail=1
elif ! grep -q 'BREAK-GLASS' "$breakglass_log" || ! grep -q 'run as root' "$breakglass_log"; then
  echo "install.sh --no-verify acknowledgement did not reach the audited root preflight"; fail=1
fi

if [[ $fail -ne 0 ]]; then
  echo
  echo "cosign-wiring gate FAILED (SUPPLY-002): cosign verification is not wired in / not fail-closed."
  exit 1
fi
echo "cosign-wiring gate: OK (install.sh default verification + Ansible package_url cosign step present and fail-closed)"
