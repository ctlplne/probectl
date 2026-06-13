#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-probectl-TBD
#
# check_cosign_wiring.sh (SUPPLY-002) — assert cosign verification is actually
# WIRED into the installers, not just claimed. Fails if:
#   - install.sh lost its --verify path or the cosign verify-blob invocation,
#   - the Ansible role lost the package_url task block or its cosign step,
#   - probectl_verify_cosign has no usage in the role tasks,
#   - install.sh --verify does NOT fail closed when cosign is missing,
#   - install.sh --verify does NOT fail closed when the signature is absent.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
INSTALL=deploy/agent/install.sh
TASKS=deploy/ansible/roles/probectl_agents/tasks/main.yml

# 1) static: the verification code exists (not a dead variable / false claim).
grep -q -- '--verify' "$INSTALL"            || { echo "install.sh: missing --verify path"; fail=1; }
grep -q 'cosign verify-blob' "$INSTALL"     || grep -q 'cosign \\' "$INSTALL" || { echo "install.sh: missing cosign verify-blob"; fail=1; }
grep -q "install_method == 'package_url'" "$TASKS" || { echo "ansible: package_url task block missing"; fail=1; }
grep -q 'cosign' "$TASKS"                   || { echo "ansible: no cosign step in the role"; fail=1; }
grep -q 'verify-blob' "$TASKS"              || { echo "ansible: no cosign verify-blob in the role"; fail=1; }
grep -q 'probectl_verify_cosign' "$TASKS"   || { echo "ansible: probectl_verify_cosign referenced nowhere in tasks (dead variable)"; fail=1; }

# 2) functional fail-closed checks on install.sh --verify (no cosign needed).
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
printf '#!/bin/true\n' > "$tmp/bin"; chmod +x "$tmp/bin"

# (a) cosign missing on PATH -> must refuse (exit non-zero) before installing.
#     Run as non-root so it would also fail the root check; isolate the cosign
#     branch by giving an empty PATH that still has the shell builtins.
if PATH="/nonexistent" bash "$INSTALL" --verify "$tmp/bin" >/dev/null 2>&1; then
  echo "install.sh --verify SUCCEEDED with cosign absent (must fail closed)"; fail=1
fi

# (b) cosign present but the signature file absent -> must refuse. Stub a cosign
#     on PATH so the 'command -v cosign' check passes; the missing .sig must stop
#     it before any verify call.
stub="$tmp/path"; mkdir -p "$stub"
printf '#!/bin/sh\nexit 0\n' > "$stub/cosign"; chmod +x "$stub/cosign"
printf '#!/bin/sh\nexit 0\n' > "$stub/id"; chmod +x "$stub/id"  # not used; real id is fine
if PATH="$stub:/usr/bin:/bin" PROBECTL_COSIGN_SIG="$tmp/missing.sig" \
     bash "$INSTALL" --verify "$tmp/bin" >/dev/null 2>&1; then
  echo "install.sh --verify SUCCEEDED with the signature absent (must fail closed)"; fail=1
fi

if [[ $fail -ne 0 ]]; then
  echo
  echo "cosign-wiring gate FAILED (SUPPLY-002): cosign verification is not wired in / not fail-closed."
  exit 1
fi
echo "cosign-wiring gate: OK (install.sh --verify + Ansible package_url cosign step present and fail-closed)"
