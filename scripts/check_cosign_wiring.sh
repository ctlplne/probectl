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
#   - the air-gap bundle or Ansible air-gap package path can bypass cosign,
#   - release images are not signed by immutable digest,
#   - the shipped privileged-agent admission policy no longer verifies digest
#     and keyless release-workflow signatures.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
INSTALL=deploy/agent/install.sh
TASKS=deploy/ansible/roles/probectl_agents/tasks/main.yml
AIRGAP=scripts/airgap-bundle.sh
RELEASE=.github/workflows/release.yml
ADMISSION=deploy/admission/probectl-agent-image-integrity.kyverno.yaml

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
grep -q "install_method == 'airgap'" "$TASKS" || { echo "ansible: airgap task block missing"; fail=1; }
grep -q 'probectl_airgap_pkg_path' "$TASKS" || { echo "ansible: airgap package path is not resolved once for verify+install"; fail=1; }
grep -q 'cosign verify-blob for the local air-gap package' "$TASKS" || { echo "ansible: airgap package cosign verify task missing"; fail=1; }
grep -q '{{ probectl_airgap_pkg_path }}.sig' "$TASKS" || { echo "ansible: airgap .sig file is not required"; fail=1; }
grep -q '{{ probectl_airgap_pkg_path }}.pem' "$TASKS" || { echo "ansible: airgap .pem file is not required"; fail=1; }

airgap_verify_line="$(grep -n 'cosign verify-blob for the local air-gap package' "$TASKS" | head -n1 | cut -d: -f1 || true)"
airgap_install_line="$(grep -n 'Install from the air-gap bundle' "$TASKS" | head -n1 | cut -d: -f1 || true)"
if [[ -z "$airgap_verify_line" || -z "$airgap_install_line" || "$airgap_verify_line" -ge "$airgap_install_line" ]]; then
  echo "ansible: airgap cosign verification must appear before the package install task"; fail=1
fi

grep -q 'PROBECTL_AIRGAP_VERIFY_COSIGN:-1' "$AIRGAP" || { echo "airgap: cosign verification is not default-on"; fail=1; }
grep -q 'PROBECTL_AIRGAP_UNVERIFIED_ACK' "$AIRGAP" || { echo "airgap: missing explicit unverified-bundle acknowledgement"; fail=1; }
grep -q 'cosign verify-blob' "$AIRGAP" || { echo "airgap: missing signed binary/package verify-blob"; fail=1; }
grep -q 'cosign verify' "$AIRGAP" || { echo "airgap: missing image signature verification"; fail=1; }
grep -q 'IMAGE-VERIFICATION.txt' "$AIRGAP" || { echo "airgap: missing image verification manifest"; fail=1; }
grep -q 'OUT/packages' "$AIRGAP" || { echo "airgap: signed deb/rpm packages are not bundled"; fail=1; }

grep -q 'cosign sign --yes "${IMAGE_REF}"' "$RELEASE" || { echo "release: image digest cosign signing is missing"; fail=1; }
grep -q 'steps.build.outputs.digest' "$RELEASE" || { echo "release: image signing is not tied to the immutable build digest"; fail=1; }
grep -q 'cosign verify' "$RELEASE" || { echo "release: image signature self-verify step is missing"; fail=1; }

grep -q 'verifyImages:' "$ADMISSION" || { echo "admission: Kyverno verifyImages policy missing"; fail=1; }
grep -q 'verifyDigest: true' "$ADMISSION" || { echo "admission: digest verification is not enforced"; fail=1; }
grep -q 'required: true' "$ADMISSION" || { echo "admission: signature verification is not required"; fail=1; }
grep -q 'keyless:' "$ADMISSION" || { echo "admission: keyless release identity verifier missing"; fail=1; }
grep -q 'token.actions.githubusercontent.com' "$ADMISSION" || { echo "admission: GitHub OIDC issuer pin missing"; fail=1; }
grep -q 'release\\.yml@refs/tags' "$ADMISSION" || { echo "admission: release workflow tag identity pin missing"; fail=1; }
grep -q 'probectl-ebpf-agent' "$ADMISSION" || { echo "admission: policy does not target the privileged eBPF agent"; fail=1; }

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
  echo "cosign-wiring gate FAILED (SUPPLY-001/002): cosign verification is not wired in / not fail-closed."
  exit 1
fi
echo "cosign-wiring gate: OK (install.sh, airgap bundle, Ansible package_url/airgap, image signing, and admission policy are fail-closed)"
