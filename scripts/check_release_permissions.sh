#!/usr/bin/env bash
# check_release_permissions.sh — least-privilege for the release workflow (SUP-04).
#
# Two properties, enforced semantically via the shared workflow-policy inspector
# (cmd/probectl-workflow-policy, which resolves YAML aliases/merges/flow maps so
# a hidden `write-all` cannot slip through):
#
#   1. No workflow-level write authority anywhere under .github/workflows/. The
#      default GITHUB_TOKEN every job inherits must be read-only; a job earns
#      write only by declaring it for itself.
#   2. In release.yml, job-level write is confined to the publishing/signing
#      allowlist (images, binaries, publish-chart, packages, airgap-bundle).
#      Any other write-capable release job — a gate job that runs `make`/`go`
#      against the tagged tree, say — is rejected.
#
# Plus a textual guard that every actions/checkout step across all workflows
# sets `persist-credentials: false`, so the git credential is not left on disk
# for later steps (OIDC/gh use the job token explicitly instead).
set -euo pipefail

cd "$(dirname "$0")/.."

# Publishing/signing jobs allowed to hold write in release.yml.
RELEASE_WRITE_ALLOWLIST="images binaries publish-chart packages airgap-bundle"

in_allowlist() {
  local job="$1" a
  for a in $RELEASE_WRITE_ALLOWLIST; do
    [[ "$job" == "$a" ]] && return 0
  done
  return 1
}

# No workflow-level write in ANY workflow file.
check_no_workflow_write() {
  local wf="$1" records scope subject level _action failed=0
  if ! records="$(go run ./cmd/probectl-workflow-policy permissions "$wf" 2>&1)"; then
    echo "release-permissions: semantic inspection failed closed for ${wf}:" >&2
    printf '%s\n' "$records" >&2
    return 1
  fi
  while IFS=$'\t' read -r scope subject level _action; do
    [[ -z "$scope" ]] && continue
    if [[ "$scope" == "workflow" && "$level" == "write" ]]; then
      echo "release-permissions: ${wf} grants workflow-level write authority (must be read-only; grant per job)" >&2
      failed=1
    fi
  done <<<"$records"
  return "$failed"
}

# In release.yml, only allowlisted jobs may hold write.
check_release_job_allowlist() {
  local wf="$1" records scope subject level _action failed=0
  records="$(go run ./cmd/probectl-workflow-policy permissions "$wf")"
  while IFS=$'\t' read -r scope subject level _action; do
    [[ -z "$scope" ]] && continue
    if [[ "$scope" == "job" && "$level" == "write" ]]; then
      if ! in_allowlist "$subject"; then
        echo "release-permissions: ${wf} job '${subject}' has write authority but is not a publishing job (allowed: ${RELEASE_WRITE_ALLOWLIST})" >&2
        failed=1
      fi
    fi
  done <<<"$records"
  return "$failed"
}

# Every actions/checkout step must disable credential persistence — enforced
# SEMANTICALLY via the policy tool, which parses step.with.persist-credentials
# as a real YAML mapping value. A grep would match the string inside a comment
# (`# persist-credentials: false`) while the input is actually unset (GitHub
# defaults to true), so a commented-out line reports "unset" and is rejected.
check_persist_credentials() {
  local wf="$1" records job line persist failed=0 total=0
  if ! records="$(go run ./cmd/probectl-workflow-policy checkouts "$wf" 2>&1)"; then
    echo "release-permissions: checkout inspection failed closed for ${wf}:" >&2
    printf '%s\n' "$records" >&2
    return 1
  fi
  while IFS=$'\t' read -r _wf job line persist; do
    [[ -z "$persist" ]] && continue
    total=$((total + 1))
    if [[ "$persist" != "false" ]]; then
      echo "release-permissions: ${wf}: checkout in job '${job}' at line ${line} has persist-credentials=${persist} (must be the literal mapping value false)" >&2
      failed=1
    fi
  done <<<"$records"
  if [[ "$total" -eq 0 ]]; then
    echo "release-permissions: ${wf}: no checkout steps found (scan logic error)" >&2
    return 1
  fi
  return "$failed"
}

run_all() {
  local failed=0 wf
  for wf in .github/workflows/*.yml; do
    check_no_workflow_write "$wf" || failed=1
    check_persist_credentials "$wf" || failed=1
  done
  check_release_job_allowlist .github/workflows/release.yml || failed=1
  [[ "$failed" -eq 0 ]]
}

selftest() {
  local tmp bad
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp:-}"' EXIT

  # (a) workflow-level write must be rejected.
  cat >"$tmp/wfwrite.yml" <<'YAML'
permissions:
  contents: write
jobs:
  build:
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000
        with:
          persist-credentials: false
YAML
  if check_no_workflow_write "$tmp/wfwrite.yml" 2>/dev/null; then
    echo "release-permissions SELFTEST: workflow-level write was accepted" >&2; exit 1
  fi

  # (b) an unlisted write-capable release job must be rejected.
  cat >"$tmp/badjob.yml" <<'YAML'
permissions:
  contents: read
jobs:
  sneaky-gate:
    permissions:
      contents: write
    steps:
      - run: make test
YAML
  if check_release_job_allowlist "$tmp/badjob.yml" 2>/dev/null; then
    echo "release-permissions SELFTEST: unlisted write-capable job was accepted" >&2; exit 1
  fi

  # (c) a checkout without persist-credentials:false must be rejected...
  cat >"$tmp/nopersist.yml" <<'YAML'
jobs:
  build:
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000
      - run: make test
YAML
  if check_persist_credentials "$tmp/nopersist.yml" 2>/dev/null; then
    echo "release-permissions SELFTEST: checkout without persist-credentials:false was accepted" >&2; exit 1
  fi
  # ...and the same file WITH the setting must pass.
  cat >"$tmp/persist.yml" <<'YAML'
jobs:
  build:
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000
        with:
          persist-credentials: false
      - run: make test
YAML
  if ! check_persist_credentials "$tmp/persist.yml" 2>/dev/null; then
    echo "release-permissions SELFTEST: well-formed checkout was rejected" >&2; exit 1
  fi

  # (c') ADVERSARIAL: a COMMENTED-OUT persist-credentials (the input is actually
  # unset; GitHub defaults to true) must be rejected — a textual grep would be
  # fooled by the comment, the semantic parser is not.
  cat >"$tmp/commented.yml" <<'YAML'
jobs:
  build:
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000
        with:
          fetch-depth: 0
          # persist-credentials: false
      - run: git push origin HEAD
YAML
  if check_persist_credentials "$tmp/commented.yml" 2>/dev/null; then
    echo "release-permissions SELFTEST: commented-out persist-credentials was accepted (grep bypass)" >&2; exit 1
  fi

  # An allowlisted write job must be accepted.
  cat >"$tmp/okjob.yml" <<'YAML'
permissions:
  contents: read
jobs:
  images:
    permissions:
      packages: write
    steps:
      - run: echo publish
YAML
  if ! check_release_job_allowlist "$tmp/okjob.yml" 2>/dev/null; then
    echo "release-permissions SELFTEST: allowlisted publishing job was rejected" >&2; exit 1
  fi

  echo "release-permissions SELFTEST: OK (workflow-write + unlisted-job-write + missing-persist-credentials all rejected)"
}

if [[ "${1:-}" == "SELFTEST" ]]; then
  selftest
  exit 0
fi

if run_all; then
  echo "release-permissions: no workflow-level write; release write-jobs are allowlisted; checkouts drop credentials"
else
  exit 1
fi
