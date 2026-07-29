#!/usr/bin/env bash
# check_workflow_permissions.sh — keep write-capable CI jobs away from PR code.
#
# The coverage job executes code from the checked-out revision, so its token is
# intentionally contents:read-only. A separate, dependent job may comment on a
# pull request, but it must not checkout or execute repository code; it only
# downloads the bounded summary artifact and passes that file to `gh`.
set -euo pipefail

cd "$(dirname "$0")/.."

extract_job() {
  local workflow="$1"
  local job="$2"

  awk -v job="$job" '
    /^jobs:[[:space:]]*$/ { in_jobs=1; next }
    in_jobs && $0 ~ "^  " job ":[[:space:]]*$" {
      found=1
      print
      next
    }
    found && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { exit }
    found { print }
    END { if (!found) exit 1 }
  ' "$workflow"
}

job_permissions() {
  awk '
    /^    permissions:[[:space:]]*$/ { in_permissions=1; next }
    in_permissions && /^      [A-Za-z0-9_-]+:[[:space:]]*/ {
      line=$0
      sub(/^[[:space:]]*/, "", line)
      print line
      next
    }
    in_permissions { exit }
  ' | LC_ALL=C sort
}

extract_named_step() {
  local step_name="$1"

  awk -v step_name="$step_name" '
    $0 == "      - name: " step_name {
      found=1
      print
      next
    }
    found && /^      - / { exit }
    found { print }
    END { if (!found) exit 1 }
  '
}

job_run_commands() {
  awk '
    /^        run:[[:space:]]*\|[[:space:]]*$/ {
      in_run=1
      next
    }
    /^        run:[[:space:]]+/ {
      line=$0
      sub(/^        run:[[:space:]]+/, "", line)
      print line
      in_run=0
      next
    }
    in_run && /^          / {
      line=$0
      sub(/^          /, "", line)
      print line
      next
    }
    in_run { in_run=0 }
  '
}

check_workflow() {
  local workflow="$1"
  local failed=0
  local coverage
  local commenter
  local permissions
  local upload_step
  local commands
  local semantic_permissions
  local scope
  local subject
  local level
  local action_use

  if ! semantic_permissions="$(go run ./cmd/probectl-workflow-policy permissions "$workflow" 2>&1)"; then
    echo "workflow-permissions: semantic YAML inspection failed closed for ${workflow}:" >&2
    printf '%s\n' "$semantic_permissions" >&2
    return 1
  fi
  while IFS=$'\t' read -r scope subject level action_use; do
    [[ -z "$scope" ]] && continue
    if [[ "$scope" == "workflow" && "$level" == "write" ]]; then
      echo "workflow-permissions: workflow-level write authority is forbidden in ${workflow}" >&2
      failed=1
    fi
    if [[ "$scope" == "job" && "$level" == "write" && "$subject" != "coverage-comment" ]]; then
      echo "workflow-permissions: unclassified job ${subject} has write authority" >&2
      failed=1
    fi
    if [[ "$scope" == "job" && "$subject" == "coverage-comment" && "$action_use" != "none" ]]; then
      echo "workflow-permissions: coverage-comment must not run actions from a repository" >&2
      failed=1
    fi
  done <<<"$semantic_permissions"

  if ! coverage="$(extract_job "$workflow" coverage)"; then
    echo "workflow-permissions: missing coverage job in ${workflow}" >&2
    return 1
  fi
  if ! commenter="$(extract_job "$workflow" coverage-comment)"; then
    echo "workflow-permissions: missing coverage-comment job in ${workflow}" >&2
    return 1
  fi

  permissions="$(printf '%s\n' "$coverage" | job_permissions)"
  if [[ "$permissions" != "contents: read" ]]; then
    echo "workflow-permissions: coverage must have only 'contents: read'; got:" >&2
    printf '%s\n' "$permissions" >&2
    failed=1
  fi
  if ! grep -q 'actions/checkout@' <<<"$coverage"; then
    echo "workflow-permissions: coverage must checkout the tested revision" >&2
    failed=1
  fi
  if grep -q 'gh pr comment' <<<"$coverage"; then
    echo "workflow-permissions: coverage must not comment on pull requests" >&2
    failed=1
  fi
  if ! grep -q 'tail -40.*cut -c1-240' <<<"$coverage"; then
    echo "workflow-permissions: coverage summary must retain its line/count bounds" >&2
    failed=1
  fi

  if ! upload_step="$(printf '%s\n' "$coverage" | extract_named_step "Upload bounded PR coverage summary")"; then
    echo "workflow-permissions: coverage is missing the bounded summary upload step" >&2
    failed=1
    upload_step=""
  fi
  if [[ -n "$upload_step" ]]; then
    grep -q 'uses: actions/upload-artifact@' <<<"$upload_step" ||
      { echo "workflow-permissions: bounded summary must use upload-artifact" >&2; failed=1; }
    grep -Eq '^        if:.*always\(\).*pull_request' <<<"$upload_step" ||
      { echo "workflow-permissions: bounded summary artifact must be PR-only" >&2; failed=1; }
    grep -Eq '^          name: coverage-pr-summary[[:space:]]*$' <<<"$upload_step" ||
      { echo "workflow-permissions: bounded artifact name must be coverage-pr-summary" >&2; failed=1; }
    grep -Eq '^          path: coverage-summary\.txt[[:space:]]*$' <<<"$upload_step" ||
      { echo "workflow-permissions: bounded artifact may contain only coverage-summary.txt" >&2; failed=1; }
    grep -Eq '^          retention-days: 1[[:space:]]*$' <<<"$upload_step" ||
      { echo "workflow-permissions: PR summary artifact retention must remain one day" >&2; failed=1; }
  fi

  permissions="$(printf '%s\n' "$commenter" | job_permissions)"
  if [[ "$permissions" != $'actions: read\npull-requests: write' ]]; then
    echo "workflow-permissions: coverage-comment must have only actions:read + pull-requests:write; got:" >&2
    printf '%s\n' "$permissions" >&2
    failed=1
  fi
  grep -Eq '^    needs: coverage[[:space:]]*$' <<<"$commenter" ||
    { echo "workflow-permissions: coverage-comment must depend on coverage" >&2; failed=1; }
  grep -Eq '^    if:.*always\(\).*pull_request' <<<"$commenter" ||
    { echo "workflow-permissions: coverage-comment must remain a PR-only always() follow-up" >&2; failed=1; }
  grep -Eq '^    continue-on-error: true[[:space:]]*$' <<<"$commenter" ||
    { echo "workflow-permissions: coverage-comment must remain best-effort" >&2; failed=1; }
  commands="$(printf '%s\n' "$commenter" | job_run_commands)"
  while IFS= read -r command; do
    [[ -z "$command" || "$command" == \#* ]] && continue
    case "$command" in
      'gh run download "${{ github.run_id }}" --name coverage-pr-summary --dir coverage-pr-summary || true') ;;
      'test -s coverage-pr-summary/coverage-summary.txt || exit 0') ;;
      'gh pr comment "${{ github.event.pull_request.number }}" --body-file coverage-pr-summary/coverage-summary.txt || true') ;;
      *)
        echo "workflow-permissions: coverage-comment command is not allowlisted: ${command}" >&2
        failed=1
        ;;
    esac
  done <<<"$commands"
  grep -Fq 'gh run download "${{ github.run_id }}" --name coverage-pr-summary --dir coverage-pr-summary || true' <<<"$commands" ||
    { echo "workflow-permissions: coverage-comment must download only coverage-pr-summary" >&2; failed=1; }
  grep -Fq 'gh pr comment "${{ github.event.pull_request.number }}" --body-file coverage-pr-summary/coverage-summary.txt || true' <<<"$commands" ||
    { echo "workflow-permissions: coverage-comment must pass only the summary file to gh" >&2; failed=1; }

  [[ "$failed" -eq 0 ]]
}

selftest() {
  local selftest_tmp
  local fixture
  local bad

  selftest_tmp="$(mktemp -d)"
  WORKFLOW_PERMISSIONS_SELFTEST_TMP="$selftest_tmp"
  trap 'rm -rf "$WORKFLOW_PERMISSIONS_SELFTEST_TMP"' EXIT
  fixture="${selftest_tmp}/valid.yml"
  bad="${selftest_tmp}/bad.yml"

  cat >"$fixture" <<'YAML'
jobs:
  coverage:
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000
      - run: go tool cover -func=coverage.out | tail -40 | cut -c1-240
      - name: Upload bounded PR coverage summary
        uses: actions/upload-artifact@0000000000000000000000000000000000000000
        if: ${{ always() && github.event_name == 'pull_request' }}
        with:
          name: coverage-pr-summary
          path: coverage-summary.txt
          retention-days: 1
  coverage-comment:
    needs: coverage
    if: ${{ always() && github.event_name == 'pull_request' }}
    continue-on-error: true
    permissions:
      actions: read
      pull-requests: write
    steps:
      - name: Download
        run: gh run download "${{ github.run_id }}" --name coverage-pr-summary --dir coverage-pr-summary || true
      - name: Comment
        run: |
          test -s coverage-pr-summary/coverage-summary.txt || exit 0
          gh pr comment "${{ github.event.pull_request.number }}" --body-file coverage-pr-summary/coverage-summary.txt || true
YAML

  check_workflow "$fixture" >/dev/null ||
    { echo "workflow-permissions SELFTEST: valid fixture was rejected" >&2; exit 1; }

  sed '/contents: read/a\
      pull-requests: write' "$fixture" >"$bad"
  if check_workflow "$bad" >/dev/null 2>&1; then
    echo "workflow-permissions SELFTEST: co-located write permission was accepted" >&2
    exit 1
  fi

  sed '/      - name: Download/i\
      - uses: actions/checkout@0000000000000000000000000000000000000000' "$fixture" >"$bad"
  if check_workflow "$bad" >/dev/null 2>&1; then
    echo "workflow-permissions SELFTEST: checkout in the write-capable job was accepted" >&2
    exit 1
  fi

  for planted_action in \
    '      - "uses": actions/github-script@v7' \
    '      - {uses: actions/github-script@v7}'; do
    awk -v planted_action="$planted_action" '
      $0 == "      - name: Download" { print planted_action }
      { print }
    ' "$fixture" >"$bad"
    if check_workflow "$bad" >/dev/null 2>&1; then
      echo "workflow-permissions SELFTEST: semantic action in the write-capable job was accepted: ${planted_action}" >&2
      exit 1
    fi
  done

  sed '/test -s coverage-pr-summary/a\
          make test' "$fixture" >"$bad"
  if check_workflow "$bad" >/dev/null 2>&1; then
    echo "workflow-permissions SELFTEST: repository execution in the write-capable job was accepted" >&2
    exit 1
  fi

  for planted_step in \
    '      - uses: actions/checkout@0000000000000000000000000000000000000000' \
    '      - uses: example/untrusted-action@0000000000000000000000000000000000000000' \
    '      - run: make test'; do
    awk -v planted_step="$planted_step" '
      { print }
      END {
        print "  planted-write:"
        print "    permissions:"
        print "      contents: write"
        print "    steps:"
        print planted_step
      }
    ' "$fixture" >"$bad"
    if check_workflow "$bad" >/dev/null 2>&1; then
      echo "workflow-permissions SELFTEST: unclassified write-capable job was accepted: ${planted_step}" >&2
      exit 1
    fi
  done

  cat "$fixture" >"$bad"
  cat >>"$bad" <<'YAML'
  "quoted-read": {permissions: {contents: read}, steps: []}
YAML
  check_workflow "$bad" >/dev/null ||
    { echo "workflow-permissions SELFTEST: safe quoted/flow job was rejected" >&2; exit 1; }

  for semantic_bypass in quoted flow multiline; do
    cat "$fixture" >"$bad"
    case "$semantic_bypass" in
      quoted)
        cat >>"$bad" <<'YAML'
  "planted-write":
    permissions: {contents: write}
    steps: [{run: "make test"}]
YAML
        ;;
      flow)
        cat >>"$bad" <<'YAML'
  planted-flow: {permissions: {contents: write}, steps: [{run: "make test"}]}
YAML
        ;;
      multiline)
        cat >>"$bad" <<'YAML'
  planted-multiline:
    permissions: >-
      write-all
    steps: []
YAML
        ;;
    esac
    if check_workflow "$bad" >/dev/null 2>&1; then
      echo "workflow-permissions SELFTEST: ${semantic_bypass} write authority escaped semantic inspection" >&2
      exit 1
    fi
  done

  cat >"$bad" <<'YAML'
read-job: &read-job {permissions: {contents: read}, steps: []}
jobs:
  coverage:
    permissions: {contents: read}
    steps: []
  coverage-comment:
    permissions: {actions: read, pull-requests: write}
    steps: []
  inherited: *read-job
YAML
  if check_workflow "$bad" >/dev/null 2>&1; then
    echo "workflow-permissions SELFTEST: YAML alias was accepted" >&2
    exit 1
  fi

  cat "$fixture" >"$bad"
  cat >>"$bad" <<'YAML'
  planted-merge:
    <<: {permissions: {contents: write}}
    steps: []
YAML
  if check_workflow "$bad" >/dev/null 2>&1; then
    echo "workflow-permissions SELFTEST: YAML merge hid write authority" >&2
    exit 1
  fi

  echo "workflow-permissions SELFTEST: OK (semantic jobs/permissions inspected; quoted/flow/multiline writes + aliases/merges rejected)"
}

if [[ "${1:-}" == "SELFTEST" ]]; then
  selftest
  exit 0
fi

check_workflow "${1:-.github/workflows/ci.yml}"
echo "workflow-permissions: coverage execution and PR write authority are isolated"
