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

list_jobs() {
  local workflow="$1"

  awk '
    /^jobs:[[:space:]]*$/ { in_jobs=1; next }
    in_jobs && /^[^[:space:]]/ { exit }
    in_jobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
      line=$0
      sub(/^  /, "", line)
      sub(/:[[:space:]]*$/, "", line)
      print line
    }
  ' "$workflow"
}

workflow_has_write_permissions() {
  local workflow="$1"

  awk '
    /^permissions:[[:space:]]*/ {
      line=$0
      sub(/[[:space:]]*#.*/, "", line)
      gsub(/"/, "", line)
      gsub(sprintf("%c", 39), "", line)
      if (line ~ /write-all/ || line ~ /(^|[{: ,])write([}, ]|$)/) {
        write=1
      }
      in_permissions=(line ~ /^permissions:[[:space:]]*$/)
      next
    }
    in_permissions && /^  [A-Za-z0-9_-]+:[[:space:]]*/ {
      line=$0
      sub(/[[:space:]]*#.*/, "", line)
      gsub(/"/, "", line)
      gsub(sprintf("%c", 39), "", line)
      if (line ~ /:[[:space:]]*write[[:space:]]*$/) {
        write=1
      }
      next
    }
    in_permissions { in_permissions=0 }
    END { exit write ? 0 : 1 }
  ' "$workflow"
}

job_has_write_permissions() {
  awk '
    /^    permissions:[[:space:]]*/ {
      line=$0
      sub(/[[:space:]]*#.*/, "", line)
      gsub(/"/, "", line)
      gsub(sprintf("%c", 39), "", line)
      if (line ~ /write-all/ || line ~ /(^|[{: ,])write([}, ]|$)/) {
        write=1
      }
      in_permissions=(line ~ /^    permissions:[[:space:]]*$/)
      next
    }
    in_permissions && /^      [A-Za-z0-9_-]+:[[:space:]]*/ {
      line=$0
      sub(/[[:space:]]*#.*/, "", line)
      gsub(/"/, "", line)
      gsub(sprintf("%c", 39), "", line)
      if (line ~ /:[[:space:]]*write[[:space:]]*$/) {
        write=1
      }
      next
    }
    in_permissions { in_permissions=0 }
    END { exit write ? 0 : 1 }
  '
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
  local job
  local job_block

  if workflow_has_write_permissions "$workflow"; then
    echo "workflow-permissions: workflow-level write authority is forbidden in ${workflow}" >&2
    failed=1
  fi

  while IFS= read -r job; do
    [[ -z "$job" ]] && continue
    if ! job_block="$(extract_job "$workflow" "$job")"; then
      echo "workflow-permissions: could not inspect job ${job} in ${workflow}" >&2
      failed=1
      continue
    fi
    if printf '%s\n' "$job_block" | job_has_write_permissions && [[ "$job" != "coverage-comment" ]]; then
      echo "workflow-permissions: unclassified job ${job} has write authority" >&2
      failed=1
    fi
  done < <(list_jobs "$workflow")

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
  if grep -q 'actions/checkout@' <<<"$commenter"; then
    echo "workflow-permissions: coverage-comment must never checkout repository code" >&2
    failed=1
  fi
  if grep -Eq '^[[:space:]]+uses:' <<<"$commenter"; then
    echo "workflow-permissions: coverage-comment must not run actions from a repository" >&2
    failed=1
  fi

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

  echo "workflow-permissions SELFTEST: OK (all write-capable jobs classified; privilege co-location + commenter code execution rejected)"
}

if [[ "${1:-}" == "SELFTEST" ]]; then
  selftest
  exit 0
fi

check_workflow "${1:-.github/workflows/ci.yml}"
echo "workflow-permissions: coverage execution and PR write authority are isolated"
