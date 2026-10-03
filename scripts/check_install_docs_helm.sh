#!/usr/bin/env bash
# RTO-09: the copy-paste Helm install command in docs/install.md MUST satisfy the
# chart's values.schema.json and render cleanly. A user who pastes it must not hit
# a schema error (or any other render failure). No other gate renders the
# DOCUMENTED command — scripts/check_helm_hardening.sh builds its own value set and
# installs secrets via an existingSecret, so it never exercised the exact flags the
# docs tell operators to run. This gate reads the command straight out of the docs,
# turns the install into a non-deploying template render, substitutes the one
# placeholder the schema can't accept (the release digest), and asserts helm
# succeeds. Requires `helm` on PATH.
set -euo pipefail

DOC="${DOC:-docs/install.md}"
CHART="${CHART:-deploy/helm/probectl}"

[ -f "$DOC" ]   || { echo "install-docs helm gate: FAIL — $DOC not found" >&2; exit 1; }
[ -d "$CHART" ] || { echo "install-docs helm gate: FAIL — chart $CHART not found" >&2; exit 1; }
command -v helm >/dev/null 2>&1 || { echo "install-docs helm gate: FAIL — helm not on PATH" >&2; exit 1; }

# 1. Extract the FIRST fenced block that runs `helm install ... deploy/helm/probectl`.
#    The doc has several ``` fenced blocks (compose, curl, helm); keying on both the
#    verb and the chart path makes this robust to block order and formatting.
cmd="$(awk '
  /^```/ {
    if (infence) {                                  # a closing fence
      if (!found && buf ~ /helm[ \t]+install/ && buf ~ /deploy\/helm\/probectl/) {
        printf "%s", buf; found=1
      }
      infence=0; buf=""; next
    }
    infence=1; buf=""; next                          # an opening fence
  }
  infence { buf = buf $0 "\n" }
  END { if (!found) exit 3 }
' "$DOC")" || { echo "install-docs helm gate: FAIL — no 'helm install ... deploy/helm/probectl' block found in $DOC (RTO-09)" >&2; exit 1; }

# 2. Render-only rewrites. The docs carry placeholders, never real secrets:
#    - install -> template: validate values + schema without deploying.
#    - drop --create-namespace: an install-time flag, irrelevant to templating and
#      not accepted by every supported helm version's `template`.
#    - sha256:<release-digest> -> a syntactically valid dummy digest so image.digest
#      satisfies the schema's ^sha256:[0-9a-f]{64}$ pattern.
#    Any openssl/$(...) substitutions in the command run live and yield valid dummy
#    key material; the DSN placeholder is a legal string the schema/template accept.
DUMMY_DIGEST="sha256:0000000000000000000000000000000000000000000000000000000000000000"
render="$(printf '%s' "$cmd" \
  | sed -e 's/helm[[:space:]]\{1,\}install/helm template/' \
        -e 's/--create-namespace//' \
        -e "s|sha256:<release-digest>|${DUMMY_DIGEST}|")"

# 3. Run it. A schema violation (RTO-09's bug: missing ingress.backendTLS.*) or any
#    other render failure makes helm exit non-zero and fails the gate. Capture stderr
#    (helm reports schema errors there) and discard the rendered manifests.
if ! err="$(eval "$render" 2>&1 >/dev/null)"; then
  {
    echo "install-docs helm gate: FAIL — the documented helm command in $DOC does not render (RTO-09)."
    echo "--- helm error ---"
    echo "$err"
  } >&2
  exit 1
fi

echo "install-docs helm gate: OK — the documented '$DOC' helm install command renders against $CHART values.schema.json"
