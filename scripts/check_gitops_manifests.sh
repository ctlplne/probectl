#!/usr/bin/env bash
# GitOps manifest gate (S35). The parser is implemented in Go with the
# repository's existing YAML dependency, so the air-gapped gate does not need
# an extra Python/PyYAML installation.
set -euo pipefail

if [ "${1:-}" = "SELFTEST" ]; then
  # RTO-12: the Argo CD Kyverno health checks are non-vacuous — each planted
  # weakening (Healthy without the webhook, no default, file gone) fails.
  bin="$(mktemp -d)"; trap 'rm -rf "$bin"' EXIT
  "${GO:-go}" build -o "$bin/gitopscheck" ./scripts/gitopscheck.go
  "$bin/gitopscheck" deploy/gitops >/dev/null || { echo "gitops SELFTEST broken: the shipped manifests fail"; exit 1; }
  for plant in 's/if cs.ready == true and webhookConfigured then/if cs.ready == true then/' \
      's/    hs.status = "Progressing"/    hs.status = "Healthy"/' 'DELETE'; do
    dir="$bin/plant"; rm -rf "$dir"; cp -R deploy/gitops "$dir"
    if [ "$plant" = DELETE ]; then rm "$dir/argocd/argocd-cm-kyverno-health.yaml"
    else sed -i.bak -e "$plant" "$dir/argocd/argocd-cm-kyverno-health.yaml"; rm -f "$dir/argocd/"*.bak; fi
    if "$bin/gitopscheck" "$dir" >/dev/null; then echo "gitops SELFTEST broken: planted '$plant' was not caught"; exit 1; fi
    echo "  planted '$plant' -> caught"
  done
  echo "gitops SELFTEST ok"
  exit 0
fi
exec "${GO:-go}" run ./scripts/gitopscheck.go "${1:-deploy/gitops}"
