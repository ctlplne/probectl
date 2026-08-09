#!/usr/bin/env bash
# GitOps manifest gate (S35). The parser is implemented in Go with the
# repository's existing YAML dependency, so the air-gapped gate does not need
# an extra Python/PyYAML installation.
set -euo pipefail

exec "${GO:-go}" run ./scripts/gitopscheck.go "${1:-deploy/gitops}"
