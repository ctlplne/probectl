#!/usr/bin/env bash
# check_domain_errors.sh — the domain-error vocabulary gate (Foundation-Loop
# S-ef8e66dc).
#
# RULE, not a denylist: an exported method of a store type must not hand a
# handler an error the handler has to CLASSIFY. Either it carries an
# apierror.Kind (so internal/control MAPS rather than invents a status), or the
# method resolves the condition itself (a missing row that is deliberately not
# an error), or it is exempted in scripts/domain_errors_allowlist.txt with a
# written reason. Stale exemptions fail the gate.
#
# SELFTEST plants each violation shape through a parser overlay — a bare
# errors.New return, a bare fmt.Errorf return, and a no-rows branch that hands
# the raw driver error onward — alongside correct methods that must NOT be
# flagged (classified, absence-is-not-an-error, negated no-rows, unexported),
# and drives them all through the same analysis the live gate runs.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" = "SELFTEST" ]; then
  go run ./cmd/probectl-domainerrors -selftest
  exit $?
fi

go run ./cmd/probectl-domainerrors
