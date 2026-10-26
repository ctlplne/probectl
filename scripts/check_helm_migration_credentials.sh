#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Migration DDL credentials must never reach the long-running control container.
set -euo pipefail
chart="${CHART:-deploy/helm/probectl}"
args=(probectl "$chart" --set secrets.existingSecret=runtime-credentials
  --set control.tls.existingSecret=listener-tls --set ingress.enabled=false
  --set-string image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000
  --set database.migrationExistingSecret=migration-credentials)
# Check the template independently first, so schema rejection cannot hide a
# missing or incorrectly scoped credential reference. Validate the schema below.
rendered="$(helm template "${args[@]}" --skip-schema-validation)"
migrate="$(awk '/- name: migrate$/{in_migrate=1} in_migrate && /^        - name:/ && !/- name: migrate$/{exit} in_migrate && /^      containers:/{exit} in_migrate{print}' <<<"$rendered")"
if ! grep -q 'name: "migration-credentials"' <<<"$migrate"; then
  echo 'FAIL: migrate init container lacks its separate database Secret reference' >&2; exit 1
fi
if [ "$(grep -c 'name: "migration-credentials"' <<<"$rendered")" -ne 1 ]; then
  echo 'FAIL: migration credential reference escaped its one init container' >&2; exit 1
fi
if ! grep -q 'key: PROBECTL_DATABASE_URL' <<<"$migrate"; then
  echo 'FAIL: migration override must select only the database URL key' >&2; exit 1
fi
helm template "${args[@]}" >/dev/null
# Also cover the env block when the trust bundle is set, and omission when
# migrations are externally managed; neither may inject DDL access into control.
helm template "${args[@]}" --set control.trustBundle.existingConfigMap=private-ca >/dev/null
without="$(helm template "${args[@]}" --set migrateOnBoot=false)"
if grep -q 'migration-credentials' <<<"$without"; then
  echo 'FAIL: disabled migrations still expose the migration Secret' >&2; exit 1
fi
printf '%s\n' 'Helm migration credentials: isolated init reference, schema and external migration mode pass'
