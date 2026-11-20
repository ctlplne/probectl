#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

set -euo pipefail
umask 077

fixture="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/probectl-opensearch.XXXXXX")"
container="probectl-qa-beta-${fixture##*/}"
cleanup() {
  docker rm -f -v "$container" >/dev/null 2>&1 || true
  rm -rf "$fixture"
}
trap cleanup EXIT

certs="$fixture/certificates"
mkdir -m 755 "$certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$certs/ca.key" -out "$certs/ca.crt" -subj '/CN=probectl-OpenSearch-test' 2>/dev/null
openssl req -newkey rsa:2048 -nodes \
  -keyout "$certs/server.key" -out "$certs/server.csr" -subj '/CN=localhost' 2>/dev/null
openssl x509 -req -days 1 -in "$certs/server.csr" \
  -CA "$certs/ca.crt" -CAkey "$certs/ca.key" -CAcreateserial \
  -out "$certs/server.crt" -extfile <(printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n') 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in "$certs/server.key" -out "$certs/server.pkcs8"
rm "$certs/ca.key" "$certs/server.key" "$certs/server.csr"
# Only this disposable non-root service receives the cert directory mount.
chmod 644 "$certs/ca.crt" "$certs/server.crt" "$certs/server.pkcs8"

export OPENSEARCH_INITIAL_ADMIN_PASSWORD
OPENSEARCH_INITIAL_ADMIN_PASSWORD="Aa9!$(openssl rand -hex 24)"
docker run -d --name "$container" --publish 127.0.0.1::9200 \
  --volume "$certs:/usr/share/opensearch/config/receipt:ro" \
  --env OPENSEARCH_INITIAL_ADMIN_PASSWORD --env discovery.type=single-node \
  --env node.store.allow_mmap=false --env 'OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m' \
  --env DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI=true \
  --env plugins.security.ssl.http.enabled=true \
  --env plugins.security.ssl.http.pemcert_filepath=receipt/server.crt \
  --env plugins.security.ssl.http.pemkey_filepath=receipt/server.pkcs8 \
  --env plugins.security.ssl.http.pemtrustedcas_filepath=receipt/ca.crt \
  opensearchproject/opensearch@sha256:3b55f6b6249cfdb92b52ee59adc8a266203ba9ef9f5d82544fad6f1af2f3609e >/dev/null
socket="$(docker port "$container" 9200/tcp)"
[[ "$socket" =~ ^127\.0\.0\.1:[0-9]+$ ]]
addr="https://$socket"
printf 'user = "admin:%s"\n' "$OPENSEARCH_INITIAL_ADMIN_PASSWORD" > "$fixture/admin.curl"
admin() {
  local endpoint="$1"
  shift
  curl --fail --silent --show-error --proto '=https' --noproxy '*' --max-time 5 \
    --cacert "$certs/ca.crt" --config "$fixture/admin.curl" \
    --header 'Content-Type: application/json' "$@" "$addr/$endpoint"
}

for attempt in {1..80}; do
  if admin _cluster/health >/dev/null 2>&1; then
    break
  fi
  if [[ "$attempt" == 80 ]]; then
    echo "OpenSearch did not reach authenticated TLS readiness" >&2
    exit 1
  fi
  sleep 1
done

role=probectl_receipt_writer
writer=probectl-receipt-writer
writer_password="Aa9!$(openssl rand -hex 24)"
security=_plugins/_security/api
admin "$security/roles/$role" --request PUT --data '{
  "cluster_permissions": ["indices:data/write/bulk*"],
  "index_permissions": [{
    "index_patterns": ["probectl-siem-*"],
    "allowed_actions": ["indices:data/write/index*", "indices:data/write/bulk*", "indices:admin/mapping/put"]
  }]
}' >/dev/null
printf '{"password":"%s"}\n' "$writer_password" |
  admin "$security/internalusers/$writer" --request PUT --data-binary @- >/dev/null
printf '{"users":["%s"]}\n' "$writer" |
  admin "$security/rolesmapping/$role" --request PUT --data-binary @- >/dev/null
rm "$fixture/admin.curl"

export PROBECTL_TEST_OPENSEARCH_URL="$addr"
export PROBECTL_TEST_OPENSEARCH_CA_FILE="$certs/ca.crt"
export PROBECTL_TEST_OPENSEARCH_USER=admin
export PROBECTL_TEST_OPENSEARCH_PASSWORD="$OPENSEARCH_INITIAL_ADMIN_PASSWORD"
export PROBECTL_TEST_OPENSEARCH_WRITER="$writer"
export PROBECTL_TEST_OPENSEARCH_WRITER_PASSWORD="$writer_password"
export PROBECTL_TEST_REQUIRE_OPENSEARCH=1
unset OPENSEARCH_INITIAL_ADMIN_PASSWORD writer_password
go test -tags=integration -count=1 -v -timeout=5m \
  -run '^TestShippedSIEMAuditReachesOpenSearchWithExactTenantIdentity$' ./internal/siem
