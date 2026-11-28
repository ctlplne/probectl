#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

set -euo pipefail
umask 077

fixture="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/probectl-openbao.XXXXXX")"
container="probectl-qa-beta-${fixture##*/}"
cleanup() {
  docker rm -f -v "$container" >/dev/null 2>&1 || true
  rm -rf "$fixture"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$fixture/ca.key" -out "$fixture/ca.crt" -subj '/CN=probectl-OpenBao-test' 2>/dev/null
openssl req -newkey rsa:2048 -nodes \
  -keyout "$fixture/server.key" -out "$fixture/server.csr" -subj '/CN=localhost' 2>/dev/null
openssl x509 -req -days 1 -in "$fixture/server.csr" \
  -CA "$fixture/ca.crt" -CAkey "$fixture/ca.key" -CAcreateserial \
  -out "$fixture/server.crt" -extfile <(printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n') 2>/dev/null
rm "$fixture/ca.key" "$fixture/server.csr"

cat > "$fixture/openbao.hcl" <<'HCL'
disable_mlock = true
storage "inmem" {}
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/fixture/server.crt"
  tls_key_file = "/fixture/server.key"
}
HCL
docker run -d --name "$container" --publish 127.0.0.1::8200 \
  --volume "$fixture:/fixture:ro" --entrypoint bao \
  openbao/openbao@sha256:5eedbca9922d85eca5e4bc68c11f968d245b4046641dd4173c1dcff7ae7091aa \
  server -config=/fixture/openbao.hcl >/dev/null
socket="$(docker port "$container" 8200/tcp)"
[[ "$socket" =~ ^127\.0\.0\.1:[0-9]+$ ]]
addr="https://$socket"

call() {
  local endpoint="$1"
  shift
  curl --fail --silent --show-error --proto '=https' --noproxy '*' --max-time 5 \
    --cacert "$fixture/ca.crt" --header 'Content-Type: application/json' \
    "$@" "$addr/v1/$endpoint"
}
admin() {
  local endpoint="$1"
  shift
  call "$endpoint" --header "@$fixture/admin.header" "$@"
}

for attempt in {1..30}; do
  if call sys/init >/dev/null 2>&1; then
    break
  fi
  if [[ "$attempt" == 30 ]]; then
    echo "OpenBao did not reach verified TLS readiness" >&2
    exit 1
  fi
  sleep 1
done
init="$(call sys/init --request PUT --data '{"secret_shares":1,"secret_threshold":1}')"
jq -ce '{key: .keys_base64[0]}' <<<"$init" |
  call sys/unseal --request PUT --data-binary @- | jq -e '.sealed == false' >/dev/null
export PROBECTL_TEST_OPENBAO_ADMIN_TOKEN
PROBECTL_TEST_OPENBAO_ADMIN_TOKEN="$(jq -er '.root_token' <<<"$init")"
unset init
printf 'X-Vault-Token: %s\n' "$PROBECTL_TEST_OPENBAO_ADMIN_TOKEN" > "$fixture/admin.header"
mounts="$(admin sys/mounts)"
if jq -e '(.data // .)["secret/"] == null' <<<"$mounts" >/dev/null; then
  admin sys/mounts/secret --data '{"type":"kv","options":{"version":"2"}}' >/dev/null
else
  jq -e '(.data // .)["secret/"].options.version == "2"' <<<"$mounts" >/dev/null
fi
admin sys/auth/approle --data '{"type":"approle"}' >/dev/null
export PROBECTL_TEST_OPENBAO_POLICY=probectl-receipt
admin "sys/policies/acl/$PROBECTL_TEST_OPENBAO_POLICY" \
  --data '{"policy":"path \"secret/data/probectl/byok/*\" { capabilities = [\"read\"] }"}' >/dev/null
role='auth/approle/role/probectl-receipt'
admin "$role" --data '{"bind_secret_id":true,"token_policies":["probectl-receipt"],"token_no_default_policy":true,"token_ttl":"5m","token_max_ttl":"10m","secret_id_ttl":"10m"}' >/dev/null
export PROBECTL_TEST_OPENBAO_ROLE_ID PROBECTL_TEST_OPENBAO_SECRET_ID
PROBECTL_TEST_OPENBAO_ROLE_ID="$(admin "$role/role-id" | jq -er '.data.role_id')"
PROBECTL_TEST_OPENBAO_SECRET_ID="$(admin "$role/secret-id" --data '{}' | jq -er '.data.secret_id')"
rm "$fixture/admin.header"

export PROBECTL_TEST_OPENBAO_URL="$addr"
export PROBECTL_TEST_OPENBAO_CA_FILE="$fixture/ca.crt"
export PROBECTL_TEST_REQUIRE_OPENBAO=1
go test -tags=integration -count=1 -v -timeout=5m \
  -run '^TestShippedVaultCompatibleKeysRevokeAndRecoverWithinTenant$' ./ee/tenantkeys
