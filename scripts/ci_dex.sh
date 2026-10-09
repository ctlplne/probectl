#!/usr/bin/env bash
#
# F22: a REAL OIDC identity provider for the integration lane. Starts Dex — the
# self-hosted reference IdP of docs/auth/self-hosted-idp.md, the same
# digest-pinned image as deploy/compose/dex-demo.yml — at
# https://localhost:5556/dex under a THROWAWAY test CA (2-day validity,
# generated per run, never committed), with one deployment client and
# password users for the two-tenant SSO receipt
# (internal/control/sso_real_idp_integration_test.go).
#
# The client secret is generated per run. The users' password hash is Dex's
# own published example (bcrypt of the word "password", from Dex's
# config-dev.yaml): a public test value, not a credential, and the container is
# bound to loopback.
#
# Exports PROBECTL_TEST_DEX_* via $GITHUB_ENV and writes the same lines to
# <dir>/env for a local `set -a; . <dir>/env; set +a`.
set -euo pipefail

dir="${1:-.ci-dex}"
mkdir -p "${dir}"
dir="$(cd "${dir}" && pwd)"
name="${PROBECTL_TEST_DEX_CONTAINER:-probectl-test-dex}"
redirect="https://localhost:18443/auth/callback"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "${dir}/ca.key" -out "${dir}/ca.crt" -subj "/CN=probectl-ci-dex-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes \
  -keyout "${dir}/server.key" -out "${dir}/server.csr" -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in "${dir}/server.csr" -CA "${dir}/ca.crt" -CAkey "${dir}/ca.key" \
  -CAcreateserial -out "${dir}/server.crt" -days 2 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") 2>/dev/null
chmod 0644 "${dir}/server.crt" "${dir}/ca.crt"
chmod 0600 "${dir}/server.key" "${dir}/ca.key"

secret="$(openssl rand -hex 24)"
hash='$2a$10$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W'
user() { # email username userID
  printf '  - email: %s\n    hash: "%s"\n    username: %s\n    userID: %s\n' "$1" "${hash}" "$2" "$3"
}
{
  cat <<YAML
issuer: https://localhost:5556/dex
storage:
  type: memory
web:
  https: 0.0.0.0:5556
  tlsCert: /etc/dex/server.crt
  tlsKey: /etc/dex/server.key
oauth2:
  responseTypes: ["code"]
  skipApprovalScreen: true
expiry:
  idTokens: 1h
enablePasswordDB: true
staticClients:
  - id: probectl
    name: probectl integration
    secretEnv: DEX_CLIENT_SECRET
    redirectURIs:
      - ${redirect}
staticPasswords:
YAML
  user ada@acme.example ada 6a1f4f3e-5d64-4f0e-9b1c-2f8f1d0c1a01
  user alice@acme.example alice 6a1f4f3e-5d64-4f0e-9b1c-2f8f1d0c1a02
  user bob@globex.example bob 6a1f4f3e-5d64-4f0e-9b1c-2f8f1d0c1a03
  user mallory@outside.example mallory 6a1f4f3e-5d64-4f0e-9b1c-2f8f1d0c1a04
} >"${dir}/config.yaml"

docker rm -f "${name}" >/dev/null 2>&1 || true
docker run -d --name "${name}" -p 127.0.0.1:5556:5556 \
  --user "$(id -u):$(id -g)" \
  -e DEX_CLIENT_SECRET="${secret}" \
  -v "${dir}:/etc/dex:ro" \
  ghcr.io/dexidp/dex@sha256:8499afd690c437f52301efd2b05b2455da5bd2dfc20332cd697dc9937f808462 \
  dex serve /etc/dex/config.yaml >/dev/null

for i in $(seq 1 40); do
  if curl -fsS --cacert "${dir}/ca.crt" https://localhost:5556/dex/.well-known/openid-configuration >/dev/null 2>&1; then
    break
  fi
  if [ "$i" = 40 ]; then
    echo "dex did not become ready" >&2
    docker logs "${name}" >&2
    exit 1
  fi
  sleep 1
done

{
  echo "PROBECTL_TEST_DEX_ISSUER=https://localhost:5556/dex"
  echo "PROBECTL_TEST_DEX_CA_FILE=${dir}/ca.crt"
  echo "PROBECTL_TEST_DEX_CERT_FILE=${dir}/server.crt"
  echo "PROBECTL_TEST_DEX_CLIENT_ID=probectl"
  echo "PROBECTL_TEST_DEX_CLIENT_SECRET=${secret}"
  echo "PROBECTL_TEST_DEX_REDIRECT_URL=${redirect}"
  echo "PROBECTL_TEST_DEX_PASSWORD=password"
} >"${dir}/env"
chmod 0600 "${dir}/env"
cat "${dir}/env" >>"${GITHUB_ENV:-/dev/null}"
echo "Dex up at https://localhost:5556/dex (test CA ${dir}/ca.crt)"
