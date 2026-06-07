#!/usr/bin/env bash
#
# OPS-010: CI exercises TLS to Postgres like production. This starts the CI
# Postgres with ssl=on under a THROWAWAY test CA (2-day validity, generated
# per run, never committed) and exports a verify-full DSN via $GITHUB_ENV —
# the client verifies the chain AND the hostname, exactly like the hardened
# deployment profile. Mirrors the shipped compose recipe's key handling
# (install postgres-owned 0600 inside the container).
set -euo pipefail

dir="${1:-.ci-pg-tls}"
mkdir -p "${dir}"

# Throwaway CA + server cert for localhost (SAN: DNS + 127.0.0.1).
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "${dir}/ca.key" -out "${dir}/ca.crt" -subj "/CN=probectl-ci-test-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes \
  -keyout "${dir}/server.key" -out "${dir}/server.csr" -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in "${dir}/server.csr" -CA "${dir}/ca.crt" -CAkey "${dir}/ca.key" \
  -CAcreateserial -out "${dir}/server.crt" -days 2 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") 2>/dev/null

docker run -d --name ci-postgres -p 5432:5432 \
  -e POSTGRES_USER=probectl -e POSTGRES_PASSWORD=probectl -e POSTGRES_DB=probectl \
  -v "$(pwd)/${dir}:/tlsin:ro" \
  postgres:16 \
  bash -c "install -o postgres -g postgres -m 600 /tlsin/server.key /var/lib/postgresql/server.key \
    && install -o postgres -g postgres -m 644 /tlsin/server.crt /var/lib/postgresql/server.crt \
    && exec docker-entrypoint.sh postgres -c ssl=on \
    -c ssl_cert_file=/var/lib/postgresql/server.crt \
    -c ssl_key_file=/var/lib/postgresql/server.key"

for i in $(seq 1 40); do
  if docker exec ci-postgres pg_isready -U probectl -d probectl >/dev/null 2>&1; then
    break
  fi
  if [ "$i" = 40 ]; then
    echo "postgres did not become ready" >&2
    docker logs ci-postgres >&2
    exit 1
  fi
  sleep 1
done

# verify-full: chain + hostname verification — the production posture.
dsn="postgres://probectl:probectl@localhost:5432/probectl?sslmode=verify-full&sslrootcert=$(pwd)/${dir}/ca.crt"
echo "PROBECTL_DATABASE_URL=${dsn}" >>"${GITHUB_ENV:-/dev/null}"
echo "CI Postgres up with TLS (verify-full, test CA at ${dir}/ca.crt)"
